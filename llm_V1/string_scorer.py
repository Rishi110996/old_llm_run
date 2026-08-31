"""
string_scorer.py
----------------
Stage 6b: Score YARA candidate strings by quality.

quality = uniqueness * maliciousness * stability

- uniqueness:    based on VT content search hit count (fewer APK hits = better)
- maliciousness: from the evidence normalizer's strength + direction
- stability:     is this string likely to persist across variants?

Entry point:
    score_candidates(iocs, vt_api_key, logger) -> List[ScoredString]
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_VT_CACHE_PATH = os.path.join(_SCRIPT_DIR, "generated_rules", "vt_string_cache.json")
_VT_SEARCH_URL = "https://www.virustotal.com/api/v3/intelligence/search"

# Max VT searches per sample (quota budget)
MAX_VT_SEARCHES_PER_SAMPLE = 12

# Max candidate strings to score (top N by evidence strength)
MAX_CANDIDATES_TO_SCORE = 60


@dataclass
class ScoredString:
    """A YARA candidate string with its computed quality score."""
    value: str
    quality_score: float      # 0.0 - 1.0  (higher = better YARA string)
    uniqueness: float         # 0.0 - 1.0
    maliciousness: float      # 0.0 - 1.0
    stability: float          # 0.0 - 1.0
    vt_apk_hits: int          # -1 = not queried
    source: str
    kind: str
    explanation: str
    behavior_tags: List[str]


# ---------------------------------------------------------------------------
# VT content search cache
# ---------------------------------------------------------------------------

_vt_cache: Dict[str, int] = {}
_vt_cache_loaded = False


def _load_vt_cache() -> None:
    global _vt_cache, _vt_cache_loaded
    if _vt_cache_loaded:
        return
    _vt_cache_loaded = True
    if os.path.isfile(_VT_CACHE_PATH):
        try:
            with open(_VT_CACHE_PATH, "r", encoding="utf-8") as f:
                _vt_cache.update(json.load(f))
        except Exception:
            pass


def _save_vt_cache() -> None:
    os.makedirs(os.path.dirname(_VT_CACHE_PATH), exist_ok=True)
    try:
        with open(_VT_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(_vt_cache, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


def _vt_content_search(query_string: str, vt_api_key: str, logger: logging.Logger) -> int:
    """
    Search VT Intelligence for APKs containing this exact string.
    Returns the estimated hit count, or -1 on error/rate-limit.
    """
    _load_vt_cache()
    if query_string in _vt_cache:
        return _vt_cache[query_string]

    try:
        import requests
    except ImportError:
        return -1

    query = f'tag:apk and content:"{query_string}"'
    try:
        r = requests.get(
            _VT_SEARCH_URL,
            params={"query": query, "limit": 1, "descriptors_only": "true"},
            headers={"x-apikey": vt_api_key, "Accept": "application/json"},
            timeout=15,
        )
        if r.status_code == 429:
            logger.debug("[string_scorer] VT rate limited for content search")
            return -1
        if not r.ok:
            logger.debug("[string_scorer] VT search failed: HTTP %d", r.status_code)
            return -1
        data = r.json()
        # If there is a cursor, there are more results; count the first page
        results = data.get("data", [])
        has_more = bool(data.get("links", {}).get("next"))
        count = len(results) + (100 if has_more else 0)
        _vt_cache[query_string] = count
        _save_vt_cache()
        time.sleep(0.5)  # gentle pacing
        return count
    except Exception as exc:
        logger.debug("[string_scorer] VT search error: %s", exc)
        return -1


# ---------------------------------------------------------------------------
# scoring functions
# ---------------------------------------------------------------------------

def _compute_uniqueness(vt_hits: int) -> float:
    if vt_hits < 0:
        return 0.60   # unknown — conservative middle
    if vt_hits == 0:
        return 1.00
    if vt_hits <= 3:
        return 0.92
    if vt_hits <= 10:
        return 0.75
    if vt_hits <= 50:
        return 0.50
    if vt_hits <= 200:
        return 0.25
    return 0.05


def _compute_maliciousness(direction: str, strength: float) -> float:
    weights = {"malicious": 1.0, "ambiguous": 0.5, "benign": 0.1}
    return min(1.0, strength * weights.get(direction, 0.3))


_HIGH_STABILITY_PATTERNS = (
    re.compile(r"^AMStrings:", re.I),
    re.compile(r"\b(?:onCreate|attachBaseContext|onStartCommand)\b"),
    re.compile(r"(?:send|upload|delete|save|get|execute|start|stop)[A-Z]"),
    re.compile(r"\.php$|\.asp$", re.I),
    re.compile(r"content://sms"),
)

_LOW_STABILITY_PATTERNS = (
    re.compile(r"^https?://", re.I),           # C2 domains change often
    re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}"), # IPs change
    re.compile(r"bot\d{7,12}:"),                # Telegram tokens rotate
)


def _compute_stability(value: str, kind: str) -> float:
    for pat in _LOW_STABILITY_PATTERNS:
        if pat.search(value):
            return 0.30
    for pat in _HIGH_STABILITY_PATTERNS:
        if pat.search(value):
            return 0.95
    if kind in ("amstring", "component_class"):
        return 0.90
    if kind == "class":
        return 0.85
    if kind == "string" and len(value) >= 15:
        return 0.70
    return 0.60


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------

def score_candidates(
    iocs: Any,  # ExtractedIOCs
    vt_api_key: Optional[str],
    logger: logging.Logger,
) -> List[ScoredString]:
    """
    Score the top YARA candidate strings from extracted IOCs.
    Optionally queries VT content search for uniqueness scoring.
    """
    candidates = iocs.yara_candidate_strings[:MAX_CANDIDATES_TO_SCORE]
    if not candidates:
        logger.info("[string_scorer] No YARA candidates to score")
        return []

    # Decide how many to VT-search (top by strength, budget-limited)
    vt_budget = MAX_VT_SEARCHES_PER_SAMPLE if vt_api_key else 0
    vt_searched = 0

    scored: List[ScoredString] = []
    for cand in candidates:
        val = cand["value"]
        direction = cand["direction"]
        strength = cand["strength"]
        kind = cand["kind"]

        # VT uniqueness search for top candidates
        vt_hits = -1
        if vt_budget > 0 and vt_searched < vt_budget and strength >= 0.50:
            vt_hits = _vt_content_search(val, vt_api_key, logger)
            if vt_hits >= 0:
                vt_searched += 1

        uniqueness = _compute_uniqueness(vt_hits)
        maliciousness = _compute_maliciousness(direction, strength)
        stability = _compute_stability(val, kind)
        quality = round(uniqueness * maliciousness * stability, 4)

        scored.append(ScoredString(
            value=val,
            quality_score=quality,
            uniqueness=uniqueness,
            maliciousness=maliciousness,
            stability=stability,
            vt_apk_hits=vt_hits,
            source=cand["source"],
            kind=kind,
            explanation=cand["explanation"],
            behavior_tags=cand.get("behavior_tags", []),
        ))

    scored.sort(key=lambda x: -x.quality_score)

    logger.info(
        "[string_scorer] Scored %d candidates (VT searched %d/%d). "
        "Top: %.3f '%s'",
        len(scored), vt_searched, vt_budget,
        scored[0].quality_score if scored else 0,
        scored[0].value[:50] if scored else "",
    )
    return scored
