"""
ioc_extractor.py
----------------
Stage 6a: Extract and classify IOCs from a completed malicious APK analysis
into buckets suitable for YARA, Snort, and CIF rule generation.

Entry point:
    extract_iocs(apk_facts, evidence_items, clusters, assessments, verdict, logger)
    -> ExtractedIOCs
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from evidence_schema import APKFacts, BehaviorCluster, ClusterAssessment, EvidenceItem

# ---------------------------------------------------------------------------
# noise filters  (reuse patterns from extract_suspicious_code.py)
# ---------------------------------------------------------------------------

_SDK_NOISE_RE = re.compile(
    r"^(?:"
    r"androidx?\.|kotlinx?\.|okhttp3(?:\.|$)|okio(?:\.|$)|retrofit2(?:\.|$)"
    r"|org\.(?:apache|json|xml|w3c|slf4j)\."
    r"|com\.google\.(?:android\.gms|firebase|ads|gson)\."
    r"|com\.squareup\.|com\.fasterxml\.jackson\."
    r"|com\.(?:facebook|mopub|inmobi|unity3d\.ads|chartboost|applovin)\."
    r"|com\.(?:ironsource|vungle|startapp|flurry|adjust)\."
    r"|com\.(?:paypal|stripe|braintreepayments)\."
    r")", re.I,
)

_RESOURCE_NOISE_RE = re.compile(
    r"^(?:res/|META-INF/|assets/[^\s]+\.(?:png|jpg|jpeg|gif|webp|xml|wav|mp3|ttf|otf|svg))",
    re.I,
)

_GENERIC_ANDROID_RE = re.compile(
    r"^(?:android\.permission\.|android\.intent\.action\.|android\.provider\."
    r"|android\.app\.action\.|android\.service\.|android\.accessibilityservice\."
    r"|android\.net\.|android\.hardware\.)", re.I,
)

_TOO_SHORT_OR_GENERIC = re.compile(r"^.{0,5}$|^[0-9]+$|^true$|^false$|^null$|^none$", re.I)

_URL_RE = re.compile(r"https?://[^\s\"'<>]{8,}", re.I)
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|io|xyz|top|tk|pw|ru|cn|su|cc|biz|info|click|ga|ml|cf|gq|"
    r"co|me|in|uk|de|fr|br|app|dev|pro|site|online|live|store|tech|space)\b", re.I,
)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_TELEGRAM_BOT_RE = re.compile(
    r"https?://api\.telegram\.org/bot\d{7,12}:[A-Za-z0-9_-]{35}", re.I,
)
_PASTE_SITE_RE = re.compile(
    r"pastebin\.com/raw/|paste\.ee/r/|hastebin\.com/raw/|rentry\.co/", re.I,
)

_BENIGN_IP_PREFIXES = (
    "8.8.", "1.1.1.", "1.0.0.", "142.250.", "142.251.", "172.217.",
    "173.194.", "104.16.", "104.17.", "104.18.", "104.19.", "104.20.",
    "104.21.", "13.107.", "20.190.", "52.96.", "17.253.",
)


# ---------------------------------------------------------------------------
# output dataclass
# ---------------------------------------------------------------------------

@dataclass
class ExtractedIOCs:
    """All IOCs extracted from a single malicious APK analysis, classified by type."""
    sha256: str
    family: str
    package_name: str
    # Static IOCs (for YARA)
    yara_candidate_strings: List[Dict[str, Any]]
    c2_urls: List[str]
    telegram_bot_tokens: List[str]
    paste_site_urls: List[str]
    embedded_file_refs: List[str]
    obfuscated_class_names: List[str]
    custom_class_names: List[str]
    amstrings: List[str]
    # Network IOCs (for Snort / CIF)
    c2_domains: List[str]
    c2_ips: List[str]
    ids_alerts: List[Dict[str, str]]
    user_agents: List[str]
    http_body_patterns: List[str]
    # Existing YARA context
    existing_yara_matches: List[str]
    # Behavior summary
    behavior_families: List[str]
    mitre_techniques: List[str]
    risk_score: int
    verdict_summary: str


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _is_benign_ip(ip: str) -> bool:
    return any(ip.startswith(p) for p in _BENIGN_IP_PREFIXES)


def _is_noise_string(s: str) -> bool:
    if _TOO_SHORT_OR_GENERIC.match(s):
        return True
    if _SDK_NOISE_RE.match(s):
        return True
    if _RESOURCE_NOISE_RE.match(s):
        return True
    if _GENERIC_ANDROID_RE.match(s):
        return True
    return False


def _guess_family(
    verdict: Dict[str, Any],
    yara_matches: List[Dict[str, Any]],
    evidence_items: List[EvidenceItem],
) -> str:
    """Best-effort family name from YARA match, VT label, or verdict summary."""
    for ym in yara_matches:
        rule = ym.get("detection_rule", "")
        parts = rule.split("_")
        if len(parts) >= 4:
            return parts[2]
    for ei in evidence_items:
        if ei.kind == "vt_threat_label" and ei.direction == "malicious":
            label = ei.value.split(":")[-1].strip()
            parts = label.split(".")
            if len(parts) >= 2:
                return parts[-1].split("/")[0].capitalize()
    summary = verdict.get("Summary", "")
    for kw in ("FluBot", "SpyNote", "Cerberus", "BankBot", "Ahmyth", "Spymax",
               "Anubis", "Triada", "Coper", "Mamont", "Anatsa", "Ermac"):
        if kw.lower() in summary.lower():
            return kw
    return "Gen"


def _mine_evidence(evidence_items, yc, cd, ci, ia, c2u, tg, pu, cc, oc, seen):
    for ei in evidence_items:
        val = ei.value.strip()
        if ei.direction == "benign":
            continue
        if ei.kind in ("vt_dns", "vt_http", "vt_ip", "vt_ids"):
            for d in _DOMAIN_RE.findall(val):
                cd.add(d.lower())
            for ip in _IP_RE.findall(val):
                if not _is_benign_ip(ip):
                    ci.add(ip)
        if ei.kind == "vt_ids" or "IDS rule" in ei.explanation:
            ia.append({"rule_msg": ei.explanation[:200],
                        "severity": "high" if ei.strength >= 0.80 else "medium"})
        if ei.kind == "string":
            if _TELEGRAM_BOT_RE.search(val):
                tg.append(val)
            elif _PASTE_SITE_RE.search(val):
                pu.append(val)
            elif _URL_RE.search(val):
                c2u.append(val)
                for d in _DOMAIN_RE.findall(val):
                    cd.add(d.lower())
            if not _is_noise_string(val) and val not in seen:
                seen.add(val)
                yc.append({"value": val, "source": ei.source_location,
                           "direction": ei.direction, "strength": ei.strength,
                           "kind": ei.kind, "explanation": ei.explanation,
                           "behavior_tags": ei.behavior_tags})
        if ei.kind == "class" and ei.direction in ("malicious", "ambiguous"):
            if not _SDK_NOISE_RE.match(val):
                cc.append(val)
                short = val.split(".")[-1]
                if len(short) <= 3 and short.isalnum():
                    oc.append(val)
        if ei.kind == "component" and ei.strength >= 0.60:
            comp = val.split("\u2192")[0].strip()
            if not _SDK_NOISE_RE.match(comp) and comp not in seen:
                seen.add(comp)
                yc.append({"value": comp, "source": ei.source_location,
                           "direction": ei.direction, "strength": ei.strength,
                           "kind": "component_class", "explanation": ei.explanation,
                           "behavior_tags": ei.behavior_tags})
    return yc, cd, ci, ia, c2u, tg, pu, cc, oc, seen


def _mine_raw_strings(apk_facts, yc, am, er, c2u, tg, cd, seen):
    for cls, strings in apk_facts.strings.items():
        for s in strings:
            s = s.strip()
            if not s or len(s) < 6 or s in seen or _is_noise_string(s):
                continue
            if s.startswith("AMStrings:"):
                am.append(s)
                seen.add(s)
                yc.append({"value": s, "source": f"class:{cls}",
                           "direction": "malicious", "strength": 0.80,
                           "kind": "amstring", "explanation": "AMStrings entry",
                           "behavior_tags": []})
                continue
            if re.match(r".*\.(dex|apk|jar|so|bin|dat|php|asp)\b", s, re.I):
                er.append(s)
            if _TELEGRAM_BOT_RE.search(s) and s not in seen:
                tg.append(s); seen.add(s)
            elif _URL_RE.search(s) and s not in seen:
                c2u.append(s); seen.add(s)
                for d in _DOMAIN_RE.findall(s):
                    cd.add(d.lower())
            if s not in seen and len(s) >= 8:
                if not re.match(r"^[A-Za-z0-9+/]{80,}={0,2}$", s):
                    if not re.match(r"^[0-9a-f]{32,}$", s, re.I):
                        seen.add(s)
                        yc.append({"value": s, "source": f"class:{cls}",
                                   "direction": "ambiguous", "strength": 0.30,
                                   "kind": "raw_string",
                                   "explanation": f"String from {cls}",
                                   "behavior_tags": []})
    return yc, am, er, c2u, tg, cd, seen


# ---------------------------------------------------------------------------
# main extractor
# ---------------------------------------------------------------------------

def extract_iocs(
    apk_facts: APKFacts,
    evidence_items: List[EvidenceItem],
    clusters: Dict[str, BehaviorCluster],
    assessments: Dict[str, ClusterAssessment],
    verdict: Dict[str, Any],
    logger: Any,
) -> ExtractedIOCs:
    """Extract and classify all IOCs from a completed malicious APK analysis."""
    import hashlib, os

    sha256 = ""
    try:
        with open(apk_facts.apk_path, "rb") as f:
            sha256 = hashlib.sha256(f.read()).hexdigest()
    except Exception:
        sha256 = os.path.basename(apk_facts.apk_path).replace(".apk", "")

    package_name = str(apk_facts.basic_info.get("package_name") or "")
    family = _guess_family(verdict, apk_facts.yara_matches, evidence_items)

    yc: List[Dict[str, Any]] = []
    c2u: List[str] = []
    tg: List[str] = []
    pu: List[str] = []
    er: List[str] = []
    oc: List[str] = []
    cc: List[str] = []
    am: List[str] = []
    cd: Set[str] = set()
    ci: Set[str] = set()
    ia: List[Dict[str, str]] = []
    seen: Set[str] = set()

    yc, cd, ci, ia, c2u, tg, pu, cc, oc, seen = _mine_evidence(
        evidence_items, yc, cd, ci, ia, c2u, tg, pu, cc, oc, seen,
    )
    yc, am, er, c2u, tg, cd, seen = _mine_raw_strings(
        apk_facts, yc, am, er, c2u, tg, cd, seen,
    )

    existing_yara = [ym.get("detection_rule", "") for ym in apk_facts.yara_matches]
    mal_fam = sorted(f for f, a in assessments.items() if a.verdict == "malicious")
    mitre: List[str] = []
    for ei in evidence_items:
        for m in re.finditer(r"T\d{4}(?:\.\d{3})?", ei.explanation + " " + ei.value):
            if m.group() not in mitre:
                mitre.append(m.group())
    yc.sort(key=lambda x: (-x["strength"], x["value"]))

    logger.info(
        "[ioc_extract] SHA=%s family=%s  yara_cands=%d  c2_domains=%d  "
        "c2_ips=%d  telegram=%d  amstrings=%d",
        sha256[:16], family, len(yc), len(cd), len(ci), len(tg), len(am),
    )
    return ExtractedIOCs(
        sha256=sha256, family=family, package_name=package_name,
        yara_candidate_strings=yc, c2_urls=c2u,
        telegram_bot_tokens=tg, paste_site_urls=pu,
        embedded_file_refs=er, obfuscated_class_names=oc,
        custom_class_names=cc, amstrings=am,
        c2_domains=sorted(cd), c2_ips=sorted(ci),
        ids_alerts=ia, user_agents=[], http_body_patterns=[],
        existing_yara_matches=existing_yara, behavior_families=mal_fam,
        mitre_techniques=mitre, risk_score=int(verdict.get("Risk-Score", 0)),
        verdict_summary=str(verdict.get("Summary", "")),
    )

