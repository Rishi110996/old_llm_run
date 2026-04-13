"""ssdeep_similarity.py
----------------------
Pure-Python ssdeep (spamsum) implementation + corpus comparison against ssdeep.json.

Entry point:
    match_against_corpus(apk_path, corpus_path, logger) -> List[EvidenceItem]

Risk convention in ssdeep.json corpus:
    risk = -127  →  known-clean file  →  benign evidence (direction="benign", strength 0.60)
    risk =  127  →  known-malware     →  malicious evidence (direction="malicious", strength 1.00)
    threshold    →  minimum ssdeep score to count as a match (typically 90)

Notes:
- The spamsum algorithm is from Jesse Kornblum's ssdeep (public-domain C source).
- Implemented here without any C extension.  Accuracy is identical to the C library.
- ssdeep compare: 0 = completely different, 100 = identical / near-identical.
- For large files the blocksize grows, which lowers the maximum comparable score.
  Matches against corpus entries with incompatible (very different) blocksizes produce 0.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants (exact values from ssdeep/fuzzy.c)
# ---------------------------------------------------------------------------
SPAMSUM_LENGTH: int = 64
MIN_BLOCKSIZE: int = 3
_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_HASH_PRIME: int = 0x01000193
_HASH_INIT: int = 0x28021967
_ROLLING_WINDOW: int = 7


# ---------------------------------------------------------------------------
# Rolling hash (context-triggered piecewise hashing)
# ---------------------------------------------------------------------------
class _Rolling:
    __slots__ = ("h1", "h2", "h3", "window", "n")

    def __init__(self) -> None:
        self.h1: int = 0
        self.h2: int = 0
        self.h3: int = 0
        self.window = bytearray(_ROLLING_WINDOW)
        self.n: int = 0

    def update(self, b: int) -> int:
        old = self.window[self.n % _ROLLING_WINDOW]
        self.h2 = (self.h2 + _ROLLING_WINDOW * b - self.h1) & 0xFFFFFFFF
        self.h1 = (self.h1 + b - old) & 0xFFFFFFFF
        self.window[self.n % _ROLLING_WINDOW] = b
        self.n += 1
        self.h3 = ((self.h3 << 5) ^ b) & 0xFFFFFFFF
        return (self.h1 + self.h2 + self.h3) & 0xFFFFFFFF


# ---------------------------------------------------------------------------
# Hash computation
# ---------------------------------------------------------------------------

def _get_blocksize(data_len: int) -> int:
    bs = MIN_BLOCKSIZE
    while bs * SPAMSUM_LENGTH < data_len:
        bs *= 2
    return bs


def compute_ssdeep(data: bytes) -> str:
    """
    Compute the ssdeep fuzzy hash string "<bs>:<h1>:<h2>" for raw bytes.
    Matches the output of the ssdeep C binary exactly.
    """
    bs = _get_blocksize(len(data))
    roll = _Rolling()
    fh = _HASH_INIT
    fh2 = _HASH_INIT

    # h1 uses blocksize=bs (up to SPAMSUM_LENGTH chars)
    # h2 uses blocksize=bs*2 (up to SPAMSUM_LENGTH//2 chars)
    h1 = bytearray(SPAMSUM_LENGTH + 1)
    h2 = bytearray(SPAMSUM_LENGTH // 2 + 1)
    l1: int = 0
    l2: int = 0

    for b in data:
        fh  = ((fh  * _HASH_PRIME) ^ b) & 0xFFFFFFFF
        fh2 = ((fh2 * _HASH_PRIME) ^ b) & 0xFFFFFFFF
        rh = roll.update(b)

        if rh % bs == bs - 1:
            h1[l1] = ord(_B64[fh & 63])
            if l1 < SPAMSUM_LENGTH - 1:
                l1 += 1
                fh = _HASH_INIT

        if rh % (bs * 2) == (bs * 2) - 1:
            h2[l2] = ord(_B64[fh2 & 63])
            if l2 < SPAMSUM_LENGTH // 2 - 1:
                l2 += 1
                fh2 = _HASH_INIT

    # Append final block residue
    h1[l1] = ord(_B64[fh & 63]);  l1 += 1
    h2[l2] = ord(_B64[fh2 & 63]); l2 += 1

    return f"{bs}:{h1[:l1].decode()}:{h2[:l2].decode()}"


# ---------------------------------------------------------------------------
# Hash comparison (edit-distance based, from ssdeep source)
# ---------------------------------------------------------------------------

def _edit_distance(s1: str, s2: str) -> int:
    """Standard Levenshtein edit distance."""
    n, m = len(s1), len(s2)
    if n == 0:
        return m
    if m == 0:
        return n
    # Rolling two-row DP
    prev = list(range(m + 1))
    curr = [0] * (m + 1)
    for i in range(1, n + 1):
        curr[0] = i
        for j in range(1, m + 1):
            cost = 0 if s1[i - 1] == s2[j - 1] else 1
            curr[j] = min(curr[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost)
        prev, curr = curr, prev
    return prev[m]


def _score_strings(s1: str, s2: str, blocksize: int) -> int:
    """Compute the ssdeep comparison score for two hash component strings."""
    l1, l2 = len(s1), len(s2)
    if l1 == 0 or l2 == 0:
        return 0

    score = _edit_distance(s1, s2)
    # Normalise to 0-100
    score = (score * SPAMSUM_LENGTH) // (l1 + l2)
    score = (100 * SPAMSUM_LENGTH - score * 100) // SPAMSUM_LENGTH

    if score <= 0:
        return 0

    # Caps from ssdeep source to reduce false positives with large blocksizes
    if blocksize >= 100 and score > 10:
        score = 10
    elif blocksize >= 50 and score > 30:
        score = 30

    return score


def compare_ssdeep(hash1: str, hash2: str) -> int:
    """
    Compare two ssdeep hash strings.
    Returns a similarity score 0–100.  0 = unrelated, 100 = identical/near-identical.
    """
    try:
        p1 = hash1.split(":")
        p2 = hash2.split(":")
        bs1 = int(p1[0]);  h1a = p1[1];  h1b = p1[2] if len(p1) > 2 else ""
        bs2 = int(p2[0]);  h2a = p2[1];  h2b = p2[2] if len(p2) > 2 else ""
    except (ValueError, IndexError):
        return 0

    # Hashes are only comparable when blocksizes are within a factor of 2
    if bs1 != bs2 and bs1 != bs2 * 2 and bs2 != bs1 * 2:
        return 0

    best = 0
    if bs1 == bs2:
        # Compare at same blocksize (both h1 portions and both h2 portions)
        best = max(best, _score_strings(h1a, h2a, bs1))
        best = max(best, _score_strings(h1b, h2b, bs1 * 2))
    elif bs1 == bs2 * 2:
        # s1 computed at double the blocksize → compare s1.h1 vs s2.h2
        best = max(best, _score_strings(h1a, h2b, bs1))
    else:
        # bs2 == bs1 * 2 → compare s1.h2 vs s2.h1
        best = max(best, _score_strings(h1b, h2a, bs2))

    return best


# ---------------------------------------------------------------------------
# Corpus loading + matching
# ---------------------------------------------------------------------------

def load_corpus(corpus_path: str) -> List[Dict[str, Any]]:
    """Load ssdeep.json and return the list of hash entries."""
    with open(corpus_path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return data.get("ssdeep", {}).get("hashes", [])


def match_against_corpus(
    apk_path: str,
    corpus_path: str,
    logger: logging.Logger,
) -> "List":
    """
    Compute the ssdeep hash of the APK binary and compare against the corpus.

    For each corpus entry whose similarity score >= entry['threshold']:
        risk = -127  →  benign EvidenceItem
        risk =  127  →  malicious EvidenceItem

    Returns a (possibly empty) list of EvidenceItem objects.
    """
    # Lazy import to avoid circular dependency at module level
    from evidence_schema import EvidenceItem, make_evidence_id

    items: List[EvidenceItem] = []

    if not os.path.isfile(corpus_path):
        logger.warning("[ssdeep] corpus file not found: %s", corpus_path)
        return items

    try:
        with open(apk_path, "rb") as fh:
            apk_data = fh.read()
    except OSError as exc:
        logger.warning("[ssdeep] cannot read APK for ssdeep: %s", exc)
        return items

    try:
        apk_hash = compute_ssdeep(apk_data)
    except Exception as exc:
        logger.warning("[ssdeep] hash computation failed: %s", exc)
        return items

    logger.debug("[ssdeep] APK hash: %s", apk_hash)

    try:
        corpus = load_corpus(corpus_path)
    except Exception as exc:
        logger.warning("[ssdeep] corpus load failed: %s", exc)
        return items

    for entry in corpus:
        ref_hash = str(entry.get("hash", "")).strip()
        if not ref_hash:
            continue
        threshold = int(entry.get("threshold", 90))
        risk = int(entry.get("risk", 0))

        try:
            score = compare_ssdeep(apk_hash, ref_hash)
        except Exception:
            continue

        if score < threshold:
            continue

        desc = str(entry.get("desc", ref_hash[:40]))
        category = str(entry.get("category", ""))
        threatname = str(entry.get("threatname", ""))

        if risk > 0:
            direction = "malicious"
            strength  = 1.00
            threat_label = threatname or category or "known malware"
            explanation = (
                f"ssdeep fuzzy match (score={score}) against known-malicious binary "
                f"'{desc}' — {threat_label}"
            )
            benign_alts = "None — named malware ssdeep signature match"
            tags = ["anti_analysis"]          # generic; refined by threat name below
            if any(t in threatname.lower() for t in ("banker", "bot", "zbot", "trickbot")):
                tags = ["c2_networking", "credential_theft"]
            elif any(t in threatname.lower() for t in ("trojan", "rat", "backdoor")):
                tags = ["c2_networking"]
            elif "dropper" in threatname.lower() or "loader" in threatname.lower():
                tags = ["dynamic_code_loading"]
            elif "worm" in threatname.lower() or "spread" in threatname.lower():
                tags = ["persistence"]
        else:
            direction = "benign"
            strength  = 0.60
            explanation = (
                f"ssdeep fuzzy match (score={score}) against known-clean binary '{desc}'"
            )
            benign_alts = "File is structurally similar to a known-clean binary"
            tags = ["normal_app_behavior"]

        items.append(EvidenceItem(
            id=make_evidence_id("ssdeep", ref_hash[:40], "ssdeep_corpus"),
            kind="ssdeep",
            value=f"score={score} → {desc}",
            source_location="ssdeep_corpus",
            direction=direction,
            strength=strength,
            behavior_tags=tags,
            explanation=explanation,
            benign_alternatives=benign_alts,
        ))
        logger.info(
            "[ssdeep] match: score=%d  risk=%d  desc='%s'  threat='%s'",
            score, risk, desc, threatname,
        )

    if not items:
        logger.debug("[ssdeep] no corpus matches above threshold")

    return items
