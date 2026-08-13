"""
financial_targets.py
--------------------
Shared financial-target intelligence for Android banking/UPI overlay analysis.

Important design rule: a financial brand/package/domain hit is not malicious
by itself. Treat it as target context until corroborated with overlay,
accessibility, app-monitoring, OTP capture, or signing-identity mismatch.
"""
from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from typing import Any, Dict, Iterable, List, Optional, Sequence


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CATALOG_PATH = os.path.join(SCRIPT_DIR, "financial_targets.json")

_IMPOSSIBLE_RE = re.compile(r"a\Ab")
_DOMAIN_CHAR_RE = re.compile(r"^[A-Za-z0-9.-]+$")
_BRAND_CONTEXT_RE = re.compile(
    r"(?:bank|upi|wallet|pay|payment|login|overlay|target|package|app|credential|"
    r"otp|pin|netbanking|mobilebanking)",
    re.I,
)


def _norm_hash(value: Any) -> str:
    return str(value or "").lower().replace(":", "").strip()


def _as_list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


@lru_cache(maxsize=1)
def load_catalog() -> Dict[str, Any]:
    try:
        with open(CATALOG_PATH, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


def iter_targets() -> Iterable[Dict[str, Any]]:
    for target in _as_list(load_catalog().get("targets")):
        if isinstance(target, dict):
            yield target


@lru_cache(maxsize=1)
def financial_package_pattern() -> re.Pattern:
    patterns: List[str] = []
    for target in iter_targets():
        patterns.extend(str(p) for p in _as_list(target.get("package_patterns")) if str(p).strip())
        for app in _as_list(target.get("official_apps")):
            if isinstance(app, dict):
                package = str(app.get("package_name") or "").strip()
                if package:
                    patterns.append(r"\b" + re.escape(package) + r"\b")
    if not patterns:
        return _IMPOSSIBLE_RE
    return re.compile("(?:%s)" % "|".join(patterns), re.I)


@lru_cache(maxsize=1)
def upi_vpa_pattern() -> re.Pattern:
    handles = [
        re.escape(str(h).strip())
        for h in _as_list(load_catalog().get("upi_vpa_handles"))
        if str(h).strip()
    ]
    if not handles:
        return _IMPOSSIBLE_RE
    pattern = r"\b[a-z0-9][a-z0-9._-]{1,80}@(?:%s)\b"
    return re.compile(pattern % "|".join(handles), re.I)


def _domain_pattern(domain: str) -> Optional[re.Pattern]:
    domain = str(domain or "").strip().lower()
    if not domain or not _DOMAIN_CHAR_RE.match(domain):
        return None
    return re.compile(r"(?<![A-Za-z0-9.-])(?:[A-Za-z0-9-]+\.)*" + re.escape(domain) + r"(?![A-Za-z0-9.-])", re.I)


def find_financial_target_references(text: str) -> List[Dict[str, str]]:
    """Return target references found in arbitrary APK strings/source text."""
    value = str(text or "")
    if not value:
        return []

    matches: List[Dict[str, str]] = []
    lower_value = value.lower()
    has_brand_context = bool(_BRAND_CONTEXT_RE.search(value))

    for target in iter_targets():
        target_id = str(target.get("id") or "unknown")
        brand = str(target.get("brand") or target_id)
        region = str(target.get("region") or "")
        category = str(target.get("category") or "")

        for pattern in _as_list(target.get("package_patterns")):
            try:
                if re.search(str(pattern), value, re.I):
                    matches.append({
                        "target_id": target_id,
                        "brand": brand,
                        "region": region,
                        "category": category,
                        "match_type": "package_pattern",
                    })
                    break
            except re.error:
                continue

        for app in _as_list(target.get("official_apps")):
            if not isinstance(app, dict):
                continue
            package = str(app.get("package_name") or "").strip()
            if package and re.search(r"\b" + re.escape(package) + r"\b", value, re.I):
                matches.append({
                    "target_id": target_id,
                    "brand": brand,
                    "region": region,
                    "category": category,
                    "match_type": "official_package_string",
                })
                break

        for domain in _as_list(target.get("domains")):
            pattern = _domain_pattern(str(domain))
            if pattern and pattern.search(value):
                matches.append({
                    "target_id": target_id,
                    "brand": brand,
                    "region": region,
                    "category": category,
                    "match_type": "official_or_lookalike_domain",
                })
                break

        # Brand keywords are weak, so only accept them in finance-like context.
        if has_brand_context:
            for keyword in _as_list(target.get("brand_keywords")):
                token = str(keyword or "").strip().lower()
                if len(token) < 4:
                    continue
                if re.search(r"(?<![A-Za-z0-9])" + re.escape(token) + r"(?![A-Za-z0-9])", lower_value, re.I):
                    matches.append({
                        "target_id": target_id,
                        "brand": brand,
                        "region": region,
                        "category": category,
                        "match_type": "brand_keyword_context",
                    })
                    break

    # Deduplicate while preserving order.
    seen = set()
    deduped: List[Dict[str, str]] = []
    for match in matches:
        key = (match["target_id"], match["match_type"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(match)
    return deduped


def official_app_entries_for_package(package_name: str) -> List[Dict[str, Any]]:
    package_name = str(package_name or "").strip()
    if not package_name:
        return []
    entries: List[Dict[str, Any]] = []
    for target in iter_targets():
        for app in _as_list(target.get("official_apps")):
            if not isinstance(app, dict):
                continue
            if str(app.get("package_name") or "").strip() != package_name:
                continue
            enriched = dict(app)
            enriched["target_id"] = str(target.get("id") or "")
            enriched["brand"] = str(target.get("brand") or target.get("id") or "")
            enriched["region"] = str(target.get("region") or "")
            enriched["category"] = str(target.get("category") or "")
            entries.append(enriched)
    return entries


def evaluate_official_identity(
    package_name: str,
    certificates: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Evaluate whether a package that looks official is signed by a configured
    known-good certificate.

    Returns:
      status = not_cataloged | verified | cert_mismatch | unverifiable_no_cert_baseline

    Package name alone is never enough to return verified.
    """
    entries = official_app_entries_for_package(package_name)
    if not entries:
        return {"status": "not_cataloged", "entries": []}

    cert_sha1 = {
        _norm_hash(c.get("thumbprint") or c.get("thumbprint_sha1") or c.get("sha1"))
        for c in certificates or []
    }
    cert_sha256 = {
        _norm_hash(c.get("thumbprint_sha256") or c.get("sha256"))
        for c in certificates or []
    }
    cert_sha1.discard("")
    cert_sha256.discard("")

    has_baseline = False
    for entry in entries:
        allowed_sha1 = {_norm_hash(v) for v in _as_list(entry.get("cert_sha1"))}
        allowed_sha256 = {_norm_hash(v) for v in _as_list(entry.get("cert_sha256"))}
        allowed_sha1.discard("")
        allowed_sha256.discard("")
        if allowed_sha1 or allowed_sha256:
            has_baseline = True
        if allowed_sha1.intersection(cert_sha1) or allowed_sha256.intersection(cert_sha256):
            return {"status": "verified", "entries": entries, "matched_entry": entry}

    if has_baseline:
        return {"status": "cert_mismatch", "entries": entries}
    return {"status": "unverifiable_no_cert_baseline", "entries": entries}
