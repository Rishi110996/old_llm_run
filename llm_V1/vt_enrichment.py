"""vt_enrichment.py
------------------
Queries the VirusTotal v3 behaviours endpoint for sandbox traffic data and
converts the results into EvidenceItems for the v2 pipeline.

Entry point:
    enrich_from_vt(sha256, vt_api_key, logger) -> List[EvidenceItem]

The VT API key can be passed explicitly or is read from
    vt_apk_downloader/config.yaml  (first premium tier key).
"""
from __future__ import annotations

import logging
import os
import re
import sys
from typing import Any, Dict, List, Optional

# ── VT API constants ──────────────────────────────────────────────────────────
_VT_BASE = "https://www.virustotal.com/api/v3"
_BEHAVIOURS_EP = _VT_BASE + "/files/{sha256}/behaviours"
_PCAP_EP       = _VT_BASE + "/file_behaviours/{sandbox_id}/pcap"

# ── Quick triage patterns (same as smba_enrichment) ──────────────────────────
_SUSPICIOUS_TLD = re.compile(
    r"\b[a-z0-9-]+\.(?:ru|cn|su|top|tk|pw|xyz|kim|click|info|biz|cc)\b", re.I
)
_IP_URL  = re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", re.I)
_RAW_IP  = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_PHP_URL = re.compile(r"https?://[^\s\"']{10,}\.php", re.I)

# ── MITRE ATT&CK tactic → behavior family mapping ────────────────────────────
_MITRE_TACTIC_MAP = {
    "collection":            (["data_exfiltration"],           0.75, "malicious"),
    "command-and-control":   (["c2_networking"],               0.85, "malicious"),
    "credential-access":     (["credential_theft"],            0.85, "malicious"),
    "defense-evasion":       (["anti_analysis"],               0.75, "malicious"),
    "discovery":             (["anti_analysis"],               0.50, "ambiguous"),
    "execution":             (["dynamic_code_loading"],        0.70, "malicious"),
    "exfiltration":          (["data_exfiltration"],           0.85, "malicious"),
    "impact":                (["persistence"],                 0.80, "malicious"),
    "persistence":           (["persistence"],                 0.75, "malicious"),
    "privilege-escalation":  (["privilege_escalation"],        0.85, "malicious"),
}


def _ei():
    from evidence_schema import EvidenceItem, make_evidence_id
    return EvidenceItem, make_evidence_id


def load_vt_api_key_from_config() -> Optional[str]:
    """Read the first premium VT key from vt_apk_downloader/config.yaml."""
    try:
        import yaml
    except ImportError:
        return None

    config_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "vt_apk_downloader",
        "config.yaml",
    )
    if not os.path.isfile(config_path):
        return None
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f)
        for key_entry in cfg.get("api", {}).get("keys", []):
            if key_entry.get("tier") == "premium" and key_entry.get("key"):
                return key_entry["key"]
    except Exception:
        pass
    return None


def _triage_value(value: str):
    """Return (direction, strength, explanation_detail) for a network IOC string."""
    if _IP_URL.search(value) or _RAW_IP.match(value):
        return "malicious", 0.85, "Direct IP connection"
    if _PHP_URL.search(value):
        return "ambiguous", 0.60, "PHP endpoint"
    if _SUSPICIOUS_TLD.search(value):
        return "ambiguous", 0.55, "Suspicious TLD domain"
    return "ambiguous", 0.35, "Network endpoint"


def _add_network_items(
    values: List[str],
    source_detail: str,
    sandbox_name: str,
    seen: set,
    items: list,
    logger: logging.Logger,
) -> None:
    EvidenceItem, make_evidence_id = _ei()
    for raw in values:
        val = str(raw).strip()
        if not val or val in seen:
            continue
        seen.add(val)
        direction, strength, detail = _triage_value(val)
        items.append(EvidenceItem(
            id=make_evidence_id("vt_traffic", val, "virustotal"),
            kind="vt_traffic",
            value=val,
            source_location=f"vt_sandbox:{sandbox_name}:{source_detail}",
            direction=direction,
            strength=strength,
            behavior_tags=["c2_networking"],
            explanation=f"{detail} observed in VT sandbox '{sandbox_name}' ({source_detail}): {val}",
            benign_alternatives="CDN, analytics, or SDK traffic",
        ))


def _items_from_sandbox_report(
    sandbox: Dict[str, Any],
    seen: set,
    items: list,
    logger: logging.Logger,
) -> None:
    """Extract network IOCs from a single VT sandbox report."""
    attrs = sandbox.get("attributes", {})
    sandbox_name = attrs.get("sandbox_name", "unknown")

    # DNS resolutions
    dns_list = attrs.get("dns_lookups", [])
    dns_values = [
        d.get("hostname") or d if isinstance(d, str) else ""
        for d in dns_list
    ]
    _add_network_items([v for v in dns_values if v], "dns", sandbox_name, seen, items, logger)

    # IP traffic
    net_list = attrs.get("network_communications", [])
    ip_values = [n.get("destination_ip") or n.get("remote_address") or "" for n in net_list]
    _add_network_items([v for v in ip_values if v], "ip", sandbox_name, seen, items, logger)

    # HTTP(S) requests
    http_list = attrs.get("http_conversations", [])
    http_values = [
        h.get("url") or h.get("request_method", "") + " " + h.get("host", "")
        for h in http_list
    ]
    _add_network_items([v.strip() for v in http_values if v.strip()], "http", sandbox_name, seen, items, logger)

    # MITRE ATT&CK tactics
    EvidenceItem, make_evidence_id = _ei()
    mitre_list = attrs.get("mitre_attack_techniques", []) or attrs.get("tactics", [])
    for t in mitre_list:
        tactic = ""
        if isinstance(t, dict):
            tactic = (t.get("tactic") or t.get("name") or "").lower().replace(" ", "-")
        elif isinstance(t, str):
            tactic = t.lower().replace(" ", "-")
        mapping = _MITRE_TACTIC_MAP.get(tactic)
        if not mapping:
            continue
        tags, strength, direction = mapping
        key = f"mitre:{tactic}"
        if key in seen:
            continue
        seen.add(key)
        items.append(EvidenceItem(
            id=make_evidence_id("vt_mitre", tactic, "virustotal"),
            kind="vt_mitre",
            value=f"MITRE ATT&CK tactic: {tactic}",
            source_location=f"vt_sandbox:{sandbox_name}:mitre",
            direction=direction,
            strength=strength,
            behavior_tags=tags,
            explanation=f"VT sandbox '{sandbox_name}' mapped tactic: {tactic}",
            benign_alternatives="None",
        ))

    # PCAP availability log
    sandbox_id = sandbox.get("id", "")
    has_evaded = attrs.get("has_evaded", True)
    if sandbox_id and not has_evaded:
        logger.info(
            "[vt] PCAP may be available for sandbox '%s' (id=%s) — not evaded",
            sandbox_name,
            sandbox_id,
        )


def enrich_from_vt(
    sha256: str,
    vt_api_key: Optional[str],
    logger: logging.Logger,
) -> list:
    """
    Query VT /files/{sha256}/behaviours for network IOCs.
    Returns a list of EvidenceItems, or [] on any failure.

    If vt_api_key is None, falls back to the premium key in vt_apk_downloader/config.yaml.
    """
    try:
        import requests
    except ImportError:
        logger.debug("[vt] 'requests' not installed, skipping VT enrichment")
        return []

    if not vt_api_key:
        vt_api_key = load_vt_api_key_from_config()
    if not vt_api_key:
        logger.debug("[vt] no API key available, skipping VT enrichment")
        return []

    url = _BEHAVIOURS_EP.format(sha256=sha256)
    headers = {"x-apikey": vt_api_key, "Accept": "application/json"}

    logger.info("[vt] querying behaviours for %s…", sha256[:16])

    try:
        resp = requests.get(url, headers=headers, timeout=30)
    except Exception as exc:
        logger.warning("[vt] request failed: %s", exc)
        return []

    if resp.status_code == 404:
        logger.info("[vt] sample %s not in VT, skipping", sha256[:16])
        return []
    if resp.status_code == 401:
        logger.warning("[vt] API key rejected (401)")
        return []
    if resp.status_code == 429:
        logger.warning("[vt] rate limited (429), skipping")
        return []
    if not resp.ok:
        logger.warning("[vt] unexpected status %d", resp.status_code)
        return []

    try:
        data = resp.json()
    except Exception as exc:
        logger.warning("[vt] JSON decode failed: %s", exc)
        return []

    sandboxes = data.get("data", [])
    if not sandboxes:
        logger.info("[vt] no behaviour reports for %s", sha256[:16])
        return []

    items: list = []
    seen: set = set()

    for sandbox in sandboxes:
        _items_from_sandbox_report(sandbox, seen, items, logger)

    logger.info("[vt] %d evidence items from VT behaviours (%d sandbox reports)", len(items), len(sandboxes))
    return items
