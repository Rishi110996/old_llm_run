"""smba_enrichment.py
--------------------
Pulls sandbox traffic + behavior data from the Zscaler BA (SMBA) UI and converts
it into EvidenceItems that feed the v2 pipeline evidence clusters.

Requirements:
    - smba_data_pull/.env  must contain ZSCALER_BASE_URL and ZSCALER_JSESSIONID
    - The sample must already exist in BA (submitted for sandbox analysis)

Entry point:
    enrich_from_smba(sha256, env_path, logger) -> List[EvidenceItem]
    Returns an empty list (silently) if SMBA is unavailable or the sample is not found.
"""
from __future__ import annotations

import logging
import os
import re
import sys
from typing import Any, Dict, List

# ── Evidence schema (lazy to avoid circular imports) ─────────────────────────
def _ei():
    from evidence_schema import EvidenceItem, make_evidence_id
    return EvidenceItem, make_evidence_id


# ── Suspicious domain / IP patterns for quick triage ─────────────────────────
_SUSPICIOUS_TLD = re.compile(
    r"\b[a-z0-9-]+\.(?:ru|cn|su|top|tk|pw|xyz|kim|click|info|biz|cc)\b", re.I
)
_IP_URL = re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", re.I)
_RAW_IP = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_PHP_URL = re.compile(r"https?://[^\s\"']{10,}\.php", re.I)

# ── SMBA behavior section → behavior family mapping ──────────────────────────
_BEHAVIOR_SECTION_MAP = {
    "spyware":         (["data_exfiltration", "call_interception"], 0.90, "malicious"),
    "stealth":         (["anti_analysis"],                          0.85, "malicious"),
    "spreading":       (["dynamic_code_loading", "persistence"],    0.85, "malicious"),
    "persistence":     (["persistence"],                            0.80, "malicious"),
    "security_bypass": (["privilege_escalation"],                   0.85, "malicious"),
    "exploiting":      (["privilege_escalation"],                   0.90, "malicious"),
    "virus_malware":   (["c2_networking", "data_exfiltration"],     0.90, "malicious"),
}

# ── MITRE ATT&CK tactic → behavior family mapping ────────────────────────────
_MITRE_TACTIC_MAP = {
    "collection":            (["data_exfiltration"],           0.75, "malicious"),
    "command-and-control":   (["c2_networking"],               0.85, "malicious"),
    "credential-access":     (["credential_theft"],            0.85, "malicious"),
    "defense-evasion":       (["anti_analysis"],               0.75, "malicious"),
    "discovery":             (["anti_analysis"],               0.55, "ambiguous"),
    "execution":             (["dynamic_code_loading"],        0.70, "malicious"),
    "exfiltration":          (["data_exfiltration"],           0.85, "malicious"),
    "impact":                (["persistence"],                 0.80, "malicious"),
    "initial-access":        (["persistence"],                 0.60, "ambiguous"),
    "lateral-movement":      (["c2_networking"],               0.80, "malicious"),
    "persistence":           (["persistence"],                 0.75, "malicious"),
    "privilege-escalation":  (["privilege_escalation"],        0.85, "malicious"),
}


def _client_available() -> bool:
    """Check if the SMBA client dependencies are installed."""
    try:
        import requests
        from dotenv import load_dotenv
        return True
    except ImportError:
        return False


def _load_smba_client(env_path: str):
    """Import and instantiate the ZscalerReportClient."""
    smba_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "smba_data_pull")
    if smba_dir not in sys.path:
        sys.path.insert(0, smba_dir)

    from zscaler_report_client import ZscalerConfig, ZscalerReportClient
    config = ZscalerConfig.from_env(env_path)
    return ZscalerReportClient(config)


def _items_from_traffic(traffic: Dict[str, Any], logger: logging.Logger) -> "List":
    """Convert SMBA traffic sections into EvidenceItems."""
    EvidenceItem, make_evidence_id = _ei()
    items = []
    seen: set = set()

    def _add_network_item(value: str, extra_explanation: str = "") -> None:
        if value in seen:
            return
        seen.add(value)

        if _IP_URL.search(value) or _RAW_IP.match(value):
            direction, strength = "malicious", 0.85
            explanation = f"Direct IP connection observed in sandbox traffic: {value}"
        elif _PHP_URL.search(value):
            direction, strength = "ambiguous", 0.60
            explanation = f"PHP endpoint observed in sandbox traffic: {value}"
        elif _SUSPICIOUS_TLD.search(value):
            direction, strength = "ambiguous", 0.55
            explanation = f"Suspicious TLD domain in sandbox traffic: {value}"
        else:
            direction, strength = "ambiguous", 0.35
            explanation = f"Network endpoint observed in sandbox traffic: {value}"

        if extra_explanation:
            explanation += f" ({extra_explanation})"

        items.append(EvidenceItem(
            id=make_evidence_id("smba_traffic", value, "smba"),
            kind="smba_traffic",
            value=value,
            source_location="smba_sandbox_traffic",
            direction=direction,
            strength=strength,
            behavior_tags=["c2_networking"],
            explanation=explanation,
            benign_alternatives="Ad/analytics SDKs, CDN endpoints, update checks",
        ))

    # HTTP/HTTPS hosts + URLs
    for proto in ("http", "https"):
        section = traffic.get(proto, {})
        if isinstance(section, dict):
            for entry in section.get("results", []):
                host = entry.get("host") or entry.get("url") or ""
                if host:
                    _add_network_item(str(host), proto.upper())
        elif isinstance(section, list):
            for entry in section:
                url = entry.get("url") or entry.get("host") or ""
                if url:
                    _add_network_item(str(url), proto.upper())

    # TCP/UDP direct IP connections
    for proto in ("tcp", "udp"):
        section = traffic.get(proto, {})
        if isinstance(section, dict):
            for entry in section.get("results", []):
                dst = entry.get("dst_ip") or entry.get("ip") or entry.get("host") or ""
                if dst:
                    _add_network_item(str(dst), f"{proto.upper()} direct")

    # DNS lookups
    dns_section = traffic.get("dns", {})
    if isinstance(dns_section, dict):
        for entry in dns_section.get("results", []):
            name = entry.get("qname") or entry.get("name") or entry.get("query") or ""
            if name:
                _add_network_item(str(name), "DNS query")

    logger.info("[smba] %d network evidence items from traffic", len(items))
    return items


def _items_from_behavior(behavior: Dict[str, Any], logger: logging.Logger) -> "List":
    """Convert SMBA behavior section flags into EvidenceItems."""
    EvidenceItem, make_evidence_id = _ei()
    items = []

    for section_name, (tags, strength, direction) in _BEHAVIOR_SECTION_MAP.items():
        section = behavior.get(section_name, {})
        if not section:
            continue
        # SMBA behavior sections are dicts with a "results" list or a top-level score
        # We treat any non-empty section as a positive signal
        result_count = 0
        if isinstance(section, dict):
            results = section.get("results", [])
            result_count = len(results) if isinstance(results, list) else (1 if results else 0)
            if not result_count:
                # Check for any other non-empty value
                result_count = 1 if any(v for v in section.values() if v) else 0
        if result_count == 0:
            continue

        items.append(EvidenceItem(
            id=make_evidence_id("smba_behavior", section_name, "smba"),
            kind="smba_behavior",
            value=f"SMBA behavior flag: {section_name} ({result_count} indicator(s))",
            source_location=f"smba_sandbox_behavior:{section_name}",
            direction=direction,
            strength=strength,
            behavior_tags=tags,
            explanation=f"Zscaler sandbox detected {section_name} behavior with {result_count} indicator(s)",
            benign_alternatives="None — SMBA sandbox behavior flag is authoritative",
        ))

    logger.info("[smba] %d behavior evidence items", len(items))
    return items


def _items_from_mitre(mitre: Dict[str, Any], logger: logging.Logger) -> "List":
    """Convert MITRE ATT&CK tactics from SMBA into EvidenceItems."""
    EvidenceItem, make_evidence_id = _ei()
    items = []

    attack = mitre.get("attack", {})
    tactics_raw = mitre.get("tactics", [])

    # Combine tactic names from both sources
    tactic_names = set()
    if isinstance(attack, dict):
        for tactic_entry in attack.get("tactics", []) or []:
            name = (tactic_entry.get("name") or "").lower().replace(" ", "-")
            if name:
                tactic_names.add(name)
    if isinstance(tactics_raw, list):
        for t in tactics_raw:
            name = (t.get("name") or t if isinstance(t, str) else "").lower().replace(" ", "-")
            if name:
                tactic_names.add(name)

    for tactic in tactic_names:
        mapping = _MITRE_TACTIC_MAP.get(tactic)
        if not mapping:
            continue
        tags, strength, direction = mapping
        items.append(EvidenceItem(
            id=make_evidence_id("smba_mitre", tactic, "smba"),
            kind="smba_mitre",
            value=f"MITRE ATT&CK tactic: {tactic}",
            source_location="smba_mitre_attack",
            direction=direction,
            strength=strength,
            behavior_tags=tags,
            explanation=f"Zscaler sandbox mapped this sample to MITRE ATT&CK tactic '{tactic}'",
            benign_alternatives="None — MITRE ATT&CK mapping is based on observed sandbox behavior",
        ))

    logger.info("[smba] %d MITRE tactic evidence items", len(items))
    return items


def enrich_from_smba(
    sha256: str,
    env_path: str,
    logger: logging.Logger,
) -> "List":
    """
    Query Zscaler SMBA sandbox for the given SHA-256 hash.
    Returns a list of EvidenceItems, or [] if unavailable/not found.

    env_path  path to the .env file containing ZSCALER_BASE_URL and ZSCALER_JSESSIONID.
    """
    if not _client_available():
        logger.debug("[smba] dependencies not installed, skipping SMBA enrichment")
        return []

    if not os.path.isfile(env_path):
        logger.debug("[smba] .env not found at %s, skipping SMBA enrichment", env_path)
        return []

    try:
        client = _load_smba_client(env_path)
    except Exception as exc:
        logger.warning("[smba] client init failed: %s", exc)
        return []

    try:
        if not client.sample_exists(sha256):
            logger.info("[smba] sample %s not found in SMBA", sha256[:16])
            return []
    except Exception as exc:
        logger.warning("[smba] sample_exists check failed: %s", exc)
        return []

    logger.info("[smba] sample found — pulling traffic + behavior + MITRE")

    try:
        report = client.get_full_report(sha256, include_artifacts=False)
    except Exception as exc:
        logger.warning("[smba] report fetch failed: %s", exc)
        return []

    items: "List" = []

    traffic  = report.get("traffic", {})
    behavior = report.get("behavior", {})
    mitre    = report.get("mitre", {})

    # Check PCAP availability and log it
    try:
        artifacts = client.get_artifacts_summary(sha256)
        pcap_info = artifacts.get("pcap", {})
        if pcap_info.get("available"):
            pcap_meta = pcap_info.get("metadata") or {}
            logger.info(
                "[smba] PCAP available for %s: size=%s  filename=%s",
                sha256[:16],
                pcap_meta.get("size", "unknown"),
                pcap_meta.get("filename", "unknown"),
            )
        else:
            logger.debug("[smba] no PCAP artifact for this sample")
    except Exception:
        pass

    items.extend(_items_from_traffic(traffic, logger))
    items.extend(_items_from_behavior(behavior, logger))
    items.extend(_items_from_mitre(mitre, logger))

    logger.info("[smba] total enrichment: %d evidence items", len(items))
    return items
