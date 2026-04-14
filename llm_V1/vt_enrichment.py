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

# -- VT API constants ----------------------------------------------------------
_VT_BASE = "https://www.virustotal.com/api/v3"
_BEHAVIOURS_EP = _VT_BASE + "/files/{sha256}/behaviours"
_PCAP_EP       = _VT_BASE + "/file_behaviours/{sandbox_id}/pcap"

# -- Quick triage patterns ----------------------------------------------------
_SUSPICIOUS_TLD = re.compile(
    r"\b[a-z0-9-]+\.(?:ru|cn|su|top|tk|pw|xyz|kim|click|info|biz|cc)\b", re.I
)
_IP_URL  = re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", re.I)
_RAW_IP  = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_PHP_URL = re.compile(r"https?://[^\s\"']{10,}\.php", re.I)

# Ports that are benign by convention; anything else on a raw IP is suspicious
_BENIGN_PORTS = {80, 443, 8080, 8443, 53, 123}

# ---------------------------------------------------------------------------
# Known-benign IP prefixes.
# IPs matching these prefixes belong to Google, Cloudflare, AWS, Akamai,
# Apple, Microsoft, Meta, Fastly, and Zscaler.
# They are downgraded to ambiguous/low-strength instead of auto-malicious.
# ---------------------------------------------------------------------------
_BENIGN_IP_PREFIXES = [
    # Google / Firebase / GCM
    "8.8.", "8.34.", "8.35.",
    "64.233.", "66.102.", "66.249.", "72.14.", "74.125.",
    "104.132.", "104.133.", "104.154.", "104.155.", "104.196.",
    "108.177.", "130.211.",
    "142.250.", "142.251.",
    "172.217.", "172.253.", "173.194.", "173.195.", "173.196.",
    "192.178.", "199.36.", "207.223.", "209.85.", "216.239.", "216.58.",
    # Cloudflare
    "1.0.0.", "1.1.1.",
    "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.",
    "104.22.", "104.23.", "104.24.", "104.25.", "104.26.", "104.27.",
    "162.158.", "172.64.", "172.65.", "172.66.", "172.67.",
    "188.114.", "190.93.", "197.234.", "198.41.",
    # Amazon AWS / CloudFront
    "13.32.", "13.33.", "13.35.", "13.224.", "13.225.", "13.226.",
    "13.227.", "13.249.", "15.197.", "18.160.", "18.164.", "18.165.",
    "52.84.", "52.85.", "52.222.", "54.230.", "54.239.",
    "143.204.", "205.251.",
    # Akamai
    "23.0.", "23.32.", "23.33.", "23.34.", "23.35.", "23.36.",
    "23.37.", "23.38.", "23.39.", "23.40.", "23.41.", "23.42.",
    "23.43.", "23.44.", "23.45.", "23.46.", "23.47.", "23.48.",
    "23.49.", "23.50.", "23.51.", "23.52.", "23.53.", "23.54.",
    "23.55.", "23.56.", "23.57.", "23.58.", "23.59.", "23.60.",
    "23.61.", "23.62.", "23.63.", "23.64.", "23.65.", "23.66.",
    "23.67.", "23.193.", "23.194.", "23.195.", "23.196.",
    "63.80.", "72.246.", "96.16.", "96.17.",
    "104.64.", "104.65.", "104.66.", "104.67.", "104.68.", "104.69.",
    "104.70.", "104.71.", "104.72.", "104.73.", "104.74.", "104.75.",
    "104.76.", "104.77.", "104.78.", "104.79.", "104.80.", "104.81.",
    "104.82.", "104.83.", "104.84.", "104.85.", "104.86.", "104.87.",
    "184.24.", "184.25.", "184.26.", "184.27.", "184.28.", "184.29.",
    "184.30.", "184.31.", "184.50.", "184.51.", "184.84.", "184.85.",
    # Microsoft / Azure
    "13.64.", "13.65.", "13.66.", "13.67.", "13.68.", "13.69.",
    "13.70.", "13.71.", "13.72.", "13.73.", "13.74.", "13.75.",
    "13.76.", "13.77.", "13.78.", "13.79.", "13.80.", "13.81.",
    "20.36.", "20.37.", "20.38.", "20.39.", "20.40.", "20.41.",
    "20.42.", "20.43.", "20.44.", "20.45.", "20.46.", "20.47.",
    "40.64.", "40.65.", "40.66.", "40.67.", "40.68.", "40.69.",
    "40.70.", "40.71.", "40.72.", "40.73.", "40.74.", "40.75.",
    "52.224.", "52.225.", "52.226.", "52.228.", "52.229.", "52.230.",
    # Apple
    "17.0.", "17.1.", "17.2.", "17.3.", "17.4.", "17.5.",
    "17.6.", "17.7.", "17.8.", "17.9.",
    "17.32.", "17.33.", "17.34.", "17.35.",
    # Meta / Facebook
    "31.13.", "66.220.", "69.63.", "69.171.",
    "157.240.", "163.70.", "163.71.", "163.72.", "179.60.",
    "185.60.", "204.15.",
    # Fastly
    "23.235.", "43.249.", "103.244.", "103.245.", "103.246.",
    "103.247.", "151.101.", "157.52.", "167.82.",
    "185.31.",
    # Zscaler cloud
    "136.226.", "147.161.", "165.225.", "170.85.",
]


def _is_known_benign_ip(ip: str) -> bool:
    """Return True if the IP belongs to a known-benign CDN/cloud provider."""
    for prefix in _BENIGN_IP_PREFIXES:
        if ip.startswith(prefix):
            return True
    return False


# VT IP reputation in-process cache {ip -> result_dict or None}
_VT_IP_REPUTATION_CACHE: Dict[str, Optional[Dict[str, Any]]] = {}


def _check_ip_reputation(
    ip: str,
    vt_api_key: Optional[str],
    logger: logging.Logger,
) -> Optional[Dict[str, Any]]:
    """
    Query VT /ip_addresses/{ip} for reputation data.
    Returns a dict with malicious/suspicious/harmless/undetected/total/owner/country,
    or None on error or rate-limit.
    Results are cached per-process to avoid redundant API calls.
    """
    if not vt_api_key:
        return None
    if ip in _VT_IP_REPUTATION_CACHE:
        return _VT_IP_REPUTATION_CACHE[ip]
    try:
        import requests as _req
        r = _req.get(
            f"{_VT_BASE}/ip_addresses/{ip}",
            headers={"x-apikey": vt_api_key, "Accept": "application/json"},
            timeout=10,
        )
        if r.status_code == 429:
            logger.debug("[vt_ip] rate limited on IP reputation lookup for %s", ip)
            _VT_IP_REPUTATION_CACHE[ip] = None
            return None
        if not r.ok:
            _VT_IP_REPUTATION_CACHE[ip] = None
            return None
        attrs = r.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        result = {
            "malicious":  int(stats.get("malicious", 0)),
            "suspicious": int(stats.get("suspicious", 0)),
            "harmless":   int(stats.get("harmless", 0)),
            "undetected": int(stats.get("undetected", 0)),
            "total":      sum(stats.get(k, 0) for k in ("malicious", "suspicious", "harmless", "undetected")),
            "community_score": int(attrs.get("reputation", 0)),
            "owner":      str(attrs.get("as_owner") or ""),
            "country":    str(attrs.get("country") or ""),
        }
        _VT_IP_REPUTATION_CACHE[ip] = result
        logger.debug("[vt_ip] %s -> mal=%d harm=%d owner=%s",
                     ip, result["malicious"], result["harmless"], result["owner"])
        return result
    except Exception as exc:
        logger.debug("[vt_ip] reputation check failed for %s: %s", ip, exc)
        _VT_IP_REPUTATION_CACHE[ip] = None
        return None


def _triage_ip(
    ip: str,
    port: int,
    proto: str,
    sandbox_name: str,
    vt_api_key: Optional[str],
    logger: logging.Logger,
) -> tuple:
    """
    Triage a sandbox IP connection.
    Returns (direction, strength, explanation, benign_alternatives).

    Decision logic:
    1. Known CDN prefix + benign port              -> ambiguous 0.15 (skip)
    2. Known CDN prefix + non-standard port        -> check VT rep; malicious 0.75 or ambiguous 0.35
    3. Non-CDN + non-standard port + VT flagged    -> malicious 0.85-0.97
    4. Non-CDN + non-standard port + VT clean      -> ambiguous 0.45
    5. Non-CDN + non-standard port + no VT data   -> malicious 0.90
    6. Non-CDN + benign port + VT flagged >=5      -> malicious 0.65-0.95
    7. Non-CDN + benign port + VT flagged 1-4      -> ambiguous 0.55
    8. Non-CDN + benign port + VT clean            -> ambiguous 0.20
    9. Non-CDN + benign port + no VT data          -> ambiguous 0.55
    """
    is_cdn = _is_known_benign_ip(ip)
    is_nonstandard = port not in _BENIGN_PORTS

    if is_nonstandard:
        if is_cdn:
            rep = _check_ip_reputation(ip, vt_api_key, logger)
            if rep is not None and rep["malicious"] == 0 and rep["harmless"] > 5:
                return (
                    "ambiguous", 0.35,
                    f"Known CDN IP {ip}:{port}/{proto} on non-standard port -- VT reputation clean (owner: {rep.get('owner', '?')})",
                    "CDN/cloud IP on alternative port (e.g. STUN/QUIC)",
                )
            owner = (rep or {}).get("owner", "?")
            return (
                "malicious", 0.75,
                f"CDN IP {ip}:{port}/{proto} on non-standard port in sandbox '{sandbox_name}' -- possible C2 tunnelling (owner: {owner})",
                "Some CDN IPs serve QUIC/STUN on non-standard ports",
            )
        # Non-CDN, non-standard port
        rep = _check_ip_reputation(ip, vt_api_key, logger)
        if rep is not None:
            if rep["malicious"] >= 3:
                return (
                    "malicious", min(0.97, 0.85 + rep["malicious"] * 0.01),
                    f"IP {ip}:{port}/{proto} non-standard port; VT: {rep['malicious']} engines flagged (owner: {rep.get('owner', '?')})",
                    "None -- flagged by VT engines on non-standard port",
                )
            if rep["malicious"] == 0 and rep["harmless"] > 5:
                return (
                    "ambiguous", 0.45,
                    f"IP {ip}:{port}/{proto} non-standard port but VT reputation clean (owner: {rep.get('owner', '?')})",
                    "Legitimate service on non-standard port",
                )
        return (
            "malicious", 0.90,
            f"Direct IP {ip}:{port}/{proto} on non-standard port in VT sandbox '{sandbox_name}'",
            "CDN or legitimate backend on unusual port",
        )

    # Standard port
    if is_cdn:
        return (
            "ambiguous", 0.15,
            f"Known CDN/cloud IP {ip}:{port}/{proto} -- likely legitimate app backend",
            "Google, Cloudflare, AWS, Akamai, Apple, Microsoft CDN",
        )

    # Non-CDN, standard port
    rep = _check_ip_reputation(ip, vt_api_key, logger)
    if rep is not None:
        if rep["malicious"] >= 5:
            return (
                "malicious", min(0.95, 0.65 + rep["malicious"] * 0.015),
                f"IP {ip}:{port}/{proto}; VT: {rep['malicious']} engines flagged (owner: {rep.get('owner', '?')})",
                "None -- multiple VT engines flagged this IP",
            )
        if rep["malicious"] >= 1:
            return (
                "ambiguous", 0.55,
                f"IP {ip}:{port}/{proto}; VT: {rep['malicious']} engine(s) flagged (owner: {rep.get('owner', '?')})",
                "Low detection count -- may be false positive",
            )
        if rep["malicious"] == 0 and rep["harmless"] > 5:
            return (
                "ambiguous", 0.20,
                f"IP {ip}:{port}/{proto}; VT reputation clean (owner: {rep.get('owner', '?')})",
                "Legitimate server with clean VT reputation",
            )

    # No VT data
    return (
        "ambiguous", 0.55,
        f"Direct IP {ip}:{port}/{proto} in VT sandbox '{sandbox_name}' (no VT reputation data available)",
        "CDN, analytics, or legitimate backend",
    )


# -- MITRE ATT&CK T-code -> (behavior_tags, strength, direction) ---------------
# Keyed by technique-id prefix (covers subtechniques via startswith match)
_MITRE_TCODE_MAP = {
    # Collection
    "T1429": (["data_exfiltration"],                       0.80, "malicious"),  # Capture Audio
    "T1430": (["data_exfiltration"],                       0.75, "malicious"),  # Location Tracking
    "T1513": (["data_exfiltration"],                       0.90, "malicious"),  # Screen Capture
    "T1636": (["data_exfiltration", "call_interception"],  0.80, "malicious"),  # Contact/Call/SMS
    # Credential Access
    "T1411": (["overlay_fraud", "credential_theft"],       0.90, "malicious"),  # Input Prompt
    "T1417": (["credential_theft"],                        0.90, "malicious"),  # Input Capture
    # C2 / Network
    "T1071": (["c2_networking"],                           0.70, "malicious"),  # App Layer Protocol
    "T1095": (["c2_networking"],                           0.80, "malicious"),  # Non-App Layer Proto
    "T1571": (["c2_networking"],                           0.85, "malicious"),  # Non-Standard Port
    "T1573": (["c2_networking", "anti_analysis"],          0.70, "malicious"),  # Encrypted Channel
    "T1437": (["c2_networking"],                           0.65, "malicious"),  # App Layer Proto
    "T1481": (["c2_networking"],                           0.70, "malicious"),  # Web Service abuse
    # Exfiltration
    "T1041": (["data_exfiltration", "c2_networking"],      0.85, "malicious"),  # Exfil over C2
    "T1532": (["data_exfiltration"],                       0.80, "malicious"),  # Data Encrypted
    # Defense Evasion
    "T1406": (["anti_analysis"],                           0.80, "malicious"),  # Obfuscated Files
    "T1418": (["anti_analysis"],                           0.55, "ambiguous"),  # Software Discovery
    "T1661": (["anti_analysis"],                           0.70, "malicious"),  # App Versioning
    # Execution
    "T1407": (["dynamic_code_loading"],                    0.90, "malicious"),  # Download New Code
    "T1059": (["dynamic_code_loading"],                    0.80, "malicious"),  # Command & Scripting
    # Persistence
    "T1402": (["persistence"],                             0.75, "malicious"),  # Broadcast Receivers
    "T1603": (["persistence"],                             0.75, "malicious"),  # Scheduled Task
    "T1624": (["persistence"],                             0.75, "malicious"),  # Event Triggered Exec
    # Privilege Escalation
    "T1404": (["privilege_escalation"],                    0.90, "malicious"),  # Exploit PE
    "T1626": (["privilege_escalation"],                    0.85, "malicious"),  # Abuse Elevation
    # Accessibility abuse (Android-specific)
    "T1616": (["accessibility_abuse"],                     0.90, "malicious"),  # Call Control
    "T1517": (["accessibility_abuse"],                     0.85, "malicious"),  # Access Notifications
}

# -- IDS alert severity -> (strength, direction) --------------------------------
_IDS_SEVERITY_MAP = {
    "critical": (0.90, "malicious"),
    "high":     (0.80, "malicious"),
    "medium":   (0.60, "ambiguous"),
    "low":      (0.40, "ambiguous"),
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


def _items_from_sandbox_report(
    sandbox: Dict[str, Any],
    seen: set,
    items: list,
    logger: logging.Logger,
    vt_api_key: Optional[str] = None,
) -> None:
    """Extract network IOCs from a single VT sandbox report (Zenbox Android field layout)."""
    EvidenceItem, make_evidence_id = _ei()
    attrs = sandbox.get("attributes", {})
    sandbox_name = attrs.get("sandbox_name", "unknown")

    # -- IP traffic (actual field: ip_traffic) ----------------------------
    for entry in attrs.get("ip_traffic", []):
        ip  = str(entry.get("destination_ip") or "").strip()
        port = int(entry.get("destination_port") or 443)
        proto = str(entry.get("transport_layer_protocol") or "TCP")
        if not ip or ip in seen:
            continue
        seen.add(ip)
        direction, strength, explanation, benign_alts = _triage_ip(
            ip, port, proto, sandbox_name, vt_api_key, logger
        )
        # Skip very-low-strength CDN items to reduce noise
        if strength < 0.20:
            logger.debug("[vt_ip] skipping known-CDN IP %s:%d (strength=%.2f)", ip, port, strength)
            continue
        items.append(EvidenceItem(
            id=make_evidence_id("vt_traffic", f"{ip}:{port}", "virustotal"),
            kind="vt_traffic",
            value=f"{ip}:{port}",
            source_location=f"vt_sandbox:{sandbox_name}:ip_traffic",
            direction=direction,
            strength=strength,
            behavior_tags=["c2_networking"],
            explanation=explanation,
            benign_alternatives=benign_alts,
        ))

    # -- Memory pattern domains (actual field: memory_pattern_domains) ----
    for raw in attrs.get("memory_pattern_domains", []):
        val = str(raw).strip()
        if not val or val in seen:
            continue
        seen.add(val)
        direction, strength, detail = _triage_value(val)
        items.append(EvidenceItem(
            id=make_evidence_id("vt_traffic", val, "virustotal"),
            kind="vt_traffic",
            value=val,
            source_location=f"vt_sandbox:{sandbox_name}:memory_pattern_domains",
            direction=direction,
            strength=strength,
            behavior_tags=["c2_networking"],
            explanation=f"{detail} found in memory patterns in VT sandbox '{sandbox_name}': {val}",
            benign_alternatives="SDK, CDN, or analytics domain",
        ))

    # -- Memory pattern URLs (actual field: memory_pattern_urls) ----------
    for raw in attrs.get("memory_pattern_urls", []):
        val = str(raw).strip()
        if not val or val in seen:
            continue
        # Skip well-known benign schema/SDK URLs
        if "schema" in val.lower() or "android.com" in val.lower():
            continue
        seen.add(val)
        direction, strength, detail = _triage_value(val)
        items.append(EvidenceItem(
            id=make_evidence_id("vt_traffic", val, "virustotal"),
            kind="vt_traffic",
            value=val,
            source_location=f"vt_sandbox:{sandbox_name}:memory_pattern_urls",
            direction=direction,
            strength=strength,
            behavior_tags=["c2_networking"],
            explanation=f"{detail} found in memory pattern URLs in VT sandbox '{sandbox_name}': {val}",
            benign_alternatives="SDK or library endpoint",
        ))

    # -- IDS alerts (Suricata/ET rules) ------------------------------------
    for alert in attrs.get("ids_alerts", []):
        severity = str(alert.get("alert_severity") or "low").lower()
        rule_msg = alert.get("rule_msg") or ""
        rule_cat = alert.get("rule_category") or ""
        ctx = alert.get("alert_context") or {}
        dest_ip = ctx.get("dest_ip") or ctx.get("destination_ip") or ""
        src_ip  = ctx.get("src_ip") or ctx.get("source_ip") or ""
        ioc_ip  = dest_ip or src_ip

        strength, direction = _IDS_SEVERITY_MAP.get(severity, (0.40, "ambiguous"))

        # Escalate anything tagged trojan/malware/rat/bot by ET
        if any(w in rule_msg.lower() for w in ("trojan", "malware", "rat", "bot", "c2", "c&c", "backdoor")):
            direction, strength = "malicious", max(strength, 0.85)
        if any(w in rule_cat.lower() for w in ("trojan", "malware")):
            direction, strength = "malicious", max(strength, 0.85)

        key = f"ids:{rule_msg[:40]}"
        if key in seen:
            continue
        seen.add(key)

        value = f"{rule_msg} [{ioc_ip}]" if ioc_ip else rule_msg
        items.append(EvidenceItem(
            id=make_evidence_id("vt_ids", key, "virustotal"),
            kind="vt_ids_alert",
            value=value,
            source_location=f"vt_sandbox:{sandbox_name}:ids_alerts",
            direction=direction,
            strength=strength,
            behavior_tags=["c2_networking"],
            explanation=f"IDS rule triggered in VT sandbox '{sandbox_name}' ({severity}): {rule_msg}",
            benign_alternatives="False positive Suricata rule on legitimate traffic",
        ))

        # Also add the dest IP from the IDS alert context as its own IOC
        if ioc_ip and ioc_ip not in seen:
            seen.add(ioc_ip)
            d2, s2, det2 = _triage_value(ioc_ip)
            items.append(EvidenceItem(
                id=make_evidence_id("vt_traffic", ioc_ip, "virustotal"),
                kind="vt_traffic",
                value=ioc_ip,
                source_location=f"vt_sandbox:{sandbox_name}:ids_alert_context",
                direction=direction,
                strength=strength,
                behavior_tags=["c2_networking"],
                explanation=f"IP from IDS alert in VT sandbox '{sandbox_name}': {rule_msg}",
                benign_alternatives="CDN or analytics IP",
            ))

    # -- MITRE ATT&CK techniques (field: mitre_attack_techniques, uses T-codes) -
    for t in attrs.get("mitre_attack_techniques", []):
        tid = (t.get("id") or "").upper() if isinstance(t, dict) else str(t).upper()
        if not tid:
            continue
        # Match by prefix (covers subtechniques T1636.001 etc.)
        mapping = None
        for prefix, m in _MITRE_TCODE_MAP.items():
            if tid.startswith(prefix):
                mapping = m
                break
        if not mapping:
            continue
        key = f"mitre:{tid}"
        if key in seen:
            continue
        seen.add(key)
        tags, strength, direction = mapping
        desc = t.get("signature_description", "") if isinstance(t, dict) else ""
        items.append(EvidenceItem(
            id=make_evidence_id("vt_mitre", tid, "virustotal"),
            kind="vt_mitre",
            value=f"MITRE {tid}: {desc}",
            source_location=f"vt_sandbox:{sandbox_name}:mitre",
            direction=direction,
            strength=strength,
            behavior_tags=tags,
            explanation=f"VT sandbox '{sandbox_name}' mapped to MITRE {tid}: {desc}",
            benign_alternatives="None -- MITRE mapping based on observed sandbox behavior",
        ))


# -- Known-generic certificate subject values ---------------------------------
# These appear in self-signed debug certs generated by build tools.
_GENERIC_CERT_SUBJECTS = {"app", "unknown", "android", "debug", "test", "example",
                          "sample", "user", "localhost", "org", "company", "name"}


def _items_from_file_report(
    attrs: Dict[str, Any],
    sha256: str,
    logger: logging.Logger,
    skip_detection: bool = False,
) -> list:
    """
    Extract high-value EvidenceItems from the VT /files/{sha256} report attributes.
    Covers: AV detection ratio, suggested threat label, certificate cross-check.

    skip_detection: if True, omits vt_detection and vt_threat_label items.
    Use this when analysing VT-sourced samples where detection is already known.
    Returns [] silently on any issue (does not raise).
    """
    EvidenceItem, make_evidence_id = _ei()
    items: list = []

    # -- 1. Detection ratio ------------------------------------------------
    stats = attrs.get("last_analysis_stats", {})
    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless   = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total = malicious + suspicious + harmless + undetected
    if total > 0 and not skip_detection:
        ratio = (malicious + suspicious) / total
        if ratio >= 0.30:
            direction, strength = "malicious", min(0.95, 0.55 + ratio)
        elif ratio >= 0.10:
            direction, strength = "malicious", 0.70
        elif malicious == 0 and suspicious == 0 and undetected > 10:
            direction, strength = "benign", 0.55
        else:
            direction = strength = None  # too ambiguous to add signal

        if direction:
            items.append(EvidenceItem(
                id=make_evidence_id("vt_detection", sha256, "virustotal"),
                kind="vt_detection",
                value=f"VT detection: {malicious}/{total} engines ({ratio*100:.0f}%)",
                source_location="vt_file_report:last_analysis_stats",
                direction=direction,
                strength=strength,
                behavior_tags=["c2_networking"] if direction == "malicious" else ["normal_app_behavior"],
                explanation=(
                    f"{malicious} of {total} AV engines flagged this file as malicious "
                    f"({'%.0f' % (ratio*100)}% detection rate)"
                ),
                benign_alternatives="FP rate for Android APKs is low when >=10 engines agree",
            ))
        logger.info("[vt] detection: %d/%d engines malicious (%.0f%%)", malicious, total, ratio * 100)

    # -- 2. Suggested threat label (AV consensus family name) -------------
    ptc = attrs.get("popular_threat_classification", {})
    label = ptc.get("suggested_threat_label", "")  # e.g. "trojan.bankbot/fuad"
    if label and not skip_detection:
        # Map generic threat category words to behavior tags
        label_lower = label.lower()
        if any(w in label_lower for w in ("banker", "bankbot", "bank")):
            tags = ["overlay_fraud", "credential_theft", "c2_networking"]
        elif any(w in label_lower for w in ("spy", "rat", "stealer")):
            tags = ["data_exfiltration", "call_interception"]
        elif any(w in label_lower for w in ("dropper", "loader", "downloader")):
            tags = ["dynamic_code_loading"]
        elif any(w in label_lower for w in ("ransom", "locker")):
            tags = ["persistence", "data_exfiltration"]
        else:
            tags = ["c2_networking"]

        items.append(EvidenceItem(
            id=make_evidence_id("vt_label", label, "virustotal"),
            kind="vt_threat_label",
            value=f"VT consensus label: {label}",
            source_location="vt_file_report:popular_threat_classification",
            direction="malicious",
            strength=0.95,
            behavior_tags=tags,
            explanation=(
                f"VirusTotal AV consensus classifies this file as '{label}' "
                f"based on {sum(e.get('count',0) for e in ptc.get('popular_threat_name',[]))} engine agreement(s)"
            ),
            benign_alternatives="None -- AV consensus label is highly reliable",
        ))
        logger.info("[vt] threat label: %s", label)

    # -- 3. Certificate cross-check via androguard ------------------------
    cert = attrs.get("androguard", {}).get("certificate", {})
    if cert:
        subj = cert.get("Subject", {})
        cn = str(subj.get("CN") or subj.get("O") or "").strip().lower()
        thumbprint = str(cert.get("thumbprint") or "").strip().lower()

        if cn in _GENERIC_CERT_SUBJECTS:
            items.append(EvidenceItem(
                id=make_evidence_id("vt_cert", thumbprint or cn, "virustotal"),
                kind="vt_cert",
                value=f"Certificate CN='{subj.get('CN')}' O='{subj.get('O')}' (VT-confirmed generic)",
                source_location="vt_file_report:androguard.certificate",
                direction="ambiguous",
                strength=0.35,
                behavior_tags=["anti_analysis"],
                explanation=(
                    "VT androguard confirms a generic/default certificate subject -- "
                    "typical of malware built with default keytool settings"
                ),
                benign_alternatives="Some legitimate small-developer apps also use generic CN values",
            ))
            logger.info("[vt] cert: generic subject CN='%s'", subj.get('CN'))

    return items


def _download_pcap(
    sandbox_id: str,
    sha256: str,
    vt_api_key: str,
    save_dir: str,
    logger: logging.Logger,
) -> Optional[str]:
    """Download the PCAP for a sandbox report and save it to save_dir.
    Returns the saved file path, or None on failure."""
    import requests
    save_path = os.path.join(save_dir, f"{sha256[:16]}_{sandbox_id.split('_')[-1].replace(' ', '_')}.pcap")
    if os.path.isfile(save_path):
        logger.info("[vt] PCAP already exists: %s", save_path)
        return save_path
    try:
        r = requests.get(
            _PCAP_EP.format(sandbox_id=sandbox_id),
            headers={"x-apikey": vt_api_key, "Accept": "application/octet-stream"},
            timeout=120,
            stream=True,
        )
        if not r.ok:
            logger.warning("[vt] PCAP download failed: HTTP %d for %s", r.status_code, sandbox_id)
            return None
        os.makedirs(save_dir, exist_ok=True)
        with open(save_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=65536):
                f.write(chunk)
        size_kb = os.path.getsize(save_path) // 1024
        logger.info("[vt] PCAP saved: %s (%d KB)", save_path, size_kb)
        return save_path
    except Exception as exc:
        logger.warning("[vt] PCAP download error: %s", exc)
        return None


def enrich_from_vt(
    sha256: str,
    vt_api_key: Optional[str],
    logger: logging.Logger,
    pcap_save_dir: Optional[str] = None,
    skip_detection: bool = False,
) -> list:
    """
    Query VT /files/{sha256}/behaviours for network IOCs and download PCAP if available.
    Returns a list of EvidenceItems, or [] on any failure.

    If vt_api_key is None, falls back to the premium key in vt_apk_downloader/config.yaml.
    pcap_save_dir: directory to save PCAP files. Defaults to a 'pcaps' folder next to this module.
    skip_detection: omit vt_detection and vt_threat_label items. Use when analysing
                    VT-sourced samples where the detection verdict is already known,
                    to avoid double-counting AV signals in the score.
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

    headers = {"x-apikey": vt_api_key, "Accept": "application/json"}

    # -- Fire both requests in parallel via threads ------------------------
    import concurrent.futures

    def _get_file_report():
        return requests.get(
            f"{_VT_BASE}/files/{sha256}", headers=headers, timeout=20
        )

    def _get_behaviours():
        return requests.get(
            _BEHAVIOURS_EP.format(sha256=sha256), headers=headers, timeout=30
        )

    logger.info("[vt] fetching file report + behaviours for %s...", sha256[:16])
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        fut_file = pool.submit(_get_file_report)
        fut_beh  = pool.submit(_get_behaviours)
        try:
            resp_file = fut_file.result(timeout=25)
        except Exception as exc:
            logger.warning("[vt] file report request failed: %s", exc)
            resp_file = None
        try:
            resp_beh = fut_beh.result(timeout=35)
        except Exception as exc:
            logger.warning("[vt] behaviours request failed: %s", exc)
            resp_beh = None

    # Central auth/rate check
    for resp in (resp_file, resp_beh):
        if resp is None:
            continue
        if resp.status_code == 401:
            logger.warning("[vt] API key rejected (401)")
            return []
        if resp.status_code == 429:
            logger.warning("[vt] rate limited (429), skipping")
            return []

    items: list = []
    seen: set   = set()

    # -- File report items -------------------------------------------------
    if resp_file is not None and resp_file.ok:
        try:
            file_attrs = resp_file.json()["data"]["attributes"]
            items.extend(_items_from_file_report(file_attrs, sha256, logger, skip_detection=skip_detection))
        except Exception as exc:
            logger.warning("[vt] file report parse error: %s", exc)
    elif resp_file is not None and resp_file.status_code == 404:
        logger.info("[vt] sample %s not in VT", sha256[:16])
        return []
    elif resp_file is not None:
        logger.warning("[vt] file report HTTP %d", resp_file.status_code)

    # -- Behaviours items --------------------------------------------------
    sandboxes: list = []
    if resp_beh is not None and resp_beh.ok:
        try:
            sandboxes = resp_beh.json().get("data", [])
        except Exception as exc:
            logger.warning("[vt] behaviours parse error: %s", exc)
    elif resp_beh is not None and resp_beh.status_code != 404:
        logger.warning("[vt] behaviours HTTP %d", resp_beh.status_code)

    if not sandboxes:
        logger.info("[vt] no behaviour reports for %s", sha256[:16])

    if pcap_save_dir is None:
        pcap_save_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pcaps")

    for sandbox in sandboxes:
        _items_from_sandbox_report(sandbox, seen, items, logger, vt_api_key=vt_api_key)

        # Download PCAP if available for this sandbox
        attrs = sandbox.get("attributes", {})
        sandbox_id = sandbox.get("id", "")
        sandbox_name = attrs.get("sandbox_name", "unknown")
        if attrs.get("has_pcap") and sandbox_id:
            pcap_path = _download_pcap(sandbox_id, sha256, vt_api_key, pcap_save_dir, logger)
            if pcap_path:
                EvidenceItem, make_evidence_id = _ei()
                items.append(EvidenceItem(
                    id=make_evidence_id("vt_pcap", sandbox_id, "virustotal"),
                    kind="vt_pcap",
                    value=f"PCAP captured: {os.path.basename(pcap_path)}",
                    source_location=f"vt_sandbox:{sandbox_name}:pcap",
                    direction="ambiguous",
                    strength=0.10,
                    behavior_tags=["c2_networking"],
                    explanation=(f"Full network PCAP from VT sandbox '{sandbox_name}' saved to: "
                                 f"{pcap_path} ({os.path.getsize(pcap_path)//1024} KB)"),
                    benign_alternatives="PCAP is raw capture -- evidence strength from IP/IDS items above",
                ))
        elif sandbox_id and attrs.get("has_pcap") is False:
            logger.debug("[vt] no PCAP for sandbox '%s'", sandbox_name)

    logger.info("[vt] %d evidence items from VT behaviours (%d sandbox report(s))", len(items), len(sandboxes))
    return items
