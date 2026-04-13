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

# ── Quick triage patterns ────────────────────────────────────────────────────
_SUSPICIOUS_TLD = re.compile(
    r"\b[a-z0-9-]+\.(?:ru|cn|su|top|tk|pw|xyz|kim|click|info|biz|cc)\b", re.I
)
_IP_URL  = re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", re.I)
_RAW_IP  = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_PHP_URL = re.compile(r"https?://[^\s\"']{10,}\.php", re.I)

# Ports that are benign by convention; anything else on a raw IP is suspicious
_BENIGN_PORTS = {80, 443, 8080, 8443, 53, 123}

# ── MITRE ATT&CK T-code → (behavior_tags, strength, direction) ───────────────
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

# ── IDS alert severity → (strength, direction) ────────────────────────────────
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
) -> None:
    """Extract network IOCs from a single VT sandbox report (Zenbox Android field layout)."""
    EvidenceItem, make_evidence_id = _ei()
    attrs = sandbox.get("attributes", {})
    sandbox_name = attrs.get("sandbox_name", "unknown")

    # ── IP traffic (actual field: ip_traffic) ────────────────────────────
    for entry in attrs.get("ip_traffic", []):
        ip  = str(entry.get("destination_ip") or "").strip()
        port = entry.get("destination_port", 443)
        proto = entry.get("transport_layer_protocol", "TCP")
        if not ip or ip in seen:
            continue
        seen.add(ip)
        # Non-standard port on a direct IP is a strong C2 signal
        if port not in _BENIGN_PORTS:
            direction, strength = "malicious", 0.90
            explanation = (f"Direct IP connection to {ip}:{port}/{proto} on non-standard port "
                           f"observed in VT sandbox '{sandbox_name}'")
        else:
            direction, strength = _triage_value(ip)[0], _triage_value(ip)[1]
            explanation = (f"Direct IP connection to {ip}:{port}/{proto} "
                           f"observed in VT sandbox '{sandbox_name}'")
        items.append(EvidenceItem(
            id=make_evidence_id("vt_traffic", f"{ip}:{port}", "virustotal"),
            kind="vt_traffic",
            value=f"{ip}:{port}",
            source_location=f"vt_sandbox:{sandbox_name}:ip_traffic",
            direction=direction,
            strength=strength,
            behavior_tags=["c2_networking"],
            explanation=explanation,
            benign_alternatives="CDN, analytics, or update endpoints",
        ))

    # ── Memory pattern domains (actual field: memory_pattern_domains) ────
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

    # ── Memory pattern URLs (actual field: memory_pattern_urls) ──────────
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

    # ── IDS alerts (Suricata/ET rules) ────────────────────────────────────
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

    # ── MITRE ATT&CK techniques (field: mitre_attack_techniques, uses T-codes) ─
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
            benign_alternatives="None — MITRE mapping based on observed sandbox behavior",
        ))


# ── Known-generic certificate subject values ─────────────────────────────────
# These appear in self-signed debug certs generated by build tools.
_GENERIC_CERT_SUBJECTS = {"app", "unknown", "android", "debug", "test", "example",
                          "sample", "user", "localhost", "org", "company", "name"}


def _items_from_file_report(
    attrs: Dict[str, Any],
    sha256: str,
    logger: logging.Logger,
) -> list:
    """
    Extract high-value EvidenceItems from the VT /files/{sha256} report attributes.
    Covers: AV detection ratio, suggested threat label, certificate cross-check.
    Returns [] silently on any issue (does not raise).
    """
    EvidenceItem, make_evidence_id = _ei()
    items: list = []

    # ── 1. Detection ratio ────────────────────────────────────────────────
    stats = attrs.get("last_analysis_stats", {})
    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless   = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total = malicious + suspicious + harmless + undetected
    if total > 0:
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
                benign_alternatives="FP rate for Android APKs is low when ≥10 engines agree",
            ))
        logger.info("[vt] detection: %d/%d engines malicious (%.0f%%)", malicious, total, ratio * 100)

    # ── 2. Suggested threat label (AV consensus family name) ─────────────
    ptc = attrs.get("popular_threat_classification", {})
    label = ptc.get("suggested_threat_label", "")  # e.g. "trojan.bankbot/fuad"
    if label:
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
            benign_alternatives="None — AV consensus label is highly reliable",
        ))
        logger.info("[vt] threat label: %s", label)

    # ── 3. Certificate cross-check via androguard ────────────────────────
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
                    "VT androguard confirms a generic/default certificate subject — "
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
) -> list:
    """
    Query VT /files/{sha256}/behaviours for network IOCs and download PCAP if available.
    Returns a list of EvidenceItems, or [] on any failure.

    If vt_api_key is None, falls back to the premium key in vt_apk_downloader/config.yaml.
    pcap_save_dir: directory to save PCAP files. Defaults to a 'pcaps' folder next to this module.
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

    # ── Fire both requests in parallel via threads ────────────────────────
    import concurrent.futures

    def _get_file_report():
        return requests.get(
            f"{_VT_BASE}/files/{sha256}", headers=headers, timeout=20
        )

    def _get_behaviours():
        return requests.get(
            _BEHAVIOURS_EP.format(sha256=sha256), headers=headers, timeout=30
        )

    logger.info("[vt] fetching file report + behaviours for %s…", sha256[:16])
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

    # ── File report items ─────────────────────────────────────────────────
    if resp_file is not None and resp_file.ok:
        try:
            file_attrs = resp_file.json()["data"]["attributes"]
            items.extend(_items_from_file_report(file_attrs, sha256, logger))
        except Exception as exc:
            logger.warning("[vt] file report parse error: %s", exc)
    elif resp_file is not None and resp_file.status_code == 404:
        logger.info("[vt] sample %s not in VT", sha256[:16])
        return []
    elif resp_file is not None:
        logger.warning("[vt] file report HTTP %d", resp_file.status_code)

    # ── Behaviours items ──────────────────────────────────────────────────
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
        _items_from_sandbox_report(sandbox, seen, items, logger)

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
                    benign_alternatives="PCAP is raw capture — evidence strength from IP/IDS items above",
                ))
        elif sandbox_id and attrs.get("has_pcap") is False:
            logger.debug("[vt] no PCAP for sandbox '%s'", sandbox_name)

    logger.info("[vt] %d evidence items from VT behaviours (%d sandbox report(s))", len(items), len(sandboxes))
    return items
