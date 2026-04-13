"""
evidence_normalizer.py
-----------------------
Converts raw APKFacts → List[EvidenceItem] using deterministic rule tables.
No LLM calls here.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Tuple, Any

from evidence_schema import APKFacts, EvidenceItem, make_evidence_id


# ---------------------------------------------------------------------------
# permission rules
# ---------------------------------------------------------------------------

# fmt: off
_PERM_RULES: Dict[str, Tuple[str, float, List[str], str, str]] = {
    # (direction, strength, behavior_tags, explanation, benign_alternatives)
    "android.permission.RECEIVE_SMS": (
        "ambiguous", 0.70, ["sms_abuse"],
        "Allows receiving SMS messages; commonly intercepted by SMS trojans",
        "Messaging apps, OTP-based 2FA apps",
    ),
    "android.permission.READ_SMS": (
        "ambiguous", 0.65, ["sms_abuse", "data_exfiltration"],
        "Allows reading the SMS inbox",
        "SMS backup apps, messaging apps",
    ),
    "android.permission.SEND_SMS": (
        "ambiguous", 0.75, ["sms_abuse"],
        "Allows sending SMS without user confirmation; used by premium-rate SMS fraud",
        "Messaging apps, SMS schedulers",
    ),
    "android.permission.BROADCAST_SMS": (
        "malicious", 0.85, ["sms_abuse"],
        "Low-level permission to broadcast raw SMS intents; almost never needed by legitimate apps",
        "System-level SMS apps only",
    ),
    "android.permission.RECEIVE_WAP_PUSH": (
        "ambiguous", 0.70, ["sms_abuse"],
        "Allows receiving WAP push (MMS) messages; exploited by some SMS trojans",
        "MMS-capable messaging apps",
    ),
    "android.permission.CALL_PHONE": (
        "ambiguous", 0.55, ["call_interception"],
        "Allows initiating phone calls without user confirmation",
        "Dialer apps, business calling apps, VoIP apps",
    ),
    "android.permission.READ_CALL_LOG": (
        "ambiguous", 0.60, ["call_interception", "data_exfiltration"],
        "Allows reading device call history",
        "Call recording apps, analytics SDKs",
    ),
    "android.permission.WRITE_CALL_LOG": (
        "ambiguous", 0.55, ["call_interception"],
        "Allows modifying the call log",
        "Dialer replacement apps",
    ),
    "android.permission.PROCESS_OUTGOING_CALLS": (
        "ambiguous", 0.65, ["call_interception"],
        "Allows intercepting and redirecting outgoing calls",
        "Call recording apps, parental control apps",
    ),
    "android.permission.BIND_ACCESSIBILITY_SERVICE": (
        "ambiguous", 0.80, ["accessibility_abuse"],
        "Grants full AccessibilityService rights; widely abused for overlay attacks and keylogging",
        "Screen readers, automation apps (AutoInput, Tasker), accessibility tools",
    ),
    "android.permission.SYSTEM_ALERT_WINDOW": (
        "ambiguous", 0.75, ["overlay_fraud"],
        "Allows drawing windows over any other app; abused by banking trojans for credential overlays",
        "Floating widget apps, chat heads, screen annotation tools",
    ),
    "android.permission.BIND_DEVICE_ADMIN": (
        "ambiguous", 0.80, ["persistence"],
        "Grants device-admin rights; used to prevent uninstall and change lock screen password",
        "MDM apps, enterprise management tools, parental control apps",
    ),
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": (
        "ambiguous", 0.70, ["data_exfiltration"],
        "Full read access to all notifications including OTP codes",
        "Notification management apps, smartwatch companion apps, Tasker",
    ),
    "android.permission.BIND_VPN_SERVICE": (
        "ambiguous", 0.75, ["c2_networking"],
        "Allows acting as a VPN provider; can intercept and redirect all device traffic",
        "Legitimate VPN apps",
    ),
    "android.permission.RECEIVE_BOOT_COMPLETED": (
        "ambiguous", 0.40, ["persistence"],
        "Allows starting on device boot; enables persistent background execution",
        "Used by the majority of apps with any background functionality",
    ),
    "android.permission.REQUEST_INSTALL_PACKAGES": (
        "ambiguous", 0.75, ["dynamic_code_loading"],
        "Allows installing APKs at runtime without the package installer UI; dropper behavior",
        "App stores, MDM, auto-update mechanisms",
    ),
    "android.permission.READ_PHONE_STATE": (
        "ambiguous", 0.45, ["data_exfiltration"],
        "Allows reading IMEI, SIM info, and phone number; device fingerprinting",
        "Analytics SDKs, anti-fraud libraries, many carrier apps",
    ),
    "android.permission.ANSWER_PHONE_CALLS": (
        "ambiguous", 0.65, ["call_interception"],
        "Programmatic call answering without user interaction",
        "VoIP apps, answering machine apps",
    ),
    "android.permission.RECORD_AUDIO": (
        "ambiguous", 0.60, ["data_exfiltration"],
        "Microphone access; can be used for covert audio recording",
        "VoIP apps, voice memos, games",
    ),
    "android.permission.CAMERA": (
        "ambiguous", 0.50, ["data_exfiltration"],
        "Camera access; can be used to take covert photos",
        "Camera apps, QR scanners, video call apps",
    ),
    "android.permission.READ_CONTACTS": (
        "ambiguous", 0.55, ["data_exfiltration"],
        "Full contacts read access; often exfiltrated to C2",
        "Messaging apps, social apps, address book synchronization",
    ),
    "android.permission.WRITE_CONTACTS": (
        "ambiguous", 0.50, ["data_exfiltration"],
        "Allows modifying or deleting contacts",
        "Messaging apps that sync contacts",
    ),
    "android.permission.WRITE_EXTERNAL_STORAGE": (
        "ambiguous", 0.35, ["data_exfiltration"],
        "Allows writing to external/shared storage; could log data for later exfiltration",
        "Almost any media-handling app uses this",
    ),
    "android.permission.READ_EXTERNAL_STORAGE": (
        "ambiguous", 0.30, ["data_exfiltration"],
        "Allows reading shared storage; could scan for documents/photos",
        "File managers, media players, photo editors",
    ),
    "android.permission.INTERNET": (
        "benign", 0.05, ["c2_networking"],
        "Basic internet permission present in almost all apps",
        "All network-connected apps",
    ),
    "android.permission.ACCESS_NETWORK_STATE": (
        "benign", 0.02, [],
        "Simple network connectivity check; entirely benign",
        "Virtually all apps",
    ),
    "android.permission.ACCESS_WIFI_STATE": (
        "benign", 0.02, [],
        "Reads Wi-Fi connection state",
        "Virtually all apps",
    ),
    "android.permission.WAKE_LOCK": (
        "benign", 0.05, ["persistence"],
        "Prevents CPU sleep; needed by background services",
        "Music players, navigation apps, any streaming service",
    ),
    "android.permission.VIBRATE": (
        "benign", 0.01, [],
        "Notification vibration; entirely benign",
        "Any app with notifications",
    ),
    "android.permission.FOREGROUND_SERVICE": (
        "benign", 0.10, ["persistence"],
        "Allows running foreground service; needed for any persistent background task",
        "Media players, fitness trackers, location services",
    ),
    "android.permission.ACCESS_FINE_LOCATION": (
        "ambiguous", 0.45, ["data_exfiltration"],
        "GPS-level location access",
        "Maps, navigation, location-based services",
    ),
    "android.permission.ACCESS_COARSE_LOCATION": (
        "ambiguous", 0.30, ["data_exfiltration"],
        "Network/cell-tower location access",
        "Weather apps, location-aware services",
    ),
    "android.permission.PACKAGE_USAGE_STATS": (
        "ambiguous", 0.55, ["anti_analysis"],
        "Allows monitoring which apps are in use; used by overlay trojans to know when banking app is open",
        "Parental control apps, battery/data managers",
    ),
    "android.permission.USE_BIOMETRIC": (
        "ambiguous", 0.35, ["credential_theft"],
        "Biometric authentication access",
        "Banking apps, password managers",
    ),
    "android.permission.MANAGE_EXTERNAL_STORAGE": (
        "ambiguous", 0.60, ["data_exfiltration"],
        "Full unrestricted file system access (Android 11+)",
        "File manager apps",
    ),
    "android.permission.READ_MEDIA_IMAGES": (
        "ambiguous", 0.35, ["data_exfiltration"],
        "Access to all photos",
        "Gallery apps, photo editors",
    ),
}
# fmt: on


# ---------------------------------------------------------------------------
# string pattern rules
# ---------------------------------------------------------------------------

@dataclass
class _StringRule:
    pattern: re.Pattern
    direction: str
    strength: float
    behavior_tags: List[str]
    explanation: str
    benign_alternatives: str


_STRING_RULES: List[_StringRule] = [
    # ── hardcoded C2 / networking ──────────────────────────────────────────
    _StringRule(
        re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", re.I),
        "malicious", 0.85, ["c2_networking"],
        "Hardcoded IP-based URL; strongly indicative of C2 endpoint",
        "Internal/dev testing endpoints",
    ),
    _StringRule(
        re.compile(r"\b(?:[a-z0-9-]{3,63}\.(?:ru|cn|su|top|tk|pw|xyz|kim|click|biz|info|cc))\b", re.I),
        "ambiguous", 0.55, ["c2_networking"],
        "Suspicious TLD domain; commonly used in malware infrastructure",
        "Legitimate Russian/Chinese apps targeting local users",
    ),
    _StringRule(
        re.compile(r"https?://[^\s\"']{10,}\.php", re.I),
        "ambiguous", 0.55, ["c2_networking"],
        "PHP endpoint URL; common pattern in malware C2 communication",
        "Legitimate web service backends may use PHP",
    ),
    _StringRule(
        re.compile(r"https?://[^\s\"']{10,}", re.I),
        "ambiguous", 0.30, ["c2_networking"],
        "Hardcoded URL; may be an API or C2 endpoint",
        "Any app that communicates with a backend server",
    ),
    # ── dynamic loading ────────────────────────────────────────────────────
    _StringRule(
        re.compile(r"\b(?:DexClassLoader|PathClassLoader|BaseDexClassLoader)\b"),
        "malicious", 0.90, ["dynamic_code_loading"],
        "Dynamic class loader class name in string literal; indicates DEX loading at runtime",
        "Hot-patch frameworks, plugin-based apps",
    ),
    _StringRule(
        re.compile(r"(?<![/\w])classes\.dex\b", re.I),
        "ambiguous", 0.50, ["dynamic_code_loading"],
        "Reference to DEX file; may indicate payload loading",
        "APK tooling, legitimate update frameworks",
    ),
    _StringRule(
        re.compile(r"(?<![/\w])[\w\-]+\.dex\b", re.I),
        "ambiguous", 0.45, ["dynamic_code_loading"],
        "Custom .dex file reference in string",
        "Plugin-based frameworks",
    ),
    # ── shell / privilege escalation ──────────────────────────────────────
    _StringRule(
        re.compile(r"\bsu\b"),
        "malicious", 0.90, ["privilege_escalation"],
        "References to 'su' (superuser) binary; root privilege escalation attempt",
        "Root management apps (SuperSU, Magisk)",
    ),
    _StringRule(
        re.compile(r"/bin/sh|/system/bin/sh|cmd\.exe", re.I),
        "malicious", 0.90, ["privilege_escalation"],
        "Shell binary path; process injection / code execution",
        "System firmware apps",
    ),
    _StringRule(
        re.compile(r"\bRuntime\.getRuntime\(\)\.exec\b"),
        "malicious", 0.85, ["privilege_escalation"],
        "Java Runtime.exec() string reference; command execution",
        "Benchmark apps, developer tools",
    ),
    _StringRule(
        re.compile(r"\bProcessBuilder\b"),
        "malicious", 0.80, ["privilege_escalation"],
        "ProcessBuilder reference; spawning OS processes",
        "Desktop-ported libraries",
    ),
    _StringRule(
        re.compile(r"\bchmod\s+[0-7]{3}", re.I),
        "malicious", 0.85, ["privilege_escalation"],
        "chmod command; changing file permissions, often used to make payloads executable",
        "Unlikely in legitimate Android apps",
    ),
    # ── anti-analysis / obfuscation ───────────────────────────────────────
    _StringRule(
        re.compile(r"\b(?:genymotion|bluestacks|nox|youwave|memu)\b", re.I),
        "ambiguous", 0.55, ["anti_analysis"],
        "Emulator detection string; app checks if running inside a sandbox",
        "Developer test code",
    ),
    _StringRule(
        re.compile(r"\bDebugger\.isAttached\b|\bis_debuggable\b|\bdebuggerConnected\b", re.I),
        "ambiguous", 0.60, ["anti_analysis"],
        "Debugger detection check; anti-analysis behavior",
        "DRM protection, hardened apps",
    ),
    _StringRule(
        re.compile(r"\bXposed\b|\bede\.xposed\b", re.I),
        "ambiguous", 0.65, ["anti_analysis"],
        "Xposed framework detection; anti-hooking check",
        "Security-sensitive apps (banking) may check for Xposed",
    ),
    # ── overlay ───────────────────────────────────────────────────────────
    _StringRule(
        re.compile(r"\bTYPE_APPLICATION_OVERLAY\b|\bTYPE_PHONE\b|\bTYPE_SYSTEM_ALERT\b"),
        "ambiguous", 0.70, ["overlay_fraud"],
        "System window type constant; drawing overlays over other apps",
        "Floating widget apps, chat heads, annotation tools",
    ),
    # ── credential theft ──────────────────────────────────────────────────
    _StringRule(
        re.compile(r"\bgetCurrentInputConnection\b|\bcommitText\b"),
        "ambiguous", 0.65, ["credential_theft"],
        "IME input connection API; can intercept keystrokes in a custom keyboard",
        "Legitimate keyboard apps (Gboard-style)",
    ),
    # ── base64 / encoded payloads ─────────────────────────────────────────
    _StringRule(
        re.compile(r"[A-Za-z0-9+/]{60,}={0,2}"),
        "ambiguous", 0.35, ["anti_analysis"],
        "Long Base64 string; may be an encoded embedded payload or C2 config",
        "Embedded images, Firebase config, certificate blobs",
    ),
    # ── hardcoded keys/hexstrings ─────────────────────────────────────────
    _StringRule(
        re.compile(r"[0-9a-fA-F]{32,}"),
        "ambiguous", 0.20, ["anti_analysis"],
        "Long hex string; may be a hardcoded RC4/AES key or command hash",
        "API keys, hash digests, Firebase sender IDs",
    ),
]


# ---------------------------------------------------------------------------
# component / intent-filter rules
# ---------------------------------------------------------------------------

# key = intent-filter action string; value = (direction, strength, behavior_tags, explanation, benign_alts)
_COMPONENT_RULES: Dict[str, Tuple[str, float, List[str], str, str]] = {
    "android.provider.Telephony.SMS_RECEIVED": (
        "ambiguous", 0.75, ["sms_abuse"],
        "Receiver registered for incoming SMS messages",
        "SMS messaging apps, OTP apps",
    ),
    "android.provider.Telephony.SMS_RECEIVED_ACTION": (
        "ambiguous", 0.75, ["sms_abuse"],
        "Receiver registered for incoming SMS messages",
        "SMS messaging apps",
    ),
    "android.provider.Telephony.SMS_DELIVER": (
        "ambiguous", 0.75, ["sms_abuse"],
        "Receiver for final SMS delivery; can intercept before system SMS app",
        "Replacement messaging apps",
    ),
    "android.provider.Telephony.WAP_PUSH_RECEIVED": (
        "ambiguous", 0.70, ["sms_abuse"],
        "Receiver for WAP push / MMS messages",
        "MMS-capable messaging apps",
    ),
    "android.intent.action.NEW_OUTGOING_CALL": (
        "ambiguous", 0.65, ["call_interception"],
        "Receiver intercepts all outgoing calls; can redirect or record them",
        "Call recording apps, parental control apps",
    ),
    "android.intent.action.BOOT_COMPLETED": (
        "ambiguous", 0.35, ["persistence"],
        "Receiver auto-starts on device boot",
        "Most background-service apps",
    ),
    "android.intent.action.LOCKED_BOOT_COMPLETED": (
        "ambiguous", 0.40, ["persistence"],
        "Receiver auto-starts on boot before screen unlock",
        "Security and alarm apps",
    ),
    "android.intent.action.REBOOT": (
        "ambiguous", 0.50, ["persistence"],
        "Triggered on reboot; ensures persistence across restarts",
        "System maintenance apps",
    ),
    "android.intent.action.MY_PACKAGE_REPLACED": (
        "ambiguous", 0.35, ["persistence"],
        "Restarts components after app update",
        "Any app with background services",
    ),
    "android.accessibilityservice.AccessibilityService": (
        "ambiguous", 0.80, ["accessibility_abuse"],
        "Service registered as AccessibilityService; high-risk for overlay and keylog attacks",
        "Screen readers, automation apps",
    ),
    "android.net.VpnService": (
        "ambiguous", 0.75, ["c2_networking"],
        "Service registered as a VPN provider; can intercept all device traffic",
        "Legitimate VPN apps",
    ),
    "android.app.admin.DeviceAdminService": (
        "ambiguous", 0.80, ["persistence"],
        "Service granted device-admin rights; can block uninstall and change lock screen",
        "MDM and enterprise management apps",
    ),
    "android.app.action.DEVICE_ADMIN_ENABLED": (
        "ambiguous", 0.75, ["persistence"],
        "Device admin activation intent; used by malware to request admin rights",
        "MDM apps",
    ),
    "android.service.notification.NotificationListenerService": (
        "ambiguous", 0.70, ["data_exfiltration"],
        "Can read all device notifications including OTP codes",
        "Notification managers, smartwatch apps, Tasker",
    ),
    "android.inputmethodservice.InputMethodService": (
        "ambiguous", 0.75, ["credential_theft"],
        "Custom keyboard / IME; can log all keystrokes",
        "Legitimate keyboard apps",
    ),
}

# Meta-data keys that indicate special service binding
_COMPONENT_META_RULES: Dict[str, Tuple[str, float, List[str], str, str]] = {
    "android.accessibilityservice": (
        "ambiguous", 0.80, ["accessibility_abuse"],
        "AccessibilityService meta-data binding",
        "Screen readers, automation apps",
    ),
    "android.app.device_admin": (
        "ambiguous", 0.80, ["persistence"],
        "Device admin receiver meta-data",
        "MDM apps",
    ),
    "android.service.notification": (
        "ambiguous", 0.70, ["data_exfiltration"],
        "NotificationListener meta-data binding",
        "Notification management apps",
    ),
}


# ---------------------------------------------------------------------------
# native lib rules
# ---------------------------------------------------------------------------

_KNOWN_BENIGN_NATIVE_PATTERNS = re.compile(
    r"(webrtc|opus|avcodec|openal|unity|cocos|gdb|lldb|flutter|"
    r"chromium|v8|angle|egl|skia|ffmpeg|libc\+\+|libjpeg|libpng|"
    r"zlib|sqlite|tflite|onnx|realm|mupdf)",
    re.I,
)


# ---------------------------------------------------------------------------
# cert rules
# ---------------------------------------------------------------------------

_DEBUG_CERT_SUBJECT_PATTERN = re.compile(
    r"android\s+debug|android\s+release|test\s+key|debug\s+key", re.I
)
_SINGLE_CHAR_ORG_PATTERN = re.compile(r'"[OC]"\s*:\s*"\w{1,2}"')


# ---------------------------------------------------------------------------
# normalizer functions
# ---------------------------------------------------------------------------

def _perm_short(full_perm: str) -> str:
    """android.permission.FOO → FOO"""
    return full_perm.rsplit(".", 1)[-1]


def normalize_permissions(permissions: List[str]) -> List[EvidenceItem]:
    items: List[EvidenceItem] = []
    for perm in permissions:
        rule = _PERM_RULES.get(perm)
        if rule is None:
            # Unknown permission — emit a very weak ambiguous item so the cluster still knows about it
            if perm.startswith("android.permission.") and _perm_short(perm) not in (
                "INTERNET", "ACCESS_NETWORK_STATE", "ACCESS_WIFI_STATE", "VIBRATE", "WAKE_LOCK"
            ):
                items.append(EvidenceItem(
                    id=make_evidence_id("permission", perm, "permissions"),
                    kind="permission",
                    value=perm,
                    source_location="permissions",
                    direction="ambiguous",
                    strength=0.15,
                    behavior_tags=[],
                    explanation="Unknown permission; may warrant further review",
                    benign_alternatives="Custom or new Android permissions",
                ))
            continue
        direction, strength, tags, explanation, benign_alts = rule
        items.append(EvidenceItem(
            id=make_evidence_id("permission", perm, "permissions"),
            kind="permission",
            value=perm,
            source_location="permissions",
            direction=direction,
            strength=strength,
            behavior_tags=tags,
            explanation=explanation,
            benign_alternatives=benign_alts,
        ))
    return items


def normalize_strings(strings_by_class: Dict[str, List[str]]) -> List[EvidenceItem]:
    items: List[EvidenceItem] = []
    seen_ids: set = set()
    for cls_name, string_list in strings_by_class.items():
        source_loc = f"class:{cls_name}"
        for s in string_list:
            if not s or len(s) < 4:
                continue
            for rule in _STRING_RULES:
                if rule.pattern.search(s):
                    eid = make_evidence_id("string", s, source_loc)
                    if eid in seen_ids:
                        continue
                    seen_ids.add(eid)
                    items.append(EvidenceItem(
                        id=eid,
                        kind="string",
                        value=s[:200],
                        source_location=source_loc,
                        direction=rule.direction,
                        strength=rule.strength,
                        behavior_tags=rule.behavior_tags,
                        explanation=rule.explanation,
                        benign_alternatives=rule.benign_alternatives,
                    ))
                    break  # first matching rule wins per string
    return items


def normalize_components(components: Dict[str, Any]) -> List[EvidenceItem]:
    """
    components dict structure:
      {activities: {name: {action: [...], ...}}, services: {...}, receivers: {...}, providers: [...]}
    """
    items: List[EvidenceItem] = []
    seen_ids: set = set()

    for comp_type in ("services", "receivers", "activities"):
        comp_dict = components.get(comp_type, {})
        if not isinstance(comp_dict, dict):
            continue
        for comp_name, filter_info in comp_dict.items():
            if not isinstance(filter_info, dict):
                continue
            source_loc = f"component:{comp_name}"

            # Check intent filter actions
            actions = filter_info.get("action", []) or []
            for action in actions:
                rule = _COMPONENT_RULES.get(action)
                if rule is None:
                    continue
                direction, strength, tags, explanation, benign_alts = rule
                eid = make_evidence_id("component", action, source_loc)
                if eid in seen_ids:
                    continue
                seen_ids.add(eid)
                items.append(EvidenceItem(
                    id=eid,
                    kind="component",
                    value=f"{comp_type}:{comp_name} [{action}]",
                    source_location=source_loc,
                    direction=direction,
                    strength=strength,
                    behavior_tags=tags,
                    explanation=explanation,
                    benign_alternatives=benign_alts,
                ))

            # Check meta-data keys
            meta = filter_info.get("meta-data", {}) or {}
            for meta_key in meta:
                for meta_pattern, meta_rule in _COMPONENT_META_RULES.items():
                    if meta_pattern in str(meta_key):
                        direction, strength, tags, explanation, benign_alts = meta_rule
                        eid = make_evidence_id("component", f"meta:{meta_key}", source_loc)
                        if eid in seen_ids:
                            continue
                        seen_ids.add(eid)
                        items.append(EvidenceItem(
                            id=eid,
                            kind="component",
                            value=f"{comp_type}:{comp_name} [meta:{meta_key}]",
                            source_location=source_loc,
                            direction=direction,
                            strength=strength,
                            behavior_tags=tags,
                            explanation=explanation,
                            benign_alternatives=benign_alts,
                        ))

            # Check permission attribute on the component
            perm = filter_info.get("permission", "")
            if perm:
                perm_rule = _PERM_RULES.get(perm)
                if perm_rule:
                    direction, strength, tags, explanation, benign_alts = perm_rule
                    eid = make_evidence_id("component", f"perm:{perm}", source_loc)
                    if eid in seen_ids:
                        continue
                    seen_ids.add(eid)
                    items.append(EvidenceItem(
                        id=eid,
                        kind="component",
                        value=f"{comp_type}:{comp_name} [permission:{perm}]",
                        source_location=source_loc,
                        direction=direction,
                        strength=strength,
                        behavior_tags=tags,
                        explanation=f"Component requires {perm}",
                        benign_alternatives=benign_alts,
                    ))

    return items


def normalize_classes(
    classes: Dict[str, str],
    class_api_scores: Dict[str, float],
    class_behavior_tags: Dict[str, List[str]],
) -> List[EvidenceItem]:
    """
    Emit one EvidenceItem per class that has API-score-derived behavior tags.
    The evidence item represents the class itself (not its strings — those come from normalize_strings).
    """
    items: List[EvidenceItem] = []
    for cls_name, source in classes.items():
        tags = class_behavior_tags.get(cls_name, [])
        score = class_api_scores.get(cls_name, 0.0)
        if not tags and score < 0.20:
            continue
        # Map score ranges to direction + strength
        if score >= 0.80:
            direction, strength = "malicious", min(1.0, score / 1.5)
        elif score >= 0.40:
            direction, strength = "ambiguous", min(0.85, score / 1.0)
        else:
            direction, strength = "ambiguous", min(0.60, score / 0.8)

        tag_str = ", ".join(tags) if tags else "general"
        items.append(EvidenceItem(
            id=make_evidence_id("class", cls_name, f"class:{cls_name}"),
            kind="class",
            value=cls_name,
            source_location=f"class:{cls_name}",
            direction=direction,
            strength=round(strength, 3),
            behavior_tags=tags or ["anti_analysis"],
            explanation=f"Class calls sensitive APIs related to: {tag_str} (score={score:.2f})",
            benign_alternatives="Legitimate app component that happens to use these APIs",
            api_score=score,
        ))
    return items


def normalize_native_libs(native_libs: List[str]) -> List[EvidenceItem]:
    items: List[EvidenceItem] = []
    for lib_path in native_libs:
        lib_name = lib_path.split("/")[-1]
        if _KNOWN_BENIGN_NATIVE_PATTERNS.search(lib_name):
            continue
        items.append(EvidenceItem(
            id=make_evidence_id("native_lib", lib_path, f"native_lib:{lib_name}"),
            kind="native_lib",
            value=lib_path,
            source_location=f"native_lib:{lib_name}",
            direction="ambiguous",
            strength=0.35,
            behavior_tags=["anti_analysis"],
            explanation="Unknown native library; native code can hide malicious logic from DEX analysis",
            benign_alternatives="Game engines, NDK networking, media processing",
        ))
    return items


def normalize_certs(certificates: List[Dict[str, Any]]) -> List[EvidenceItem]:
    items: List[EvidenceItem] = []
    for cert in certificates:
        subject = str(cert.get("subject", ""))
        issuer = str(cert.get("issuer", ""))
        source_loc = "certificate"

        # Same subject and issuer → self-signed
        if subject and issuer and subject == issuer:
            items.append(EvidenceItem(
                id=make_evidence_id("cert", "self_signed", source_loc),
                kind="cert",
                value="self-signed certificate",
                source_location=source_loc,
                direction="ambiguous",
                strength=0.20,
                behavior_tags=[],
                explanation="Self-signed certificate; most malware uses self-signed certs",
                benign_alternatives="Most independent Android apps are also self-signed",
            ))

        # Debug / test cert
        if _DEBUG_CERT_SUBJECT_PATTERN.search(subject):
            items.append(EvidenceItem(
                id=make_evidence_id("cert", "debug_cert", source_loc),
                kind="cert",
                value="debug/test certificate",
                source_location=source_loc,
                direction="ambiguous",
                strength=0.25,
                behavior_tags=[],
                explanation="Debug or test signing certificate; suggests non-production or repackaged app",
                benign_alternatives="Development builds, sideloaded beta releases",
            ))

    return items


# ---------------------------------------------------------------------------
# top-level entrypoint
# ---------------------------------------------------------------------------

def normalize_all(apk_facts: APKFacts) -> List[EvidenceItem]:
    """Convert all APKFacts into a flat list of EvidenceItems."""
    items: List[EvidenceItem] = []
    items.extend(normalize_permissions(apk_facts.permissions))
    items.extend(normalize_strings(apk_facts.strings))
    items.extend(normalize_components(apk_facts.components))
    items.extend(normalize_classes(
        apk_facts.classes,
        apk_facts.class_api_scores,
        apk_facts.class_behavior_tags,
    ))
    items.extend(normalize_native_libs(apk_facts.native_libs))
    items.extend(normalize_certs(apk_facts.certificates))
    return items
