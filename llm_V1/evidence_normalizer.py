"""
evidence_normalizer.py
-----------------------
Converts raw APKFacts -> List[EvidenceItem] using deterministic rule tables.
No LLM calls here.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Tuple, Any, Optional

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
    # -- hardcoded C2 / networking ------------------------------------------
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
    # -- dynamic loading ----------------------------------------------------
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
    # -- shell / privilege escalation --------------------------------------
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
    # -- anti-analysis / obfuscation ---------------------------------------
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
    # -- overlay -----------------------------------------------------------
    _StringRule(
        re.compile(r"\bTYPE_APPLICATION_OVERLAY\b|\bTYPE_PHONE\b|\bTYPE_SYSTEM_ALERT\b"),
        "ambiguous", 0.70, ["overlay_fraud"],
        "System window type constant; drawing overlays over other apps",
        "Floating widget apps, chat heads, annotation tools",
    ),
    # -- credential theft --------------------------------------------------
    _StringRule(
        re.compile(r"\bgetCurrentInputConnection\b|\bcommitText\b"),
        "ambiguous", 0.65, ["credential_theft"],
        "IME input connection API; can intercept keystrokes in a custom keyboard",
        "Legitimate keyboard apps (Gboard-style)",
    ),
    # -- base64 / encoded payloads -----------------------------------------
    _StringRule(
        re.compile(r"[A-Za-z0-9+/]{60,}={0,2}"),
        "ambiguous", 0.35, ["anti_analysis"],
        "Long Base64 string; may be an encoded embedded payload or C2 config",
        "Embedded images, Firebase config, certificate blobs",
    ),
    # -- hardcoded keys/hexstrings -----------------------------------------
    _StringRule(
        re.compile(r"[0-9a-fA-F]{32,}"),
        "ambiguous", 0.20, ["anti_analysis"],
        "Long hex string; may be a hardcoded RC4/AES key or command hash",
        "API keys, hash digests, Firebase sender IDs",
    ),
    # -- Telegram Bot C2 dead-drop (Spymax, Spynote, modern Android RATs) -----
    _StringRule(
        re.compile(r"https?://api\.telegram\.org/bot\d{7,12}:[A-Za-z0-9_-]{35}", re.I),
        "malicious", 0.90, ["c2_networking"],
        "Telegram Bot API token acting as C2 dead-drop; used extensively by Spymax, Spynote, AhMyth variants, and modern Android RATs",
        "Legitimate Telegram bot SDK integration (extremely rare to hardcode token in production APK)",
    ),
    # -- Paste-site dead-drops (Anubis, Cerberus, BankBot) --------------------
    _StringRule(
        re.compile(r"pastebin\.com/raw/|paste\.ee/r/|hastebin\.com/raw/|rentry\.co/", re.I),
        "malicious", 0.80, ["c2_networking"],
        "Paste-site raw endpoint used as dead-drop C2 relay; changes C2 domain without updating APK to evade domain blocklists",
        "Developer sharing configs via paste-sites (should not appear in a production APK)",
    ),
    # -- Hardcoded banking app package targets (overlay launch trigger) --------
    _StringRule(
        re.compile(
            r"com\.(?:chase|bankofamerica|wellsfargo|citibank|hsbc|barclays|"
            r"natwest|santander|lloydsbank|ing(?:direct)?|bnpparibas|societegenerale|"
            r"commerzbank|deutschebank|jpmorgan|usbank)\b",
            re.I,
        ),
        "malicious", 0.85, ["overlay_fraud"],
        "Hardcoded banking app package name; indicates overlay trojan maintaining a target list to know when to launch credential-phishing overlay",
        "Banking apps that self-reference their own package for deep linking (self-referential, not cross-app)",
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
    r"zlib|sqlite|tflite|onnx|realm|mupdf|rootbeer|sqlcipher|"
    r"boringssl|conscrypt|reactnativejni|hermes|jsc|pdfium)",
    re.I,
)

_SUSPICIOUS_NATIVE_LIB_RULES: List[Tuple[re.Pattern, str, float, List[str], str, str]] = [
    (
        re.compile(r"(frida|xposed|substrate|zygisk|magisk)", re.I),
        "malicious",
        0.90,
        ["anti_analysis", "privilege_escalation"],
        "Native library name references a hooking/root framework often used for runtime tampering or sandbox evasion",
        "Security research tools or red-team utilities bundled inside the app",
    ),
    (
        re.compile(r"(inject|inlinehook|hook|intercept|trampoline|patcher)", re.I),
        "ambiguous",
        0.72,
        ["anti_analysis", "privilege_escalation"],
        "Native library name suggests code hooking or process injection capability",
        "Instrumentation SDKs, compatibility shims, or game-mod frameworks",
    ),
    (
        re.compile(r"(dexloader|classloader|loader|payload|dropper|unpack|packer)", re.I),
        "ambiguous",
        0.68,
        ["dynamic_code_loading", "anti_analysis"],
        "Native library name suggests staged payload loading or unpacking outside normal DEX inspection",
        "Hot-update frameworks or commercial packers",
    ),
    (
        re.compile(r"(daemon|watchdog|keepalive|servicecore|bot|backdoor|rat)", re.I),
        "ambiguous",
        0.64,
        ["persistence", "c2_networking"],
        "Native library name suggests background persistence or remote-control support",
        "Internal service helper libraries with unusually aggressive naming",
    ),
    (
        re.compile(r"(keylog|overlay|bank|cred|steal|grabber|exfil)", re.I),
        "malicious",
        0.78,
        ["credential_theft", "overlay_fraud", "data_exfiltration"],
        "Native library name directly references credential theft, overlays, or exfiltration behavior",
        "Test fixtures or intentionally named research samples",
    ),
]

_SDK_ELEVATION_PERMISSIONS = {
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.ANSWER_PHONE_CALLS",
}

_PACKAGE_TYPOSQUAT_RULES: List[Tuple[re.Pattern, str, float, List[str], str, str]] = [
    (
        re.compile(r"^com\.google\.play\.services(?:\..+)?$", re.I),
        "malicious",
        0.82,
        ["overlay_fraud", "credential_theft"],
        "Package name impersonates Google Play Services; malware often borrows this namespace to appear trusted",
        "None for third-party APKs -- the canonical Play Services package is com.google.android.gms",
    ),
    (
        re.compile(r"^com\.android\.(?:settings|system|systemui|update|security|packageinstaller)(?:\..+)?$", re.I),
        "ambiguous",
        0.72,
        ["overlay_fraud", "credential_theft"],
        "Package name imitates a core Android system component to gain user trust",
        "OEM/system apps signed by the device vendor",
    ),
    (
        re.compile(r"^com\.(?:andriod|anroid|goog1e|gooogle|g00gle)\.", re.I),
        "malicious",
        0.80,
        ["overlay_fraud", "credential_theft"],
        "Package name uses a typo-squatted trusted brand namespace",
        "None -- the misspelling itself is a deception signal",
    ),
]


# ---------------------------------------------------------------------------
# cert rules
# ---------------------------------------------------------------------------

_DEBUG_CERT_SUBJECT_PATTERN = re.compile(
    r"android\s+debug|android\s+release|test\s+key|debug\s+key", re.I
)
_SINGLE_CHAR_ORG_PATTERN = re.compile(r'"[OC]"\s*:\s*"\w{1,2}"')

# Known-malicious signing cert SHA-1 thumbprints (add as threat intel accumulates).
# Sources: public threat intel reports, malware analysis blogs.
_KNOWN_MALWARE_CERT_THUMBPRINTS: Dict[str, str] = {
    # SpyNote / CypherRAT variants (SHA-1, from public campaign analysis)
    "6ae7b4b5cbee95be47ff22e62a4ef9af7534a9e0": "SpyNote/CypherRAT",
    # Standard Android debug keystore (keytool default DN; recycled in repackaged/trojanised APKs)
    # Note: CN is also caught by _DEBUG_CERT_SUBJECT_PATTERN; thumbprint gives strength=1.0
    "a40da80a59d170caa950cf15c18c454d47a39b26": "android_debug_cert_repack",
    # -- ADD MORE FROM YOUR OWN MALWARE CORPUS ------------------------------------
    # Extract with:  apksigner verify --print-certs sample.apk
    #           or:  keytool -printcert -jarfile sample.apk
    # Format: "<sha1_40hex_no_colons_lowercase>": "<FamilyName>",
}

# Suspicious subject CN / O patterns in signing certs
_SUSPICIOUS_CERT_PATTERNS: List[re.Pattern] = [
    re.compile(r'"common_name"\s*:\s*"[a-z]{1,3}"', re.I),         # 1-3 char CN
    re.compile(r'"organization"\s*:\s*"[a-z0-9]{1,4}"', re.I),     # very short org
    re.compile(r'"common_name"\s*:\s*"\d{4,}"', re.I),             # all-numeric CN
    re.compile(r'"common_name"\s*:\s*"android\s+debug"', re.I),    # default debug CN
]


# ---------------------------------------------------------------------------
# normalizer functions
# ---------------------------------------------------------------------------

def _perm_short(full_perm: str) -> str:
    """android.permission.FOO -> FOO"""
    return full_perm.rsplit(".", 1)[-1]


def _safe_int(value: Any) -> Optional[int]:
    try:
        if value is None or value == "":
            return None
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _collect_permission_tags(permissions: List[str]) -> List[str]:
    tags: List[str] = []
    for perm in permissions:
        rule = _PERM_RULES.get(perm)
        if rule is None:
            continue
        for tag in rule[2]:
            if tag not in tags:
                tags.append(tag)
    return tags


def normalize_basic_info(
    basic_info: Dict[str, Any],
    permissions: List[str],
) -> List[EvidenceItem]:
    items: List[EvidenceItem] = []
    package_name = str(basic_info.get("package_name") or "").strip()
    min_sdk = _safe_int(basic_info.get("min_sdk"))
    target_sdk = _safe_int(basic_info.get("target_sdk"))

    risky_permissions = sorted(set(permissions) & _SDK_ELEVATION_PERMISSIONS)
    risky_tags = _collect_permission_tags(risky_permissions)

    if target_sdk is not None and target_sdk < 23:
        strength = 0.40
        direction = "ambiguous"
        explanation = (
            f"Legacy targetSdkVersion={target_sdk} lets the app avoid Android 6+ runtime permission prompts"
        )
        if risky_permissions:
            strength = 0.58 if target_sdk <= 22 else 0.48
            explanation += (
                f" while still requesting high-risk permissions such as {', '.join(_perm_short(p) for p in risky_permissions[:4])}"
            )
        items.append(EvidenceItem(
            id=make_evidence_id("basic_info", f"target_sdk:{target_sdk}", "basic_info:target_sdk"),
            kind="basic_info",
            value=f"targetSdkVersion={target_sdk}",
            source_location="basic_info:target_sdk",
            direction=direction,
            strength=strength,
            behavior_tags=risky_tags or ["anti_analysis"],
            explanation=explanation,
            benign_alternatives="Legitimate legacy apps that have not been modernized for recent Android permission behavior",
        ))

    if min_sdk is not None and min_sdk <= 16:
        items.append(EvidenceItem(
            id=make_evidence_id("basic_info", f"min_sdk:{min_sdk}", "basic_info:min_sdk"),
            kind="basic_info",
            value=f"minSdkVersion={min_sdk}",
            source_location="basic_info:min_sdk",
            direction="ambiguous",
            strength=0.32,
            behavior_tags=["anti_analysis"],
            explanation="Very old minSdkVersion indicates compatibility with pre-runtime-permission Android builds often favored by broad-compatibility malware",
            benign_alternatives="Apps intentionally supporting very old Android devices",
        ))

    if (
        min_sdk is not None
        and target_sdk is not None
        and target_sdk < 23
        and min_sdk <= 16
    ):
        items.append(EvidenceItem(
            id=make_evidence_id("basic_info", "legacy_sdk_combo", "basic_info:sdk_combo"),
            kind="basic_info",
            value=f"legacy_sdk_combo(min={min_sdk}, target={target_sdk})",
            source_location="basic_info:sdk_combo",
            direction="ambiguous",
            strength=0.48,
            behavior_tags=risky_tags or ["anti_analysis"],
            explanation="Combination of very old minSdkVersion and legacy targetSdkVersion maximizes device reach while retaining pre-Marshmallow permission behavior",
            benign_alternatives="Old enterprise or long-tail consumer apps with unusually broad backwards compatibility requirements",
        ))

    if package_name:
        for pattern, direction, strength, tags, explanation, benign_alts in _PACKAGE_TYPOSQUAT_RULES:
            if not pattern.search(package_name):
                continue
            items.append(EvidenceItem(
                id=make_evidence_id("basic_info", package_name, "basic_info:package_name"),
                kind="basic_info",
                value=package_name,
                source_location="basic_info:package_name",
                direction=direction,
                strength=strength,
                behavior_tags=tags,
                explanation=explanation,
                benign_alternatives=benign_alts,
            ))
            break

    return items


def normalize_permissions(permissions: List[str]) -> List[EvidenceItem]:
    items: List[EvidenceItem] = []
    for perm in permissions:
        rule = _PERM_RULES.get(perm)
        if rule is None:
            # Unknown permission -- emit a very weak ambiguous item so the cluster still knows about it
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

            # Exposed-without-permission: receiver/service with custom actions but no protection
            # Any app on the device can send a broadcast to trigger it -- classic C2 command channel
            if comp_type in ("receivers", "services") and not perm:
                custom_actions = [
                    a for a in (filter_info.get("action", []) or [])
                    if not a.startswith(("android.", "com.google.", "com.android."))
                ]
                for action in custom_actions[:3]:  # cap to avoid flooding clusters
                    eid = make_evidence_id("component", f"exposed:{action}", source_loc)
                    if eid in seen_ids:
                        continue
                    seen_ids.add(eid)
                    comp_singular = comp_type.rstrip("s")
                    items.append(EvidenceItem(
                        id=eid,
                        kind="component",
                        value=f"{comp_singular}:{comp_name} [unprotected action:{action}]",
                        source_location=source_loc,
                        direction="ambiguous",
                        strength=0.50,
                        behavior_tags=["c2_networking"],
                        explanation=(
                            f"Exported {comp_singular} responds to custom action '{action}' with no "
                            f"android:permission guard -- any app on the device can trigger it remotely"
                        ),
                        benign_alternatives="Plugin architecture, inter-app communication frameworks",
                    ))

    return items


def normalize_classes(
    classes: Dict[str, str],
    class_api_scores: Dict[str, float],
    class_behavior_tags: Dict[str, List[str]],
) -> List[EvidenceItem]:
    """
    Emit one EvidenceItem per class that has API-score-derived behavior tags.
    The evidence item represents the class itself (not its strings -- those come from normalize_strings).
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
        lib_stem = lib_name
        if lib_stem.lower().startswith("lib"):
            lib_stem = lib_stem[3:]
        if lib_stem.lower().endswith(".so"):
            lib_stem = lib_stem[:-3]

        matched_rule = None
        for rule in _SUSPICIOUS_NATIVE_LIB_RULES:
            if rule[0].search(lib_stem):
                matched_rule = rule
                break

        if matched_rule is not None:
            _, direction, strength, tags, explanation, benign_alternatives = matched_rule
            items.append(EvidenceItem(
                id=make_evidence_id("native_lib", lib_path, f"native_lib:{lib_name}"),
                kind="native_lib",
                value=lib_path,
                source_location=f"native_lib:{lib_name}",
                direction=direction,
                strength=strength,
                behavior_tags=tags,
                explanation=explanation,
                benign_alternatives=benign_alternatives,
            ))
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
    import time as _time
    items: List[EvidenceItem] = []
    now_ts = _time.time()

    for cert in certificates:
        subject = str(cert.get("subject", ""))
        issuer  = str(cert.get("issuer", ""))
        thumbprint = str(cert.get("thumbprint", "")).lower().replace(":", "")
        serial = str(cert.get("serial_number", "")).lower().strip("0x").lstrip("0")
        valid_from = cert.get("valid_from")
        valid_to   = cert.get("valid_to")
        source_loc = "certificate"

        # -- 1. Known-malicious thumbprint ---------------------------------
        threat = _KNOWN_MALWARE_CERT_THUMBPRINTS.get(thumbprint)
        if threat:
            items.append(EvidenceItem(
                id=make_evidence_id("cert", f"known_bad:{thumbprint}", source_loc),
                kind="cert",
                value=f"known-malware cert ({threat}): {thumbprint}",
                source_location=source_loc,
                direction="malicious",
                strength=1.00,
                behavior_tags=["anti_analysis"],
                explanation=f"Certificate SHA-1 thumbprint matches known-malicious signing key used by {threat}",
                benign_alternatives="None -- named malware campaign signing cert",
            ))

        # -- 2. Self-signed ------------------------------------------------
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

        # -- 3. Debug / test cert ------------------------------------------
        if _DEBUG_CERT_SUBJECT_PATTERN.search(subject):
            items.append(EvidenceItem(
                id=make_evidence_id("cert", "debug_cert", source_loc),
                kind="cert",
                value="debug/test certificate",
                source_location=source_loc,
                direction="ambiguous",
                strength=0.30,
                behavior_tags=[],
                explanation="Debug or test signing certificate; common in repackaged/trojanised apps",
                benign_alternatives="Development builds, sideloaded beta releases",
            ))

        # -- 4. Suspicious subject pattern (very short CN/O) --------------
        for pat in _SUSPICIOUS_CERT_PATTERNS:
            if pat.search(subject):
                items.append(EvidenceItem(
                    id=make_evidence_id("cert", f"suspicious_subject:{pat.pattern[:30]}", source_loc),
                    kind="cert",
                    value=f"suspicious cert subject: {subject[:120]}",
                    source_location=source_loc,
                    direction="ambiguous",
                    strength=0.30,
                    behavior_tags=[],
                    explanation="Cert subject has trivially short or numeric CN/O -- typical of auto-generated malware certs",
                    benign_alternatives="Quick-build scripts, tutorial apps",
                ))
                break

        # -- 5. Zero / trivially small serial number -----------------------
        if serial in ("0", "1", "", "00"):
            items.append(EvidenceItem(
                id=make_evidence_id("cert", "zero_serial", source_loc),
                kind="cert",
                value=f"suspicious serial number: {cert.get('serial_number', '')}",
                source_location=source_loc,
                direction="ambiguous",
                strength=0.25,
                behavior_tags=[],
                explanation="Certificate serial is zero or one -- auto-generated with keytool defaults, common in malware",
                benign_alternatives="Old keytool-generated certs sometimes use serial=1",
            ))

        # -- 6. Validity period anomalies ---------------------------------
        if valid_from is not None and valid_to is not None:
            try:
                vf, vt = float(valid_from), float(valid_to)
                span_days = (vt - vf) / 86400

                if span_days <= 1:
                    items.append(EvidenceItem(
                        id=make_evidence_id("cert", "same_day_cert", source_loc),
                        kind="cert",
                        value="cert validity <= 1 day",
                        source_location=source_loc,
                        direction="malicious",
                        strength=0.70,
                        behavior_tags=["anti_analysis"],
                        explanation="Certificate valid for <= 1 day -- likely auto-generated for a single campaign",
                        benign_alternatives="None -- legitimate apps need certs valid for their deployment lifetime",
                    ))
                elif span_days > 50 * 365:
                    # > 50 year validity -- common in automated malware cert generation
                    items.append(EvidenceItem(
                        id=make_evidence_id("cert", "extreme_validity", source_loc),
                        kind="cert",
                        value=f"cert validity {int(span_days // 365)} years",
                        source_location=source_loc,
                        direction="ambiguous",
                        strength=0.25,
                        behavior_tags=[],
                        explanation="Unusually long certificate validity (>50 years); common default in malware toolkits",
                        benign_alternatives="Some developers set very long validity to avoid re-signing",
                    ))

                if vt < now_ts:
                    items.append(EvidenceItem(
                        id=make_evidence_id("cert", "expired_cert", source_loc),
                        kind="cert",
                        value="certificate is expired",
                        source_location=source_loc,
                        direction="ambiguous",
                        strength=0.20,
                        behavior_tags=[],
                        explanation="Certificate has passed its expiry date; may indicate an old repackaged app",
                        benign_alternatives="Old apps still function with expired certs on Android",
                    ))
            except (TypeError, ValueError):
                pass

    return items


# ---------------------------------------------------------------------------
# top-level entrypoint
# ---------------------------------------------------------------------------

def normalize_all(apk_facts: APKFacts) -> List[EvidenceItem]:
    """Convert all APKFacts into a flat list of EvidenceItems."""
    items: List[EvidenceItem] = []
    items.extend(normalize_basic_info(apk_facts.basic_info, apk_facts.permissions))
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
