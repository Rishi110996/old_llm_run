import json
import re
from typing import Dict, List, Tuple
from androguard.core.dex import DEX
from androguard.core.analysis.analysis import Analysis
from androguard.core.analysis.analysis import StringAnalysis
from androguard.decompiler.decompiler import DecompilerDAD


class APKAnalyzer:
    SAFE_CLASSES = (
            # Android / system
            "Landroid/",
            "Ljava/",
            "Ldalvik/",
            "Lorg/apache/",
            "Lorg/json/",
            "Lorg/xml/",
            "Lorg/w3c/",
        
            # Kotlin
            "Lkotlin/",
            "Lkotlinx/",
        
            # Jetpack / androidx
            "Landroidx/",
        
            # Google official SDKs (explicit)
            "Lcom/google/android/gms/",   # Play Services
            "Lcom/google/firebase/",      # Firebase
            "Lcom/google/ads/",           # Ads SDK
        
            # Networking / serialization
            "Lokhttp3/",
            "Lokio/",
            "Lretrofit2/",
            "Lcom/squareup/moshi/",
            "Lcom/squareup/picasso/",
            "Lcom/bumptech/glide/",
            "Lorg/slf4j/",
            "Lcom/fasterxml/jackson/",
            "Lcom/google/gson/",
        
            # Crash / analytics / ads
            "Lcom/crashlytics/",          # Crashlytics
            "Lcom/google/firebase/crash/", 
            "Lcom/facebook/appevents/",   # Facebook analytics
            "Lcom/google/analytics/",     # Google analytics
            "Lcom/mopub/",                # MoPub ads
            "Lcom/inmobi/",               # InMobi ads
            "Lcom/unity3d/ads/",          # Unity ads
            "Lcom/chartboost/",           # Chartboost ads
            "Lcom/applovin/",             # AppLovin ads
        
            # Ads mediation & attribution
            "Lcom/ironsource/",
            "Lcom/vungle/",
            "Lcom/startapp/",
            "Lcom/flurry/",
            "Lcom/adjust/",
        
            # Social SDKs
            "Lcom/facebook/",
            "Lcom/twitter/sdk/",
            "Lcom/instagram/",
        
            # Payment SDKs (official only!)
            "Lcom/paypal/",
            "Lcom/stripe/",
            "Lcom/braintreepayments/",
            )

    IMPORTANT_METHODS = (
        "onCreate",
        "attachBaseContext",
        "onStartCommand",
        "doInBackground",)

    SUSP_STRING_PATTERNS = re.compile(
        r"(http[s]?://|\.php|\.cn|\.ru|root|su|cmd|bin/sh|eval|dex|Base64)",
        re.IGNORECASE,)

        # SUSP_RECV_ACTIONS = [
        #     "android.provider.Telephony.SMS_RECEIVED",
        #     "android.intent.action.BOOT_COMPLETED",
        #     "android.app.action.DEVICE_ADMIN_ENABLED",
        #     "android.intent.action.NEW_OUTGOING_CALL",
        #     "android.provider.Telephony.WAP_PUSH_RECEIVED",
        # ]
    SUSP_SERV_ACTIONS = [
            "android.service.notification.NotificationListenerService",
            "android.accessibilityservice.AccessibilityService",
            "android.net.VpnService",
            "android.app.admin.DeviceAdminService",
        ]
    SUSP_RECV_ACTIONS = [
        # SMS
        "android.provider.Telephony.SMS_RECEIVED",
        "android.provider.Telephony.SMS_RECEIVED_ACTION",
        "android.provider.Telephony.SMS_DELIVER",
        "android.provider.Telephony.SMS_DELIVER_ACTION",
        "android.provider.Telephony.WAP_PUSH_RECEIVED",
        "android.provider.Telephony.WAP_PUSH_DELIVER",
    
        # Calls
        "android.intent.action.NEW_OUTGOING_CALL",
    
        # Boot / persistence
        "android.intent.action.BOOT_COMPLETED",
        "android.intent.action.LOCKED_BOOT_COMPLETED",
        "android.intent.action.REBOOT",
        "android.intent.action.QUICKBOOT_POWERON",
        "android.intent.action.MY_PACKAGE_REPLACED",
        "android.intent.action.PACKAGE_REPLACED",
        "android.intent.action.PACKAGE_ADDED"]
    
    SUSP_PERMISSIONS = [
        # SMS / Calls
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.BROADCAST_SMS",
        "android.permission.CALL_PHONE",
        "android.permission.READ_PHONE_STATE",
        "android.permission.PROCESS_OUTGOING_CALLS",
    
        # Persistence
        "android.permission.RECEIVE_BOOT_COMPLETED",
    
        # Accessibility
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
    
        # Notifications
        "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
    
        # Device admin
        "android.permission.BIND_DEVICE_ADMIN",
    
        # VPN
        "android.permission.BIND_VPN_SERVICE"]

    # ------------------------------------------------------------------
    # Phase-1 API sensitivity scoring tables (bytecode-level, no decompile)
    # ------------------------------------------------------------------

    # Dalvik method descriptor → score added to containing class
    # Key format: anything that appears in get_xref_to() class name or
    # the resolved method descriptor string.
    API_SCORES: Dict[str, Tuple[float, List[str]]] = {
        # dynamic code loading
        "Ldalvik/system/DexClassLoader;":       (1.00, ["dynamic_code_loading"]),
        "Ldalvik/system/PathClassLoader;":      (0.90, ["dynamic_code_loading"]),
        "Ldalvik/system/BaseDexClassLoader;":   (0.85, ["dynamic_code_loading"]),
        "Ldalvik/system/InMemoryDexClassLoader;": (1.00, ["dynamic_code_loading"]),
        # shell / privilege escalation
        "Ljava/lang/Runtime;":                  (0.85, ["privilege_escalation"]),
        "Ljava/lang/ProcessBuilder;":           (0.85, ["privilege_escalation"]),
        # SMS abuse
        "Landroid/telephony/SmsManager;":       (1.00, ["sms_abuse"]),
        "Lcom/android/internal/telephony/ISms;": (0.90, ["sms_abuse"]),
        # call interception
        "Landroid/telephony/TelephonyManager;": (0.60, ["call_interception", "data_exfiltration"]),
        # overlay / window
        "Landroid/view/WindowManager;":         (0.75, ["overlay_fraud"]),
        # accessibility abuse
        "Landroid/accessibilityservice/AccessibilityService;": (0.85, ["accessibility_abuse"]),
        "Landroid/view/accessibility/AccessibilityNodeInfo;":  (0.75, ["accessibility_abuse"]),
        # data exfiltration
        "Landroid/provider/ContactsContract;":  (0.70, ["data_exfiltration"]),
        "Landroid/content/ContentResolver;":    (0.45, ["data_exfiltration"]),
        "Landroid/provider/Telephony;":         (0.75, ["data_exfiltration"]),
        "Landroid/location/LocationManager;":   (0.55, ["data_exfiltration"]),
        "Landroid/hardware/Camera;":            (0.55, ["data_exfiltration"]),
        "Landroid/media/AudioRecord;":          (0.65, ["data_exfiltration"]),
        # C2 networking
        "Ljava/net/Socket;":                    (0.55, ["c2_networking"]),
        "Ljava/net/URL;":                       (0.40, ["c2_networking"]),
        "Lorg/apache/http/client/HttpClient;":  (0.40, ["c2_networking"]),
        # reflection / anti-analysis
        "Ljava/lang/reflect/Method;":           (0.50, ["anti_analysis"]),
        "Ljava/lang/Class;":                    (0.40, ["anti_analysis"]),
        "Ljava/lang/ClassLoader;":              (0.50, ["anti_analysis"]),
        # crypto (lower — very common; elevated only in combination)
        "Ljavax/crypto/Cipher;":                (0.30, ["anti_analysis"]),
        "Ljavax/crypto/spec/SecretKeySpec;":    (0.25, ["anti_analysis"]),
        "Ljava/security/MessageDigest;":        (0.20, ["anti_analysis"]),
        # credential theft
        "Landroid/view/inputmethod/InputMethodManager;": (0.55, ["credential_theft"]),
        "Landroid/app/KeyguardManager;":        (0.55, ["credential_theft"]),
        # device admin / persistence
        "Landroid/app/admin/DevicePolicyManager;": (0.80, ["persistence"]),
        "Landroid/app/AlarmManager;":           (0.35, ["persistence"]),
        "Landroid/app/job/JobScheduler;":       (0.30, ["persistence"]),
        # app enumeration / overlay timing — banking trojans wait until banking app is foreground
        "Landroid/content/pm/PackageManager;":  (0.55, ["anti_analysis", "overlay_fraud"]),
        "Landroid/app/usage/UsageStatsManager;": (0.75, ["anti_analysis", "overlay_fraud"]),
        "Landroid/app/ActivityManager;":        (0.50, ["anti_analysis"]),
        # screen capture / recording
        "Landroid/media/projection/MediaProjectionManager;": (0.90, ["data_exfiltration"]),
        "Landroid/media/projection/MediaProjection;":        (0.90, ["data_exfiltration"]),
        "Landroid/media/MediaRecorder;":        (0.65, ["data_exfiltration"]),
        # clipboard hijacking (crypto address substitution)
        "Landroid/content/ClipboardManager;":   (0.70, ["credential_theft", "data_exfiltration"]),
        # hardware key injection / input event manipulation
        "Landroid/hardware/input/InputManager;": (0.80, ["accessibility_abuse"]),
        "Landroid/view/inputmethod/InputConnection;": (0.65, ["credential_theft"]),
        # Bluetooth recon — device fingerprinting and proximity scanning
        "Landroid/bluetooth/BluetoothAdapter;": (0.40, ["data_exfiltration"]),
        # Wi-Fi scanning — SSID/BSSID collection for location tracking and network recon
        "Landroid/net/wifi/WifiManager;":       (0.45, ["data_exfiltration"]),
        # account credential theft — sync adapter, AccountManager abuse
        "Landroid/accounts/AccountManager;":    (0.75, ["credential_theft"]),
        # WebView phishing — malware overlays WebView to capture banking creds
        "Landroid/webkit/WebView;":             (0.50, ["overlay_fraud", "credential_theft"]),
        "Landroid/webkit/WebViewClient;":       (0.45, ["overlay_fraud"]),
        # HTTP networking (direct, not OkHttp) — C2 raw
        "Ljava/net/HttpURLConnection;":         (0.45, ["c2_networking"]),
        # custom TLS / cert pinning bypass
        "Ljavax/net/ssl/SSLContext;":           (0.50, ["anti_analysis"]),
        "Ljavax/net/ssl/TrustManager;":         (0.50, ["anti_analysis"]),
        # content observer — watching contacts/call-log for exfil trigger
        "Landroid/database/ContentObserver;":   (0.55, ["data_exfiltration"]),
        # process / shell execution
        "Landroid/os/Process;":                 (0.55, ["privilege_escalation"]),
    }

    # Suspicious string patterns in bytecode const-string (fast scan, no decompile)
    SUSPICIOUS_STR_SCORE: List[Tuple[re.Pattern, float, List[str]]] = [
        (re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", re.I), 0.80, ["c2_networking"]),
        (re.compile(r"\b(?:[a-z0-9-]+\.(?:ru|cn|su|top|tk|pw|xyz|kim|click|biz|info))\b", re.I), 0.50, ["c2_networking"]),
        (re.compile(r"https?://[^\s\"']{10,}\.php", re.I), 0.50, ["c2_networking"]),
        (re.compile(r"\b(?:DexClassLoader|PathClassLoader|InMemoryDexClassLoader)\b"), 0.85, ["dynamic_code_loading"]),
        (re.compile(r"/bin/sh|/system/bin/sh|cmd\.exe", re.I), 0.85, ["privilege_escalation"]),
        (re.compile(r"\bsu\b"), 0.80, ["privilege_escalation"]),
        (re.compile(r"\bTYPE_APPLICATION_OVERLAY\b|\bTYPE_PHONE\b|\bTYPE_SYSTEM_ALERT\b"), 0.65, ["overlay_fraud"]),
        (re.compile(r"\bXposed\b|\bgenymotion\b|\bbluestacks\b", re.I), 0.50, ["anti_analysis"]),
        (re.compile(r"\bchmod\s+[0-7]{3}", re.I), 0.80, ["privilege_escalation"]),
    ]

    # Budget cap: stop decompiling after this many bytes of source code
    MAX_SOURCE_BUDGET_BYTES: int = 55_000
    # Floor: skip decompiling classes below this score
    MIN_CLASS_SCORE_FOR_DECOMPILE: float = 0.20
    # Propagation multiplier: if class A (score S) calls class B, add S * PROP_FACTOR to B
    PROPAGATION_FACTOR: float = 0.30

    def __init__(self, apk, apk_data):
        self.apk = apk
        self.apk_data = apk_data
        self.analysis = self._analyze_apk()
        self._susp_classes = self.get_list_of_susp_classes()

    def _analyze_apk(self):
        dx = Analysis()
        for data in self.apk.get_all_dex():
            d = DEX(data)
            dx.add(d)
            for d in dx.vms:
                d.set_decompiler(DecompilerDAD(d, dx))
                d.set_analysis(dx)
        dx.create_xref()
        return dx

    def extract_all_strings(self):
        """Extract only suspicious strings"""
        strings = []
        for string in self.analysis.find_strings(string=".*"):
            val = string.get_value()
            if self.SUSP_STRING_PATTERNS.search(val):
                strings.append(val)
        return strings

    def extract_all_strings_scoped(self, susp_classes):
        strings = set()

        for s in self.analysis.find_strings():
            val = s.get_value()
            for cls in susp_classes:
                print("Processing class ",cls)
                # heuristic: class name or package appears near string
                if cls.replace('/', '.')[:-1] in val:
                    strings.add(val)

        return list(strings)

    def extract_strings_from_classes(self, max_depth):
        strings = set()
        visited = set()

        def process_class(cls, depth):
            if cls.name in visited or depth > max_depth:
                return
            if cls.name.startswith(self.SAFE_CLASSES):
                return
            visited.add(cls.name)

            for m in cls.get_methods():
                ma = self.analysis.get_method(m.method)
                if not ma:
                    continue

                for block in ma.get_basic_blocks():
                    for ins in block.get_instructions():
                        if ins.get_name().startswith("const-string"):
                            for op in ins.get_operands():
                                if isinstance(op, tuple) and len(op) == 3:
                                    op_type, str_index, actual_str = op
                                    if isinstance(actual_str, str):
                                        strings.add(actual_str)
                                        # print(actual_str)


            for xref_cls in cls.get_xref_to():
                if not xref_cls.is_external() and not xref_cls.name.startswith(self.SAFE_CLASSES):
                    process_class(xref_cls, depth + 1)

        for c in self._susp_classes:
            for cls in self.analysis.find_classes(name=c, no_external=True):
                process_class(cls, 0)

        return list(strings)

    def _get_susp_classes(self, components):
        susp = set()

        for name, info in components.items():
            actions = info.get("action", [])
            meta = info.get("meta-data", {})
            perms = info.get("permission", "")

            # Action-based
            if any(a in self.SUSP_RECV_ACTIONS + self.SUSP_SERV_ACTIONS for a in actions):
                susp.add(name)

            # Permission-based
            if perms in self.SUSP_PERMISSIONS:
                susp.add(name)

            # Meta-data based
            if any(k in meta for k in [
                "android.accessibilityservice",
                "android.app.device_admin",
                "android.service.notification"
            ]):
                susp.add(name)

        return [f"L{x.replace('.', '/')};" for x in susp]


    def extract_classes_code(self, max_depth):
        """
        Extract suspicious classes with depth-limited traversal.
        Returns:
            full_classes: list of full class source code
            important_methods: list of only important methods
        """
        full_classes = []
        full_classes_json = {}
        visited = set()

        def process_class(cls, depth):
            if cls.name in visited or depth > max_depth:
                return

            if cls.name.startswith(self.SAFE_CLASSES):
                return
            visited.add(cls.name)

            # Full class source
            try:
                source_code = cls.get_class().get_source()
                # full_classes.append(f"\n// ===== CLASS: {cls.name} (depth={depth}) =====\n{source_code}\n")
                full_classes_json[cls.name] = f"class depth: {depth} \n{source_code}"
            except Exception:
                print(f"\n// [Could not decompile class: {cls.name}]")

            # Follow cross-references recursively (depth limited)
            if depth < max_depth:
                for xref_cls in cls.get_xref_to():
                    if not xref_cls.is_external() and not xref_cls.name.startswith(self.SAFE_CLASSES):
                        process_class(xref_cls, depth + 1)

        # Start traversal
        for sus_cls in self._susp_classes:
            for cls in self.analysis.find_classes(name=sus_cls, no_external=True):
                process_class(cls, depth=0)

        return full_classes_json

    def extract_methods_code(self, max_depth):
        important_methods = {}
        visited = set()

        def process_class(cls, depth):
            if cls.name in visited or depth > max_depth:
                return

            if cls.name.startswith(self.SAFE_CLASSES):
                return
            visited.add(cls.name)

            # Extract only important methods
            for m in cls.get_methods():
                try:
                    method_name = m.method.get_name()
                    if method_name in self.IMPORTANT_METHODS:
                        try:
                            method_src = m.method.get_source()
                            important_methods[method_name] = method_src
                        except Exception:
                            print(
                                f"\n// [Could not decompile method: {cls.name}->{method_name}]"
                            )
                except Exception:
                    continue

            # Follow cross-references recursively (depth limited)
            if depth < max_depth:
                for xref_cls in cls.get_xref_to():
                    if not xref_cls.is_external() and not xref_cls.name.startswith(self.SAFE_CLASSES):
                        process_class(xref_cls, depth + 1)

        # Start traversal
        for sus_cls in self._susp_classes:
            for cls in self.analysis.find_classes(name=sus_cls, no_external=True):
                process_class(cls, depth=0)

        return important_methods

    def get_list_of_susp_classes(self):
        list_susp_classes = []

        # Application class
        application_class = self.apk_data.get("app_class")
        if application_class:
            list_susp_classes.append(f"L{application_class.replace('.', '/')};")

        # Main activity
        main_class = self.apk_data.get("main_act")
        if main_class:
            list_susp_classes.append(f"L{main_class.replace('.', '/')};")

        # Receivers & services
        receivers = self.apk_data.get("receivers", {})
        services = self.apk_data.get("services", {})

        list_susp_classes.extend(self._get_susp_classes(receivers))
        list_susp_classes.extend(self._get_susp_classes(services))
        return list_susp_classes

    def extract_relevant_strings(self,max_depth):
        instr_strings = []
        if self._susp_classes:
            instr_strings = self.extract_strings_from_classes(max_depth)
            # all_strings = extract_strings(self.analysis)
        else:
            print("⚠️ Suspicious classes-strings not found")
        return instr_strings


    def extract_relevant_classes(self,max_depth):
        classes = []
        if self._susp_classes:
            classes = self.extract_classes_code(max_depth)
        else:
            print("⚠️ Suspicious classes not found")

        return classes

    def extract_relevant_methods(self,max_depth):
        methods = []
        if self._susp_classes:
            methods = self.extract_methods_code(max_depth)
        else:
            print("⚠️ Suspicious methods not found")

        return methods

    # ------------------------------------------------------------------
    # v2: score-based class selection  (replaces max_depth traversal)
    # ------------------------------------------------------------------

    def score_all_classes(self) -> Tuple[Dict[str, float], Dict[str, List[str]]]:
        """
        Phase 1 + Phase 2: score every non-safe class using API call graph and
        suspicious strings in bytecode — no decompilation.

        Returns:
          scores       : {class_name: float}
          behavior_tags: {class_name: List[str]}  — deduplicated tags per class
        """
        scores: Dict[str, float] = {}
        tag_map: Dict[str, List[str]] = {}

        # --- Phase 1: raw API + string scan ---
        for class_obj in self.analysis.get_classes():
            cls_name = class_obj.name
            if cls_name.startswith(self.SAFE_CLASSES):
                continue

            score = 0.0
            tags: List[str] = []

            # obfuscation heuristics — two-tier method-name ratio
            short_name = cls_name.split("/")[-1].rstrip(";")
            cls_name_short = len(short_name) <= 2
            if cls_name_short:
                score += 0.15    # reduced from 0.20; ProGuard does this on benign apps too
                tags.append("anti_analysis")

            methods = list(class_obj.get_methods())
            if methods:
                short_method_count = sum(
                    1 for m in methods if len(m.name) <= 2 and not m.name.startswith("<")
                )
                ratio = short_method_count / len(methods)
                if ratio > 0.90:
                    # Near-complete renaming — almost certainly intentional obfuscation
                    score += 0.35
                    tags.append("anti_analysis")
                elif ratio > 0.70:
                    # Strong obfuscation
                    score += 0.20
                    tags.append("anti_analysis")
                elif ratio > 0.50:
                    # Moderate — possible benign ProGuard, small signal only
                    score += 0.08
                    tags.append("anti_analysis")

            # sensitive API calls (xref_to = classes this class references)
            for xref_cls in class_obj.get_xref_to():
                xref_name = xref_cls.name
                for api_prefix, (api_score, api_tags) in self.API_SCORES.items():
                    if xref_name.startswith(api_prefix):
                        score += api_score
                        tags.extend(api_tags)

            # suspicious strings in bytecode (const-string instructions)
            for method_obj in methods:
                try:
                    ma = self.analysis.get_method(method_obj.method)
                    if ma is None:
                        continue
                    for block in ma.get_basic_blocks():
                        for ins in block.get_instructions():
                            if not ins.get_name().startswith("const-string"):
                                continue
                            for op in ins.get_operands():
                                if not (isinstance(op, tuple) and len(op) == 3):
                                    continue
                                _, _, val = op
                                if not isinstance(val, str):
                                    continue
                                for pat, str_score, str_tags in self.SUSPICIOUS_STR_SCORE:
                                    if pat.search(val):
                                        score += str_score
                                        tags.extend(str_tags)
                                        break
                except Exception:
                    continue

            if score > 0:
                scores[cls_name] = round(score, 4)
                # deduplicate while preserving insertion order
                seen: set = set()
                deduped: List[str] = []
                for t in tags:
                    if t not in seen:
                        seen.add(t)
                        deduped.append(t)
                tag_map[cls_name] = deduped

        # --- Phase 2: one-hop propagation ---
        # If class A scored ≥ 0.6 and calls class B, share PROPAGATION_FACTOR × A's score with B.
        propagation_deltas: Dict[str, float] = {}
        propagation_tags: Dict[str, List[str]] = {}
        for class_obj in self.analysis.get_classes():
            cls_name = class_obj.name
            if cls_name not in scores or scores[cls_name] < 0.60:
                continue
            a_score = scores[cls_name]
            a_tags = tag_map.get(cls_name, [])
            for xref_cls in class_obj.get_xref_to():
                target = xref_cls.name
                if target.startswith(self.SAFE_CLASSES) or target == cls_name:
                    continue
                delta = round(a_score * self.PROPAGATION_FACTOR, 4)
                propagation_deltas[target] = propagation_deltas.get(target, 0.0) + delta
                existing = propagation_tags.get(target, [])
                for t in a_tags:
                    if t not in existing:
                        existing.append(t)
                propagation_tags[target] = existing

        for cls_name, delta in propagation_deltas.items():
            if cls_name.startswith(self.SAFE_CLASSES):
                continue
            scores[cls_name] = round(scores.get(cls_name, 0.0) + delta, 4)
            existing = tag_map.get(cls_name, [])
            for t in propagation_tags.get(cls_name, []):
                if t not in existing:
                    existing.append(t)
            tag_map[cls_name] = existing

        return scores, tag_map

    def select_and_decompile_classes(
        self,
        scores: Dict[str, float],
    ) -> Dict[str, str]:
        """
        Phase 3: sort classes by score descending, then decompile greedily until
        MAX_SOURCE_BUDGET_BYTES is exhausted.  Classes below MIN_CLASS_SCORE_FOR_DECOMPILE
        are never decompiled.

        Returns {class_name: decompiled_source}
        """
        # Sort by score descending
        ordered = sorted(
            [(name, s) for name, s in scores.items() if s >= self.MIN_CLASS_SCORE_FOR_DECOMPILE],
            key=lambda x: x[1],
            reverse=True,
        )

        decompiled: Dict[str, str] = {}
        bytes_used = 0
        skip_count = 0

        for cls_name, score in ordered:
            for cls_obj in self.analysis.find_classes(name=cls_name, no_external=True):
                try:
                    source = cls_obj.get_class().get_source() or ""
                except Exception:
                    source = f"// [decompile failed: {cls_name}]"

                if not source.strip():
                    continue

                src_bytes = len(source.encode("utf-8", errors="replace"))

                if bytes_used + src_bytes > self.MAX_SOURCE_BUDGET_BYTES:
                    skip_count += 1
                    # keep trying smaller classes further down the list
                    if bytes_used > self.MAX_SOURCE_BUDGET_BYTES * 0.85:
                        # budget nearly full — stop iterating
                        break
                    continue

                decompiled[cls_name] = source
                bytes_used += src_bytes
                break  # found the class, stop inner loop

            if bytes_used > self.MAX_SOURCE_BUDGET_BYTES * 0.85 and skip_count > 5:
                break

        return decompiled

    def extract_strings_from_scored_classes(
        self,
        selected_class_names: List[str],
    ) -> Dict[str, List[str]]:
        """
        Extract const-string values from the budget-selected classes only.
        Returns {class_name: [string, …]}.
        """
        result: Dict[str, List[str]] = {}
        for cls_name in selected_class_names:
            strs: List[str] = []
            for cls_obj in self.analysis.find_classes(name=cls_name, no_external=True):
                for method_obj in cls_obj.get_methods():
                    try:
                        ma = self.analysis.get_method(method_obj.method)
                        if ma is None:
                            continue
                        for block in ma.get_basic_blocks():
                            for ins in block.get_instructions():
                                if not ins.get_name().startswith("const-string"):
                                    continue
                                for op in ins.get_operands():
                                    if isinstance(op, tuple) and len(op) == 3:
                                        _, _, val = op
                                        if isinstance(val, str) and len(val) >= 4:
                                            strs.append(val)
                    except Exception:
                        continue
            if strs:
                result[cls_name] = strs
        return result

