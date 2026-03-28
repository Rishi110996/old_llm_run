import json
import re
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


