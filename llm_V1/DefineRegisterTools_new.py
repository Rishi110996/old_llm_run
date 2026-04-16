# apk_context.py

from loguru import logger
logger.remove()
logger.add(lambda msg: None, level="WARNING")

import logging
logging.getLogger("androguard").setLevel(logging.WARNING)

import hashlib
from androguard.core.apk import APK
from extract_suspicious_code import APKAnalyzer

# -------------------------------------------------
# APKContext: single source of truth for one APK
# -------------------------------------------------

class APKContext:
    """
    Holds all parsed state for a single APK.
    APK + metadata + DEX analysis are created ONCE.
    """

    def __init__(self, apk_path: str):
        self.apk_path = apk_path
        self.apk = APK(apk_path)

        # Metadata
        self.metadata = self._extract_metadata()

        # Analyzer (DEX + xrefs)
        self.analyzer = APKAnalyzer(self.apk, self.metadata)

        # Lazy caches
        self._strings = None
        self._classes = None
        self._methods = None

    # -------------------------
    # Metadata helpers
    # -------------------------

    def _extract_metadata(self):
        return {
            "main_act": self.apk.get_main_activity(),
            "app_class": self.apk.get_attribute_value("application", "name"),
            "receivers": {
                name: self.apk.get_intent_filters("receiver", name)
                for name in self.apk.get_receivers()
            },
            "services": {
                name: self.apk.get_intent_filters("service", name)
                for name in self.apk.get_services()
            },
        }

    def _safe_androidversion_name(self):
        try:
            return self.apk.get_androidversion_name()
        except KeyError:
            return self.apk.get_attribute_value("manifest", "versionName") or ""

    def _safe_androidversion_code(self):
        try:
            return self.apk.get_androidversion_code()
        except KeyError:
            return self.apk.get_attribute_value("manifest", "versionCode") or ""

    # -------------------------
    # Public getters (cached)
    # -------------------------

    def get_basic_info(self):
        return {
            "app_name": self.apk.get_app_name(),
            "package_name": self.apk.get_package(),
            "main_activity": self.apk.get_main_activity(),
            "app_class": self.apk.get_attribute_value("application", "name"),
            "internal_version": self._safe_androidversion_name(),
            "displayed_version": self._safe_androidversion_code(),
            "min_sdk": self.apk.get_min_sdk_version(),
            "target_sdk": self.apk.get_effective_target_sdk_version(),
        }

    def get_permissions(self):
        return self.apk.get_permissions()

    def get_components(self):
        return {
            "activities": {
                name: self.apk.get_intent_filters("activity", name)
                for name in self.apk.get_activities()
            },
            "services": {
                name: self.apk.get_intent_filters("service", name)
                for name in self.apk.get_services()
            },
            "receivers": {
                name: self.apk.get_intent_filters("receiver", name)
                for name in self.apk.get_receivers()
            },
            "providers": self.apk.get_providers(),
        }

    def get_native_libs(self):
        return sorted(
            f for f in self.apk.get_files()
            if f.startswith("lib/") and f.endswith(".so")
        )

    def get_certificates(self):
        return [self._parse_cert(cert) for cert in self.apk.get_certificates()]

    # -------------------------
    # Suspicious content (cached)
    # -------------------------

    def get_interesting_strings(self,max_depth=3):
        if self._strings is None:
            self._strings = self.analyzer.extract_relevant_strings(max_depth)
        return self._strings

    def get_interesting_classes(self,max_depth=2):
        if self._classes is None:
            self._classes = self.analyzer.extract_relevant_classes(max_depth)
        return self._classes

    def get_interesting_methods(self,max_depth=3):
        if self._methods is None:
            self._methods = self.analyzer.extract_relevant_methods(max_depth)
        return self._methods

    # -------------------------
    # Internal helpers
    # -------------------------

    @staticmethod
    def _parse_cert(cert_obj):
        cert = cert_obj.native
        tbs = cert["tbs_certificate"]

        return {
            "subject": tbs["subject"],
            "issuer": tbs["issuer"],
            "algorithm": cert["signature_algorithm"]["algorithm"],
            "serial_number": hex(tbs["serial_number"])[2:].strip("L"),
            "thumbprint": hashlib.sha1(cert_obj.dump()).hexdigest(),
            "valid_from": int(tbs["validity"]["not_before"].timestamp()),
            "valid_to": int(tbs["validity"]["not_after"].timestamp()),
        }


# -------------------------------------------------
# Context cache (important for tool-based systems)
# -------------------------------------------------

_CONTEXT_CACHE = {}

def get_apk_context(apk_path: str) -> APKContext:
    if apk_path not in _CONTEXT_CACHE:
        _CONTEXT_CACHE[apk_path] = APKContext(apk_path)
    return _CONTEXT_CACHE[apk_path]


def clear_apk_context(apk_path: str) -> None:
    _CONTEXT_CACHE.pop(apk_path, None)


# -------------------------------------------------
# Tool registry (LLM / agent compatible)
# -------------------------------------------------

TOOL_REGISTRY = {}

# def register_tool(name, func, description):
#     TOOL_REGISTRY[name] = {
#         "func": func,
#         "description": description,
#         "parameters": {"apk_path": "string"},
#     }

def register_tool(name, func):
    TOOL_REGISTRY[name] = func


def register_apk_tools():
    register_tool(
        "get_basic_info",
        lambda args: get_apk_context(args["apk_path"]).get_basic_info()
    )

    register_tool(
        "get_permissions",
        lambda args: get_apk_context(args["apk_path"]).get_permissions()
    )

    register_tool(
        "get_components",
        lambda args: get_apk_context(args["apk_path"]).get_components()
    )

    register_tool(
        "get_certificates",
        lambda args: get_apk_context(args["apk_path"]).get_certificates()
    )

    register_tool(
        "get_native_libs",
        lambda args: get_apk_context(args["apk_path"]).get_native_libs()
    )

    register_tool(
        "get_interesting_strings",
        lambda args: get_apk_context(args["apk_path"]).get_interesting_strings()
    )

    register_tool(
        "get_interesting_classes",
        lambda args: get_apk_context(args["apk_path"]).get_interesting_classes()
    )

    register_tool(
        "get_interesting_methods",
        lambda args: get_apk_context(args["apk_path"]).get_interesting_methods()
    )


# a = APKContext("E:\\samples\\bigger_RAT\\e0eacd72afe39de3b327a164f9c69a78c9c0f672d3ad202271772d816db4fad8.apk")
# print(a.get_interesting_classes(2))
