from collections import defaultdict
import statistics
import hashlib
import sys
import os
import threading
import subprocess
import time
import uuid
from dataclasses import dataclass
from typing import Dict, Any, List
import zipfile
import re
import io
import json
import logging
import argparse
import sqlite3
import datetime as dt
import requests
from typing import List, Dict, Any, Tuple, Optional
from openai import OpenAI
import openai, certifi, httpx
from DefineRegisterTools_new import get_apk_context, clear_apk_context
import apk_pipeline_v2

# -------------------- I/O ENCODING --------------------
utf8_stream = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8',errors="replace")
sys.stdout.reconfigure(encoding='utf-8')

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
    handlers=[logging.StreamHandler(utf8_stream)]
)

# -------------------- CONFIG --------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(SCRIPT_DIR, "config.json")
_RUNTIME_CONFIG_CACHE: Optional[Dict[str, Any]] = None

# -- Runtime enrichment flags (set from CLI args at startup) ------------------
_USE_SMBA: bool = False
_VT_API_KEY: Optional[str] = None
_SMBA_JSESSIONID: Optional[str] = None  # overrides .env when set via --smba-jsessionid


@dataclass(frozen=True)
class LLMKeyConfig:
    name: str
    api_key: str
    base_url: Optional[str] = None


def load_runtime_config() -> Dict[str, Any]:
    global _RUNTIME_CONFIG_CACHE
    if _RUNTIME_CONFIG_CACHE is not None:
        return _RUNTIME_CONFIG_CACHE

    if not os.path.isfile(CONFIG_PATH):
        _RUNTIME_CONFIG_CACHE = {}
        return _RUNTIME_CONFIG_CACHE

    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        raw = f.read().strip()

    if not raw:
        _RUNTIME_CONFIG_CACHE = {}
        return _RUNTIME_CONFIG_CACHE

    payload = json.loads(raw)
    _RUNTIME_CONFIG_CACHE = payload if isinstance(payload, dict) else {}
    return _RUNTIME_CONFIG_CACHE


def get_llm_request_metadata(config: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    config = config or load_runtime_config()
    metadata = config.get("llm_request_metadata")
    if isinstance(metadata, dict) and metadata:
        return metadata

    guardrails = config.get("guardrails")
    if isinstance(guardrails, dict) and guardrails:
        return {"guardrails": guardrails}

    return None


def get_disabled_guardrail_metadata(
    config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    config = config or load_runtime_config()
    metadata = config.get("llm_guardrails_disabled_metadata")
    if isinstance(metadata, dict) and metadata:
        return metadata

    return {
        "guardrails": {
            "custom-pre-guard": False,
            "custom-post-guard": False,
        }
    }


def should_retry_without_guardrails(config: Optional[Dict[str, Any]] = None) -> bool:
    config = config or load_runtime_config()
    value = config.get("disable_guardrails_on_policy_error")
    if value is None:
        return True
    return bool(value)


def is_guardrail_policy_error(exc: Exception) -> bool:
    message = str(exc or "").lower()
    markers = (
        "guardrail",
        "guardrails",
        "policy error",
        "policy violation",
        "violates policy",
        "content policy",
        "content_filter",
        "safety system",
        "blocked by policy",
    )
    return any(marker in message for marker in markers)


def parse_llm_json_content(content: str) -> Optional[Any]:
    text = str(content or "").strip()
    if not text:
        return None

    candidates = [text]

    fenced_match = re.search(r"```(?:json)?\s*(.*?)\s*```", text, re.DOTALL | re.IGNORECASE)
    if fenced_match:
        candidates.insert(0, fenced_match.group(1).strip())

    first_object = text.find("{")
    last_object = text.rfind("}")
    if first_object != -1 and last_object != -1 and last_object > first_object:
        candidates.append(text[first_object:last_object + 1])

    first_array = text.find("[")
    last_array = text.rfind("]")
    if first_array != -1 and last_array != -1 and last_array > first_array:
        candidates.append(text[first_array:last_array + 1])

    seen = set()
    for candidate in candidates:
        normalized = candidate.strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        try:
            return json.loads(normalized)
        except Exception:
            continue

    return None


def load_llm_key_configs(config: Dict[str, Any]) -> List[LLMKeyConfig]:
    base_url = config.get("base_url_zllama")
    keys: List[LLMKeyConfig] = []

    configured_entries = config.get("llm_api_keys")
    if isinstance(configured_entries, list):
        for idx, entry in enumerate(configured_entries, start=1):
            if isinstance(entry, dict):
                api_key = str(entry.get("api_key") or entry.get("value") or "").strip()
                if not api_key:
                    continue
                name = str(entry.get("name") or f"runner-{idx}").strip() or f"runner-{idx}"
                keys.append(
                    LLMKeyConfig(
                        name=name,
                        api_key=api_key,
                        base_url=str(entry.get("base_url") or base_url or "").strip() or None,
                    )
                )
            else:
                api_key = str(entry or "").strip()
                if api_key:
                    keys.append(
                        LLMKeyConfig(
                            name=f"runner-{idx}",
                            api_key=api_key,
                            base_url=str(base_url or "").strip() or None,
                        )
                    )

    if keys:
        return keys

    legacy_key = str(config.get("api_key_zllama") or "").strip()
    if legacy_key:
        return [
            LLMKeyConfig(
                name=str(config.get("llm_runner_name") or "runner-1").strip() or "runner-1",
                api_key=legacy_key,
                base_url=str(base_url or "").strip() or None,
            )
        ]

    return []


def summarize_llm_key_configuration(config: Dict[str, Any]) -> Dict[str, Any]:
    configured_entries = config.get("llm_api_keys")
    active_names: List[str] = []
    inactive_names: List[str] = []

    if isinstance(configured_entries, list):
        for idx, entry in enumerate(configured_entries, start=1):
            if isinstance(entry, dict):
                name = str(entry.get("name") or f"runner-{idx}").strip() or f"runner-{idx}"
                api_key = str(entry.get("api_key") or entry.get("value") or "").strip()
            else:
                name = f"runner-{idx}"
                api_key = str(entry or "").strip()

            if api_key:
                active_names.append(name)
            else:
                inactive_names.append(name)

        return {
            "active_names": active_names,
            "inactive_names": inactive_names,
            "uses_legacy_key": False,
        }

    legacy_key = str(config.get("api_key_zllama") or "").strip()
    if legacy_key:
        return {
            "active_names": [
                str(config.get("llm_runner_name") or "runner-1").strip() or "runner-1"
            ],
            "inactive_names": [],
            "uses_legacy_key": True,
        }

    return {
        "active_names": [],
        "inactive_names": [],
        "uses_legacy_key": False,
    }


def create_llm_client(key_config: LLMKeyConfig) -> OpenAI:
    kwargs: Dict[str, Any] = {"api_key": key_config.api_key}
    if key_config.base_url:
        kwargs["base_url"] = key_config.base_url
    return OpenAI(**kwargs)


def sanitize_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "worker")).strip("._") or "worker"


def utc_after_iso(seconds: float) -> str:
    return (dt.datetime.now(tz=dt.timezone.utc) + dt.timedelta(seconds=float(seconds))).isoformat()


def pick_llm_key_config(key_name: Optional[str], config: Dict[str, Any]) -> LLMKeyConfig:
    keys = load_llm_key_configs(config)
    if not keys:
        raise RuntimeError(
            "No LLM API keys configured in llm_V1/config.json. "
            "Set api_key_zllama for single-key mode or llm_api_keys for multi-key mode."
        )

    if key_name is None:
        return keys[0]

    for key in keys:
        if key.name == key_name:
            return key

    available = ", ".join(key.name for key in keys)
    raise RuntimeError(f"Unknown llm key name {key_name!r}. Available keys: {available}")

# -------------------- CONSTANTS --------------------
SUSPICIOUS_TLDS = {".ru", ".cn", ".su", ".top", ".xyz", ".click", ".pw", ".kim"}
BENIGN_DOMAIN_WHITELIST = {
    "google.com", "gstatic.com", "googleapis.com", "firebaseio.com",
    "googleusercontent.com", "gvt1.com", "ggpht.com", "app-measurement.com",
    "facebook.com", "fbcdn.net", "whatsapp.net",
    "crashlytics.com", "fabric.io", "appsflyer.com", "branch.io",
    "cloudflare.com", "cloudfront.net", "akamaihd.net", "microsoft.com",
    "amazonaws.com"
}
SENSITIVE_PERMS = {
    "READ_SMS", "RECEIVE_SMS", "SEND_SMS",
    "READ_CALL_LOG", "WRITE_CALL_LOG", "PROCESS_OUTGOING_CALLS",
    "READ_CONTACTS", "WRITE_CONTACTS",
    "RECORD_AUDIO", "CAMERA",
    "READ_PHONE_STATE", "ANSWER_PHONE_CALLS", "CALL_PHONE",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
    "BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW",
    "PACKAGE_USAGE_STATS", "REQUEST_INSTALL_PACKAGES",
    "READ_MEDIA_AUDIO", "READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO",
    "WRITE_SETTINGS"
}
COMMON_BENIGN_PERMS = {
    "INTERNET", "ACCESS_NETWORK_STATE", "ACCESS_WIFI_STATE", "WAKE_LOCK",
    "VIBRATE", "FOREGROUND_SERVICE", "RECEIVE_BOOT_COMPLETED",
    "ACCESS_COARSE_LOCATION", "ACCESS_FINE_LOCATION"
}
STRONG_CODE_PATTERNS = [
    r"\bDexClassLoader\b", r"\bPathClassLoader\b",
    r"\bRuntime\.getRuntime\(\)\.exec\(",
    r"\bProcessBuilder\(",
    r"\bsu\s*-c\b",
    r"\bchmod\b", r"\bchown\b", r"\bmount\b", r"\brm\s+-rf\b",
    r"\beval\(", r"\bloadUrl\("
]
MEDIUM_CODE_PATTERNS = [
    r"\bBase64\.decode\b", r"\bCipher\.getInstance\b",
    r"\bKeyStore\b", r"\bMessageDigest\b",
    r"\bAccessibilityService\b", r"\bJobScheduler\b",
    r"\bAlarmManager\b", r"\bBroadcastReceiver\b",
]
DOMAIN_REGEX = re.compile(r"\b([a-z0-9][a-z0-9\-]{1,63}\.)+[a-z]{2,}\b", re.IGNORECASE)
IP_REGEX = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")
PRIVATE_IP_RANGES = [
    re.compile(r"^10\."), re.compile(r"^192\.168\."), re.compile(r"^172\.(1[6-9]|2\d|3[0-1])\.")
]
TERMINAL_SAMPLE_STATUSES = {"done", "corrupt"}
RETRYABLE_SAMPLE_STATUSES = {"failed", "in_progress"}
RUNNER_KEY_UNAVAILABLE_EXIT_CODE = 20
WORKER_RESCAN_SLEEP_SEC = 5.0


def is_terminal_corrupt_error(error: Exception) -> bool:
    message = str(error or "").lower()
    terminal_markers = (
        "is encrypted, password required for extraction",
        "password required for extraction",
        "bad crc-32",
        "bad crc",
        "file is not a zip file",
        "bad zip file",
        "error -3 while decompressing",
        "end-of-central-directory signature not found",
    )
    return any(marker in message for marker in terminal_markers)


class AnalysisStateDB:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self._init()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=60)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=60000;")
        return conn

    def _init(self):
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS analysis_samples (
                  sha256 TEXT PRIMARY KEY,
                  apk_name TEXT NOT NULL,
                  apk_path TEXT NOT NULL,
                  status TEXT NOT NULL,
                  attempts INTEGER NOT NULL DEFAULT 0,
                  last_error TEXT,
                  log_path TEXT,
                  verdict_path TEXT,
                  started_at_utc TEXT,
                  finished_at_utc TEXT,
                  runner_id TEXT,
                  llm_key_name TEXT,
                  lease_expires_at_utc TEXT
                );
                """
            )
            existing_columns = {
                str(row[1]) for row in conn.execute("PRAGMA table_info(analysis_samples);").fetchall()
            }
            required_columns = {
                "runner_id": "TEXT",
                "llm_key_name": "TEXT",
                "lease_expires_at_utc": "TEXT",
            }
            for column_name, column_type in required_columns.items():
                if column_name not in existing_columns:
                    conn.execute(
                        f"ALTER TABLE analysis_samples ADD COLUMN {column_name} {column_type};"
                    )
            conn.commit()

    def get(self, sha256: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            cur = conn.execute(
                """
                SELECT sha256, apk_name, apk_path, status, attempts, last_error,
                       log_path, verdict_path, started_at_utc, finished_at_utc,
                       runner_id, llm_key_name, lease_expires_at_utc
                FROM analysis_samples
                WHERE sha256 = ?;
                """,
                (sha256,),
            )
            row = cur.fetchone()
        if row is None:
            return None
        return {
            "sha256": row[0],
            "apk_name": row[1],
            "apk_path": row[2],
            "status": row[3],
            "attempts": int(row[4] or 0),
            "last_error": row[5],
            "log_path": row[6],
            "verdict_path": row[7],
            "started_at_utc": row[8],
            "finished_at_utc": row[9],
            "runner_id": row[10],
            "llm_key_name": row[11],
            "lease_expires_at_utc": row[12],
        }

    def try_claim(
        self,
        *,
        sha256: str,
        apk_name: str,
        apk_path: str,
        log_path: str,
        verdict_path: str,
        runner_id: str,
        llm_key_name: str,
        lease_duration_sec: float,
    ) -> bool:
        now = utc_now_iso()
        lease_expires_at = utc_after_iso(lease_duration_sec)
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO analysis_samples
                  (sha256, apk_name, apk_path, status, attempts, log_path, verdict_path,
                   started_at_utc, finished_at_utc, runner_id, llm_key_name, lease_expires_at_utc)
                VALUES (?, ?, ?, 'in_progress', 1, ?, ?, ?, NULL, ?, ?, ?)
                ON CONFLICT(sha256) DO UPDATE SET
                  apk_name = excluded.apk_name,
                  apk_path = excluded.apk_path,
                  status = 'in_progress',
                  attempts = analysis_samples.attempts + 1,
                  last_error = NULL,
                  log_path = excluded.log_path,
                  verdict_path = excluded.verdict_path,
                  started_at_utc = excluded.started_at_utc,
                  finished_at_utc = NULL,
                  runner_id = excluded.runner_id,
                  llm_key_name = excluded.llm_key_name,
                  lease_expires_at_utc = excluded.lease_expires_at_utc
                WHERE analysis_samples.status NOT IN ('done', 'corrupt')
                  AND (
                    analysis_samples.status != 'in_progress'
                    OR COALESCE(analysis_samples.lease_expires_at_utc, '') <= ?
                    OR analysis_samples.runner_id = ?
                  );
                """,
                (
                    sha256,
                    apk_name,
                    apk_path,
                    log_path,
                    verdict_path,
                    now,
                    runner_id,
                    llm_key_name,
                    lease_expires_at,
                    now,
                    runner_id,
                ),
            )
            conn.commit()
            return int(cur.rowcount or 0) > 0

    def renew_lease(self, *, sha256: str, runner_id: str, lease_duration_sec: float) -> bool:
        with self._connect() as conn:
            cur = conn.execute(
                """
                UPDATE analysis_samples
                SET lease_expires_at_utc = ?
                WHERE sha256 = ? AND runner_id = ? AND status = 'in_progress';
                """,
                (utc_after_iso(lease_duration_sec), sha256, runner_id),
            )
            conn.commit()
            return int(cur.rowcount or 0) > 0

    def finish(
        self,
        *,
        sha256: str,
        status: str,
        last_error: Optional[str] = None,
        runner_id: Optional[str] = None,
    ):
        where_clause = "WHERE sha256 = ?"
        params: List[Any] = [status, last_error, utc_now_iso()]
        if runner_id:
            where_clause += " AND runner_id = ?"
        params.append(sha256)
        if runner_id:
            params.append(runner_id)

        with self._connect() as conn:
            conn.execute(
                f"""
                UPDATE analysis_samples
                SET status = ?, last_error = ?, finished_at_utc = ?,
                    runner_id = NULL, lease_expires_at_utc = NULL
                {where_clause};
                """,
                params,
            )
            conn.commit()

    def status_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT status, COUNT(*) FROM analysis_samples GROUP BY status;"
            )
            for status, count in cur.fetchall():
                counts[str(status)] = int(count)
        return counts

    def close(self):
        return None


class LeaseHeartbeat:
    def __init__(
        self,
        *,
        state_db: AnalysisStateDB,
        sha256: str,
        runner_id: str,
        lease_duration_sec: float,
        logger,
    ):
        self.state_db = state_db
        self.sha256 = sha256
        self.runner_id = runner_id
        self.lease_duration_sec = float(lease_duration_sec)
        self.logger = logger
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        refresh_interval = max(30.0, min(self.lease_duration_sec / 3.0, 300.0))

        def keep_alive() -> None:
            while not self._stop.wait(refresh_interval):
                try:
                    renewed = self.state_db.renew_lease(
                        sha256=self.sha256,
                        runner_id=self.runner_id,
                        lease_duration_sec=self.lease_duration_sec,
                    )
                    if not renewed:
                        self.logger.warning(
                            "Lease renewal skipped because sample ownership changed for %s",
                            self.sha256,
                        )
                        return
                except Exception as exc:
                    self.logger.warning("Lease renewal failed for %s: %s", self.sha256, exc)

        self._thread = threading.Thread(target=keep_alive, name=f"lease-{self.sha256[:8]}", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)


def utc_now_iso() -> str:
    return dt.datetime.now(tz=dt.timezone.utc).isoformat()


class LLMUnavailableError(RuntimeError):
    pass


def compute_file_sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: str, payload: dict) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


def probe_apk_readability(apk_path: str) -> Tuple[bool, str]:
    try:
        get_apk_context(apk_path)
        return True, ""
    except Exception as e:
        return False, str(e)

# -------------------- LOGGER --------------------
def setup_logger(log_file_path, apk_name):
    # Unique logger per APK
    logger = logging.getLogger(f"LLM_Logger_{apk_name}")
    logger.setLevel(logging.INFO)

    # Remove old handlers (avoid duplicates when re-running)
    if logger.hasHandlers():
        logger.handlers.clear()

    fh = logging.FileHandler(log_file_path, mode="w", encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
    logger.addHandler(fh)

    return logger


def safe_log(logger, msg):
    logger.info(msg.encode("utf-8", errors="replace").decode("utf-8"))

LLM_CALL_STATS = {
    "call_count": 0,
    "prompt_tokens": 0,
    "completion_tokens": 0,
    "total_tokens": 0,
    "estimated_tokens": 0,
    "token_count_estimated": False,
}


def reset_llm_call_stats() -> None:
    LLM_CALL_STATS.clear()
    LLM_CALL_STATS.update({
        "call_count": 0,
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "total_tokens": 0,
        "estimated_tokens": 0,
        "token_count_estimated": False,
    })


def get_llm_call_stats() -> Dict[str, Any]:
    return dict(LLM_CALL_STATS)


def _usage_to_dict(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if value is None:
        return {}
    if hasattr(value, "model_dump"):
        try:
            dumped = value.model_dump()
            if isinstance(dumped, dict):
                return dumped
        except Exception:
            pass
    if hasattr(value, "dict"):
        try:
            dumped = value.dict()
            if isinstance(dumped, dict):
                return dumped
        except Exception:
            pass
    return {}


def _usage_int(source: Any, key: str) -> int:
    if source is None:
        return 0
    if isinstance(source, dict):
        value = source.get(key, 0)
    else:
        value = getattr(source, key, 0)
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _extract_usage_counts(response: Any) -> Dict[str, int]:
    usage = getattr(response, "usage", None)
    usage_dict = _usage_to_dict(usage)

    if not usage_dict and hasattr(response, "model_dump"):
        try:
            response_dict = response.model_dump()
            usage_dict = _usage_to_dict(response_dict.get("usage")) if isinstance(response_dict, dict) else {}
        except Exception:
            usage_dict = {}

    prompt_tokens = _usage_int(usage_dict or usage, "prompt_tokens")
    completion_tokens = _usage_int(usage_dict or usage, "completion_tokens")
    total_tokens = _usage_int(usage_dict or usage, "total_tokens")

    if not total_tokens:
        prompt_tokens = prompt_tokens or _usage_int(response, "prompt_tokens")
        completion_tokens = completion_tokens or _usage_int(response, "completion_tokens")
        total_tokens = _usage_int(response, "total_tokens")

    if not total_tokens and (prompt_tokens or completion_tokens):
        total_tokens = prompt_tokens + completion_tokens

    return {
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": total_tokens,
    }


def _estimate_tokens_from_messages(messages: List[Dict[str, Any]], content: str) -> int:
    text_parts: List[str] = []
    for message in messages or []:
        if isinstance(message, dict):
            text_parts.append(str(message.get("content") or ""))
        else:
            text_parts.append(str(message))
    text_parts.append(str(content or ""))
    # Conservative fallback when the gateway omits usage. This is explicitly
    # marked as estimated in output payloads.
    return max(1, int(sum(len(part) for part in text_parts) / 4))


# -------------------- TOOLS --------------------
def run_tools(apk_path, logger):
    results = {}
    for tool_name, tool_func in TOOL_REGISTRY.items():
        try:
            logger.info(f"Running tool: {tool_name}")
            results[tool_name] = tool_func({"apk_path": apk_path})
        except Exception as e:
            results[tool_name] = {"error": str(e)}
            logger.error(f"Tool {tool_name} failed: {e}")
    return results

def call_llm(messages, model, logger, llm_client: OpenAI, max_retries=3):
    """
    Call LLM through the ZLlama/OpenAI-compatible client.
    Tracks call count and total tokens used in global context.
    """
    runtime_config = load_runtime_config()
    default_metadata = get_llm_request_metadata(runtime_config)
    disabled_guardrail_metadata = get_disabled_guardrail_metadata(runtime_config)
    allow_guardrail_retry = should_retry_without_guardrails(runtime_config)

    for attempt in range(1, max_retries + 1):
        used_guardrail_fallback = False
        try:
            request_kwargs = {
                "model": model,
                "messages": messages,
                "temperature": 0.2,
                "stream": False,
            }
            if default_metadata:
                request_kwargs["metadata"] = default_metadata

            try:
                response = llm_client.chat.completions.create(**request_kwargs)
            except Exception as exc:
                if not (
                    allow_guardrail_retry
                    and is_guardrail_policy_error(exc)
                    and default_metadata != disabled_guardrail_metadata
                ):
                    raise

                fallback_kwargs = dict(request_kwargs)
                fallback_kwargs["metadata"] = disabled_guardrail_metadata
                used_guardrail_fallback = True
                logger.warning(
                    "Guardrail policy block detected for model %s on attempt %s; retrying with guardrails disabled.",
                    model,
                    attempt,
                )
                response = llm_client.chat.completions.create(**fallback_kwargs)

            content = response.choices[0].message.content

            usage_counts = _extract_usage_counts(response)
            total_tokens = usage_counts["total_tokens"]
            estimated = False
            if not total_tokens:
                total_tokens = _estimate_tokens_from_messages(messages, str(content or ""))
                estimated = True

            LLM_CALL_STATS["call_count"] += 1
            LLM_CALL_STATS["prompt_tokens"] += usage_counts["prompt_tokens"]
            LLM_CALL_STATS["completion_tokens"] += usage_counts["completion_tokens"]
            LLM_CALL_STATS["total_tokens"] += total_tokens
            if estimated:
                LLM_CALL_STATS["estimated_tokens"] += total_tokens
                LLM_CALL_STATS["token_count_estimated"] = True
                logger.warning(
                    "LLM response did not include usage metadata; estimated %d tokens for model %s.",
                    total_tokens,
                    model,
                )

            if content is None or not str(content).strip():
                logger.error(f"LLM returned empty content on attempt {attempt}")
                continue

            if used_guardrail_fallback:
                logger.info(
                    "LLM response succeeded after retrying with guardrails disabled for model %s.",
                    model,
                )

            safe_log(logger, f"LLM Attempt {attempt} Raw: {content}")

            parsed = parse_llm_json_content(content)
            if parsed is not None:
                return parsed

            try:
                return json.loads(content)
            except Exception:
                return {
                    "summary": content,
                    "relevant": [],
                    "evidence": []
                }

        except Exception as e:
            logger.error(f"LLM error on attempt {attempt}: {e}")
            continue

    logger.error("LLM failed after retries.")
    raise LLMUnavailableError("LLM request failed after retries or returned no response")

# # -------------------- LLM CALL --------------------
# def call_llm(messages, model, logger, max_retries=3):
#     for attempt in range(1, max_retries + 1):
#         payload = {"messages": messages, "model": model, "stream": False}
#         try:

#             response = requests.post(LLM_URL, headers=HEADERS, data=json.dumps(payload),timeout=260)
#             if not response.text.strip():
#                 logger.error(f"Empty response from API on attempt {attempt}")
#                 continue
#             try:
#                 data = json.loads(response.text)
#             except Exception as e:
#                 logger.error(f"Failed to load JSON from API response. Error: {e}")
#                 continue

#             if "message" in data and "content" in data["message"]:
#                 content = data["message"]["content"]
#             elif "choices" in data and len(data["choices"]) > 0:
#                 content = data["choices"][0]["message"]["content"]
#             else:
#                 logger.error(f"Unexpected response format: {data}")
#                 continue

#             safe_log(logger, f"LLM Attempt {attempt} Raw: {content}")

#             try:
#                 return json.loads(content)
#             except Exception:
#                 return {"summary": content, "evidence": [], "relevant": []}

#         except Exception as e:
#             logger.error(f"Transport/Parsing error on attempt {attempt}: {e}")
#             continue

#     logger.error("LLM failed after retries.")
#     return None

# -------------------- CHUNKING --------------------
def chunk_list(lst: List[Any], size=300):
    for i in range(0, len(lst), size):
        yield lst[i:i + size]


# -------------------- PROMPTS (CHUNK ANALYSIS) --------------------
EVIDENCE_SCHEMA_TEXT = """
Return ONLY JSON with this schema:
{
  "summary": "short summary of THIS CHUNK",
  "relevant": ["items from input"],
  "evidence": [
    {
      "indicator": "string/API/class/permission",
      "source": "strings|classes|permissions",
      "category": "networking|exec|dynamic_loading|crypto|evasion|exfil|overlay|accessibility|sms|call|storage|other",
      "strength": "strong|medium|weak",
      "confidence": 0.0-1.0,
      "explanation": "1 short sentence"
    }
  ]
}
If nothing suspicious, return an empty 'evidence' and benign 'summary'.
"""

BASE_CHUNK_HEADER = """
You are an expert Android malware analyst.
[!] Default to BENIGN unless clear malicious intent exists.
- Sensitive permissions, reflection, crypto, ads, analytics SDKs, Firebase alone are NOT malicious.
- strong  = clear abuse (C2, exec, dynamic load, root, SMS exfil)
- medium  = unusual but context-dependent (Accessibility + overlay, obfuscation + network)
- weak    = common benign signals
Only extract indicators from provided input.
"""

def prompt_strings_chunk(chunk: str):
    return [
        {"role": "system", "content": "Only output valid JSON."},
        {"role": "user", "content": f"""{BASE_CHUNK_HEADER}
Analyze these APK STRINGS:

{EVIDENCE_SCHEMA_TEXT}

--- STRINGS START ---
{chunk}
--- STRINGS END ---
"""}
    ]

def prompt_permissions_chunk(chunk: str):
    return [
        {"role": "system", "content": "Only output valid JSON."},
        {"role": "user", "content": f"""{BASE_CHUNK_HEADER}
Analyze these APK PERMISSIONS.

{EVIDENCE_SCHEMA_TEXT}

--- PERMISSIONS START ---
{chunk}
--- PERMISSIONS END ---
"""}
    ]

def prompt_classes_chunk(chunk: str):
    return [
        {"role": "system", "content": "Only output valid JSON."},
        {"role": "user", "content": f"""{BASE_CHUNK_HEADER}
Analyze these APK CLASSES:

{EVIDENCE_SCHEMA_TEXT}

--- CLASSES START ---
{chunk}
--- CLASSES END ---
"""}
    ]

def prompt_methods_chunk(chunk: str):
    return [
        {"role": "system", "content": "Only output valid JSON."},
        {"role": "user", "content": f"""{BASE_CHUNK_HEADER}
Analyze these APK METHODS:

{EVIDENCE_SCHEMA_TEXT}

--- METHODS START ---
{chunk}
--- METHODS END ---
"""}
    ]

#------------------yara deection -----------------------------------
""" Make sure to run the update_yara_export.py file to update the export files"""
def add_yara_scan_result(apk_path):
    dump_individual_apk(apk_path)
    apk_dir = os.path.dirname(apk_path)
    apk_name = os.path.basename(apk_path)
    bin_folder = os.path.join(apk_dir, f"bin_{apk_name}")

    # Compute md5 of apk to match dump filename
    apk_md5 = hashlib.md5(open(apk_path, 'rb').read()).hexdigest()
    bin_file = os.path.join(bin_folder, f"{apk_md5}_apk_dump.bin")

    report = scan_this_bin_file_with_static_yara(bin_file)
    # print(report)
    return report


def append_response_data(result_dict):
    summary = result_dict.get("summary", "")
    summaries = ""
    if len(summary) < 400:
       summaries = summary
    all_relevant = result_dict.get("relevant", [])
    all_evidence = result_dict.get("evidence", [])
    return summaries,all_relevant,all_evidence


def normalize_tool_list(value, *, logger, tool_name: str) -> List[Any]:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    if isinstance(value, dict) and value.get("error"):
        logger.warning(f"[{tool_name}] tool returned error payload: {value['error']}")
        return []
    logger.warning(f"[{tool_name}] unexpected payload type {type(value).__name__}; treating as empty list")
    return []


def normalize_tool_dict(value, *, logger, tool_name: str) -> Dict[str, Any]:
    if isinstance(value, dict) and not value.get("error"):
        return value
    if value is None:
        return {}
    if isinstance(value, dict) and value.get("error"):
        logger.warning(f"[{tool_name}] tool returned error payload: {value['error']}")
        return {}
    logger.warning(f"[{tool_name}] unexpected payload type {type(value).__name__}; treating as empty dict")
    return {}


# -------------------- CHUNK ANALYZERS --------------------
def analyze_strings_with_chunking(apk_strings: List[str], logger, model, llm_client: OpenAI, chunk_size=200):
    apk_strings = normalize_tool_list(apk_strings, logger=logger, tool_name="get_interesting_strings")
    if not apk_strings:
        return {
            "summary": "",
            "relevant_strings": [],
            "evidence": []
        }

    all_relevant, all_evidence, summaries = [], [], []
    for idx, chunk in enumerate(chunk_list(apk_strings, size=chunk_size), start=1):
        logger.info(f"[strings] Analyzing chunk {idx} ({len(chunk)} items)")
        result = call_llm(prompt_strings_chunk("\n".join(chunk)), model, logger, llm_client) or {}

        if result:
            if isinstance(result,dict):
                chunk_summary,chunk_all_relevant,chunk_all_evidence = append_response_data(result)
                summaries.append(chunk_summary)
                all_relevant.extend(chunk_all_relevant)
                all_evidence.extend(chunk_all_evidence)
            elif isinstance(result,list):
                for each_result in result:
                    chunk_summary,chunk_all_relevant,chunk_all_evidence = append_response_data(each_result)
                    summaries.append(chunk_summary)
                    all_relevant.extend(chunk_all_relevant)
                    all_evidence.extend(chunk_all_evidence)
    return {
        "summary": " ".join(s for s in summaries if s)[:2000],
        "relevant_strings": sorted(set(all_relevant))[:200],
        "evidence": all_evidence
    }

def analyze_permissions_with_chunking(apk_perms: List[str], logger, model, llm_client: OpenAI, chunk_size=100):
    apk_perms = normalize_tool_list(apk_perms, logger=logger, tool_name="get_permissions")
    if not apk_perms:
        return {
            "summary": "",
            "relevant_permissions": [],
            "evidence": []
        }

    all_relevant, all_evidence, summaries = [], [], []
    for idx, chunk in enumerate(chunk_list(apk_perms, size=chunk_size), start=1):
        logger.info(f"[perms] Analyzing chunk {idx} ({len(chunk)} items)")
        result = call_llm(prompt_permissions_chunk("\n".join(chunk)), model, logger, llm_client) or {}
        
        if result:
            if isinstance(result,dict):
                chunk_summary,chunk_all_relevant,chunk_all_evidence = append_response_data(result)
                summaries.append(chunk_summary)
                all_relevant.extend(chunk_all_relevant)
                all_evidence.extend(chunk_all_evidence)
            elif isinstance(result,list):
                for each_result in result:
                    chunk_summary,chunk_all_relevant,chunk_all_evidence = append_response_data(each_result)
                    summaries.append(chunk_summary)
                    all_relevant.extend(chunk_all_relevant)
                    all_evidence.extend(chunk_all_evidence)

    return {
        "summary": " ".join(s for s in summaries if s)[:2000],
        "relevant_permissions": sorted(set(all_relevant))[:200],
        "evidence": all_evidence
    }

def analyze_classes_with_chunking(apk_classes: dict, logger, model, llm_client: OpenAI, chunk_size=1):
    apk_classes = normalize_tool_dict(apk_classes, logger=logger, tool_name="get_interesting_classes")
    if not apk_classes:
        return {
            "summary": "",
            "relevant_classes": [],
            "evidence": []
        }

    all_relevant, all_evidence, summaries = [], [], []
    items = list(apk_classes.items())
    for idx, chunk in enumerate(chunk_list(items, size=chunk_size), start=1):
        logger.info(f"[classes] Analyzing class {idx}")
        chunk_str = "\n\n".join(f"{classname}:\n{code}" for classname, code in chunk)
        result = call_llm(prompt_classes_chunk(chunk_str), model, logger, llm_client) or {}
        
        if result:
            if isinstance(result,dict):
                chunk_summary,chunk_all_relevant,chunk_all_evidence = append_response_data(result)
                summaries.append(chunk_summary)
                all_relevant.extend(chunk_all_relevant)
                all_evidence.extend(chunk_all_evidence)
            elif isinstance(result,list):
                for each_result in result:
                    chunk_summary,chunk_all_relevant,chunk_all_evidence = append_response_data(each_result)
                    summaries.append(chunk_summary)
                    all_relevant.extend(chunk_all_relevant)
                    all_evidence.extend(chunk_all_evidence)
                    
    return {
        "summary": " ".join(s for s in summaries if s)[:2000],
        "relevant_classes": sorted(set(all_relevant))[:200],
        "evidence": all_evidence
    }

def analyze_methods_with_chunking(apk_methods: dict, logger, model, llm_client: OpenAI, chunk_size=5):
    apk_methods = normalize_tool_dict(apk_methods, logger=logger, tool_name="get_interesting_methods")
    if apk_methods:
        all_relevant, all_evidence, summaries = [], [], []
        items = list(apk_methods.items())
        for idx, chunk in enumerate(chunk_list(items, size=chunk_size), start=1):
            logger.info(f"[methods] Analyzing method {idx}")
            chunk_str = "\n\n".join(f"{methodname}:\n{code}" for methodname, code in chunk)
            result = call_llm(prompt_methods_chunk(chunk_str), model, logger, llm_client) or {}
            
            if result:
                if isinstance(result,dict):
                    chunk_summary,chunk_all_relevant,chunk_all_evidence = append_response_data(result)
                    summaries.append(chunk_summary)
                    all_relevant.extend(chunk_all_relevant)
                    all_evidence.extend(chunk_all_evidence)
                elif isinstance(result,list):
                    for each_result in result:
                        chunk_summary,chunk_all_relevant,chunk_all_evidence = append_response_data(each_result)
                        summaries.append(chunk_summary)
                        all_relevant.extend(chunk_all_relevant)
                        all_evidence.extend(chunk_all_evidence)
                        
        return {
            "summary": " ".join(s for s in summaries if s)[:2000],
            "relevant_methods": sorted(set(all_relevant))[:200],
            "evidence": all_evidence
        }
    else:
        return {'summary': '', 'relevant_methods': [], 'evidence': []}
# -------------------- STATIC INDICATOR EXTRACTION --------------------
def is_private_ip(ip: str) -> bool:
    return any(p.match(ip) for p in PRIVATE_IP_RANGES)

def extract_domains_ips(text_blob: str) -> Tuple[List[str], List[str]]:
    domains = set(m.group(0).lower() for m in DOMAIN_REGEX.finditer(text_blob))
    ips = set(m.group(0) for m in IP_REGEX.finditer(text_blob))
    return sorted(domains), sorted(ips)

def static_evidence_from_tools(tool_results: Dict[str, Any]) -> List[Dict[str, Any]]:
    blob = json.dumps(tool_results, ensure_ascii=False)
    domains, ips = extract_domains_ips(blob)
    evidence = []

    for d in domains:
        base = d.split(":")[0]
        if any(base.endswith(tld) for tld in SUSPICIOUS_TLDS) and not any(base.endswith(w) for w in BENIGN_DOMAIN_WHITELIST):
            evidence.append({"indicator": d, "source": "strings", "category": "networking", "strength": "strong", "confidence": 0.9, "explanation": "Suspicious TLD"})
        elif any(base.endswith(w) for w in BENIGN_DOMAIN_WHITELIST):
            evidence.append({"indicator": d, "source": "strings", "category": "networking", "strength": "weak", "confidence": 0.8, "explanation": "Common benign domain"})
        else:
            evidence.append({"indicator": d, "source": "strings", "category": "networking", "strength": "medium", "confidence": 0.6, "explanation": "External domain"})

    for ip in ips:
        if is_private_ip(ip):
            evidence.append({"indicator": ip, "source": "strings", "category": "networking", "strength": "weak", "confidence": 0.7, "explanation": "Private IP"})
        else:
            evidence.append({"indicator": ip, "source": "strings", "category": "networking", "strength": "medium", "confidence": 0.7, "explanation": "External IP"})

    for pat in STRONG_CODE_PATTERNS:
        if re.search(pat, blob):
            evidence.append({"indicator": pat, "source": "classes", "category": "exec" if "exec" in pat else "dynamic_loading", "strength": "strong", "confidence": 0.85, "explanation": "Strong abuse pattern"})
    for pat in MEDIUM_CODE_PATTERNS:
        if re.search(pat, blob):
            evidence.append({"indicator": pat, "source": "classes", "category": "other", "strength": "medium", "confidence": 0.55, "explanation": "Context-dependent API"})

    return evidence

# -------------------- VERDICT ADJUDICATOR --------------------
def score_strength(strength: str) -> int:
    return {"strong": 3, "medium": 2, "weak": 1}.get(strength, 0)

def adjudicate(final_evidence: List[Dict[str, Any]]) -> Tuple[Dict[str, int], int, List[str]]:
    if not final_evidence:
        return {"Malicious": 0, "Suspicious": 0, "Clean": 1}, 5, []

    categories, risk, strong_count, iocs = {}, 0, 0, []
    for ev in final_evidence:
        st, cat, ind = ev.get("strength", "weak"), ev.get("category", "other"), ev.get("indicator", "")
        if ind: iocs.append(ind)
        categories.setdefault(cat, {"strong": 0, "medium": 0, "weak": 0})
        categories[cat][st] += 1
        risk += score_strength(st)
        if st == "strong" and cat in {"exec", "dynamic_loading", "networking", "evasion", "exfil", "sms"}:
            strong_count += 1

    distinct_medium_cats = sum(1 for c in categories.values() if c["medium"] > 0)
    distinct_strong_cats = sum(1 for c in categories.values() if c["strong"] > 0)

    # MALICIOUS
    if strong_count >= 1 and distinct_strong_cats >= 1:
        return {"Malicious": 1, "Suspicious": 0, "Clean": 0}, min(100, 70 + 8 * strong_count + 3 * distinct_strong_cats), sorted(set(iocs))[:50]

    # SUSPICIOUS
    if distinct_medium_cats >= 3 or risk >= 15:
        return {"Malicious": 0, "Suspicious": 1, "Clean": 0}, min(100, 50 + 2 * distinct_medium_cats + risk), sorted(set(iocs))[:50]

    # CLEAN
    return {"Malicious": 0, "Suspicious": 0, "Clean": 1}, min(100, max(5, 10 + risk)), sorted(set(iocs))[:50]


# --- Evidence consolidation helper ---
from typing import List, Dict, Any

def consolidate_evidence(
    evidence_list: List[Dict[str, Any]],
    limits: Dict[str, int] = {"strong": 60, "medium": 40, "weak": 20}
) -> List[Dict[str, Any]]:
    """
    Consolidate evidence by strength.
    - Groups weak/medium/strong indicators together
    - Keeps only the top-N (by confidence) indicators per bucket
    - Merges explanations and averages confidence
    """
    buckets = {"weak": [], "medium": [], "strong": []}

    # bucketize
    for ev in evidence_list:
        strength = ev.get("strength", "weak").lower()
        if strength in buckets:
            buckets[strength].append(ev)
        else:
            buckets["weak"].append(ev)

    consolidated = []

    for strength, items in buckets.items():
        if not items:
            continue

        # sort by confidence (high -> low)
        items_sorted = sorted(items, key=lambda x: x.get("confidence", 0.5), reverse=True)

        # cap items per bucket
        max_items = limits.get(strength, len(items_sorted))
        items_top = items_sorted[:max_items]

        # collect unique indicators
        indicators = list({i.get("indicator", "") for i in items_top})

        # average confidence of used items
        avg_conf = round(sum(i.get("confidence", 0.5) for i in items_top) / len(items_top), 2)

        # explanation summary
        explanations = list({i.get("explanation", "") for i in items_top if i.get("explanation")})
        explanation_summary = f"{len(items)} {strength} indicator(s) found, showing top {len(indicators)}. " + " ".join(explanations[:3])

        consolidated.append({
            "strength": strength,
            "indicators": indicators,
            "confidence": avg_conf,
            "explanation": explanation_summary.strip(),
            # "total_found": len(items),
            # "total_used": len(indicators)
        })

    return consolidated


def normalize_final_verdict(verdict: Any, logger) -> Optional[Dict[str, Any]]:
    if not isinstance(verdict, dict):
        logger.error("Final LLM verdict is not a JSON object")
        return None

    try:
        malicious = int(verdict.get("Malicious"))
        suspicious = int(verdict.get("Suspicious"))
        clean = int(verdict.get("Clean"))
    except Exception:
        logger.error("Final LLM verdict is missing required Malicious/Suspicious/Clean flags")
        return None

    if (malicious + suspicious + clean) != 1:
        logger.error(
            "Final LLM verdict is not one-hot: %s",
            json.dumps(verdict, ensure_ascii=False),
        )
        return None

    normalized: Dict[str, Any] = {
        "Malicious": malicious,
        "Suspicious": suspicious,
        "Clean": clean,
    }

    risk_score = verdict.get("Risk-Score")
    if risk_score is not None:
        try:
            normalized["Risk-Score"] = max(0, min(100, int(risk_score)))
        except Exception:
            logger.warning("Final LLM verdict had invalid Risk-Score; dropping it")

    summary = verdict.get("Summary")
    if isinstance(summary, str) and summary.strip():
        normalized["Summary"] = summary.strip()

    iocs = verdict.get("IOCs")
    if isinstance(iocs, list):
        normalized["IOCs"] = [str(item) for item in iocs if str(item).strip()][:100]

    return normalized


# --- Final LLM Verdict ---
def final_llm_verdict(
    apk_path,
    tool_results,
    preliminary_verdict,
    preliminary_risk,
    preliminary_iocs,
    consolidated_evidence,
    logger,
    llm_client: OpenAI,
):
    # # Step 1: consolidate evidence
    # raw_evidence = {
    #     "strings": tool_results.get("strings_analysis", {}).get("evidence", []),
    #     "classes": tool_results.get("classes_analysis", {}).get("evidence", []),
    #     "permissions": tool_results.get("permissions_analysis", {}).get("evidence", []),
    # }

    # Step 2: build user content
    user_content = {
        "apk_file": os.path.basename(apk_path),
        "preliminary_verdict": preliminary_verdict,
        "preliminary_risk_score": preliminary_risk,
        "tools_summary": {
            "apk_basic_info": tool_results.get("get_apk_basic_info", {}),
            "certs": tool_results.get("get_apk_certificates", {}),
            "permissions_summary": tool_results.get("permissions_analysis", {}).get("summary", ""),
            "classes_summary": tool_results.get("classes_analysis", {}).get("summary", ""),
            "strings_summary": tool_results.get("strings_analysis", {}).get("summary", ""),
            "yara_detections": tool_results.get("yara_detection", []),
        },
        "evidence": consolidated_evidence,
        "iocs": preliminary_iocs,
    }

    # # Step 3: handle YARA hits
    # yara_hits = tool_results.get("yara_detection", [])
    # yara_sig_text = ""
    # if yara_hits:
    #     yara_sig_text = (
    #         "\n\nIMPORTANT: YARA scan matched the following signature(s). "
    #         "These are authoritative and prove the APK is malicious.\n\n"
    #     )
    #     for hit in yara_hits:
    #         yara_sig_text += f"---\nSignature: {hit['detection_rule']}\nFull Rule:\n{hit['full_rule']}\n\n"

    # Step 4: build messages for LLM
    messages = [
        {
            "role": "system",
            "content": (
                "You are an expert Android malware analyst. Think carefully and reason deeply.\n"
                "You are provided with multiple sources of information about the APK, including:\n"
                "- Preliminary adjudication (Clean / Suspicious / Malicious)\n"
                "- Basic app details, certificates, and components (activities, services, receivers, providers)\n"
                "- Permissions analysis\n"
                "- Strings and classes analysis\n"
                "- Consolidated evidence grouped by strength\n"
                "- Extracted IOCs\n\n"
                "[!] Your job is to evaluate ALL the evidence objectively and decide the most accurate classification.\n"
                "- Do NOT assume Clean or Malicious by default -- base your decision only on evidence.\n"
                "- Legitimate apps may use sensitive permissions, networking, crypto, reflection, or ads/Firebase. These alone are NOT malicious.\n"
                "- Mark as Malicious ONLY if there is undeniable malicious evidence such as:\n"
                "  * Hardcoded C2 domains or IPs (not common cloud/CDN)\n"
                "  * Runtime exec, su/root checks, privilege escalation\n"
                "  * Dynamic payload loading (DexClassLoader, PathClassLoader, eval, exec)\n"
                "  * Obfuscation/anti-analysis combined with abuse\n"
                "  * SMS/call interception, credential stealing, overlay attacks, data exfiltration\n"
                "- Mark as Suspicious if there are unusual or clustered risky patterns suggesting possible abuse but without conclusive proof.\n"
                "- Mark as Clean if no malicious evidence exists.\n\n"
                "Return STRICT JSON in this schema:\n"
                "{\n"
                "  \"Malicious\": 0|1,\n"
                "  \"Suspicious\": 0|1,\n"
                "  \"Clean\": 0|1,\n"
                "  \"Risk-Score\": 0-100,\n"
                "  \"Summary\": \"short explanation with reasoning and IOCs if any\",\n"
                "  \"IOCs\": [\"list of domains, IPs, classes, strings, etc.\"]\n"
                "}\n"
                "- Exactly one of Malicious, Suspicious, or Clean must be 1.\n"
                "- No extra text, no markdown, no explanations outside JSON.\n"
                "- Do not invent fields beyond this schema.\n"
            )
        },
        {
            "role": "user",
            "content": json.dumps(user_content, indent=2, ensure_ascii=False)
        }
    ]

    # Step 5: log & call LLM
    safe_log(logger, json.dumps(user_content, indent=2, ensure_ascii=False))
    verdict = call_llm(messages, "claude-4-sonnet", logger, llm_client)
    normalized_verdict = normalize_final_verdict(verdict, logger)
    if normalized_verdict is None:
        raise RuntimeError("Final LLM verdict unavailable or invalid after retries")
    return normalized_verdict


# -------------------- PIPELINE --------------------
def analyze_apk_pipeline(apk_path, logger, llm_client: OpenAI):
    """
    Thin wrapper -- delegates to apk_pipeline_v2.run().
    Enrichment flags (use_smba, vt_api_key) are read from module-level globals
    set by the CLI argument parser at startup.
    """
    return apk_pipeline_v2.run(
        apk_path,
        logger,
        llm_client,
        use_smba=_USE_SMBA,
        smba_jsessionid=_SMBA_JSESSIONID or "",
        vt_api_key=_VT_API_KEY,
        no_vt_detection=_NO_VT_DETECTION,
    )


def isapk(path):
    if not os.path.isfile(path):
        return False

    try:
        with open(path, "rb") as f:
            magic = f.read(4)
            if magic != b"PK\x03\x04":
                return False  # Not a valid ZIP

        # with zipfile.ZipFile(path, "r") as zf:
        #     if "AndroidManifest.xml" not in zf.namelist():
        #         return False  # Not a valid APK structure

        return True
    except Exception:
        return False


def analyze_sample_with_state(
    *,
    apk_path: str,
    report_dir: str,
    state_db: AnalysisStateDB,
    master_log,
    llm_client: OpenAI,
    llm_key_name: str,
    runner_id: str,
    lease_duration_sec: float,
) -> str:
    apk_name = os.path.splitext(os.path.basename(apk_path))[0]
    sha256 = compute_file_sha256(apk_path)
    log_path = os.path.join(report_dir, f"{apk_name}_llm_analysis.log")
    verdict_path = os.path.join(report_dir, f"{apk_name}_verdict.json")

    existing = state_db.get(sha256)
    if existing and existing.get("status") in TERMINAL_SAMPLE_STATUSES:
        print(f"[skip] {apk_name} already marked {existing['status']}")
        return "skipped_terminal"

    claimed = state_db.try_claim(
        sha256=sha256,
        apk_name=apk_name,
        apk_path=apk_path,
        log_path=log_path,
        verdict_path=verdict_path,
        runner_id=runner_id,
        llm_key_name=llm_key_name,
        lease_duration_sec=lease_duration_sec,
    )
    if not claimed:
        existing = state_db.get(sha256)
        if existing and existing.get("status") in TERMINAL_SAMPLE_STATUSES:
            print(f"[skip] {apk_name} already marked {existing['status']}")
        else:
            owner = (existing or {}).get("runner_id") or "another-runner"
            print(f"[skip] {apk_name} already claimed by {owner}")
        return "claimed_elsewhere"

    logger = setup_logger(log_path, apk_name)
    lease_heartbeat = LeaseHeartbeat(
        state_db=state_db,
        sha256=sha256,
        runner_id=runner_id,
        lease_duration_sec=lease_duration_sec,
        logger=logger,
    )
    lease_heartbeat.start()


    import time
    start_time = time.time()
    try:
        readable, parse_error = probe_apk_readability(apk_path)
        if not readable:
            logger.error(f"APK parse failed before analysis: {parse_error}")
            elapsed = time.time() - start_time
            payload = {
                "apk_file": os.path.basename(apk_path),
                "sha256": sha256,
                "status": "corrupt",
                "error": parse_error,
                "analysis_time_sec": round(elapsed, 2),
            }
            write_json(verdict_path, payload)
            master_log.write(f"{apk_name}: {json.dumps(payload, ensure_ascii=False)}\n")
            master_log.flush()
            state_db.finish(sha256=sha256, status="corrupt", last_error=parse_error, runner_id=runner_id)
            return "corrupt"

        verdict = analyze_apk_pipeline(apk_path, logger, llm_client)
        if not isinstance(verdict, dict) or not verdict:
            raise RuntimeError("Analyzer returned no verdict")

        elapsed = time.time() - start_time
        # Extract LLM stats if present in verdict
        llm_call_count = verdict.get("llm_call_count", 0)
        llm_input_tokens = verdict.get("llm_input_tokens", verdict.get("llm_prompt_tokens", 0))
        llm_output_tokens = verdict.get("llm_output_tokens", verdict.get("llm_completion_tokens", 0))
        llm_total_tokens = verdict.get("llm_total_tokens", 0)
        llm_estimated_tokens = verdict.get("llm_estimated_tokens", 0)
        llm_token_count_estimated = bool(verdict.get("llm_token_count_estimated", False))
        payload = {
            "apk_file": os.path.basename(apk_path),
            "sha256": sha256,
            "status": "done",
            "verdict": verdict,
            "analysis_time_sec": round(elapsed, 2),
            "llm_call_count": llm_call_count,
            "llm_input_tokens": llm_input_tokens,
            "llm_output_tokens": llm_output_tokens,
            "llm_total_tokens": llm_total_tokens,
            # Backward-compatible aliases for older dashboards/scripts.
            "llm_prompt_tokens": llm_input_tokens,
            "llm_completion_tokens": llm_output_tokens,
            "llm_estimated_tokens": llm_estimated_tokens,
            "llm_token_count_estimated": llm_token_count_estimated,
        }
        write_json(verdict_path, payload)

        logger.info("\n[FINAL VERDICT]\n%s", json.dumps(verdict, indent=2, ensure_ascii=False))
        master_log.write(f"{apk_name}: {json.dumps(payload, ensure_ascii=False)}\n")
        master_log.flush()

        state_db.finish(sha256=sha256, status="done", last_error=None, runner_id=runner_id)
        return "done"

    except Exception as e:
        logger.exception(f"Analysis failed for {apk_name}: {e}")
        elapsed = time.time() - start_time
        if is_terminal_corrupt_error(e):
            payload = {
                "apk_file": os.path.basename(apk_path),
                "sha256": sha256,
                "status": "corrupt",
                "error": str(e),
                "analysis_time_sec": round(elapsed, 2),
            }
            write_json(verdict_path, payload)
            master_log.write(f"{apk_name}: {json.dumps(payload, ensure_ascii=False)}\n")
            master_log.flush()
            state_db.finish(sha256=sha256, status="corrupt", last_error=str(e), runner_id=runner_id)
            return "corrupt"

        if isinstance(e, LLMUnavailableError):
            payload = {
                "apk_file": os.path.basename(apk_path),
                "sha256": sha256,
                "status": "failed",
                "error": str(e),
                "analysis_time_sec": round(elapsed, 2),
            }
            write_json(verdict_path, payload)
            state_db.finish(sha256=sha256, status="failed", last_error=str(e), runner_id=runner_id)
            return "key_unavailable"

        state_db.finish(sha256=sha256, status="failed", last_error=str(e), runner_id=runner_id)
        return "failed"
    finally:
        lease_heartbeat.stop()
        clear_apk_context(apk_path)
        for h in list(logger.handlers):
            h.close()
            logger.removeHandler(h)


def merge_runner_master_logs(report_dir: str) -> str:
    merged_path = os.path.join(report_dir, "master_summary.log")
    runner_logs = sorted(
        os.path.join(report_dir, name)
        for name in os.listdir(report_dir)
        if name.startswith("master_summary_") and name.endswith(".log")
    )
    with open(merged_path, "w", encoding="utf-8") as out_f:
        for log_path in runner_logs:
            with open(log_path, "r", encoding="utf-8") as in_f:
                out_f.write(in_f.read())
    return merged_path


def write_run_summary(
    report_dir: str,
    *,
    counts: Dict[str, int],
    run_counts: Dict[str, int],
    runner_id: Optional[str] = None,
    llm_key_name: Optional[str] = None,
    worker_pid: Optional[int] = None,
    output_name: str = "analysis_run_summary.json",
) -> Dict[str, Any]:
    summary_payload: Dict[str, Any] = {
        "counts": counts,
        "run_counts": run_counts,
    }
    if runner_id:
        summary_payload["runner_id"] = runner_id
    if llm_key_name:
        summary_payload["llm_key_name"] = llm_key_name
    if worker_pid is not None:
        summary_payload["worker_pid"] = int(worker_pid)
    write_json(os.path.join(report_dir, output_name), summary_payload)
    return summary_payload


def write_worker_launch_manifest(
    report_dir: str,
    *,
    worker_launches: List[Dict[str, Any]],
    lease_duration_sec: float,
) -> Dict[str, Any]:
    payload = {
        "started_at_utc": utc_now_iso(),
        "expected_worker_count": len(worker_launches),
        "lease_duration_sec": float(lease_duration_sec),
        "workers": worker_launches,
    }
    write_json(os.path.join(report_dir, "worker_launch_manifest.json"), payload)
    return payload


def run_single_runner(
    *,
    folder_path: str,
    report_dir: str,
    llm_key_config: LLMKeyConfig,
    lease_duration_sec: float,
    worker_mode: bool,
) -> int:
    # Tool registry removed in v2 -- extraction is handled directly in apk_pipeline_v2.

    apk_files = sorted(f for f in os.listdir(folder_path) if isapk(folder_path + os.sep + f))
    if not apk_files:
        print("No APK files found in the folder.")
        return 0

    runner_id = f"{sanitize_name(llm_key_config.name)}-pid{os.getpid()}-{uuid.uuid4().hex[:8]}"
    llm_client = create_llm_client(llm_key_config)
    state_db = AnalysisStateDB(os.path.join(report_dir, "analysis_state.sqlite"))
    master_log_name = (
        f"master_summary_{sanitize_name(llm_key_config.name)}_{os.getpid()}.log"
        if worker_mode
        else "master_summary.log"
    )
    master_log_path = os.path.join(report_dir, master_log_name)
    run_counts = {"done": 0, "failed": 0, "corrupt": 0, "skipped": 0}
    first_pass = True

    print(f"[runner:{runner_id}] starting with key={llm_key_config.name}")
    with open(master_log_path, "a", encoding="utf-8") as master_log:
        master_log.write(
            f"# runner_start runner_id={runner_id} key={llm_key_config.name} pid={os.getpid()} "
            f"started_at={utc_now_iso()}\n"
        )
        master_log.flush()
        while True:
            pass_completed = 0
            pass_contended = 0
            key_unavailable = False

            for apk_file in apk_files:
                apk_path = os.path.join(folder_path, apk_file)
                print(f"\n[runner:{runner_id}] [PKG Processing APK: {apk_file}]")
                status = analyze_sample_with_state(
                    apk_path=apk_path,
                    report_dir=report_dir,
                    state_db=state_db,
                    master_log=master_log,
                    llm_client=llm_client,
                    llm_key_name=llm_key_config.name,
                    runner_id=runner_id,
                    lease_duration_sec=lease_duration_sec,
                )

                if status == "key_unavailable":
                    run_counts["failed"] += 1
                    key_unavailable = True
                    print(
                        f"[runner:{runner_id}] disabling key {llm_key_config.name} because it is "
                        "returning errors or no responses"
                    )
                    break

                if status in {"done", "failed", "corrupt"}:
                    run_counts[status] += 1
                    pass_completed += 1
                    continue

                if status == "claimed_elsewhere":
                    pass_contended += 1
                    continue

                if first_pass and status == "skipped_terminal":
                    run_counts["skipped"] += 1

            first_pass = False

            if key_unavailable:
                counts = state_db.status_counts()
                summary_name = f"analysis_run_summary_{sanitize_name(llm_key_config.name)}_{os.getpid()}.json"
                summary_payload = write_run_summary(
                    report_dir,
                    counts=counts,
                    run_counts=run_counts,
                    runner_id=runner_id,
                    llm_key_name=llm_key_config.name,
                    worker_pid=os.getpid(),
                    output_name=summary_name if worker_mode else "analysis_run_summary.json",
                )
                summary_payload["key_disabled"] = True
                write_json(os.path.join(report_dir, summary_name if worker_mode else "analysis_run_summary.json"), summary_payload)
                master_log.write(
                    f"# runner_stop runner_id={runner_id} key={llm_key_config.name} pid={os.getpid()} "
                    f"stopped_at={utc_now_iso()} reason=key_unavailable\n"
                )
                master_log.flush()
                state_db.close()
                print(json.dumps(summary_payload, indent=2, ensure_ascii=False))
                return RUNNER_KEY_UNAVAILABLE_EXIT_CODE

            if pass_completed > 0:
                continue

            if pass_contended > 0:
                print(
                    f"[runner:{runner_id}] waiting {WORKER_RESCAN_SLEEP_SEC:.1f}s for "
                    f"{pass_contended} sample(s) currently owned by other runners"
                )
                time.sleep(WORKER_RESCAN_SLEEP_SEC)
                continue

            break

    counts = state_db.status_counts()
    summary_name = (
        f"analysis_run_summary_{sanitize_name(llm_key_config.name)}_{os.getpid()}.json"
        if worker_mode
        else "analysis_run_summary.json"
    )
    summary_payload = write_run_summary(
        report_dir,
        counts=counts,
        run_counts=run_counts,
        runner_id=runner_id,
        llm_key_name=llm_key_config.name,
        worker_pid=os.getpid(),
        output_name=summary_name,
    )
    with open(master_log_path, "a", encoding="utf-8") as master_log:
        master_log.write(
            f"# runner_stop runner_id={runner_id} key={llm_key_config.name} pid={os.getpid()} "
            f"stopped_at={utc_now_iso()} reason=completed\n"
        )
    state_db.close()
    print(json.dumps(summary_payload, indent=2, ensure_ascii=False))
    if counts.get("failed", 0) > 0 or counts.get("in_progress", 0) > 0:
        return 2
    return 0


def run_multi_key_parent(
    *,
    folder_path: str,
    report_dir: str,
    lease_duration_sec: float,
    key_configs: List[LLMKeyConfig],
) -> int:
    worker_procs: List[Tuple[LLMKeyConfig, subprocess.Popen]] = []
    worker_launches: List[Dict[str, Any]] = []

    print(
        f"[parent] launching {len(key_configs)} worker(s) for keys: "
        f"{', '.join(key.name for key in key_configs)}"
    )
    for key_config in key_configs:
        cmd = [
            sys.executable,
            os.path.abspath(__file__),
            folder_path,
            "--report-dir",
            report_dir,
            "--llm-key-name",
            key_config.name,
            "--worker-mode",
            "--lease-hours",
            str(lease_duration_sec / 3600.0),
        ]
        print(f"[parent] starting worker for key={key_config.name}: {' '.join(cmd)}")
        proc = subprocess.Popen(cmd, cwd=SCRIPT_DIR)
        worker_procs.append((key_config, proc))
        worker_launch = {
            "llm_key_name": key_config.name,
            "worker_pid": int(proc.pid),
            "command": cmd,
            "started_at_utc": utc_now_iso(),
        }
        worker_launches.append(worker_launch)
        print(
            f"[parent] worker_started key={key_config.name} pid={proc.pid} "
            f"report_dir={report_dir}"
        )

    write_worker_launch_manifest(
        report_dir,
        worker_launches=worker_launches,
        lease_duration_sec=lease_duration_sec,
    )

    worker_results: List[Dict[str, Any]] = []
    highest_rc = 0
    disabled_key_count = 0
    for key_config, proc in worker_procs:
        rc = int(proc.wait())
        highest_rc = max(highest_rc, rc)
        worker_results.append(
            {
                "llm_key_name": key_config.name,
                "worker_pid": int(proc.pid),
                "exit_code": rc,
            }
        )
        if rc == RUNNER_KEY_UNAVAILABLE_EXIT_CODE:
            disabled_key_count += 1
        print(f"[parent] worker key={key_config.name} exited with code {rc}")

    state_db = AnalysisStateDB(os.path.join(report_dir, "analysis_state.sqlite"))
    counts = state_db.status_counts()
    state_db.close()
    merge_runner_master_logs(report_dir)
    summary_payload = write_run_summary(
        report_dir,
        counts=counts,
        run_counts={"done": 0, "failed": 0, "corrupt": 0, "skipped": 0},
    )
    summary_payload["configured_keys"] = [key.name for key in key_configs]
    summary_payload["expected_worker_count"] = len(key_configs)
    summary_payload["launched_worker_count"] = len(worker_launches)
    summary_payload["worker_results"] = worker_results
    summary_payload["disabled_key_count"] = disabled_key_count
    summary_payload["all_keys_unavailable"] = disabled_key_count == len(key_configs)
    write_json(os.path.join(report_dir, "analysis_run_summary.json"), summary_payload)
    print(json.dumps(summary_payload, indent=2, ensure_ascii=False))

    if counts.get("failed", 0) > 0 or counts.get("in_progress", 0) > 0:
        return 2
    if disabled_key_count == len(key_configs):
        return 2
    return 0 if highest_rc == RUNNER_KEY_UNAVAILABLE_EXIT_CODE else highest_rc


# -------------------- MAIN --------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze APK files in a folder.")
    parser.add_argument("apk_folder", help="Folder containing APK samples")
    parser.add_argument(
        "--report-dir",
        default=None,
        help="Optional folder where logs/reports should be written. Defaults to apk_folder.",
    )
    parser.add_argument(
        "--llm-key-name",
        default=None,
        help="Run with a specific llm_api_keys entry name from config.json.",
    )
    parser.add_argument(
        "--worker-mode",
        action="store_true",
        help="Internal flag used by the parent runner to launch one subprocess per API key.",
    )
    parser.add_argument(
        "--lease-hours",
        type=float,
        default=6.0,
        help="How long a sample claim stays valid before another runner may recover it after a crash.",
    )
    parser.add_argument(
        "--use-smba",
        action="store_true",
        default=False,
        help=(
            "Enrich analysis with Zscaler SMBA sandbox data. "
            "Requires ZSCALER_JSESSIONID via --smba-jsessionid or llm_V1/smba_data_pull/.env"
        ),
    )
    parser.add_argument(
        "--smba-jsessionid",
        default=None,
        metavar="JSESSIONID",
        help=(
            "Zscaler SMBA JSESSIONID cookie value. "
            "Overrides the ZSCALER_JSESSIONID value in smba_data_pull/.env. "
            "Use this when the session has expired and you need to paste a fresh token. "
            "Example: --smba-jsessionid ABCDEF1234567890"
        ),
    )
    parser.add_argument(
        "--vt-enrich",
        action="store_true",
        default=False,
        help=(
            "Enrich analysis with VirusTotal behaviour data. "
            "Uses the premium key from the active VT downloader config automatically."
        ),
    )
    parser.add_argument(
        "--no-vt-detection",
        action="store_true",
        default=False,
        help=(
            "Skip VT detection-ratio and threat-label evidence items. "
            "Keeps PCAP/traffic/IDS/MITRE data. "
            "Use when batch-analysing VT-sourced samples where the verdict is already known."
        ),
    )
    args = parser.parse_args()
    _USE_SMBA = bool(args.use_smba)
    if getattr(args, "smba_jsessionid", None):
        _SMBA_JSESSIONID = str(args.smba_jsessionid).strip()
        # Write the fresh session ID into .env so smba_enrichment picks it up.
        _smba_env_path = os.path.join(SCRIPT_DIR, "smba_data_pull", ".env")
        try:
            _env_lines = []
            _found = False
            if os.path.isfile(_smba_env_path):
                with open(_smba_env_path, "r", encoding="utf-8") as _ef:
                    for _line in _ef:
                        if _line.startswith("ZSCALER_JSESSIONID="):
                            _env_lines.append(f"ZSCALER_JSESSIONID={_SMBA_JSESSIONID}\n")
                            _found = True
                        else:
                            _env_lines.append(_line)
            if not _found:
                _env_lines.append(f"ZSCALER_JSESSIONID={_SMBA_JSESSIONID}\n")
            with open(_smba_env_path, "w", encoding="utf-8") as _ef:
                _ef.writelines(_env_lines)
            print(f"[startup] SMBA JSESSIONID updated in {_smba_env_path}")
        except Exception as _env_exc:
            print(f"[startup] WARNING: could not update .env with new JSESSIONID: {_env_exc}")
            print(f"[startup] SMBA will use the token directly from --smba-jsessionid")
    _NO_VT_DETECTION = bool(args.no_vt_detection)
    if args.vt_enrich:
        import vt_enrichment as _vt_mod
        _vt_config_path = _vt_mod.resolve_vt_config_path()
        _VT_API_KEY = _vt_mod.load_vt_api_key_from_config(_vt_config_path)
        if not _VT_API_KEY:
            print(f"[startup] --vt-enrich: no premium VT key found in {_vt_config_path}")

    folder_path = args.apk_folder
    if not os.path.isdir(folder_path):
        print("Invalid folder path.")
        sys.exit(1)

    report_dir = args.report_dir or folder_path
    os.makedirs(report_dir, exist_ok=True)
    config = load_runtime_config()
    key_config_summary = summarize_llm_key_configuration(config)
    key_configs = load_llm_key_configs(config)
    if not key_configs:
        raise SystemExit(
            "No LLM API keys configured in llm_V1/config.json. "
            "Add api_key_zllama or llm_api_keys before running analysis."
        )

    print(
        f"[startup] loaded {len(key_configs)} LLM key(s): "
        f"{', '.join(key.name for key in key_configs)}"
    )

    if not args.worker_mode and len(key_config_summary.get("active_names") or []) == 1:
        active_name = (key_config_summary.get("active_names") or ["runner-1"])[0]
        inactive_names = key_config_summary.get("inactive_names") or []
        inactive_note = ""
        if inactive_names:
            inactive_note = (
                f" Inactive configured runner slot(s): {', '.join(inactive_names)}."
            )
        elif key_config_summary.get("uses_legacy_key"):
            inactive_note = " Using legacy single-key configuration."

        print(
            "[startup] WARNING: only one active LLM runner key is configured "
            f"({active_name}). If that key is exhausted or starts failing, the batch "
            "will not mark samples clean, but there is no second runner to keep the run "
            "moving; failed samples will need a rerun, and stale in-progress leases may "
            f"need lease expiry or manual release.{inactive_note}"
        )

    if args.worker_mode or args.llm_key_name or len(key_configs) == 1:
        llm_key_config = pick_llm_key_config(args.llm_key_name, config)
        exit_code = run_single_runner(
            folder_path=folder_path,
            report_dir=report_dir,
            llm_key_config=llm_key_config,
            lease_duration_sec=max(300.0, float(args.lease_hours) * 3600.0),
            worker_mode=bool(args.worker_mode),
        )
        if not args.worker_mode and exit_code == RUNNER_KEY_UNAVAILABLE_EXIT_CODE:
            exit_code = 2
        sys.exit(exit_code)

    exit_code = run_multi_key_parent(
        folder_path=folder_path,
        report_dir=report_dir,
        lease_duration_sec=max(300.0, float(args.lease_hours) * 3600.0),
        key_configs=key_configs,
    )
    sys.exit(exit_code)

