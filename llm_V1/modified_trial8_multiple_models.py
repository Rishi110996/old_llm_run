from collections import defaultdict
import statistics
import hashlib
import sys
import os
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
from DefineRegisterTools_new import TOOL_REGISTRY, register_apk_tools, get_apk_context, clear_apk_context
from updated_zstatic_apk_dump import dump_individual_apk
from scan_with_yara import scan_this_bin_file_with_static_yara

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

with open(os.path.join(SCRIPT_DIR, "config.json"), "r", encoding="utf-8") as f:
    config = json.load(f)
client = openai.OpenAI(api_key=config.get("api_key_zllama"), base_url=config.get("base_url_zllama"))

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


class AnalysisStateDB:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.conn = sqlite3.connect(path, timeout=60)
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA busy_timeout=60000;")
        self._init()

    def _init(self):
        self.conn.execute(
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
              finished_at_utc TEXT
            );
            """
        )
        self.conn.commit()

    def get(self, sha256: str) -> Optional[Dict[str, Any]]:
        cur = self.conn.execute(
            """
            SELECT sha256, apk_name, apk_path, status, attempts, last_error,
                   log_path, verdict_path, started_at_utc, finished_at_utc
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
        }

    def start_attempt(self, *, sha256: str, apk_name: str, apk_path: str, log_path: str, verdict_path: str):
        now = utc_now_iso()
        self.conn.execute(
            """
            INSERT INTO analysis_samples
              (sha256, apk_name, apk_path, status, attempts, log_path, verdict_path, started_at_utc, finished_at_utc)
            VALUES (?, ?, ?, 'in_progress', 1, ?, ?, ?, NULL)
            ON CONFLICT(sha256) DO UPDATE SET
              apk_name = excluded.apk_name,
              apk_path = excluded.apk_path,
              status = 'in_progress',
              attempts = analysis_samples.attempts + 1,
              log_path = excluded.log_path,
              verdict_path = excluded.verdict_path,
              started_at_utc = excluded.started_at_utc,
              finished_at_utc = NULL;
            """,
            (sha256, apk_name, apk_path, log_path, verdict_path, now),
        )
        self.conn.commit()

    def finish(self, *, sha256: str, status: str, last_error: Optional[str] = None):
        self.conn.execute(
            """
            UPDATE analysis_samples
            SET status = ?, last_error = ?, finished_at_utc = ?
            WHERE sha256 = ?;
            """,
            (status, last_error, utc_now_iso(), sha256),
        )
        self.conn.commit()

    def status_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        cur = self.conn.execute(
            "SELECT status, COUNT(*) FROM analysis_samples GROUP BY status;"
        )
        for status, count in cur.fetchall():
            counts[str(status)] = int(count)
        return counts

    def close(self):
        self.conn.close()


def utc_now_iso() -> str:
    return dt.datetime.now(tz=dt.timezone.utc).isoformat()


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

def call_llm(messages, model, logger, max_retries=3):
    """
    Call LLM through the ZLlama/OpenAI-compatible client.
    """
    for attempt in range(1, max_retries + 1):
        try:
            response = client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=0.2,
                stream=False
            )

            content = response.choices[0].message.content

            safe_log(logger, f"LLM Attempt {attempt} Raw: {content}")

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
    return None

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
⚠️ Default to BENIGN unless clear malicious intent exists.
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


# -------------------- CHUNK ANALYZERS --------------------
def analyze_strings_with_chunking(apk_strings: List[str], logger, model, chunk_size=200):
    all_relevant, all_evidence, summaries = [], [], []
    for idx, chunk in enumerate(chunk_list(apk_strings, size=chunk_size), start=1):
        logger.info(f"[strings] Analyzing chunk {idx} ({len(chunk)} items)")
        result = call_llm(prompt_strings_chunk("\n".join(chunk)), model, logger) or {}

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

def analyze_permissions_with_chunking(apk_perms: List[str], logger, model, chunk_size=100):
    all_relevant, all_evidence, summaries = [], [], []
    for idx, chunk in enumerate(chunk_list(apk_perms, size=chunk_size), start=1):
        logger.info(f"[perms] Analyzing chunk {idx} ({len(chunk)} items)")
        result = call_llm(prompt_permissions_chunk("\n".join(chunk)),model, logger) or {}
        
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

def analyze_classes_with_chunking(apk_classes: dict, logger, model, chunk_size=1):
    all_relevant, all_evidence, summaries = [], [], []
    items = list(apk_classes.items())
    for idx, chunk in enumerate(chunk_list(items, size=chunk_size), start=1):
        logger.info(f"[classes] Analyzing class {idx}")
        chunk_str = "\n\n".join(f"{classname}:\n{code}" for classname, code in chunk)
        result = call_llm(prompt_classes_chunk(chunk_str), model, logger) or {}
        
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

def analyze_methods_with_chunking(apk_methods: dict, logger, model, chunk_size=5):
    if apk_methods:
        all_relevant, all_evidence, summaries = [], [], []
        items = list(apk_methods.items())
        for idx, chunk in enumerate(chunk_list(items, size=chunk_size), start=1):
            logger.info(f"[methods] Analyzing method {idx}")
            chunk_str = "\n\n".join(f"{methodname}:\n{code}" for methodname, code in chunk)
            result = call_llm(prompt_methods_chunk(chunk_str), model, logger) or {}
            
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

        # sort by confidence (high → low)
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


# --- Final LLM Verdict ---
def final_llm_verdict(apk_path, tool_results, preliminary, consolidated_evidence, logger):
    # # Step 1: consolidate evidence
    # raw_evidence = {
    #     "strings": tool_results.get("strings_analysis", {}).get("evidence", []),
    #     "classes": tool_results.get("classes_analysis", {}).get("evidence", []),
    #     "permissions": tool_results.get("permissions_analysis", {}).get("evidence", []),
    # }

    # Step 2: build user content
    user_content = {
        "apk_file": os.path.basename(apk_path),
        "preliminary_verdict": preliminary,
        "tools_summary": {
            "apk_basic_info": tool_results.get("get_apk_basic_info", {}),
            "certs": tool_results.get("get_apk_certificates", {}),
            "permissions_summary": tool_results.get("permissions_analysis", {}).get("summary", ""),
            "classes_summary": tool_results.get("classes_analysis", {}).get("summary", ""),
            "strings_summary": tool_results.get("strings_analysis", {}).get("summary", ""),
            "yara_detections": tool_results.get("yara_detection", []),
        },
        "evidence": consolidated_evidence,
        "iocs": preliminary.get("IOCs", [])
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
                "⚠️ Your job is to evaluate ALL the evidence objectively and decide the most accurate classification.\n"
                "- Do NOT assume Clean or Malicious by default — base your decision only on evidence.\n"
                "- Legitimate apps may use sensitive permissions, networking, crypto, reflection, or ads/Firebase. These alone are NOT malicious.\n"
                "- Mark as Malicious ONLY if there is undeniable malicious evidence such as:\n"
                "  • Hardcoded C2 domains or IPs (not common cloud/CDN)\n"
                "  • Runtime exec, su/root checks, privilege escalation\n"
                "  • Dynamic payload loading (DexClassLoader, PathClassLoader, eval, exec)\n"
                "  • Obfuscation/anti-analysis combined with abuse\n"
                "  • SMS/call interception, credential stealing, overlay attacks, data exfiltration\n"
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
    verdict = call_llm(messages,"claude-4-sonnet", logger) or preliminary
    return verdict


# -------------------- PIPELINE --------------------
def analyze_apk_pipeline(apk_path, logger):
    """
    Full pipeline for analyzing an APK.
    Integrates string/class/permission analysis, static tools, YARA, consolidation, and verdict scoring.
    """

    logger.info(f"Analyzing {apk_path}")

    tool_results = run_tools(apk_path, logger)
    strings_raw = tool_results.get("get_interesting_strings", [])
    strings_out = analyze_strings_with_chunking(strings_raw, logger,"gpt-4.1-mini")

    classes_raw = tool_results.get("get_interesting_classes", {})
    classes_out = analyze_classes_with_chunking(classes_raw, logger,"gpt-4.1-mini")

    # methods_raw = tool_results.get("get_interesting_methods",{})
    # methods_out = analyze_methods_with_chunking(methods_raw,logger,"gpt-4.1-mini")

    perms_raw = tool_results.get("get_permissions", [])
    perms_out = analyze_permissions_with_chunking(perms_raw or [], logger,"gpt-4.1-mini")

    yara_report = add_yara_scan_result(apk_path)
    yara_evidence = []
    for detections in yara_report:
        yara_evidence.append({"indicator": detections["detection_rule"], "source": "YARA", "category": "Malware", "strength": "strong", "confidence": 1, "explanation": "Malware detected by yara rule"})

    tool_results["yara_detection"] = yara_report
    tool_results["strings_analysis"] = strings_out
    tool_results["classes_analysis"] = classes_out
    # tool_results["methods_analysis"] = methods_out
    tool_results["permissions_analysis"] = perms_out

    keys_not_to_copy = ["get_interesting_strings","get_interesting_classes","get_interesting_methods","get_permissions"]
    updated_tools_result = {k:tool_results[k] for k in tool_results if k not in keys_not_to_copy}

    # 5. Combine evidence
    combined_evidence = []
    for section in (strings_out, classes_out, perms_out):
        combined_evidence.extend(section.get("evidence", []))
    # print(combined_evidence)
    # exit(0)
    combined_evidence.extend(static_evidence_from_tools(tool_results))
    combined_evidence.extend(yara_evidence)

    #Consolidate evidence
    consolidated = consolidate_evidence(combined_evidence)

    # # 6. Flatten consolidated evidence for scoring
    # flat_evidence = []
    # for strength, data in consolidated.items():
    #     for ind in data["indicators"]:
    #         flat_evidence.append({
    #             "indicator": ind,
    #             "strength": strength.replace("_confidence", ""),
    #             "confidence": data["avg_confidence"],
    #             "category": "mixed",
    #             "explanation": data["summary_explanation"]
    #         })

    # 7. Adjudicate → preliminary verdict + risk + IOCs
    prelim, risk, iocs = adjudicate(consolidated)

    # 8. Final LLM refinement (pass consolidated instead of raw)
    verdict = final_llm_verdict(
        apk_path=apk_path,
        tool_results=updated_tools_result,
        preliminary=prelim,
        consolidated_evidence=consolidated,
        logger=logger
    )

    return verdict


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
) -> str:
    apk_name = os.path.splitext(os.path.basename(apk_path))[0]
    sha256 = compute_file_sha256(apk_path)
    log_path = os.path.join(report_dir, f"{apk_name}_llm_analysis.log")
    verdict_path = os.path.join(report_dir, f"{apk_name}_verdict.json")

    existing = state_db.get(sha256)
    if existing and existing.get("status") in TERMINAL_SAMPLE_STATUSES:
        print(f"[skip] {apk_name} already marked {existing['status']}")
        return str(existing["status"])

    logger = setup_logger(log_path, apk_name)
    state_db.start_attempt(
        sha256=sha256,
        apk_name=apk_name,
        apk_path=apk_path,
        log_path=log_path,
        verdict_path=verdict_path,
    )

    try:
        readable, parse_error = probe_apk_readability(apk_path)
        if not readable:
            logger.error(f"APK parse failed before analysis: {parse_error}")
            payload = {
                "apk_file": os.path.basename(apk_path),
                "sha256": sha256,
                "status": "corrupt",
                "error": parse_error,
            }
            write_json(verdict_path, payload)
            master_log.write(f"{apk_name}: {json.dumps(payload, ensure_ascii=False)}\n")
            master_log.flush()
            state_db.finish(sha256=sha256, status="corrupt", last_error=parse_error)
            return "corrupt"

        verdict = analyze_apk_pipeline(apk_path, logger)
        if not isinstance(verdict, dict) or not verdict:
            raise RuntimeError("Analyzer returned no verdict")

        payload = {
            "apk_file": os.path.basename(apk_path),
            "sha256": sha256,
            "status": "done",
            "verdict": verdict,
        }
        write_json(verdict_path, payload)

        logger.info("\n[FINAL VERDICT]\n%s", json.dumps(verdict, indent=2, ensure_ascii=False))
        master_log.write(f"{apk_name}: {json.dumps(verdict, ensure_ascii=False)}\n")
        master_log.flush()

        state_db.finish(sha256=sha256, status="done", last_error=None)
        return "done"

    except Exception as e:
        logger.exception(f"Analysis failed for {apk_name}: {e}")
        state_db.finish(sha256=sha256, status="failed", last_error=str(e))
        return "failed"
    finally:
        clear_apk_context(apk_path)
        for h in list(logger.handlers):
            h.close()
            logger.removeHandler(h)


# -------------------- MAIN --------------------
if __name__ == "__main__":
    register_apk_tools()

    parser = argparse.ArgumentParser(description="Analyze APK files in a folder.")
    parser.add_argument("apk_folder", help="Folder containing APK samples")
    parser.add_argument(
        "--report-dir",
        default=None,
        help="Optional folder where logs/reports should be written. Defaults to apk_folder.",
    )
    args = parser.parse_args()

    folder_path = args.apk_folder
    if not os.path.isdir(folder_path):
        print("Invalid folder path.")
        sys.exit(1)

    report_dir = args.report_dir or folder_path
    os.makedirs(report_dir, exist_ok=True)

    apk_files = sorted(f for f in os.listdir(folder_path) if isapk(folder_path+os.sep+f))

    if not apk_files:
        print("No APK files found in the folder.")
        sys.exit(0)

    state_db = AnalysisStateDB(os.path.join(report_dir, "analysis_state.sqlite"))
    master_log_path = os.path.join(report_dir, "master_summary.log")
    run_counts = {"done": 0, "failed": 0, "corrupt": 0, "skipped": 0}

    with open(master_log_path, "a", encoding="utf-8") as master_log:
        for apk_file in apk_files:
            apk_path = os.path.join(folder_path, apk_file)
            print(f"\n[📦 Processing APK: {apk_file}]")
            status = analyze_sample_with_state(
                apk_path=apk_path,
                report_dir=report_dir,
                state_db=state_db,
                master_log=master_log,
            )
            if status in run_counts:
                run_counts[status] += 1
            else:
                run_counts["skipped"] += 1

    counts = state_db.status_counts()
    summary_payload = {
        "counts": counts,
        "run_counts": run_counts,
    }
    write_json(os.path.join(report_dir, "analysis_run_summary.json"), summary_payload)
    state_db.close()

    print(json.dumps(summary_payload, indent=2, ensure_ascii=False))
    if counts.get("failed", 0) > 0 or counts.get("in_progress", 0) > 0:
        sys.exit(2)
    sys.exit(0)

