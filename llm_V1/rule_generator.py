"""
rule_generator.py  –  Stage 6 YARA / Snort / CIF rule generation.

Key design:
  1. Read the actual .bin dump to get ground-truth strings (guaranteed to match).
  2. Cross-reference with analysis context (behavior, decompiled source, verdict).
  3. Build a focused prompt with verified strings + 2 example rules.
  4. Validate: compile + self-match against the bin dump. Save only if both pass.
"""
from __future__ import annotations

import datetime as dt, hashlib, json, logging, os, re, shutil, subprocess, tempfile
from typing import Any, Dict, List, Optional, Set

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_GENERATED_DIR = os.path.join(_SCRIPT_DIR, "generated_rules")
_YARA_DIR = os.path.join(_GENERATED_DIR, "yara")
_SNORT_DIR = os.path.join(_GENERATED_DIR, "snort")
_CIF_DIR = os.path.join(_GENERATED_DIR, "cif")
_VT_CACHE_PATH = os.path.join(_GENERATED_DIR, "vt_string_cache.json")
_VT_SEARCH_URL = "https://www.virustotal.com/api/v3/intelligence/search"
RULE_GEN_MODEL = "claude-sonnet-4-6"
MAX_VT_CHECKS_PER_SAMPLE = 12


# ---------------------------------------------------------------------------
# Goodware / noise strings to exclude from bin dump extraction
# ---------------------------------------------------------------------------
_NOISE_PREFIXES = (
    "android.", "androidx.", "kotlin.", "kotlinx.", "java.", "javax.",
    "dalvik.", "okhttp3.", "okio.", "retrofit2.", "com.google.android.gms.",
    "com.google.firebase.", "com.google.ads.", "com.google.gson.",
    "com.squareup.", "com.fasterxml.", "com.facebook.", "org.apache.",
    "org.json.", "org.xml.", "org.w3c.", "org.slf4j.",
    "res/", "META-INF/", "filename:", "filetype:",
)
_NOISE_EXACT = {
    "true", "false", "null", "none", "name", "value", "type", "class",
    "field", "method", "string", "invoke", "return", "const", "public",
    "private", "protected", "static", "final", "void", "this", "super",
    "android", "intent", "action", "permission", "provider", "receiver",
    "service", "activity", "application", "manifest", "xmlns",
}
_NOISE_RE = re.compile(
    r"^(?:\d+$|0x[0-9a-f]+$|[A-Za-z0-9+/]{80,}={0,2}$|[0-9a-f]{32,}$)", re.I
)


# ---------------------------------------------------------------------------
# 1. Read bin dump → extract unique strings (ground truth)
# ---------------------------------------------------------------------------

def _extract_strings_from_bin(bin_path: str, min_len: int = 8) -> List[str]:
    """Extract printable ASCII strings ≥ min_len from the bin dump file."""
    try:
        with open(bin_path, "rb") as f:
            data = f.read()
    except Exception:
        return []

    # Simple ASCII string extraction (like `strings -n 8`)
    result: List[str] = []
    current: List[int] = []
    for byte in data:
        if 0x20 <= byte < 0x7F:
            current.append(byte)
        else:
            if len(current) >= min_len:
                result.append(bytes(current).decode("ascii"))
            current = []
    if len(current) >= min_len:
        result.append(bytes(current).decode("ascii"))
    return result


def _filter_dump_strings(raw_strings: List[str]) -> List[str]:
    """Filter out noise, keep only YARA-worthy strings."""
    seen: Set[str] = set()
    filtered: List[str] = []
    for s in raw_strings:
        s = s.strip()
        if len(s) < 8 or len(s) > 200:
            continue
        if s.lower() in _NOISE_EXACT or s in seen:
            continue
        if _NOISE_RE.match(s):
            continue
        if any(s.startswith(p) for p in _NOISE_PREFIXES):
            continue
        if s.startswith(".") and len(s) > 1 and s[1:2].islower():
            continue
        seen.add(s)
        filtered.append(s)
    return filtered


# ---------------------------------------------------------------------------
# 2. Cross-reference: rank dump strings using analysis context
# ---------------------------------------------------------------------------

def _rank_dump_strings(
    dump_strings: List[str],
    apk_facts: Any,
    evidence_items: List,
    verdict: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Score dump strings by relevance to the analysis findings."""
    # Build lookup sets from analysis data
    ioc_set = {s.lower() for s in (verdict.get("IOCs") or [])}
    evidence_values = {ei.value.lower() for ei in evidence_items if ei.direction != "benign"}
    mal_class_names = {
        c for c, score in apk_facts.class_api_scores.items() if score >= 0.40
    }
    mal_class_fragments = set()
    for c in mal_class_names:
        for part in c.split("."):
            if len(part) >= 5:
                mal_class_fragments.add(part.lower())
    # Source code literals from decompiled classes
    source_literals: Set[str] = set()
    for cls, src in apk_facts.classes.items():
        if src and apk_facts.class_api_scores.get(cls, 0) >= 0.30:
            for m in re.finditer(r'"([^"]{8,80})"', src):
                source_literals.add(m.group(1).lower())

    ranked: List[Dict[str, Any]] = []
    for s in dump_strings:
        sl = s.lower()
        score = 0.0
        reason = ""
        # Exact IOC match
        if sl in ioc_set or any(sl in ioc for ioc in ioc_set):
            score += 3.0
            reason = "IOC match"
        # Evidence item match
        if sl in evidence_values or any(sl in ev for ev in evidence_values):
            score += 2.0
            reason = reason or "evidence match"
        # Source code literal match
        if sl in source_literals:
            score += 2.5
            reason = reason or "source literal"
        # Malicious class fragment match
        if any(frag in sl for frag in mal_class_fragments):
            score += 1.5
            reason = reason or "malicious class fragment"
        # C2/URL patterns
        if re.match(r"https?://|/\w+\.php|api\.telegram\.org", s, re.I):
            score += 2.0
            reason = reason or "C2/URL pattern"
        # Dalvik class refs (Lcom/pkg/Class;)
        if re.match(r"L[a-z]+/", s) and s.endswith(";"):
            score += 1.0
            reason = reason or "Dalvik class ref"
        # AMStrings
        if s.startswith("AMStrings:"):
            score += 3.0
            reason = reason or "AMStrings entry"
        # Bot/malware keywords
        if re.search(r"bot[./]|inject|c2|exfil|steal|sms|hook|admin|payload", sl):
            score += 1.0
            reason = reason or "malware keyword"
        # Unique-looking strings (mixed case, specific)
        if len(s) >= 15 and not s.startswith("Landroid") and score == 0:
            score += 0.3
            reason = reason or "long unique string"
        if score > 0:
            ranked.append({"value": s, "score": round(score, 2), "reason": reason})
    ranked.sort(key=lambda x: -x["score"])
    return ranked


# ---------------------------------------------------------------------------
# 2b. VT content search — validate top candidates for uniqueness
# ---------------------------------------------------------------------------

import time as _time

_vt_cache: Dict[str, int] = {}
_vt_cache_loaded = False


def _load_vt_cache() -> None:
    global _vt_cache, _vt_cache_loaded
    if _vt_cache_loaded:
        return
    _vt_cache_loaded = True
    if os.path.isfile(_VT_CACHE_PATH):
        try:
            with open(_VT_CACHE_PATH, "r", encoding="utf-8") as f:
                _vt_cache.update(json.load(f))
        except Exception:
            pass


def _save_vt_cache() -> None:
    os.makedirs(os.path.dirname(_VT_CACHE_PATH), exist_ok=True)
    try:
        with open(_VT_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(_vt_cache, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


def _vt_content_search(s: str, vt_key: str, logger: logging.Logger) -> int:
    """Search VT for APKs containing this string. Returns hit count or -1."""
    _load_vt_cache()
    if s in _vt_cache:
        return _vt_cache[s]
    try:
        import requests as _req
        r = _req.get(
            _VT_SEARCH_URL,
            params={"query": f'tag:apk and content:"{s}"',
                    "limit": 1, "descriptors_only": "true"},
            headers={"x-apikey": vt_key, "Accept": "application/json"},
            timeout=15,
        )
        if r.status_code == 429 or not r.ok:
            return -1
        data = r.json()
        count = len(data.get("data", []))
        if data.get("links", {}).get("next"):
            count += 100
        _vt_cache[s] = count
        _save_vt_cache()
        _time.sleep(0.5)
        return count
    except Exception:
        return -1


def _vt_validate_ranked(
    ranked: List[Dict[str, Any]],
    vt_api_key: Optional[str],
    logger: logging.Logger,
) -> List[Dict[str, Any]]:
    """Check top ranked strings on VT. Boost unique, penalize common."""
    if not vt_api_key:
        logger.info("[vt_check] No VT key — skipping VT validation")
        return ranked
    checked = 0
    for s in ranked:
        if checked >= MAX_VT_CHECKS_PER_SAMPLE:
            break
        val = s["value"]
        # Qualifying criteria
        if s["score"] < 1.0 or len(val) < 10:
            s["vt_hits"] = -1
            continue
        if re.match(r"https?://|^\d{1,3}\.\d{1,3}", val):
            s["vt_hits"] = -1
            continue
        if val.startswith("AMStrings:"):
            s["vt_hits"] = -1
            continue
        if val.startswith("L") and val.endswith(";") and "/" in val:
            s["vt_hits"] = -1
            continue
        hits = _vt_content_search(val, vt_api_key, logger)
        s["vt_hits"] = hits
        if hits < 0:
            continue
        checked += 1
        if hits == 0:
            s["score"] += 2.0
            s["reason"] += " +VT:unique(0)"
        elif hits <= 3:
            s["score"] += 1.5
            s["reason"] += f" +VT:rare({hits})"
        elif hits <= 10:
            s["score"] += 0.5
            s["reason"] += f" +VT:uncommon({hits})"
        elif hits <= 50:
            s["reason"] += f" VT:{hits}"
        elif hits <= 200:
            s["score"] -= 1.0
            s["reason"] += f" -VT:common({hits})"
        else:
            s["score"] -= 3.0
            s["reason"] += f" -VT:FP({hits})"
        logger.info("[vt_check] '%s' → %d hits (score=%.1f)",
                    val[:50], hits, s["score"])
    ranked.sort(key=lambda x: -x["score"])
    ranked = [s for s in ranked if s["score"] > 0]
    logger.info("[vt_check] Checked %d strings on VT. %d remain.",
                checked, len(ranked))
    return ranked


# ---------------------------------------------------------------------------
# 3. Fetch example rules from existing YARA corpus
# ---------------------------------------------------------------------------

def _get_example_rules(category: str, max_examples: int = 2) -> str:
    """Find example rules from zstatic-apk-sig.yara matching a category keyword."""
    yara_path = os.path.join(_SCRIPT_DIR, "yara_exports", "zstatic-apk-sig.yara")
    if not os.path.isfile(yara_path):
        return ""
    try:
        content = open(yara_path, "r", encoding="utf-8", errors="replace").read()
    except Exception:
        return ""
    # Find rules matching the category
    pattern = r"(rule\s+Android_\w*" + re.escape(category) + r"\w*\s*:\s*knownmalware\s*\{[\s\S]*?\n\})"
    matches = re.findall(pattern, content, re.I)
    if not matches:
        # Fallback: try broader match
        pattern = r"(rule\s+Android_\w+\s*:\s*knownmalware\s*\{[\s\S]*?\n\})"
        matches = re.findall(pattern, content)
    examples = []
    for m in matches[:max_examples]:
        if len(m) < 3000:  # skip overly long rules
            examples.append(m.strip())
    return "\n\n".join(examples)


# ---------------------------------------------------------------------------
# 4. Build the YARA prompt
# ---------------------------------------------------------------------------

def _build_yara_prompt(
    ranked_strings: List[Dict[str, Any]],
    apk_facts: Any,
    assessments: Dict,
    verdict: Dict[str, Any],
    example_rules: str,
    family: str,
    sha256: str,
) -> List[Dict[str, str]]:
    """Build LLM messages for YARA rule generation."""

    # Top 20 verified strings from the bin dump
    str_lines = []
    for rs in ranked_strings[:20]:
        vt_info = ""
        vt_hits = rs.get("vt_hits", -1)
        if vt_hits >= 0:
            vt_info = f" VT_APK_hits={vt_hits}"
        str_lines.append(f'  [score={rs["score"]:.1f}{vt_info}] "{rs["value"]}"  ({rs["reason"]})')

    # Decompiled source of top 2 suspicious classes
    source_blocks = []
    if apk_facts.classes and apk_facts.class_api_scores:
        top_classes = sorted(
            apk_facts.class_api_scores.items(), key=lambda x: -x[1]
        )[:2]
        for cls_name, score in top_classes:
            src = apk_facts.classes.get(cls_name, "")
            if src:
                source_blocks.append(
                    f"--- {cls_name} (api_score={score:.2f}) ---\n{src[:2500]}"
                )

    # Component names (services/receivers + intent filters) from manifest
    component_lines = []
    for comp_type in ("services", "receivers"):
        comps = apk_facts.components.get(comp_type, {})
        if isinstance(comps, dict):
            for name, info in list(comps.items())[:10]:
                filters = ""
                if isinstance(info, dict):
                    f_list = info.get("intent_filters", [])
                    if isinstance(f_list, list) and f_list:
                        filters = " → " + ", ".join(str(f) for f in f_list[:3])
                    elif isinstance(f_list, dict):
                        filters = " → " + str(f_list)
                component_lines.append(f"  [{comp_type[:-1]}] {name}{filters}")

    # Malicious cluster summary
    cluster_lines = []
    for fam, asmt in sorted(assessments.items(), key=lambda x: -x[1].confidence):
        if asmt.verdict == "malicious":
            cluster_lines.append(f"  {fam}: {asmt.verdict} (conf={asmt.confidence:.2f})")

    system_msg = (
        "You are an expert YARA rule author for Android malware.\n\n"
        "IMPORTANT CONTEXT ABOUT THE SCAN TARGET:\n"
        "- The rule will scan APK dump .bin files produced by apktool.\n"
        "- The dump contains: decoded AndroidManifest.xml (plain text), "
        "smali disassembly of all DEX files, res/values/strings.xml, "
        "certificate details, and a file listing.\n"
        "- Class names appear in Dalvik format: Lcom/pkg/ClassName; (slashes, L-prefix, semicolon)\n"
        "- Method/field names appear as plain ASCII in smali.\n"
        "- String literals from code appear as plain ASCII.\n"
        "- AndroidManifest entries (permissions, components, intent filters) appear as plain XML text.\n\n"
        "RULES FOR GOOD YARA:\n"
        "- I am providing you VERIFIED strings extracted directly from the dump. "
        "Use ONLY these strings or substrings of them. Do NOT invent strings.\n"
        "- Categorize strings: $c2_*, $bot_*, $sms_*, $class_*, $perm_*, $cmd_*\n"
        "- Use flexible conditions: '3 of ($bot_*) and 2 of ($sms_*)' not 'all of them'\n"
        "- Include meta: threatname, category, risk=127, date, author=pipeline-auto\n"
        "- Return ONLY the YARA rule text. No markdown fences, no explanation.\n"
    )

    user_msg = f"SAMPLE: {family}  SHA256={sha256[:16]}...  Risk={verdict.get('Risk-Score', 0)}\n"
    user_msg += f"Package: {apk_facts.basic_info.get('package_name', '?')}\n"
    user_msg += f"App label: {apk_facts.basic_info.get('app_name', '?')}\n"
    user_msg += f"Summary: {verdict.get('Summary', '')[:300]}\n\n"

    if cluster_lines:
        user_msg += "MALICIOUS BEHAVIORS:\n" + "\n".join(cluster_lines) + "\n\n"

    user_msg += "VERIFIED STRINGS FROM THE DUMP (guaranteed to match):\n"


# ---------------------------------------------------------------------------
# 5. YARA validation
# ---------------------------------------------------------------------------

def _resolve_yara():
    found = shutil.which("yara") or shutil.which("yara64")
    if found:
        return found
    for n in ("yara64.exe", "yara64", "yara"):
        p = os.path.join(_SCRIPT_DIR, "yara-master-v4.5.4-win64", n)
        if os.path.isfile(p):
            return p
    return None


def _extract_raw_text(llm_response: Any) -> str:
    """Unwrap call_llm's dict wrapper back to raw text."""
    if isinstance(llm_response, str):
        return llm_response
    if isinstance(llm_response, dict):
        for key in ("summary", "rule", "yara", "snort", "rules", "content"):
            val = llm_response.get(key)
            if isinstance(val, str) and len(val) > 20:
                return val
        return str(llm_response)
    return str(llm_response)


def _clean_markdown(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        lines = [l for l in lines if not l.strip().startswith("```")]
        text = "\n".join(lines).strip()
    return text


def _validate_yara(rule_text: str, bin_file: Optional[str], logger: logging.Logger) -> Dict:
    result = {"valid": False, "compiles": False, "self_matches": False, "error": ""}
    yara_exe = _resolve_yara()
    if not yara_exe:
        result["error"] = "No yara executable found"
        if rule_text.startswith("rule ") and "condition:" in rule_text:
            result["valid"] = True
        return result

    tmpdir = tempfile.mkdtemp(prefix="yara_val_")
    rule_path = os.path.join(tmpdir, "candidate.yara")
    try:
        with open(rule_path, "w", encoding="utf-8") as f:
            f.write(rule_text)
        # Compile check
        r = subprocess.run([yara_exe, rule_path, rule_path],
                           capture_output=True, text=True, timeout=15)
        result["compiles"] = (r.returncode == 0)
        if not result["compiles"]:
            result["error"] = r.stderr.strip()[:300]
            logger.warning("[yara_val] compile failed: %s", result["error"])
            return result
        # Self-match
        if bin_file and os.path.isfile(bin_file):
            r = subprocess.run([yara_exe, rule_path, bin_file],
                               capture_output=True, text=True, timeout=30)
            result["self_matches"] = bool(r.stdout.strip())
            if not result["self_matches"]:
                logger.info("[yara_val] compiles OK but does NOT match source sample")
        result["valid"] = result["compiles"]
    except Exception as exc:
        result["error"] = str(exc)[:200]
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    return result


# ---------------------------------------------------------------------------
# 6. Snort prompt (network IOCs from evidence items)
# ---------------------------------------------------------------------------

def _build_snort_prompt(evidence_items: List, verdict: Dict, family: str) -> Optional[List[Dict]]:
    domains, ips, urls, ids_alerts = [], [], [], []
    for ei in evidence_items:
        if ei.direction == "benign":
            continue
        val = ei.value
        if ei.kind in ("vt_dns", "vt_http", "vt_ip"):
            for d in re.findall(r"\b[\w.-]+\.(?:com|net|org|io|xyz|ru|cn|tk|top)\b", val, re.I):
                if d not in domains:
                    domains.append(d)
            for ip in re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", val):
                if ip not in ips:
                    ips.append(ip)
        if ei.kind == "string" and re.match(r"https?://", val, re.I):
            urls.append(val)
        if "IDS rule" in ei.explanation:
            ids_alerts.append(ei.explanation[:150])
    if not domains and not ips and not urls:
        return None
    system_msg = (
        "You are an expert Snort/Suricata IDS rule author.\n"
        "Write Snort 3 compatible rules for this malware's network behavior.\n"
        "Use content matches, dns.query, http.host. Set sid starting 9900001.\n"
        "Return ONLY rule text, no markdown.\n"
    )
    user_msg = (
        f"Malware: {family}  Verdict: {verdict.get('Summary', '')[:200]}\n"
        f"C2 domains: {', '.join(domains[:15]) or 'none'}\n"
        f"C2 IPs: {', '.join(ips[:15]) or 'none'}\n"
        f"URLs: {chr(10).join(urls[:8]) or 'none'}\n"
        f"IDS alerts: {chr(10).join(ids_alerts[:5]) or 'none'}\n"
    )
    return [{"role": "system", "content": system_msg}, {"role": "user", "content": user_msg}]


# ---------------------------------------------------------------------------
# 7. CIF blocklist (deterministic)
# ---------------------------------------------------------------------------

def _generate_cif(evidence_items: List, family: str, sha256: str) -> List[Dict]:
    today = dt.datetime.utcnow().strftime("%Y-%m-%d")
    tags = ["malware", "android", family.lower()]
    entries = []
    seen = set()
    for ei in evidence_items:
        if ei.direction != "malicious":
            continue
        val = ei.value
        for d in re.findall(r"\b[\w.-]+\.(?:com|net|org|io|xyz|ru|cn|tk|top)\b", val, re.I):
            if d.lower() not in seen:
                seen.add(d.lower())
                entries.append({"indicator": d, "itype": "fqdn", "tags": tags,
                                "confidence": 8, "provider": "apk-pipeline",
                                "description": f"{family} C2", "sha256": sha256,
                                "first_seen": today, "last_seen": today})
        for ip in re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", val):
            if ip not in seen:
                seen.add(ip)
                entries.append({"indicator": ip, "itype": "ipv4", "tags": tags,
                                "confidence": 7, "provider": "apk-pipeline",
                                "description": f"{family} C2 IP", "sha256": sha256,
                                "first_seen": today, "last_seen": today})
    return entries


# ---------------------------------------------------------------------------
# 8. Helpers
# ---------------------------------------------------------------------------

def _find_bin_dump(apk_path: str) -> Optional[str]:
    base_dir = os.path.dirname(apk_path)
    apk_name = os.path.basename(apk_path)
    bin_folder = os.path.join(base_dir, f"bin_{apk_name}")
    if os.path.isdir(bin_folder):
        for f in os.listdir(bin_folder):
            if f.endswith("_apk_dump.bin"):
                return os.path.join(bin_folder, f)
    try:
        md5 = hashlib.md5(open(apk_path, "rb").read()).hexdigest()
        candidate = os.path.join(bin_folder, f"{md5}_apk_dump.bin")
        if os.path.isfile(candidate):
            return candidate
    except Exception:
        pass
    return None


def _save_rule(directory: str, filename: str, content: str) -> str:
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


def _guess_family(verdict: Dict, yara_matches: List) -> str:
    for ym in yara_matches:
        parts = ym.get("detection_rule", "").split("_")
        if len(parts) >= 4:
            return parts[2]
    summary = verdict.get("Summary", "")
    for kw in ("FluBot", "SpyNote", "Cerberus", "BankBot", "Ahmyth", "Spymax",
               "Anubis", "Triada", "Coper", "Mamont", "Anatsa", "Ermac",
               "SoumniBot", "Redhook", "TsarBot", "Crocodilus"):
        if kw.lower() in summary.lower():
            return kw
    return "Gen"


def _guess_category(assessments: Dict) -> str:
    mal = [f for f, a in assessments.items() if a.verdict == "malicious"]
    if "overlay_fraud" in mal or "credential_theft" in mal:
        return "Banker"
    if "data_exfiltration" in mal and "call_interception" in mal:
        return "Spyware"
    if "sms_abuse" in mal:
        return "Trojan"
    if "dynamic_code_loading" in mal:
        return "Dropper"
    if "c2_networking" in mal:
        return "RAT"
    return "Trojan"


# ---------------------------------------------------------------------------
# 9. Main entry point
# ---------------------------------------------------------------------------

def generate_rules(
    apk_path: str,
    apk_facts: Any,
    evidence_items: List,
    clusters: Dict,
    assessments: Dict,
    verdict: Dict[str, Any],
    yara_matches: List,
    logger: logging.Logger,
    llm_client: Any,
    vt_api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Stage 6: generate YARA/Snort/CIF rules for a confirmed malicious APK."""
    from modified_trial8_multiple_models import call_llm

    family = _guess_family(verdict, yara_matches)
    category = _guess_category(assessments)
    sha256 = ""
    try:
        sha256 = hashlib.sha256(open(apk_path, "rb").read()).hexdigest()
    except Exception:
        sha256 = os.path.basename(apk_path).replace(".apk", "")

    output: Dict[str, Any] = {
        "yara_rule": None, "yara_rule_path": None, "yara_validation": None,
        "snort_rules": None, "snort_rules_path": None,
        "cif_entries": [], "cif_path": None,
        "ioc_summary": {"family": family, "category": category},
    }

    date_tag = dt.datetime.utcnow().strftime("%y%m%d")
    sha_short = sha256[:8]

    # ── YARA ──────────────────────────────────────────────────────────────

    # Step 1: Find the bin dump
    bin_file = _find_bin_dump(apk_path)
    if not bin_file:
        logger.warning("[rule_gen] No bin dump found — cannot generate YARA")
    else:
        logger.info("[rule_gen] Bin dump: %s", bin_file)

        # Step 2: Extract strings from bin dump (ground truth)
        raw_strings = _extract_strings_from_bin(bin_file)
        filtered = _filter_dump_strings(raw_strings)
        logger.info("[rule_gen] Bin dump: %d raw strings → %d after filtering",
                    len(raw_strings), len(filtered))

        # Step 3: Rank using analysis context
        ranked = _rank_dump_strings(filtered, apk_facts, evidence_items, verdict)
        logger.info("[rule_gen] Ranked: %d strings with score > 0. Top: %s",
                    len(ranked),
                    f'{ranked[0]["score"]} "{ranked[0]["value"][:50]}"' if ranked else "none")

        # Step 3b: VT content search validation (if VT key available)
        ranked = _vt_validate_ranked(ranked, vt_api_key, logger)
        output["ioc_summary"]["ranked_strings"] = len(ranked)
        output["ioc_summary"]["vt_validated"] = vt_api_key is not None

        if len(ranked) >= 3:
            # Step 4: Get example rules for this category
            examples = _get_example_rules(category)

            # Step 5: Build LLM prompt
            yara_msgs = _build_yara_prompt(
                ranked, apk_facts, assessments, verdict, examples, family, sha256,
            )

            # Step 6: Call LLM
            logger.info("[rule_gen] LLM YARA generation (model=%s)", RULE_GEN_MODEL)
            try:
                raw = call_llm(yara_msgs, RULE_GEN_MODEL, logger, llm_client)
                yara_text = _clean_markdown(_extract_raw_text(raw))
                output["yara_rule"] = yara_text

                # Step 7: Validate
                logger.info("[rule_gen] YARA validation")
                validation = _validate_yara(yara_text, bin_file, logger)
                output["yara_validation"] = validation

                if validation["compiles"] and validation["self_matches"]:
                    fname = f"Android_{category}_{family}_{sha_short}_{date_tag}.yara"
                    path = _save_rule(_YARA_DIR, fname, yara_text)
                    output["yara_rule_path"] = path
                    logger.info("[rule_gen] ✓ YARA saved: %s", path)
                elif validation["compiles"]:
                    logger.warning(
                        "[rule_gen] ✗ YARA compiles but does NOT match source sample — NOT saved"
                    )
                else:
                    logger.warning("[rule_gen] ✗ YARA compile error: %s", validation["error"])
            except Exception as exc:
                logger.error("[rule_gen] YARA generation failed: %s", exc)
        else:
            logger.info("[rule_gen] Only %d ranked strings — skipping YARA", len(ranked))

    # ── Snort ─────────────────────────────────────────────────────────────
    snort_msgs = _build_snort_prompt(evidence_items, verdict, family)
    if snort_msgs:
        logger.info("[rule_gen] LLM Snort generation")
        try:
            raw = call_llm(snort_msgs, RULE_GEN_MODEL, logger, llm_client)
            snort_text = _clean_markdown(_extract_raw_text(raw))
            output["snort_rules"] = snort_text
            fname = f"Android_{family}_{sha_short}_{date_tag}.rules"
            path = _save_rule(_SNORT_DIR, fname, snort_text)
            output["snort_rules_path"] = path
            logger.info("[rule_gen] Snort saved: %s", path)
        except Exception as exc:
            logger.error("[rule_gen] Snort generation failed: %s", exc)

    # ── CIF ───────────────────────────────────────────────────────────────
    cif = _generate_cif(evidence_items, family, sha256)
    if cif:
        output["cif_entries"] = cif
        cif_fname = f"{date_tag}_{family}_{sha_short}_blocklist.json"
        cif_path = _save_rule(_CIF_DIR, cif_fname, json.dumps(cif, indent=2))
        output["cif_path"] = cif_path
        logger.info("[rule_gen] CIF: %d indicators → %s", len(cif), cif_path)

    logger.info("[rule_gen] Stage 6 complete: YARA=%s Snort=%s CIF=%d",
                "saved" if output["yara_rule_path"] else ("generated" if output["yara_rule"] else "skip"),
                "OK" if output["snort_rules"] else "skip", len(cif))
    return output
