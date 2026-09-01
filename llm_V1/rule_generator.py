"""
rule_generator.py  –  Stage 6: YARA / Snort / CIF rule generation.

Architecture:
  1. Parse bin dump by section (AndroidManifest vs DEX vs file listing).
  2. Extract const-string values from DEX, component names from manifest, asset paths from listing.
  3. Rank by cross-referencing with analysis context (IOCs, decompiled source, verdict).
  4. Optionally validate top strings via VT content search.
  5. Build focused LLM prompt with verified strings + example rules.
  6. Validate: compile + self-match. Retry with relaxed condition if needed.
"""
from __future__ import annotations
import datetime as dt, hashlib, json, logging, os, re, shutil, subprocess, tempfile, time as _time
from typing import Any, Dict, List, Optional, Set, Tuple

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_GENERATED_DIR = os.path.join(_SCRIPT_DIR, "generated_rules")
_YARA_DIR = os.path.join(_GENERATED_DIR, "yara")
_SNORT_DIR = os.path.join(_GENERATED_DIR, "snort")
_CIF_DIR = os.path.join(_GENERATED_DIR, "cif")
_VT_CACHE_PATH = os.path.join(_GENERATED_DIR, "vt_string_cache.json")
_VT_SEARCH_URL = "https://www.virustotal.com/api/v3/intelligence/search"
RULE_GEN_MODEL = "claude-sonnet-4-6"
MAX_VT_CHECKS = 12

# SDK / library noise — strings containing these are NOT useful for YARA
_SDK_NOISE = re.compile(
    r"^(?:Landroid/|Ljava/|Ljavax/|Lkotlin/|Lkotlinx/|Landroidx/|Ldalvik/|"
    r"Lokhttp3/|Lokio/|Lretrofit2/|Lcom/google/|Lcom/squareup/|Lcom/fasterxml/|"
    r"Lcom/facebook/|Lorg/apache/|Lorg/json/|Lorg/xml/|"
    r"Lcn/jpush/|Lcn/jiguang/|Lcom/alibaba/|Lcom/alipay/|Lcom/tencent/|"
    r"Lcom/baidu/|Lcom/xiaomi/|Lcom/huawei/|Lcom/umeng/|Lcom/taobao/|"
    r"Lcom/sina/|Lbolts/|Lcom/crashlytics/|Lio/fabric/|Lcom/adjust/|"
    r"Lcom/appsflyer/|Lcom/airbnb/|Lcom/bumptech/|Lcom/github/)"
)
# Words too generic to be useful alone
_GENERIC_WORDS = {
    "true", "false", "null", "name", "value", "type", "class", "field",
    "method", "string", "invoke", "return", "const", "public", "private",
    "protected", "static", "final", "void", "this", "super", "interface",
    "extends", "implements", "abstract", "override", "exception",
    "android", "intent", "action", "permission", "provider", "receiver",
    "service", "activity", "application", "manifest", "xmlns",
    "layout", "drawable", "fragment", "adapter", "handler", "listener",
    "context", "content", "bundle", "manager", "system", "process",
    "runtime", "message", "request", "response", "connection",
    "accessibility", "notification", "broadcast", "callback",
}


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 1: Parse the bin dump by section type
# ═══════════════════════════════════════════════════════════════════════════

def _extract_ascii_strings(data: bytes, min_len: int = 8) -> List[str]:
    """Extract printable ASCII strings from raw bytes."""
    result, current = [], []
    for b in data:
        if 0x20 <= b < 0x7F:
            current.append(b)
        else:
            if len(current) >= min_len:
                result.append(bytes(current).decode("ascii"))
            current = []
    if len(current) >= min_len:
        result.append(bytes(current).decode("ascii"))
    return result


def parse_bin_dump(bin_path: str) -> Dict[str, List[str]]:
    """
    Parse the bin dump file into sections and extract strings from each.
    Returns dict with keys: manifest_components, manifest_permissions,
    dex_strings, asset_paths, all_filenames.
    """
    try:
        with open(bin_path, "rb") as f:
            raw = f.read()
    except Exception:
        return {"manifest_components": [], "manifest_permissions": [],
                "dex_strings": [], "asset_paths": [], "all_filenames": []}

    text = raw.decode("utf-8", errors="replace")
    lines = text.split("\n")

    manifest_components: List[str] = []
    manifest_permissions: List[str] = []
    asset_paths: List[str] = []
    all_filenames: List[str] = []

    # Track which section we're in based on filename: markers
    in_manifest = False
    in_dex = False
    manifest_text = ""

    for line in lines:
        if line.startswith("filename:"):
            fname = line.split("filename:", 1)[1].split(" filetype:")[0].strip()
            all_filenames.append(fname)
            in_manifest = "AndroidManifest.xml" in fname
            in_dex = fname.endswith(".dex")
            # Suspicious asset paths
            if re.search(r"\.(apk|dex|jar|so|bin|dat|php|zip)$", fname, re.I):
                if not fname.startswith("res/") and not fname.startswith("META-INF/"):
                    asset_paths.append(fname)
            continue

        if in_manifest:
            manifest_text += line + "\n"

    # Parse manifest for components and permissions
    for m in re.finditer(r'android:name="([^"]+)"', manifest_text):
        name = m.group(1)
        if name.startswith("android.permission."):
            manifest_permissions.append(name)
        elif "." in name and not name.startswith("android."):
            manifest_components.append(name)

    # Extract ASCII strings from the DEX portions of the raw binary.
    # The DEX binary is embedded after "filename:*.dex filetype: unknown\n"
    # We extract ALL ASCII strings >= 8 chars from the entire dump,
    # then filter out manifest/filename noise.
    dex_raw = _extract_ascii_strings(raw, min_len=8)

    # Filter: keep only strings that look like code-level content
    seen: Set[str] = set()
    dex_strings: List[str] = []
    for s in dex_raw:
        s = s.strip()
        if len(s) < 8 or len(s) > 200 or s in seen:
            continue
        sl = s.lower()
        if sl in _GENERIC_WORDS:
            continue
        # Skip SDK Dalvik refs
        if s.startswith("L") and "/" in s and _SDK_NOISE.match(s):
            continue
        # Skip dump structural noise
        if s.startswith("filename:") or s.startswith("filetype:"):
            continue
        # Skip XML tags
        if s.startswith("<") or s.startswith("<?"):
            continue

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 2: Rank strings using analysis context
# ═══════════════════════════════════════════════════════════════════════════

def rank_strings(
    parsed: Dict[str, List[str]],
    apk_facts: Any,
    evidence_items: List,
    verdict: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Rank DEX strings + manifest components by relevance to analysis."""
    ioc_set = {s.lower() for s in (verdict.get("IOCs") or [])}
    evidence_vals = {ei.value.lower() for ei in evidence_items if ei.direction != "benign"}

    # Collect source code literals from decompiled suspicious classes
    source_lits: Set[str] = set()
    for cls, src in apk_facts.classes.items():
        if src and apk_facts.class_api_scores.get(cls, 0) >= 0.30:
            for m in re.finditer(r'"([^"]{8,80})"', src):
                source_lits.add(m.group(1).lower())

    ranked: List[Dict[str, Any]] = []

    # --- Rank DEX strings (the gold mine) ---
    for s in parsed["dex_strings"]:
        sl = s.lower()
        score, reason = 0.0, ""

        # IOC exact match
        if sl in ioc_set:
            score += 5.0; reason = "IOC"
        # Source literal match (from decompiled classes)
        if sl in source_lits:
            score += 4.0; reason = reason or "source_literal"
        # C2/URL patterns
        if re.match(r"https?://|/\w+\.php|api\.telegram\.org", s, re.I):
            score += 3.5; reason = reason or "C2_URL"
        # Bot/inject/c2 path keywords
        if re.search(r"[/.](?:bot|inject|c2|exfil|steal|hook|socks|vnc|screencast)[/.]", sl):
            score += 3.0; reason = reason or "bot_path"
        # Bot command-like strings (CamelCase or underscore compound names)
        if re.match(r"[a-z]+_[a-z]+_[a-z]+", sl) and len(s) >= 12:
            if re.search(r"sms|upload|send|delete|record|capture|inject|install|command|task|kill", sl):
                score += 3.0; reason = reason or "bot_command"
        # CamelCase service/worker names
        if re.match(r"[A-Z][a-z]+[A-Z][a-z]+", s) and len(s) >= 12:
            if re.search(r"Service|Worker|Receiver|Exporter|Sender|Handler|Manager", s):
                score += 2.5; reason = reason or "service_name"
        # AMStrings entries
        if s.startswith("AMStrings:"):
            score += 4.0; reason = reason or "AMStrings"
        # Dalvik class path for app-specific class (not SDK)
        if s.startswith("L") and s.endswith(";") and "/" in s and not _SDK_NOISE.match(s):
            score += 1.0; reason = reason or "dalvik_class"
        # Evidence exact match
        if sl in evidence_vals and not reason:
            score += 2.0; reason = "evidence"
        # Log/debug messages (quoted-looking or sentence-like)
        if re.search(r"[A-Z][a-z]+ [a-z]+ [a-z]+", s) and len(s) >= 15:
            if not any(w in sl for w in ("android", "java", "kotlin", "google")):
                score += 1.5; reason = reason or "log_message"

        if score > 0:
            ranked.append({"value": s, "score": round(score, 2),
                          "reason": reason, "type": "dex_string"})

    # --- Rank manifest components (service/receiver names) ---
    for comp in parsed["manifest_components"]:
        sl = comp.lower()
        score, reason = 0.0, ""
        if sl in ioc_set:
            score += 4.0; reason = "IOC"
        if re.search(r"bot|inject|sms|admin|helper|periodic|screencast|socks|vnc", sl):
            score += 3.0; reason = reason or "bot_component"
        elif re.search(r"receiver|service", sl) and not re.search(r"firebase|google|jpush|jiguang|alibaba|tencent|airbnb", sl):
            score += 1.0; reason = reason or "custom_component"
        if score > 0:
            ranked.append({"value": comp, "score": round(score, 2),
                          "reason": reason, "type": "manifest_component"})

    # --- Rank suspicious asset paths ---
    for path in parsed["asset_paths"]:
        score = 2.5
        reason = "suspicious_asset"
        if re.search(r"\.apk$|\.dex$|implant|payload|inject", path, re.I):
            score = 3.5
            reason = "dropper_asset"
        ranked.append({"value": path, "score": round(score, 2),
                      "reason": reason, "type": "asset_path"})

    ranked.sort(key=lambda x: -x["score"])
    return ranked


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 3: VT content search validation
# ═══════════════════════════════════════════════════════════════════════════

_vt_cache: Dict[str, int] = {}
_vt_loaded = False

def _load_vt_cache():
    global _vt_cache, _vt_loaded
    if _vt_loaded: return
    _vt_loaded = True
    if os.path.isfile(_VT_CACHE_PATH):
        try: _vt_cache.update(json.load(open(_VT_CACHE_PATH, "r")))
        except Exception: pass

def _save_vt_cache():
    os.makedirs(os.path.dirname(_VT_CACHE_PATH), exist_ok=True)
    try: json.dump(_vt_cache, open(_VT_CACHE_PATH, "w"), indent=2)
    except Exception: pass

def _vt_search(s: str, key: str, log: logging.Logger) -> int:
    _load_vt_cache()
    if s in _vt_cache: return _vt_cache[s]
    try:
        import requests as _rq
        r = _rq.get(_VT_SEARCH_URL,
                    params={"query": f'tag:apk and content:"{s}"', "limit": 1, "descriptors_only": "true"},
                    headers={"x-apikey": key, "Accept": "application/json"}, timeout=15)
        if r.status_code == 429 or not r.ok: return -1
        d = r.json()
        c = len(d.get("data", [])) + (100 if d.get("links", {}).get("next") else 0)
        _vt_cache[s] = c; _save_vt_cache(); _time.sleep(0.5)
        return c
    except Exception: return -1

def vt_validate(ranked: List[Dict], vt_key: Optional[str], log: logging.Logger) -> List[Dict]:
    if not vt_key:
        log.info("[vt_check] No VT key — skipping"); return ranked
    checked = 0
    for s in ranked:
        if checked >= MAX_VT_CHECKS: break
        val = s["value"]
        # Only check high-scoring DEX strings (not paths, not Dalvik refs)
        if s["score"] < 2.0 or len(val) < 10 or s["type"] != "dex_string": continue
        if re.match(r"https?://|^L[a-z]", val): continue
        hits = _vt_search(val, vt_key, log)
        s["vt_hits"] = hits
        if hits < 0: continue
        checked += 1
        if hits == 0: s["score"] += 2.0; s["reason"] += " +VT:unique"
        elif hits <= 5: s["score"] += 1.0; s["reason"] += f" +VT:rare({hits})"
        elif hits <= 30: s["reason"] += f" VT:{hits}"

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 4: Example rules + YARA prompt builder
# ═══════════════════════════════════════════════════════════════════════════

def _get_examples(category: str) -> str:
    p = os.path.join(_SCRIPT_DIR, "yara_exports", "zstatic-apk-sig.yara")
    if not os.path.isfile(p): return ""
    try: content = open(p, "r", encoding="utf-8", errors="replace").read()
    except Exception: return ""
    pat = r"(rule\s+Android_\w*" + re.escape(category) + r"\w*\s*:\s*knownmalware\s*\{[\s\S]*?\n\})"
    matches = re.findall(pat, content, re.I)
    if not matches:
        matches = re.findall(r"(rule\s+Android_\w+\s*:\s*knownmalware\s*\{[\s\S]*?\n\})", content)
    return "\n\n".join(m.strip() for m in matches[:2] if len(m) < 3000)


def build_yara_prompt(
    ranked: List[Dict], apk_facts: Any, assessments: Dict,
    verdict: Dict, examples: str, family: str, sha256: str,
) -> List[Dict[str, str]]:
    """Build the LLM prompt for YARA generation."""

    # Separate by type
    dex_strs = [r for r in ranked if r["type"] == "dex_string"][:15]
    components = [r for r in ranked if r["type"] == "manifest_component"][:5]
    assets = [r for r in ranked if r["type"] == "asset_path"][:3]

    # Format strings
    dex_lines = []
    for r in dex_strs:
        vt = f" VT={r['vt_hits']}" if r.get("vt_hits", -1) >= 0 else ""
        dex_lines.append(f'  [{r["score"]:.1f}{vt}] "{r["value"]}"  ({r["reason"]})')

    comp_lines = [f'  {r["value"]}  ({r["reason"]})' for r in components]
    asset_lines = [f'  {r["value"]}  ({r["reason"]})' for r in assets]

    # Top 2 decompiled classes
    src_blocks = []
    if apk_facts.classes and apk_facts.class_api_scores:
        for cls, score in sorted(apk_facts.class_api_scores.items(), key=lambda x: -x[1])[:2]:
            src = apk_facts.classes.get(cls, "")
            if src:
                src_blocks.append(f"--- {cls} (score={score:.2f}) ---\n{src[:2000]}")

    # Malicious clusters
    mal_clusters = [f"  {f}: {a.verdict} ({a.confidence:.2f})"
                    for f, a in sorted(assessments.items(), key=lambda x: -x[1].confidence)
                    if a.verdict == "malicious"]

    sys_msg = (
        "You are an expert YARA rule author for Android malware.\n\n"
        "TARGET FORMAT: APK dump .bin files containing decoded AndroidManifest.xml "
        "and RAW DEX binary. String constants from Java/Kotlin code appear as "
        "plain ASCII in the DEX binary. Component names appear as plain text in "
        "the decoded manifest.\n\n"
        "HOW TO WRITE GOOD ANDROID YARA RULES:\n"
        "- Use string CONSTANTS from code: bot commands (e.g. 'streaming_mic', "
        "'kill_bot'), C2 API paths ('/api/upload_sms.php'), log messages, "
        "unique function names, encoded tokens.\n"
        "- Use manifest component names that indicate bot infrastructure: "
        "'BotHeartbeatService', 'SmsDataWorker', 'InjAccessibilityService'.\n"
        "- Use suspicious asset paths: 'res/raw/implant.apk', 'injects/ServiceName.txt'.\n"
        "- Categorize: $cmd_*, $c2_*, $sms_*, $bot_*, $asset_*\n"
        "- Flexible conditions: '3 of ($cmd_*)' or '4 of them', NOT 'all of them'.\n"
        "- DO NOT use: SDK class refs (Jiguang, Bolts, Lottie, Google, Alibaba), "
        "randomized package names, generic Android permissions alone.\n"
        "- I provide VERIFIED strings from the dump. Use ONLY these.\n"
        "- Include meta: threatname, category, risk=127, date, author=pipeline-auto.\n"
        "- Return ONLY the YARA rule. No markdown fences, no explanation.\n"
    )

    usr = f"SAMPLE: {family} | SHA256={sha256[:16]}... | Risk={verdict.get('Risk-Score',0)}\n"
    usr += f"Package: {apk_facts.basic_info.get('package_name','?')}\n"
    usr += f"Summary: {verdict.get('Summary','')[:300]}\n\n"
    if mal_clusters:
        usr += "MALICIOUS BEHAVIORS:\n" + "\n".join(mal_clusters) + "\n\n"
    if dex_lines:
        usr += "DEX STRING CONSTANTS (from code — highest quality):\n" + "\n".join(dex_lines) + "\n\n"
    if comp_lines:
        usr += "MANIFEST COMPONENTS (service/receiver names):\n" + "\n".join(comp_lines) + "\n\n"

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 5: YARA validation + condition relaxer
# ═══════════════════════════════════════════════════════════════════════════

def _resolve_yara():
    found = shutil.which("yara") or shutil.which("yara64")
    if found: return found
    for n in ("yara64.exe", "yara64", "yara"):
        p = os.path.join(_SCRIPT_DIR, "yara-master-v4.5.4-win64", n)
        if os.path.isfile(p): return p
    return None

def _extract_raw_text(resp: Any) -> str:
    if isinstance(resp, str): return resp
    if isinstance(resp, dict):
        for k in ("summary", "rule", "yara", "snort", "rules", "content"):
            v = resp.get(k)
            if isinstance(v, str) and len(v) > 20: return v
        return str(resp)
    return str(resp)

def _clean_md(t: str) -> str:
    t = t.strip()
    if t.startswith("```"):
        t = "\n".join(l for l in t.split("\n") if not l.strip().startswith("```")).strip()
    return t

def _validate_yara(rule: str, bin_file: Optional[str], log: logging.Logger) -> Dict:
    r = {"valid": False, "compiles": False, "self_matches": False, "error": ""}
    yara = _resolve_yara()
    if not yara:
        r["error"] = "No yara executable"
        if rule.startswith("rule ") and "condition:" in rule: r["valid"] = True
        return r
    d = tempfile.mkdtemp(prefix="yara_v_")
    rp = os.path.join(d, "rule.yara")
    try:
        open(rp, "w", encoding="utf-8").write(rule)
        p = subprocess.run([yara, rp, rp], capture_output=True, text=True, timeout=15)
        r["compiles"] = p.returncode == 0
        if not r["compiles"]:
            r["error"] = p.stderr.strip()[:300]; return r
        if bin_file and os.path.isfile(bin_file):
            p = subprocess.run([yara, rp, bin_file], capture_output=True, text=True, timeout=30)
            r["self_matches"] = bool(p.stdout.strip())
        r["valid"] = r["compiles"]
    except Exception as e:
        r["error"] = str(e)[:200]
    finally:
        shutil.rmtree(d, ignore_errors=True)
    return r

def _relax_condition(rule: str) -> str:
    n = len(re.findall(r"\$\w+\s*=", rule))
    if n < 2: return rule

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 6: Snort, CIF, helpers
# ═══════════════════════════════════════════════════════════════════════════

def _build_snort(evidence: List, verdict: Dict, family: str) -> Optional[List[Dict]]:
    domains, ips, urls = [], [], []
    for ei in evidence:
        if ei.direction == "benign": continue
        v = ei.value
        if ei.kind in ("vt_dns","vt_http","vt_ip"):
            for d in re.findall(r"\b[\w.-]+\.(?:com|net|org|io|xyz|ru|cn|tk|top)\b", v, re.I):
                if d not in domains: domains.append(d)
            for ip in re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", v):
                if ip not in ips: ips.append(ip)
        if ei.kind == "string" and re.match(r"https?://", v, re.I):
            urls.append(v)
    if not domains and not ips and not urls: return None
    sys_msg = ("You are a Snort/Suricata rule author.\n"
               "Write Snort 3 rules. Use content, dns.query, http.host. sid from 9900001.\n"
               "Return ONLY rule text.\n")
    usr = (f"Malware: {family}\n"
           f"Domains: {', '.join(domains[:15])}\nIPs: {', '.join(ips[:15])}\n"
           f"URLs: {chr(10).join(urls[:8])}\n")
    return [{"role":"system","content":sys_msg},{"role":"user","content":usr}]

def _gen_cif(evidence: List, family: str, sha: str) -> List[Dict]:
    today = dt.datetime.utcnow().strftime("%Y-%m-%d")
    tags = ["malware","android",family.lower()]
    entries, seen = [], set()
    for ei in evidence:
        if ei.direction != "malicious": continue
        for d in re.findall(r"\b[\w.-]+\.(?:com|net|org|io|xyz|ru|cn|tk|top)\b", ei.value, re.I):
            if d.lower() not in seen:
                seen.add(d.lower())
                entries.append({"indicator":d,"itype":"fqdn","tags":tags,
                                "confidence":8,"provider":"apk-pipeline","sha256":sha,
                                "first_seen":today,"last_seen":today})
    return entries

def _find_bin(apk_path: str) -> Optional[str]:
    d = os.path.dirname(apk_path)
    n = os.path.basename(apk_path)
    bf = os.path.join(d, f"bin_{n}")
    if os.path.isdir(bf):
        for f in os.listdir(bf):
            if f.endswith("_apk_dump.bin"):
                return os.path.join(bf, f)
    try:
        md5 = hashlib.md5(open(apk_path,"rb").read()).hexdigest()
        c = os.path.join(bf, f"{md5}_apk_dump.bin")
        if os.path.isfile(c): return c
    except Exception: pass
    return None

def _save(directory: str, fname: str, content: str) -> str:
    os.makedirs(directory, exist_ok=True)
    p = os.path.join(directory, fname)
    open(p, "w", encoding="utf-8").write(content)
    return p

def _family(verdict: Dict, yara_matches: List) -> str:
    for ym in yara_matches:
        parts = ym.get("detection_rule","").split("_")
        if len(parts) >= 4: return parts[2]
    s = verdict.get("Summary","")
    for kw in ("FluBot","SpyNote","Cerberus","BankBot","Ahmyth","Spymax",
               "Anubis","Triada","Coper","Mamont","Anatsa","Ermac","SoumniBot",
               "Redhook","TsarBot","Crocodilus","Zanubis","Sharkbot"):
        if kw.lower() in s.lower(): return kw
    return "Gen"


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 7: Main entry point
# ═══════════════════════════════════════════════════════════════════════════

def generate_rules(
    apk_path: str, apk_facts: Any, evidence_items: List, clusters: Dict,
    assessments: Dict, verdict: Dict[str, Any], yara_matches: List,
    logger: logging.Logger, llm_client: Any, vt_api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Stage 6: generate YARA/Snort/CIF rules for a confirmed malicious APK."""
    from modified_trial8_multiple_models import call_llm

    fam = _family(verdict, yara_matches)
    cat = _category(assessments)
    sha = ""
    try: sha = hashlib.sha256(open(apk_path,"rb").read()).hexdigest()
    except Exception: sha = os.path.basename(apk_path).replace(".apk","")

    out: Dict[str, Any] = {
        "yara_rule": None, "yara_rule_path": None, "yara_validation": None,
        "snort_rules": None, "snort_rules_path": None,
        "cif_entries": [], "cif_path": None,
        "ioc_summary": {"family": fam, "category": cat},
    }
    dtag = dt.datetime.utcnow().strftime("%y%m%d")
    ss = sha[:8]

    # ── YARA ──────────────────────────────────────────────────────────
    bin_file = _find_bin(apk_path)
    if not bin_file:
        logger.warning("[rule_gen] No bin dump — skipping YARA")
    else:
        logger.info("[rule_gen] Bin dump: %s", bin_file)

        # Step 1: Parse by section
        parsed = parse_bin_dump(bin_file)
        logger.info("[rule_gen] Parsed: %d dex_strings, %d components, %d assets",
                    len(parsed["dex_strings"]), len(parsed["manifest_components"]),
                    len(parsed["asset_paths"]))

        # Step 2: Rank using analysis context
        ranked = rank_strings(parsed, apk_facts, evidence_items, verdict)
        dex_count = sum(1 for r in ranked if r["type"] == "dex_string")
        comp_count = sum(1 for r in ranked if r["type"] == "manifest_component")
        logger.info("[rule_gen] Ranked: %d total (%d dex_strings, %d components). Top: %s",
                    len(ranked), dex_count, comp_count,
                    f'{ranked[0]["score"]:.1f} "{ranked[0]["value"][:50]}"' if ranked else "none")

        # Step 3: VT validation
        ranked = vt_validate(ranked, vt_api_key, logger)
        out["ioc_summary"]["ranked_strings"] = len(ranked)

        if len(ranked) >= 3:
            # Step 4: Build prompt
            examples = _get_examples(cat)
            msgs = build_yara_prompt(ranked, apk_facts, assessments, verdict, examples, fam, sha)
            psize = sum(len(m.get("content","")) for m in msgs)
            logger.info("[rule_gen] LLM YARA gen (prompt=%d chars)", psize)

            try:
                raw = call_llm(msgs, RULE_GEN_MODEL, logger, llm_client)
                yara = _clean_md(_extract_raw_text(raw))
                out["yara_rule"] = yara

                # Step 5: Validate
                val = _validate_yara(yara, bin_file, logger)
                out["yara_validation"] = val

                if val["compiles"] and val["self_matches"]:
                    fn = f"Android_{cat}_{fam}_{ss}_{dtag}.yara"
                    out["yara_rule_path"] = _save(_YARA_DIR, fn, yara)
                    logger.info("[rule_gen] ✓ YARA saved: %s", out["yara_rule_path"])
                elif val["compiles"]:
                    logger.warning("[rule_gen] Self-match failed — trying relaxed condition")
                    relaxed = _relax_condition(yara)
                    if relaxed != yara:
                        v2 = _validate_yara(relaxed, bin_file, logger)
                        if v2["compiles"] and v2["self_matches"]:
                            out["yara_rule"] = relaxed
                            out["yara_validation"] = v2
                            fn = f"Android_{cat}_{fam}_{ss}_{dtag}.yara"
                            out["yara_rule_path"] = _save(_YARA_DIR, fn, relaxed)
                            logger.info("[rule_gen] ✓ YARA saved (relaxed): %s", out["yara_rule_path"])
                        else:
                            logger.warning("[rule_gen] ✗ Relaxed also failed — NOT saved")
                    else:
                        logger.warning("[rule_gen] ✗ Could not relax — NOT saved")
                else:
                    logger.warning("[rule_gen] ✗ Compile error: %s", val["error"])
            except Exception as e:
                logger.error("[rule_gen] YARA gen failed: %s", e)
        else:
            logger.info("[rule_gen] Only %d ranked — skipping YARA", len(ranked))

    # ── Snort ─────────────────────────────────────────────────────────
    snort_msgs = _build_snort(evidence_items, verdict, fam)
    if snort_msgs:
        logger.info("[rule_gen] LLM Snort gen")
        try:
            raw = call_llm(snort_msgs, RULE_GEN_MODEL, logger, llm_client)
            txt = _clean_md(_extract_raw_text(raw))
            out["snort_rules"] = txt
            out["snort_rules_path"] = _save(_SNORT_DIR, f"Android_{fam}_{ss}_{dtag}.rules", txt)
            logger.info("[rule_gen] Snort saved: %s", out["snort_rules_path"])
        except Exception as e:
            logger.error("[rule_gen] Snort failed: %s", e)

    # ── CIF ───────────────────────────────────────────────────────────
    cif = _gen_cif(evidence_items, fam, sha)
    if cif:
        out["cif_entries"] = cif
        out["cif_path"] = _save(_CIF_DIR, f"{dtag}_{fam}_{ss}.json", json.dumps(cif, indent=2))
        logger.info("[rule_gen] CIF: %d → %s", len(cif), out["cif_path"])

    logger.info("[rule_gen] Done: YARA=%s Snort=%s CIF=%d",
                "saved" if out["yara_rule_path"] else ("gen" if out["yara_rule"] else "skip"),
                "OK" if out["snort_rules"] else "skip", len(cif))
    return out

def _category(assessments: Dict) -> str:
    mal = [f for f,a in assessments.items() if a.verdict == "malicious"]
    if "overlay_fraud" in mal or "credential_theft" in mal: return "Banker"
    if "data_exfiltration" in mal and "call_interception" in mal: return "Spyware"
    if "sms_abuse" in mal: return "Trojan"
    if "dynamic_code_loading" in mal: return "Dropper"
    return "Trojan"

