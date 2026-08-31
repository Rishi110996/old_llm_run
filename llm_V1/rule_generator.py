"""
rule_generator.py
-----------------
Stage 6c + 6d: LLM-assisted YARA/Snort/CIF rule drafting and validation.

Entry point:
    generate_rules(apk_path, apk_facts, evidence_items, clusters,
                   assessments, verdict, yara_matches, logger,
                   llm_client, vt_api_key) -> dict

Returns a dict with keys: yara_rule, snort_rules, cif_entries, validation.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import os
import re
import subprocess
import shutil
import tempfile
from typing import Any, Dict, List, Optional

from ioc_extractor import ExtractedIOCs, extract_iocs
from string_scorer import ScoredString, score_candidates

# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_GENERATED_DIR = os.path.join(_SCRIPT_DIR, "generated_rules")
_YARA_DIR = os.path.join(_GENERATED_DIR, "yara")
_SNORT_DIR = os.path.join(_GENERATED_DIR, "snort")
_CIF_DIR = os.path.join(_GENERATED_DIR, "cif")

RULE_GEN_MODEL = "claude-sonnet-4-6"
MIN_SCORED_STRINGS_FOR_YARA = 3
TOP_STRINGS_FOR_PROMPT = 25
MAX_SOURCE_IN_PROMPT = 3000     # bytes of decompiled source to include


def _extract_raw_text(llm_response: Any) -> str:
    """
    Extract raw text from call_llm() output.

    call_llm() always tries to parse the response as JSON.  When the LLM
    returns plain text (like a YARA rule), the parser wraps it as:
        {"summary": "<raw text>", "relevant": [], "evidence": []}
    This helper unwraps that back to the original text.
    """
    if isinstance(llm_response, str):
        return llm_response
    if isinstance(llm_response, dict):
        # The "summary" key holds the raw non-JSON text from call_llm fallback
        for key in ("summary", "rule", "yara", "snort", "rules", "content"):
            val = llm_response.get(key)
            if isinstance(val, str) and len(val) > 20:
                return val
        # Last resort: stringify the whole dict
        return str(llm_response)
    return str(llm_response)


# ---------------------------------------------------------------------------
# YARA prompt builder
# ---------------------------------------------------------------------------

def _build_yara_prompt(
    iocs: ExtractedIOCs,
    scored: List[ScoredString],
    apk_facts: Any,
    existing_rule_text: str,
) -> List[Dict[str, str]]:
    """Build the LLM messages for YARA rule generation."""

    # Format scored strings for the prompt
    string_lines = []
    for ss in scored[:TOP_STRINGS_FOR_PROMPT]:
        vt_info = f"VT_hits={ss.vt_apk_hits}" if ss.vt_apk_hits >= 0 else "VT=n/a"
        string_lines.append(
            f"  [q={ss.quality_score:.2f} u={ss.uniqueness:.2f} "
            f"m={ss.maliciousness:.2f} s={ss.stability:.2f} {vt_info}] "
            f'"{ss.value[:120]}"  ({ss.kind}, {ss.source})'
        )

    # Decompiled source snippet (most suspicious class)
    source_snippet = ""
    if apk_facts.classes:
        top_cls = max(apk_facts.class_api_scores, key=apk_facts.class_api_scores.get, default=None)
        if top_cls and top_cls in apk_facts.classes:
            source_snippet = apk_facts.classes[top_cls][:MAX_SOURCE_IN_PROMPT]

    system_msg = (
        "You are an expert YARA rule author for Android malware detection.\n"
        "Write a production-quality YARA rule that detects the described sample "
        "and its likely variants.\n\n"
        "RULES FOR WRITING GOOD YARA:\n"
        "- Use string categories ($c2_*, $exfil_*, $cmd_*, $class_*) with "
        "condition logic like '3 of ($c2_*) and 2 of ($exfil_*)' or "
        "'N of them' rather than always 'all of them'.\n"
        "- Prefer strings with high quality scores (q >= 0.60). Avoid strings "
        "that appear in 50+ APKs on VT (low uniqueness).\n"
        "- Do NOT use package names or generic Android permissions as primary "
        "detection strings. Those appear in thousands of benign apps.\n"
        "- AMStrings:* entries and obfuscated class/method names are excellent "
        "YARA candidates — they survive across variants.\n"
        "- C2 URLs/domains are valid but mark them as low-stability (variants "
        "will change them). Use them as optional, not required.\n"
        "- Include meta: threatname, category, risk=127, date, author.\n"
        "- CRITICAL: The rule scans APK dump .bin files created by apktool. "
        "The dump contains: decoded AndroidManifest.xml, smali disassembly of "
        "all DEX files, res/values/strings.xml, certificate info, and file paths.\n"
        "- In the dump, Java class names appear in Dalvik format with SLASHES: "
        "Lcom/example/MyClass; not com.example.MyClass. Method names and string "
        "literals appear as plain ASCII in the smali. Use strings that actually "
        "appear in smali/manifest, NOT Java dot-notation package names.\n"
        "- Good YARA strings for Android: method/function names (e.g. "
        "'readSMSBox', 'executeShell', 'sendToC2'), C2 URL paths (e.g. "
        "'/set/log_add.php'), command strings, AMStrings:* entries, "
        "Dalvik class references (Lcom/pkg/ClassName;), and unique manifest "
        "entries.\n"
        "- BAD YARA strings: Java dot-notation package names (won't match), "
        "generic Android permission strings, common SDK class names.\n"
        "- Return ONLY the complete YARA rule text. No markdown fences, no "
        "explanation, no extra text.\n"
    )

    user_msg = (
        f"SAMPLE CONTEXT:\n"
        f"  Family:    {iocs.family}\n"
        f"  SHA256:    {iocs.sha256}\n"
        f"  Package:   {iocs.package_name}\n"
        f"  Risk:      {iocs.risk_score}\n"
        f"  Behaviors: {', '.join(iocs.behavior_families)}\n"
        f"  MITRE:     {', '.join(iocs.mitre_techniques) or 'none'}\n"
        f"  Existing YARA hit: {', '.join(iocs.existing_yara_matches) or 'none (new rule needed)'}\n\n"
        f"CANDIDATE STRINGS (sorted by quality_score):\n"
        f"{chr(10).join(string_lines)}\n\n"
    )
    if source_snippet:
        user_msg += (
            f"DECOMPILED SOURCE (most suspicious class):\n"
            f"{source_snippet}\n\n"
        )
    if existing_rule_text and existing_rule_text != "<not found in source>":
        user_msg += (
            f"EXISTING RULE FOR THIS FAMILY (reference pattern):\n"
            f"{existing_rule_text[:2000]}\n\n"
        )
    user_msg += (
        "Write the YARA rule now. Use rule name format: "
        f"Android_<Category>_{iocs.family}_Pipeline_<6digit_date>\n"
    )

    return [
        {"role": "system", "content": system_msg},
        {"role": "user", "content": user_msg},
    ]


# ---------------------------------------------------------------------------
# Snort prompt builder
# ---------------------------------------------------------------------------

def _build_snort_prompt(iocs: ExtractedIOCs) -> Optional[List[Dict[str, str]]]:
    """Build LLM messages for Snort rule generation. Returns None if no network IOCs."""
    if not iocs.c2_domains and not iocs.c2_ips and not iocs.c2_urls:
        return None

    system_msg = (
        "You are an expert Snort/Suricata IDS rule author.\n"
        "Write production-quality Snort 3 compatible rules for the described "
        "Android malware's network behavior.\n\n"
        "RULES:\n"
        "- Use content matches for HTTP headers/body, not just IP/domain.\n"
        "- For domain-based detection use dns.query or http.host.\n"
        "- Set appropriate sid (start from 9900001), rev:1, classtype, priority.\n"
        "- Include reference:url,virustotal.com/...\n"
        "- Return ONLY the Snort rule text. No markdown, no explanation.\n"
    )
    user_msg = (
        f"MALWARE: {iocs.family} (SHA256: {iocs.sha256[:16]}...)\n"
        f"C2 DOMAINS: {', '.join(iocs.c2_domains[:20]) or 'none'}\n"
        f"C2 IPs: {', '.join(iocs.c2_ips[:20]) or 'none'}\n"
        f"C2 URLs: {chr(10).join(iocs.c2_urls[:10]) or 'none'}\n"
        f"TELEGRAM BOTS: {', '.join(iocs.telegram_bot_tokens[:5]) or 'none'}\n"
        f"IDS ALERTS ALREADY TRIGGERED:\n"
    )
    for alert in iocs.ids_alerts[:10]:
        user_msg += f"  - [{alert['severity']}] {alert['rule_msg']}\n"
    user_msg += "\nWrite the Snort rules now.\n"

    return [
        {"role": "system", "content": system_msg},
        {"role": "user", "content": user_msg},
    ]


# ---------------------------------------------------------------------------
# CIF blocklist generator (deterministic, no LLM)
# ---------------------------------------------------------------------------

def _generate_cif_entries(iocs: ExtractedIOCs) -> List[Dict[str, Any]]:
    """Generate CIF-format blocklist entries from confirmed C2 indicators."""
    entries: List[Dict[str, Any]] = []
    today = dt.datetime.utcnow().strftime("%Y-%m-%d")
    tags = ["malware", "android", iocs.family.lower()]

    for domain in iocs.c2_domains:
        entries.append({
            "indicator": domain, "itype": "fqdn", "tags": tags,
            "confidence": 8, "provider": "apk-analysis-pipeline",
            "description": f"{iocs.family} C2 domain",
            "first_seen": today, "last_seen": today, "sha256": iocs.sha256,
        })
    for ip in iocs.c2_ips:
        entries.append({
            "indicator": ip, "itype": "ipv4", "tags": tags,
            "confidence": 7, "provider": "apk-analysis-pipeline",
            "description": f"{iocs.family} C2 IP",
            "first_seen": today, "last_seen": today, "sha256": iocs.sha256,
        })
    for url in iocs.telegram_bot_tokens:
        entries.append({
            "indicator": url, "itype": "url", "tags": tags + ["telegram", "c2"],
            "confidence": 9, "provider": "apk-analysis-pipeline",
            "description": f"{iocs.family} Telegram bot C2 dead-drop",
            "first_seen": today, "last_seen": today, "sha256": iocs.sha256,
        })
    return entries


# ---------------------------------------------------------------------------
# YARA validation (compile + self-match)
# ---------------------------------------------------------------------------

def _resolve_yarac():
    """Find yarac on system PATH first, then fall back to bundled Windows binary."""
    found = shutil.which("yarac") or shutil.which("yarac64")
    if found:
        return found
    # Bundled Windows fallback
    for name in ("yarac64.exe", "yarac64", "yarac"):
        p = os.path.join(_SCRIPT_DIR, "yara-master-v4.5.4-win64", name)
        if os.path.isfile(p):
            return p
    return None


def _resolve_yara():
    """Find yara on system PATH first, then fall back to bundled Windows binary."""
    found = shutil.which("yara") or shutil.which("yara64")
    if found:
        return found
    # Bundled Windows fallback
    for name in ("yara64.exe", "yara64", "yara"):
        p = os.path.join(_SCRIPT_DIR, "yara-master-v4.5.4-win64", name)
        if os.path.isfile(p):
            return p
    return None


def _validate_yara_rule(
    rule_text: str, bin_file: Optional[str], logger: logging.Logger,
) -> Dict[str, Any]:
    """
    Validate a YARA rule:
    1. Write to temp file and compile with yarac.
    2. If bin_file provided, scan the sample to confirm self-match.
    Returns {valid, compiles, self_matches, error}.
    """
    result = {"valid": False, "compiles": False, "self_matches": False, "error": ""}

    # Clean markdown fences if LLM wrapped the rule
    cleaned = rule_text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.split("\n")
        lines = [l for l in lines if not l.strip().startswith("```")]
        cleaned = "\n".join(lines).strip()

    yarac = _resolve_yarac()
    yara_exe = _resolve_yara()

    if not yarac and not yara_exe:
        result["error"] = "No YARA compiler found"
        logger.warning("[rule_validator] %s", result["error"])
        # Still consider it provisionally valid if it looks like a rule
        if cleaned.startswith("rule ") and "condition:" in cleaned:
            result["valid"] = True
        return result

    tmpdir = tempfile.mkdtemp(prefix="yara_validate_")
    rule_path = os.path.join(tmpdir, "candidate.yara")
    compiled_path = os.path.join(tmpdir, "candidate.yarc")

    try:
        with open(rule_path, "w", encoding="utf-8") as f:
            f.write(cleaned)

        # 1. Compile / syntax check
        #    Prefer yarac if available; otherwise use `yara <rule> <dummy>` as syntax test.
        if yarac:
            r = subprocess.run(
                [yarac, rule_path, compiled_path],
                capture_output=True, text=True, timeout=15,
            )
            if r.returncode == 0:
                result["compiles"] = True
            else:
                result["error"] = r.stderr.strip()[:300]
                logger.warning("[rule_validator] compile failed: %s", result["error"])
                return result
        elif yara_exe:
            # yara <rule_file> <target_file> — scan rule file against itself as syntax check
            r = subprocess.run(
                [yara_exe, rule_path, rule_path],
                capture_output=True, text=True, timeout=15,
            )
            result["compiles"] = (r.returncode == 0)
            if not result["compiles"]:
                result["error"] = r.stderr.strip()[:300]
                return result

        # 2. Self-match: scan the sample's bin dump with the new rule
        if bin_file and os.path.isfile(bin_file) and yara_exe:
            r = subprocess.run(
                [yara_exe, rule_path, bin_file],
                capture_output=True, text=True, timeout=30,
            )
            if r.stdout.strip():
                result["self_matches"] = True
            else:
                logger.info("[rule_validator] Rule compiles but does NOT match the source sample")

        result["valid"] = result["compiles"]
    except Exception as exc:
        result["error"] = str(exc)[:200]
        logger.warning("[rule_validator] validation error: %s", exc)
    finally:
        try:
            shutil.rmtree(tmpdir, ignore_errors=True)
        except Exception:
            pass

    return result


# ---------------------------------------------------------------------------
# file writers
# ---------------------------------------------------------------------------

def _save_rule(directory: str, filename: str, content: str) -> str:
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


# ---------------------------------------------------------------------------
# find bin dump for self-match
# ---------------------------------------------------------------------------

def _find_bin_dump(apk_path: str) -> Optional[str]:
    """Locate the bin dump file generated by updated_zstatic_apk_dump.py."""
    import hashlib
    base_dir = os.path.dirname(apk_path)
    apk_name = os.path.basename(apk_path)
    bin_folder = os.path.join(base_dir, f"bin_{apk_name}")
    if os.path.isdir(bin_folder):
        for f in os.listdir(bin_folder):
            if f.endswith("_apk_dump.bin"):
                return os.path.join(bin_folder, f)
    # Also check by MD5
    try:
        md5 = hashlib.md5(open(apk_path, "rb").read()).hexdigest()
        candidate = os.path.join(bin_folder, f"{md5}_apk_dump.bin")
        if os.path.isfile(candidate):
            return candidate
    except Exception:
        pass
    return None


def _get_existing_rule_text(iocs: ExtractedIOCs) -> str:
    """Fetch the text of the first existing YARA rule that matched."""
    if not iocs.existing_yara_matches:
        return ""
    rule_name = iocs.existing_yara_matches[0]
    yara_dir = os.path.join(_SCRIPT_DIR, "yara_exports")
    for fname in ("zstatic-apk-sig.yara", "bankbot-static-bridge.yara",
                   "smsthief-static-bridge.yara"):
        fpath = os.path.join(yara_dir, fname)
        if not os.path.isfile(fpath):
            continue
        try:
            content = open(fpath, "r", encoding="utf-8").read()
            pat = r"(rule\s+" + re.escape(rule_name) + r"\b[\s\S]*?\n\})"
            m = re.search(pat, content)
            if m:
                return m.group(1).strip()
        except Exception:
            pass
    return ""


# ---------------------------------------------------------------------------
# main entry point
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
    """
    Stage 6: Generate YARA, Snort, and CIF rules for a confirmed malicious APK.
    Returns a summary dict that gets attached to the verdict JSON.
    """
    from modified_trial8_multiple_models import call_llm

    output: Dict[str, Any] = {
        "yara_rule": None,
        "yara_rule_path": None,
        "yara_validation": None,
        "snort_rules": None,
        "snort_rules_path": None,
        "cif_entries": [],
        "cif_path": None,
        "scored_strings_count": 0,
        "ioc_summary": {},
    }

    # -- 6a: extract IOCs --
    logger.info("[rule_gen] Stage 6a: IOC extraction")
    iocs = extract_iocs(
        apk_facts, evidence_items, clusters, assessments, verdict, logger,
    )
    output["ioc_summary"] = {
        "family": iocs.family,
        "yara_candidates": len(iocs.yara_candidate_strings),
        "c2_domains": len(iocs.c2_domains),
        "c2_ips": len(iocs.c2_ips),
        "telegram_tokens": len(iocs.telegram_bot_tokens),
        "amstrings": len(iocs.amstrings),
    }

    # -- 6b: score strings --
    logger.info("[rule_gen] Stage 6b: string scoring")
    scored = score_candidates(iocs, vt_api_key, logger)
    output["scored_strings_count"] = len(scored)

    date_tag = dt.datetime.utcnow().strftime("%y%m%d")
    sha_short = iocs.sha256[:8]

    # -- 6c: YARA generation --
    if len(scored) >= MIN_SCORED_STRINGS_FOR_YARA:
        logger.info("[rule_gen] Stage 6c: LLM YARA generation")
        existing_rule = _get_existing_rule_text(iocs)
        yara_msgs = _build_yara_prompt(iocs, scored, apk_facts, existing_rule)

        try:
            raw = call_llm(yara_msgs, RULE_GEN_MODEL, logger, llm_client)
            yara_text = _extract_raw_text(raw)
            # Strip markdown fences
            yara_text = yara_text.strip()
            if yara_text.startswith("```"):
                lines = yara_text.split("\n")
                lines = [l for l in lines if not l.strip().startswith("```")]
                yara_text = "\n".join(lines).strip()

            output["yara_rule"] = yara_text

            # -- 6d: validate --
            logger.info("[rule_gen] Stage 6d: YARA validation")
            bin_file = _find_bin_dump(apk_path)
            validation = _validate_yara_rule(yara_text, bin_file, logger)
            output["yara_validation"] = validation

            if validation["compiles"] and validation["self_matches"]:
                fname = f"Android_{iocs.family}_{sha_short}_{date_tag}.yara"
                path = _save_rule(_YARA_DIR, fname, yara_text)
                output["yara_rule_path"] = path
                logger.info("[rule_gen] YARA saved: %s (compiles=%s self_match=%s)",
                            path, validation["compiles"], validation["self_matches"])
            elif validation["compiles"] and not validation["self_matches"]:
                logger.warning(
                    "[rule_gen] YARA compiles but does NOT match the source sample -- "
                    "rule NOT saved. The LLM likely used strings not present in the "
                    "APK dump .bin file."
                )
            else:
                logger.warning("[rule_gen] YARA failed validation: %s",
                               validation.get("error", "unknown"))
        except Exception as exc:
            logger.error("[rule_gen] YARA generation failed: %s", exc)
    else:
        logger.info("[rule_gen] Skipping YARA: only %d scored strings (need %d)",
                     len(scored), MIN_SCORED_STRINGS_FOR_YARA)

    # -- 6c: Snort generation --
    snort_msgs = _build_snort_prompt(iocs)
    if snort_msgs:
        logger.info("[rule_gen] Stage 6c: LLM Snort generation")
        try:
            raw = call_llm(snort_msgs, RULE_GEN_MODEL, logger, llm_client)
            snort_text = _extract_raw_text(raw)
            snort_text = snort_text.strip()
            if snort_text.startswith("```"):
                lines = snort_text.split("\n")
                lines = [l for l in lines if not l.strip().startswith("```")]
                snort_text = "\n".join(lines).strip()
            output["snort_rules"] = snort_text
            fname = f"Android_{iocs.family}_{sha_short}_{date_tag}.rules"
            path = _save_rule(_SNORT_DIR, fname, snort_text)
            output["snort_rules_path"] = path
            logger.info("[rule_gen] Snort saved: %s", path)
        except Exception as exc:
            logger.error("[rule_gen] Snort generation failed: %s", exc)

    # -- 6c: CIF entries (deterministic) --
    cif_entries = _generate_cif_entries(iocs)
    if cif_entries:
        output["cif_entries"] = cif_entries
        cif_fname = f"{date_tag}_{iocs.family}_{sha_short}_blocklist.json"
        cif_path = _save_rule(_CIF_DIR, cif_fname,
                              json.dumps(cif_entries, indent=2, ensure_ascii=False))
        output["cif_path"] = cif_path
        logger.info("[rule_gen] CIF entries: %d indicators saved to %s",
                     len(cif_entries), cif_path)

    logger.info(
        "[rule_gen] Stage 6 complete: YARA=%s Snort=%s CIF=%d",
        "OK" if output["yara_rule"] else "skip",
        "OK" if output["snort_rules"] else "skip",
        len(cif_entries),
    )
    return output
