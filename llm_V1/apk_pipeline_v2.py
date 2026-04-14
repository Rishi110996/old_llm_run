"""
apk_pipeline_v2.py
------------------
Full analysis pipeline for one APK -- 6 stages, no tool registry.

Stage 0  Full deterministic extraction via APKContext
Stage 1  Evidence normalization (rule tables)
Stage 2  Behavior clustering + cross-source corroboration
Stage 3  Deterministic pre-scoring
Stage 4  Parallel LLM cluster review (claude-4-sonnet, needs_llm_review only)
Stage 5  Final synthesis verdict (claude-4-sonnet)

Entry point:  run(apk_path, logger, llm_client) -> dict  (same schema as v1)
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional

from openai import OpenAI

from DefineRegisterTools_new import get_apk_context
from evidence_schema import APKFacts, ClusterAssessment
from evidence_normalizer import normalize_all
from behavior_clusterer import build_clusters
from cluster_scorer import score_all_clusters
from llm_cluster_reviewer import review_clusters
import ssdeep_similarity
import smba_enrichment
import vt_enrichment

# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------

FINAL_MODEL = "claude-4-sonnet"
MAX_IOC_OUTPUT = 80     # cap on IOCs returned in final verdict


# ---------------------------------------------------------------------------
# Stage 0: full deterministic extraction
# ---------------------------------------------------------------------------

def _extract_facts(apk_path: str, logger: logging.Logger) -> APKFacts:
    ctx = get_apk_context(apk_path)
    analyzer = ctx.analyzer

    logger.info("[stage0] scoring all classes (Phase 1+2: no decompile yet)")
    class_scores, class_behavior_tags = analyzer.score_all_classes()
    logger.info("[stage0] scored %d non-safe classes", len(class_scores))

    logger.info("[stage0] budget-controlled decompilation (budget=55 KB)")
    selected_classes = analyzer.select_and_decompile_classes(class_scores)
    logger.info("[stage0] decompiled %d classes", len(selected_classes))

    logger.info("[stage0] extracting strings from selected classes")
    strings_by_class = analyzer.extract_strings_from_scored_classes(list(selected_classes.keys()))

    # Conditionally run YARA: only if any class has a score >= 0.5 or any
    # known C2/dynamic-loading string was found.  This avoids the expensive
    # dump_individual_apk() call on clean APKs.
    yara_matches: List[Dict[str, Any]] = []
    high_score_classes = [n for n, s in class_scores.items() if s >= 0.50]
    if high_score_classes:
        try:
            from scan_with_yara import scan_this_bin_file_with_static_yara
            from updated_zstatic_apk_dump import dump_individual_apk
            import hashlib

            logger.info("[stage0] YARA: dumping APK (high-score classes present)")
            dump_individual_apk(apk_path)
            apk_md5 = hashlib.md5(open(apk_path, "rb").read()).hexdigest()
            bin_folder = os.path.join(
                os.path.dirname(apk_path),
                f"bin_{os.path.basename(apk_path)}",
            )
            bin_file = os.path.join(bin_folder, f"{apk_md5}_apk_dump.bin")
            if os.path.isfile(bin_file):
                yara_matches = scan_this_bin_file_with_static_yara(bin_file) or []
                logger.info("[stage0] YARA: %d match(es)", len(yara_matches))
        except Exception as exc:
            logger.warning("[stage0] YARA scan failed: %s", exc)
    else:
        logger.info("[stage0] YARA skipped (no high-score classes)")

    return APKFacts(
        apk_path=apk_path,
        basic_info=ctx.get_basic_info(),
        permissions=ctx.get_permissions() or [],
        components=ctx.get_components() or {},
        certificates=ctx.get_certificates() or [],
        native_libs=ctx.get_native_libs() or [],
        strings=strings_by_class,
        classes=selected_classes,
        class_api_scores=class_scores,
        class_behavior_tags=class_behavior_tags,
        yara_matches=yara_matches,
    )


def _run_ssdeep(apk_path: str, logger: logging.Logger) -> List:
    """Compute ssdeep for the APK and compare against the corpus. Returns EvidenceItems."""
    corpus_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "yara_exports", "ssdeep.json")
    try:
        return ssdeep_similarity.match_against_corpus(apk_path, corpus_path, logger)
    except Exception as exc:
        logger.warning("[stage0] ssdeep comparison failed: %s", exc)
        return []


def _check_multidex_and_assets(apk_path: str, logger: logging.Logger) -> List:
    """Check for multi-DEX files and embedded DEX/APK/JAR payloads in APK assets."""
    from evidence_schema import EvidenceItem, make_evidence_id
    _PAYLOAD_EXTS = {".dex", ".apk", ".jar", ".odex"}
    items: List = []
    try:
        apk = get_apk_context(apk_path).apk

        # --- Multi-DEX: classes2.dex, classes3.dex, ... ---
        all_dex = list(apk.get_all_dex())
        if len(all_dex) > 1:
            items.append(EvidenceItem(
                id=make_evidence_id("class", "multi_dex", "apk_structure"),
                kind="class",
                value=f"multi-DEX APK ({len(all_dex)} DEX files)",
                source_location="apk_structure",
                direction="ambiguous",
                strength=0.65,
                behavior_tags=["dynamic_code_loading", "anti_analysis"],
                explanation=(
                    f"APK contains {len(all_dex)} DEX files (classes.dex + classes2.dex...); "
                    "common payload-hiding technique in droppers and banking trojans"
                ),
                benign_alternatives="Large apps exceeding the 64K method limit, multi-module build toolchains",
            ))

        # --- Embedded DEX/APK/JAR in assets or non-lib paths ---
        for fname in apk.get_files():
            fname_lower = fname.lower()
            _, ext = os.path.splitext(fname_lower)
            if ext not in _PAYLOAD_EXTS:
                continue
            # Skip the normal top-level DEX files and native libraries
            if fname_lower.startswith("classes") and ext == ".dex":
                continue
            if fname_lower.startswith("lib/"):
                continue
            kind_label = (
                "DEX bytecode payload" if ext == ".dex"
                else "embedded APK" if ext == ".apk"
                else "embedded JAR"
            )
            items.append(EvidenceItem(
                id=make_evidence_id("class", f"asset:{fname}", "apk_structure"),
                kind="class",
                value=f"embedded {kind_label}: {fname}",
                source_location="apk_structure",
                direction="malicious",
                strength=0.90,
                behavior_tags=["dynamic_code_loading"],
                explanation=(
                    f"APK asset '{fname}' is an embedded {kind_label}; "
                    "classic dropper / staged-payload delivery -- secondary code is loaded and executed at runtime"
                ),
                benign_alternatives="Cordova/React-Native bundle assets, auto-update frameworks (rare; usually signed separately)",
            ))
    except Exception as exc:
        logger.warning("[stage0] multi-DEX/asset check failed: %s", exc)
    return items


def _check_app_obfuscation_entropy(apk_path: str, logger: logging.Logger) -> List:
    """Compute app-level class-name entropy as a DexGuard/Allatori obfuscation signal."""
    from evidence_schema import EvidenceItem, make_evidence_id
    items: List = []
    try:
        ctx = get_apk_context(apk_path)
        analyzer = ctx.analyzer
        total = 0
        short = 0
        for cls_obj in analyzer.analysis.get_classes():
            cls_name = cls_obj.name
            if cls_name.startswith(analyzer.SAFE_CLASSES):
                continue
            total += 1
            leaf = cls_name.split("/")[-1].rstrip(";")
            if len(leaf) <= 2:
                short += 1
        if total == 0:
            return items
        ratio = short / total
        if ratio >= 0.70:
            strength = round(min(0.90, 0.60 + ratio * 0.40), 2)
            items.append(EvidenceItem(
                id=make_evidence_id("class", "app_class_entropy", "apk_structure"),
                kind="class",
                value=f"heavy class-name obfuscation: {ratio:.0%} short names ({short}/{total} user classes)",
                source_location="apk_structure",
                direction="malicious",
                strength=strength,
                behavior_tags=["anti_analysis"],
                explanation=(
                    f"{ratio:.0%} of user-defined class names are <=2 chars -- "
                    "signature of DexGuard/Allatori/commercial obfuscator used to hinder static analysis"
                ),
                benign_alternatives="Aggressive ProGuard minification in release builds can produce similar ratios",
            ))
        elif ratio >= 0.50:
            items.append(EvidenceItem(
                id=make_evidence_id("class", "app_class_entropy", "apk_structure"),
                kind="class",
                value=f"moderate class-name obfuscation: {ratio:.0%} short names ({short}/{total} user classes)",
                source_location="apk_structure",
                direction="ambiguous",
                strength=0.55,
                behavior_tags=["anti_analysis"],
                explanation=(
                    f"{ratio:.0%} of user-defined class names are <=2 chars -- "
                    "moderate obfuscation consistent with ProGuard minification or commercial obfuscator"
                ),
                benign_alternatives="Production apps commonly use ProGuard; this alone is not malicious",
            ))
    except Exception as exc:
        logger.warning("[stage0] class entropy check failed: %s", exc)
    return items


# ---------------------------------------------------------------------------
# YARA -> evidence items
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# YARA rule name -> behavior family mapping
# Rule names follow the convention: Platform_Category_Family_ID
# We match against lowercase rule name tokens (first match wins per entry).
# Each entry: (keyword, behavior_tags, strength, direction)
# ---------------------------------------------------------------------------
_YARA_CATEGORY_MAP = [
    # --- Benign ---
    ("clean",          ["normal_app_behavior"],                          0.70, "benign"),
    # --- Credential theft / banking ---
    ("pws",            ["credential_theft"],                             1.00, "malicious"),
    ("banker",         ["overlay_fraud", "credential_theft", "c2_networking"], 1.00, "malicious"),
    ("banking",        ["overlay_fraud", "credential_theft", "c2_networking"], 1.00, "malicious"),
    ("stealer",        ["credential_theft", "data_exfiltration"],        1.00, "malicious"),
    ("keylog",         ["credential_theft"],                             1.00, "malicious"),
    ("phish",          ["overlay_fraud", "credential_theft"],            1.00, "malicious"),
    # --- Spyware / RAT ---
    ("spyware",        ["data_exfiltration", "call_interception"],       1.00, "malicious"),
    ("rat",            ["c2_networking", "data_exfiltration"],           1.00, "malicious"),
    # --- Dropper / downloader / dynamic loading ---
    ("dropper",        ["dynamic_code_loading", "persistence"],          1.00, "malicious"),
    ("downloader",     ["dynamic_code_loading"],                         0.90, "malicious"),
    ("loader",         ["dynamic_code_loading"],                         0.90, "malicious"),
    ("inject",         ["dynamic_code_loading", "privilege_escalation"], 0.95, "malicious"),
    # --- Backdoor / C2 ---
    ("backdoor",       ["c2_networking"],                                1.00, "malicious"),
    ("c2",             ["c2_networking"],                                1.00, "malicious"),
    ("bot",            ["c2_networking", "persistence"],                 0.90, "malicious"),
    # --- Ransomware / locker ---
    ("ransom",         ["data_exfiltration", "persistence"],             1.00, "malicious"),
    ("locker",         ["persistence", "privilege_escalation"],          1.00, "malicious"),
    # --- Privilege escalation / root / exploit ---
    ("exploit",        ["privilege_escalation"],                         1.00, "malicious"),
    ("hacktool",       ["privilege_escalation"],                         0.95, "malicious"),
    ("rootkit",        ["privilege_escalation"],                         1.00, "malicious"),
    # --- Anti-analysis / obfuscation / packer ---
    ("packer",         ["anti_analysis"],                                0.90, "malicious"),
    ("antisandbox",    ["anti_analysis"],                                0.95, "malicious"),
    ("antivm",         ["anti_analysis"],                                0.95, "malicious"),
    # --- Ad fraud / PUA ---
    ("adfraud",        ["ad_analytics_only"],                            0.70, "ambiguous"),
    ("pua",            ["ad_analytics_only"],                            0.60, "ambiguous"),
    ("adware",         ["ad_analytics_only"],                            0.70, "ambiguous"),
    # --- Generic trojan (broad -- comes last to not shadow specific ones) ---
    ("trojan",         ["c2_networking", "data_exfiltration"],           0.85, "malicious"),
    ("spy",            ["data_exfiltration", "call_interception"],       0.90, "malicious"),
]


def _yara_tags_for_rule(rule_name: str):
    """Return (behavior_tags, strength, direction) for a YARA rule name."""
    low = rule_name.lower()
    for keyword, tags, strength, direction in _YARA_CATEGORY_MAP:
        if keyword in low:
            return tags, strength, direction
    # fallback: unrecognised rule, treat as generic malicious signal
    return ["anti_analysis"], 0.85, "malicious"


def _yara_evidence_items(yara_matches: List[Dict[str, Any]]):
    """Convert YARA hits to EvidenceItems with per-rule family mapping."""
    from evidence_schema import EvidenceItem, make_evidence_id
    items = []
    for hit in yara_matches:
        rule = str(hit.get("detection_rule", hit.get("rule", "unknown")))
        tags, strength, direction = _yara_tags_for_rule(rule)
        if direction == "benign":
            explanation = f"Known-clean YARA rule matched: {rule}"
            benign_alts = "Rule is explicitly classified as clean/benign by YARA signature"
        else:
            explanation = f"YARA rule matched: {rule}"
            benign_alts = "None -- a named YARA signature match is authoritative"
        items.append(EvidenceItem(
            id=make_evidence_id("yara", rule, "yara"),
            kind="yara",
            value=rule,
            source_location="yara",
            direction=direction,
            strength=strength,
            behavior_tags=tags,
            explanation=explanation,
            benign_alternatives=benign_alts,
        ))
    return items


# ---------------------------------------------------------------------------
# Stage 5: final synthesis verdict
# ---------------------------------------------------------------------------

def _build_final_prompt(
    apk_facts: APKFacts,
    assessments: Dict[str, ClusterAssessment],
    app_pre_score: int,
) -> List[Dict[str, str]]:
    bi = apk_facts.basic_info

    all_iocs: List[str] = []
    cluster_summaries: Dict[str, Any] = {}
    for family, assessment in assessments.items():
        cluster_summaries[family] = {
            "verdict":    assessment.verdict,
            "confidence": round(assessment.confidence, 2),
            "reasoning":  assessment.reasoning,
        }
        all_iocs.extend(assessment.iocs)

    cross_cluster = _infer_cross_cluster(assessments)

    user_content = {
        "apk_identity": {
            "app_name":    bi.get("app_name",    "unknown"),
            "package":     bi.get("package_name","unknown"),
            "min_sdk":     bi.get("min_sdk",     "?"),
            "target_sdk":  bi.get("target_sdk",  "?"),
            "main_activity": bi.get("main_activity", ""),
            "certs":       apk_facts.certificates,
            "components_summary": {
                k: len(v) if isinstance(v, dict) else v
                for k, v in apk_facts.components.items()
            },
            "native_libs": apk_facts.native_libs,
        },
        "permissions": apk_facts.permissions,
        "cluster_assessments": cluster_summaries,
        "cross_cluster_patterns": cross_cluster,
        "app_pre_score": app_pre_score,
        "extracted_iocs": sorted(set(all_iocs))[:MAX_IOC_OUTPUT],
    }

    system_msg = (
        "You are a senior Android malware analyst making a final classification decision.\n"
        "You are provided with:\n"
        "  - APK identity (package, app name, certificates, components)\n"
        "  - Per-behavior-family cluster assessments produced by an LLM reviewer\n"
        "  - Cross-cluster patterns (combinations that are typical of known malware families)\n"
        "  - A deterministic pre-score\n"
        "  - All extracted IOCs\n\n"
        "Rules:\n"
        "  Mark Malicious ONLY if one or more cluster assessments are 'malicious' with confidence >= 0.70,\n"
        "    OR the cross_cluster_patterns field shows a known malware combination.\n"
        "  Mark Suspicious if clusters are 'ambiguous' with no 'malicious' verdict, "
        "or malicious confidence < 0.70.\n"
        "  Mark Clean if all clusters are 'benign' or below meaningful threshold.\n"
        "  Do NOT invent evidence. The cluster assessments are your only source of truth.\n\n"
        "Return STRICT JSON only -- no markdown, no extra keys:\n"
        "{\n"
        "  \"Malicious\": 0|1,\n"
        "  \"Suspicious\": 0|1,\n"
        "  \"Clean\": 0|1,\n"
        "  \"Risk-Score\": 0-100,\n"
        "  \"Summary\": \"2-3 sentences: what the APK does, why this verdict, key evidence\",\n"
        "  \"IOCs\": [\"concrete domains/IPs/class names/strings confirmed as malicious\"]\n"
        "}\n"
        "Exactly one of Malicious/Suspicious/Clean must be 1."
    )

    return [
        {"role": "system", "content": system_msg},
        {"role": "user",   "content": json.dumps(user_content, indent=2, ensure_ascii=False)},
    ]


def _infer_cross_cluster(assessments: Dict[str, ClusterAssessment]) -> List[str]:
    """
    Look for known dangerous combination patterns across cluster verdicts.
    Returns list of human-readable pattern descriptions.
    """
    malicious = {f for f, a in assessments.items() if a.verdict == "malicious"}
    patterns: List[str] = []

    # Classic SMS trojan
    if malicious & {"sms_abuse", "c2_networking"}:
        patterns.append("SMS trojan pattern: SMS abuse + C2 networking active together")
    # Overlay banking trojan
    if malicious & {"overlay_fraud", "accessibility_abuse"}:
        patterns.append("Banking trojan pattern: overlay fraud + accessibility abuse")
    # Dropper
    if malicious & {"dynamic_code_loading", "anti_analysis"}:
        patterns.append("Dropper pattern: dynamic code loading + anti-analysis")
    # Spyware
    if malicious & {"data_exfiltration", "c2_networking"}:
        patterns.append("Spyware pattern: data exfiltration + C2 networking")
    # Root exploit
    if malicious & {"privilege_escalation"}:
        patterns.append("Root exploit: privilege escalation detected")

    return patterns


# ---------------------------------------------------------------------------
# pipeline entry point
# ---------------------------------------------------------------------------

def run(
    apk_path: str,
    logger: logging.Logger,
    llm_client: OpenAI,
    *,
    use_smba: bool = False,
    smba_jsessionid: str = "",
    vt_api_key: Optional[str] = None,
    no_vt_detection: bool = False,
) -> Dict[str, Any]:
    """
    Run the v2 pipeline.  Returns a verdict dict matching the v1 schema:
      {Malicious: 0|1, Suspicious: 0|1, Clean: 0|1,
       Risk-Score: int, Summary: str, IOCs: [str]}

    Optional enrichment flags:
      use_smba         -- query Zscaler SMBA sandbox (requires smba_data_pull/.env)
      vt_api_key       -- query VT behaviours endpoint (falls back to config.yaml key if None)
      no_vt_detection  -- skip vt_detection / vt_threat_label items; keeps traffic/PCAP.
                         Use when batch-analysing VT-sourced samples where detection is known.
    """
    from modified_trial8_multiple_models import call_llm, normalize_final_verdict, safe_log

    # -- Stage 0: extraction ------------------------------------------------
    logger.info("[pipeline_v2] Stage 0: extraction")
    apk_facts = _extract_facts(apk_path, logger)

    # -- Stage 0b: ssdeep corpus comparison --------------------------------
    logger.info("[pipeline_v2] Stage 0b: ssdeep similarity")
    ssdeep_items = _run_ssdeep(apk_path, logger)
    logger.info("[pipeline_v2] ssdeep: %d evidence item(s)", len(ssdeep_items))

    # -- Stage 0c: multi-DEX / embedded asset detection --------------------
    logger.info("[pipeline_v2] Stage 0c: multi-DEX / embedded asset detection")
    multidex_items = _check_multidex_and_assets(apk_path, logger)
    logger.info("[pipeline_v2] multi-DEX/asset: %d evidence item(s)", len(multidex_items))

    # -- Stage 0d: app-level class-name entropy (obfuscation depth) --------
    logger.info("[pipeline_v2] Stage 0d: class-name entropy")
    entropy_items = _check_app_obfuscation_entropy(apk_path, logger)
    logger.info("[pipeline_v2] entropy: %d evidence item(s)", len(entropy_items))

    # -- Stage 1: evidence normalization -----------------------------------
    logger.info("[pipeline_v2] Stage 1: normalization")
    evidence_items = normalize_all(apk_facts)

    # Include YARA items
    evidence_items.extend(_yara_evidence_items(apk_facts.yara_matches))
    # Include ssdeep items
    evidence_items.extend(ssdeep_items)
    # Include multi-DEX / embedded asset items
    evidence_items.extend(multidex_items)
    # Include app-level obfuscation entropy items
    evidence_items.extend(entropy_items)

    logger.info("[pipeline_v2] %d evidence items after normalization", len(evidence_items))

    # -- Stage 1b/c (optional): sandbox enrichment ------------------------
    # NOTE: sha256 is only computed when at least one enrichment source is active.
    # VT runs only when vt_api_key was explicitly provided by the caller
    # (set via --vt-enrich flag in the CLI); it does NOT auto-load from config here.
    _needs_sha256 = use_smba or vt_api_key is not None
    if _needs_sha256:
        import hashlib
        _sha256 = hashlib.sha256(open(apk_path, "rb").read()).hexdigest()
    else:
        _sha256 = None

    if use_smba and _sha256:
        smba_env = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "smba_data_pull", ".env")
        logger.info("[pipeline_v2] Stage 1b: SMBA enrichment (sha256=%s...)", _sha256[:16])
        smba_items = smba_enrichment.enrich_from_smba(_sha256, smba_env, logger, jsessionid_override=smba_jsessionid)
        evidence_items.extend(smba_items)
        logger.info("[pipeline_v2] SMBA: %d item(s) added", len(smba_items))

    if vt_api_key is not None and _sha256:
        logger.info("[pipeline_v2] Stage 1c: VT behaviour enrichment (sha256=%s%s)\u2026",
                    _sha256[:16], "  [no-vt-detection]" if no_vt_detection else "")
        pcap_dir = os.path.join(os.path.dirname(os.path.abspath(apk_path)), "pcaps")
        vt_items = vt_enrichment.enrich_from_vt(
            _sha256, vt_api_key, logger,
            pcap_save_dir=pcap_dir,
            skip_detection=no_vt_detection,
        )
        evidence_items.extend(vt_items)
        logger.info("[pipeline_v2] VT: %d item(s) added", len(vt_items))

    # -- Stage 2: clustering ------------------------------------------------
    logger.info("[pipeline_v2] Stage 2: clustering")
    clusters = build_clusters(evidence_items, apk_facts)
    logger.info("[pipeline_v2] %d active cluster(s): %s", len(clusters), list(clusters.keys()))

    # -- Stage 3: pre-scoring -----------------------------------------------
    logger.info("[pipeline_v2] Stage 3: pre-scoring")
    clusters, app_pre_score = score_all_clusters(clusters)
    logger.info("[pipeline_v2] app pre-score: %d", app_pre_score)
    for fam, cl in clusters.items():
        logger.info(
            "[pipeline_v2]   %-28s score=%.3f  review=%s",
            fam, cl.preliminary_score, cl.needs_llm_review,
        )

    # -- Stage 4: parallel LLM cluster review ------------------------------
    logger.info("[pipeline_v2] Stage 4: LLM cluster review")

    def _call_llm_bound(messages, model, _logger):
        return call_llm(messages, model, _logger, llm_client)

    assessments = review_clusters(clusters, apk_facts, _call_llm_bound, logger)

    # -- Stage 5: final synthesis -------------------------------------------
    logger.info("[pipeline_v2] Stage 5: final synthesis verdict")
    final_messages = _build_final_prompt(apk_facts, assessments, app_pre_score)
    safe_log(logger, json.dumps({"stage5_input": {
        "cluster_summaries": {f: {"verdict": a.verdict, "confidence": a.confidence}
                               for f, a in assessments.items()},
        "app_pre_score": app_pre_score,
    }}, indent=2, ensure_ascii=False))

    raw_verdict = call_llm(final_messages, FINAL_MODEL, logger, llm_client)
    normalized = normalize_final_verdict(raw_verdict, logger)
    if normalized is None:
        raise RuntimeError("Final LLM verdict unavailable or invalid after retries")

    logger.info("[pipeline_v2] DONE -- %s  risk=%d",
                normalized.get("Malicious") and "MALICIOUS" or
                normalized.get("Suspicious") and "SUSPICIOUS" or "CLEAN",
                normalized.get("Risk-Score", 0))

    return normalized
