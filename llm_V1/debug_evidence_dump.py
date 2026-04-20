"""
debug_evidence_dump.py
-----------------------
Runs Stage 0 + Stage 1 (extraction + normalization) of the v2 pipeline
on one or more APKs and prints a structured human-readable evidence dump.

No LLM calls.  No state DB.  Useful for validating new evidence rules
(basic_info, native_libs, package typosquat, etc.) without burning LLM quota.

Usage:
    python debug_evidence_dump.py <apk_or_folder> [--vt-enrich] [--use-smba] [--no-vt-detection]

Output:
    - Per-kind evidence count table
    - Per-cluster summary
    - Highlighted basic_info and native_lib items (new rules validation)
    - JSON dump written to  <sha256[:16]>_evidence_debug.json  next to the APK
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sys
import io
from typing import Any, Dict, List, Optional

# Force UTF-8 stdout/stderr on Windows
if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "buffer"):
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# Make sure llm_V1 is on the path when running from repo root
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)

from DefineRegisterTools_new import get_apk_context, clear_apk_context
from evidence_schema import APKFacts, EvidenceItem
from evidence_normalizer import normalize_all
from behavior_clusterer import build_clusters
from cluster_scorer import score_all_clusters
import ssdeep_similarity
import smba_enrichment
import vt_enrichment

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("evidence_debug")


# ---------------------------------------------------------------------------
# ASCII-safe print helpers
# ---------------------------------------------------------------------------

def _section(title: str) -> None:
    print()
    print("=" * 80)
    print("  " + title)
    print("=" * 80)


def _subsection(title: str) -> None:
    print()
    print("  -- " + title + " --")


def _dir_badge(direction: str, strength: float) -> str:
    return f"[{direction:<9} str={strength:.2f}]"


# ---------------------------------------------------------------------------
# Stage 0 helpers  (mirrors apk_pipeline_v2 without LLM stages)
# ---------------------------------------------------------------------------

def _extract_facts(apk_path: str) -> APKFacts:
    ctx = get_apk_context(apk_path)
    analyzer = ctx.analyzer
    class_scores, class_behavior_tags = analyzer.score_all_classes()
    selected_classes = analyzer.select_and_decompile_classes(class_scores)
    strings_by_class = analyzer.extract_strings_from_scored_classes(list(selected_classes.keys()))

    yara_matches: List[Dict[str, Any]] = []
    high_score_classes = [n for n, s in class_scores.items() if s >= 0.50]
    if high_score_classes:
        try:
            from scan_with_yara import scan_this_bin_file_with_static_yara
            from updated_zstatic_apk_dump import dump_individual_apk
            logger.info("YARA: dumping APK")
            dump_individual_apk(apk_path)
            apk_md5 = hashlib.md5(open(apk_path, "rb").read()).hexdigest()
            bin_folder = os.path.join(
                os.path.dirname(apk_path), f"bin_{os.path.basename(apk_path)}"
            )
            bin_file = os.path.join(bin_folder, f"{apk_md5}_apk_dump.bin")
            if os.path.isfile(bin_file):
                yara_matches = scan_this_bin_file_with_static_yara(bin_file) or []
                logger.info("YARA: %d match(es)", len(yara_matches))
        except Exception as exc:
            logger.warning("YARA scan failed: %s", exc)

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


def _run_ssdeep(apk_path: str) -> List:
    corpus_path = os.path.join(_SCRIPT_DIR, "yara_exports", "ssdeep.json")
    try:
        return ssdeep_similarity.match_against_corpus(apk_path, corpus_path, logger)
    except Exception as exc:
        logger.warning("ssdeep failed: %s", exc)
        return []


def _check_multidex_and_assets(apk_path: str) -> List:
    from apk_pipeline_v2 import _check_multidex_and_assets as _impl
    return _impl(apk_path, logger)


def _check_app_obfuscation_entropy(apk_path: str) -> List:
    from apk_pipeline_v2 import _check_app_obfuscation_entropy as _impl
    return _impl(apk_path, logger)


def _yara_evidence_items(yara_matches) -> List:
    from apk_pipeline_v2 import _yara_evidence_items as _impl
    return _impl(yara_matches)


# ---------------------------------------------------------------------------
# Print helpers
# ---------------------------------------------------------------------------

def _print_evidence_table(items: List[EvidenceItem], title: str) -> None:
    _section(title)
    if not items:
        print("  (none)")
        return
    order = {"malicious": 0, "ambiguous": 1, "benign": 2}
    items_sorted = sorted(items, key=lambda x: (order.get(x.direction, 9), -x.strength))
    for item in items_sorted:
        badge = _dir_badge(item.direction, item.strength)
        val = item.value[:90]
        tags = ", ".join(item.behavior_tags) or "-"
        print(f"  {badge}  [{item.kind}]  {val}")
        print(f"    tags : {tags}")
        print(f"    expl : {item.explanation[:110]}")
        print()


def _highlight_new_rules(items: List[EvidenceItem]) -> None:
    """Print focused summary of the NEW rules (basic_info + native_lib)."""
    _section("NEW RULES VALIDATION  --  basic_info  +  native_lib  highlights")

    basic_info_items = [i for i in items if i.kind == "basic_info"]
    native_lib_items = [i for i in items if i.kind == "native_lib" and i.strength > 0.35]

    _subsection("basic_info evidence (SDK anomalies + package typosquat)")
    if basic_info_items:
        for item in basic_info_items:
            badge = _dir_badge(item.direction, item.strength)
            print(f"    {badge}  {item.value}")
            print(f"      tags : {item.behavior_tags}")
            print(f"      expl : {item.explanation}")
            print()
    else:
        print("    (no basic_info items emitted)")

    _subsection("native_lib evidence  (strength > 0.35)")
    if native_lib_items:
        for item in native_lib_items:
            badge = _dir_badge(item.direction, item.strength)
            print(f"    {badge}  {item.value}")
            print(f"      tags : {item.behavior_tags}")
            print(f"      expl : {item.explanation}")
            print()
    else:
        print("    (no suspicious native_lib items emitted)")


def _print_cluster_summary(clusters: Dict) -> None:
    _section("CLUSTER SUMMARY  (post-scoring)")
    print(f"  {'family':<30}  {'score':>7}  {'mal':>4}  {'amb':>4}  {'ben':>4}  {'chain':>5}  review")
    print(f"  {'-'*30}  {'-'*7}  {'-'*4}  {'-'*4}  {'-'*4}  {'-'*5}  ------")
    for family, cluster in sorted(clusters.items(), key=lambda x: -x[1].preliminary_score):
        score_str = f"{cluster.preliminary_score:.3f}"
        review_str = "NEEDS_LLM" if cluster.needs_llm_review else "skip"
        mal = cluster.malicious_item_count
        amb = cluster.ambiguous_item_count
        ben = cluster.benign_item_count
        chain_len = cluster.max_chain_length
        print(f"  {family:<30}  {score_str:>7}  {mal:>4}  {amb:>4}  {ben:>4}  {chain_len:>5}  {review_str}")
        top = sorted(cluster.evidence_items, key=lambda x: -x.strength)[:2]
        for ei in top:
            print(f"      * [{ei.kind}] {ei.value[:68]}  (str={ei.strength:.2f}, {ei.direction})")
    print()


def _kind_stats(items: List[EvidenceItem]) -> Dict[str, Dict[str, int]]:
    stats: Dict[str, Dict[str, int]] = {}
    for item in items:
        k = item.kind
        d = item.direction
        stats.setdefault(k, {"malicious": 0, "ambiguous": 0, "benign": 0, "total": 0})
        stats[k][d] = stats[k].get(d, 0) + 1
        stats[k]["total"] += 1
    return stats


# ---------------------------------------------------------------------------
# Main analysis function
# ---------------------------------------------------------------------------

def analyse_apk(
    apk_path: str,
    *,
    use_smba: bool = False,
    vt_api_key: Optional[str] = None,
    no_vt_detection: bool = False,
) -> Dict[str, Any]:

    apk_name = os.path.basename(apk_path)
    with open(apk_path, "rb") as f:
        file_data = f.read()
    sha256 = hashlib.sha256(file_data).hexdigest()
    md5 = hashlib.md5(file_data).hexdigest() if use_smba else None

    print()
    print("=" * 80)
    print(f"  APK    : {apk_name}")
    print(f"  SHA256 : {sha256}")
    print(f"  MD5    : {md5}")
    print(f"  Size   : {os.path.getsize(apk_path) // 1024} KB")
    print("=" * 80)

    # Stage 0
    logger.info("Stage 0: extraction")
    apk_facts = _extract_facts(apk_path)

    bi = apk_facts.basic_info
    print(f"\n  Package   : {bi.get('package_name', '?')}")
    print(f"  App name  : {bi.get('app_name', '?')}")
    print(f"  minSdk    : {bi.get('min_sdk', '?')}")
    print(f"  targetSdk : {bi.get('target_sdk', '?')}")
    print(f"  Perms     : {len(apk_facts.permissions)}")
    print(f"  NativeLib : {len(apk_facts.native_libs)}")
    print(f"  YARA hits : {len(apk_facts.yara_matches)}")

    # Stage 0b-0d
    logger.info("Stage 0b: ssdeep")
    ssdeep_items = _run_ssdeep(apk_path)
    logger.info("Stage 0c: multi-DEX / assets")
    multidex_items = _check_multidex_and_assets(apk_path)
    logger.info("Stage 0d: class-name entropy")
    entropy_items = _check_app_obfuscation_entropy(apk_path)

    # Stage 1: normalization
    logger.info("Stage 1: normalization")
    evidence_items = normalize_all(apk_facts)
    evidence_items.extend(_yara_evidence_items(apk_facts.yara_matches))
    evidence_items.extend(ssdeep_items)
    evidence_items.extend(multidex_items)
    evidence_items.extend(entropy_items)

    # Optional enrichment
    if use_smba:
        smba_env = os.path.join(_SCRIPT_DIR, "smba_data_pull", ".env")
        logger.info("SMBA enrichment (md5=%s...)  ", md5[:16])
        smba_items = smba_enrichment.enrich_from_smba(md5, smba_env, logger)
        evidence_items.extend(smba_items)
        logger.info("SMBA: %d item(s) added", len(smba_items))

    if vt_api_key:
        pcap_dir = os.path.join(os.path.dirname(apk_path), "pcaps")
        suffix = " [no-vt-detection]" if no_vt_detection else ""
        logger.info("VT enrichment (sha256=%s%s)...", sha256[:16], suffix)
        vt_items = vt_enrichment.enrich_from_vt(
            sha256, vt_api_key, logger,
            pcap_save_dir=pcap_dir,
            skip_detection=no_vt_detection,
        )
        evidence_items.extend(vt_items)
        logger.info("VT: %d item(s) added", len(vt_items))

    # Stage 2+3
    logger.info("Stage 2: clustering")
    clusters = build_clusters(evidence_items, apk_facts)
    logger.info("Stage 3: pre-scoring")
    clusters, app_pre_score = score_all_clusters(clusters)

    # Output
    _highlight_new_rules(evidence_items)
    _print_cluster_summary(clusters)

    kind_stats = _kind_stats(evidence_items)
    _section("EVIDENCE COUNTS BY KIND")
    print(f"  {'kind':<20}  {'total':>6}  {'malicious':>10}  {'ambiguous':>10}  {'benign':>7}")
    print(f"  {'-'*20}  {'-'*6}  {'-'*10}  {'-'*10}  {'-'*7}")
    for kind, st in sorted(kind_stats.items(), key=lambda x: -x[1]["total"]):
        print(f"  {kind:<20}  {st['total']:>6}  "
              f"{st.get('malicious', 0):>10}  "
              f"{st.get('ambiguous', 0):>10}  "
              f"{st.get('benign', 0):>7}")

    print(f"\n  App pre-score        : {app_pre_score}")
    print(f"  Total evidence items : {len(evidence_items)}")

    _print_evidence_table(
        [i for i in evidence_items if i.kind == "basic_info"],
        "basic_info items detail"
    )
    _print_evidence_table(
        [i for i in evidence_items if i.kind == "native_lib"],
        "native_lib items detail"
    )
    _print_evidence_table(
        [i for i in evidence_items if i.direction == "malicious"],
        "ALL MALICIOUS-direction items"
    )

    # JSON dump
    dump_path = os.path.join(
        os.path.dirname(apk_path),
        f"{sha256[:16]}_evidence_debug.json",
    )
    dump_payload = {
        "apk": apk_name,
        "sha256": sha256,
        "basic_info": apk_facts.basic_info,
        "app_pre_score": app_pre_score,
        "total_evidence_items": len(evidence_items),
        "kind_stats": kind_stats,
        "new_rules": {
            "basic_info_items": [
                {
                    "value": i.value,
                    "direction": i.direction,
                    "strength": i.strength,
                    "tags": i.behavior_tags,
                    "explanation": i.explanation,
                }
                for i in evidence_items if i.kind == "basic_info"
            ],
            "native_lib_items": [
                {
                    "value": i.value,
                    "direction": i.direction,
                    "strength": i.strength,
                    "tags": i.behavior_tags,
                    "explanation": i.explanation,
                }
                for i in evidence_items if i.kind == "native_lib"
            ],
        },
        "clusters": {
            family: {
                "preliminary_score": round(cluster.preliminary_score, 4),
                "needs_llm_review": cluster.needs_llm_review,
                "malicious_items": cluster.malicious_item_count,
                "ambiguous_items": cluster.ambiguous_item_count,
                "benign_items": cluster.benign_item_count,
                "max_chain_length": cluster.max_chain_length,
                "top_evidence": [
                    {
                        "kind": e.kind,
                        "value": e.value[:80],
                        "strength": e.strength,
                        "direction": e.direction,
                    }
                    for e in sorted(cluster.evidence_items, key=lambda x: -x.strength)[:5]
                ],
            }
            for family, cluster in clusters.items()
        },
        "all_malicious_items": [
            {
                "kind": i.kind,
                "value": i.value[:100],
                "strength": i.strength,
                "tags": i.behavior_tags,
                "explanation": i.explanation[:120],
            }
            for i in sorted(evidence_items, key=lambda x: -x.strength)
            if i.direction == "malicious"
        ],
    }
    with open(dump_path, "w", encoding="utf-8") as f:
        json.dump(dump_payload, f, indent=2, ensure_ascii=False)
    print(f"\n  JSON dump: {dump_path}")

    clear_apk_context(apk_path)
    return dump_payload


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Dump v2 evidence (Stages 0-3) without any LLM calls."
    )
    ap.add_argument("target", help="APK file or folder of APKs")
    ap.add_argument("--use-smba", action="store_true", default=False,
                    help="Enrich with SMBA sandbox data")
    ap.add_argument("--vt-enrich", action="store_true", default=False,
                    help="Enrich with VT behaviour data (auto-loads premium key)")
    ap.add_argument("--no-vt-detection", action="store_true", default=False,
                    help="Skip vt_detection/vt_threat_label items")
    args = ap.parse_args()

    vt_api_key: Optional[str] = None
    if args.vt_enrich:
        vt_config_path = vt_enrichment.resolve_vt_config_path()
        vt_api_key = vt_enrichment.load_vt_api_key_from_config(vt_config_path)
        if vt_api_key:
            logger.info("VT premium key loaded from %s", vt_config_path)
        else:
            logger.warning("--vt-enrich: no premium key found in %s", vt_config_path)

    target = args.target
    apk_paths: List[str] = []
    if os.path.isfile(target):
        apk_paths = [target]
    elif os.path.isdir(target):
        for f in sorted(os.listdir(target)):
            fp = os.path.join(target, f)
            if not os.path.isfile(fp):
                continue
            try:
                with open(fp, "rb") as fh:
                    magic = fh.read(4)
                if magic == b"PK\x03\x04":
                    apk_paths.append(fp)
            except Exception:
                pass
    else:
        print(f"ERROR: {target!r} is not a file or directory", file=sys.stderr)
        return 1

    if not apk_paths:
        print(f"No APK files found in {target!r}", file=sys.stderr)
        return 1

    logger.info("Found %d APK(s) to analyse", len(apk_paths))

    results = []
    for apk_path in apk_paths:
        try:
            result = analyse_apk(
                apk_path,
                use_smba=args.use_smba,
                vt_api_key=vt_api_key,
                no_vt_detection=args.no_vt_detection,
            )
            results.append(result)
        except Exception as exc:
            logger.exception("Failed to analyse %s: %s", apk_path, exc)

    print()
    print("=" * 80)
    print(f"  Done. Analysed {len(results)}/{len(apk_paths)} APK(s).")
    print("=" * 80)
    return 0


if __name__ == "__main__":
    sys.exit(main())