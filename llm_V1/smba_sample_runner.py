#!/usr/bin/env python3
"""
smba_sample_runner.py
---------------------
Fetch new SMBA sample runs, extract APKs, and run the APK analyzer.

Scans an SMBA output directory for smba_run_* and smba_susp_* folders,
extracts APKs from artifacts/*.zip (password: infected), and launches
the APK analysis pipeline on each batch.

Usage:
    python smba_sample_runner.py /path/to/smba/output/llm_sample_downloads

    # With VT enrichment
    python smba_sample_runner.py /path/to/smba/output/llm_sample_downloads --vt-enrich

    # Specify report output directory
    python smba_sample_runner.py /path/to/smba/output/llm_sample_downloads --report-base /path/to/reports
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

SCRIPT_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
STATE_FILE = "smba_processed_runs.json"
ZIP_PASSWORD = b"infected"
ANALYZER_SCRIPT = str(SCRIPT_DIR / "modified_trial8_multiple_models.py")


# ---------------------------------------------------------------------------
# State tracking - remember which runs we already processed
# ---------------------------------------------------------------------------

def _load_state(state_path: Path) -> Dict:
    if state_path.exists():
        try:
            return json.loads(state_path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"processed_runs": {}}


def _save_state(state_path: Path, state: Dict) -> None:
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(
        json.dumps(state, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Discovery - find SMBA run folders and their zip files
# ---------------------------------------------------------------------------

def discover_smba_runs(smba_dir: Path) -> List[Dict]:
    """Find all smba_run_* and smba_susp_* folders with extractable zips."""
    runs = []

    if not smba_dir.is_dir():
        print(f"[-] SMBA directory not found: {smba_dir}")
        return runs

    for entry in sorted(smba_dir.iterdir()):
        if not entry.is_dir():
            continue
        name = entry.name
        if not (name.startswith("smba_run_") or name.startswith("smba_susp_")):
            continue

        # Find all zip files in artifacts/ subdirectories
        zip_files = []

        # Pattern 1: smba_run_*/subcategory/artifacts/*.zip
        for subdir in sorted(entry.iterdir()):
            if not subdir.is_dir():
                continue
            artifacts_dir = subdir / "artifacts"
            if artifacts_dir.is_dir():
                for zf in sorted(artifacts_dir.glob("*.zip")):
                    if zf.stat().st_size > 0:
                        zip_files.append({
                            "zip_path": str(zf),
                            "category": subdir.name,
                            "size_bytes": zf.stat().st_size,
                        })
                    else:
                        print(f"[!] Skipping empty zip: {zf}")

        # Pattern 2: smba_susp_*/artifacts/*.zip (flat)
        flat_artifacts = entry / "artifacts"
        if flat_artifacts.is_dir():
            for zf in sorted(flat_artifacts.glob("*.zip")):
                if zf.stat().st_size > 0:
                    # Avoid duplicates if already found via subcategory
                    zf_str = str(zf)
                    if not any(z["zip_path"] == zf_str for z in zip_files):
                        zip_files.append({
                            "zip_path": zf_str,
                            "category": "flat",
                            "size_bytes": zf.stat().st_size,
                        })
                else:
                    print(f"[!] Skipping empty zip: {zf}")

        if zip_files:
            runs.append({
                "run_name": name,
                "run_path": str(entry),
                "zip_files": zip_files,
                "total_zips": len(zip_files),
            })

    return runs


# ---------------------------------------------------------------------------
# Extraction - unzip APKs from sample zips
# ---------------------------------------------------------------------------

def extract_apks(zip_info: Dict, extract_dir: Path) -> Optional[Path]:
    """Extract APKs from a zip file. Returns the extraction directory."""
    zip_path = Path(zip_info["zip_path"])
    extract_dir.mkdir(parents=True, exist_ok=True)

    try:
        with zipfile.ZipFile(str(zip_path), "r") as zf:
            zf.extractall(path=str(extract_dir), pwd=ZIP_PASSWORD)

        apks = list(extract_dir.rglob("*.apk"))
        print(f"[+] Extracted {len(apks)} APK(s) from {zip_path.name} -> {extract_dir}")
        return extract_dir if apks else None

    except zipfile.BadZipFile:
        print(f"[-] Bad zip file: {zip_path}")
        return None
    except RuntimeError as e:
        print(f"[-] Extraction failed for {zip_path}: {e}")
        return None
    except Exception as e:
        print(f"[-] Unexpected error extracting {zip_path}: {e}")
        return None


def collect_apk_dirs(base: Path) -> List[Path]:
    """Find all directories containing APK files."""
    apk_dirs = set()
    for apk_file in base.rglob("*.apk"):
        apk_dirs.add(apk_file.parent)
    return sorted(apk_dirs)


# ---------------------------------------------------------------------------
# Analysis - run the APK analyzer
# ---------------------------------------------------------------------------

def run_analysis(
    apk_dir: Path, report_dir: Path, *,
    vt_enrich: bool = False, use_smba: bool = False,
    extra_args: Optional[List[str]] = None,
) -> int:
    """Run modified_trial8_multiple_models.py on a directory of APKs."""
    cmd = [
        sys.executable, ANALYZER_SCRIPT,
        str(apk_dir.resolve()),
        "--report-dir", str(report_dir.resolve()),
    ]
    if vt_enrich:
        cmd.append("--vt-enrich")
    if use_smba:
        cmd.append("--use-smba")
    if extra_args:
        cmd.extend(extra_args)

    print(f"\n[*] Running analysis: {' '.join(cmd)}")
    print(f"    APK dir:    {apk_dir}")
    print(f"    Report dir: {report_dir}")

    try:
        result = subprocess.run(cmd, cwd=str(SCRIPT_DIR))
        return result.returncode
    except Exception as e:
        print(f"[-] Analysis failed: {e}")
        return 1


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def process_smba_runs(
    smba_dir: Path, report_base: Path, *,
    vt_enrich: bool = False, use_smba: bool = False,
    force: bool = False, extra_args: Optional[List[str]] = None,
) -> Dict:
    """Main orchestrator: discover -> extract -> analyze new SMBA runs."""
    state_path = report_base / STATE_FILE
    state = _load_state(state_path)
    processed = state.get("processed_runs", {})

    runs = discover_smba_runs(smba_dir)
    if not runs:
        print("[*] No SMBA runs with valid zip files found.")
        return {"new_runs": 0, "results": []}

    new_runs = [r for r in runs if force or r["run_name"] not in processed]
    if not new_runs:
        print(f"[*] All {len(runs)} run(s) already processed. Use --force to re-run.")
        return {"new_runs": 0, "results": []}

    print(f"[*] Found {len(new_runs)} new run(s) to process out of {len(runs)} total\n")
    results = []

    for run in new_runs:
        run_name = run["run_name"]
        print("=" * 80)
        print(f"[*] Processing: {run_name} ({run['total_zips']} zips)")
        print("=" * 80)

        extract_base = report_base / run_name / "extracted_samples"
        total_apks = 0

        for zip_info in run["zip_files"]:
            category = zip_info.get("category", "unknown")
            extracted = extract_apks(zip_info, extract_base / category)
            if extracted:
                total_apks += len(list(extracted.rglob("*.apk")))

        if total_apks == 0:
            print(f"[!] No APKs found in {run_name}, skipping")
            processed[run_name] = {
                "processed_at": datetime.now(timezone.utc).isoformat(),
                "status": "no_apks", "total_apks": 0,
            }
            _save_state(state_path, state)
            continue

        print(f"[+] Total APKs extracted: {total_apks}")
        apk_dirs = collect_apk_dirs(extract_base)
        run_report_dir = report_base / run_name / "reports"
        run_report_dir.mkdir(parents=True, exist_ok=True)
        run_result = {"run_name": run_name, "total_apks": total_apks, "categories": [], "exit_codes": []}

        for apk_dir in apk_dirs:
            cat_name = apk_dir.relative_to(extract_base).parts[0] if apk_dir != extract_base else "root"
            cat_report_dir = run_report_dir / cat_name
            cat_report_dir.mkdir(parents=True, exist_ok=True)
            apk_count = len(list(apk_dir.glob("*.apk")))
            print(f"\n[*] Category: {cat_name} ({apk_count} APKs)")

            rc = run_analysis(apk_dir, cat_report_dir, vt_enrich=vt_enrich, use_smba=use_smba, extra_args=extra_args)
            run_result["categories"].append({"category": cat_name, "apk_count": apk_count, "report_dir": str(cat_report_dir), "exit_code": rc})
            run_result["exit_codes"].append(rc)

        processed[run_name] = {
            "processed_at": datetime.now(timezone.utc).isoformat(),
            "status": "done" if all(rc == 0 for rc in run_result["exit_codes"]) else "partial",
            "total_apks": total_apks, "report_dir": str(run_report_dir),
        }
        _save_state(state_path, state)
        results.append(run_result)

    return {"new_runs": len(results), "results": results}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="Fetch SMBA sample runs, extract APKs, and run analysis.")
    parser.add_argument("smba_dir", help="SMBA output directory containing smba_run_*/smba_susp_* folders")
    parser.add_argument("--report-base", "-o", default=None, help="Base dir for reports (default: smba_dir/analysis_reports)")
    parser.add_argument("--vt-enrich", action="store_true", default=False)
    parser.add_argument("--use-smba", action="store_true", default=False)
    parser.add_argument("--force", action="store_true", default=False, help="Re-process already processed runs")
    parser.add_argument("--list", action="store_true", default=False, dest="list_only", help="List runs without processing")
    args = parser.parse_args()

    smba_dir = Path(args.smba_dir).resolve()
    report_base = Path(args.report_base).resolve() if args.report_base else smba_dir / "analysis_reports"

    if not smba_dir.is_dir():
        print(f"[-] Directory not found: {smba_dir}")
        return 1

    if args.list_only:
        runs = discover_smba_runs(smba_dir)
        state = _load_state(report_base / STATE_FILE)
        processed = state.get("processed_runs", {})
        print(f"\nSMBA runs in: {smba_dir}\n" + "-" * 80)
        for run in runs:
            status = "DONE" if run["run_name"] in processed else "NEW"
            total_mb = sum(z["size_bytes"] for z in run["zip_files"]) / (1024 * 1024)
            print(f"  [{status}] {run['run_name']}  ({run['total_zips']} zips, {total_mb:.1f} MB)")
            for zf in run["zip_files"]:
                print(f"         - {zf['category']}: {Path(zf['zip_path']).name} ({zf['size_bytes'] / (1024*1024):.1f} MB)")
        print(f"\nTotal: {len(runs)} run(s), {sum(1 for r in runs if r['run_name'] not in processed)} new")
        return 0

    print(f"\n{'='*80}\n  SMBA Sample Runner\n{'='*80}")
    print(f"  SMBA dir:    {smba_dir}")
    print(f"  Report base: {report_base}")
    print(f"  VT enrich:   {args.vt_enrich}")
    print(f"{'='*80}\n")

    report_base.mkdir(parents=True, exist_ok=True)
    summary = process_smba_runs(smba_dir, report_base, vt_enrich=args.vt_enrich, use_smba=args.use_smba, force=args.force)

    print(f"\n{'='*80}")
    print(f"  Completed: {summary['new_runs']} run(s) processed")
    for r in summary.get("results", []):
        status = "OK" if all(rc == 0 for rc in r["exit_codes"]) else "PARTIAL"
        print(f"    [{status}] {r['run_name']}: {r['total_apks']} APKs, {len(r['categories'])} categories")
    print("=" * 80)
    return 0


if __name__ == "__main__":
    sys.exit(main())

