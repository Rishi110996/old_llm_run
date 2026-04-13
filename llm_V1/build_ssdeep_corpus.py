"""build_ssdeep_corpus.py
------------------------
Scan a directory of family-labelled APK files, compute an ssdeep fuzzy hash for
each, and write the results to  llm_V1/yara_exports/ssdeep.json  in the format
expected by ssdeep_similarity.match_against_corpus().

Expected layout:
    <download_dir>/
        Bankbot/      ← malicious family directories
            sha256.apk
            ...
        Cerberus/
            ...
        benign/       ← benign samples (exact dir name match, case-insensitive)
            sha256.apk

Usage:
    python build_ssdeep_corpus.py
    python build_ssdeep_corpus.py --apk-dir "E:/path/to/downloaded_apks" --out yara_exports/ssdeep.json
    python build_ssdeep_corpus.py --dry-run      # preview counts only
    python build_ssdeep_corpus.py --threshold 85  # looser match threshold
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Dict, List

# Resolve the llm_V1 directory (script lives there)
_HERE = os.path.dirname(os.path.abspath(__file__))

# Default paths
_DEFAULT_APK_DIR = os.path.join(
    _HERE, "..", "vt_apk_downloader", "downloaded_apks"
)
_DEFAULT_OUT = os.path.join(_HERE, "yara_exports", "ssdeep.json")

# Families whose directory name maps to clean/benign samples
_BENIGN_FAMILY_NAMES = {"benign", "clean", "goodware", "benign_apps"}

# ssdeep similarity threshold: minimum score (0–100) to count as a match
# 90 = tight (near-identical), 80 = moderate, 70 = loose
_DEFAULT_THRESHOLD = 90


# ---------------------------------------------------------------------------
# ssdeep via pure-Python implementation in ssdeep_similarity module
# ---------------------------------------------------------------------------

def _compute_hash(apk_path: str) -> str:
    """Return the ssdeep hash string for an APK file."""
    sys.path.insert(0, _HERE)
    from ssdeep_similarity import compute_ssdeep  # noqa: PLC0415
    with open(apk_path, "rb") as fh:
        data = fh.read()
    return compute_ssdeep(data)


# ---------------------------------------------------------------------------
# Corpus builder
# ---------------------------------------------------------------------------

def build_corpus(
    apk_dir: str,
    threshold: int = _DEFAULT_THRESHOLD,
    dry_run: bool = False,
    verbose: bool = False,
) -> Dict:
    """
    Walk apk_dir, hash every .apk file, and return the corpus dict.

    Directory structure:  <apk_dir>/<FamilyName>/*.apk
    """
    if not os.path.isdir(apk_dir):
        print(f"[error] APK directory not found: {apk_dir}", file=sys.stderr)
        sys.exit(1)

    hashes: List[Dict] = []
    total = skipped = 0

    for family_dir in sorted(os.listdir(apk_dir)):
        family_path = os.path.join(apk_dir, family_dir)
        if not os.path.isdir(family_path):
            continue

        is_benign = family_dir.lower() in _BENIGN_FAMILY_NAMES
        risk = -127 if is_benign else 127
        label = "benign" if is_benign else family_dir

        apk_files = [
            f for f in os.listdir(family_path)
            if f.lower().endswith(".apk")
        ]

        print(f"[{label}]  {len(apk_files)} APK(s)  risk={risk}")

        for apk_name in apk_files:
            apk_path = os.path.join(family_path, apk_name)
            sha256 = os.path.splitext(apk_name)[0]  # vt_downloader saves as <sha256>.apk

            if dry_run:
                total += 1
                if verbose:
                    print(f"  (dry-run) {sha256[:16]}…  [{label}]")
                continue

            try:
                h = _compute_hash(apk_path)
                hashes.append({
                    "hash":      h,
                    "desc":      f"{sha256[:32]}",
                    "category":  label,
                    "threatname": "" if is_benign else label,
                    "risk":      risk,
                    "threshold": threshold,
                })
                total += 1
                if verbose:
                    print(f"  {sha256[:16]}…  {h[:30]}  [{label}]")
            except Exception as exc:
                print(f"  [skip] {apk_name}: {exc}", file=sys.stderr)
                skipped += 1

    print(f"\nTotal hashed: {total}  Skipped: {skipped}")
    return {"ssdeep": {"hashes": hashes}}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Build ssdeep corpus from labelled APK directory")
    parser.add_argument(
        "--apk-dir",
        default=_DEFAULT_APK_DIR,
        help=f"Root APK directory (default: {_DEFAULT_APK_DIR})",
    )
    parser.add_argument(
        "--out",
        default=_DEFAULT_OUT,
        help=f"Output ssdeep.json path (default: {_DEFAULT_OUT})",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=_DEFAULT_THRESHOLD,
        help="Minimum ssdeep similarity score to count as a match (0–100, default: 90)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Count files only, do not compute hashes or write output",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print each file as it is processed",
    )
    args = parser.parse_args()

    apk_dir = os.path.abspath(args.apk_dir)
    out_path = os.path.abspath(args.out)

    print(f"APK directory : {apk_dir}")
    print(f"Output        : {out_path}")
    print(f"Threshold     : {args.threshold}")
    print(f"Dry run       : {args.dry_run}\n")

    corpus = build_corpus(
        apk_dir=apk_dir,
        threshold=args.threshold,
        dry_run=args.dry_run,
        verbose=args.verbose,
    )

    if args.dry_run:
        print("\n[dry-run] No file written.")
        return

    # Merge with any existing corpus (keeps manual entries)
    existing_hashes: List[Dict] = []
    if os.path.isfile(out_path):
        try:
            with open(out_path, "r", encoding="utf-8") as fh:
                existing = json.load(fh)
            existing_hashes = existing.get("ssdeep", {}).get("hashes", [])
            # Only keep entries that have no matching sha256/desc in the new set
            new_descs = {e["desc"] for e in corpus["ssdeep"]["hashes"]}
            kept = [e for e in existing_hashes if e.get("desc", "") not in new_descs]
            if kept:
                print(f"\nMerging {len(kept)} existing manual entries.")
            corpus["ssdeep"]["hashes"] = kept + corpus["ssdeep"]["hashes"]
        except Exception as exc:
            print(f"[warn] Could not read existing corpus (will overwrite): {exc}", file=sys.stderr)

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(corpus, fh, indent=2, ensure_ascii=False)

    n = len(corpus["ssdeep"]["hashes"])
    print(f"\nWrote {n} hash entries → {out_path}")


if __name__ == "__main__":
    main()
