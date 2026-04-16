import argparse
import json
import sqlite3
import sys
from pathlib import Path


DEFAULT_FAMILIES = ["Bankbot", "SMSthief", "Cerberus", "SMSreg", "Coper"]
DEFAULT_CENTRAL_DB_CANDIDATES = [
    Path("state.sqlite"),
    Path("vt_apk_downloader") / "state.sqlite",
]


def normalize_family(value: str) -> str:
    return str(value).strip().lower()


def resolve_central_state_db(explicit_path: str | None) -> Path:
    if explicit_path:
        path = Path(explicit_path).expanduser()
        if not path.is_file():
            raise FileNotFoundError(f"Central state DB not found: {path}")
        return path

    for candidate in DEFAULT_CENTRAL_DB_CANDIDATES:
        resolved = candidate.resolve()
        if resolved.is_file():
            return resolved

    candidate_text = ", ".join(str(path) for path in DEFAULT_CENTRAL_DB_CANDIDATES)
    raise FileNotFoundError(
        "Could not auto-detect the central state.sqlite. "
        f"Tried: {candidate_text}. Pass --central-state explicitly."
    )


def load_family_hashes(central_state_db: Path, target_families: list[str]) -> dict[str, set[str]]:
    normalized_targets = [normalize_family(family) for family in target_families]
    result = {family: set() for family in normalized_targets}

    conn = sqlite3.connect(str(central_state_db))
    try:
        table_names = {
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()
        }

        if "sample_families" in table_names:
            placeholders = ",".join("?" for _ in normalized_targets)
            rows = conn.execute(
                f"""
                SELECT lower(family), lower(sha256)
                FROM sample_families
                WHERE lower(family) IN ({placeholders})
                """,
                normalized_targets,
            ).fetchall()
            for family, sha256 in rows:
                result[str(family)].add(str(sha256))
            return result

        if "samples" in table_names:
            column_names = {
                row[1]
                for row in conn.execute("PRAGMA table_info(samples);").fetchall()
            }
            if "family" in column_names and "sha256" in column_names:
                placeholders = ",".join("?" for _ in normalized_targets)
                rows = conn.execute(
                    f"""
                    SELECT lower(family), lower(sha256)
                    FROM samples
                    WHERE lower(COALESCE(family, '')) IN ({placeholders})
                    """,
                    normalized_targets,
                ).fetchall()
                for family, sha256 in rows:
                    result[str(family)].add(str(sha256))
                return result

        raise RuntimeError(
            f"Central DB {central_state_db} does not contain sample_families or samples.family"
        )
    finally:
        conn.close()


def verdict_is_clean(payload: dict) -> bool:
    verdict = payload.get("verdict")
    if not isinstance(verdict, dict):
        return False
    try:
        clean = int(verdict.get("Clean") or 0)
        malicious = int(verdict.get("Malicious") or 0)
        suspicious = int(verdict.get("Suspicious") or 0)
    except Exception:
        return False
    return clean == 1 and malicious == 0 and suspicious == 0


def load_clean_hashes_from_report_db(report_db: Path) -> set[str]:
    conn = sqlite3.connect(str(report_db))
    try:
        table_names = {
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()
        }
        if "analysis_samples" not in table_names:
            return set()

        column_names = {
            row[1]
            for row in conn.execute("PRAGMA table_info(analysis_samples);").fetchall()
        }
        required_columns = {"sha256", "status", "verdict_path"}
        if not required_columns.issubset(column_names):
            return set()

        rows = conn.execute(
            """
            SELECT sha256, verdict_path
            FROM analysis_samples
            WHERE status = 'done'
            """
        ).fetchall()
    finally:
        conn.close()

    clean_hashes: set[str] = set()
    report_dir = report_db.parent
    for sha256, verdict_path in rows:
        verdict_file = Path(str(verdict_path or "")).expanduser()
        if not verdict_file.is_file() and verdict_file.name:
            verdict_file = report_dir / verdict_file.name
        if not verdict_file.is_file():
            continue
        try:
            payload = json.loads(verdict_file.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(payload, dict) and verdict_is_clean(payload):
            clean_hashes.add(str(sha256).strip().lower())
    return clean_hashes


def find_report_dbs(report_root: Path) -> list[Path]:
    if not report_root.is_dir():
        raise FileNotFoundError(f"Report root not found: {report_root}")

    dbs = []
    for path in report_root.rglob("analysis_state.sqlite"):
        if path.parent.name == "malicious":
            dbs.append(path)
    return sorted(set(dbs))


def collect_clean_hashes(report_root: Path) -> tuple[set[str], list[str]]:
    clean_hashes: set[str] = set()
    scanned_dbs: list[str] = []
    for report_db in find_report_dbs(report_root):
        scanned_dbs.append(str(report_db))
        clean_hashes.update(load_clean_hashes_from_report_db(report_db))
    return clean_hashes, scanned_dbs


def build_output(
    report_root: Path,
    central_state_db: Path,
    target_families: list[str],
) -> dict:
    family_hashes = load_family_hashes(central_state_db, target_families)
    clean_hashes, scanned_dbs = collect_clean_hashes(report_root)

    family_results = {}
    for family in target_families:
        key = normalize_family(family)
        matches = sorted(family_hashes.get(key, set()) & clean_hashes)
        family_results[family] = matches

    return {
        "report_root": str(report_root),
        "central_state_db": str(central_state_db),
        "families": target_families,
        "scanned_report_db_count": len(scanned_dbs),
        "scanned_report_dbs": scanned_dbs,
        "clean_hash_count_total": len(clean_hashes),
        "results": family_results,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Find clean-analyzed hashes for selected families by scanning batch analysis_state.sqlite files."
    )
    parser.add_argument(
        "--report-root",
        required=True,
        help="Root directory that contains timestamped analysis report folders, e.g. /mnt/ext_storage/vt_analysis_reports",
    )
    parser.add_argument(
        "--central-state",
        default=None,
        help="Path to the central state.sqlite that contains family mappings. If omitted, tries ./state.sqlite and ./vt_apk_downloader/state.sqlite",
    )
    parser.add_argument(
        "--families",
        nargs="+",
        default=DEFAULT_FAMILIES,
        help="Families to extract. Default: %(default)s",
    )
    parser.add_argument(
        "--flat",
        action="store_true",
        help="Print a flat list of family<TAB>sha256 instead of JSON.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    report_root = Path(args.report_root).expanduser()
    central_state_db = resolve_central_state_db(args.central_state)
    output = build_output(report_root, central_state_db, list(args.families))

    if args.flat:
        for family, hashes in output["results"].items():
            for sha256 in hashes:
                print(f"{family}\t{sha256}")
        return 0

    json.dump(output, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())