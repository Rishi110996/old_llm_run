import argparse
import json
import os
import sqlite3
from typing import Any, Dict, List, Optional, Tuple


def load_rows(report_dir: str) -> List[Dict[str, Any]]:
    db_path = os.path.join(report_dir, "analysis_state.sqlite")
    if not os.path.isfile(db_path):
        raise FileNotFoundError(f"analysis_state.sqlite not found in {report_dir}")

    conn = sqlite3.connect(db_path, timeout=30)
    try:
        cur = conn.execute(
            """
            SELECT sha256, apk_name, status, last_error, log_path, verdict_path,
                   started_at_utc, finished_at_utc
            FROM analysis_samples
            ORDER BY COALESCE(finished_at_utc, started_at_utc, ''), apk_name;
            """
        )
        return [
            {
                "sha256": str(row[0]),
                "apk_name": str(row[1]),
                "status": str(row[2]),
                "last_error": row[3],
                "log_path": row[4],
                "verdict_path": row[5],
                "started_at_utc": row[6],
                "finished_at_utc": row[7],
            }
            for row in cur.fetchall()
        ]
    finally:
        conn.close()


def load_json(path: str) -> Optional[Dict[str, Any]]:
    if not path or not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data if isinstance(data, dict) else None


def extract_json_after_marker(text: str, marker: str) -> Optional[Dict[str, Any]]:
    idx = text.rfind(marker)
    if idx == -1:
        return None

    brace_idx = text.find("{", idx)
    if brace_idx == -1:
        return None

    decoder = json.JSONDecoder()
    try:
        obj, _end = decoder.raw_decode(text[brace_idx:])
    except json.JSONDecodeError:
        return None
    return obj if isinstance(obj, dict) else None


def load_verdict_from_log(path: str) -> Optional[Dict[str, Any]]:
    if not path or not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    return extract_json_after_marker(text, "[FINAL VERDICT]")


def build_line(row: Dict[str, Any]) -> Tuple[Optional[str], str]:
    apk_name = row["apk_name"]
    status = row["status"]
    verdict_path = row.get("verdict_path") or ""
    log_path = row.get("log_path") or ""

    payload = load_json(verdict_path)
    if payload:
        if status == "done" and isinstance(payload.get("verdict"), dict):
            return f"{apk_name}: {json.dumps(payload['verdict'], ensure_ascii=False)}", "verdict_json"
        return f"{apk_name}: {json.dumps(payload, ensure_ascii=False)}", "verdict_json"

    if status == "done":
        verdict = load_verdict_from_log(log_path)
        if verdict:
            return f"{apk_name}: {json.dumps(verdict, ensure_ascii=False)}", "analysis_log"
        return None, "missing_done_payload"

    if status == "corrupt":
        reconstructed = {
            "apk_file": f"{apk_name}.apk",
            "sha256": row["sha256"],
            "status": "corrupt",
            "error": row.get("last_error"),
        }
        return f"{apk_name}: {json.dumps(reconstructed, ensure_ascii=False)}", "sqlite_fallback"

    return None, f"unsupported_status:{status}"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Rebuild master_summary.log from analysis_state.sqlite plus verdict/log files."
    )
    parser.add_argument("report_dir", help="Batch report directory containing analysis_state.sqlite")
    parser.add_argument(
        "--output",
        default=None,
        help="Output log path. Defaults to <report_dir>/master_summary.log.rebuilt",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite the output file if it already exists.",
    )
    args = parser.parse_args()

    report_dir = os.path.abspath(args.report_dir)
    output_path = os.path.abspath(
        args.output or os.path.join(report_dir, "master_summary.log.rebuilt")
    )

    if os.path.exists(output_path) and not args.overwrite:
        raise FileExistsError(
            f"{output_path} already exists. Use --overwrite to replace it."
        )

    rows = load_rows(report_dir)
    written = 0
    skipped = 0
    source_counts: Dict[str, int] = {}

    with open(output_path, "w", encoding="utf-8") as out:
        for row in rows:
            line, source = build_line(row)
            source_counts[source] = source_counts.get(source, 0) + 1
            if line is None:
                skipped += 1
                continue
            out.write(line + "\n")
            written += 1

    summary = {
        "report_dir": report_dir,
        "output_path": output_path,
        "rows_in_sqlite": len(rows),
        "lines_written": written,
        "rows_skipped": skipped,
        "source_counts": source_counts,
    }
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0 if skipped == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
