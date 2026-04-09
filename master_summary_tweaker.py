from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import yaml


@dataclass
class ParsedLine:
    line_no: int
    raw_line: str
    sha256: Optional[str]
    payload: Optional[dict]
    verdict_label: str


@dataclass
class LogSummary:
    log_path: Path
    run_id: str
    bucket: str
    report_dir: Path
    total_lines: int
    parsed_entries: int
    malicious_count: int
    suspicious_count: int
    clean_count: int
    corrupt_count: int
    unknown_count: int

    @property
    def countable_entries(self) -> int:
        return self.malicious_count + self.suspicious_count + self.clean_count

    @property
    def tp_ratio_malicious_only(self) -> float:
        total = self.countable_entries
        return (self.malicious_count / total) if total else 0.0

    @property
    def tp_ratio_malicious_or_suspicious(self) -> float:
        total = self.countable_entries
        return ((self.malicious_count + self.suspicious_count) / total) if total else 0.0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Export per-master-summary TSV stats and apply per-log clean-entry removal "
            "percentages into sibling master_summary_tweaked.log files."
        )
    )
    parser.add_argument(
        "--config",
        default=os.path.join("vt_apk_downloader", "config.yaml"),
        help="Path to config.yaml. Defaults to vt_apk_downloader/config.yaml",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    export_parser = subparsers.add_parser(
        "export",
        help="Write a TSV listing every master_summary.log and its verdict counts.",
    )
    export_parser.add_argument(
        "--output-tsv",
        default="master_summary_removal_plan.tsv",
        help="Where to write the TSV plan file.",
    )

    apply_parser = subparsers.add_parser(
        "apply",
        help="Read an edited TSV and create master_summary_tweaked.log files beside each source log.",
    )
    apply_parser.add_argument(
        "--plan-tsv",
        required=True,
        help="Edited TSV produced by the export command.",
    )
    apply_parser.add_argument(
        "--output-name",
        default="master_summary_tweaked.log",
        help="Filename to create next to each original log.",
    )
    return parser.parse_args()


def resolve_path(base_dir: Path, configured_path: str) -> Path:
    path = Path(configured_path)
    if not path.is_absolute():
        path = base_dir / path
    return path.resolve()


def load_report_root(config_path: Path) -> Path:
    with config_path.open("r", encoding="utf-8") as handle:
        cfg = yaml.safe_load(handle)
    base_dir = config_path.parent.resolve()
    return resolve_path(base_dir, str(cfg["analysis"]["report_dir"]))


def discover_master_logs(report_root: Path) -> List[Path]:
    logs = sorted(report_root.rglob("master_summary.log"))
    return sorted(logs, key=lambda path: extract_sort_key(report_root, path))


def extract_sort_key(report_root: Path, log_path: Path) -> Tuple[str, str, str]:
    rel = log_path.relative_to(report_root)
    parts = rel.parts
    run_id = parts[0] if len(parts) >= 1 else ""
    bucket = parts[1] if len(parts) >= 2 else ""
    return run_id, bucket, str(rel)


def parse_master_line(line: str) -> Tuple[Optional[str], Optional[dict]]:
    stripped = line.strip()
    if not stripped or ": " not in stripped:
        return None, None

    prefix, payload_text = stripped.split(": ", 1)
    try:
        payload = json.loads(payload_text)
    except json.JSONDecodeError:
        return None, None

    sha256 = prefix.strip()
    if sha256.endswith(".apk"):
        sha256 = sha256[:-4]
    return sha256, payload if isinstance(payload, dict) else None


def normalize_verdict_label(payload: Optional[dict]) -> str:
    if not isinstance(payload, dict):
        return "unknown"
    if payload.get("status") == "corrupt":
        return "corrupt"

    verdict = payload.get("verdict") if isinstance(payload.get("verdict"), dict) else payload
    if not isinstance(verdict, dict):
        return "unknown"

    try:
        malicious = int(verdict.get("Malicious") or 0)
        suspicious = int(verdict.get("Suspicious") or 0)
        clean = int(verdict.get("Clean") or 0)
    except Exception:
        return "unknown"

    if malicious == 1:
        return "malicious"
    if suspicious == 1:
        return "suspicious"
    if clean == 1:
        return "clean"
    return "unknown"


def parse_log(log_path: Path, report_root: Path) -> Tuple[LogSummary, List[ParsedLine]]:
    rel = log_path.relative_to(report_root)
    parts = rel.parts
    run_id = parts[0] if len(parts) >= 1 else "unknown"
    bucket = parts[1] if len(parts) >= 2 else "unknown"

    parsed_lines: List[ParsedLine] = []
    total_lines = 0
    counts = {
        "malicious": 0,
        "suspicious": 0,
        "clean": 0,
        "corrupt": 0,
        "unknown": 0,
    }

    with log_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_no, raw_line in enumerate(handle, start=1):
            total_lines += 1
            sha256, payload = parse_master_line(raw_line)
            verdict_label = normalize_verdict_label(payload)
            if verdict_label not in counts:
                verdict_label = "unknown"
            if payload is not None:
                counts[verdict_label] += 1
            parsed_lines.append(
                ParsedLine(
                    line_no=line_no,
                    raw_line=raw_line,
                    sha256=sha256,
                    payload=payload,
                    verdict_label=verdict_label,
                )
            )

    summary = LogSummary(
        log_path=log_path,
        run_id=run_id,
        bucket=bucket,
        report_dir=log_path.parent,
        total_lines=total_lines,
        parsed_entries=sum(counts.values()),
        malicious_count=counts["malicious"],
        suspicious_count=counts["suspicious"],
        clean_count=counts["clean"],
        corrupt_count=counts["corrupt"],
        unknown_count=counts["unknown"],
    )
    return summary, parsed_lines


def summarize_logs(report_root: Path, logs: Sequence[Path]) -> List[LogSummary]:
    summaries: List[LogSummary] = []
    for log_path in logs:
        summary, _parsed = parse_log(log_path, report_root)
        summaries.append(summary)
    return summaries


def format_ratio(value: float) -> str:
    return f"{value:.6f}"


def export_plan(report_root: Path, output_tsv: Path) -> None:
    logs = discover_master_logs(report_root)
    if not logs:
        raise SystemExit(f"No master_summary.log files found under {report_root}")

    summaries = summarize_logs(report_root, logs)
    output_tsv.parent.mkdir(parents=True, exist_ok=True)
    with output_tsv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, delimiter="\t")
        writer.writerow(
            [
                "run_id",
                "bucket",
                "report_dir",
                "master_summary_log",
                "total_lines",
                "parsed_entries",
                "malicious_count",
                "suspicious_count",
                "clean_count",
                "corrupt_count",
                "unknown_count",
                "tp_ratio_malicious_only",
                "tp_ratio_malicious_or_suspicious",
                "percentage_removal",
            ]
        )
        for summary in summaries:
            writer.writerow(
                [
                    summary.run_id,
                    summary.bucket,
                    str(summary.report_dir),
                    str(summary.log_path),
                    summary.total_lines,
                    summary.parsed_entries,
                    summary.malicious_count,
                    summary.suspicious_count,
                    summary.clean_count,
                    summary.corrupt_count,
                    summary.unknown_count,
                    format_ratio(summary.tp_ratio_malicious_only),
                    format_ratio(summary.tp_ratio_malicious_or_suspicious),
                    "0",
                ]
            )

    print(f"[export] wrote {len(summaries)} rows to {output_tsv}")


def read_plan_rows(plan_tsv: Path) -> List[dict]:
    with plan_tsv.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        return list(reader)


def parse_percentage(value: str, *, log_path: str) -> float:
    text = str(value or "0").strip()
    if not text:
        return 0.0
    try:
        parsed = float(text)
    except ValueError as exc:
        raise SystemExit(f"Invalid percentage_removal '{text}' for {log_path}") from exc
    if parsed < 0 or parsed > 100:
        raise SystemExit(f"percentage_removal must be between 0 and 100 for {log_path}")
    return parsed


def pick_clean_lines_to_remove(parsed_lines: Sequence[ParsedLine], removal_pct: float) -> set[int]:
    clean_lines = [line for line in parsed_lines if line.verdict_label == "clean" and line.payload is not None]
    if not clean_lines or removal_pct <= 0:
        return set()

    remove_count = min(len(clean_lines), int(math.floor(len(clean_lines) * (removal_pct / 100.0))))
    if remove_count <= 0:
        return set()

    ranked = sorted(
        clean_lines,
        key=lambda line: stable_rank_key(line),
    )
    return {line.line_no for line in ranked[:remove_count]}


def stable_rank_key(line: ParsedLine) -> Tuple[str, int]:
    base = f"{line.sha256 or ''}|{line.line_no}|{line.raw_line.rstrip()}".encode("utf-8", errors="replace")
    digest = hashlib.sha256(base).hexdigest()
    return digest, line.line_no


def write_tweaked_log(
    *,
    parsed_lines: Sequence[ParsedLine],
    output_path: Path,
    lines_to_remove: set[int],
) -> Tuple[int, int]:
    kept = 0
    removed = 0
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        for line in parsed_lines:
            if line.line_no in lines_to_remove:
                removed += 1
                continue
            handle.write(line.raw_line)
            kept += 1
    return kept, removed


def apply_plan(report_root: Path, plan_tsv: Path, output_name: str) -> None:
    rows = read_plan_rows(plan_tsv)
    if not rows:
        raise SystemExit(f"No rows found in {plan_tsv}")

    applied = 0
    for row in rows:
        log_text = str(row.get("master_summary_log") or "").strip()
        if not log_text:
            continue

        log_path = Path(log_text)
        if not log_path.is_absolute():
            log_path = (report_root / log_path).resolve()
        if not log_path.is_file():
            raise SystemExit(f"Listed master_summary.log does not exist: {log_path}")

        removal_pct = parse_percentage(str(row.get("percentage_removal") or "0"), log_path=str(log_path))
        summary, parsed_lines = parse_log(log_path, report_root)
        lines_to_remove = pick_clean_lines_to_remove(parsed_lines, removal_pct)
        output_path = log_path.with_name(output_name)
        kept, removed = write_tweaked_log(
            parsed_lines=parsed_lines,
            output_path=output_path,
            lines_to_remove=lines_to_remove,
        )
        applied += 1
        print(
            f"[apply] {summary.run_id}/{summary.bucket} removal_pct={removal_pct:.2f} "
            f"clean_removed={removed}/{summary.clean_count} kept_lines={kept} output={output_path}"
        )

    print(f"[apply] wrote tweaked logs for {applied} master summary file(s)")


def main() -> int:
    args = parse_args()
    config_path = Path(args.config).resolve()
    report_root = load_report_root(config_path)

    if args.command == "export":
        export_plan(report_root, Path(args.output_tsv).resolve())
        return 0
    if args.command == "apply":
        apply_plan(report_root, Path(args.plan_tsv).resolve(), args.output_name)
        return 0

    raise SystemExit(f"Unsupported command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
