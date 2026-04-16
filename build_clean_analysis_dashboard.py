from __future__ import annotations

import argparse
import csv
import html
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


@dataclass
class MasterEntry:
    sha256: str
    run_id: str
    bucket: str
    report_dir: str
    source_file: str
    source_line: int
    verdict_label: str
    raw_payload: Dict[str, Any]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Aggregate clean-sample master_summary.log files under a report root, "
            "deduplicate by latest hash entry, and generate an FP-focused dashboard."
        )
    )
    parser.add_argument(
        "--report-root",
        required=True,
        help="Root directory containing the clean batch run IDs.",
    )
    parser.add_argument(
        "--output-dir",
        default="clean_dashboard_output",
        help="Directory where the dashboard HTML, JSON, and CSV outputs will be written.",
    )
    parser.add_argument(
        "--master-log-name",
        default="master_summary.log",
        help="Master summary filename to aggregate. Defaults to master_summary.log",
    )
    return parser.parse_args()


def discover_master_logs(report_root: Path, master_log_name: str) -> List[Path]:
    logs = sorted(report_root.rglob(master_log_name))
    return sorted(logs, key=lambda path: extract_sort_key(report_root, path))


def extract_sort_key(report_root: Path, log_path: Path) -> Tuple[str, str, str]:
    rel = log_path.relative_to(report_root)
    parts = rel.parts
    run_id = parts[0] if len(parts) >= 1 else ""
    bucket = parts[1] if len(parts) >= 2 else ""
    return run_id, bucket, str(rel)


def parse_master_line(line: str) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
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


def normalize_verdict_label(payload: Dict[str, Any]) -> str:
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


def aggregate_entries(
    report_root: Path,
    logs: List[Path],
) -> Tuple[Dict[str, MasterEntry], Dict[str, int], List[Dict[str, Any]]]:
    latest_by_sha: Dict[str, MasterEntry] = {}
    occurrence_count: Counter[str] = Counter()
    raw_occurrences: List[Dict[str, Any]] = []

    for log_path in logs:
        rel = log_path.relative_to(report_root)
        parts = rel.parts
        run_id = parts[0] if len(parts) >= 1 else "unknown"
        bucket = parts[1] if len(parts) >= 2 else "unknown"
        report_dir = str(log_path.parent)

        with log_path.open("r", encoding="utf-8", errors="replace") as handle:
            for line_no, line in enumerate(handle, start=1):
                sha256, payload = parse_master_line(line)
                if not sha256 or not payload:
                    continue

                verdict_label = normalize_verdict_label(payload)
                entry = MasterEntry(
                    sha256=sha256,
                    run_id=run_id,
                    bucket=bucket,
                    report_dir=report_dir,
                    source_file=str(log_path),
                    source_line=line_no,
                    verdict_label=verdict_label,
                    raw_payload=payload,
                )
                latest_by_sha[sha256] = entry
                occurrence_count[sha256] += 1
                raw_occurrences.append(
                    {
                        "sha256": sha256,
                        "run_id": run_id,
                        "bucket": bucket,
                        "source_file": str(log_path),
                        "source_line": line_no,
                    }
                )

    return latest_by_sha, dict(occurrence_count), raw_occurrences


def filter_countable_entries(entries: Iterable[MasterEntry]) -> List[MasterEntry]:
    return [entry for entry in entries if entry.verdict_label != "corrupt"]


def percentage(numerator: int, denominator: int) -> Optional[float]:
    if denominator <= 0:
        return None
    return round((numerator / denominator) * 100.0, 2)


def build_metrics(entries: Iterable[MasterEntry], duplicate_counts: Dict[str, int], log_count: int) -> Dict[str, Any]:
    entries = list(entries)
    predicted_counts = Counter(entry.verdict_label for entry in entries)
    total_entries = len(entries)

    malicious_count = predicted_counts.get("malicious", 0)
    suspicious_count = predicted_counts.get("suspicious", 0)
    clean_count = predicted_counts.get("clean", 0)
    unknown_count = predicted_counts.get("unknown", 0)
    false_positive_count = malicious_count + suspicious_count

    duplicate_hashes = sum(1 for count in duplicate_counts.values() if count > 1)
    duplicate_entries = sum(max(0, count - 1) for count in duplicate_counts.values())

    per_run: List[Dict[str, Any]] = []
    run_buckets: Dict[str, Counter[str]] = defaultdict(Counter)
    for entry in entries:
        run_buckets[entry.run_id]["total"] += 1
        run_buckets[entry.run_id][entry.verdict_label] += 1

    for run_id, counts in sorted(run_buckets.items(), key=lambda item: item[0]):
        per_run.append(
            {
                "run_id": run_id,
                "total": counts.get("total", 0),
                "malicious": counts.get("malicious", 0),
                "suspicious": counts.get("suspicious", 0),
                "clean": counts.get("clean", 0),
                "unknown": counts.get("unknown", 0),
                "fp_pct": percentage(
                    counts.get("malicious", 0) + counts.get("suspicious", 0),
                    counts.get("total", 0),
                ),
            }
        )

    return {
        "overview": {
            "master_log_files_scanned": log_count,
            "total_unique_samples": total_entries,
            "total_log_overrides": duplicate_entries,
            "duplicate_hashes": duplicate_hashes,
        },
        "predicted_counts": {
            "malicious": malicious_count,
            "suspicious": suspicious_count,
            "clean": clean_count,
            "unknown": unknown_count,
        },
        "performance": {
            "fp_ratio": percentage(false_positive_count, total_entries),
            "malicious_fp_ratio": percentage(malicious_count, total_entries),
            "suspicious_fp_ratio": percentage(suspicious_count, total_entries),
            "tn_ratio": percentage(clean_count, total_entries),
            "unknown_ratio": percentage(unknown_count, total_entries),
            "false_positive": false_positive_count,
            "malicious_false_positive": malicious_count,
            "suspicious_false_positive": suspicious_count,
            "true_negative": clean_count,
            "unknown": unknown_count,
        },
        "per_run": per_run,
    }


def export_latest_entries_csv(path: Path, entries: List[MasterEntry], duplicate_counts: Dict[str, int]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "sha256",
                "verdict_label",
                "run_id",
                "bucket",
                "report_dir",
                "source_file",
                "source_line",
                "occurrences_seen",
            ]
        )
        for entry in entries:
            writer.writerow(
                [
                    entry.sha256,
                    entry.verdict_label,
                    entry.run_id,
                    entry.bucket,
                    entry.report_dir,
                    entry.source_file,
                    entry.source_line,
                    duplicate_counts.get(entry.sha256, 1),
                ]
            )


def fmt_pct(value: Optional[float]) -> str:
    return "N/A" if value is None else f"{value:.2f}%"


def render_metric_card(title: str, value: Any, subtitle: str = "") -> str:
    subtitle_html = f'<div class="metric-subtitle">{html.escape(subtitle)}</div>' if subtitle else ""
    return (
        '<div class="metric-card">'
        f'<div class="metric-title">{html.escape(title)}</div>'
        f'<div class="metric-value">{html.escape(str(value))}</div>'
        f"{subtitle_html}"
        "</div>"
    )


def render_bar(label: str, count: int, total: int, hue: str) -> str:
    width = 0.0 if total <= 0 else (count / total) * 100.0
    return (
        '<div class="bar-row">'
        f'<div class="bar-label">{html.escape(label)}</div>'
        f'<div class="bar-track"><div class="bar-fill" style="width:{width:.2f}%;background:{hue};"></div></div>'
        f'<div class="bar-value">{count}</div>'
        "</div>"
    )


def render_run_table(rows: List[Dict[str, Any]]) -> str:
    body = []
    for row in rows:
        body.append(
            "<tr>"
            f"<td>{html.escape(str(row['run_id']))}</td>"
            f"<td>{row.get('total', 0)}</td>"
            f"<td>{row.get('malicious', 0)}</td>"
            f"<td>{row.get('suspicious', 0)}</td>"
            f"<td>{row.get('clean', 0)}</td>"
            f"<td>{row.get('unknown', 0)}</td>"
            f"<td>{fmt_pct(row.get('fp_pct'))}</td>"
            "</tr>"
        )
    return (
        "<table>"
        "<thead><tr><th>Run ID</th><th>Unique Final Samples</th><th>Malicious</th><th>Suspicious</th><th>Clean</th><th>Unknown</th><th>FP %</th></tr></thead>"
        f"<tbody>{''.join(body)}</tbody>"
        "</table>"
    )


def build_dashboard_html(metrics: Dict[str, Any], output_dir: Path, report_root: Path, master_log_name: str) -> str:
    overview = metrics["overview"]
    predicted = metrics["predicted_counts"]
    performance = metrics["performance"]

    metric_cards = "".join(
        [
            render_metric_card("Unique Samples", overview["total_unique_samples"]),
            render_metric_card("FP Ratio", fmt_pct(performance["fp_ratio"]), "Predicted Malicious or Suspicious"),
            render_metric_card("Predicted Malicious", predicted["malicious"]),
            render_metric_card("Predicted Suspicious", predicted["suspicious"]),
            render_metric_card("Predicted Clean", predicted["clean"]),
            render_metric_card("TN Ratio", fmt_pct(performance["tn_ratio"]), "Predicted Clean"),
        ]
    )

    total = max(1, overview["total_unique_samples"])
    breakdown_bars = "".join(
        [
            render_bar("Malicious", predicted["malicious"], total, "#b03a2e"),
            render_bar("Suspicious", predicted["suspicious"], total, "#ca8a04"),
            render_bar("Clean", predicted["clean"], total, "#15803d"),
            render_bar("Unknown", predicted["unknown"], total, "#6b7280"),
        ]
    )

    insight_list = "".join(
        [
            f"<li>Master logs scanned: <strong>{overview['master_log_files_scanned']}</strong></li>",
            f"<li>Duplicate hashes across reruns: <strong>{overview['duplicate_hashes']}</strong></li>",
            f"<li>Overridden older hash entries: <strong>{overview['total_log_overrides']}</strong></li>",
            f"<li>False positives (Malicious + Suspicious): <strong>{performance['false_positive']}</strong></li>",
            f"<li>Predicted Malicious false positives: <strong>{performance['malicious_false_positive']}</strong></li>",
            f"<li>Predicted Suspicious false positives: <strong>{performance['suspicious_false_positive']}</strong></li>",
            f"<li>Predicted Clean true negatives: <strong>{performance['true_negative']}</strong></li>",
            f"<li>Unknown verdict count: <strong>{performance['unknown']}</strong></li>",
        ]
    )

    return f"""<!DOCTYPE html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
  <title>Clean APK Dashboard</title>
  <style>
    :root {{
      --bg: #eef5ef;
      --panel: #fbfef8;
      --ink: #1f2933;
      --muted: #64748b;
      --accent: #215732;
      --accent-soft: #dcebdc;
      --border: #d9e5d8;
      --shadow: 0 12px 32px rgba(25, 52, 31, 0.08);
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; font-family: Georgia, 'Times New Roman', serif; background: radial-gradient(circle at top left, #f8fff4 0%, var(--bg) 45%, #e6efe6 100%); color: var(--ink); }}
    .wrap {{ max-width: 1440px; margin: 0 auto; padding: 32px 24px 64px; }}
    .hero {{ display: grid; grid-template-columns: 1.4fr 1fr; gap: 24px; align-items: stretch; margin-bottom: 24px; }}
    .hero-panel, .panel {{ background: var(--panel); border: 1px solid var(--border); border-radius: 24px; box-shadow: var(--shadow); }}
    .hero-panel {{ padding: 28px; }}
    .eyebrow {{ letter-spacing: 0.12em; text-transform: uppercase; color: var(--accent); font-size: 12px; margin-bottom: 12px; }}
    h1 {{ margin: 0 0 12px; font-size: 46px; line-height: 1.02; }}
    .hero p {{ color: var(--muted); font-size: 17px; line-height: 1.55; }}
    .metrics {{ display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 16px; margin-bottom: 24px; }}
    .metric-card {{ background: var(--panel); border: 1px solid var(--border); border-radius: 20px; padding: 18px; box-shadow: var(--shadow); }}
    .metric-title {{ font-size: 12px; text-transform: uppercase; letter-spacing: 0.1em; color: var(--muted); margin-bottom: 8px; }}
    .metric-value {{ font-size: 34px; font-weight: 700; line-height: 1; }}
    .metric-subtitle {{ color: var(--muted); margin-top: 10px; font-size: 13px; line-height: 1.4; }}
    .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-bottom: 24px; }}
    .panel {{ padding: 24px; overflow: hidden; }}
    h2 {{ margin-top: 0; margin-bottom: 16px; font-size: 24px; }}
    .bar-row {{ display: grid; grid-template-columns: 120px 1fr 72px; gap: 14px; align-items: center; margin-bottom: 14px; }}
    .bar-label, .bar-value {{ font-size: 14px; }}
    .bar-track {{ width: 100%; height: 14px; background: #e8efe7; border-radius: 999px; overflow: hidden; }}
    .bar-fill {{ height: 100%; border-radius: 999px; }}
    ul.insights {{ margin: 0; padding-left: 18px; color: var(--muted); line-height: 1.7; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
    th, td {{ padding: 12px 10px; border-bottom: 1px solid var(--border); text-align: left; vertical-align: top; }}
    th {{ font-size: 12px; letter-spacing: 0.08em; text-transform: uppercase; color: var(--muted); }}
    .footer {{ color: var(--muted); font-size: 13px; margin-top: 18px; }}
    @media (max-width: 1100px) {{
      .hero, .grid {{ grid-template-columns: 1fr; }}
      .metrics {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
    }}
    @media (max-width: 700px) {{
      .metrics {{ grid-template-columns: 1fr; }}
      h1 {{ font-size: 34px; }}
      .wrap {{ padding: 20px 14px 40px; }}
      .bar-row {{ grid-template-columns: 90px 1fr 54px; gap: 8px; }}
    }}
  </style>
</head>
<body>
  <div class=\"wrap\">
    <section class=\"hero\">
      <div class=\"hero-panel\">
        <div class=\"eyebrow\">Clean Sample Aggregation Dashboard</div>
        <h1>Benign APK False Positive Overview</h1>
        <p>This dashboard aggregates every <strong>{html.escape(master_log_name)}</strong> under the clean report root and treats each deduplicated sample as benign ground truth.</p>
        <p class=\"footer\">Report root: {html.escape(str(report_root))}<br>Output files are written under {html.escape(str(output_dir))}.</p>
      </div>
      <div class=\"panel\">
        <h2>Verdict Breakdown</h2>
        {breakdown_bars}
      </div>
    </section>

    <section class=\"metrics\">{metric_cards}</section>

    <section class=\"grid\">
      <div class=\"panel\">
        <h2>Presentation Notes</h2>
        <ul class=\"insights\">{insight_list}</ul>
      </div>
      <div class=\"panel\">
        <h2>Ground Truth Assumption</h2>
        <ul class=\"insights\">
          <li>Every aggregated entry is treated as a clean sample.</li>
          <li><strong>FP %</strong> is calculated as <strong>(Malicious + Suspicious) / Total Unique Samples</strong>.</li>
          <li><strong>TN %</strong> is calculated as <strong>Clean / Total Unique Samples</strong>.</li>
          <li>Corrupt entries are excluded because they do not carry a final verdict.</li>
        </ul>
      </div>
    </section>

    <section class=\"panel\">
      <h2>Run Breakdown</h2>
      {render_run_table(metrics['per_run'])}
    </section>
  </div>
</body>
</html>
"""


def main() -> int:
    args = parse_args()
    report_root = Path(args.report_root).expanduser().resolve()
    if not report_root.is_dir():
        raise SystemExit(f"Report root does not exist or is not a directory: {report_root}")

    logs = discover_master_logs(report_root, args.master_log_name)
    if not logs:
        raise SystemExit(f"No {args.master_log_name} files found under {report_root}")

    latest_by_sha, duplicate_counts, raw_occurrences = aggregate_entries(
        report_root=report_root,
        logs=logs,
    )
    latest_entries = sorted(filter_countable_entries(latest_by_sha.values()), key=lambda entry: entry.sha256)
    metrics = build_metrics(latest_entries, duplicate_counts, len(logs))

    out_dir = Path(args.output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    dashboard_data = {
        "report_root": str(report_root),
        "master_log_name": args.master_log_name,
        "metrics": metrics,
        "latest_entries": [
            {
                "sha256": entry.sha256,
                "verdict_label": entry.verdict_label,
                "run_id": entry.run_id,
                "bucket": entry.bucket,
                "report_dir": entry.report_dir,
                "source_file": entry.source_file,
                "source_line": entry.source_line,
                "occurrences_seen": duplicate_counts.get(entry.sha256, 1),
                "raw_payload": entry.raw_payload,
            }
            for entry in latest_entries
        ],
        "raw_occurrences": raw_occurrences,
    }

    json_path = out_dir / "clean_analysis_dashboard_data.json"
    with json_path.open("w", encoding="utf-8") as handle:
        json.dump(dashboard_data, handle, indent=2, ensure_ascii=False)

    csv_path = out_dir / "clean_analysis_dashboard_latest_entries.csv"
    export_latest_entries_csv(csv_path, latest_entries, duplicate_counts)

    html_path = out_dir / "clean_analysis_dashboard.html"
    html_path.write_text(
        build_dashboard_html(metrics, out_dir, report_root, args.master_log_name),
        encoding="utf-8",
    )

    print(
        json.dumps(
            {
                "master_log_name": args.master_log_name,
                "master_log_files_scanned": len(logs),
                "unique_samples": len(latest_entries),
                "output_html": str(html_path),
                "output_json": str(json_path),
                "output_csv": str(csv_path),
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())