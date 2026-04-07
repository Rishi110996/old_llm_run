from __future__ import annotations

import argparse
import csv
import html
import json
import os
import sqlite3
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import yaml


@dataclass
class MasterEntry:
    sha256: str
    apk_name: str
    run_id: str
    bucket: str
    report_dir: str
    source_file: str
    source_line: int
    verdict_label: str
    raw_payload: Dict[str, Any]
    families: List[str]
    category: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Aggregate all master_summary.log files under the analysis report root, "
            "deduplicate by latest hash entry, and generate a presentation-friendly dashboard."
        )
    )
    parser.add_argument(
        "--config",
        default=os.path.join("vt_apk_downloader", "config.yaml"),
        help="Path to config.yaml. Defaults to vt_apk_downloader/config.yaml",
    )
    parser.add_argument(
        "--output-dir",
        default="dashboard_output",
        help="Directory where the dashboard HTML, JSON, and CSV outputs will be written.",
    )
    return parser.parse_args()


def resolve_path(base_dir: Path, configured_path: str) -> Path:
    path = Path(configured_path)
    if not path.is_absolute():
        path = base_dir / path
    return path.resolve()


def load_config(config_path: Path) -> Tuple[Dict[str, Any], Path, Path, Path]:
    with config_path.open("r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    base_dir = config_path.parent.resolve()
    report_root = resolve_path(base_dir, str(cfg["analysis"]["report_dir"]))
    state_db = resolve_path(base_dir, str(cfg["dataset"]["state_db_path"]))
    output_dir = resolve_path(base_dir, str(cfg["dataset"]["output_dir"]))
    return cfg, report_root, state_db, output_dir


def discover_master_logs(report_root: Path) -> List[Path]:
    logs = sorted(report_root.rglob("master_summary.log"))
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

    apk_name = prefix.strip()
    if apk_name.endswith(".apk"):
        apk_name = apk_name[:-4]
    return apk_name, payload if isinstance(payload, dict) else None


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


def load_state_family_mapping(state_db: Path) -> Tuple[Dict[str, List[str]], Dict[str, str]]:
    families_by_sha: Dict[str, set[str]] = defaultdict(set)
    category_by_sha: Dict[str, str] = {}

    if not state_db.is_file():
        return {}, {}

    conn = sqlite3.connect(str(state_db), timeout=30)
    try:
        cur = conn.execute("SELECT sha256, family FROM sample_families;")
        for sha256, family in cur.fetchall():
            if sha256 and family:
                families_by_sha[str(sha256)].add(str(family))

        cur = conn.execute("SELECT sha256, category, family FROM samples;")
        for sha256, category, family in cur.fetchall():
            if not sha256:
                continue
            sha = str(sha256)
            if category:
                category_by_sha[sha] = str(category)
            if family:
                families_by_sha[sha].add(str(family))
    finally:
        conn.close()

    return (
        {sha: sorted(values) for sha, values in families_by_sha.items()},
        category_by_sha,
    )


def load_output_family_mapping(output_dir: Path) -> Tuple[Dict[str, List[str]], Dict[str, str]]:
    families_by_sha: Dict[str, set[str]] = defaultdict(set)
    category_by_sha: Dict[str, str] = {}

    if not output_dir.is_dir():
        return {}, {}

    for bucket_dir in sorted(path for path in output_dir.iterdir() if path.is_dir()):
        hashes_path = bucket_dir / "hashes.txt"
        if not hashes_path.is_file():
            continue

        bucket = bucket_dir.name
        category = "benign" if bucket.lower() == "benign" else "malicious"

        with hashes_path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                sha = line.strip()
                if not sha:
                    continue
                category_by_sha[sha] = category
                if category == "malicious":
                    families_by_sha[sha].add(bucket)
                else:
                    families_by_sha[sha].add("benign")

    return (
        {sha: sorted(values) for sha, values in families_by_sha.items()},
        category_by_sha,
    )


def merge_family_mapping(*maps: Tuple[Dict[str, List[str]], Dict[str, str]]) -> Tuple[Dict[str, List[str]], Dict[str, str]]:
    merged_families: Dict[str, set[str]] = defaultdict(set)
    merged_categories: Dict[str, str] = {}

    for families_map, category_map in maps:
        for sha, families in families_map.items():
            merged_families[sha].update(families)
        for sha, category in category_map.items():
            if sha not in merged_categories or merged_categories[sha] == "unknown":
                merged_categories[sha] = category

    finalized_families = {sha: sorted(values) for sha, values in merged_families.items()}
    return finalized_families, merged_categories


def determine_category(sha256: str, families: List[str], category_by_sha: Dict[str, str]) -> str:
    category = category_by_sha.get(sha256)
    if category:
        return category
    if any(family.lower() == "benign" for family in families):
        return "benign"
    if families:
        return "malicious"
    return "unknown"


def aggregate_entries(
    report_root: Path,
    logs: List[Path],
    families_by_sha: Dict[str, List[str]],
    category_by_sha: Dict[str, str],
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

        with log_path.open("r", encoding="utf-8", errors="replace") as f:
            for line_no, line in enumerate(f, start=1):
                sha256, payload = parse_master_line(line)
                if not sha256 or not payload:
                    continue

                families = families_by_sha.get(sha256, [])
                category = determine_category(sha256, families, category_by_sha)
                verdict_label = normalize_verdict_label(payload)

                entry = MasterEntry(
                    sha256=sha256,
                    apk_name=sha256,
                    run_id=run_id,
                    bucket=bucket,
                    report_dir=report_dir,
                    source_file=str(log_path),
                    source_line=line_no,
                    verdict_label=verdict_label,
                    raw_payload=payload,
                    families=families,
                    category=category,
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


def percentage(numerator: int, denominator: int) -> Optional[float]:
    if denominator <= 0:
        return None
    return round((numerator / denominator) * 100.0, 2)


def family_display(entry: MasterEntry) -> str:
    if entry.category == "benign":
        return "benign"
    if not entry.families:
        return "unknown"
    return ", ".join(entry.families)


def build_metrics(entries: Iterable[MasterEntry], duplicate_counts: Dict[str, int], log_count: int) -> Dict[str, Any]:
    entries = list(entries)
    predicted_counts = Counter(entry.verdict_label for entry in entries)
    category_counts = Counter(entry.category for entry in entries)

    malicious_entries = [entry for entry in entries if entry.category == "malicious"]
    benign_entries = [entry for entry in entries if entry.category == "benign"]
    unknown_entries = [entry for entry in entries if entry.category == "unknown"]

    strict_tp = sum(1 for entry in malicious_entries if entry.verdict_label == "malicious")
    suspicious_on_malicious = sum(1 for entry in malicious_entries if entry.verdict_label == "suspicious")
    false_negative = sum(1 for entry in malicious_entries if entry.verdict_label == "clean")
    corrupt_malicious = sum(1 for entry in malicious_entries if entry.verdict_label == "corrupt")

    true_negative = sum(1 for entry in benign_entries if entry.verdict_label == "clean")
    false_positive = sum(
        1 for entry in benign_entries if entry.verdict_label in {"malicious", "suspicious"}
    )
    corrupt_benign = sum(1 for entry in benign_entries if entry.verdict_label == "corrupt")

    per_family: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
        "total": 0,
        "malicious": 0,
        "suspicious": 0,
        "clean": 0,
        "corrupt": 0,
        "unknown": 0,
    })
    for entry in entries:
        families = entry.families or (["benign"] if entry.category == "benign" else ["unknown"])
        for family in families:
            bucket = per_family[family]
            bucket["total"] += 1
            bucket[entry.verdict_label] += 1

    family_rows = []
    for family, counts in sorted(per_family.items(), key=lambda item: (-item[1]["total"], item[0].lower())):
        family_rows.append(
            {
                "family": family,
                **counts,
                "strict_tp_pct": percentage(counts["malicious"], counts["total"]),
                "detection_pct": percentage(counts["malicious"] + counts["suspicious"], counts["total"]),
            }
        )

    per_run = []
    run_buckets: Dict[str, Counter[str]] = defaultdict(Counter)
    for entry in entries:
        run_buckets[entry.run_id]["total"] += 1
        run_buckets[entry.run_id][entry.verdict_label] += 1
    for run_id, counts in sorted(run_buckets.items(), key=lambda item: item[0]):
        per_run.append({"run_id": run_id, **counts})

    duplicate_hashes = sum(1 for count in duplicate_counts.values() if count > 1)
    duplicate_entries = sum(max(0, count - 1) for count in duplicate_counts.values())

    metrics = {
        "overview": {
            "master_log_files_scanned": log_count,
            "total_unique_samples": len(entries),
            "total_log_overrides": duplicate_entries,
            "duplicate_hashes": duplicate_hashes,
            "families_covered": len([row for row in family_rows if row["family"] not in {"benign", "unknown"}]),
            "malicious_ground_truth_samples": len(malicious_entries),
            "benign_ground_truth_samples": len(benign_entries),
            "unknown_ground_truth_samples": len(unknown_entries),
        },
        "predicted_counts": {
            "malicious": predicted_counts.get("malicious", 0),
            "suspicious": predicted_counts.get("suspicious", 0),
            "clean": predicted_counts.get("clean", 0),
            "corrupt": predicted_counts.get("corrupt", 0),
            "unknown": predicted_counts.get("unknown", 0),
        },
        "performance": {
            "strict_tp_ratio": percentage(strict_tp, len(malicious_entries)),
            "detection_ratio": percentage(strict_tp + suspicious_on_malicious, len(malicious_entries)),
            "false_negative_ratio": percentage(false_negative, len(malicious_entries)),
            "fp_ratio": percentage(false_positive, len(benign_entries)),
            "tn_ratio": percentage(true_negative, len(benign_entries)),
            "strict_tp": strict_tp,
            "suspicious_on_malicious": suspicious_on_malicious,
            "false_negative": false_negative,
            "corrupt_malicious": corrupt_malicious,
            "false_positive": false_positive,
            "true_negative": true_negative,
            "corrupt_benign": corrupt_benign,
        },
        "per_family": family_rows,
        "per_run": per_run,
    }
    return metrics


def export_latest_entries_csv(path: Path, entries: List[MasterEntry], duplicate_counts: Dict[str, int]) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "sha256",
                "category",
                "families",
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
                    entry.category,
                    family_display(entry),
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
    subtitle_html = f"<div class=\"metric-subtitle\">{html.escape(subtitle)}</div>" if subtitle else ""
    return (
        "<div class=\"metric-card\">"
        f"<div class=\"metric-title\">{html.escape(title)}</div>"
        f"<div class=\"metric-value\">{html.escape(str(value))}</div>"
        f"{subtitle_html}"
        "</div>"
    )


def render_bar(label: str, count: int, total: int, hue: str) -> str:
    width = 0.0 if total <= 0 else (count / total) * 100.0
    return (
        "<div class=\"bar-row\">"
        f"<div class=\"bar-label\">{html.escape(label)}</div>"
        f"<div class=\"bar-track\"><div class=\"bar-fill\" style=\"width:{width:.2f}%;background:{hue};\"></div></div>"
        f"<div class=\"bar-value\">{count}</div>"
        "</div>"
    )


def render_family_table(rows: List[Dict[str, Any]]) -> str:
    body = []
    for row in rows:
        body.append(
            "<tr>"
            f"<td>{html.escape(str(row['family']))}</td>"
            f"<td>{row['total']}</td>"
            f"<td>{row['malicious']}</td>"
            f"<td>{row['suspicious']}</td>"
            f"<td>{row['clean']}</td>"
            f"<td>{row['corrupt']}</td>"
            f"<td>{fmt_pct(row['strict_tp_pct'])}</td>"
            f"<td>{fmt_pct(row['detection_pct'])}</td>"
            "</tr>"
        )
    return (
        "<table>"
        "<thead><tr><th>Family</th><th>Total</th><th>Malicious</th><th>Suspicious</th><th>Clean</th><th>Corrupt</th><th>Strict TP %</th><th>Detected %</th></tr></thead>"
        f"<tbody>{''.join(body)}</tbody>"
        "</table>"
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
            f"<td>{row.get('corrupt', 0)}</td>"
            "</tr>"
        )
    return (
        "<table>"
        "<thead><tr><th>Run ID</th><th>Unique Final Samples</th><th>Malicious</th><th>Suspicious</th><th>Clean</th><th>Corrupt</th></tr></thead>"
        f"<tbody>{''.join(body)}</tbody>"
        "</table>"
    )


def build_dashboard_html(metrics: Dict[str, Any], output_dir: Path) -> str:
    overview = metrics["overview"]
    predicted = metrics["predicted_counts"]
    performance = metrics["performance"]

    metric_cards = "".join(
        [
            render_metric_card("Unique Samples", overview["total_unique_samples"], "Bottom-most verdict per hash wins"),
            render_metric_card("Total Overrides", overview["total_log_overrides"], "Older duplicate log entries ignored"),
            render_metric_card("Strict TP Ratio", fmt_pct(performance["strict_tp_ratio"]), "Malicious ground-truth predicted Malicious"),
            render_metric_card("FP Ratio", fmt_pct(performance["fp_ratio"]), "Benign ground-truth predicted Malicious/Suspicious"),
            render_metric_card("Predicted Malicious", predicted["malicious"]),
            render_metric_card("Predicted Suspicious", predicted["suspicious"]),
            render_metric_card("Predicted Clean", predicted["clean"]),
            render_metric_card("Predicted Corrupt", predicted["corrupt"]),
        ]
    )

    total = max(1, overview["total_unique_samples"])
    breakdown_bars = "".join(
        [
            render_bar("Malicious", predicted["malicious"], total, "#c0392b"),
            render_bar("Suspicious", predicted["suspicious"], total, "#d68910"),
            render_bar("Clean", predicted["clean"], total, "#1e8449"),
            render_bar("Corrupt", predicted["corrupt"], total, "#566573"),
        ]
    )

    insight_list = "".join(
        [
            f"<li>Master logs scanned: <strong>{overview['master_log_files_scanned']}</strong></li>",
            f"<li>Malicious-labeled samples with known family/category: <strong>{overview['malicious_ground_truth_samples']}</strong></li>",
            f"<li>Benign-labeled samples available for FP measurement: <strong>{overview['benign_ground_truth_samples']}</strong></li>",
            f"<li>Unknown family/category mappings: <strong>{overview['unknown_ground_truth_samples']}</strong></li>",
            f"<li>Malicious ground-truth predicted Suspicious: <strong>{performance['suspicious_on_malicious']}</strong></li>",
            f"<li>Malicious ground-truth predicted Clean: <strong>{performance['false_negative']}</strong></li>",
            f"<li>Benign ground-truth predicted Clean: <strong>{performance['true_negative']}</strong></li>",
            f"<li>Benign ground-truth flagged as Malicious/Suspicious: <strong>{performance['false_positive']}</strong></li>",
        ]
    )

    return f"""<!DOCTYPE html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
  <title>APK Analysis Dashboard</title>
  <style>
    :root {{
      --bg: #f4efe6;
      --panel: #fffaf2;
      --ink: #1f2933;
      --muted: #6b7280;
      --accent: #b24c2a;
      --accent-soft: #f0d3c6;
      --border: #e7d9c8;
      --shadow: 0 12px 32px rgba(73, 52, 36, 0.08);
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; font-family: Georgia, 'Times New Roman', serif; background: radial-gradient(circle at top left, #fff4de 0%, var(--bg) 45%, #efe7db 100%); color: var(--ink); }}
    .wrap {{ max-width: 1440px; margin: 0 auto; padding: 32px 24px 64px; }}
    .hero {{ display: grid; grid-template-columns: 1.4fr 1fr; gap: 24px; align-items: stretch; margin-bottom: 24px; }}
    .hero-panel, .panel {{ background: var(--panel); border: 1px solid var(--border); border-radius: 24px; box-shadow: var(--shadow); }}
    .hero-panel {{ padding: 28px; }}
    .eyebrow {{ letter-spacing: 0.12em; text-transform: uppercase; color: var(--accent); font-size: 12px; margin-bottom: 12px; }}
    h1 {{ margin: 0 0 12px; font-size: 46px; line-height: 1.02; }}
    .hero p {{ color: var(--muted); font-size: 17px; line-height: 1.55; }}
    .metrics {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 16px; margin-bottom: 24px; }}
    .metric-card {{ background: var(--panel); border: 1px solid var(--border); border-radius: 20px; padding: 18px; box-shadow: var(--shadow); }}
    .metric-title {{ font-size: 12px; text-transform: uppercase; letter-spacing: 0.1em; color: var(--muted); margin-bottom: 8px; }}
    .metric-value {{ font-size: 34px; font-weight: 700; line-height: 1; }}
    .metric-subtitle {{ color: var(--muted); margin-top: 10px; font-size: 13px; line-height: 1.4; }}
    .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-bottom: 24px; }}
    .panel {{ padding: 24px; overflow: hidden; }}
    h2 {{ margin-top: 0; margin-bottom: 16px; font-size: 24px; }}
    .bar-row {{ display: grid; grid-template-columns: 120px 1fr 72px; gap: 14px; align-items: center; margin-bottom: 14px; }}
    .bar-label, .bar-value {{ font-size: 14px; }}
    .bar-track {{ width: 100%; height: 14px; background: #ede5d9; border-radius: 999px; overflow: hidden; }}
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
        <div class=\"eyebrow\">Static Aggregation Dashboard</div>
        <h1>APK Verdict Overview</h1>
        <p>This dashboard aggregates every <strong>master_summary.log</strong> under the analysis report root, keeps only the <strong>latest occurrence per SHA256</strong>, and enriches each sample with family/category data from the central dataset state.</p>
        <p class=\"footer\">Output files are written under {html.escape(str(output_dir))}. Use the CSV/JSON exports there for downstream reporting.</p>
      </div>
      <div class=\"panel\">
        <h2>Ground Truth Coverage</h2>
        <div class=\"bar-row\"><div class=\"bar-label\">Malicious</div><div class=\"bar-track\"><div class=\"bar-fill\" style=\"width:{(overview['malicious_ground_truth_samples'] / max(1, overview['total_unique_samples'])) * 100:.2f}%;background:#b24c2a;\"></div></div><div class=\"bar-value\">{overview['malicious_ground_truth_samples']}</div></div>
        <div class=\"bar-row\"><div class=\"bar-label\">Benign</div><div class=\"bar-track\"><div class=\"bar-fill\" style=\"width:{(overview['benign_ground_truth_samples'] / max(1, overview['total_unique_samples'])) * 100:.2f}%;background:#2c7a7b;\"></div></div><div class=\"bar-value\">{overview['benign_ground_truth_samples']}</div></div>
        <div class=\"bar-row\"><div class=\"bar-label\">Unknown</div><div class=\"bar-track\"><div class=\"bar-fill\" style=\"width:{(overview['unknown_ground_truth_samples'] / max(1, overview['total_unique_samples'])) * 100:.2f}%;background:#8e7c6b;\"></div></div><div class=\"bar-value\">{overview['unknown_ground_truth_samples']}</div></div>
      </div>
    </section>

    <section class=\"metrics\">{metric_cards}</section>

    <section class=\"grid\">
      <div class=\"panel\">
        <h2>Final Verdict Breakdown</h2>
        {breakdown_bars}
      </div>
      <div class=\"panel\">
        <h2>Presentation Notes</h2>
        <ul class=\"insights\">{insight_list}</ul>
      </div>
    </section>

    <section class=\"panel\" style=\"margin-bottom:24px;\">
      <h2>Family Breakdown</h2>
      <p class=\"footer\">Family counts are derived from the central <strong>state.sqlite</strong> and the dataset <strong>output</strong> folders. If a sample maps to multiple malware families, it is counted once per mapped family in this table.</p>
      {render_family_table(metrics['per_family'])}
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
    config_path = Path(args.config).resolve()
    _, report_root, state_db, output_dir = load_config(config_path)

    logs = discover_master_logs(report_root)
    if not logs:
        raise SystemExit(f"No master_summary.log files found under {report_root}")

    state_mapping = load_state_family_mapping(state_db)
    output_mapping = load_output_family_mapping(output_dir)
    families_by_sha, category_by_sha = merge_family_mapping(state_mapping, output_mapping)

    latest_by_sha, duplicate_counts, raw_occurrences = aggregate_entries(
        report_root=report_root,
        logs=logs,
        families_by_sha=families_by_sha,
        category_by_sha=category_by_sha,
    )
    latest_entries = sorted(latest_by_sha.values(), key=lambda entry: entry.sha256)
    metrics = build_metrics(latest_entries, duplicate_counts, len(logs))

    out_dir = Path(args.output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    dashboard_data = {
        "report_root": str(report_root),
        "state_db": str(state_db),
        "output_dir": str(output_dir),
        "metrics": metrics,
        "latest_entries": [
            {
                "sha256": entry.sha256,
                "category": entry.category,
                "families": entry.families,
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

    json_path = out_dir / "analysis_dashboard_data.json"
    with json_path.open("w", encoding="utf-8") as f:
        json.dump(dashboard_data, f, indent=2, ensure_ascii=False)

    csv_path = out_dir / "analysis_dashboard_latest_entries.csv"
    export_latest_entries_csv(csv_path, latest_entries, duplicate_counts)

    html_path = out_dir / "analysis_dashboard.html"
    html_path.write_text(build_dashboard_html(metrics, out_dir), encoding="utf-8")

    print(
        json.dumps(
            {
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