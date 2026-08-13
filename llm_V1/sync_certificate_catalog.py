#!/usr/bin/env python3
"""Standalone script to download and update whitelisted (clean) and blacklisted
(malicious) certificate hash catalogs from the Zintel API.

Requirements: Python 3.8+, requests

Usage:
    export ZINTEL_API_KEY="your-api-key"
    export ZINTEL_URL="https://z-intel-plus.corp.zscaler.com/"
    python sync_certificate_catalog.py
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests


# ---------------------------------------------------------------------------
# Zintel API helpers
# ---------------------------------------------------------------------------

def _api_headers(api_key: str) -> Dict[str, str]:
    return {
        "accept": "application/json",
        "Authorization": f"Api-Key {api_key}",
        "Content-Type": "application/json",
    }


def fetch_certificate_feed(
    api_key: str,
    base_url: str,
    *,
    timeout: int = 30,
    verify_ssl: bool = True,
    max_retries: int = 3,
    retry_delay: float = 5,
) -> dict:
    """Fetch the full certificate feed from Zintel."""
    url = f"{base_url.rstrip('/')}/api/research/sample/certificates/feeds/"
    headers = _api_headers(api_key)

    last_error: Optional[Exception] = None
    for attempt in range(1, max_retries + 1):
        try:
            response = requests.get(
                url, headers=headers, timeout=timeout, verify=verify_ssl,
            )
            if response.status_code == 200:
                return response.json() or {}
            if response.status_code in (429, 500, 502, 503, 504) and attempt < max_retries:
                print(f"  [retry {attempt}/{max_retries}] HTTP {response.status_code}, retrying in {retry_delay}s ...")
                time.sleep(retry_delay)
                continue
            response.raise_for_status()
        except requests.RequestException as exc:
            last_error = exc
            if attempt < max_retries:
                print(f"  [retry {attempt}/{max_retries}] {exc}, retrying in {retry_delay}s ...")
                time.sleep(retry_delay)
            else:
                raise SystemExit(f"ERROR: Failed to fetch certificate feed: {last_error}") from exc

    raise SystemExit(f"ERROR: Failed to fetch certificate feed: {last_error}")


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _extract_certificate_threatname(entry: dict) -> str:
    for key in (
        "threatname", "threat_name", "threatName", "zscaler_name",
        "malware_name", "family_name", "signature", "classification",
    ):
        value = entry.get(key)
        if isinstance(value, dict):
            value = value.get("name") or value.get("title") or value.get("value")
        text = str(value or "").strip()
        if text:
            return text
    return ""


def parse_certificate_feed(
    feed: dict,
    risk_value: int,
) -> Tuple[List[str], Dict[str, str]]:
    data = feed.get("data", feed) if isinstance(feed, dict) else {}
    catalog = data.get("code_signing_certificates", data) if isinstance(data, dict) else {}
    fingerprints = catalog.get("fingerprints", []) if isinstance(catalog, dict) else []

    md5s: List[str] = []
    threatname_map: Dict[str, str] = {}
    expected_risk = str(risk_value)

    for entry in fingerprints:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("risk") or "").strip() != expected_risk:
            continue

        fingerprint = str(entry.get("md5_fingerprint") or "").strip().lower()
        if not fingerprint:
            continue
        if fingerprint not in md5s:
            md5s.append(fingerprint)

        threatname = _extract_certificate_threatname(entry)
        if threatname and fingerprint not in threatname_map:
            threatname_map[fingerprint] = threatname

    return md5s, threatname_map


# ---------------------------------------------------------------------------
# Snapshot I/O
# ---------------------------------------------------------------------------

SNAPSHOT_VERSION = 2


def _build_content_hash(md5s: List[str], threatnames: Optional[Dict[str, str]] = None) -> str:
    payload = json.dumps(
        {"clean_cert_md5s": sorted(md5s or []), "cert_threatnames": threatnames or {}},
        sort_keys=True, ensure_ascii=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _load_existing_snapshot(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _diff_new_values(previous: List[str], current: List[str]) -> List[str]:
    previous_set = set(previous or [])
    return [v for v in current if v and v not in previous_set]


def write_clean_snapshot(md5s: List[str], output_dir: Path, source_url: str) -> dict:
    snapshot_path = output_dir / "zintel_clean_certificates.json"
    previous = _load_existing_snapshot(snapshot_path)
    previous_md5s = previous.get("clean_cert_md5s", []) or []
    previous_hash = previous.get("content_hash", "")
    content_hash = _build_content_hash(md5s)
    new_md5s = _diff_new_values(previous_md5s, md5s)
    snapshot_updated = content_hash != previous_hash or not snapshot_path.exists()
    synced_at = datetime.now(timezone.utc).isoformat()
    payload = {
        "snapshot_version": SNAPSHOT_VERSION, "last_sync_at": synced_at,
        "content_hash": content_hash, "risk_filter": -127,
        "source_url": source_url, "clean_cert_md5_count": len(md5s),
        "new_clean_cert_md5_count": len(new_md5s), "clean_cert_md5s": md5s,
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    snapshot_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return {"type": "clean", "snapshot_path": str(snapshot_path), "total_md5s": len(md5s),
            "new_md5s": len(new_md5s), "snapshot_updated": snapshot_updated,
            "content_hash": content_hash, "synced_at": synced_at}


def write_malicious_snapshot(md5s: List[str], threatnames: Dict[str, str],
                             output_dir: Path, source_url: str) -> dict:
    snapshot_path = output_dir / "zintel_malicious_certificates.json"
    previous = _load_existing_snapshot(snapshot_path)
    previous_md5s = previous.get("malicious_cert_md5s", []) or []
    previous_hash = previous.get("content_hash", "")
    content_hash = _build_content_hash(md5s, threatnames)
    new_md5s = _diff_new_values(previous_md5s, md5s)
    snapshot_updated = content_hash != previous_hash or not snapshot_path.exists()
    synced_at = datetime.now(timezone.utc).isoformat()
    payload = {
        "snapshot_version": SNAPSHOT_VERSION, "last_sync_at": synced_at,
        "content_hash": content_hash, "risk_filter": 127,
        "source_url": source_url, "malicious_cert_md5_count": len(md5s),
        "malicious_cert_threatname_count": len(threatnames),
        "new_malicious_cert_md5_count": len(new_md5s),
        "malicious_cert_md5s": md5s, "malicious_cert_threatnames": threatnames,
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    snapshot_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return {"type": "malicious", "snapshot_path": str(snapshot_path), "total_md5s": len(md5s),
            "total_threatnames": len(threatnames), "new_md5s": len(new_md5s),
            "snapshot_updated": snapshot_updated, "content_hash": content_hash, "synced_at": synced_at}


# ---------------------------------------------------------------------------
# Loading helpers (used by zintel_cert_checker.py)
# ---------------------------------------------------------------------------

def load_clean_cert_hashes(snapshot_path: str | Path) -> List[str]:
    path = Path(snapshot_path)
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data.get("clean_cert_md5s", []) or []
    except Exception:
        return []


def load_malicious_cert_hashes(snapshot_path: str | Path) -> Tuple[List[str], Dict[str, str]]:
    path = Path(snapshot_path)
    if not path.exists():
        return [], {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        md5s = data.get("malicious_cert_md5s", []) or []
        threatnames = data.get("malicious_cert_threatnames", {}) or {}
        return md5s, threatnames
    except Exception:
        return [], {}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Sync certificate catalogs from Zintel.")
    parser.add_argument("--api-key", default=os.environ.get("ZINTEL_API_KEY", ""))
    parser.add_argument("--url", default=os.environ.get("ZINTEL_URL", "https://z-intel-plus.corp.zscaler.com/"))
    parser.add_argument("--output-dir", "-o", default=".")
    parser.add_argument("--catalog", choices=["clean", "malicious", "both"], default="both")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--no-verify-ssl", action="store_true")
    parser.add_argument("--quiet", "-q", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    if not args.api_key:
        print("ERROR: No API key. Set ZINTEL_API_KEY or use --api-key.", file=sys.stderr)
        sys.exit(1)
    output_dir = Path(args.output_dir)
    source_url = f"{args.url.rstrip('/')}/api/research/sample/certificates/feeds/"
    if not args.quiet:
        print(f"Fetching certificate feed from {source_url} ...")
    feed = fetch_certificate_feed(
        api_key=args.api_key, base_url=args.url,
        timeout=args.timeout, verify_ssl=not args.no_verify_ssl,
    )
    if args.catalog in ("clean", "both"):
        clean_md5s, _ = parse_certificate_feed(feed, risk_value=-127)
        s = write_clean_snapshot(clean_md5s, output_dir, source_url)
        if not args.quiet:
            print(f"  Clean: {s['total_md5s']} hashes, +{s['new_md5s']} new  [{'UPDATED' if s['snapshot_updated'] else 'unchanged'}]")
    if args.catalog in ("malicious", "both"):
        mal_md5s, mal_t = parse_certificate_feed(feed, risk_value=127)
        s = write_malicious_snapshot(mal_md5s, mal_t, output_dir, source_url)
        if not args.quiet:
            print(f"  Malicious: {s['total_md5s']} hashes, {s['total_threatnames']} threats, +{s['new_md5s']} new  [{'UPDATED' if s['snapshot_updated'] else 'unchanged'}]")
    if not args.quiet:
        print("Done.")


if __name__ == "__main__":
    main()
