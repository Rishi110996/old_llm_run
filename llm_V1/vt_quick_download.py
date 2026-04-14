"""
vt_quick_download.py
---------------------
Quickly downloads one or more APKs from VirusTotal by SHA256.
Uses the premium key from vt_apk_downloader/config.yaml.

Usage:
    python vt_quick_download.py --sha256 <hash> --out-dir <dir>
    python vt_quick_download.py --query "type:apk and p:0 and size:100KB-500KB" --count 1 --out-dir <dir>

Examples:
    # Download a specific known sample (e.g. Anubis banker)
    python vt_quick_download.py --sha256 <hash> --out-dir E:\\Malware\\sample

    # Download 1 benign APK (0 detections)
    python vt_quick_download.py --query "type:apk and p:0 and size:50KB-400KB" --count 1 --out-dir E:\\Malware\\sample

    # Download 1 known banking trojan by family tag
    python vt_quick_download.py --query "type:apk and engines:Bankbot and p:20+" --count 1 --out-dir E:\\Malware\\sample
"""
from __future__ import annotations

import argparse
import io
import json
import os
import sys
from typing import List, Optional

import requests
import yaml

if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "buffer"):
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
VT_BASE = "https://www.virustotal.com/api/v3"


def _load_premium_key() -> Optional[str]:
    config_path = os.path.join(
        os.path.dirname(_SCRIPT_DIR), "vt_apk_downloader", "config.yaml"
    )
    if not os.path.isfile(config_path):
        return None
    with open(config_path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    for k in cfg.get("api", {}).get("keys", []):
        if k.get("tier") == "premium" and k.get("key"):
            return str(k["key"])
    return None


def _search(api_key: str, query: str, limit: int) -> List[dict]:
    """Run VT Intelligence search and return file objects."""
    headers = {"x-apikey": api_key}
    params = {"query": query, "limit": min(limit, 40)}
    r = requests.get(f"{VT_BASE}/intelligence/search",
                     headers=headers, params=params, timeout=30)
    r.raise_for_status()
    return r.json().get("data", [])


def _download_apk(api_key: str, sha256: str, dest_path: str) -> bool:
    """Download APK binary. Returns True on success."""
    headers = {"x-apikey": api_key}
    tmp = dest_path + ".part"
    try:
        with requests.get(
            f"{VT_BASE}/files/{sha256}/download",
            headers=headers, timeout=120, stream=True
        ) as r:
            if not r.ok:
                print(f"  [!] Download HTTP {r.status_code} for {sha256[:16]}")
                return False
            os.makedirs(os.path.dirname(dest_path) or ".", exist_ok=True)
            with open(tmp, "wb") as f:
                for chunk in r.iter_content(chunk_size=1024 * 512):
                    f.write(chunk)
        # Verify ZIP magic
        with open(tmp, "rb") as f:
            magic = f.read(4)
        if magic != b"PK\x03\x04":
            os.remove(tmp)
            print(f"  [!] Not a valid ZIP/APK for {sha256[:16]}")
            return False
        os.replace(tmp, dest_path)
        size_kb = os.path.getsize(dest_path) // 1024
        print(f"  [+] Saved {dest_path}  ({size_kb} KB)")
        return True
    except Exception as exc:
        print(f"  [!] Download error: {exc}")
        if os.path.exists(tmp):
            os.remove(tmp)
        return False


def _get_file_info(api_key: str, sha256: str) -> dict:
    """Fetch file report attributes."""
    headers = {"x-apikey": api_key}
    r = requests.get(f"{VT_BASE}/files/{sha256}",
                     headers=headers, timeout=20)
    if not r.ok:
        return {}
    attrs = r.json().get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "sha256": sha256,
        "meaningful_name": attrs.get("meaningful_name", ""),
        "type_tag": attrs.get("type_tag", ""),
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "size": attrs.get("size", 0),
        "threat_label": attrs.get("popular_threat_classification", {}).get("suggested_threat_label", ""),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Quick VT APK downloader.")
    ap.add_argument("--sha256", default=None,
                    help="Specific SHA256 to download")
    ap.add_argument("--query", default=None,
                    help="VT Intelligence search query to find samples")
    ap.add_argument("--count", type=int, default=1,
                    help="Number of samples to download from query results")
    ap.add_argument("--out-dir", default="E:\\Malware\\sample",
                    help="Destination directory for downloaded APKs")
    ap.add_argument("--max-size-kb", type=int, default=6000,
                    help="Skip APKs larger than this many KB")
    ap.add_argument("--rename", action="store_true", default=False,
                    help="Save as <sha256>.apk instead of bare sha256")
    args = ap.parse_args()

    api_key = _load_premium_key()
    if not api_key:
        print("ERROR: No premium VT key found in vt_apk_downloader/config.yaml", file=sys.stderr)
        return 1
    print(f"[+] VT premium key loaded")
    print(f"[+] Output dir: {args.out_dir}")
    os.makedirs(args.out_dir, exist_ok=True)

    sha256s: List[dict] = []

    if args.sha256:
        # Direct download
        info = _get_file_info(api_key, args.sha256)
        info["sha256"] = args.sha256
        sha256s.append(info)

    elif args.query:
        print(f"[+] Searching VT: {args.query}")
        items = _search(api_key, args.query, args.count + 20)
        for item in items:
            attrs = item.get("attributes", {})
            sha = attrs.get("sha256") or item.get("id", "")
            if not sha:
                continue
            size_bytes = attrs.get("size", 0)
            if size_bytes and size_bytes > args.max_size_kb * 1024:
                print(f"  [skip] {sha[:16]}  size={size_bytes//1024}KB > limit")
                continue
            type_tag = str(attrs.get("type_tag") or "").lower()
            tags = {str(t).lower() for t in (attrs.get("tags") or [])}
            name = str(attrs.get("meaningful_name") or "").lower()
            if type_tag != "apk" and "apk" not in tags and not name.endswith(".apk"):
                print(f"  [skip] {sha[:16]}  not APK (type_tag={type_tag})")
                continue
            stats = attrs.get("last_analysis_stats", {})
            sha256s.append({
                "sha256": sha,
                "meaningful_name": attrs.get("meaningful_name", ""),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "size": size_bytes,
                "threat_label": attrs.get("popular_threat_classification", {}).get("suggested_threat_label", ""),
            })
            if len(sha256s) >= args.count:
                break
    else:
        print("ERROR: provide --sha256 or --query", file=sys.stderr)
        return 1

    if not sha256s:
        print("[!] No samples found / matched filters.")
        return 0

    print(f"[+] Downloading {len(sha256s)} sample(s)...")
    downloaded = 0
    for info in sha256s:
        sha = info["sha256"]
        name = info.get("meaningful_name") or sha
        mal = info.get("malicious", "?")
        size_kb = (info.get("size") or 0) // 1024
        label = info.get("threat_label", "")
        print(f"\n  SHA256 : {sha}")
        print(f"  Name   : {name}")
        print(f"  Size   : {size_kb} KB")
        print(f"  AV hits: {mal}")
        print(f"  Label  : {label or 'none'}")

        filename = f"{sha}.apk" if args.rename else sha
        dest = os.path.join(args.out_dir, filename)

        if os.path.isfile(dest):
            print(f"  [=] Already exists, skipping")
            downloaded += 1
            continue

        ok = _download_apk(api_key, sha, dest)
        if ok:
            downloaded += 1
            # Write a small metadata sidecar
            meta_path = dest + ".meta.json"
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(info, f, indent=2, ensure_ascii=False)

    print(f"\n[+] Downloaded {downloaded}/{len(sha256s)} sample(s) to {args.out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
