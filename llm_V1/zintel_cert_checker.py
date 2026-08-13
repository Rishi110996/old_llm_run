"""
zintel_cert_checker.py
----------------------
Loads Zintel clean/malicious certificate catalogs and provides fast lookup.
Syncs from Zintel API at most once per day (24 h cooldown).
Between syncs the catalogs are served from local JSON snapshots.

Usage:
    from zintel_cert_checker import check_cert_md5
    result = check_cert_md5("abcdef1234567890abcdef1234567890")
    # {"status": "clean"} | {"status": "malicious", "threatname": "..."} | {"status": "unknown"}
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Set

logger = logging.getLogger(__name__)

_SCRIPT_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
_CATALOG_DIR = _SCRIPT_DIR / "cert_catalogs"
_CLEAN_PATH = _CATALOG_DIR / "zintel_clean_certificates.json"
_MALICIOUS_PATH = _CATALOG_DIR / "zintel_malicious_certificates.json"
_SYNC_INTERVAL = 86400  # 24 hours

_lock = threading.Lock()
_clean_set: Set[str] = set()
_malicious_set: Set[str] = set()
_malicious_threatnames: Dict[str, str] = {}
_last_sync_time: float = 0.0
_loaded: bool = False


def _read_snapshot_sync_time(path: Path) -> float:
    if not path.exists():
        return 0.0
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        ts = data.get("last_sync_at", "")
        if ts:
            return datetime.fromisoformat(ts).timestamp()
    except Exception:
        pass
    return 0.0


def _load_catalogs() -> None:
    global _clean_set, _malicious_set, _malicious_threatnames, _loaded

    if _CLEAN_PATH.exists():
        try:
            data = json.loads(_CLEAN_PATH.read_text(encoding="utf-8"))
            _clean_set = {h.strip().lower() for h in (data.get("clean_cert_md5s") or []) if h}
        except Exception as e:
            logger.warning("Failed to load clean cert catalog: %s", e)
            _clean_set = set()
    else:
        _clean_set = set()

    if _MALICIOUS_PATH.exists():
        try:
            data = json.loads(_MALICIOUS_PATH.read_text(encoding="utf-8"))
            _malicious_set = {h.strip().lower() for h in (data.get("malicious_cert_md5s") or []) if h}
            raw = data.get("malicious_cert_threatnames") or {}
            _malicious_threatnames = {k.strip().lower(): v for k, v in raw.items()}
        except Exception as e:
            logger.warning("Failed to load malicious cert catalog: %s", e)
            _malicious_set = set()
            _malicious_threatnames = {}
    else:
        _malicious_set = set()
        _malicious_threatnames = {}

    _loaded = True
    logger.info("Zintel certs loaded: %d clean, %d malicious", len(_clean_set), len(_malicious_set))


def _try_sync() -> None:
    global _last_sync_time

    api_key = os.environ.get("ZINTEL_API_KEY", "")
    base_url = os.environ.get("ZINTEL_URL", "https://z-intel-plus.corp.zscaler.com/")
    if not api_key:
        return

    now = time.time()

    # On first call, check file timestamps to avoid re-syncing
    if _last_sync_time == 0.0:
        file_sync = max(_read_snapshot_sync_time(_CLEAN_PATH), _read_snapshot_sync_time(_MALICIOUS_PATH))
        if file_sync > 0 and (now - file_sync) < _SYNC_INTERVAL:
            _last_sync_time = file_sync
            logger.debug("Zintel sync: last sync %.1fh ago, skipping", (now - file_sync) / 3600)
            return

    if _last_sync_time > 0 and (now - _last_sync_time) < _SYNC_INTERVAL:
        return

    logger.info("Zintel cert sync: syncing (24h interval)...")
    try:
        from sync_certificate_catalog import (
            fetch_certificate_feed, parse_certificate_feed,
            write_clean_snapshot, write_malicious_snapshot,
        )
        feed_url = f"{base_url.rstrip('/')}/api/research/sample/certificates/feeds/"
        feed = fetch_certificate_feed(api_key=api_key, base_url=base_url, timeout=30, verify_ssl=True)
        clean_md5s, _ = parse_certificate_feed(feed, risk_value=-127)
        write_clean_snapshot(clean_md5s, _CATALOG_DIR, feed_url)
        mal_md5s, mal_tn = parse_certificate_feed(feed, risk_value=127)
        write_malicious_snapshot(mal_md5s, mal_tn, _CATALOG_DIR, feed_url)
        _last_sync_time = now
        logger.info("Zintel sync done: %d clean, %d malicious", len(clean_md5s), len(mal_md5s))
        _load_catalogs()
    except Exception as e:
        logger.warning("Zintel sync failed (retry in 10m): %s", e)
        _last_sync_time = now - _SYNC_INTERVAL + 600


def _ensure_loaded() -> None:
    with _lock:
        if not _loaded:
            _load_catalogs()
        _try_sync()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_cert_md5(cert_md5: str) -> Dict[str, str]:
    """Check cert MD5 against Zintel catalogs.
    Returns: {"status": "clean"|"malicious"|"unknown", "threatname": "..."}
    """
    _ensure_loaded()
    normalized = (cert_md5 or "").strip().lower()
    if not normalized:
        return {"status": "unknown"}
    if normalized in _malicious_set:
        return {"status": "malicious", "threatname": _malicious_threatnames.get(normalized, "")}
    if normalized in _clean_set:
        return {"status": "clean"}
    return {"status": "unknown"}


def get_catalog_stats() -> Dict[str, int]:
    _ensure_loaded()
    return {"clean_count": len(_clean_set), "malicious_count": len(_malicious_set)}
