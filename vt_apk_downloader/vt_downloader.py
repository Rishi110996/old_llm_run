"""vt_downloader.py

This project builds an Android APK dataset from VirusTotal (VT) Intelligence Search.

It supports:
  - Per-family (malicious) hash lists + JSONL metadata
  - A benign hash list + JSONL metadata
  - Optional APK binary downloads for a small batch of newly collected samples
  - Optional analysis + cleanup of each downloaded batch to reduce storage pressure
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import dataclasses
import datetime as dt
import json
import os
import random
import re
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

import requests
import yaml
from tqdm import tqdm


class VTApiError(RuntimeError):
    def __init__(self, status_code: int, message: str, details: Optional[dict] = None):
        super().__init__(f"VT API error {status_code}: {message}")
        self.status_code = status_code
        self.message = message
        self.details = details or {}


class AllKeysExhaustedError(RuntimeError):
    pass


def _vt_error_message(err: VTApiError) -> str:
    """Extract a human message from VTApiError details if possible."""
    try:
        if isinstance(err.details, dict):
            e = err.details.get("error")
            if isinstance(e, dict) and e.get("message"):
                return str(e.get("message"))
    except Exception:
        pass
    return str(getattr(err, "message", "") or "")


def classify_download_error(err: Exception) -> Dict[str, Any]:
    reason = str(err)
    permanent = False

    if isinstance(err, VTApiError):
        message = _vt_error_message(err).lower()
        if err.status_code in {400, 404, 410, 422}:
            permanent = True
        elif any(
            token in message
            for token in (
                "not found",
                "not available",
                "is not downloadable",
                "not downloadable",
                "download is not allowed",
                "unsupported",
            )
        ):
            permanent = True

    return {
        "reason": reason,
        "permanent": permanent,
    }


@dataclasses.dataclass
class ApiKey:
    name: str
    value: str
    tier: str  # "free" | "premium"
    disabled: bool = False
    cooldown_until_utc: dt.datetime = dataclasses.field(
        default_factory=lambda: dt.datetime.fromtimestamp(0, tz=dt.timezone.utc)
    )
    last_error: str = ""

    # Ensures a key is not used concurrently by multiple threads.
    in_flight_lock: threading.Lock = dataclasses.field(
        default_factory=threading.Lock,
        repr=False,
        compare=False,
    )

    def is_available(self, now_utc: dt.datetime) -> bool:
        return (not self.disabled) and (now_utc >= self.cooldown_until_utc)


class KeyRing:
    def __init__(
        self,
        keys: List[ApiKey],
        exhausted_sleep_hours: float = 24.0,
        stop_when_exhausted: bool = False,
    ):
        if not keys:
            raise ValueError("No API keys configured")
        self._keys = keys
        self._idx = 0
        self._exhausted_sleep_hours = exhausted_sleep_hours
        self._stop_when_exhausted = bool(stop_when_exhausted)
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)

    def next_available_key(
        self,
        required_tier: Optional[str],
        *,
        reserve_for_sec: float = 0.0,
    ) -> Optional[ApiKey]:
        """Select an available key (round-robin), optionally reserving it.

        reserve_for_sec:
          If > 0, the returned key is immediately placed in cooldown for that many
          seconds so other threads won't pick it in parallel.
        """

        now = dt.datetime.now(tz=dt.timezone.utc)
        with self._lock:
            n = len(self._keys)
            for _ in range(n):
                k = self._keys[self._idx]
                self._idx = (self._idx + 1) % n
                if required_tier and k.tier != required_tier:
                    continue
                if k.is_available(now):
                    # Avoid concurrent use of the same key.
                    if not k.in_flight_lock.acquire(blocking=False):
                        continue
                    if reserve_for_sec > 0:
                        k.cooldown_until_utc = max(
                            k.cooldown_until_utc,
                            now + dt.timedelta(seconds=float(reserve_for_sec)),
                        )
                    return k
        return None

    def release_key(self, key: ApiKey) -> None:
        # Release the per-key in-flight lock and wake any waiter.
        try:
            key.in_flight_lock.release()
        finally:
            with self._lock:
                self._cond.notify_all()

    def any_key_available(self, required_tier: Optional[str]) -> bool:
        now = dt.datetime.now(tz=dt.timezone.utc)
        with self._lock:
            for k in self._keys:
                if required_tier and k.tier != required_tier:
                    continue
                if not k.is_available(now):
                    continue

                # Consider in-flight usage.
                if k.in_flight_lock.acquire(blocking=False):
                    k.in_flight_lock.release()
                    return True
            return False

    def sleep_if_exhausted(self, required_tier: Optional[str]) -> None:
        max_sleep_sec = float(self._exhausted_sleep_hours) * 3600.0
        start = time.monotonic()

        while not self.any_key_available(required_tier):
            # Determine a sensible sleep duration:
            # - If the soonest cooldown is in the future, wait until then.
            # - If cooldowns have passed but keys are just busy (in-flight), wait briefly and
            #   rely on release_key() notifications.
            now_dt = dt.datetime.now(tz=dt.timezone.utc)
            with self._lock:
                eligible = [
                    k
                    for k in self._keys
                    if (not k.disabled) and (not required_tier or k.tier == required_tier)
                ]

                if not eligible:
                    raise AllKeysExhaustedError(
                        f"All API keys are disabled (tier requirement: {required_tier!r})."
                    )

                if self._stop_when_exhausted:
                    raise AllKeysExhaustedError(
                        f"All eligible API keys are exhausted or cooling down (tier={required_tier!r})."
                    )

                soonest = min(k.cooldown_until_utc for k in eligible)

                wait_sec = max(0.0, (soonest - now_dt).total_seconds())
                if wait_sec <= 0:
                    wait_sec = 0.25

                elapsed = time.monotonic() - start
                if elapsed >= max_sleep_sec:
                    raise AllKeysExhaustedError(
                        f"All eligible API keys remain exhausted after waiting (tier={required_tier!r})."
                    )

                wait_sec = min(wait_sec, max_sleep_sec - elapsed)

                print(
                    f"[keyring] No key available (tier={required_tier!r}). "
                    f"Waiting for {wait_sec:.2f}s..."
                )
                self._cond.wait(timeout=wait_sec)

    def snapshot(self, required_tier: Optional[str] = None) -> List[dict]:
        now = dt.datetime.now(tz=dt.timezone.utc)
        rows: List[dict] = []
        with self._lock:
            for key in self._keys:
                if required_tier and key.tier != required_tier:
                    continue

                in_flight = key.in_flight_lock.locked()
                cooldown_remaining_sec = max(
                    0.0, (key.cooldown_until_utc - now).total_seconds()
                )
                if key.disabled:
                    status = "disabled"
                elif in_flight:
                    status = "in_flight"
                elif cooldown_remaining_sec > 0:
                    status = "cooling_down"
                else:
                    status = "eligible"

                rows.append(
                    {
                        "name": key.name,
                        "tier": key.tier,
                        "status": status,
                        "cooldown_remaining_sec": round(cooldown_remaining_sec, 3),
                        "last_error": key.last_error,
                    }
                )
        return rows


class VTClient:
    def __init__(
        self,
        base_url: str,
        keyring: KeyRing,
        timeout_sec: int,
        max_attempts_per_request: int,
        backoff_initial_sec: float,
        backoff_max_sec: float,
        per_key_min_interval_sec: Optional[Dict[str, float]] = None,
        global_min_interval_sec: float = 0.0,
        max_in_flight_requests: int = 0,
        jitter_sec: float = 0.0,
        user_agent: str = "vt-apk-dataset-builder/1.0",
    ):
        self._base_url = base_url.rstrip("/")
        self._keyring = keyring
        self._timeout_sec = timeout_sec
        self._max_attempts = max_attempts_per_request
        self._backoff_initial = backoff_initial_sec
        self._backoff_max = backoff_max_sec
        self._per_key_min_interval_sec = per_key_min_interval_sec or {}
        self._global_min_interval_sec = float(global_min_interval_sec or 0.0)
        self._jitter_sec = float(jitter_sec or 0.0)
        self._tls = threading.local()

        self._global_lock = threading.Lock()
        self._global_next_allowed_mono = time.monotonic()

        self._in_flight: Optional[threading.Semaphore] = None
        if int(max_in_flight_requests or 0) > 0:
            self._in_flight = threading.BoundedSemaphore(int(max_in_flight_requests))

        self._user_agent = user_agent

    def _get_session(self) -> requests.Session:
        sess = getattr(self._tls, "session", None)
        if sess is None:
            sess = requests.Session()
            sess.headers.update({"User-Agent": self._user_agent})
            self._tls.session = sess
        return sess

    def _sleep(self, seconds: float) -> None:
        if seconds <= 0:
            return
        jitter = random.uniform(0.0, self._jitter_sec) if self._jitter_sec > 0 else 0.0
        time.sleep(seconds + jitter)

    def _throttle_global(self) -> None:
        """Optional global pacing across *all* requests (across keys/threads)."""
        if self._global_min_interval_sec <= 0:
            return

        sleep_for = 0.0
        with self._global_lock:
            now = time.monotonic()
            if now < self._global_next_allowed_mono:
                sleep_for = self._global_next_allowed_mono - now
                self._global_next_allowed_mono += self._global_min_interval_sec
            else:
                self._global_next_allowed_mono = now + self._global_min_interval_sec

        self._sleep(sleep_for)

    def request_json(
        self,
        method: str,
        path: str,
        *,
        required_tier: Optional[str] = None,
        params: Optional[dict] = None,
    ) -> dict:
        """Make a VT API call with key rotation + backoff.

        required_tier:
          - None: any key
          - "premium": only premium keys
          - "free": only free keys
        """

        backoff = float(self._backoff_initial)
        last_err: Optional[Exception] = None

        for _attempt in range(1, self._max_attempts + 1):
            # Per-key pacing. We keep this simple: one interval per tier.
            reserve_sec = 0.0
            if required_tier:
                reserve_sec = float(self._per_key_min_interval_sec.get(required_tier) or 0.0)
                # Safe defaults if the user didn't configure throttling.
                if reserve_sec <= 0:
                    reserve_sec = 1.0 if required_tier == "premium" else 15.0

            key = self._keyring.next_available_key(required_tier, reserve_for_sec=reserve_sec)
            if key is None:
                self._keyring.sleep_if_exhausted(required_tier)
                key = self._keyring.next_available_key(required_tier, reserve_for_sec=reserve_sec)
                if key is None:
                    raise RuntimeError("No API key available even after exhaustion sleep")

            try:
                url = f"{self._base_url}{path}"
                headers = {"x-apikey": key.value}

                try:
                    if self._in_flight:
                        self._in_flight.acquire()
                    try:
                        self._throttle_global()
                        sess = self._get_session()
                        resp = sess.request(
                            method,
                            url,
                            headers=headers,
                            params=params,
                            timeout=self._timeout_sec,
                        )
                    finally:
                        if self._in_flight:
                            self._in_flight.release()
                except requests.RequestException as e:
                    last_err = e
                    key.last_error = f"network_error: {e}"
                    key.cooldown_until_utc = max(
                        key.cooldown_until_utc,
                        dt.datetime.now(tz=dt.timezone.utc)
                        + dt.timedelta(seconds=min(30, float(backoff))),
                    )
                    self._sleep(min(self._backoff_max, backoff))
                    backoff = min(self._backoff_max, backoff * 2)
                    continue

                # Handle key-level failures
                if resp.status_code == 429:
                    retry_after = _parse_retry_after_seconds(resp.headers.get("Retry-After"))
                    cooldown_sec = (
                        int(retry_after)
                        if retry_after is not None
                        else min(900, int(backoff))
                    )
                    key.last_error = "rate_limited"
                    key.cooldown_until_utc = max(
                        key.cooldown_until_utc,
                        dt.datetime.now(tz=dt.timezone.utc)
                        + dt.timedelta(seconds=cooldown_sec),
                    )
                    continue

                if resp.status_code in (401, 403):
                    # Likely invalid key or endpoint not allowed for this key/plan.
                    key.disabled = True
                    key.last_error = f"unauthorized_or_forbidden ({resp.status_code})"
                    continue

                if resp.status_code >= 500:
                    key.last_error = f"server_error ({resp.status_code})"
                    self._sleep(min(self._backoff_max, backoff))
                    backoff = min(self._backoff_max, backoff * 2)
                    continue

                if not resp.ok:
                    # Non-retriable client error (usually query syntax, etc.)
                    try:
                        payload = resp.json()
                    except Exception:
                        payload = None
                    raise VTApiError(resp.status_code, resp.text[:500], payload)

                return resp.json()

            finally:
                # Release the per-key lock so other threads can use this key.
                try:
                    self._keyring.release_key(key)
                except RuntimeError:
                    # Defensive: if something went wrong and the lock isn't held.
                    pass

        if last_err:
            raise RuntimeError(f"VT request failed after retries: {last_err}")
        raise RuntimeError("VT request failed after retries")

    def download_file(
        self,
        sha256: str,
        dest_path: str,
        *,
        required_tier: Optional[str] = "premium",
    ) -> None:
        """Download a file from VT to dest_path with key rotation + backoff."""

        backoff = float(self._backoff_initial)
        last_err: Optional[Exception] = None
        temp_path = f"{dest_path}.part"

        for _attempt in range(1, self._max_attempts + 1):
            reserve_sec = 0.0
            if required_tier:
                reserve_sec = float(self._per_key_min_interval_sec.get(required_tier) or 0.0)
                if reserve_sec <= 0:
                    reserve_sec = 1.0 if required_tier == "premium" else 15.0

            key = self._keyring.next_available_key(required_tier, reserve_for_sec=reserve_sec)
            if key is None:
                self._keyring.sleep_if_exhausted(required_tier)
                key = self._keyring.next_available_key(required_tier, reserve_for_sec=reserve_sec)
                if key is None:
                    raise RuntimeError("No API key available even after exhaustion sleep")

            try:
                url = f"{self._base_url}/files/{sha256}/download"
                headers = {"x-apikey": key.value}

                try:
                    if self._in_flight:
                        self._in_flight.acquire()
                    try:
                        self._throttle_global()
                        sess = self._get_session()
                        with sess.get(
                            url,
                            headers=headers,
                            timeout=self._timeout_sec,
                            stream=True,
                        ) as resp:
                            if resp.status_code == 429:
                                retry_after = _parse_retry_after_seconds(
                                    resp.headers.get("Retry-After")
                                )
                                cooldown_sec = (
                                    int(retry_after)
                                    if retry_after is not None
                                    else min(900, int(backoff))
                                )
                                key.last_error = "rate_limited"
                                key.cooldown_until_utc = max(
                                    key.cooldown_until_utc,
                                    dt.datetime.now(tz=dt.timezone.utc)
                                    + dt.timedelta(seconds=cooldown_sec),
                                )
                                continue

                            if resp.status_code in (401, 403):
                                key.disabled = True
                                key.last_error = (
                                    f"unauthorized_or_forbidden ({resp.status_code})"
                                )
                                continue

                            if resp.status_code >= 500:
                                key.last_error = f"server_error ({resp.status_code})"
                                self._sleep(min(self._backoff_max, backoff))
                                backoff = min(self._backoff_max, backoff * 2)
                                continue

                            if not resp.ok:
                                try:
                                    payload = resp.json()
                                except Exception:
                                    payload = None
                                raise VTApiError(resp.status_code, resp.text[:500], payload)

                            ensure_dir(os.path.dirname(dest_path) or ".")
                            with open(temp_path, "wb") as f:
                                for chunk in resp.iter_content(chunk_size=1024 * 1024):
                                    if chunk:
                                        f.write(chunk)
                            os.replace(temp_path, dest_path)
                            return
                    finally:
                        if self._in_flight:
                            self._in_flight.release()
                except requests.RequestException as e:
                    last_err = e
                    key.last_error = f"network_error: {e}"
                    key.cooldown_until_utc = max(
                        key.cooldown_until_utc,
                        dt.datetime.now(tz=dt.timezone.utc)
                        + dt.timedelta(seconds=min(30, float(backoff))),
                    )
                    self._sleep(min(self._backoff_max, backoff))
                    backoff = min(self._backoff_max, backoff * 2)
                    continue
            finally:
                if os.path.exists(temp_path):
                    try:
                        os.remove(temp_path)
                    except OSError:
                        pass
                try:
                    self._keyring.release_key(key)
                except RuntimeError:
                    pass

        if last_err:
            raise RuntimeError(f"VT download failed after retries: {last_err}")
        raise RuntimeError(f"VT download failed after retries for {sha256}")


def _parse_retry_after_seconds(value: Optional[str]) -> Optional[int]:
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


class StateDB:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        # Each worker thread should use its own connection.
        # timeout helps when multiple threads commit concurrently.
        self.conn = sqlite3.connect(path, timeout=60)
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA busy_timeout=60000;")
        self._init()

    def _init(self) -> None:
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS samples (
              sha256 TEXT PRIMARY KEY,
              category TEXT NOT NULL,
              family TEXT,
              size INTEGER,
              malicious_count INTEGER,
              suspicious_count INTEGER,
              collected_at_utc TEXT NOT NULL
            );
            """
        )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_samples_cat_fam ON samples(category, family);"
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS catalog_samples (
              sha256 TEXT PRIMARY KEY,
              category TEXT NOT NULL,
              size INTEGER,
              malicious_count INTEGER,
              suspicious_count INTEGER,
              meaningful_name TEXT,
              downloadable INTEGER,
              first_indexed_at_utc TEXT NOT NULL,
              last_seen_at_utc TEXT NOT NULL
            );
            """
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sample_families (
              sha256 TEXT NOT NULL,
              family TEXT NOT NULL,
              PRIMARY KEY (sha256, family)
            );
            """
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS family_index_state (
              category TEXT NOT NULL,
              family TEXT NOT NULL,
              cursor TEXT,
              exhausted INTEGER NOT NULL DEFAULT 0,
              last_updated_at_utc TEXT NOT NULL,
              PRIMARY KEY (category, family)
            );
            """
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS download_states (
              sha256 TEXT PRIMARY KEY,
              status TEXT NOT NULL,
              permanent_failure INTEGER NOT NULL DEFAULT 0,
              fail_count INTEGER NOT NULL DEFAULT 0,
              last_error TEXT,
              last_attempt_at_utc TEXT NOT NULL
            );
            """
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS analysis_states (
              sha256 TEXT PRIMARY KEY,
              status TEXT NOT NULL,
              apk_name TEXT,
              source_report_dir TEXT,
              last_synced_at_utc TEXT NOT NULL
            );
            """
        )
        self.conn.commit()

    def has(self, sha256: str) -> bool:
        cur = self.conn.execute("SELECT 1 FROM samples WHERE sha256 = ? LIMIT 1;", (sha256,))
        return cur.fetchone() is not None

    def insert(
        self,
        *,
        sha256: str,
        category: str,
        family: Optional[str],
        size: Optional[int],
        malicious_count: Optional[int],
        suspicious_count: Optional[int],
    ) -> bool:
        now = dt.datetime.now(tz=dt.timezone.utc).isoformat()

        # Small retry loop for occasional lock contention in multi-threaded runs.
        for attempt in range(1, 11):
            try:
                before = self.conn.total_changes
                cur = self.conn.execute(
                    """
                    INSERT OR IGNORE INTO samples
                    (sha256, category, family, size, malicious_count, suspicious_count, collected_at_utc)
                    VALUES (?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        sha256,
                        category,
                        family,
                        size,
                        malicious_count,
                        suspicious_count,
                        now,
                    ),
                )
                self.conn.commit()
                # sqlite3 cursor.rowcount should be 1 (inserted) or 0 (ignored), but can be -1
                # in some edge cases/drivers; fall back to connection.total_changes delta.
                if cur.rowcount != -1:
                    return cur.rowcount == 1
                return self.conn.total_changes > before
            except sqlite3.OperationalError as e:
                msg = str(e).lower()
                if "locked" not in msg and "busy" not in msg:
                    raise
                time.sleep(min(1.0, 0.05 * attempt))

        raise sqlite3.OperationalError("state.sqlite remained locked after retries")

    def close(self) -> None:
        try:
            self.conn.commit()
        finally:
            self.conn.close()

    def count(self, *, category: str, family: Optional[str] = None) -> int:
        if family is None:
            cur = self.conn.execute(
                "SELECT COUNT(*) FROM samples WHERE category = ?;", (category,)
            )
        else:
            cur = self.conn.execute(
                "SELECT COUNT(*) FROM samples WHERE category = ? AND family = ?;",
                (category, family),
            )
        return int(cur.fetchone()[0])

    def upsert_catalog_sample(self, *, category: str, rec: dict) -> bool:
        now = dt.datetime.now(tz=dt.timezone.utc).isoformat()
        before = self.conn.total_changes
        self.conn.execute(
            """
            INSERT INTO catalog_samples
              (sha256, category, size, malicious_count, suspicious_count, meaningful_name,
               downloadable, first_indexed_at_utc, last_seen_at_utc)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(sha256) DO UPDATE SET
              category = excluded.category,
              size = COALESCE(excluded.size, catalog_samples.size),
              malicious_count = COALESCE(excluded.malicious_count, catalog_samples.malicious_count),
              suspicious_count = COALESCE(excluded.suspicious_count, catalog_samples.suspicious_count),
              meaningful_name = COALESCE(excluded.meaningful_name, catalog_samples.meaningful_name),
              downloadable = COALESCE(excluded.downloadable, catalog_samples.downloadable),
              last_seen_at_utc = excluded.last_seen_at_utc;
            """,
            (
                rec["sha256"],
                category,
                rec.get("size") if isinstance(rec.get("size"), int) else None,
                rec.get("malicious"),
                rec.get("suspicious"),
                rec.get("meaningful_name"),
                1 if rec.get("downloadable") else 0,
                now,
                now,
            ),
        )
        self.conn.commit()
        return self.conn.total_changes > before

    def add_family_mapping(self, *, sha256: str, family: str) -> None:
        self.conn.execute(
            """
            INSERT OR IGNORE INTO sample_families (sha256, family)
            VALUES (?, ?);
            """,
            (sha256, family),
        )
        self.conn.commit()

    def get_family_index_state(self, *, category: str, family: str) -> Dict[str, Any]:
        cur = self.conn.execute(
            """
            SELECT cursor, exhausted
            FROM family_index_state
            WHERE category = ? AND family = ?;
            """,
            (category, family),
        )
        row = cur.fetchone()
        if row is None:
            return {"cursor": None, "exhausted": False}
        return {"cursor": row[0], "exhausted": bool(row[1])}

    def update_family_index_state(
        self,
        *,
        category: str,
        family: str,
        cursor: Optional[str],
        exhausted: bool,
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO family_index_state (category, family, cursor, exhausted, last_updated_at_utc)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(category, family) DO UPDATE SET
              cursor = excluded.cursor,
              exhausted = excluded.exhausted,
              last_updated_at_utc = excluded.last_updated_at_utc;
            """,
            (
                category,
                family,
                cursor,
                1 if exhausted else 0,
                dt.datetime.now(tz=dt.timezone.utc).isoformat(),
            ),
        )
        self.conn.commit()

    def total_catalog_count(self, *, category: str) -> int:
        cur = self.conn.execute(
            "SELECT COUNT(*) FROM catalog_samples WHERE category = ?;",
            (category,),
        )
        return int(cur.fetchone()[0])

    def family_catalog_count(self, *, category: str, family: str) -> int:
        cur = self.conn.execute(
            """
            SELECT COUNT(*)
            FROM sample_families sf
            JOIN catalog_samples cs ON cs.sha256 = sf.sha256
            WHERE cs.category = ? AND sf.family = ?;
            """,
            (category, family),
        )
        return int(cur.fetchone()[0])

    def get_family_candidate_rows(
        self,
        *,
        category: str,
        families: List[str],
    ) -> List[dict]:
        if not families:
            return []
        placeholders = ",".join("?" for _ in families)
        cur = self.conn.execute(
            f"""
            SELECT sf.family, cs.sha256, cs.size, cs.malicious_count, cs.suspicious_count,
                   cs.meaningful_name, cs.downloadable
            FROM sample_families sf
            JOIN catalog_samples cs ON cs.sha256 = sf.sha256
            WHERE cs.category = ? AND sf.family IN ({placeholders})
            ORDER BY sf.family ASC, cs.size ASC, cs.sha256 ASC;
            """,
            [category, *families],
        )
        rows = []
        for row in cur.fetchall():
            rows.append(
                {
                    "family": row[0],
                    "sha256": row[1],
                    "size": row[2],
                    "malicious": row[3],
                    "suspicious": row[4],
                    "meaningful_name": row[5],
                    "downloadable": bool(row[6]) if row[6] is not None else True,
                    "category": category,
                }
            )
        return rows

    def record_download_success(self, *, sha256: str) -> None:
        self.conn.execute(
            """
            INSERT INTO download_states
              (sha256, status, permanent_failure, fail_count, last_error, last_attempt_at_utc)
            VALUES (?, 'downloaded', 0, 0, NULL, ?)
            ON CONFLICT(sha256) DO UPDATE SET
              status = 'downloaded',
              permanent_failure = 0,
              last_error = NULL,
              last_attempt_at_utc = excluded.last_attempt_at_utc;
            """,
            (
                sha256,
                dt.datetime.now(tz=dt.timezone.utc).isoformat(),
            ),
        )
        self.conn.commit()

    def record_download_failure(self, *, sha256: str, reason: str, permanent: bool) -> None:
        self.conn.execute(
            """
            INSERT INTO download_states
              (sha256, status, permanent_failure, fail_count, last_error, last_attempt_at_utc)
            VALUES (?, ?, ?, 1, ?, ?)
            ON CONFLICT(sha256) DO UPDATE SET
              status = excluded.status,
              permanent_failure = excluded.permanent_failure,
              fail_count = download_states.fail_count + 1,
              last_error = excluded.last_error,
              last_attempt_at_utc = excluded.last_attempt_at_utc;
            """,
            (
                sha256,
                "permanent_failed" if permanent else "retryable_failed",
                1 if permanent else 0,
                reason,
                dt.datetime.now(tz=dt.timezone.utc).isoformat(),
            ),
        )
        self.conn.commit()

    def is_permanent_download_failure(self, *, sha256: str) -> bool:
        cur = self.conn.execute(
            """
            SELECT permanent_failure
            FROM download_states
            WHERE sha256 = ?;
            """,
            (sha256,),
        )
        row = cur.fetchone()
        return bool(row[0]) if row is not None else False

    def record_analysis_status(
        self,
        *,
        sha256: str,
        status: str,
        apk_name: Optional[str],
        source_report_dir: str,
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO analysis_states
              (sha256, status, apk_name, source_report_dir, last_synced_at_utc)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(sha256) DO UPDATE SET
              status = excluded.status,
              apk_name = COALESCE(excluded.apk_name, analysis_states.apk_name),
              source_report_dir = excluded.source_report_dir,
              last_synced_at_utc = excluded.last_synced_at_utc;
            """,
            (
                sha256,
                status,
                apk_name,
                source_report_dir,
                dt.datetime.now(tz=dt.timezone.utc).isoformat(),
            ),
        )
        self.conn.commit()

    def get_analysis_status(self, *, sha256: str) -> Optional[str]:
        cur = self.conn.execute(
            """
            SELECT status
            FROM analysis_states
            WHERE sha256 = ?;
            """,
            (sha256,),
        )
        row = cur.fetchone()
        return str(row[0]) if row is not None else None

    def is_terminal_analysis_status(self, *, sha256: str) -> bool:
        status = self.get_analysis_status(sha256=sha256)
        return status in {"done", "corrupt"}


def vt_intelligence_search(
    client: VTClient,
    *,
    query: str,
    limit: int,
    cursor: Optional[str],
) -> Tuple[List[dict], Optional[str]]:
    params: Dict[str, Any] = {"query": query, "limit": limit}
    if cursor:
        params["cursor"] = cursor

    payload = client.request_json(
        "GET", "/intelligence/search", required_tier="premium", params=params
    )

    items = payload.get("data") or []
    next_cursor = None

    meta = payload.get("meta") or {}
    if isinstance(meta, dict) and meta.get("cursor"):
        next_cursor = meta.get("cursor")

    if not next_cursor:
        links = payload.get("links") or {}
        next_link = links.get("next") if isinstance(links, dict) else None
        if next_link:
            parsed = urlparse(next_link)
            qs = parse_qs(parsed.query)
            cur = qs.get("cursor")
            if cur:
                next_cursor = cur[0]

    return list(items), next_cursor


def extract_record(file_obj: dict) -> Optional[dict]:
    """Normalize a VT file object from Intelligence Search into our record."""
    if not isinstance(file_obj, dict):
        return None
    attrs = file_obj.get("attributes") or {}
    if not isinstance(attrs, dict):
        attrs = {}

    sha256 = attrs.get("sha256") or file_obj.get("id")
    if not sha256:
        return None

    size = attrs.get("size")
    stats = attrs.get("last_analysis_stats") or {}
    if not isinstance(stats, dict):
        stats = {}

    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    meaningful_name = attrs.get("meaningful_name")
    downloadable = attrs.get("downloadable")
    type_tag = attrs.get("type_tag")
    tags = attrs.get("tags") or []

    return {
        "sha256": sha256,
        "size": size,
        "malicious": malicious,
        "suspicious": suspicious,
        "meaningful_name": meaningful_name,
        "downloadable": True if downloadable is None else bool(downloadable),
        "type_tag": type_tag,
        "tags": list(tags) if isinstance(tags, list) else [],
        "raw": file_obj,
    }


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def append_line(path: str, line: str) -> None:
    with open(path, "a", encoding="utf-8") as f:
        f.write(line)
        f.write("\n")


def append_jsonl(path: str, obj: dict) -> None:
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False))
        f.write("\n")


def has_apk_magic(path: str) -> bool:
    if not os.path.isfile(path):
        return False
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"PK\x03\x04"
    except OSError:
        return False


def split_targets(total: int, families: List[str]) -> Dict[str, int]:
    if total < 0:
        raise ValueError("total must be >= 0")
    if not families:
        return {}
    base = total // len(families)
    rem = total % len(families)
    out: Dict[str, int] = {}
    for i, fam in enumerate(families):
        out[fam] = base + (1 if i < rem else 0)
    return out


def build_query(template: str, *, common: str, **kwargs: Any) -> str:
    return template.format(common=common, **kwargs)


def resolve_path(base_dir: str, configured_path: str) -> str:
    path = str(configured_path)
    if not os.path.isabs(path):
        path = os.path.join(base_dir, path)
    return os.path.abspath(path)


def sanitize_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
    return cleaned or "bucket"


def is_apk_record(rec: dict) -> bool:
    type_tag = str(rec.get("type_tag") or "").strip().lower()
    tags = {str(tag).strip().lower() for tag in (rec.get("tags") or []) if str(tag).strip()}
    meaningful_name = str(rec.get("meaningful_name") or "").strip().lower()

    if "faulty" in tags:
        return False

    if type_tag == "apk" or "apk" in tags:
        return True

    return meaningful_name.endswith(".apk")


def collect_category(
    *,
    client: VTClient,
    db: StateDB,
    output_dir: str,
    limit: int,
    max_size_bytes: int,
    category: str,
    family: Optional[str],
    target: int,
    query: str,
    predicate,
    show_progress: bool,
    max_new: Optional[int] = None,
) -> List[dict]:
    """Collect records for a single bucket (family or benign)."""

    bucket = family or "benign"
    bucket_dir = os.path.join(output_dir, bucket)
    ensure_dir(bucket_dir)

    hashes_path = os.path.join(bucket_dir, "hashes.txt")
    meta_path = os.path.join(bucket_dir, "metadata.jsonl")

    already = db.count(category=category, family=family)
    effective_target = target
    if max_new is not None:
        effective_target = min(effective_target, already + int(max_new))

    remaining = max(0, effective_target - already)
    if remaining == 0:
        print(f"[{category}:{bucket}] target already satisfied ({already}/{effective_target})")
        return []

    cursor = None
    added = 0
    new_records: List[dict] = []

    pbar = tqdm(total=remaining, desc=f"{category}:{bucket}") if show_progress else None

    try:
        while added < remaining:
            try:
                items, cursor = vt_intelligence_search(
                    client, query=query, limit=limit, cursor=cursor
                )
            except VTApiError as e:
                # VT returns 400 for invalid query syntax/fields/values.
                # For per-family collection, this often happens when the configured
                # family value isn't recognized by the query template (e.g. tag:{family}).
                # Don't crash the entire run; print actionable info and skip this bucket.
                if int(getattr(e, "status_code", 0)) == 400:
                    msg = _vt_error_message(e)
                    print(f"[{category}:{bucket}] VT query error (400): {msg}")
                    print(f"[{category}:{bucket}] Query was: {query}")
                    print(
                        f"[{category}:{bucket}] Hint: update `search.malicious_template` "
                        "and/or `dataset.malicious.families` in config.yaml to match your "
                        "VT tenant's query syntax / tag naming."
                    )
                    return new_records
                raise
            if not items:
                print(f"[{category}:{bucket}] no more results from search")
                break

            for it in items:
                rec = extract_record(it)
                if not rec:
                    continue
                if not is_apk_record(rec):
                    continue

                sha256 = rec["sha256"]

                size = rec.get("size")
                if isinstance(size, int) and size > max_size_bytes:
                    continue

                if not predicate(rec):
                    continue

                # Persist: insert into the global state DB first to guarantee global de-dup
                # across families/categories even when running with multiple workers.
                inserted = db.insert(
                    sha256=sha256,
                    category=category,
                    family=family,
                    size=rec.get("size") if isinstance(rec.get("size"), int) else None,
                    malicious_count=rec.get("malicious"),
                    suspicious_count=rec.get("suspicious"),
                )

                if not inserted:
                    continue

                append_line(hashes_path, sha256)
                append_jsonl(
                    meta_path,
                    {
                        "sha256": sha256,
                        "family": family,
                        "category": category,
                        "size": rec.get("size"),
                        "malicious": rec.get("malicious"),
                        "suspicious": rec.get("suspicious"),
                        "meaningful_name": rec.get("meaningful_name"),
                        "downloadable": rec.get("downloadable"),
                        "type_tag": rec.get("type_tag"),
                        "tags": rec.get("tags") or [],
                    },
                )

                new_records.append(
                    {
                        "sha256": sha256,
                        "family": family,
                        "category": category,
                        "size": rec.get("size"),
                        "malicious": rec.get("malicious"),
                        "suspicious": rec.get("suspicious"),
                        "meaningful_name": rec.get("meaningful_name"),
                        "downloadable": rec.get("downloadable"),
                        "type_tag": rec.get("type_tag"),
                        "tags": rec.get("tags") or [],
                    }
                )
                added += 1
                if pbar:
                    pbar.update(1)
                if added >= remaining:
                    break

            if not cursor:
                break

    finally:
        if pbar:
            pbar.close()

    print(
        f"[{category}:{bucket}] added {added} records (now {db.count(category=category, family=family)}/{effective_target})"
    )
    return new_records


def index_family_catalog(
    *,
    client: VTClient,
    db: StateDB,
    family: str,
    query: str,
    limit: int,
    max_size_bytes: int,
    min_malicious_vendors: int,
) -> Dict[str, Any]:
    state = db.get_family_index_state(category="malicious", family=family)
    if state["exhausted"]:
        count = db.family_catalog_count(category="malicious", family=family)
        print(f"[index:{family}] already exhausted ({count} indexed)")
        return {"family": family, "new_unique": 0, "indexed_total": count, "exhausted": True}

    cursor = state["cursor"]
    new_unique = 0
    pages = 0

    while True:
        try:
            items, next_cursor = vt_intelligence_search(
                client,
                query=query,
                limit=limit,
                cursor=cursor,
            )
        except VTApiError as e:
            if int(getattr(e, "status_code", 0)) == 400:
                msg = _vt_error_message(e)
                print(f"[index:{family}] VT query error (400): {msg}")
                print(f"[index:{family}] Query was: {query}")
                db.update_family_index_state(
                    category="malicious",
                    family=family,
                    cursor=cursor,
                    exhausted=False,
                )
                return {"family": family, "new_unique": 0, "indexed_total": db.family_catalog_count(category="malicious", family=family), "exhausted": False}
            raise

        if not items:
            db.update_family_index_state(
                category="malicious",
                family=family,
                cursor=None,
                exhausted=True,
            )
            break

        pages += 1
        for it in items:
            rec = extract_record(it)
            if not rec:
                continue
            if not is_apk_record(rec):
                continue
            size = rec.get("size")
            if isinstance(size, int) and size > max_size_bytes:
                continue
            if int(rec.get("malicious") or 0) < min_malicious_vendors:
                continue

            inserted = db.upsert_catalog_sample(category="malicious", rec=rec)
            db.add_family_mapping(sha256=rec["sha256"], family=family)
            if inserted:
                new_unique += 1

        exhausted = not bool(next_cursor)
        db.update_family_index_state(
            category="malicious",
            family=family,
            cursor=next_cursor,
            exhausted=exhausted,
        )
        cursor = next_cursor
        if exhausted:
            break

    total_indexed = db.family_catalog_count(category="malicious", family=family)
    print(
        f"[index:{family}] pages={pages} new_unique={new_unique} indexed_total={total_indexed}"
    )
    return {
        "family": family,
        "new_unique": new_unique,
        "indexed_total": total_indexed,
        "exhausted": True,
    }


def collect_assigned_sha256s(db: StateDB, report_root: str, *, category: str) -> set[str]:
    assigned: set[str] = set()
    for summary_path in batch_summary_paths(report_root):
        payload = read_batch_summary(summary_path)
        if str(payload.get("category") or "") != category:
            continue
        for rec in payload.get("records") or []:
            sha256 = rec.get("sha256")
            if (
                sha256
                and not db.is_permanent_download_failure(sha256=str(sha256))
                and not db.is_terminal_analysis_status(sha256=str(sha256))
            ):
                assigned.add(str(sha256))
    return assigned


def plan_weighted_family_batch(
    *,
    db: StateDB,
    families: List[str],
    assigned_sha256s: set[str],
    remaining_target: int,
    max_batch_total_bytes: int,
    max_batch_samples: Optional[int],
) -> List[dict]:
    family_rows = db.get_family_candidate_rows(category="malicious", families=families)
    queues: Dict[str, List[dict]] = {fam: [] for fam in families}
    for row in family_rows:
        if row["sha256"] in assigned_sha256s:
            continue
        if db.is_permanent_download_failure(sha256=row["sha256"]):
            continue
        if db.is_terminal_analysis_status(sha256=row["sha256"]):
            continue
        if row.get("downloadable") is False:
            continue
        queues[row["family"]].append(row)

    selected: List[dict] = []
    selected_sha256s: set[str] = set()
    total_bytes = 0
    pointers: Dict[str, int] = {fam: 0 for fam in families}

    while True:
        if remaining_target <= 0:
            break
        if max_batch_samples is not None and len(selected) >= int(max_batch_samples):
            break

        active_families = []
        for fam in families:
            rows = queues[fam]
            idx = pointers[fam]
            while idx < len(rows) and rows[idx]["sha256"] in selected_sha256s:
                idx += 1
            pointers[fam] = idx
            if idx < len(rows):
                active_families.append((fam, len(rows) - idx))

        if not active_families:
            break

        fam = max(active_families, key=lambda item: item[1])[0]
        rows = queues[fam]
        idx = pointers[fam]
        picked = None
        while idx < len(rows):
            candidate = rows[idx]
            idx += 1
            if candidate["sha256"] in selected_sha256s:
                continue
            size = int(candidate.get("size") or 0)
            if total_bytes + size > max_batch_total_bytes:
                continue
            picked = dict(candidate)
            picked["family"] = fam
            break
        pointers[fam] = idx

        if picked is None:
            queues[fam] = []
            continue

        selected.append(picked)
        selected_sha256s.add(picked["sha256"])
        total_bytes += int(picked.get("size") or 0)
        remaining_target -= 1

    return selected


def download_records(
    *,
    db: StateDB,
    client: VTClient,
    records: List[dict],
    samples_dir: str,
    bucket_label: str,
    overwrite_existing: bool,
    show_progress: bool,
) -> Dict[str, Any]:
    ensure_dir(samples_dir)

    downloaded: List[dict] = []
    permanent_failures: List[dict] = []
    transient_failures: List[dict] = []
    exhausted_reason: Optional[str] = None
    pbar = tqdm(total=len(records), desc=f"download:{bucket_label}") if show_progress else None

    try:
        for rec in records:
            sha256 = str(rec["sha256"])
            dest_path = os.path.join(samples_dir, f"{sha256}.apk")
            try:
                if rec.get("downloadable") is False:
                    reason = "VT marked sample as non-downloadable"
                    permanent_failures.append(
                        {"sha256": sha256, "reason": "VT marked sample as non-downloadable"}
                    )
                    db.record_download_failure(
                        sha256=sha256,
                        reason=reason,
                        permanent=True,
                    )
                    continue

                if db.is_permanent_download_failure(sha256=sha256):
                    permanent_failures.append(
                        {"sha256": sha256, "reason": "Previously marked as permanent download failure"}
                    )
                    continue

                if os.path.exists(dest_path) and not overwrite_existing:
                    if has_apk_magic(dest_path):
                        db.record_download_success(sha256=sha256)
                        downloaded.append(
                            {
                                "sha256": sha256,
                                "path": dest_path,
                                "reused_existing": True,
                            }
                        )
                        continue
                    try:
                        os.remove(dest_path)
                    except OSError:
                        pass

                client.download_file(sha256, dest_path, required_tier="premium")
                if not has_apk_magic(dest_path):
                    try:
                        os.remove(dest_path)
                    except OSError:
                        pass
                    reason = "Downloaded payload did not match APK zip magic"
                    permanent_failures.append({"sha256": sha256, "reason": reason})
                    db.record_download_failure(
                        sha256=sha256,
                        reason=reason,
                        permanent=True,
                    )
                    continue
                db.record_download_success(sha256=sha256)
                downloaded.append(
                    {
                        "sha256": sha256,
                        "path": dest_path,
                        "reused_existing": False,
                    }
                )
            except AllKeysExhaustedError as e:
                exhausted_reason = str(e)
                break
            except Exception as e:
                failure = classify_download_error(e)
                row = {"sha256": sha256, "reason": failure["reason"]}
                if failure["permanent"]:
                    permanent_failures.append(row)
                else:
                    transient_failures.append(row)
                db.record_download_failure(
                    sha256=sha256,
                    reason=failure["reason"],
                    permanent=bool(failure["permanent"]),
                )
            finally:
                if pbar:
                    pbar.update(1)
    finally:
        if pbar:
            pbar.close()

    return {
        "downloaded": downloaded,
        "permanent_failures": permanent_failures,
        "transient_failures": transient_failures,
        "exhausted": bool(exhausted_reason),
        "exhausted_reason": exhausted_reason,
    }


def run_analysis(samples_dir: str, report_dir: str, analysis_script_path: str) -> int:
    ensure_dir(report_dir)

    cmd = [
        sys.executable,
        analysis_script_path,
        samples_dir,
        "--report-dir",
        report_dir,
    ]
    print(f"[analysis] Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=os.path.dirname(analysis_script_path))
    return int(result.returncode)


def cleanup_samples_dir(samples_dir: str, download_root: str) -> None:
    samples_dir_abs = os.path.abspath(samples_dir)
    download_root_abs = os.path.abspath(download_root)

    if os.path.commonpath([samples_dir_abs, download_root_abs]) != download_root_abs:
        raise RuntimeError(
            f"Refusing to delete {samples_dir_abs!r}; it is outside download_root {download_root_abs!r}"
        )

    if os.path.isdir(samples_dir_abs):
        shutil.rmtree(samples_dir_abs)


def cleanup_completed_sample_artifacts(samples_dir: str, report_dir: str) -> Dict[str, int]:
    cleaned_apks = 0
    cleaned_bins = 0

    for row in read_analysis_rows(report_dir):
        if row["status"] not in {"done", "corrupt"}:
            continue

        apk_filename = f"{row['sha256']}.apk"
        apk_path = os.path.join(samples_dir, apk_filename)
        bin_dir = os.path.join(samples_dir, f"bin_{apk_filename}")

        if os.path.isfile(apk_path):
            try:
                os.remove(apk_path)
                cleaned_apks += 1
            except OSError:
                pass

        if os.path.isdir(bin_dir):
            try:
                shutil.rmtree(bin_dir)
                cleaned_bins += 1
            except OSError:
                pass

    return {"cleaned_apks": cleaned_apks, "cleaned_bins": cleaned_bins}


def write_batch_summary(path: str, payload: dict) -> None:
    ensure_dir(os.path.dirname(path) or ".")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


def read_batch_summary(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def batch_summary_paths(report_root: str) -> List[str]:
    out: List[str] = []
    for root, _dirs, files in os.walk(report_root):
        if "batch_summary.json" in files:
            out.append(os.path.join(root, "batch_summary.json"))
    return sorted(out)


def read_analysis_counts(report_dir: str) -> Dict[str, int]:
    db_path = os.path.join(report_dir, "analysis_state.sqlite")
    if not os.path.isfile(db_path):
        return {}

    conn = sqlite3.connect(db_path, timeout=30)
    try:
        cur = conn.execute(
            "SELECT status, COUNT(*) FROM analysis_samples GROUP BY status;"
        )
        return {str(status): int(count) for status, count in cur.fetchall()}
    finally:
        conn.close()


def read_analysis_rows(report_dir: str) -> List[dict]:
    db_path = os.path.join(report_dir, "analysis_state.sqlite")
    if not os.path.isfile(db_path):
        return []

    conn = sqlite3.connect(db_path, timeout=30)
    try:
        cur = conn.execute(
            """
            SELECT sha256, apk_name, status
            FROM analysis_samples;
            """
        )
        return [
            {"sha256": str(row[0]), "apk_name": str(row[1]), "status": str(row[2])}
            for row in cur.fetchall()
        ]
    finally:
        conn.close()


def sync_analysis_state_into_db(
    *,
    db: StateDB,
    report_root: str,
    only: str,
    selected_families: List[str],
) -> Dict[str, int]:
    summaries = batch_summary_paths(report_root)
    imported = 0
    done = 0
    corrupt = 0

    for summary_path in summaries:
        payload = read_batch_summary(summary_path)
        if not batch_matches_selection(
            payload,
            only=only,
            selected_families=selected_families,
        ):
            continue

        report_dir = os.path.dirname(summary_path)
        for row in read_analysis_rows(report_dir):
            status = str(row.get("status") or "")
            if status not in {"done", "corrupt"}:
                continue
            sha256 = row.get("sha256")
            if not sha256:
                continue

            db.record_analysis_status(
                sha256=str(sha256),
                status=status,
                apk_name=str(row.get("apk_name") or ""),
                source_report_dir=report_dir,
            )
            imported += 1
            if status == "done":
                done += 1
            elif status == "corrupt":
                corrupt += 1

    return {"imported": imported, "done": done, "corrupt": corrupt}


def print_batch_summaries(
    *,
    report_root: str,
    only: str,
    selected_families: List[str],
) -> None:
    summaries = batch_summary_paths(report_root)
    selected_family_set = set(selected_families)

    if not summaries:
        print(f"[summary] No batch_summary.json files found under {report_root}")
        return

    aggregate = {
        "batches": 0,
        "records": 0,
        "pending_downloads": 0,
        "terminal_download_failures": 0,
        "done": 0,
        "failed": 0,
        "corrupt": 0,
        "in_progress": 0,
    }

    for summary_path in summaries:
        payload = read_batch_summary(summary_path)
        category = str(payload.get("category") or "")
        family = payload.get("family")

        if only != "all" and category != only:
            continue
        if category == "malicious" and selected_family_set and family not in selected_family_set:
            continue

        report_dir = os.path.dirname(summary_path)
        analysis_counts = read_analysis_counts(report_dir)
        pending_downloads = len(payload.get("pending_downloads") or [])
        terminal_download_failures = int(payload.get("terminal_download_failure_count") or 0)
        record_count = len(payload.get("records") or [])
        status = str(payload.get("status") or "unknown")

        aggregate["batches"] += 1
        aggregate["records"] += record_count
        aggregate["pending_downloads"] += pending_downloads
        aggregate["terminal_download_failures"] += terminal_download_failures
        for key in ("done", "failed", "corrupt", "in_progress"):
            aggregate[key] += int(analysis_counts.get(key, 0))

        print(
            json.dumps(
                {
                    "run_id": payload.get("run_id"),
                    "category": category,
                    "family": family,
                    "status": status,
                    "records": record_count,
                    "pending_downloads": pending_downloads,
                    "terminal_download_failures": terminal_download_failures,
                    "analysis_counts": analysis_counts,
                    "report_dir": report_dir,
                    "samples_dir": payload.get("samples_dir"),
                },
                ensure_ascii=False,
            )
        )

    print(json.dumps({"aggregate": aggregate}, ensure_ascii=False))


def batch_matches_selection(
    payload: dict,
    *,
    only: str,
    selected_families: List[str],
) -> bool:
    category = str(payload.get("category") or "")
    family = payload.get("family")

    if only != "all" and category != only:
        return False
    if (
        category == "malicious"
        and selected_families
        and family is not None
        and family not in selected_families
    ):
        return False
    return True


def process_batch_from_summary(
    *,
    db: StateDB,
    client: VTClient,
    summary_path: str,
    overwrite_existing: bool,
    show_progress: bool,
    analyze_enabled: bool,
    cleanup_after_analysis: bool,
    cleanup_completed_samples: bool,
    download_root: str,
    analysis_script_path: Optional[str],
) -> bool:
    payload = read_batch_summary(summary_path)
    records = list(payload.get("records") or [])
    samples_dir = str(payload["samples_dir"])
    report_dir = os.path.dirname(summary_path)
    category = str(payload.get("category") or "")
    family = payload.get("family")
    bucket_label = f"{category}:{family or 'all'}"

    payload["last_attempt_utc"] = dt.datetime.now(tz=dt.timezone.utc).isoformat()

    download_result = download_records(
        db=db,
        client=client,
        records=records,
        samples_dir=samples_dir,
        bucket_label=bucket_label,
        overwrite_existing=overwrite_existing,
        show_progress=show_progress,
    )
    payload["last_download_result"] = download_result

    terminal_failures: Dict[str, dict] = {
        str(row.get("sha256")): row
        for row in (payload.get("terminal_download_failures") or [])
        if row.get("sha256")
    }
    for row in download_result.get("permanent_failures") or []:
        sha256 = row.get("sha256")
        if sha256:
            terminal_failures[str(sha256)] = row
    payload["terminal_download_failures"] = list(terminal_failures.values())

    local_apks = {
        os.path.splitext(name)[0]
        for name in os.listdir(samples_dir)
        if name.lower().endswith(".apk") and has_apk_magic(os.path.join(samples_dir, name))
    } if os.path.isdir(samples_dir) else set()

    terminal_failed_sha256s = set(terminal_failures.keys())
    pending_downloads = [
        rec["sha256"]
        for rec in records
        if rec.get("downloadable") is not False
        and rec["sha256"] not in local_apks
        and rec["sha256"] not in terminal_failed_sha256s
    ]
    payload["pending_downloads"] = pending_downloads
    payload["terminal_download_failure_count"] = len(terminal_failed_sha256s)

    downloaded_now = len(download_result.get("downloaded") or [])
    permanent_now = len(download_result.get("permanent_failures") or [])
    transient_now = len(download_result.get("transient_failures") or [])
    print(
        f"[download-summary:{bucket_label}] downloaded={len(local_apks)} "
        f"new_or_reused_this_run={downloaded_now} permanent_failures_now={permanent_now} "
        f"transient_failures_now={transient_now} pending_retryable={len(pending_downloads)} "
        f"terminal_failures_total={len(terminal_failed_sha256s)}"
    )

    if download_result.get("exhausted"):
        payload["status"] = "download_paused_key_exhausted"
        payload["pause_reason"] = str(download_result.get("exhausted_reason") or "")
        write_batch_summary(summary_path, payload)
        print(
            f"[batch:{bucket_label}] paused with {len(pending_downloads)} download(s) still pending: "
            f"{payload['pause_reason']}"
        )
        raise AllKeysExhaustedError(payload["pause_reason"])

    if pending_downloads:
        payload["status"] = "download_incomplete"
        write_batch_summary(summary_path, payload)
        print(
            f"[batch:{bucket_label}] waiting on {len(pending_downloads)} missing download(s); not starting analysis yet"
        )
        return False

    if not local_apks:
        payload["status"] = "completed_no_downloads"
        write_batch_summary(summary_path, payload)
        print(
            f"[batch:{bucket_label}] no local APKs available to analyze; "
            f"terminal_download_failures={len(terminal_failed_sha256s)}"
        )
        return True

    if analyze_enabled:
        if not analysis_script_path:
            raise RuntimeError("analysis_script_path is required when analysis is enabled")

        analysis_rc = run_analysis(samples_dir, report_dir, analysis_script_path)
        payload["analysis_exit_code"] = analysis_rc
        sync_counts = sync_analysis_state_into_db(
            db=db,
            report_root=os.path.dirname(report_dir),
            only="all",
            selected_families=[],
        )
        payload["analysis_state_sync"] = sync_counts
        if cleanup_completed_samples:
            cleanup_counts = cleanup_completed_sample_artifacts(samples_dir, report_dir)
            payload["cleanup_counts"] = cleanup_counts
            print(
                f"[cleanup:{bucket_label}] cleaned_apks={cleanup_counts['cleaned_apks']} "
                f"cleaned_bins={cleanup_counts['cleaned_bins']}"
            )
        if analysis_rc != 0:
            payload["status"] = "analysis_incomplete"
            write_batch_summary(summary_path, payload)
            print(f"[batch:{bucket_label}] analysis incomplete (exit={analysis_rc})")
            return False

        if cleanup_after_analysis:
            cleanup_samples_dir(samples_dir, download_root)
            payload["status"] = "cleaned"
            payload["cleaned_at_utc"] = dt.datetime.now(tz=dt.timezone.utc).isoformat()
            print(f"[cleanup:{bucket_label}] removed {samples_dir}")
        else:
            payload["status"] = "completed"
    else:
        payload["status"] = "downloaded"

    write_batch_summary(summary_path, payload)
    return True


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Build an APK dataset from VirusTotal Intelligence and optionally download/analyze batches."
    )
    ap.add_argument(
        "--config",
        default="config.yaml",
        help="Path to config.yaml (default: config.yaml)",
    )
    ap.add_argument(
        "--only",
        choices=["all", "malicious", "benign"],
        default="all",
        help="Which category to collect",
    )
    ap.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable tqdm progress bars",
    )
    ap.add_argument(
        "--workers",
        type=int,
        default=None,
        help=(
            "Parallel worker threads (mainly for collecting multiple families in parallel). "
            "Overrides api.max_workers in config."
        ),
    )
    ap.add_argument(
        "--smoke",
        type=int,
        default=None,
        help=(
            "Smoke-test mode: cap planned downloads to N total samples in this run. "
            "Useful for quick validation."
        ),
    )
    ap.add_argument(
        "--families",
        nargs="+",
        default=None,
        help="Restrict malicious collection to these family names for this run.",
    )
    ap.add_argument(
        "--batch-size",
        type=int,
        default=None,
        help="Optional cap on the total number of samples to plan/download in this run.",
    )
    ap.add_argument(
        "--download-apks",
        action="store_true",
        help="Download APK binaries for newly collected records.",
    )
    ap.add_argument(
        "--analyze-downloaded",
        action="store_true",
        help="Run the LLM analysis pipeline on each downloaded batch.",
    )
    ap.add_argument(
        "--delete-samples-after-analysis",
        action="store_true",
        help="Delete the downloaded sample batch after successful analysis.",
    )
    ap.add_argument(
        "--summary-only",
        action="store_true",
        help="Print batch/download/analysis status from existing batch manifests, then exit.",
    )
    ap.add_argument(
        "--debug-keys",
        action="store_true",
        help="Print VT key status (eligible/cooling_down/disabled/in_flight) and exit.",
    )
    args = ap.parse_args()

    config_path = os.path.abspath(args.config)

    with open(config_path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    api_cfg = cfg["api"]
    ds_cfg = cfg["dataset"]
    search_cfg = cfg["search"]
    download_cfg = ds_cfg.get("downloads") or {}
    analysis_cfg = cfg.get("analysis") or {}

    keys_cfg = api_cfg["keys"]
    keys: List[ApiKey] = []
    for k in keys_cfg:
        name = str(k.get("name") or "")
        key_value = str(k.get("key") or "")
        tier = str(k.get("tier") or "free")
        if not key_value:
            continue
        keys.append(ApiKey(name=name, value=key_value, tier=tier))

    if not keys:
        raise SystemExit(
            "No API keys provided. Please edit config.yaml and set api.keys[*].key values."
        )

    keyring = KeyRing(
        keys,
        exhausted_sleep_hours=float(api_cfg["all_keys_exhausted_sleep_hours"]),
        stop_when_exhausted=bool(api_cfg.get("stop_when_all_keys_exhausted", True)),
    )

    if args.debug_keys:
        snapshot = keyring.snapshot(required_tier="premium")
        print(
            json.dumps(
                {
                    "required_tier": "premium",
                    "count": len(snapshot),
                    "keys": snapshot,
                },
                ensure_ascii=False,
            )
        )
        return 0

    rate_cfg = api_cfg.get("rate_limit") or {}
    per_key_min = rate_cfg.get("per_key_min_interval_sec") or {}
    if not isinstance(per_key_min, dict):
        per_key_min = {}

    global_min_interval_sec = float(rate_cfg.get("global_min_interval_sec") or 0.0)
    jitter_sec = float(rate_cfg.get("jitter_sec") or 0.0)
    max_in_flight = int(rate_cfg.get("max_in_flight_requests") or 0)

    client = VTClient(
        base_url=str(api_cfg["base_url"]),
        keyring=keyring,
        timeout_sec=int(api_cfg["timeout_sec"]),
        max_attempts_per_request=int(api_cfg["max_attempts_per_request"]),
        backoff_initial_sec=float(api_cfg["backoff_initial_sec"]),
        backoff_max_sec=float(api_cfg["backoff_max_sec"]),
        per_key_min_interval_sec={k: float(v) for k, v in per_key_min.items()},
        global_min_interval_sec=global_min_interval_sec,
        max_in_flight_requests=max_in_flight,
        jitter_sec=jitter_sec,
    )

    # Resolve dataset paths relative to the config file location (not the current working dir)
    # so running from different directories behaves consistently.
    base_dir = os.path.dirname(config_path)

    output_dir = resolve_path(base_dir, str(ds_cfg["output_dir"]))
    ensure_dir(output_dir)

    state_db_path = resolve_path(base_dir, str(ds_cfg["state_db_path"]))
    # This DB handle is only used on the main thread. Worker threads open their own.
    db = StateDB(state_db_path)

    download_enabled = bool(download_cfg.get("enabled")) or args.download_apks
    analyze_enabled = (
        bool(analysis_cfg.get("enabled"))
        or args.analyze_downloaded
        or args.delete_samples_after_analysis
    )
    cleanup_after_analysis = bool(analysis_cfg.get("cleanup_samples_after_analysis")) or (
        args.delete_samples_after_analysis
    )
    cleanup_completed_samples = bool(
        analysis_cfg.get("cleanup_completed_samples_after_analysis", True)
    )

    if analyze_enabled:
        download_enabled = True

    if cleanup_after_analysis and not analyze_enabled:
        raise SystemExit("--delete-samples-after-analysis requires analysis to be enabled.")

    download_root = None
    report_root = None
    analysis_script_path = None
    overwrite_existing = bool(download_cfg.get("overwrite_existing"))
    run_id = dt.datetime.now(tz=dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    if download_enabled:
        download_root = resolve_path(
            base_dir,
            str(download_cfg.get("download_dir") or "/mnt/ext_storage/vt_apk_samples"),
        )
        ensure_dir(download_root)

    if analyze_enabled:
        report_root = resolve_path(
            base_dir,
            str(analysis_cfg.get("report_dir") or "/mnt/ext_storage/vt_analysis_reports"),
        )
        ensure_dir(report_root)

        analysis_script_path = resolve_path(
            base_dir,
            str(
                analysis_cfg.get("script_path")
                or os.path.join("..", "llm_V1", "modified_trial8_multiple_models.py")
            ),
        )
        if not os.path.isfile(analysis_script_path):
            raise SystemExit(
                f"Configured analysis script does not exist: {analysis_script_path}"
            )
    elif download_enabled:
        report_root = resolve_path(base_dir, os.path.join(str(ds_cfg["output_dir"]), "batch_reports"))
        ensure_dir(report_root)

    max_size_bytes = int(ds_cfg["max_file_size_bytes"])
    max_size_kb = max(1, int(max_size_bytes / 1024))

    common = str(search_cfg["common_apk_size_filter"]).format(max_size_kb=max_size_kb)
    limit = int(search_cfg.get("limit") or 100)

    show_progress = not args.no_progress

    max_workers_cfg = int(api_cfg.get("max_workers") or 1)
    max_workers = int(args.workers) if args.workers is not None else max_workers_cfg
    if max_workers < 1:
        max_workers = 1

    if max_workers > 1 and show_progress:
        # tqdm across multiple threads gets messy; disable by default.
        print("[info] --workers > 1: disabling progress bars (tqdm) for cleaner output")
        show_progress = False

    selected_families_cfg = download_cfg.get("selected_families") or []
    selected_families = list(args.families) if args.families else list(selected_families_cfg)
    selected_family_set = set(selected_families)

    if report_root and os.path.isdir(report_root):
        sync_counts = sync_analysis_state_into_db(
            db=db,
            report_root=report_root,
            only=args.only,
            selected_families=selected_families,
        )
        if sync_counts["imported"] > 0:
            print(
                f"[analysis-sync] imported={sync_counts['imported']} "
                f"done={sync_counts['done']} corrupt={sync_counts['corrupt']}"
            )

    if args.summary_only:
        if report_root is None:
            report_root = resolve_path(
                base_dir,
                str(analysis_cfg.get("report_dir") or os.path.join(str(ds_cfg["output_dir"]), "batch_reports")),
            )
        print_batch_summaries(
            report_root=report_root,
            only=args.only,
            selected_families=selected_families,
        )
        db.close()
        return 0

    if args.batch_size is not None:
        max_batch_samples = int(args.batch_size)
    elif args.smoke is not None:
        max_batch_samples = int(args.smoke)
    else:
        max_batch_samples = None

    max_batch_total_bytes = int(
        download_cfg.get("max_batch_total_bytes") or (50 * 1024 * 1024 * 1024)
    )

    def maybe_process_downloaded_batch(
        *,
        category: str,
        family: Optional[str],
        new_records: List[dict],
    ) -> bool:
        if not download_enabled or not new_records:
            return True

        assert download_root is not None
        assert report_root is not None
        bucket_name = sanitize_name(family or category)
        samples_dir = os.path.join(download_root, run_id, bucket_name)
        report_dir = os.path.join(report_root, run_id, bucket_name)
        summary_path = os.path.join(report_dir, "batch_summary.json")

        if not os.path.exists(summary_path):
            write_batch_summary(
                summary_path,
                {
                    "run_id": run_id,
                    "category": category,
                    "family": family,
                    "samples_dir": samples_dir,
                    "records": new_records,
                    "status": "created",
                    "terminal_download_failures": [],
                },
            )

        return process_batch_from_summary(
            db=db,
            client=client,
            summary_path=summary_path,
            overwrite_existing=overwrite_existing,
            show_progress=show_progress,
            analyze_enabled=analyze_enabled,
            cleanup_after_analysis=cleanup_after_analysis,
            cleanup_completed_samples=cleanup_completed_samples,
            download_root=download_root,
            analysis_script_path=analysis_script_path,
        )

    def resume_pending_batches() -> None:
        if not (download_enabled and report_root and download_root):
            return

        pending = []
        for summary_path in batch_summary_paths(report_root):
            payload = read_batch_summary(summary_path)
            if not batch_matches_selection(
                payload,
                only=args.only,
                selected_families=selected_families,
            ):
                continue
            if payload.get("status") in {"completed", "completed_no_downloads", "cleaned", "downloaded"}:
                continue
            pending.append(summary_path)

        if not pending:
            return

        print(f"[resume] Found {len(pending)} pending batch(es). Resuming them before collecting new samples.")
        for summary_path in pending:
            ok = process_batch_from_summary(
                db=db,
                client=client,
                summary_path=summary_path,
                overwrite_existing=overwrite_existing,
                show_progress=show_progress,
                analyze_enabled=analyze_enabled,
                cleanup_after_analysis=cleanup_after_analysis,
                cleanup_completed_samples=cleanup_completed_samples,
                download_root=download_root,
                analysis_script_path=analysis_script_path,
            )
            if not ok:
                raise RuntimeError(
                    f"Pending batch is still incomplete: {summary_path}. "
                    "Resolve or rerun after the underlying failure is fixed."
                )

    try:
        resume_pending_batches()

        # Malicious
        if args.only in ("all", "malicious"):
            mal_cfg = ds_cfg["malicious"]
            all_families = list(mal_cfg["families"])
            overall_malicious_target = int(mal_cfg["total_target"])

            if selected_families:
                unknown_families = [fam for fam in selected_families if fam not in all_families]
                if unknown_families:
                    raise SystemExit(
                        f"Unknown family/families in selection: {', '.join(unknown_families)}"
                    )
                families = [fam for fam in all_families if fam in selected_family_set]
            else:
                families = all_families

            min_pos = int(mal_cfg["min_malicious_vendors"])
            templ = str(search_cfg["malicious_template"])
            for fam in families:
                q = build_query(
                    templ,
                    common=common,
                    family=fam,
                    min_positives=min_pos,
                )
                index_family_catalog(
                    client=client,
                    db=db,
                    family=fam,
                    query=q,
                    limit=limit,
                    max_size_bytes=max_size_bytes,
                    min_malicious_vendors=min_pos,
                )

            indexed_total = db.total_catalog_count(category="malicious")
            print(f"[malicious] indexed unique catalog samples: {indexed_total}")
            for fam in families:
                fam_count = db.family_catalog_count(category="malicious", family=fam)
                print(f"[malicious] family={fam} indexed={fam_count}")

            if download_enabled:
                assert report_root is not None
                assigned_sha256s = collect_assigned_sha256s(
                    db,
                    report_root,
                    category="malicious",
                )
                remaining_target = max(0, overall_malicious_target - len(assigned_sha256s))

                if remaining_target <= 0:
                    print(
                        f"[malicious] planning target already satisfied "
                        f"({len(assigned_sha256s)}/{overall_malicious_target})"
                    )
                else:
                    planned_records = plan_weighted_family_batch(
                        db=db,
                        families=families,
                        assigned_sha256s=assigned_sha256s,
                        remaining_target=remaining_target,
                        max_batch_total_bytes=max_batch_total_bytes,
                        max_batch_samples=max_batch_samples,
                    )

                    planned_bytes = sum(int(rec.get("size") or 0) for rec in planned_records)
                    print(
                        f"[malicious] planned next batch samples={len(planned_records)} "
                        f"bytes={planned_bytes} remaining_target_after_plan={max(0, remaining_target - len(planned_records))}"
                    )

                    if planned_records:
                        ok = maybe_process_downloaded_batch(
                            category="malicious",
                            family=None,
                            new_records=planned_records,
                        )
                        if not ok:
                            raise RuntimeError(
                                "Planned malicious batch did not complete. "
                                "Fix the issue and rerun to resume this batch."
                            )

        # Benign
        if args.only in ("all", "benign"):
            ben_cfg = ds_cfg["benign"]
            target = int(ben_cfg["total_target"])
            max_mal = int(ben_cfg["max_malicious_vendors"])
            max_susp = int(ben_cfg["max_suspicious_vendors"])
            templ = str(search_cfg["benign_template"])
            q = build_query(templ, common=common)

            def pred(rec: dict) -> bool:
                return (int(rec.get("malicious") or 0) <= max_mal) and (
                    int(rec.get("suspicious") or 0) <= max_susp
                )

            new_records = collect_category(
                client=client,
                db=db,
                output_dir=output_dir,
                limit=limit,
                max_size_bytes=max_size_bytes,
                category="benign",
                family=None,
                target=target,
                query=q,
                predicate=pred,
                show_progress=show_progress,
                max_new=max_batch_samples,
            )
            ok = maybe_process_downloaded_batch(
                category="benign",
                family=None,
                new_records=new_records,
            )
            if not ok:
                raise RuntimeError(
                    "Batch processing did not complete for benign samples. "
                    "Fix the issue and rerun to resume this batch."
                )

    except AllKeysExhaustedError as e:
        print(f"[graceful-stop] {e}")
        print("[graceful-stop] Progress has been saved. Re-run later when VT quota resets.")
        return 0
    finally:
        db.close()

    print("Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
