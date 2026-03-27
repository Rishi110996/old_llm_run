"""vt_downloader.py

This project is a *dataset builder* for Android APKs using VirusTotal (VT) Intelligence Search.

It exports:
  - Per-family (malicious) hash lists + JSONL metadata
  - A benign hash list + JSONL metadata

It intentionally does NOT download APK binaries.

Why: Mass-downloading malware binaries can be harmful and may violate policies/terms.
If you have an approved/legal workflow for obtaining binaries, use VirusTotal's official
datasets/feeds and comply with VT's Terms of Service.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import dataclasses
import datetime as dt
import json
import os
import random
import sqlite3
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
    def __init__(self, keys: List[ApiKey], exhausted_sleep_hours: float = 24.0):
        if not keys:
            raise ValueError("No API keys configured")
        self._keys = keys
        self._idx = 0
        self._exhausted_sleep_hours = exhausted_sleep_hours
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
                    raise RuntimeError(
                        f"All API keys are disabled (tier requirement: {required_tier!r})."
                    )

                soonest = min(k.cooldown_until_utc for k in eligible)

                wait_sec = max(0.0, (soonest - now_dt).total_seconds())
                if wait_sec <= 0:
                    wait_sec = 0.25

                elapsed = time.monotonic() - start
                if elapsed >= max_sleep_sec:
                    # Don't sleep forever; return control to caller.
                    return

                wait_sec = min(wait_sec, max_sleep_sec - elapsed)

                print(
                    f"[keyring] No key available (tier={required_tier!r}). "
                    f"Waiting for {wait_sec:.2f}s..."
                )
                self._cond.wait(timeout=wait_sec)


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

    return {
        "sha256": sha256,
        "size": size,
        "malicious": malicious,
        "suspicious": suspicious,
        "meaningful_name": meaningful_name,
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
) -> int:
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
        return 0

    cursor = None
    added = 0

    pbar = tqdm(total=remaining, desc=f"{category}:{bucket}") if show_progress else None

    try:
        while added < remaining:
            items, cursor = vt_intelligence_search(
                client, query=query, limit=limit, cursor=cursor
            )
            if not items:
                print(f"[{category}:{bucket}] no more results from search")
                break

            for it in items:
                rec = extract_record(it)
                if not rec:
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
                    },
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
    return added


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Build an APK dataset from VirusTotal Intelligence (hashes + metadata only)."
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
            "Smoke-test mode: limit to N new samples per family and N benign samples. "
            "Useful for quick validation."
        ),
    )
    args = ap.parse_args()

    config_path = os.path.abspath(args.config)

    with open(config_path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    api_cfg = cfg["api"]
    ds_cfg = cfg["dataset"]
    search_cfg = cfg["search"]

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

    keyring = KeyRing(keys, exhausted_sleep_hours=float(api_cfg["all_keys_exhausted_sleep_hours"]))

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

    output_dir = str(ds_cfg["output_dir"])
    if not os.path.isabs(output_dir):
        output_dir = os.path.join(base_dir, output_dir)
    ensure_dir(output_dir)

    state_db_path = str(ds_cfg["state_db_path"])
    if not os.path.isabs(state_db_path):
        state_db_path = os.path.join(base_dir, state_db_path)
    # This DB handle is only used on the main thread. Worker threads open their own.
    db = StateDB(state_db_path)

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

    # Malicious
    if args.only in ("all", "malicious"):
        mal_cfg = ds_cfg["malicious"]
        families = list(mal_cfg["families"])
        targets = split_targets(int(mal_cfg["total_target"]), families)
        min_pos = int(mal_cfg["min_malicious_vendors"])
        templ = str(search_cfg["malicious_template"])

        def run_family(fam: str) -> None:
            local_db = StateDB(state_db_path)
            try:
                q = build_query(
                    templ,
                    common=common,
                    family=fam,
                    min_positives=min_pos,
                )

                def pred(rec: dict) -> bool:
                    return int(rec.get("malicious") or 0) >= min_pos

                collect_category(
                    client=client,
                    db=local_db,
                    output_dir=output_dir,
                    limit=limit,
                    max_size_bytes=max_size_bytes,
                    category="malicious",
                    family=fam,
                    target=targets[fam],
                    query=q,
                    predicate=pred,
                    show_progress=show_progress,
                    max_new=args.smoke,
                )
            finally:
                local_db.close()

        if max_workers <= 1:
            for fam in families:
                run_family(fam)
        else:
            with cf.ThreadPoolExecutor(max_workers=max_workers) as ex:
                futs = {ex.submit(run_family, fam): fam for fam in families}
                for fut in cf.as_completed(futs):
                    fam = futs[fut]
                    try:
                        fut.result()
                    except Exception as e:
                        raise RuntimeError(f"Worker failed for family={fam}: {e}") from e

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

        collect_category(
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
            max_new=args.smoke,
        )

    db.close()

    print("Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
