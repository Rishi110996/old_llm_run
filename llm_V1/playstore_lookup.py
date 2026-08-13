"""
playstore_lookup.py
-------------------
Best-effort public Google Play metadata lookup for package triage.

This module intentionally does NOT prove APK identity.  Google Play metadata can
tell us that a package exists, who publishes it, and broad popularity/update
signals, but a sideloaded APK with the same package name can still be repacked
and signed by a different certificate.  Use signing-certificate baselines for
identity verification.
"""
from __future__ import annotations

import argparse
import datetime as dt
import html as html_lib
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote, unquote

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


PLAY_DETAILS_URL = "https://play.google.com/store/apps/details?id={package}&hl={hl}&gl={gl}"
PLAY_BASE_URL = "https://play.google.com"


@dataclass
class PlayStoreAppDetails:
    package_name: str
    found: bool
    fetched_at_utc: str
    status_code: int = 0
    final_url: str = ""
    hl: str = "en"
    gl: str = "IN"
    app_name: str = ""
    developer_name: str = ""
    developer_id: str = ""
    developer_apps_url: str = ""
    developer_published_apps: List[str] = field(default_factory=list)
    count_of_developer_published_apps: int = 0
    rating: str = ""
    review_count: str = ""
    downloads: str = ""
    updated_date: str = ""
    released_date: str = ""
    app_icon: str = ""
    developer_website: str = ""
    developer_email: str = ""
    privacy_policy_url: str = ""
    content_rating: str = ""
    error: str = ""
    identity_note: str = (
        "Google Play metadata is not proof that a sideloaded APK is clean; "
        "verify package name with signing certificate baseline."
    )


def _utc_now() -> str:
    return dt.datetime.now(tz=dt.timezone.utc).isoformat()


def _clean_text(value: str) -> str:
    text = html_lib.unescape(str(value or ""))
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _dedupe(values: Iterable[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for value in values:
        item = str(value or "").strip()
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _extract_meta(page: str, key: str) -> str:
    # Handles both property/name before content and content before property/name.
    key_re = re.escape(key)
    patterns = [
        rf'<meta[^>]+(?:property|name)=["\']{key_re}["\'][^>]+content=["\']([^"\']*)["\']',
        rf'<meta[^>]+content=["\']([^"\']*)["\'][^>]+(?:property|name)=["\']{key_re}["\']',
    ]
    for pattern in patterns:
        match = re.search(pattern, page, re.I)
        if match:
            return html_lib.unescape(match.group(1)).strip()
    return ""


def _extract_first(pattern: str, page: str, flags: int = re.I | re.S) -> str:
    match = re.search(pattern, page, flags)
    if not match:
        return ""
    return _clean_text(match.group(1))


def _extract_developer(page: str) -> Tuple[str, str, str]:
    match = re.search(
        r'<a\s+href=["\'](/store/apps/(?:developer|dev)\?id=([^"\']+))["\'][^>]*>\s*<span>(.*?)</span>',
        page,
        re.I | re.S,
    )
    if not match:
        return "", "", ""
    path = html_lib.unescape(match.group(1)).strip()
    developer_id = unquote(html_lib.unescape(match.group(2)).strip())
    developer_name = _clean_text(match.group(3))
    return developer_name, developer_id, PLAY_BASE_URL + path


def _extract_downloads(page: str) -> str:
    value = _extract_first(
        r'<div[^>]*class=["\'][^"\']*\bClM7O\b[^"\']*["\'][^>]*>\s*([^<]+?)\s*</div>\s*<div[^>]*class=["\'][^"\']*\bg1rdde\b[^"\']*["\'][^>]*>\s*Downloads\s*</div>',
        page,
    )
    return value


def _extract_updated_date(page: str) -> str:
    return _extract_first(
        r'>Updated on</div>\s*<div[^>]*>(.*?)</div>',
        page,
    )


def _extract_privacy_policy(page: str) -> str:
    match = re.search(r'<a\s+href=["\']([^"\']+)["\'][^>]*>\s*Privacy Policy\s*</a>', page, re.I | re.S)
    if match:
        return html_lib.unescape(match.group(1)).strip()
    return ""


def _extract_released_date(page: str) -> str:
    # Google Play often hides/omits this on current pages. Do not infer it from
    # arbitrary dates because that can accidentally repeat the update date.
    return _extract_first(r'>Released on</div>\s*<div[^>]*>(.*?)</div>', page)


def create_session(timeout_retries: int = 3) -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=timeout_retries,
        connect=timeout_retries,
        read=timeout_retries,
        backoff_factor=0.75,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET"]),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
    session.mount("https://", adapter)
    session.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    })
    return session


def fetch_play_page(
    package_name: str,
    *,
    hl: str = "en",
    gl: str = "IN",
    timeout: float = 20.0,
    session: Optional[requests.Session] = None,
) -> Tuple[int, str, str]:
    session = session or create_session()
    url = PLAY_DETAILS_URL.format(
        package=quote(package_name, safe="."),
        hl=quote(hl),
        gl=quote(gl),
    )
    response = session.get(url, timeout=timeout)
    return int(response.status_code), str(response.url), response.text or ""


def parse_play_page(
    package_name: str,
    page: str,
    *,
    status_code: int,
    final_url: str,
    hl: str,
    gl: str,
) -> PlayStoreAppDetails:
    result = PlayStoreAppDetails(
        package_name=package_name,
        found=False,
        fetched_at_utc=_utc_now(),
        status_code=status_code,
        final_url=final_url,
        hl=hl,
        gl=gl,
    )

    if status_code == 404 or "We're sorry, the requested URL was not found" in page:
        result.error = "not_found"
        return result
    if status_code >= 400:
        result.error = f"http_{status_code}"
        return result
    if "AF_initDataCallback" not in page and "Apps on Google Play" not in page:
        result.error = "unexpected_response"
        return result

    og_title = _extract_meta(page, "og:title")
    app_name = _extract_first(r'<h1[^>]*>\s*<span[^>]*itemprop=["\']name["\'][^>]*>(.*?)</span>', page)
    if not app_name and og_title:
        app_name = re.sub(r"\s+-\s+Apps on Google Play\s*$", "", og_title).strip()

    developer_name, developer_id, developer_apps_url = _extract_developer(page)
    rating = _extract_first(r'aria-label=["\']Rated\s+([0-9.]+)\s+stars out of five stars["\']', page)
    reviews = _extract_first(r'<div[^>]*class=["\'][^"\']*g1rdde[^"\']*["\'][^>]*>([^<]*reviews?)</div>', page)
    content_rating = _extract_first(r'<span[^>]*itemprop=["\']contentRating["\'][^>]*>\s*<span>(.*?)</span>', page)

    result.found = bool(app_name or developer_name or _extract_meta(page, "appstore:bundle_id"))
    result.app_name = app_name
    result.developer_name = developer_name
    result.developer_id = developer_id
    result.developer_apps_url = developer_apps_url
    result.rating = rating
    result.review_count = reviews
    result.downloads = _extract_downloads(page)
    result.updated_date = _extract_updated_date(page)
    result.released_date = _extract_released_date(page)
    result.app_icon = _extract_meta(page, "og:image")
    result.developer_website = _extract_meta(page, "appstore:developer_url")
    result.developer_email = _extract_first(r'href=["\']mailto:([^"\']+)["\']', page)
    result.privacy_policy_url = _extract_privacy_policy(page)
    result.content_rating = content_rating
    return result


def fetch_developer_apps(
    developer_apps_url: str,
    *,
    timeout: float = 20.0,
    session: Optional[requests.Session] = None,
) -> List[str]:
    if not developer_apps_url:
        return []
    session = session or create_session()
    response = session.get(developer_apps_url, timeout=timeout)
    if response.status_code >= 400:
        return []
    apps = re.findall(r'/store/apps/details\?id=([A-Za-z0-9_.$-]+)', response.text or "")
    return _dedupe(apps)


def lookup_app(
    package_name: str,
    *,
    hl: str = "en",
    gl: str = "IN",
    timeout: float = 20.0,
    include_developer_apps: bool = False,
    session: Optional[requests.Session] = None,
) -> PlayStoreAppDetails:
    session = session or create_session()
    try:
        status_code, final_url, page = fetch_play_page(
            package_name,
            hl=hl,
            gl=gl,
            timeout=timeout,
            session=session,
        )
        result = parse_play_page(
            package_name,
            page,
            status_code=status_code,
            final_url=final_url,
            hl=hl,
            gl=gl,
        )
        if include_developer_apps and result.developer_apps_url:
            result.developer_published_apps = fetch_developer_apps(
                result.developer_apps_url,
                timeout=timeout,
                session=session,
            )
            result.count_of_developer_published_apps = len(result.developer_published_apps)
        return result
    except Exception as exc:
        return PlayStoreAppDetails(
            package_name=package_name,
            found=False,
            fetched_at_utc=_utc_now(),
            hl=hl,
            gl=gl,
            error=str(exc),
        )


def _read_packages(args: argparse.Namespace) -> List[str]:
    packages = list(args.packages or [])
    if args.package_file:
        with open(args.package_file, "r", encoding="utf-8") as fh:
            for line in fh:
                value = line.strip()
                if not value or value.startswith("#"):
                    continue
                packages.append(value.split()[0])
    return _dedupe(packages)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Best-effort public Google Play metadata lookup for package names."
    )
    parser.add_argument("packages", nargs="*", help="Package name(s), e.g. com.phonepe.app")
    parser.add_argument("--package-file", help="Text file with one package name per line")
    parser.add_argument("--out", help="Write JSONL results to this path")
    parser.add_argument("--hl", default="en", help="Play Store language parameter (default: en)")
    parser.add_argument("--gl", default="IN", help="Play Store country parameter (default: IN)")
    parser.add_argument("--timeout", type=float, default=20.0, help="HTTP timeout seconds")
    parser.add_argument("--workers", type=int, default=1, help="Concurrent lookups; keep low for Play")
    parser.add_argument("--delay-sec", type=float, default=0.5, help="Delay between sequential requests")
    parser.add_argument(
        "--include-developer-apps",
        action="store_true",
        help="Also fetch the developer page and list other published package names",
    )
    args = parser.parse_args()

    packages = _read_packages(args)
    if not packages:
        parser.error("provide package names or --package-file")

    workers = max(1, int(args.workers))
    session = create_session()

    def run_one(pkg: str) -> Dict:
        detail = lookup_app(
            pkg,
            hl=args.hl,
            gl=args.gl,
            timeout=args.timeout,
            include_developer_apps=args.include_developer_apps,
            session=session if workers == 1 else None,
        )
        return asdict(detail)

    results: List[Dict] = []
    if workers == 1:
        for pkg in packages:
            results.append(run_one(pkg))
            if args.delay_sec > 0:
                time.sleep(args.delay_sec)
    else:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            future_to_pkg = {pool.submit(run_one, pkg): pkg for pkg in packages}
            for future in as_completed(future_to_pkg):
                results.append(future.result())

    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as fh:
            for row in results:
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    else:
        print(json.dumps(results, indent=2, ensure_ascii=False))

    return 0 if all(row.get("found") or row.get("error") == "not_found" for row in results) else 2


if __name__ == "__main__":
    raise SystemExit(main())
