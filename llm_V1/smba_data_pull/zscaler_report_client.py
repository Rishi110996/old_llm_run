from __future__ import annotations

import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed
from dataclasses import asdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote
from urllib.parse import urljoin

import requests
from dotenv import load_dotenv


class ZscalerClientError(Exception):
    """Raised when the client is misconfigured or a request fails."""


class ReportNotFoundError(ZscalerClientError):
    """Raised when a sample/report does not exist in BA UI."""


class DownloadNotAvailableError(ZscalerClientError):
    """Raised when a requested report artifact is not available for download."""


@dataclass(frozen=True)
class DownloadArtifactMetadata:
    artifact: str
    filename: str | None
    content_type: str | None
    detected_type: str
    extension: str
    size: int | None


REPORT_ENDPOINTS: dict[str, str] = {
    "summary": "summary",
    "classification": "block/classification",
    "download_summary": "block/downloadsummary",
    "apk_file_info": "block/apkfileinfo/details",
    "permissions": "block/permissions",
    "networking": "block/networking",
    "network_http": "block/networkhttpinfo",
    "network_https": "block/networkhttpsinfo",
    "network_tcp": "block/networktcpinfo",
    "network_udp": "block/networkudpinfo",
    "network_dns": "block/networkdnsinfo",
    "network_ftp": "block/networkftpinfo",
    "network_smtp": "block/networksmtpinfo",
    "network_icmp": "block/networkicmpinfo",
    "network_irc": "block/networkircinfo",
    "exploiting": "block/exploiting",
    "stealth": "block/stealth",
    "spreading": "block/spreading",
    "persistence": "block/persistence",
    "security_bypass": "block/securitybypass",
    "spyware": "block/spyware",
    "virus_malware": "block/virusmalware",
    "ml_score": "block/mlscore",
    "category_summary": "block/categorysummary",
    "malware_config_extract": "block/malwareconfigextract",
    "mitre_attack": "block/mitreattack",
    "mitre_attack_tactics": "mitreAttack/tactics",
    "dropped_files": "block/droppedfiles/details",
    "origin": "block/origin",
    "screenshots": "screenshots",
}


DOWNLOAD_ENDPOINTS: dict[str, str] = {
    "original": "download/content",
    "dropped": "download/droppedcontent",
    "pcap": "download/pcap",
}


@dataclass(frozen=True)
class ZscalerConfig:
    base_url: str
    jsessionid: str
    timeout: int = 30
    verify_ssl: bool = True
    max_workers: int = 8

    @classmethod
    def from_env(cls, env_file: str = ".env") -> "ZscalerConfig":
        load_dotenv(env_file)

        base_url = os.getenv("ZSCALER_BASE_URL", "").strip()
        jsessionid = os.getenv("ZSCALER_JSESSIONID", "").strip()
        timeout_value = os.getenv("ZSCALER_TIMEOUT", "30").strip()
        verify_ssl_value = os.getenv("ZSCALER_VERIFY_SSL", "true").strip().lower()
        max_workers_value = os.getenv("ZSCALER_MAX_WORKERS", "8").strip()

        if not base_url:
            raise ZscalerClientError("Missing ZSCALER_BASE_URL in .env")
        if not jsessionid:
            raise ZscalerClientError("Missing ZSCALER_JSESSIONID in .env")

        try:
            timeout = int(timeout_value)
        except ValueError as exc:
            raise ZscalerClientError("ZSCALER_TIMEOUT must be an integer") from exc

        try:
            max_workers = int(max_workers_value)
        except ValueError as exc:
            raise ZscalerClientError("ZSCALER_MAX_WORKERS must be an integer") from exc

        if max_workers < 1:
            raise ZscalerClientError("ZSCALER_MAX_WORKERS must be at least 1")

        verify_ssl = verify_ssl_value not in {"0", "false", "no"}

        return cls(
            base_url=base_url.rstrip("/"),
            jsessionid=jsessionid,
            timeout=timeout,
            verify_ssl=verify_ssl,
            max_workers=max_workers,
        )


class ZscalerReportClient:
    def __init__(self, config: ZscalerConfig) -> None:
        self.config = config
        self._thread_local = threading.local()
        self.session = self._create_session()
        self._thread_local.session = self.session

    def sample_exists(self, sample_id: str) -> bool:
        path = f"/ba/api/v1/reports/{sample_id}/{REPORT_ENDPOINTS['summary']}"
        response = self._request("GET", path, expected_status=(200, 404))
        return response.status_code == 200

    def get_all_components(self, sample_id: str) -> dict[str, Any]:
        return self.get_full_report(sample_id, include_artifacts=True)

    def get_full_report(self, sample_id: str, *, include_artifacts: bool = True) -> dict[str, Any]:
        section_funcs = {
            "summary": lambda: self.get_summary(sample_id),
            "classification": lambda: self.get_classification(sample_id),
            "files": lambda: self.get_files(sample_id),
            "traffic": lambda: self.get_traffic(sample_id),
            "behavior": lambda: self.get_behavior(sample_id),
            "permissions": lambda: self.get_permissions(sample_id),
            "mitre": lambda: self.get_mitre(sample_id),
        }
        sections = {}
        for key, func in section_funcs.items():
            try:
                sections[key] = func()
            except Exception as exc:
                # Only treat 'invalid report id' as sample not found
                if "invalid report id" in str(exc).lower():
                    raise ReportNotFoundError(f"Sample {sample_id} not found in SMBA: {exc}")
                sections[key] = None

        report: dict[str, Any] = {
            "sample_id": sample_id,
            "sample_id_lower": sample_id.lower(),
            "exists": True,
            "report_url": f"{self.config.base_url}/ba/report?id={sample_id}",
        }
        report.update(sections)

        files = sections.get("files") or {}
        apk_file_info = files.get("apk_file_info", {}) if isinstance(files, dict) else {}
        if isinstance(apk_file_info, dict):
            report["identifiers"] = {
                "md5": apk_file_info.get("md5") or sample_id.lower(),
                "sha1": apk_file_info.get("sha"),
                "sha256": apk_file_info.get("sha256"),
                "package_name": apk_file_info.get("packageName"),
            }

        if include_artifacts:
            try:
                report["artifacts"] = self.get_artifacts_summary(sample_id)
            except Exception as exc:
                if "invalid report id" in str(exc).lower():
                    raise ReportNotFoundError(f"Sample {sample_id} not found in SMBA: {exc}")
                report["artifacts"] = None

        return report

    def get_artifacts_summary(self, sample_id: str) -> dict[str, Any]:
        def artifact_summary(artifact: str) -> dict[str, Any]:
            try:
                metadata = self._get_download_metadata(sample_id, artifact)
                return {
                    "available": True,
                    "metadata": asdict(metadata),
                }
            except DownloadNotAvailableError:
                return {
                    "available": False,
                    "metadata": None,
                }

        return self._fetch_named_calls(
            {
                artifact: (lambda artifact=artifact: artifact_summary(artifact))
                for artifact in DOWNLOAD_ENDPOINTS
            }
        )

    def get_analysis_bundle(self, sample_id: str) -> dict[str, Any]:
        """Compatibility-friendly alias for downstream APK analysis scripts."""

        return self.get_full_report(sample_id, include_artifacts=True)

    def get_core_signal_summary(self, sample_id: str) -> dict[str, Any]:
        """Smaller normalized view for scripts that only need high-signal fields."""

        report = self.get_full_report(sample_id, include_artifacts=True)
        identifiers = report.get("identifiers", {})
        summary = report.get("summary", {})
        classification = report.get("classification", {})
        files = report.get("files", {})
        apk_file_info = files.get("apk_file_info", {})
        download_summary = files.get("download_summary", {})
        permissions = report.get("permissions", {})

        return {
            "sample_id": report["sample_id"],
            "report_url": report["report_url"],
            "package_name": identifiers.get("package_name"),
            "md5": identifiers.get("md5"),
            "sha1": identifiers.get("sha1"),
            "sha256": identifiers.get("sha256"),
            "status": summary.get("status"),
            "category": summary.get("category"),
            "file_type": summary.get("fileType"),
            "source_url": summary.get("url"),
            "malware_type": classification.get("type"),
            "malware_category": classification.get("category"),
            "detected_malware": classification.get("detectedMalware"),
            "rating": classification.get("rating"),
            "package_size": apk_file_info.get("size"),
            "download_allowed": download_summary.get("downloadAllowed"),
            "permission_count": len(permissions.get("results", []))
            if isinstance(permissions, dict)
            else None,
            "artifacts": report.get("artifacts"),
        }

    def get_traffic(self, sample_id: str) -> dict[str, Any]:
        return self._fetch_named_calls(
            {
                "overview": lambda: self.get_component(sample_id, "networking"),
                "http": lambda: self.get_component(sample_id, "network_http"),
                "https": lambda: self.get_component(sample_id, "network_https"),
                "tcp": lambda: self.get_component(sample_id, "network_tcp"),
                "udp": lambda: self.get_component(sample_id, "network_udp"),
                "dns": lambda: self.get_component(sample_id, "network_dns"),
                "ftp": lambda: self.get_component(sample_id, "network_ftp"),
                "smtp": lambda: self.get_component(sample_id, "network_smtp"),
                "icmp": lambda: self.get_component(sample_id, "network_icmp"),
                "irc": lambda: self.get_component(sample_id, "network_irc"),
                "origin": lambda: self.get_component(sample_id, "origin"),
            }
        )

    def get_permissions(self, sample_id: str) -> dict[str, Any]:
        return self.get_component(sample_id, "permissions")

    def get_summary(self, sample_id: str) -> dict[str, Any]:
        return self.get_component(sample_id, "summary")

    def get_classification(self, sample_id: str) -> dict[str, Any]:
        return self.get_component(sample_id, "classification")

    def get_files(self, sample_id: str) -> dict[str, Any]:
        return self._fetch_named_calls(
            {
                "apk_file_info": lambda: self.get_component(sample_id, "apk_file_info"),
                "download_summary": lambda: self.get_component(sample_id, "download_summary"),
                "dropped_files": lambda: self.get_component(sample_id, "dropped_files"),
            }
        )

    def get_behavior(self, sample_id: str) -> dict[str, Any]:
        return self._fetch_named_calls(
            {
                "classification": lambda: self.get_component(sample_id, "classification"),
                "category_summary": lambda: self.get_component(sample_id, "category_summary"),
                "ml_score": lambda: self.get_component(sample_id, "ml_score"),
                "virus_malware": lambda: self.get_component(sample_id, "virus_malware"),
                "spyware": lambda: self.get_component(sample_id, "spyware"),
                "security_bypass": lambda: self.get_component(sample_id, "security_bypass"),
                "exploiting": lambda: self.get_component(sample_id, "exploiting"),
                "stealth": lambda: self.get_component(sample_id, "stealth"),
                "spreading": lambda: self.get_component(sample_id, "spreading"),
                "persistence": lambda: self.get_component(sample_id, "persistence"),
                "malware_config_extract": lambda: self.get_component(sample_id, "malware_config_extract"),
            }
        )

    def get_mitre(self, sample_id: str) -> dict[str, Any]:
        return self._fetch_named_calls(
            {
                "attack": lambda: self.get_component(sample_id, "mitre_attack"),
                "tactics": lambda: self.get_component(sample_id, "mitre_attack_tactics"),
            }
        )

    def get_screenshots(self, sample_id: str) -> dict[str, Any]:
        return self.get_component(sample_id, "screenshots")

    def get_component(self, sample_id: str, component: str) -> dict[str, Any] | list[Any]:
        endpoint = REPORT_ENDPOINTS.get(component)
        if endpoint is None:
            raise ZscalerClientError(f"Unknown component: {component}")

        if component == "mitre_attack_tactics":
            path = f"/ba/api/v1/reports/{endpoint}"
        else:
            path = f"/ba/api/v1/reports/{sample_id}/{endpoint}"

        return self._get_json(path, sample_id=sample_id, component=component)

    def has_original_file(self, sample_id: str) -> bool:
        return self._download_available(sample_id, "original")

    def has_dropped_file(self, sample_id: str) -> bool:
        return self._download_available(sample_id, "dropped")

    def has_pcap_file(self, sample_id: str) -> bool:
        return self._download_available(sample_id, "pcap")

    def download_original_file(self, sample_id: str, output_path: str | os.PathLike[str]) -> Path:
        return self._download_to_path(sample_id, "original", output_path)

    def download_dropped_file(self, sample_id: str, output_path: str | os.PathLike[str]) -> Path:
        return self._download_to_path(sample_id, "dropped", output_path)

    def download_pcap_file(self, sample_id: str, output_path: str | os.PathLike[str]) -> Path:
        return self._download_to_path(sample_id, "pcap", output_path)

    def get_original_file_bytes(self, sample_id: str) -> bytes:
        return self._download_bytes(sample_id, "original")

    def get_dropped_file_bytes(self, sample_id: str) -> bytes:
        return self._download_bytes(sample_id, "dropped")

    def get_pcap_file_bytes(self, sample_id: str) -> bytes:
        return self._download_bytes(sample_id, "pcap")

    def get_original_file_metadata(self, sample_id: str) -> DownloadArtifactMetadata:
        return self._get_download_metadata(sample_id, "original")

    def get_dropped_file_metadata(self, sample_id: str) -> DownloadArtifactMetadata:
        return self._get_download_metadata(sample_id, "dropped")

    def get_pcap_file_metadata(self, sample_id: str) -> DownloadArtifactMetadata:
        return self._get_download_metadata(sample_id, "pcap")

    def get_report_page_html(self, sample_id: str) -> str:
        response = self._request("GET", f"/ba/report?id={sample_id}", expected_status=(200,))
        return response.text

    def list_components(self) -> list[str]:
        return sorted(REPORT_ENDPOINTS.keys())

    def _get_json(
        self,
        path: str,
        *,
        sample_id: str | None = None,
        component: str | None = None,
    ) -> dict[str, Any] | list[Any]:
        response = self._request("GET", path, expected_status=(200, 404))
        if response.status_code == 404:
            if sample_id is not None:
                raise ReportNotFoundError(
                    f"Sample {sample_id} was not found while fetching {component or path}"
                )
            raise ReportNotFoundError(f"Resource not found: {path}")
        try:
            return response.json()
        except ValueError as exc:
            raise ZscalerClientError(f"Response from {path} was not valid JSON") from exc

    def _download_available(self, sample_id: str, artifact: str) -> bool:
        response = self._download_request(sample_id, artifact, expected_status=(200, 404), stream=True)
        response.close()
        return response.status_code == 200

    def _download_to_path(
        self,
        sample_id: str,
        artifact: str,
        output_path: str | os.PathLike[str],
    ) -> Path:
        response = self._download_request(sample_id, artifact, expected_status=(200, 404), stream=True)
        if response.status_code == 404:
            response.close()
            raise DownloadNotAvailableError(
                f"{artifact} download is not available for sample {sample_id}"
            )

        stream = response.iter_content(chunk_size=8192)
        first_chunk = next(stream, b"")
        metadata = self._build_download_metadata(response, artifact, first_chunk)
        path = self._resolve_download_path(output_path, metadata)
        path.parent.mkdir(parents=True, exist_ok=True)

        with path.open("wb") as handle:
            if first_chunk:
                handle.write(first_chunk)
            for chunk in stream:
                if chunk:
                    handle.write(chunk)
        response.close()
        return path

    def _download_bytes(self, sample_id: str, artifact: str) -> bytes:
        response = self._download_request(sample_id, artifact, expected_status=(200, 404), stream=False)
        if response.status_code == 404:
            raise DownloadNotAvailableError(
                f"{artifact} download is not available for sample {sample_id}"
            )
        return response.content

    def _get_download_metadata(self, sample_id: str, artifact: str) -> DownloadArtifactMetadata:
        response = self._download_request(sample_id, artifact, expected_status=(200, 404), stream=True)
        if response.status_code == 404:
            response.close()
            raise DownloadNotAvailableError(
                f"{artifact} download is not available for sample {sample_id}"
            )
        first_chunk = next(response.iter_content(chunk_size=512), b"")
        metadata = self._build_download_metadata(response, artifact, first_chunk)
        response.close()
        return metadata

    def _build_download_metadata(
        self,
        response: requests.Response,
        artifact: str,
        sample: bytes,
    ) -> DownloadArtifactMetadata:
        filename = self._extract_filename(response.headers.get("Content-Disposition"))
        detected_type, extension = self._detect_file_type(sample)

        if extension == ".bin" and filename:
            extension = Path(filename).suffix or extension

        size_header = response.headers.get("Content-Length")
        size = int(size_header) if size_header and size_header.isdigit() else None

        return DownloadArtifactMetadata(
            artifact=artifact,
            filename=filename,
            content_type=response.headers.get("Content-Type"),
            detected_type=detected_type,
            extension=extension,
            size=size,
        )

    def _resolve_download_path(
        self,
        output_path: str | os.PathLike[str],
        metadata: DownloadArtifactMetadata,
    ) -> Path:
        path = Path(output_path)

        if path.exists() and path.is_dir():
            return path / self._preferred_filename(metadata)

        if path.suffix.lower() in {"", ".zs"}:
            return path.with_suffix(metadata.extension)

        return path

    def _preferred_filename(self, metadata: DownloadArtifactMetadata) -> str:
        if metadata.filename:
            return metadata.filename
        return f"{metadata.artifact}{metadata.extension}"

    def _extract_filename(self, content_disposition: str | None) -> str | None:
        if not content_disposition:
            return None

        filename_star = re.search(r"filename\*=([^']*)''([^;]+)", content_disposition, re.IGNORECASE)
        if filename_star:
            return unquote(filename_star.group(2).strip().strip('"'))

        filename = re.search(r'filename="?([^";]+)"?', content_disposition, re.IGNORECASE)
        if filename:
            return filename.group(1).strip()

        return None

    def _detect_file_type(self, sample: bytes) -> tuple[str, str]:
        if sample.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
            return ("zip", ".zip")

        if sample.startswith(
            (
                b"\xd4\xc3\xb2\xa1",
                b"\xa1\xb2\xc3\xd4",
                b"\x4d\x3c\xb2\xa1",
                b"\xa1\xb2\x3c\x4d",
            )
        ):
            return ("pcap", ".pcap")

        if sample.startswith(b"\x1f\x8b"):
            return ("gzip", ".gz")

        return ("binary", ".bin")

    def _download_request(
        self,
        sample_id: str,
        artifact: str,
        *,
        expected_status: tuple[int, ...],
        stream: bool,
    ) -> requests.Response:
        endpoint = DOWNLOAD_ENDPOINTS.get(artifact)
        if endpoint is None:
            raise ZscalerClientError(f"Unknown download artifact: {artifact}")

        normalized_sample_id = sample_id.lower()
        path = f"/ba/api/v1/reports/{normalized_sample_id}/{endpoint}"
        return self._request("GET", path, expected_status=expected_status, stream=stream)

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        session.verify = self.config.verify_ssl
        session.cookies.set("JSESSIONID", self.config.jsessionid, domain="baui.zscalerfeed.net")
        session.headers.update(
            {
                "Accept": "application/json, text/plain, */*",
                "User-Agent": "smba-data-pull/0.1",
            }
        )
        return session

    def _get_session(self) -> requests.Session:
        session = getattr(self._thread_local, "session", None)
        if session is None:
            session = self._create_session()
            self._thread_local.session = session
        return session

    def _fetch_named_calls(self, call_map: dict[str, Any]) -> dict[str, Any]:
        if len(call_map) <= 1 or self.config.max_workers == 1:
            return {name: func() for name, func in call_map.items()}

        results: dict[str, Any] = {}
        with ThreadPoolExecutor(max_workers=min(self.config.max_workers, len(call_map))) as executor:
            future_map = {executor.submit(func): name for name, func in call_map.items()}
            for future in as_completed(future_map):
                results[future_map[future]] = future.result()
        return results

    def _request(
        self,
        method: str,
        path: str,
        *,
        expected_status: tuple[int, ...] = (200,),
        **kwargs: Any,
    ) -> requests.Response:
        url = urljoin(f"{self.config.base_url}/", path.lstrip("/"))
        response = self._get_session().request(method, url, timeout=self.config.timeout, **kwargs)
        if response.status_code not in expected_status:
            raise ZscalerClientError(
                f"{method} {url} failed with status {response.status_code}: {response.text[:500]}"
            )
        return response


def build_client(env_file: str = ".env") -> ZscalerReportClient:
    return ZscalerReportClient(ZscalerConfig.from_env(env_file=env_file))
