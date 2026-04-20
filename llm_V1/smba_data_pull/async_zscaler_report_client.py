from __future__ import annotations

import asyncio
import os
import re
from dataclasses import asdict
from pathlib import Path
from typing import Any
from urllib.parse import unquote
from urllib.parse import urljoin

import aiohttp

from zscaler_report_client import DOWNLOAD_ENDPOINTS
from zscaler_report_client import REPORT_ENDPOINTS
from zscaler_report_client import DownloadArtifactMetadata
from zscaler_report_client import DownloadNotAvailableError
from zscaler_report_client import ReportNotFoundError
from zscaler_report_client import ZscalerClientError
from zscaler_report_client import ZscalerConfig


class AsyncZscalerReportClient:
    def __init__(self, config: ZscalerConfig) -> None:
        self.config = config
        self._session: aiohttp.ClientSession | None = None
        self._semaphore = asyncio.Semaphore(config.max_workers)

    async def __aenter__(self) -> "AsyncZscalerReportClient":
        await self._ensure_session()
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        await self.close()

    async def close(self) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None

    async def sample_exists(self, sample_id: str) -> bool:
        path = f"/ba/api/v1/reports/{sample_id}/{REPORT_ENDPOINTS['summary']}"
        response = await self._request("GET", path, expected_status=(200, 404))
        return response.status == 200

    async def get_full_report(
        self,
        sample_id: str,
        *,
        include_artifacts: bool = True,
    ) -> dict[str, Any]:
        sections = await self._gather_named_calls(
            {
                "summary": self.get_summary(sample_id),
                "classification": self.get_classification(sample_id),
                "files": self.get_files(sample_id),
                "traffic": self.get_traffic(sample_id),
                "behavior": self.get_behavior(sample_id),
                "permissions": self.get_permissions(sample_id),
                "mitre": self.get_mitre(sample_id),
                "screenshots": self.get_screenshots(sample_id),
            }
        )

        files = sections["files"]
        report: dict[str, Any] = {
            "sample_id": sample_id,
            "sample_id_lower": sample_id.lower(),
            "exists": True,
            "report_url": f"{self.config.base_url}/ba/report?id={sample_id}",
            **sections,
        }

        apk_file_info = files.get("apk_file_info", {})
        if isinstance(apk_file_info, dict):
            report["identifiers"] = {
                "md5": apk_file_info.get("md5") or sample_id.lower(),
                "sha1": apk_file_info.get("sha"),
                "sha256": apk_file_info.get("sha256"),
                "package_name": apk_file_info.get("packageName"),
            }

        if include_artifacts:
            report["artifacts"] = await self.get_artifacts_summary(sample_id)

        return report

    async def get_analysis_bundle(self, sample_id: str) -> dict[str, Any]:
        return await self.get_full_report(sample_id, include_artifacts=True)

    async def get_core_signal_summary(self, sample_id: str) -> dict[str, Any]:
        report = await self.get_full_report(sample_id, include_artifacts=True)
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

    async def get_summary(self, sample_id: str) -> dict[str, Any]:
        return await self.get_component(sample_id, "summary")

    async def get_classification(self, sample_id: str) -> dict[str, Any]:
        return await self.get_component(sample_id, "classification")

    async def get_permissions(self, sample_id: str) -> dict[str, Any]:
        return await self.get_component(sample_id, "permissions")

    async def get_screenshots(self, sample_id: str) -> dict[str, Any]:
        return await self.get_component(sample_id, "screenshots")

    async def get_files(self, sample_id: str) -> dict[str, Any]:
        return await self._gather_named_calls(
            {
                "apk_file_info": self.get_component(sample_id, "apk_file_info"),
                "download_summary": self.get_component(sample_id, "download_summary"),
                "dropped_files": self.get_component(sample_id, "dropped_files"),
            }
        )

    async def get_traffic(self, sample_id: str) -> dict[str, Any]:
        return await self._gather_named_calls(
            {
                "overview": self.get_component(sample_id, "networking"),
                "http": self.get_component(sample_id, "network_http"),
                "https": self.get_component(sample_id, "network_https"),
                "tcp": self.get_component(sample_id, "network_tcp"),
                "udp": self.get_component(sample_id, "network_udp"),
                "dns": self.get_component(sample_id, "network_dns"),
                "ftp": self.get_component(sample_id, "network_ftp"),
                "smtp": self.get_component(sample_id, "network_smtp"),
                "icmp": self.get_component(sample_id, "network_icmp"),
                "irc": self.get_component(sample_id, "network_irc"),
                "origin": self.get_component(sample_id, "origin"),
            }
        )

    async def get_behavior(self, sample_id: str) -> dict[str, Any]:
        return await self._gather_named_calls(
            {
                "classification": self.get_component(sample_id, "classification"),
                "category_summary": self.get_component(sample_id, "category_summary"),
                "ml_score": self.get_component(sample_id, "ml_score"),
                "virus_malware": self.get_component(sample_id, "virus_malware"),
                "spyware": self.get_component(sample_id, "spyware"),
                "security_bypass": self.get_component(sample_id, "security_bypass"),
                "exploiting": self.get_component(sample_id, "exploiting"),
                "stealth": self.get_component(sample_id, "stealth"),
                "spreading": self.get_component(sample_id, "spreading"),
                "persistence": self.get_component(sample_id, "persistence"),
                "malware_config_extract": self.get_component(sample_id, "malware_config_extract"),
            }
        )

    async def get_mitre(self, sample_id: str) -> dict[str, Any]:
        return await self._gather_named_calls(
            {
                "attack": self.get_component(sample_id, "mitre_attack"),
                "tactics": self.get_component(sample_id, "mitre_attack_tactics"),
            }
        )

    async def get_component(self, sample_id: str, component: str) -> dict[str, Any] | list[Any]:
        endpoint = REPORT_ENDPOINTS.get(component)
        if endpoint is None:
            raise ZscalerClientError(f"Unknown component: {component}")

        if component == "mitre_attack_tactics":
            path = f"/ba/api/v1/reports/{endpoint}"
        else:
            path = f"/ba/api/v1/reports/{sample_id}/{endpoint}"

        return await self._get_json(path, sample_id=sample_id, component=component)

    async def get_artifacts_summary(self, sample_id: str) -> dict[str, Any]:
        async def artifact_summary(artifact: str) -> dict[str, Any]:
            try:
                metadata = await self._get_download_metadata(sample_id, artifact)
                return {"available": True, "metadata": asdict(metadata)}
            except DownloadNotAvailableError:
                return {"available": False, "metadata": None}

        return await self._gather_named_calls(
            {
                artifact: artifact_summary(artifact)
                for artifact in DOWNLOAD_ENDPOINTS
            }
        )

    async def has_original_file(self, sample_id: str) -> bool:
        return await self._download_available(sample_id, "original")

    async def has_dropped_file(self, sample_id: str) -> bool:
        return await self._download_available(sample_id, "dropped")

    async def has_pcap_file(self, sample_id: str) -> bool:
        return await self._download_available(sample_id, "pcap")

    async def get_original_file_metadata(self, sample_id: str) -> DownloadArtifactMetadata:
        return await self._get_download_metadata(sample_id, "original")

    async def get_dropped_file_metadata(self, sample_id: str) -> DownloadArtifactMetadata:
        return await self._get_download_metadata(sample_id, "dropped")

    async def get_pcap_file_metadata(self, sample_id: str) -> DownloadArtifactMetadata:
        return await self._get_download_metadata(sample_id, "pcap")

    async def get_original_file_bytes(self, sample_id: str) -> bytes:
        return await self._download_bytes(sample_id, "original")

    async def get_dropped_file_bytes(self, sample_id: str) -> bytes:
        return await self._download_bytes(sample_id, "dropped")

    async def get_pcap_file_bytes(self, sample_id: str) -> bytes:
        return await self._download_bytes(sample_id, "pcap")

    async def download_original_file(self, sample_id: str, output_path: str | os.PathLike[str]) -> Path:
        return await self._download_to_path(sample_id, "original", output_path)

    async def download_dropped_file(self, sample_id: str, output_path: str | os.PathLike[str]) -> Path:
        return await self._download_to_path(sample_id, "dropped", output_path)

    async def download_pcap_file(self, sample_id: str, output_path: str | os.PathLike[str]) -> Path:
        return await self._download_to_path(sample_id, "pcap", output_path)

    async def _get_json(
        self,
        path: str,
        *,
        sample_id: str | None = None,
        component: str | None = None,
    ) -> dict[str, Any] | list[Any]:
        response = await self._request("GET", path, expected_status=(200, 404))
        if response.status == 404:
            response.release()
            if sample_id is not None:
                raise ReportNotFoundError(
                    f"Sample {sample_id} was not found while fetching {component or path}"
                )
            raise ReportNotFoundError(f"Resource not found: {path}")

        try:
            data = await response.json()
        except Exception as exc:
            text = await response.text()
            raise ZscalerClientError(f"Response from {path} was not valid JSON: {text[:500]}") from exc
        finally:
            response.release()
        return data

    async def _download_available(self, sample_id: str, artifact: str) -> bool:
        response = await self._download_request(sample_id, artifact, expected_status=(200, 404))
        available = response.status == 200
        response.release()
        return available

    async def _download_to_path(
        self,
        sample_id: str,
        artifact: str,
        output_path: str | os.PathLike[str],
    ) -> Path:
        response = await self._download_request(sample_id, artifact, expected_status=(200, 404))
        if response.status == 404:
            response.release()
            raise DownloadNotAvailableError(f"{artifact} download is not available for sample {sample_id}")

        first_chunk = await response.content.read(8192)
        metadata = self._build_download_metadata(response, artifact, first_chunk)
        path = self._resolve_download_path(output_path, metadata)
        path.parent.mkdir(parents=True, exist_ok=True)

        with path.open("wb") as handle:
            if first_chunk:
                handle.write(first_chunk)
            async for chunk in response.content.iter_chunked(8192):
                if chunk:
                    handle.write(chunk)
        response.release()
        return path

    async def _download_bytes(self, sample_id: str, artifact: str) -> bytes:
        response = await self._download_request(sample_id, artifact, expected_status=(200, 404))
        if response.status == 404:
            response.release()
            raise DownloadNotAvailableError(f"{artifact} download is not available for sample {sample_id}")
        data = await response.read()
        response.release()
        return data

    async def _get_download_metadata(self, sample_id: str, artifact: str) -> DownloadArtifactMetadata:
        response = await self._download_request(sample_id, artifact, expected_status=(200, 404))
        if response.status == 404:
            response.release()
            raise DownloadNotAvailableError(f"{artifact} download is not available for sample {sample_id}")
        first_chunk = await response.content.read(512)
        metadata = self._build_download_metadata(response, artifact, first_chunk)
        response.release()
        return metadata

    async def _download_request(
        self,
        sample_id: str,
        artifact: str,
        *,
        expected_status: tuple[int, ...],
    ) -> aiohttp.ClientResponse:
        endpoint = DOWNLOAD_ENDPOINTS.get(artifact)
        if endpoint is None:
            raise ZscalerClientError(f"Unknown download artifact: {artifact}")
        path = f"/ba/api/v1/reports/{sample_id.lower()}/{endpoint}"
        return await self._request("GET", path, expected_status=expected_status)

    async def _request(
        self,
        method: str,
        path: str,
        *,
        expected_status: tuple[int, ...] = (200,),
        **kwargs: Any,
    ) -> aiohttp.ClientResponse:
        session = await self._ensure_session()
        url = urljoin(f"{self.config.base_url}/", path.lstrip("/"))
        async with self._semaphore:
            response = await session.request(method, url, timeout=self.config.timeout, **kwargs)
        if response.status not in expected_status:
            text = await response.text()
            response.release()
            raise ZscalerClientError(
                f"{method} {url} failed with status {response.status}: {text[:500]}"
            )
        return response

    async def _ensure_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector(
                limit=self.config.max_workers,
                limit_per_host=self.config.max_workers,
                ssl=self.config.verify_ssl,
            )
            self._session = aiohttp.ClientSession(
                connector=connector,
                headers={
                    "Accept": "application/json, text/plain, */*",
                    "Cookie": f"JSESSIONID={self.config.jsessionid}",
                    "User-Agent": "smba-data-pull/0.1",
                },
            )
        return self._session

    async def _gather_named_calls(self, call_map: dict[str, Any]) -> dict[str, Any]:
        keys = list(call_map.keys())
        values = await asyncio.gather(*call_map.values())
        return dict(zip(keys, values))

    def _build_download_metadata(
        self,
        response: aiohttp.ClientResponse,
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


def build_async_client(env_file: str = ".env") -> AsyncZscalerReportClient:
    return AsyncZscalerReportClient(ZscalerConfig.from_env(env_file=env_file))
