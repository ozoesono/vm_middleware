"""Client for the Tenable One Inventory API (Exposure Management).

This is the SINGLE source of truth for all vulnerability and misconfiguration
findings. The Inventory API aggregates data from all Tenable modules:
  - Tenable Vulnerability Management (infrastructure findings)
  - Tenable Cloud Security (cloud misconfigs, VM & container vulns)
  - Tenable Web App Scanning (web application findings)
  - Third-party connectors (Orca, PrismaCloud, etc.)

Two retrieval modes are supported:
  1. Synchronous Search — paginated, immediate results (good for <50k findings)
  2. Async Export — queued, chunked download (designed for large datasets)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from src.common.config import TenableConfig
from src.common.logging import get_logger

logger = get_logger("tenable_client")


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class TenableAPIError(Exception):
    """Raised when the Tenable API returns an error."""

    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
        super().__init__(f"Tenable API error {status_code}: {message}")


class TenableRateLimitError(TenableAPIError):
    """Raised on 429 rate limit responses."""
    pass


class TenableExportTimeoutError(TenableAPIError):
    """Raised when an async export does not complete within the allowed time."""
    pass


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class TenableFindingsPage:
    """A single page of findings from the synchronous search API."""
    findings: list[dict[str, Any]]
    total: int
    offset: int
    limit: int


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


@dataclass
class TenableClient:
    """Client for the Tenable One Inventory API.

    Provides two ways to retrieve findings from the unified Exposure Management
    Inventory:

    1. ``paginate_findings()`` — Synchronous search via
       ``POST /api/v1/t1/inventory/findings/search``.
       Returns pages of up to 10,000 findings. Best for datasets under ~50k.

    2. ``export_findings()`` — Asynchronous bulk export via
       ``POST /api/v1/t1/inventory/export/findings`` → poll status → download chunks.
       Designed for large datasets. Returns findings in JSON chunks.

    Usage::

        client = TenableClient(config=cfg, access_key="...", secret_key="...")

        # Option A: Synchronous search
        findings = client.paginate_findings()

        # Option B: Async export (for large datasets)
        findings = client.export_findings()
    """

    config: TenableConfig
    access_key: str
    secret_key: str
    _http_client: httpx.Client | None = field(default=None, repr=False)

    @property
    def http_client(self) -> httpx.Client:
        if self._http_client is None:
            self._http_client = httpx.Client(
                base_url=self.config.base_url,
                headers={
                    "X-ApiKeys": f"accessKey={self.access_key};secretKey={self.secret_key}",
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                timeout=httpx.Timeout(self.config.request_timeout_seconds),
            )
        return self._http_client

    def close(self) -> None:
        """Close the HTTP client."""
        if self._http_client is not None:
            self._http_client.close()
            self._http_client = None

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _raise_for_status(self, response: httpx.Response) -> None:
        """Raise appropriate exception for error status codes."""
        if response.status_code == 429:
            raise TenableRateLimitError(429, "Rate limit exceeded")
        if response.status_code == 401:
            raise TenableAPIError(401, "Invalid API keys")
        if response.status_code == 403:
            raise TenableAPIError(403, "Insufficient permissions — check licence includes Exposure Management")
        if response.status_code >= 400:
            raise TenableAPIError(response.status_code, response.text[:500])

    # ==================================================================
    # MODE 1: Synchronous Search
    # POST /api/v1/t1/inventory/findings/search
    # ==================================================================

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=2, min=4, max=60),
        retry=retry_if_exception_type(TenableRateLimitError),
    )
    def _fetch_page(
        self,
        offset: int = 0,
        limit: int | None = None,
        filters: list[dict] | None = None,
    ) -> TenableFindingsPage:
        """Fetch a single page of findings via the synchronous search API."""
        limit = limit or self.config.page_size
        params = {
            "offset": offset,
            "limit": limit,
            "extra_properties": self.config.extra_properties,
            "sort": "finding_severity:desc",
        }

        body: dict[str, Any] = {}
        if filters:
            body["filters"] = filters

        logger.debug("search_fetching_page", offset=offset, limit=limit)
        response = self.http_client.post(
            self.config.findings_endpoint,
            params=params,
            json=body,  # always send a body (even {}); API returns 415 otherwise
        )
        self._raise_for_status(response)

        data = response.json()
        pagination = data.get("pagination", {})

        return TenableFindingsPage(
            findings=data.get("data", []),
            total=pagination.get("total", 0),
            offset=pagination.get("offset", offset),
            limit=pagination.get("limit", limit),
        )

    def paginate_findings(
        self,
        filters: list[dict] | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch ALL findings via synchronous paginated search.

        Uses: POST /api/v1/t1/inventory/findings/search
        Best for: datasets under ~50,000 findings.
        """
        all_findings: list[dict[str, Any]] = []
        offset = 0
        limit = self.config.page_size
        total = None

        while True:
            page = self._fetch_page(offset=offset, limit=limit, filters=filters)

            if total is None:
                total = page.total
                logger.info("search_findings_total", total=total)

            all_findings.extend(page.findings)
            logger.info(
                "search_page_fetched",
                offset=offset,
                fetched=len(page.findings),
                cumulative=len(all_findings),
                total=total,
            )

            if len(all_findings) >= total or len(page.findings) == 0:
                break

            offset += limit

        logger.info("search_complete", total_findings=len(all_findings))
        return all_findings

    # ==================================================================
    # MODE 2: Asynchronous Export
    # POST /api/v1/t1/inventory/export/findings  → poll → download
    # ==================================================================

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=2, min=4, max=60),
        retry=retry_if_exception_type(TenableRateLimitError),
    )
    def _initiate_export(
        self,
        filters: list[dict] | None = None,
    ) -> str:
        """Queue an async findings export. Returns the export_id."""
        params = {
            "properties": self.config.extra_properties,
            "file_format": "JSON",
            "compress": "false",
        }

        body: dict[str, Any] = {}
        if filters:
            body["filters"] = filters

        logger.info("export_initiating")
        response = self.http_client.post(
            self.config.export_endpoint,
            params=params,
            json=body,  # always send a body (even {})
        )
        self._raise_for_status(response)

        data = response.json()
        export_id = data.get("export_id", "")
        logger.info("export_queued", export_id=export_id)
        return export_id

    def _poll_export_status(
        self,
        export_id: str,
        poll_interval: int = 10,
        max_wait: int = 600,
    ) -> dict[str, Any]:
        """Poll export status until FINISHED or timeout.

        Returns the status response including chunk info.
        """
        elapsed = 0
        while elapsed < max_wait:
            response = self.http_client.get(
                f"/api/v1/t1/inventory/export/{export_id}/status"
            )
            self._raise_for_status(response)

            data = response.json()
            status = data.get("status", "UNKNOWN")
            logger.info("export_status", export_id=export_id, status=status, elapsed=elapsed)

            if status == "FINISHED":
                return data
            elif status in ("ERROR", "CANCELLED"):
                raise TenableAPIError(500, f"Export {export_id} failed with status: {status}")

            time.sleep(poll_interval)
            elapsed += poll_interval

        raise TenableExportTimeoutError(
            408, f"Export {export_id} did not complete within {max_wait}s"
        )

    def _download_export_chunks(
        self,
        export_id: str,
        chunk_ids: list[int],
    ) -> list[dict[str, Any]]:
        """Download all chunks for a completed export."""
        all_findings: list[dict[str, Any]] = []

        for chunk_id in chunk_ids:
            logger.info("export_downloading_chunk", export_id=export_id, chunk_id=chunk_id)
            response = self.http_client.get(
                f"/api/v1/t1/inventory/export/{export_id}/download/{chunk_id}"
            )
            self._raise_for_status(response)

            chunk_data = response.json()
            # Chunks may be a list of findings or wrapped in a data key
            if isinstance(chunk_data, list):
                all_findings.extend(chunk_data)
            elif isinstance(chunk_data, dict):
                all_findings.extend(chunk_data.get("data", chunk_data.get("findings", [])))

            logger.info(
                "export_chunk_downloaded",
                chunk_id=chunk_id,
                findings_in_chunk=len(chunk_data) if isinstance(chunk_data, list) else "wrapped",
                cumulative=len(all_findings),
            )

        return all_findings

    def export_findings(
        self,
        filters: list[dict] | None = None,
        poll_interval: int = 10,
        max_wait: int = 600,
    ) -> list[dict[str, Any]]:
        """Fetch ALL findings via async bulk export.

        Uses:
          POST /api/v1/t1/inventory/export/findings  (initiate)
          GET  /api/v1/export/{export_id}/status      (poll)
          GET  /api/v1/export/{export_id}/download/{chunk_id}  (download)

        Best for: large datasets (50k+ findings).
        """
        # Step 1: Initiate export
        export_id = self._initiate_export(filters=filters)

        # Step 2: Poll until complete
        status_data = self._poll_export_status(
            export_id,
            poll_interval=poll_interval,
            max_wait=max_wait,
        )

        # Step 3: Download all chunks
        # The status response should contain chunk IDs — extract them
        chunks = status_data.get("chunks", [])
        if not chunks:
            # Some API versions use chunks_available or similar
            chunks_available = status_data.get("chunks_available", [])
            if chunks_available:
                chunks = chunks_available
            else:
                # Fall back to trying chunk 0
                logger.warning("export_no_chunks_listed", export_id=export_id)
                chunks = [0]

        all_findings = self._download_export_chunks(export_id, chunks)
        logger.info("export_complete", export_id=export_id, total_findings=len(all_findings))
        return all_findings

    # ==================================================================
    # Unified entry point
    # ==================================================================

    def fetch_findings(
        self,
        filters: list[dict] | None = None,
        mode: str | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch findings using the configured retrieval mode.

        Args:
            filters: Optional API filters
            mode: Override retrieval mode ("search" or "export").
                  If None, uses config.retrieval_mode.

        Returns:
            List of finding dicts from the Tenable Inventory API.
        """
        effective_mode = mode or self.config.retrieval_mode

        if effective_mode == "export":
            return self.export_findings(filters=filters)
        else:
            return self.paginate_findings(filters=filters)


# ---------------------------------------------------------------------------
# Mock client for local development / testing
# ---------------------------------------------------------------------------


class MockTenableClient:
    """Mock client that loads findings from a JSON fixture file."""

    def __init__(self, fixture_path: str):
        import json
        from pathlib import Path

        data = json.loads(Path(fixture_path).read_text())
        if isinstance(data, list):
            self._findings = data
        elif isinstance(data, dict):
            self._findings = data.get("data", data.get("findings", []))
        else:
            self._findings = []

    def fetch_findings(self, filters: list[dict] | None = None, mode: str | None = None) -> list[dict[str, Any]]:
        """Return all findings from the fixture."""
        logger.info("mock_tenable_findings_loaded", total=len(self._findings))
        return self._findings

    # Keep backward compat
    def paginate_findings(self, filters: list[dict] | None = None) -> list[dict[str, Any]]:
        return self.fetch_findings(filters=filters)

    def export_findings(self, filters: list[dict] | None = None, **kwargs) -> list[dict[str, Any]]:
        return self.fetch_findings(filters=filters)

    def close(self) -> None:
        pass
