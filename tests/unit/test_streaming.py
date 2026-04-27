"""Tests for the streaming/resume logic in TenableClient and pipeline."""

import uuid
from unittest.mock import patch

import pytest

from src.common.config import AppConfig, AppSettings, TenableConfig
from src.ingestion.tenable_client import TenableClient, TenableFindingsPage


def _make_finding(fid: str) -> dict:
    return {
        "id": fid,
        "name": "test",
        "severity": "HIGH",
        "state": "ACTIVE",
        "extra_properties": {"asset_name": f"asset-{fid}"},
    }


class TestIterPages:
    """Tests for the iter_pages generator."""

    def test_yields_pages_in_order(self):
        """iter_pages yields each page returned by _fetch_page."""
        cfg = TenableConfig(page_size=2)
        client = TenableClient(config=cfg, access_key="x", secret_key="y")

        pages = [
            TenableFindingsPage(findings=[_make_finding("1"), _make_finding("2")], total=5, offset=0, limit=2),
            TenableFindingsPage(findings=[_make_finding("3"), _make_finding("4")], total=5, offset=2, limit=2),
            TenableFindingsPage(findings=[_make_finding("5")], total=5, offset=4, limit=2),
        ]

        with patch.object(client, "_fetch_page", side_effect=pages):
            result = list(client.iter_pages())

        assert len(result) == 3
        assert result[0].findings[0]["id"] == "1"
        assert result[2].findings[0]["id"] == "5"

    def test_iter_pages_starts_at_offset(self):
        """iter_pages respects the start_offset parameter."""
        cfg = TenableConfig(page_size=2)
        client = TenableClient(config=cfg, access_key="x", secret_key="y")

        recorded_offsets = []

        def fake_fetch(offset, limit, filters=None):
            recorded_offsets.append(offset)
            if offset >= 4:
                return TenableFindingsPage(findings=[_make_finding(str(offset))], total=5, offset=offset, limit=limit)
            return TenableFindingsPage(
                findings=[_make_finding(str(offset)), _make_finding(str(offset + 1))],
                total=5, offset=offset, limit=limit,
            )

        with patch.object(client, "_fetch_page", side_effect=fake_fetch):
            result = list(client.iter_pages(start_offset=2))

        assert recorded_offsets[0] == 2
        # First page returned should be the one starting at offset 2
        assert result[0].offset == 2

    def test_paginate_findings_uses_iter_pages(self):
        """Backward-compat wrapper accumulates all pages."""
        cfg = TenableConfig(page_size=2)
        client = TenableClient(config=cfg, access_key="x", secret_key="y")

        pages = [
            TenableFindingsPage(findings=[_make_finding("1"), _make_finding("2")], total=3, offset=0, limit=2),
            TenableFindingsPage(findings=[_make_finding("3")], total=3, offset=2, limit=2),
        ]
        with patch.object(client, "_fetch_page", side_effect=pages):
            all_findings = client.paginate_findings()

        assert len(all_findings) == 3
        ids = [f["id"] for f in all_findings]
        assert ids == ["1", "2", "3"]
