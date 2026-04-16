"""Tests for the Tenable API client with mocked responses."""

import json
from pathlib import Path

import pytest

from src.common.config import TenableConfig
from src.ingestion.tenable_client import MockTenableClient
from src.ingestion.tenable_ingestion import normalise_finding


FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


class TestMockTenableClient:
    """Tests for the mock client and fixture loading."""

    def test_loads_fixture(self):
        """MockTenableClient loads findings from JSON fixture."""
        client = MockTenableClient(str(FIXTURES_DIR / "sample_tenable_findings.json"))
        findings = client.fetch_findings()
        assert len(findings) == 7
        assert findings[0]["id"] == "finding-001"

    def test_fetch_findings_is_unified_entry_point(self):
        """fetch_findings works regardless of mode parameter."""
        client = MockTenableClient(str(FIXTURES_DIR / "sample_tenable_findings.json"))
        assert len(client.fetch_findings(mode="search")) == 7
        assert len(client.fetch_findings(mode="export")) == 7

    def test_backward_compat_methods(self):
        """paginate_findings and export_findings still work."""
        client = MockTenableClient(str(FIXTURES_DIR / "sample_tenable_findings.json"))
        assert len(client.paginate_findings()) == 7
        assert len(client.export_findings()) == 7

    def test_finding_has_expected_fields(self):
        """Each finding has the expected structure."""
        client = MockTenableClient(str(FIXTURES_DIR / "sample_tenable_findings.json"))
        findings = client.fetch_findings()
        f = findings[0]
        assert "id" in f
        assert "name" in f
        assert "severity" in f
        assert "state" in f
        assert "extra_properties" in f
        assert "vpr_score" in f["extra_properties"]


class TestFindingNormalisation:
    """Tests for normalising raw Tenable findings to staging records."""

    def test_normalises_standard_finding(self, run_id, sample_finding_data):
        staged = normalise_finding(sample_finding_data, run_id)
        assert staged.tenable_finding_id == "finding-test-001"
        assert staged.title == "Test Vulnerability"
        assert staged.severity == "High"
        assert staged.vpr_score == 7.5
        assert staged.cve_id == "CVE-2024-0001"
        assert staged.source == "CloudSecurity"
        assert staged.asset_name == "test-server-01"
        assert staged.tenable_state == "Active"
        assert staged.run_id == run_id

    def test_normalises_missing_fields(self, run_id):
        """Finding with minimal fields should normalise without errors."""
        raw = {
            "id": "finding-minimal",
            "name": "Minimal Finding",
            "severity": "Low",
            "state": "Active",
        }
        staged = normalise_finding(raw, run_id)
        assert staged.tenable_finding_id == "finding-minimal"
        assert staged.vpr_score is None
        assert staged.cve_id is None
        assert staged.asset_name is None

    def test_normalises_fixed_finding(self, run_id):
        """Finding with Fixed state should be normalised correctly."""
        raw = {
            "id": "finding-fixed",
            "name": "Fixed Vuln",
            "severity": "Critical",
            "state": "Fixed",
            "extra_properties": {"vpr_score": 9.0},
        }
        staged = normalise_finding(raw, run_id)
        assert staged.tenable_state == "Fixed"
        assert staged.vpr_score == 9.0

    def test_normalises_all_fixture_findings(self, run_id):
        """All findings in the fixture should normalise without errors."""
        data = json.loads((FIXTURES_DIR / "sample_tenable_findings.json").read_text())
        for raw in data:
            staged = normalise_finding(raw, run_id)
            assert staged.tenable_finding_id is not None
            assert staged.title is not None
