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
        assert findings[0]["id"] == "0019db22-b421-581f-971d-18b8fc24e6dc"

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
        """Each finding has the actual Tenable Inventory API structure."""
        client = MockTenableClient(str(FIXTURES_DIR / "sample_tenable_findings.json"))
        findings = client.fetch_findings()
        f = findings[0]
        assert "id" in f
        assert "name" in f
        assert "severity" in f
        assert "state" in f
        assert "asset_id" in f
        assert "extra_properties" in f
        extra = f["extra_properties"]
        assert "finding_vpr_score" in extra
        assert "finding_cves" in extra
        assert isinstance(extra["finding_cves"], list)


class TestFindingNormalisation:
    """Tests for normalising raw Tenable findings to staging records."""

    def test_normalises_standard_finding(self, run_id):
        """Normalise a finding with the real Tenable field names."""
        raw = {
            "id": "0019db22-b421-581f-971d-18b8fc24e6dc",
            "name": "CVE-2023-2640",
            "asset_id": "90908bcc-193b-5eb4-bedb-b5d09953cb6f",
            "state": "ACTIVE",
            "severity": "CRITICAL",
            "extra_properties": {
                "finding_vpr_score": 9.6,
                "finding_cvss3_base_score": 7.8,
                "finding_cves": ["CVE-2023-2640"],
                "finding_solution": "Upgrade the package.",
                "asset_name": "767397682808.dkr.ecr.eu-west-2.amazonaws.com/datahub/bf:build-987f1701",
                "asset_class": "containerImage",
                "sensor_type": "CS:AC_AWS",
                "first_observed_at": "2026-03-15T08:00:00Z",
                "last_observed_at": "2026-04-09T06:00:00Z",
                "ipv4_addresses": ["10.0.1.50"],
            },
        }
        staged = normalise_finding(raw, run_id)
        assert staged.tenable_finding_id == "0019db22-b421-581f-971d-18b8fc24e6dc"
        assert staged.title == "CVE-2023-2640"
        assert staged.severity == "CRITICAL"
        assert staged.vpr_score == 9.6
        assert staged.cvssv3_score == 7.8
        assert staged.cve_id == "CVE-2023-2640"
        assert staged.solution == "Upgrade the package."
        assert staged.source == "CS:AC_AWS"
        assert staged.asset_name == "767397682808.dkr.ecr.eu-west-2.amazonaws.com/datahub/bf:build-987f1701"
        assert staged.asset_type == "containerImage"
        assert staged.asset_ip == "10.0.1.50"
        assert staged.tenable_state == "ACTIVE"
        assert staged.run_id == run_id

    def test_normalises_cve_list_to_first_item(self, run_id):
        """finding_cves is a list — we take the first item."""
        raw = {
            "id": "f-cve-list",
            "name": "CVE-2024-1234",
            "severity": "HIGH",
            "state": "ACTIVE",
            "extra_properties": {
                "finding_cves": ["CVE-2024-1234", "CVE-2024-5678"],
            },
        }
        staged = normalise_finding(raw, run_id)
        assert staged.cve_id == "CVE-2024-1234"

    def test_normalises_empty_cve_list(self, run_id):
        """Empty finding_cves list results in None."""
        raw = {
            "id": "f-no-cve",
            "name": "S3 Public Access",
            "severity": "HIGH",
            "state": "ACTIVE",
            "extra_properties": {"finding_cves": []},
        }
        staged = normalise_finding(raw, run_id)
        assert staged.cve_id is None

    def test_normalises_missing_fields(self, run_id):
        """Finding with minimal fields should normalise without errors."""
        raw = {
            "id": "finding-minimal",
            "name": "Minimal Finding",
            "severity": "LOW",
            "state": "ACTIVE",
        }
        staged = normalise_finding(raw, run_id)
        assert staged.tenable_finding_id == "finding-minimal"
        assert staged.vpr_score is None
        assert staged.cve_id is None
        assert staged.asset_name is None
        assert staged.source is None

    def test_normalises_fixed_finding(self, run_id):
        """Finding with FIXED state should be normalised correctly."""
        raw = {
            "id": "finding-fixed",
            "name": "CVE-2022-22965",
            "severity": "CRITICAL",
            "state": "FIXED",
            "extra_properties": {"finding_vpr_score": 9.5},
        }
        staged = normalise_finding(raw, run_id)
        assert staged.tenable_state == "FIXED"
        assert staged.vpr_score == 9.5

    def test_normalises_resurfaced_finding(self, run_id):
        """Finding with RESURFACED state should be normalised correctly."""
        raw = {
            "id": "finding-resurfaced",
            "name": "CVE-2015-7501",
            "severity": "CRITICAL",
            "state": "RESURFACED",
            "extra_properties": {"finding_vpr_score": 9.0},
        }
        staged = normalise_finding(raw, run_id)
        assert staged.tenable_state == "RESURFACED"

    def test_normalises_tags(self, run_id):
        """Tags should be stored in tenable_tags dict."""
        raw = {
            "id": "f-tags",
            "name": "CVE-2024-0001",
            "severity": "HIGH",
            "state": "ACTIVE",
            "extra_properties": {
                "tag_names": ["Portfolio:payments", "Environment:prod"],
                "tag_ids": ["tag-001", "tag-002"],
            },
        }
        staged = normalise_finding(raw, run_id)
        assert staged.tenable_tags is not None
        assert staged.tenable_tags["tag_names"] == ["Portfolio:payments", "Environment:prod"]
        assert staged.tenable_tags["tag_ids"] == ["tag-001", "tag-002"]

    def test_no_tags_gives_none(self, run_id):
        """No tags results in tenable_tags being None."""
        raw = {
            "id": "f-no-tags",
            "name": "CVE-2024-0002",
            "severity": "LOW",
            "state": "ACTIVE",
            "extra_properties": {},
        }
        staged = normalise_finding(raw, run_id)
        assert staged.tenable_tags is None

    def test_normalises_all_fixture_findings(self, run_id):
        """All findings in the fixture should normalise without errors."""
        data = json.loads((FIXTURES_DIR / "sample_tenable_findings.json").read_text())
        for raw in data:
            staged = normalise_finding(raw, run_id)
            assert staged.tenable_finding_id is not None
            assert staged.title is not None
            assert staged.severity is not None
