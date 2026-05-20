"""Tests for NVD enrichment + the rich Description/Solution columns in
the findings report."""

import uuid
from datetime import datetime
from unittest.mock import patch

import pytest

from src.common.models import CveDetails, Finding, FindingStaging
from src.ingestion.nvd_enrichment import _parse_nvd_response, enrich_unique_cves_for_run
from src.reporting import csv_reports


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


class TestParseNvdResponse:
    def test_parses_full_response(self):
        sample = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2024-1234",
                    "published": "2024-01-15T08:00:00.000",
                    "descriptions": [
                        {"lang": "en", "value": "A remote attacker can..."},
                        {"lang": "es", "value": "Un atacante remoto..."},
                    ],
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}
                        }]
                    },
                    "weaknesses": [{
                        "description": [{"lang": "en", "value": "CWE-79"}]
                    }],
                    "references": [
                        {"url": "https://vendor.com/advisory", "source": "vendor"},
                        {"url": "https://github.com/blah", "source": "github"},
                    ],
                }
            }]
        }

        result = _parse_nvd_response(sample, "CVE-2024-1234")
        assert result is not None
        assert result["description"] == "A remote attacker can..."
        assert result["cvss_v3_score"] == 9.8
        assert result["cvss_v3_severity"] == "CRITICAL"
        assert result["cwe_id"] == "CWE-79"
        assert len(result["references"]) == 2
        assert result["references"][0]["url"] == "https://vendor.com/advisory"

    def test_handles_missing_fields(self):
        sample = {"vulnerabilities": [{"cve": {"id": "CVE-2024-1234"}}]}
        result = _parse_nvd_response(sample, "CVE-2024-1234")
        assert result is not None
        assert result["description"] is None
        assert result["cvss_v3_score"] is None
        assert result["references"] == []

    def test_empty_response(self):
        assert _parse_nvd_response({"vulnerabilities": []}, "CVE-2024-1234") is None


# ---------------------------------------------------------------------------
# Enrichment dispatcher (mocked HTTP)
# ---------------------------------------------------------------------------


class TestEnrichUniqueCvesForRun:
    def test_fetches_uncached_cves(self, db_session):
        run_id = uuid.uuid4()
        db_session.add(FindingStaging(
            id=uuid.uuid4(), run_id=run_id, tenable_finding_id="f1",
            title="t", severity="HIGH", cve_id="CVE-2024-0001", tenable_state="ACTIVE",
        ))
        db_session.add(FindingStaging(
            id=uuid.uuid4(), run_id=run_id, tenable_finding_id="f2",
            title="t", severity="HIGH", cve_id="CVE-2024-0002", tenable_state="ACTIVE",
        ))
        db_session.flush()

        def fake_fetch(client, cve_id, api_key):
            return {
                "cve_id": cve_id,
                "description": f"desc for {cve_id}",
                "cvss_v3_score": 7.5,
                "cvss_v3_severity": "HIGH",
                "cwe_id": None,
                "cwe_name": None,
                "published_at": None,
                "references": [],
            }

        with patch("src.ingestion.nvd_enrichment._fetch_one", side_effect=fake_fetch):
            with patch("src.ingestion.nvd_enrichment.time.sleep"):
                count = enrich_unique_cves_for_run(db_session, run_id, ttl_days=30)

        assert count == 2
        cves = db_session.query(CveDetails).all()
        assert {c.cve_id for c in cves} == {"CVE-2024-0001", "CVE-2024-0002"}

    def test_skips_cached_within_ttl(self, db_session):
        run_id = uuid.uuid4()
        db_session.add(FindingStaging(
            id=uuid.uuid4(), run_id=run_id, tenable_finding_id="f1",
            title="t", severity="HIGH", cve_id="CVE-2024-0001", tenable_state="ACTIVE",
        ))
        db_session.add(CveDetails(
            cve_id="CVE-2024-0001",
            description="cached",
            last_fetched_at=datetime.utcnow(),
        ))
        db_session.flush()

        with patch("src.ingestion.nvd_enrichment._fetch_one") as fake:
            count = enrich_unique_cves_for_run(db_session, run_id, ttl_days=30)
            fake.assert_not_called()

        assert count == 0


# ---------------------------------------------------------------------------
# Report — uses NVD data
# ---------------------------------------------------------------------------


def _make_finding(session, **kwargs):
    defaults = dict(
        id=uuid.uuid4(),
        tenable_finding_id=f"f-{uuid.uuid4()}",
        title="CVE-2024-0001",
        cve_id="CVE-2024-0001",
        severity="HIGH",
        vpr_score=7.5,
        risk_model="custom",
        risk_score=0.6,
        risk_rating="HIGH",
        sla_days=30,
        sla_status="WITHIN_SLA",
        state="OPEN",
        asset_name="server-01",
        source="CLOUD_SCAN",
        asset_criticality_score=0.5,
    )
    defaults.update(kwargs)
    f = Finding(**defaults)
    session.add(f)
    session.flush()
    return f


def _make_cve(session, **kwargs):
    defaults = dict(
        cve_id="CVE-2024-0001",
        description="A remote attacker can execute arbitrary code.",
        cvss_v3_score=9.8,
        cwe_id="CWE-94",
        references=[
            {"url": "https://vendor.com/CVE-2024-0001", "source": "vendor"},
            {"url": "https://nvd.nist.gov/vuln/CVE-2024-0001", "source": "nist"},
        ],
        last_fetched_at=datetime.utcnow(),
        source="nvd",
    )
    defaults.update(kwargs)
    c = CveDetails(**defaults)
    session.add(c)
    session.flush()
    return c


class TestReportEnrichedColumns:
    def test_description_includes_nvd_text(self, db_session):
        _make_finding(db_session)
        _make_cve(db_session)
        out = csv_reports.report_findings(db_session)

        # Header should include the new columns
        assert "description" in out
        assert "solution" in out
        assert "references" in out
        # Description should mention the CVE id, severity, and NVD text
        assert "CVE-2024-0001" in out
        assert "remote attacker can execute" in out
        assert "CVSS v3: 9.8" in out

    def test_solution_includes_references_when_solution_empty(self, db_session):
        _make_finding(db_session, solution=None)
        _make_cve(db_session)
        out = csv_reports.report_findings(db_session)
        # Should have synthesised guidance + the vendor URLs
        assert "No vendor-specific solution available from Tenable" in out
        assert "https://vendor.com/CVE-2024-0001" in out

    def test_solution_prefers_tenable_when_present(self, db_session):
        _make_finding(db_session, solution="Upgrade to v2.5.1")
        _make_cve(db_session)
        out = csv_reports.report_findings(db_session)
        assert "Upgrade to v2.5.1" in out
        # References should still be included as a separate paragraph
        assert "References:" in out

    def test_works_without_cve_details_row(self, db_session):
        _make_finding(db_session)  # no matching CveDetails
        out = csv_reports.report_findings(db_session)
        # Should still produce something usable — at least the title
        assert "CVE-2024-0001" in out

    def test_finding_without_cve_id(self, db_session):
        _make_finding(db_session, cve_id=None, title="S3 Bucket Public Access")
        out = csv_reports.report_findings(db_session)
        assert "S3 Bucket Public Access" in out
