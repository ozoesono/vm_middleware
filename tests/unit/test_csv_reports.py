"""Tests for CSV report generation."""

import csv
import io
import uuid
from datetime import date, datetime

import pytest

from src.common.models import Finding
from src.reporting import csv_reports


def _make_finding(session, **kwargs):
    defaults = {
        "id": uuid.uuid4(),
        "tenable_finding_id": f"f-{uuid.uuid4()}",
        "title": "CVE-2024-0001",
        "cve_id": "CVE-2024-0001",
        "severity": "HIGH",
        "vpr_score": 7.5,
        "risk_model": "custom",
        "risk_score": 0.6,
        "risk_rating": "HIGH",
        "sla_days": 30,
        "sla_status": "WITHIN_SLA",
        "state": "OPEN",
        "asset_criticality_score": 0.5,
        "portfolio": "Business-Growth",
        "asset_criticality": "High",
    }
    defaults.update(kwargs)
    f = Finding(**defaults)
    session.add(f)
    session.flush()
    return f


def _parse(csv_str):
    return list(csv.DictReader(io.StringIO(csv_str)))


class TestFindingsReport:
    def test_empty(self, db_session):
        out = csv_reports.report_findings(db_session)
        rows = _parse(out)
        assert rows == []
        # header still present
        assert "tenable_finding_id" in out

    def test_basic_export(self, db_session):
        _make_finding(db_session, cve_id="CVE-2024-1111", risk_rating="CRITICAL", risk_score=0.9)
        _make_finding(db_session, cve_id="CVE-2024-2222", risk_rating="LOW", risk_score=0.2)
        rows = _parse(csv_reports.report_findings(db_session))
        assert len(rows) == 2
        # ordered by risk_score desc
        assert rows[0]["cve_id"] == "CVE-2024-1111"
        assert rows[1]["cve_id"] == "CVE-2024-2222"

    def test_filter_by_risk_rating(self, db_session):
        _make_finding(db_session, risk_rating="CRITICAL")
        _make_finding(db_session, risk_rating="LOW")
        rows = _parse(csv_reports.report_findings(db_session, {"risk_rating": "CRITICAL"}))
        assert len(rows) == 1
        assert rows[0]["risk_rating"] == "CRITICAL"

    def test_filter_by_list(self, db_session):
        _make_finding(db_session, risk_rating="CRITICAL")
        _make_finding(db_session, risk_rating="HIGH")
        _make_finding(db_session, risk_rating="LOW")
        rows = _parse(csv_reports.report_findings(
            db_session, {"risk_rating": ["CRITICAL", "HIGH"]}
        ))
        assert len(rows) == 2

    def test_filter_by_portfolio(self, db_session):
        _make_finding(db_session, portfolio="Business-Growth")
        _make_finding(db_session, portfolio="Payments")
        rows = _parse(csv_reports.report_findings(
            db_session, {"portfolio": "Business-Growth"}
        ))
        assert len(rows) == 1


class TestRiskSummary:
    def test_grouping(self, db_session):
        _make_finding(db_session, risk_rating="CRITICAL", portfolio="A", asset_criticality="Critical")
        _make_finding(db_session, risk_rating="CRITICAL", portfolio="A", asset_criticality="Critical")
        _make_finding(db_session, risk_rating="HIGH", portfolio="B", asset_criticality="High")
        rows = _parse(csv_reports.report_risk_summary(db_session))
        # 2 groups
        assert len(rows) == 2
        crit = next(r for r in rows if r["risk_rating"] == "CRITICAL")
        assert crit["count"] == "2"
        assert crit["portfolio"] == "A"


class TestSLAReports:
    def test_breaches_only(self, db_session):
        _make_finding(db_session, sla_status="BREACHED", sla_due_date=date(2026, 1, 1))
        _make_finding(db_session, sla_status="WITHIN_SLA")
        rows = _parse(csv_reports.report_sla_breaches(db_session))
        assert len(rows) == 1
        assert rows[0]["sla_status"] == "BREACHED"

    def test_approaching_only(self, db_session):
        _make_finding(db_session, sla_status="APPROACHING")
        _make_finding(db_session, sla_status="WITHIN_SLA")
        rows = _parse(csv_reports.report_sla_approaching(db_session))
        assert len(rows) == 1


class TestRecurrence:
    def test_only_recurrences(self, db_session):
        _make_finding(db_session, is_recurrence=True, recurrence_count=2)
        _make_finding(db_session, is_recurrence=False)
        rows = _parse(csv_reports.report_recurrence(db_session))
        assert len(rows) == 1
        assert rows[0]["recurrence_count"] == "2"


class TestPortfolioSummary:
    def test_rollup(self, db_session):
        _make_finding(db_session, portfolio="A", risk_rating="CRITICAL", sla_status="BREACHED")
        _make_finding(db_session, portfolio="A", risk_rating="HIGH")
        _make_finding(db_session, portfolio="B", risk_rating="LOW")
        rows = _parse(csv_reports.report_portfolio_summary(db_session))
        assert len(rows) == 2
        a = next(r for r in rows if r["portfolio"] == "A")
        assert a["total_findings"] == "2"
        assert a["critical"] == "1"
        assert a["sla_breached"] == "1"


class TestDispatcher:
    def test_unknown_report_raises(self, db_session):
        with pytest.raises(ValueError, match="Unknown report"):
            csv_reports.generate(db_session, "nonexistent")

    def test_dispatch_works(self, db_session):
        _make_finding(db_session)
        out = csv_reports.generate(db_session, "findings")
        assert "tenable_finding_id" in out
