"""Tests for the reconciliation engine — all state transition paths."""

import uuid
from datetime import datetime, timedelta

import pytest

from src.common.config import AppConfig, AppSettings
from src.common.db import Base
from src.common.models import Finding, FindingStaging, JiraActionQueue
from src.reconciliation.reconciler import reconcile


class TestReconciliation:
    """Tests for the reconciliation state machine."""

    @pytest.fixture
    def config(self):
        settings = AppSettings(database_url="sqlite:///:memory:", config_dir="config")
        return AppConfig(settings=settings)

    def _make_staged(self, session, run_id, tenable_finding_id="f-001", **kwargs):
        defaults = {
            "id": uuid.uuid4(),
            "run_id": run_id,
            "tenable_finding_id": tenable_finding_id,
            "tenable_asset_id": "asset-001",
            "title": "Test Vuln",
            "severity": "High",
            "vpr_score": 7.0,
            "tenable_state": "Active",
            "first_seen": datetime(2026, 4, 1),
            "last_seen": datetime(2026, 4, 9),
        }
        defaults.update(kwargs)
        sf = FindingStaging(**defaults)
        session.add(sf)
        session.flush()
        return sf

    def _make_finding(self, session, tenable_finding_id="f-001", **kwargs):
        defaults = {
            "id": uuid.uuid4(),
            "tenable_finding_id": tenable_finding_id,
            "tenable_asset_id": "asset-001",
            "title": "Test Vuln",
            "severity": "High",
            "vpr_score": 7.0,
            "state": "OPEN",
            "tenable_state": "Active",
            "risk_model": "custom",
            "risk_score": 0.6,
            "risk_rating": "HIGH",
            "sla_days": 30,
            "sla_status": "WITHIN_SLA",
            "first_seen": datetime(2026, 4, 1),
            "last_seen": datetime(2026, 4, 8),
            "asset_criticality_score": 0.5,
        }
        defaults.update(kwargs)
        f = Finding(**defaults)
        session.add(f)
        session.flush()
        return f

    def test_new_finding(self, db_session, config, run_id):
        """A staged finding with no match in DB is NEW."""
        self._make_staged(db_session, run_id, tenable_finding_id="f-new")

        stats = reconcile(db_session, config, run_id)

        assert stats.findings_new == 1
        assert stats.jira_actions_created == 1

        finding = db_session.query(Finding).filter_by(tenable_finding_id="f-new").first()
        assert finding is not None
        assert finding.state == "OPEN"
        assert finding.risk_score > 0

        action = db_session.query(JiraActionQueue).filter_by(run_id=run_id).first()
        assert action.action == "CREATE"

    def test_still_open(self, db_session, config, run_id):
        """A finding in both DB and staging with Active state = STILL OPEN."""
        self._make_finding(db_session, tenable_finding_id="f-open")
        self._make_staged(db_session, run_id, tenable_finding_id="f-open", tenable_state="Active")

        stats = reconcile(db_session, config, run_id)

        assert stats.findings_updated == 1
        assert stats.findings_new == 0

        finding = db_session.query(Finding).filter_by(tenable_finding_id="f-open").first()
        assert finding.state == "OPEN"
        assert finding.last_seen == datetime(2026, 4, 9)

    def test_remediated(self, db_session, config, run_id):
        """A finding in DB as OPEN + staged with Fixed state = REMEDIATED."""
        self._make_finding(db_session, tenable_finding_id="f-fixed")
        self._make_staged(db_session, run_id, tenable_finding_id="f-fixed", tenable_state="Fixed")

        stats = reconcile(db_session, config, run_id)

        assert stats.findings_remediated == 1

        finding = db_session.query(Finding).filter_by(tenable_finding_id="f-fixed").first()
        assert finding.state == "REMEDIATED"
        assert finding.remediated_at is not None
        assert finding.time_to_fix_days is not None

        action = db_session.query(JiraActionQueue).filter_by(run_id=run_id).first()
        assert action.action == "CLOSE"

    def test_recurrence(self, db_session, config, run_id):
        """A previously REMEDIATED finding that reappears = RECURRENCE."""
        self._make_finding(
            db_session,
            tenable_finding_id="f-recur",
            state="REMEDIATED",
            remediated_at=datetime(2026, 3, 20),
        )
        self._make_staged(
            db_session, run_id, tenable_finding_id="f-recur", tenable_state="Resurfaced"
        )

        stats = reconcile(db_session, config, run_id)

        assert stats.findings_recurred == 1

        finding = db_session.query(Finding).filter_by(tenable_finding_id="f-recur").first()
        assert finding.state == "OPEN"
        assert finding.is_recurrence is True
        assert finding.recurrence_count == 1
        assert finding.remediated_at is None

        action = db_session.query(JiraActionQueue).filter_by(run_id=run_id).first()
        assert action.action == "REOPEN"

    def test_stale(self, db_session, config, run_id):
        """A finding in DB but NOT in staging, past stale threshold = STALE."""
        old_last_seen = datetime.now() - timedelta(days=config.tenable.stale_threshold_days + 1)
        self._make_finding(
            db_session, tenable_finding_id="f-stale", last_seen=old_last_seen
        )
        # No staged finding for f-stale

        stats = reconcile(db_session, config, run_id)

        assert stats.findings_stale == 1

        finding = db_session.query(Finding).filter_by(tenable_finding_id="f-stale").first()
        assert finding.state == "STALE"

    def test_not_stale_if_within_threshold(self, db_session, config, run_id):
        """A finding missing from staging but within threshold is NOT marked stale."""
        recent_last_seen = datetime.now() - timedelta(days=1)
        self._make_finding(
            db_session, tenable_finding_id="f-recent", last_seen=recent_last_seen
        )

        stats = reconcile(db_session, config, run_id)

        assert stats.findings_stale == 0
        finding = db_session.query(Finding).filter_by(tenable_finding_id="f-recent").first()
        assert finding.state == "OPEN"

    def test_multiple_findings_mixed(self, db_session, config, run_id):
        """Test a mix of new, updated, remediated, and stale findings."""
        # Existing OPEN finding that will be updated
        self._make_finding(db_session, tenable_finding_id="f-update")
        # Existing OPEN finding that will be remediated
        self._make_finding(db_session, tenable_finding_id="f-fix")
        # Existing OPEN finding that will go stale
        old = datetime.now() - timedelta(days=30)
        self._make_finding(db_session, tenable_finding_id="f-gone", last_seen=old)

        # Staged: update + fix + new
        self._make_staged(db_session, run_id, tenable_finding_id="f-update", tenable_state="Active")
        self._make_staged(db_session, run_id, tenable_finding_id="f-fix", tenable_state="Fixed")
        self._make_staged(db_session, run_id, tenable_finding_id="f-brand-new")

        stats = reconcile(db_session, config, run_id)

        assert stats.findings_new == 1
        assert stats.findings_updated == 1
        assert stats.findings_remediated == 1
        assert stats.findings_stale == 1
