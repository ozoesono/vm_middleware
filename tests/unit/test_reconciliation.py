"""Tests for the reconciliation engine — all state transition paths."""

import uuid
from datetime import datetime, timedelta

import pytest

from src.common.config import AppConfig, AppSettings
from src.common.db import Base
from src.common.models import Finding, FindingStaging, JiraActionQueue, PipelineRun
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
        self._make_staged(db_session, run_id, tenable_finding_id="f-open", tenable_state="ACTIVE")

        stats = reconcile(db_session, config, run_id)

        assert stats.findings_updated == 1
        assert stats.findings_new == 0

        finding = db_session.query(Finding).filter_by(tenable_finding_id="f-open").first()
        assert finding.state == "OPEN"
        assert finding.last_seen == datetime(2026, 4, 9)

    def test_remediated(self, db_session, config, run_id):
        """A finding in DB as OPEN + staged with Fixed state = REMEDIATED."""
        self._make_finding(db_session, tenable_finding_id="f-fixed")
        self._make_staged(db_session, run_id, tenable_finding_id="f-fixed", tenable_state="FIXED")

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
            db_session, run_id, tenable_finding_id="f-recur", tenable_state="RESURFACED"
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
        """A finding missing from a non-empty scan, past stale threshold = STALE."""
        old_last_seen = datetime.now() - timedelta(days=config.tenable.stale_threshold_days + 1)
        self._make_finding(
            db_session, tenable_finding_id="f-stale", last_seen=old_last_seen
        )
        # The scan returned data (just not this finding), so staging is non-empty.
        self._make_staged(db_session, run_id, tenable_finding_id="f-other")

        stats = reconcile(db_session, config, run_id)

        assert stats.findings_stale == 1

        finding = db_session.query(Finding).filter_by(tenable_finding_id="f-stale").first()
        assert finding.state == "STALE"

    def test_not_stale_if_within_threshold(self, db_session, config, run_id):
        """A finding missing from a non-empty scan but within threshold is NOT stale."""
        recent_last_seen = datetime.now() - timedelta(days=1)
        self._make_finding(
            db_session, tenable_finding_id="f-recent", last_seen=recent_last_seen
        )
        self._make_staged(db_session, run_id, tenable_finding_id="f-other")

        stats = reconcile(db_session, config, run_id)

        assert stats.findings_stale == 0
        finding = db_session.query(Finding).filter_by(tenable_finding_id="f-recent").first()
        assert finding.state == "OPEN"

    def test_empty_pull_does_not_stale(self, db_session, config, run_id):
        """An empty scan (0 findings staged) must NOT age out existing findings.

        Reproduces the incident where a run that fetched 0 findings marked an
        entire portfolio STALE.
        """
        old = datetime.now() - timedelta(days=config.tenable.stale_threshold_days + 5)
        self._make_finding(db_session, tenable_finding_id="f-1", last_seen=old)
        self._make_finding(db_session, tenable_finding_id="f-2", last_seen=old)
        # No staged findings at all — the pull returned nothing.

        stats = reconcile(db_session, config, run_id)

        assert stats.findings_stale == 0
        assert db_session.query(Finding).filter_by(state="STALE").count() == 0
        assert db_session.query(Finding).filter_by(state="OPEN").count() == 2

    def test_scoped_run_does_not_stale_out_of_scope(self, db_session, config, run_id):
        """A tag-scoped run must only stale findings on the assets it pulled."""
        db_session.add(PipelineRun(
            id=run_id,
            started_at=datetime.now(),
            status="RUNNING",
            asset_ids_for_run={"ids": ["asset-A"], "tags": {}},
        ))
        old = datetime.now() - timedelta(days=config.tenable.stale_threshold_days + 5)
        # In scope, missing from this run's scan -> STALE
        self._make_finding(db_session, tenable_finding_id="f-a-gone",
                           tenable_asset_id="asset-A", last_seen=old)
        # Out of scope (an asset this run never pulled) -> must stay OPEN
        self._make_finding(db_session, tenable_finding_id="f-b-safe",
                           tenable_asset_id="asset-B", last_seen=old)
        # Something WAS returned for asset-A, so staging is non-empty
        self._make_staged(db_session, run_id, tenable_finding_id="f-a-present",
                          tenable_asset_id="asset-A")

        stats = reconcile(db_session, config, run_id)

        assert stats.findings_stale == 1
        assert db_session.query(Finding).filter_by(tenable_finding_id="f-a-gone").first().state == "STALE"
        assert db_session.query(Finding).filter_by(tenable_finding_id="f-b-safe").first().state == "OPEN"

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
        self._make_staged(db_session, run_id, tenable_finding_id="f-update", tenable_state="ACTIVE")
        self._make_staged(db_session, run_id, tenable_finding_id="f-fix", tenable_state="FIXED")
        self._make_staged(db_session, run_id, tenable_finding_id="f-brand-new")

        stats = reconcile(db_session, config, run_id)

        assert stats.findings_new == 1
        assert stats.findings_updated == 1
        assert stats.findings_remediated == 1
        assert stats.findings_stale == 1
