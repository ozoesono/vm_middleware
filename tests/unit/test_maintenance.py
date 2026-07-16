"""Tests for maintenance operations: reaping abandoned runs, pruning STALE."""

import uuid
from datetime import datetime, timedelta

from src.common.config import AppConfig, AppSettings
from src.common.models import Finding, PipelineRun
from src.maintenance.retention import prune_stale_findings, reap_stale_runs


def _make_run(session, status, started_at, updated_at, tag_filter=None):
    run = PipelineRun(
        id=uuid.uuid4(),
        status=status,
        started_at=started_at,
        updated_at=updated_at,
        tag_filter=tag_filter,
        last_batch_idx=3,
    )
    session.add(run)
    session.flush()
    return run


class TestReapStaleRuns:
    def test_reaps_abandoned_running_run(self, db_session):
        now = datetime(2026, 7, 16, 12, 0, 0)
        started = now - timedelta(hours=30)
        last_progress = now - timedelta(hours=29)  # died shortly after starting
        run = _make_run(db_session, "RUNNING", started, last_progress)

        reaped = reap_stale_runs(db_session, timeout_hours=6, now=now)

        assert len(reaped) == 1
        assert reaped[0]["id"] == str(run.id)
        assert run.status == "TIMED_OUT"
        # completed_at reflects real work (last progress), NOT the idle gap to now
        assert run.completed_at == last_progress
        assert (run.completed_at - run.started_at) == timedelta(hours=1)

    def test_fresh_running_run_is_not_reaped(self, db_session):
        now = datetime(2026, 7, 16, 12, 0, 0)
        # Long-running but ALIVE: started days ago, but heartbeat is recent.
        run = _make_run(
            db_session, "RUNNING",
            started_at=now - timedelta(days=3),
            updated_at=now - timedelta(minutes=2),
        )

        reaped = reap_stale_runs(db_session, timeout_hours=6, now=now)

        assert reaped == []
        assert run.status == "RUNNING"

    def test_partial_failure_is_not_reaped(self, db_session):
        now = datetime(2026, 7, 16, 12, 0, 0)
        # PARTIAL_FAILURE is intentionally resumable and already has completed_at.
        run = _make_run(
            db_session, "PARTIAL_FAILURE",
            started_at=now - timedelta(days=5),
            updated_at=now - timedelta(days=5),
        )

        reaped = reap_stale_runs(db_session, timeout_hours=6, now=now)

        assert reaped == []
        assert run.status == "PARTIAL_FAILURE"

    def test_dry_run_changes_nothing(self, db_session):
        now = datetime(2026, 7, 16, 12, 0, 0)
        run = _make_run(
            db_session, "RUNNING",
            started_at=now - timedelta(hours=30),
            updated_at=now - timedelta(hours=30),
        )

        reaped = reap_stale_runs(db_session, timeout_hours=6, dry_run=True, now=now)

        assert len(reaped) == 1  # reported...
        assert run.status == "RUNNING"  # ...but not mutated
        assert run.completed_at is None

    def test_last_progress_falls_back_to_started_at_when_no_heartbeat(self):
        # Detached object (never INSERTed), so server_default/onupdate don't
        # fire — models a pre-migration row whose updated_at is genuinely NULL.
        from src.maintenance.retention import _last_progress

        run = PipelineRun(
            id=uuid.uuid4(),
            started_at=datetime(2026, 7, 1, 0, 0, 0),
            updated_at=None,
        )
        assert _last_progress(run) == datetime(2026, 7, 1, 0, 0, 0)
        run.updated_at = datetime(2026, 7, 2, 0, 0, 0)
        assert _last_progress(run) == datetime(2026, 7, 2, 0, 0, 0)


class TestReapIntegratedWithSetup:
    def _config(self, tag_filter=None):
        settings = AppSettings(database_url="sqlite:///:memory:", config_dir="config")
        cfg = AppConfig(settings=settings)
        cfg.tenable.tag_filter = tag_filter
        return cfg

    def test_zombie_run_does_not_hijack_auto_resume(self, db_session):
        """An abandoned RUNNING run with matching tags must be reaped, not
        silently resumed, so the next pipeline starts clean."""
        from src.pipeline import _setup_or_resume_run

        long_ago = datetime.utcnow() - timedelta(hours=48)
        zombie = _make_run(
            db_session, "RUNNING",
            started_at=long_ago, updated_at=long_ago,
            tag_filter=["Portfolio-A"],
        )

        cfg = self._config(tag_filter=["Portfolio-A"])
        run_id, start_offset, is_resume = _setup_or_resume_run(
            db_session, cfg, start_fresh=False
        )

        # Zombie was reaped, so a FRESH run started instead of resuming it.
        assert is_resume is False
        assert start_offset == 0
        assert run_id != zombie.id
        assert zombie.status == "TIMED_OUT"


def _make_finding(session, state, last_seen, tid=None, updated_at=None):
    f = Finding(
        id=uuid.uuid4(),
        tenable_finding_id=tid or f"f-{uuid.uuid4()}",
        title="CVE-2024-0001",
        severity="HIGH",
        state=state,
        last_seen=last_seen,
        updated_at=updated_at,
    )
    session.add(f)
    session.flush()
    return f


class TestPruneStaleFindings:
    NOW = datetime(2026, 7, 16, 12, 0, 0)

    def _seed(self, session):
        return {
            "old_stale": _make_finding(session, "STALE", self.NOW - timedelta(days=200)),
            "recent_stale": _make_finding(session, "STALE", self.NOW - timedelta(days=30)),
            "old_remediated": _make_finding(session, "REMEDIATED", self.NOW - timedelta(days=400)),
            "old_open": _make_finding(session, "OPEN", self.NOW - timedelta(days=400)),
        }

    def test_dry_run_counts_but_deletes_nothing(self, db_session):
        self._seed(db_session)
        result = prune_stale_findings(db_session, retention_days=180, dry_run=True, now=self.NOW)

        assert result["total_stale"] == 2
        assert result["eligible"] == 1  # only old_stale
        assert result["deleted"] == 0
        assert db_session.query(Finding).count() == 4  # nothing removed

    def test_apply_deletes_only_aged_stale(self, db_session):
        seed = self._seed(db_session)
        result = prune_stale_findings(db_session, retention_days=180, dry_run=False, now=self.NOW)

        assert result["eligible"] == 1
        assert result["deleted"] == 1
        remaining_ids = {f.id for f in db_session.query(Finding).all()}
        assert seed["old_stale"].id not in remaining_ids
        # recent STALE, and old REMEDIATED/OPEN are all retained
        assert seed["recent_stale"].id in remaining_ids
        assert seed["old_remediated"].id in remaining_ids
        assert seed["old_open"].id in remaining_ids

    def test_remediated_never_pruned_even_when_ancient(self, db_session):
        _make_finding(db_session, "REMEDIATED", self.NOW - timedelta(days=3650))
        result = prune_stale_findings(db_session, retention_days=180, dry_run=False, now=self.NOW)

        assert result["eligible"] == 0
        assert result["deleted"] == 0
        assert db_session.query(Finding).count() == 1

    def test_falls_back_to_updated_at_when_last_seen_null(self, db_session):
        _make_finding(
            db_session, "STALE", last_seen=None,
            updated_at=self.NOW - timedelta(days=300),
        )
        result = prune_stale_findings(db_session, retention_days=180, dry_run=False, now=self.NOW)

        assert result["deleted"] == 1
