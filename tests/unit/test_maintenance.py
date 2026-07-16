"""Tests for maintenance operations: reaping abandoned runs."""

import uuid
from datetime import datetime, timedelta

from src.common.config import AppConfig, AppSettings
from src.common.models import PipelineRun
from src.maintenance.retention import reap_stale_runs


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
