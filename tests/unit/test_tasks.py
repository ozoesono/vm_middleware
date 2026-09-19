"""Tests for the Celery task wrappers: locking, delegation, summaries."""

from contextlib import contextmanager
from types import SimpleNamespace

import src.tasks as tasks


class _FakeLock:
    """Stand-in for redis.lock.Lock with scripted acquire behaviour."""

    def __init__(self, acquired: bool):
        self._acquired = acquired
        self.released = False

    def acquire(self):
        return self._acquired

    def release(self):
        self.released = True


class _FakeRedis:
    def __init__(self, lock: _FakeLock):
        self._lock = lock
        self.lock_args = None

    def lock(self, name, timeout, blocking):
        self.lock_args = {"name": name, "timeout": timeout, "blocking": blocking}
        return self._lock


@contextmanager
def _fake_session():
    yield None


def _fake_run(**overrides):
    defaults = {
        "id": "11111111-2222-3333-4444-555555555555",
        "status": "SUCCESS",
        "findings_fetched": 10,
        "findings_new": 4,
        "findings_updated": 2,
        "findings_remediated": 1,
        "findings_recurred": 1,
        "findings_stale": 2,
    }
    return SimpleNamespace(**(defaults | overrides))


class TestRunPipelineTask:
    def test_runs_pipeline_under_lock_as_scheduled(self, monkeypatch):
        lock = _FakeLock(acquired=True)
        fake_redis = _FakeRedis(lock)
        monkeypatch.setattr(tasks, "_redis_client", lambda: fake_redis)

        calls = {}

        def fake_run_pipeline(config, start_fresh=False, trigger=None):
            calls.update(start_fresh=start_fresh, trigger=trigger)
            return _fake_run()

        monkeypatch.setattr(tasks, "run_pipeline", fake_run_pipeline)

        result = tasks.run_pipeline_task()

        assert result["skipped"] is False
        assert result["status"] == "SUCCESS"
        assert result["findings_new"] == 4
        assert calls == {"start_fresh": False, "trigger": "scheduled"}
        assert lock.released is True
        assert fake_redis.lock_args["name"] == tasks.PIPELINE_LOCK_KEY
        assert fake_redis.lock_args["blocking"] is False

    def test_skips_when_lock_held(self, monkeypatch):
        lock = _FakeLock(acquired=False)
        monkeypatch.setattr(tasks, "_redis_client", lambda: _FakeRedis(lock))
        monkeypatch.setattr(
            tasks,
            "run_pipeline",
            lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not run")),
        )

        result = tasks.run_pipeline_task()

        assert result["skipped"] is True
        assert "reason" in result

    def test_lock_released_on_pipeline_error(self, monkeypatch):
        lock = _FakeLock(acquired=True)
        monkeypatch.setattr(tasks, "_redis_client", lambda: _FakeRedis(lock))

        def boom(config, start_fresh=False, trigger=None):
            raise RuntimeError("tenable exploded")

        monkeypatch.setattr(tasks, "run_pipeline", boom)

        try:
            tasks.run_pipeline_task()
        except RuntimeError:
            pass
        assert lock.released is True


class TestMaintenanceTask:
    def test_reaps_and_prunes_with_configured_thresholds(self, monkeypatch):
        monkeypatch.setattr(tasks, "get_session", _fake_session)

        calls = {}

        def fake_reap(session, timeout_hours, dry_run):
            calls["reap"] = {"timeout_hours": timeout_hours, "dry_run": dry_run}
            return [{"id": "run-1"}]

        def fake_prune(session, retention_days, dry_run):
            calls["prune"] = {"retention_days": retention_days, "dry_run": dry_run}
            return {"deleted": 3}

        monkeypatch.setattr(tasks, "reap_stale_runs", fake_reap)
        monkeypatch.setattr(tasks, "prune_stale_findings", fake_prune)

        result = tasks.maintenance_task()

        config = tasks.get_config()
        assert calls["reap"] == {
            "timeout_hours": config.maintenance.run_timeout_hours,
            "dry_run": False,
        }
        assert calls["prune"] == {
            "retention_days": config.maintenance.stale_retention_days,
            "dry_run": False,
        }
        assert result["reaped_runs"] == 1
        assert result["pruned"] == {"deleted": 3}


class TestEnrichNvdTask:
    def test_bounded_chunk_defaults(self, monkeypatch):
        monkeypatch.setattr(tasks, "get_session", _fake_session)

        calls = {}

        def fake_enrich(session, **kwargs):
            calls.update(kwargs)
            return 7

        monkeypatch.setattr(tasks, "enrich_cves_from_findings", fake_enrich)

        result = tasks.enrich_nvd_task()

        config = tasks.get_config()
        # nvd.max_cves_per_run defaults to 0 (no inline cap) -> task default 500
        assert calls["max_fetch"] == (config.nvd.max_cves_per_run or 500)
        assert calls["ttl_days"] == config.nvd.ttl_days
        assert result == {"cached": 7, "max_fetch": calls["max_fetch"]}

    def test_explicit_max_overrides_default(self, monkeypatch):
        monkeypatch.setattr(tasks, "get_session", _fake_session)
        monkeypatch.setattr(tasks, "enrich_cves_from_findings", lambda session, **kwargs: 0)

        result = tasks.enrich_nvd_task(max_cves=25)

        assert result["max_fetch"] == 25
