"""Tests for the resilience guarantees:
  - Per-record fault tolerance (one bad record doesn't kill a batch).
  - Per-page fault tolerance (one bad page doesn't kill the pipeline).
  - Auto-resume of incomplete runs.
"""

import uuid
from unittest.mock import patch

import pytest

from src.common.config import AppConfig, AppSettings
from src.common.models import FindingStaging, PipelineRun
from src.ingestion.tenable_ingestion import ingest_findings


# ---------------------------------------------------------------------------
# Per-record fault tolerance
# ---------------------------------------------------------------------------


def _good_finding(fid: str) -> dict:
    return {
        "id": fid,
        "name": "CVE-2024-0001",
        "severity": "HIGH",
        "state": "ACTIVE",
        "extra_properties": {"asset_name": f"asset-{fid}"},
    }


class TestIngestResilience:
    def test_returns_saved_skipped_tuple(self, db_session, run_id):
        findings = [_good_finding("f1"), _good_finding("f2")]
        saved, skipped = ingest_findings(
            findings, run_id, db_session,
            tag_filter=None,
            clear_staging=False,
        )
        assert saved == 2
        assert skipped == 0

    def test_bad_record_normalisation_is_skipped(self, db_session, run_id):
        """A finding that raises in normalisation is skipped, not crashed on."""
        findings = [
            _good_finding("f1"),
            {"id": None},  # will fail normalisation (no name/severity)
            _good_finding("f3"),
        ]

        # Patch normalise_finding to raise on the bad row only
        from src.ingestion import tenable_ingestion

        original = tenable_ingestion.normalise_finding

        def faulty_normalise(raw, rid):
            if raw.get("id") is None:
                raise ValueError("simulated normalisation error")
            return original(raw, rid)

        with patch.object(tenable_ingestion, "normalise_finding", side_effect=faulty_normalise):
            saved, skipped = ingest_findings(
                findings, run_id, db_session,
                tag_filter=None,
                clear_staging=False,
            )

        assert saved == 2
        assert skipped == 1

    def test_bulk_insert_failure_falls_back_to_per_row(self, db_session, run_id):
        """If bulk_save_objects raises, the resilient path falls back to
        per-row inserts so a single bad row doesn't kill the batch."""
        findings = [_good_finding(f"f{i}") for i in range(5)]

        from src.ingestion import tenable_ingestion

        # Force bulk_save to fail once, then succeed on subsequent calls
        call_count = {"n": 0}
        original_bulk = db_session.bulk_save_objects

        def faulty_bulk(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise RuntimeError("simulated bulk insert failure")
            return original_bulk(*args, **kwargs)

        with patch.object(db_session, "bulk_save_objects", side_effect=faulty_bulk):
            saved, skipped = ingest_findings(
                findings, run_id, db_session,
                tag_filter=None,
                clear_staging=False,
            )

        # Falling back to per-row should save all 5
        assert saved == 5
        assert skipped == 0


# ---------------------------------------------------------------------------
# Auto-resume logic
# ---------------------------------------------------------------------------


def _make_run(session, status, tag_filter=None, **kwargs):
    defaults = dict(
        id=uuid.uuid4(),
        status=status,
        tag_filter=tag_filter,
        last_offset=kwargs.get("last_offset", 100),
        last_batch_idx=kwargs.get("last_batch_idx", 2),
        pages_completed=kwargs.get("pages_completed", 2),
        findings_fetched=kwargs.get("findings_fetched", 200),
    )
    defaults.update(kwargs)
    run = PipelineRun(**defaults)
    session.add(run)
    session.flush()
    return run


class TestAutoResume:
    def _config(self, tag_filter=None):
        settings = AppSettings(database_url="sqlite:///:memory:", config_dir="config")
        cfg = AppConfig(settings=settings)
        cfg.tenable.tag_filter = tag_filter
        return cfg

    def test_no_incomplete_run_creates_fresh(self, db_session):
        from src.pipeline import _setup_or_resume_run
        run_id, start_offset, is_resume = _setup_or_resume_run(
            db_session, self._config(), start_fresh=False
        )
        assert is_resume is False
        assert start_offset == 0

    def test_auto_resumes_matching_incomplete_run(self, db_session):
        from src.pipeline import _setup_or_resume_run
        _make_run(db_session, "PARTIAL_FAILURE", tag_filter=["Portfolio-A"], last_offset=500)

        cfg = self._config(tag_filter=["Portfolio-A"])
        run_id, start_offset, is_resume = _setup_or_resume_run(
            db_session, cfg, start_fresh=False
        )

        assert is_resume is True
        assert start_offset == 500

    def test_tag_mismatch_starts_fresh(self, db_session):
        from src.pipeline import _setup_or_resume_run
        _make_run(db_session, "PARTIAL_FAILURE", tag_filter=["Portfolio-A"], last_offset=500)

        cfg = self._config(tag_filter=["Portfolio-B"])
        run_id, start_offset, is_resume = _setup_or_resume_run(
            db_session, cfg, start_fresh=False
        )

        assert is_resume is False
        assert start_offset == 0

    def test_start_fresh_ignores_incomplete_run(self, db_session):
        from src.pipeline import _setup_or_resume_run
        _make_run(db_session, "PARTIAL_FAILURE", tag_filter=["Portfolio-A"], last_offset=500)

        cfg = self._config(tag_filter=["Portfolio-A"])
        run_id, start_offset, is_resume = _setup_or_resume_run(
            db_session, cfg, start_fresh=True
        )

        assert is_resume is False
        assert start_offset == 0

    def test_completed_run_does_not_resume(self, db_session):
        from src.pipeline import _setup_or_resume_run
        _make_run(db_session, "SUCCESS", tag_filter=["Portfolio-A"], last_offset=500)

        cfg = self._config(tag_filter=["Portfolio-A"])
        run_id, start_offset, is_resume = _setup_or_resume_run(
            db_session, cfg, start_fresh=False
        )

        assert is_resume is False
        assert start_offset == 0


# ---------------------------------------------------------------------------
# Error append helper
# ---------------------------------------------------------------------------


class TestAppendError:
    def test_appends_with_timestamp(self):
        from src.pipeline import _append_error
        run = PipelineRun(id=uuid.uuid4(), tag_filter=None)
        _append_error(run, "first error")
        _append_error(run, "second error")
        assert len(run.errors) == 2
        assert run.errors[0]["msg"] == "first error"
        assert run.errors[1]["msg"] == "second error"
        assert "at" in run.errors[0]

    def test_caps_at_max(self):
        from src.pipeline import _append_error
        run = PipelineRun(id=uuid.uuid4(), tag_filter=None)
        for i in range(60):
            _append_error(run, f"err{i}", max_kept=10)
        assert len(run.errors) == 10
        # Last 10 should be kept
        assert run.errors[-1]["msg"] == "err59"
        assert run.errors[0]["msg"] == "err50"
