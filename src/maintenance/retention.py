"""Maintenance: reap abandoned pipeline runs, prune aged STALE findings.

Two independent housekeeping operations, both safe to run repeatedly.

reap_stale_runs
    A RUNNING run whose process died never sets a terminal status or
    completed_at. Left alone it (a) reports a duration that grows without
    bound — the "run took 5 days" artefact was one of these — and (b) sits in
    the auto-resume set, so the next pipeline silently resumes the corpse
    instead of starting clean. Reaping marks such a run TIMED_OUT and sets its
    completed_at to its last observed progress, so its duration reflects real
    work and it drops out of the resume set. Staleness is measured from the
    run's last progress (updated_at), not its start, so a genuinely
    long-running-but-live run — which keeps committing checkpoints — is never
    reaped.

prune_stale_findings
    STALE findings accumulate as assets churn (historically the container
    build-image churn drove the table to millions of rows). A finding not seen
    for stale_retention_days is aged out. REMEDIATED findings are never
    touched — they are audit evidence and kept indefinitely.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func
from sqlalchemy.orm import Session

from src.common.logging import get_logger
from src.common.models import Finding, PipelineRun

logger = get_logger("maintenance")

# A run in this status with no terminal completion is a candidate for reaping.
# PARTIAL_FAILURE / FAILED already carry completed_at and are intentionally
# resumable, so they are left alone.
REAPABLE_STATUSES = ("RUNNING",)
TIMED_OUT_STATUS = "TIMED_OUT"


def _utcnow() -> datetime:
    """Current UTC time as a naive datetime (consistent with DB storage)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _last_progress(run: PipelineRun) -> datetime | None:
    """Best estimate of when a run last did work: its heartbeat, else its start."""
    return run.updated_at or run.started_at


def reap_stale_runs(
    session: Session,
    timeout_hours: int,
    dry_run: bool = False,
    now: datetime | None = None,
) -> list[dict]:
    """Mark abandoned RUNNING runs as TIMED_OUT.

    A run is abandoned when its last progress is older than timeout_hours.
    Returns a list of {id, started_at, last_progress_at, duration_hours} for
    every run reaped (or, in dry_run mode, that would be reaped). When not a
    dry run the changes are flushed but NOT committed — the caller owns the
    transaction boundary.
    """
    now = now or _utcnow()
    cutoff = now - timedelta(hours=timeout_hours)

    candidates = (
        session.query(PipelineRun)
        .filter(PipelineRun.status.in_(REAPABLE_STATUSES))
        .all()
    )

    reaped: list[dict] = []
    for run in candidates:
        progressed_at = _last_progress(run)
        if progressed_at is None or progressed_at >= cutoff:
            continue  # never started, or still fresh — leave it

        duration_hours = None
        if run.started_at:
            duration_hours = round((progressed_at - run.started_at).total_seconds() / 3600, 2)

        record = {
            "id": str(run.id),
            "started_at": run.started_at.isoformat() if run.started_at else None,
            "last_progress_at": progressed_at.isoformat(),
            "duration_hours": duration_hours,
        }
        reaped.append(record)

        if not dry_run:
            run.status = TIMED_OUT_STATUS
            # completed_at = last progress, so duration reflects real work rather
            # than the idle gap until the reaper noticed.
            run.completed_at = progressed_at
            errs = list(run.errors or [])
            errs.append({
                "at": now.isoformat(),
                "msg": (
                    f"run timed out: no progress since {progressed_at.isoformat()} "
                    f"(> {timeout_hours}h); marked {TIMED_OUT_STATUS} by reaper"
                ),
            })
            run.errors = errs

    if reaped:
        logger.info(
            "stale_runs_reaped" if not dry_run else "stale_runs_reap_preview",
            count=len(reaped),
            timeout_hours=timeout_hours,
            run_ids=[r["id"] for r in reaped],
        )
    if not dry_run and reaped:
        session.flush()
    return reaped


def prune_stale_findings(
    session: Session,
    retention_days: int,
    dry_run: bool = True,
    now: datetime | None = None,
) -> dict:
    """Delete STALE findings not seen for longer than retention_days.

    Age is taken from last_seen, falling back to updated_at then created_at so
    a finding with no observation timestamp is never deleted on a NULL. Only
    state == 'STALE' rows are eligible; REMEDIATED findings are retained
    indefinitely as audit evidence. The delete is a single set-based statement
    (no rows loaded into memory), so it scales to a multi-million-row table.

    Returns a summary dict. When not a dry run the delete is executed within the
    caller's transaction (not committed here). Defaults to dry_run=True — a
    destructive op should not fire by accident.
    """
    now = now or _utcnow()
    cutoff = now - timedelta(days=retention_days)
    last_activity = func.coalesce(Finding.last_seen, Finding.updated_at, Finding.created_at)

    total_stale = session.query(Finding).filter(Finding.state == "STALE").count()
    eligible_q = session.query(Finding).filter(
        Finding.state == "STALE",
        last_activity < cutoff,
    )
    eligible = eligible_q.count()

    deleted = 0
    if not dry_run and eligible:
        deleted = eligible_q.delete(synchronize_session=False)

    logger.info(
        "stale_findings_pruned" if not dry_run else "stale_findings_prune_preview",
        retention_days=retention_days,
        cutoff=cutoff.isoformat(),
        total_stale=total_stale,
        eligible=eligible,
        deleted=deleted,
    )
    return {
        "retention_days": retention_days,
        "cutoff": cutoff.isoformat(),
        "total_stale": total_stale,
        "eligible": eligible,
        "deleted": deleted,
        "dry_run": dry_run,
    }
