"""Celery tasks — scheduled entry points for the pipeline, NVD backfill, and
housekeeping.

Each task is a thin wrapper over the existing modules (src.pipeline,
src.ingestion.nvd_enrichment, src.maintenance.retention), so the workers and
the CLI scripts share exactly one code path. Resumability lives underneath:
the pipeline checkpoints per page, the NVD cache accumulates, and reap/prune
are idempotent — so a task can safely be retried or killed and rescheduled.
"""

from __future__ import annotations

import os

import redis

from src.celery_app import celery_app
from src.common.config import AppConfig, get_config
from src.common.db import get_engine, get_session
from src.common.logging import get_logger, setup_logging
from src.exclusions.service import refresh_exclusions
from src.ingestion.nvd_enrichment import enrich_cves_from_findings
from src.integration.jira_sync import sync_jira
from src.maintenance.retention import prune_stale_findings, reap_stale_runs
from src.pipeline import run_pipeline

logger = get_logger("tasks")

PIPELINE_LOCK_KEY = "vm:pipeline:lock"


@celery_app.task(name="src.tasks.sync_jira_task")
def sync_jira_task() -> dict:
    """Load a fresh, validated config snapshot on every delivery batch."""
    config = AppConfig()
    setup_logging(config.settings.log_level)
    if not config.jira.enabled:
        return {"skipped": True, "reason": "Jira delivery is disabled"}
    return sync_jira(get_engine(), config)


@celery_app.task(name="src.tasks.refresh_exclusions_task")
def refresh_exclusions_task() -> dict:
    """Apply edited rules and expiry even when Jira delivery is disabled."""
    config = AppConfig()
    with get_session() as session:
        return refresh_exclusions(session, config)


def _redis_client() -> redis.Redis:
    return redis.Redis.from_url(get_config().settings.redis_url)


@celery_app.task(name="src.tasks.run_pipeline_task")
def run_pipeline_task(start_fresh: bool = False) -> dict:
    """Run the ingestion/scoring pipeline under a non-blocking Redis lock.

    If another run is already active this tick skips instead of competing —
    the in-flight run is already checkpointing progress, and the next tick
    picks up again.
    """
    config = AppConfig()
    setup_logging(config.settings.log_level)

    lock = _redis_client().lock(
        PIPELINE_LOCK_KEY,
        timeout=config.maintenance.run_timeout_hours * 3600,
        blocking=False,
    )
    if not lock.acquire():
        logger.warning("pipeline_skipped_overlap", lock=PIPELINE_LOCK_KEY)
        return {"skipped": True, "reason": "another pipeline run is active"}

    try:
        run = run_pipeline(config, start_fresh=start_fresh, trigger="scheduled")
        return {
            "skipped": False,
            "run_id": str(run.id),
            "status": run.status,
            "findings_fetched": run.findings_fetched,
            "findings_new": run.findings_new,
            "findings_updated": run.findings_updated,
            "findings_remediated": run.findings_remediated,
            "findings_recurred": run.findings_recurred,
            "findings_stale": run.findings_stale,
        }
    finally:
        lock.release()


@celery_app.task(name="src.tasks.enrich_nvd_task")
def enrich_nvd_task(max_cves: int | None = None) -> dict:
    """Fetch a bounded chunk of uncached CVE descriptions from the NVD.

    The cache accumulates, so every tick just continues the backfill until the
    cache is fresh. Bounded so the task stays short; the interval schedule in
    celery_app drives the overall throughput.
    """
    config = get_config()
    setup_logging(config.settings.log_level)

    limit = max_cves or config.nvd.max_cves_per_run or 500
    with get_session() as session:
        cached = enrich_cves_from_findings(
            session,
            ttl_days=config.nvd.ttl_days,
            api_key=os.environ.get("NVD_API_KEY"),
            max_fetch=limit,
            exclude_container=False,
            container_patterns=config.tenable.container_registry_patterns,
        )
    return {"cached": cached, "max_fetch": limit}


@celery_app.task(name="src.tasks.maintenance_task")
def maintenance_task() -> dict:
    """Reap abandoned RUNNING runs and prune STALE findings past retention.

    Both operations are set-based and idempotent; thresholds come from
    config/maintenance.yaml. REMEDIATED findings are never pruned.
    """
    config = get_config()
    setup_logging(config.settings.log_level)

    with get_session() as session:
        reaped = reap_stale_runs(session, config.maintenance.run_timeout_hours, dry_run=False)
        pruned = prune_stale_findings(
            session, config.maintenance.stale_retention_days, dry_run=False
        )
    return {"reaped_runs": len(reaped), "reaped": reaped, "pruned": pruned}
