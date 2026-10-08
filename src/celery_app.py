"""Celery application — Redis broker, worker config, and the Beat schedule.

This is the orchestration entry point used by the worker and beat services in
docker-compose. The schedule comes from config/schedule.yaml:

  - run-pipeline    the daily ingestion/scoring run (schedule.cron, gated by
                    schedule.enabled)
  - nvd-enrichment  a bounded CVE backfill chunk every nvd_interval_minutes
  - maintenance     reap abandoned runs + prune aged STALE findings
                    (schedule.maintenance_cron)

Tasks live in src.tasks; all real work is done by the existing modules, so the
CLI scripts and the workers share one code path.
"""

from __future__ import annotations

from celery import Celery
from celery.schedules import crontab

from src.common.config import AppConfig, get_config


def _crontab(expr: str) -> crontab:
    """Build a Celery crontab from a standard 5-field cron expression."""
    minute, hour, day_of_month, month_of_year, day_of_week = expr.split()
    return crontab(
        minute=minute,
        hour=hour,
        day_of_month=day_of_month,
        month_of_year=month_of_year,
        day_of_week=day_of_week,
    )


def _build_beat_schedule(config: AppConfig) -> dict:
    """Beat entries from the schedule config. The pipeline entry is omitted
    entirely when scheduling is disabled; NVD and maintenance always run (they
    are cheap and resumable)."""
    entries = {}
    if config.schedule.enabled:
        entries["run-pipeline"] = {
            "task": "src.tasks.run_pipeline_task",
            "schedule": _crontab(config.schedule.cron),
        }
    entries["nvd-enrichment"] = {
        "task": "src.tasks.enrich_nvd_task",
        "schedule": float(config.schedule.nvd_interval_minutes * 60),
    }
    entries["maintenance"] = {
        "task": "src.tasks.maintenance_task",
        "schedule": _crontab(config.schedule.maintenance_cron),
    }
    # The task reads jira.enabled afresh, so team configuration can be reloaded
    # without restarting Beat. A disabled integration makes no database/API calls.
    entries["jira-sync"] = {
        "task": "src.tasks.sync_jira_task",
        "schedule": float(config.schedule.jira_interval_seconds),
    }
    entries["exclusion-refresh"] = {
        "task": "src.tasks.refresh_exclusions_task",
        "schedule": float(config.schedule.exclusion_interval_seconds),
    }
    return entries


_config = get_config()

celery_app = Celery(
    "vm_middleware",
    broker=_config.settings.redis_url,
    backend=_config.settings.redis_url,
    include=["src.tasks"],
)

celery_app.conf.update(
    timezone=_config.schedule.timezone,
    task_track_started=True,
    task_acks_late=True,
    # Recycle worker processes periodically — a full-estate ingestion run can
    # hold hundreds of MB of staged rows; this stops slow memory growth.
    worker_max_tasks_per_child=50,
    broker_connection_retry_on_startup=True,
    beat_schedule=_build_beat_schedule(_config),
)
