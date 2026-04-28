"""Pipeline runner — streams findings from Tenable, stages page-by-page,
checkpoints progress, and resumes from the last successful page on restart.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import desc

from src.common.config import AppConfig
from src.common.db import get_session
from src.common.logging import get_logger, setup_logging
from src.common.models import FindingStaging, JiraActionQueue, PipelineRun
from src.ingestion.enrichment import apply_enrichment, load_enrichment_from_csv
from src.ingestion.tagged_assets import fetch_tagged_asset_ids
from src.ingestion.tenable_client import MockTenableClient, TenableClient
from src.ingestion.tenable_ingestion import (
    filter_by_asset_ids,
    filter_by_tags,
    ingest_findings,
)
from src.reconciliation.reconciler import reconcile

logger = get_logger("pipeline")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _setup_or_resume_run(
    session,
    config: AppConfig,
    resume: bool,
) -> tuple[uuid.UUID, int, bool]:
    """Either create a fresh run or resume an interrupted one.

    Returns:
        (run_id, start_offset, is_resume)
    """
    if resume:
        # Look for the most recent RUNNING/PARTIAL_FAILURE/FAILED pipeline run
        prev = (
            session.query(PipelineRun)
            .filter(PipelineRun.status.in_(["RUNNING", "PARTIAL_FAILURE", "FAILED"]))
            .order_by(desc(PipelineRun.started_at))
            .first()
        )
        if prev is not None:
            # Verify the tag filter hasn't changed (otherwise resume would mix data)
            prev_tags = sorted(prev.tag_filter or [])
            cur_tags = sorted(config.tenable.tag_filter or [])
            if prev_tags != cur_tags:
                logger.warning(
                    "resume_tag_mismatch_starting_fresh",
                    previous=prev_tags,
                    current=cur_tags,
                )
            else:
                logger.info(
                    "pipeline_resuming",
                    run_id=str(prev.id),
                    last_offset=prev.last_offset,
                    pages_completed=prev.pages_completed,
                )
                prev.status = "RUNNING"
                session.flush()
                return prev.id, prev.last_offset, True

    # Fresh run
    run_id = uuid.uuid4()
    pipeline_run = PipelineRun(
        id=run_id,
        started_at=_utcnow(),
        status="RUNNING",
        trigger="manual",
        tag_filter=config.tenable.tag_filter,
    )
    session.add(pipeline_run)
    session.flush()
    return run_id, 0, False


def run_pipeline(
    config: AppConfig,
    mock_fixture_path: str | None = None,
    enrichment_csv_path: str | None = None,
    resume: bool = False,
) -> PipelineRun:
    """Execute the streaming pipeline.

    Steps:
        1. Setup or resume a pipeline run
        2. Sync enrichment data
        3. Stream findings from Tenable, page by page:
             - Filter client-side by tag
             - Stage in DB, commit
             - Update checkpoint
        4. Apply enrichment to staged findings
        5. Reconcile (state transitions, scoring, SLA)
        6. Mark run complete

    Args:
        resume: If True, attempt to resume the most recent incomplete run.
    """
    setup_logging(config.settings.log_level)

    with get_session() as session:
        run_id, start_offset, is_resume = _setup_or_resume_run(session, config, resume)
        session.commit()

        logger.info(
            "pipeline_start",
            run_id=str(run_id),
            start_offset=start_offset,
            is_resume=is_resume,
        )

        try:
            # Step 1: Enrichment sync (skip on resume — already done)
            if not is_resume and enrichment_csv_path:
                logger.info("step_1_enrichment_sync")
                count = load_enrichment_from_csv(enrichment_csv_path, session)
                logger.info("enrichment_loaded", count=count)
                session.commit()

            # Step 2: Stream Tenable findings (with checkpoint per page)
            logger.info("step_2_tenable_ingestion_streaming")

            if mock_fixture_path:
                _run_mock(session, config, run_id, mock_fixture_path)
            else:
                _run_streaming(session, config, run_id, start_offset)

            # Step 3: Apply enrichment to all staged findings
            logger.info("step_3_apply_enrichment")
            apply_enrichment(session, run_id)
            session.commit()

            # Step 4: Reconciliation
            logger.info("step_4_scoring_reconciliation")
            recon_stats = reconcile(session, config, run_id)

            # Update final stats
            run = session.query(PipelineRun).filter(PipelineRun.id == run_id).first()
            run.findings_new = recon_stats.findings_new
            run.findings_updated = recon_stats.findings_updated
            run.findings_remediated = recon_stats.findings_remediated
            run.findings_recurred = recon_stats.findings_recurred
            run.findings_stale = recon_stats.findings_stale

            # Step 5: Log Jira queue (not actually called in Phase 0)
            actions = (
                session.query(JiraActionQueue)
                .filter(JiraActionQueue.run_id == run_id)
                .count()
            )
            logger.info("step_5_jira_queue", actions=actions)

            # Clean up staging for this run
            session.query(FindingStaging).filter(FindingStaging.run_id == run_id).delete()

            run.status = "SUCCESS"
            run.completed_at = _utcnow()
            session.commit()

        except Exception as e:
            logger.error("pipeline_error", error=str(e), run_id=str(run_id))
            run = session.query(PipelineRun).filter(PipelineRun.id == run_id).first()
            if run is not None:
                run.status = "PARTIAL_FAILURE"  # so it can be resumed
                run.completed_at = _utcnow()
                run.errors = [str(e)]
                session.commit()
            raise

        run = session.query(PipelineRun).filter(PipelineRun.id == run_id).first()
        _print_summary(run)
        return run


def _run_streaming(session, config, run_id: uuid.UUID, start_offset: int) -> None:
    """Stream findings from Tenable page-by-page, with per-page commit + checkpoint.

    When a tag_filter is configured, first fetches the set of asset_ids that
    have that tag (via the assets/search endpoint with advanced query),
    then filters streamed findings by asset_id IN the set. This is more
    reliable than filtering by tag_names on the finding itself.
    """
    # If filtering by tag, build the asset_id set upfront
    tagged_asset_ids: set[str] | None = None
    if config.tenable.tag_filter:
        logger.info("step_2a_fetching_tagged_assets", tags=config.tenable.tag_filter)
        tagged_asset_ids = fetch_tagged_asset_ids(
            config=config.tenable,
            access_key=config.settings.tenable_access_key,
            secret_key=config.settings.tenable_secret_key,
            tag_names=config.tenable.tag_filter,
        )
        logger.info("step_2a_tagged_assets_done", asset_count=len(tagged_asset_ids))
        if not tagged_asset_ids:
            logger.warning("no_tagged_assets_found_pipeline_will_stage_nothing")

    client = TenableClient(
        config=config.tenable,
        access_key=config.settings.tenable_access_key,
        secret_key=config.settings.tenable_secret_key,
    )

    try:
        total_fetched_this_session = 0
        total_kept_this_session = 0
        page_num = 0

        for page in client.iter_pages(start_offset=start_offset):
            page_num += 1

            # Update total expected on the run record (first page only)
            if page_num == 1:
                run = session.query(PipelineRun).filter(PipelineRun.id == run_id).first()
                run.total_findings_expected = page.total
                session.commit()

            # Filter client-side by asset_id (preferred) or tag_names (fallback)
            if tagged_asset_ids is not None:
                kept = filter_by_asset_ids(page.findings, tagged_asset_ids)
            else:
                kept = filter_by_tags(page.findings, config.tenable.tag_filter)

            # Stage them — accumulate (don't clear), and tolerate bad rows
            try:
                ingest_findings(
                    kept, run_id, session,
                    tag_filter=None,         # already filtered above
                    clear_staging=False,     # accumulate across pages
                )
            except Exception as e:
                # If staging fails entirely, rollback so we don't poison the session
                logger.error(
                    "page_staging_failed",
                    error=str(e)[:200],
                    offset=page.offset,
                )
                session.rollback()
                # Don't advance the checkpoint — caller can retry / resume
                raise

            # Update checkpoint
            run = session.query(PipelineRun).filter(PipelineRun.id == run_id).first()
            run.last_offset = page.offset + len(page.findings)
            run.pages_completed += 1
            run.findings_fetched = (run.findings_fetched or 0) + len(page.findings)
            session.commit()

            total_fetched_this_session += len(page.findings)
            total_kept_this_session += len(kept)

            logger.info(
                "page_committed",
                page_num=page_num,
                offset=page.offset,
                next_offset=run.last_offset,
                fetched_this_page=len(page.findings),
                kept_this_page=len(kept),
                fetched_total=run.findings_fetched,
                expected_total=run.total_findings_expected,
                progress_pct=round(100 * run.findings_fetched / max(run.total_findings_expected or 1, 1), 1),
            )

        logger.info(
            "streaming_done",
            run_id=str(run_id),
            fetched_this_session=total_fetched_this_session,
            kept_this_session=total_kept_this_session,
        )
    finally:
        client.close()


def _run_mock(session, config, run_id: uuid.UUID, fixture_path: str) -> None:
    """Mock path: read fixture in one go (no streaming needed)."""
    client = MockTenableClient(fixture_path=fixture_path)
    try:
        raw_findings = client.fetch_findings()
        run = session.query(PipelineRun).filter(PipelineRun.id == run_id).first()
        run.total_findings_expected = len(raw_findings)
        run.findings_fetched = len(raw_findings)
        session.commit()

        kept = filter_by_tags(raw_findings, config.tenable.tag_filter)
        ingest_findings(kept, run_id, session, tag_filter=None)
        session.commit()
    finally:
        client.close()


def _print_summary(run: PipelineRun) -> None:
    """Print a human-readable pipeline run summary."""
    duration = ""
    if run.completed_at and run.started_at:
        delta = run.completed_at - run.started_at
        duration = f" ({delta.total_seconds():.1f}s)"

    print("\n" + "=" * 60)
    print(f"  PIPELINE RUN SUMMARY{duration}")
    print("=" * 60)
    print(f"  Run ID:            {run.id}")
    print(f"  Status:            {run.status}")
    print(f"  Pages completed:   {run.pages_completed}")
    print(f"  Last offset:       {run.last_offset}")
    print(f"  Findings fetched:  {run.findings_fetched}")
    print(f"  Expected total:    {run.total_findings_expected}")
    print(f"  New:               {run.findings_new}")
    print(f"  Updated:           {run.findings_updated}")
    print(f"  Remediated:        {run.findings_remediated}")
    print(f"  Recurred:          {run.findings_recurred}")
    print(f"  Stale:             {run.findings_stale}")
    print("-" * 60)
    print(f"  Jira actions:      create={run.jira_tickets_created} "
          f"update={run.jira_tickets_updated} close={run.jira_tickets_closed}")
    if run.errors:
        print(f"  Errors:            {len(run.errors)}")
        for err in run.errors[:5]:
            print(f"    - {err}")
    print("=" * 60 + "\n")
