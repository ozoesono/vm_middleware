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
from src.ingestion.enrichment import (
    apply_asset_tags_enrichment,
    apply_enrichment,
    load_enrichment_from_csv,
)
from src.ingestion.tagged_assets import fetch_tagged_assets_with_tags
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

            # Step 3a: Apply tag-based enrichment from the asset_tags_map (if any)
            run = session.query(PipelineRun).filter(PipelineRun.id == run_id).first()
            asset_tags_map = None
            if run.asset_ids_for_run and isinstance(run.asset_ids_for_run, dict):
                asset_tags_map = run.asset_ids_for_run.get("tags")
            if asset_tags_map:
                logger.info("step_3a_apply_tag_enrichment")
                apply_asset_tags_enrichment(
                    session=session,
                    run_id=run_id,
                    asset_tags_map=asset_tags_map,
                    criticality_scores=config.scoring.criticality_scores,
                    default_criticality_score=config.scoring.default_criticality_score,
                )
                session.commit()

            # Step 3b: CSV-based enrichment (manual overrides on top of tag enrichment)
            logger.info("step_3b_apply_csv_enrichment")
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
    """Stream findings from Tenable.

    Two paths:
      A) tag_filter is set:
         - Pre-flight: fetch asset_ids for the tag via assets/search (advanced)
         - Then call findings/search batched by asset_id (server-side filter)
         - Way faster: only the matching findings come back
      B) No tag_filter:
         - Fall back to streaming all findings (legacy path)
    """
    if config.tenable.tag_filter:
        _run_streaming_by_tagged_assets(session, config, run_id)
    else:
        _run_streaming_all(session, config, run_id, start_offset)


def _run_streaming_by_tagged_assets(session, config, run_id: uuid.UUID) -> None:
    """Tagged-asset path: fetch asset_ids+tags first, then batched server-side filter."""
    run = session.query(PipelineRun).filter(PipelineRun.id == run_id).first()

    # Either resume an existing asset list or fetch fresh
    if run.asset_ids_for_run:
        # asset_ids_for_run on resume holds {"ids": [...], "tags": {asset_id: [tag_names]}}
        stored = run.asset_ids_for_run
        if isinstance(stored, dict):
            asset_ids = stored.get("ids", [])
            asset_tags_map = stored.get("tags", {})
        else:
            # Older runs stored just a list — degrade gracefully
            asset_ids = stored
            asset_tags_map = {}
        start_batch = run.last_batch_idx
        logger.info(
            "resuming_batched_fetch",
            batch_idx=start_batch,
            total_assets=len(asset_ids),
            with_tags=bool(asset_tags_map),
        )
    else:
        logger.info("step_2a_fetching_tagged_assets", tags=config.tenable.tag_filter)
        asset_tags_map = fetch_tagged_assets_with_tags(
            config=config.tenable,
            access_key=config.settings.tenable_access_key,
            secret_key=config.settings.tenable_secret_key,
            tag_names=config.tenable.tag_filter,
        )
        asset_ids = sorted(asset_tags_map.keys())  # deterministic ordering for resume
        # Save both the ordered ID list AND the per-asset tag map for resume
        run.asset_ids_for_run = {"ids": asset_ids, "tags": asset_tags_map}
        session.commit()
        start_batch = 0
        logger.info("step_2a_tagged_assets_done", asset_count=len(asset_ids))

    if not asset_ids:
        logger.warning("no_tagged_assets_found_nothing_to_fetch")
        return

    batch_size = 500
    total_batches = (len(asset_ids) + batch_size - 1) // batch_size
    run.total_batches = total_batches
    session.commit()

    client = TenableClient(
        config=config.tenable,
        access_key=config.settings.tenable_access_key,
        secret_key=config.settings.tenable_secret_key,
    )

    try:
        current_batch = start_batch
        for batch_idx, page in client.iter_findings_by_asset_ids(
            asset_ids=asset_ids,
            batch_size=batch_size,
            start_batch=start_batch,
        ):
            # Stage findings from this page (no client-side filter — server already did it)
            try:
                ingest_findings(
                    page.findings, run_id, session,
                    tag_filter=None,
                    clear_staging=False,
                )
            except Exception as e:
                logger.error("batch_staging_failed", error=str(e)[:200], batch_idx=batch_idx)
                session.rollback()
                raise

            # Update checkpoint
            run = session.query(PipelineRun).filter(PipelineRun.id == run_id).first()
            run.last_batch_idx = batch_idx + 1  # next one to do
            run.pages_completed += 1
            run.findings_fetched = (run.findings_fetched or 0) + len(page.findings)
            session.commit()

            if batch_idx != current_batch:
                # Just moved to a new batch
                current_batch = batch_idx

            logger.info(
                "batch_page_committed",
                batch_idx=batch_idx,
                of=total_batches,
                staged_this_page=len(page.findings),
                fetched_total=run.findings_fetched,
                progress_pct=round(100 * (batch_idx + 1) / max(total_batches, 1), 1),
            )

        logger.info("batched_fetch_done", run_id=str(run_id))
    finally:
        client.close()


def _run_streaming_all(session, config, run_id: uuid.UUID, start_offset: int) -> None:
    """No-tag path: stream all findings (legacy, slow on full datasets)."""
    client = TenableClient(
        config=config.tenable,
        access_key=config.settings.tenable_access_key,
        secret_key=config.settings.tenable_secret_key,
    )

    try:
        page_num = 0
        for page in client.iter_pages(start_offset=start_offset):
            page_num += 1

            if page_num == 1:
                run = session.query(PipelineRun).filter(PipelineRun.id == run_id).first()
                run.total_findings_expected = page.total
                session.commit()

            try:
                ingest_findings(
                    page.findings, run_id, session,
                    tag_filter=None,
                    clear_staging=False,
                )
            except Exception as e:
                logger.error("page_staging_failed", error=str(e)[:200], offset=page.offset)
                session.rollback()
                raise

            run = session.query(PipelineRun).filter(PipelineRun.id == run_id).first()
            run.last_offset = page.offset + len(page.findings)
            run.pages_completed += 1
            run.findings_fetched = (run.findings_fetched or 0) + len(page.findings)
            session.commit()

            logger.info(
                "page_committed",
                page_num=page_num,
                offset=page.offset,
                next_offset=run.last_offset,
                fetched_total=run.findings_fetched,
                expected_total=run.total_findings_expected,
                progress_pct=round(100 * run.findings_fetched / max(run.total_findings_expected or 1, 1), 1),
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
