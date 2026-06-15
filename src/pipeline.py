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
from src.ingestion.nvd_enrichment import enrich_unique_cves_for_run
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


def _append_error(run: PipelineRun, message: str, max_kept: int = 50) -> None:
    """Append an error message to the run's errors list, bounded to max_kept.
    Errors are persisted but capped to avoid unbounded growth on a chronic
    failure (e.g., every page failing)."""
    errs = list(run.errors or [])
    errs.append({"at": _utcnow().isoformat(), "msg": message[:300]})
    if len(errs) > max_kept:
        errs = errs[-max_kept:]
    run.errors = errs


def _stage_page(session, run_id: uuid.UUID, findings: list) -> tuple[int, int, bool]:
    """Stage one page's findings resiliently.

    ingest_findings already does per-record fault tolerance internally.
    This wraps it once more so a catastrophic staging failure (e.g. the
    session itself is broken) is caught rather than crashing the loop.

    Returns (saved, skipped, page_failed).
    """
    try:
        saved, skipped = ingest_findings(
            findings, run_id, session,
            tag_filter=None,
            clear_staging=False,
        )
        return saved, skipped, False
    except Exception as e:
        logger.error("page_stage_failed_skipping", error=str(e)[:200], findings_in_page=len(findings))
        session.rollback()
        return 0, 0, True


def _setup_or_resume_run(
    session,
    config: AppConfig,
    start_fresh: bool = False,
) -> tuple[uuid.UUID, int, bool]:
    """Setup the pipeline run.

    Default behaviour is AUTO-RESUME: if there's an incomplete run
    (status RUNNING/PARTIAL_FAILURE/FAILED) whose tag_filter matches
    the current request, we resume from its checkpoint. Otherwise we
    start a fresh run.

    Pass start_fresh=True to force a new run even if an incomplete one
    exists (it will remain in its current state for forensics).

    Returns:
        (run_id, start_offset, is_resume)
    """
    if not start_fresh:
        prev = (
            session.query(PipelineRun)
            .filter(PipelineRun.status.in_(["RUNNING", "PARTIAL_FAILURE", "FAILED"]))
            .order_by(desc(PipelineRun.started_at))
            .first()
        )
        if prev is not None:
            prev_tags = sorted(prev.tag_filter or [])
            cur_tags = sorted(config.tenable.tag_filter or [])
            if prev_tags == cur_tags:
                logger.info(
                    "auto_resume_detected_incomplete_run",
                    run_id=str(prev.id),
                    last_offset=prev.last_offset,
                    last_batch_idx=prev.last_batch_idx,
                    pages_completed=prev.pages_completed,
                    findings_fetched=prev.findings_fetched,
                    findings_skipped=prev.findings_skipped,
                    pages_failed=prev.pages_failed,
                    prev_status=prev.status,
                )
                prev.status = "RUNNING"
                session.flush()
                return prev.id, prev.last_offset, True
            else:
                logger.info(
                    "incomplete_run_tag_mismatch_starting_fresh",
                    incomplete_run=str(prev.id),
                    previous_tags=prev_tags,
                    current_tags=cur_tags,
                )

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
    logger.info("pipeline_fresh_run_started", run_id=str(run_id))
    return run_id, 0, False


def run_pipeline(
    config: AppConfig,
    mock_fixture_path: str | None = None,
    enrichment_csv_path: str | None = None,
    start_fresh: bool = False,
) -> PipelineRun:
    """Execute the streaming pipeline.

    Resilience guarantees:
      - Auto-resume: if there's an incomplete run with matching tag_filter,
        it is continued from its checkpoint. Pass start_fresh=True to force
        a brand new run.
      - Per-record fault tolerance: a single malformed finding is logged and
        skipped (counter: pipeline_runs.findings_skipped).
      - Per-page fault tolerance: a page that fails entirely is logged and
        skipped (counter: pipeline_runs.pages_failed); the pipeline advances
        the checkpoint and continues to the next page.
      - Resume safety: each page commits before the next page is fetched,
        so a hard stop at any point loses at most one in-flight page.

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
        run_id, start_offset, is_resume = _setup_or_resume_run(session, config, start_fresh)
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
                ingestion_complete = True
            else:
                ingestion_complete = _run_streaming(session, config, run_id, start_offset)

            # If ingestion aborted early (persistent fetch failures), DO NOT
            # reconcile — a partial dataset would wrongly mark unfetched findings
            # as STALE. Leave the run PARTIAL_FAILURE + staging intact so the next
            # run resumes ingestion from the checkpoint.
            if not ingestion_complete:
                run = session.query(PipelineRun).filter(PipelineRun.id == run_id).first()
                run.status = "PARTIAL_FAILURE"
                run.completed_at = _utcnow()
                _append_error(run, "ingestion aborted early (persistent fetch failures); resumable")
                session.commit()
                logger.warning("pipeline_ingestion_incomplete_resumable", run_id=str(run_id))
                _print_summary(run)
                return run

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

            # Step 3c: NVD enrichment — pulls description + references for each unique CVE
            logger.info("step_3c_nvd_enrichment")
            enrich_unique_cves_for_run(session, run_id)
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

            # If some pages were skipped (fetch/stage failures) but ingestion
            # ran to completion, mark COMPLETED_WITH_ERRORS rather than SUCCESS.
            # This is NOT in the auto-resume set: the missed findings will be
            # re-pulled on the next scheduled run (pull-and-reconcile).
            run.status = "COMPLETED_WITH_ERRORS" if (run.pages_failed or 0) > 0 else "SUCCESS"
            run.completed_at = _utcnow()
            session.commit()

        except Exception as e:
            logger.error("pipeline_error", error=str(e), run_id=str(run_id))
            run = session.query(PipelineRun).filter(PipelineRun.id == run_id).first()
            if run is not None:
                run.status = "PARTIAL_FAILURE"  # so it can be resumed
                run.completed_at = _utcnow()
                _append_error(run, f"unhandled pipeline error: {str(e)[:200]}")
                session.commit()
            raise

        run = session.query(PipelineRun).filter(PipelineRun.id == run_id).first()
        _print_summary(run)
        return run


def _run_streaming(session, config, run_id: uuid.UUID, start_offset: int) -> bool:
    """Stream findings from Tenable.

    Returns True if ingestion completed, False if it aborted early due to
    persistent fetch failures (run stays resumable).

    Two paths:
      A) tag_filter is set:
         - Pre-flight: fetch asset_ids for the tag via assets/search (advanced)
         - Then call findings/search batched by asset_id (server-side filter)
      B) No tag_filter:
         - Stream all findings (legacy path)
    """
    if config.tenable.tag_filter:
        return _run_streaming_by_tagged_assets(session, config, run_id)
    else:
        return _run_streaming_all(session, config, run_id, start_offset)


def _run_streaming_by_tagged_assets(session, config, run_id: uuid.UUID) -> bool:
    """Tagged-asset path: fetch asset_ids+tags first, then batched server-side filter.

    Returns True if all batches were attempted, False if aborted early.
    """
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
        return True  # nothing to fetch is a complete (empty) ingestion

    batch_size = 500
    total_batches = (len(asset_ids) + batch_size - 1) // batch_size
    run.total_batches = total_batches
    session.commit()

    client = TenableClient(
        config=config.tenable,
        access_key=config.settings.tenable_access_key,
        secret_key=config.settings.tenable_secret_key,
    )

    page_size = config.tenable.page_size
    max_consec = config.tenable.max_consecutive_fetch_failures

    try:
        consec_failures = 0

        # Drive batch iteration MANUALLY so a failed batch FETCH is caught,
        # logged, the checkpoint advanced, and the next batch attempted.
        for batch_idx in range(start_batch, total_batches):
            batch = asset_ids[batch_idx * batch_size:(batch_idx + 1) * batch_size]

            batch_saved = 0
            batch_skipped = 0
            batch_failed = False

            # Paginate within this batch (a batch can have >page_size findings)
            offset = 0
            batch_total: int | None = None
            while True:
                try:
                    page = client.fetch_asset_page(batch, offset=offset, limit=page_size)
                    consec_failures = 0
                except Exception as e:
                    consec_failures += 1
                    batch_failed = True
                    logger.error(
                        "batch_fetch_failed_skipping",
                        error=str(e)[:200],
                        batch_idx=batch_idx,
                        offset=offset,
                        consecutive_failures=consec_failures,
                    )
                    break  # skip the rest of this batch; move to the next

                if batch_total is None:
                    batch_total = page.total

                saved, skipped, page_failed = _stage_page(session, run_id, page.findings)
                batch_saved += saved
                batch_skipped += skipped
                if page_failed:
                    batch_failed = True

                offset += page_size
                if offset >= (batch_total or 0) or len(page.findings) == 0:
                    break

            # Advance checkpoint (always, even if the batch failed)
            run = session.query(PipelineRun).filter(PipelineRun.id == run_id).first()
            run.last_batch_idx = batch_idx + 1
            run.pages_completed += 1
            run.findings_fetched = (run.findings_fetched or 0) + batch_saved + batch_skipped
            run.findings_skipped = (run.findings_skipped or 0) + batch_skipped
            if batch_failed:
                run.pages_failed = (run.pages_failed or 0) + 1
                _append_error(run, f"batch {batch_idx} (asset_ids {batch[0]}...) had failures")
            session.commit()

            logger.info(
                "batch_committed",
                batch_idx=batch_idx,
                of=total_batches,
                saved_this_batch=batch_saved,
                skipped_this_batch=batch_skipped,
                batch_failed=batch_failed,
                fetched_total=run.findings_fetched,
                skipped_total=run.findings_skipped,
                pages_failed_total=run.pages_failed,
                progress_pct=round(100 * (batch_idx + 1) / max(total_batches, 1), 1),
            )

            if consec_failures >= max_consec:
                logger.error("aborting_after_consecutive_fetch_failures", count=consec_failures)
                return False  # aborted early — caller keeps run resumable

        logger.info("batched_fetch_done", run_id=str(run_id))
        return True
    finally:
        client.close()


def _run_streaming_all(session, config, run_id: uuid.UUID, start_offset: int) -> bool:
    """No-tag path: stream all findings (legacy, slow on full datasets).

    Drives pagination MANUALLY so a failed page FETCH (HTTP error after the
    per-request retries are exhausted) is caught, logged, counted, and skipped
    — the offset advances and the pipeline continues to the next page rather
    than crashing. A run of consecutive fetch failures aborts gracefully
    (run stays resumable).
    """
    client = TenableClient(
        config=config.tenable,
        access_key=config.settings.tenable_access_key,
        secret_key=config.settings.tenable_secret_key,
    )

    page_size = config.tenable.page_size
    max_consec = config.tenable.max_consecutive_fetch_failures

    try:
        offset = start_offset
        total: int | None = None
        consec_failures = 0

        while True:
            # --- Fetch (resilient) ---
            try:
                page = client.fetch_page(offset=offset, limit=page_size)
                consec_failures = 0
            except Exception as e:
                consec_failures += 1
                logger.error(
                    "page_fetch_failed_skipping",
                    error=str(e)[:200],
                    offset=offset,
                    consecutive_failures=consec_failures,
                )
                run = session.query(PipelineRun).filter(PipelineRun.id == run_id).first()
                run.pages_failed = (run.pages_failed or 0) + 1
                run.last_offset = offset + page_size  # advance past the bad page
                _append_error(run, f"fetch failed at offset {offset}: {str(e)[:120]}")
                session.commit()

                if consec_failures >= max_consec:
                    logger.error("aborting_after_consecutive_fetch_failures", count=consec_failures)
                    return False  # aborted early — caller keeps run resumable

                offset += page_size
                if total is not None and offset >= total:
                    return True
                continue

            if total is None:
                total = page.total
                run = session.query(PipelineRun).filter(PipelineRun.id == run_id).first()
                run.total_findings_expected = total
                session.commit()

            # --- Stage (resilient) ---
            saved, skipped, page_failed = _stage_page(session, run_id, page.findings)

            run = session.query(PipelineRun).filter(PipelineRun.id == run_id).first()
            run.last_offset = offset + len(page.findings)
            run.pages_completed += 1
            run.findings_fetched = (run.findings_fetched or 0) + len(page.findings)
            run.findings_skipped = (run.findings_skipped or 0) + skipped
            if page_failed:
                run.pages_failed = (run.pages_failed or 0) + 1
                _append_error(run, f"stage failed at offset {offset}")
            session.commit()

            logger.info(
                "page_committed",
                offset=offset,
                next_offset=run.last_offset,
                saved_this_page=saved,
                skipped_this_page=skipped,
                page_failed=page_failed,
                fetched_total=run.findings_fetched,
                skipped_total=run.findings_skipped,
                pages_failed_total=run.pages_failed,
                expected_total=total,
                progress_pct=round(100 * run.findings_fetched / max(total or 1, 1), 1),
            )

            offset += page_size
            if offset >= (total or 0) or len(page.findings) == 0:
                return True
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
        saved, skipped = ingest_findings(kept, run_id, session, tag_filter=None)
        run = session.query(PipelineRun).filter(PipelineRun.id == run_id).first()
        run.findings_skipped = (run.findings_skipped or 0) + skipped
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
    print(f"  Pages failed:      {run.pages_failed}")
    print(f"  Last offset:       {run.last_offset}")
    print(f"  Last batch idx:    {run.last_batch_idx}")
    print(f"  Findings fetched:  {run.findings_fetched}")
    print(f"  Findings skipped:  {run.findings_skipped}")
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
        print(f"  Recent errors:     {len(run.errors)}")
        for err in run.errors[-5:]:
            print(f"    - {err}")
    if run.status == "PARTIAL_FAILURE":
        print(f"  --> Run again (without --start-fresh) to resume from checkpoint.")
    elif run.status == "COMPLETED_WITH_ERRORS":
        print(f"  --> Completed but {run.pages_failed} page(s) failed; missed findings")
        print(f"      will be re-pulled on the next scheduled run.")
    print("=" * 60 + "\n")
