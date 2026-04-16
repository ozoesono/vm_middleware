"""Pipeline runner — executes all steps in sequence for local development."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy.orm import Session

from src.common.config import AppConfig
from src.common.db import get_session
from src.common.logging import get_logger, setup_logging
from src.common.models import FindingStaging, JiraActionQueue, PipelineRun
from src.ingestion.enrichment import apply_enrichment, load_enrichment_from_csv
from src.ingestion.tenable_client import MockTenableClient, TenableClient
from src.ingestion.tenable_ingestion import ingest_findings
from src.reconciliation.reconciler import reconcile

logger = get_logger("pipeline")


def run_pipeline(
    config: AppConfig,
    mock_fixture_path: str | None = None,
    enrichment_csv_path: str | None = None,
) -> PipelineRun:
    """Execute the full pipeline: enrich → ingest → score/reconcile.

    Args:
        config: Application configuration
        mock_fixture_path: If provided, use MockTenableClient with this fixture
        enrichment_csv_path: If provided, load enrichment data from this CSV
    """
    run_id = uuid.uuid4()
    setup_logging(config.settings.log_level)

    logger.info("pipeline_start", run_id=str(run_id))

    with get_session() as session:
        # Create pipeline run record
        pipeline_run = PipelineRun(
            id=run_id,
            started_at=datetime.utcnow(),
            status="RUNNING",
            trigger="manual",
        )
        session.add(pipeline_run)
        session.flush()

        try:
            # Step 1: Enrichment sync
            logger.info("step_1_enrichment_sync")
            if enrichment_csv_path:
                enrichment_count = load_enrichment_from_csv(enrichment_csv_path, session)
                logger.info("enrichment_loaded", count=enrichment_count)

            # Step 2: Tenable ingestion
            logger.info("step_2_tenable_ingestion")
            if mock_fixture_path:
                client = MockTenableClient(fixture_path=mock_fixture_path)
            else:
                client = TenableClient(
                    config=config.tenable,
                    access_key=config.settings.tenable_access_key,
                    secret_key=config.settings.tenable_secret_key,
                )

            try:
                raw_findings = client.fetch_findings()
                pipeline_run.findings_fetched = len(raw_findings)

                staged_count = ingest_findings(raw_findings, run_id, session)
                logger.info("ingestion_complete", staged=staged_count)
            finally:
                client.close()

            # Step 2b: Apply enrichment to staged findings
            logger.info("step_2b_apply_enrichment")
            apply_enrichment(session, run_id)

            # Step 3: Scoring & Reconciliation
            logger.info("step_3_scoring_reconciliation")
            recon_stats = reconcile(session, config, run_id)

            # Update pipeline run stats
            pipeline_run.findings_new = recon_stats.findings_new
            pipeline_run.findings_updated = recon_stats.findings_updated
            pipeline_run.findings_remediated = recon_stats.findings_remediated
            pipeline_run.findings_recurred = recon_stats.findings_recurred
            pipeline_run.findings_stale = recon_stats.findings_stale

            # Step 4: Log Jira action queue (no actual Jira calls in Phase 0)
            jira_actions = (
                session.query(JiraActionQueue)
                .filter(JiraActionQueue.run_id == run_id)
                .all()
            )
            logger.info("step_4_jira_queue", actions=len(jira_actions))
            for action in jira_actions:
                logger.info(
                    "jira_action_queued",
                    action=action.action,
                    finding_id=str(action.finding_id),
                    payload=action.payload,
                )

            # Clean up staging table for this run
            session.query(FindingStaging).filter(FindingStaging.run_id == run_id).delete()

            # Mark run as complete
            pipeline_run.status = "SUCCESS"
            pipeline_run.completed_at = datetime.utcnow()
            pipeline_run.errors = recon_stats.errors if recon_stats.errors else None

        except Exception as e:
            logger.error("pipeline_error", error=str(e), run_id=str(run_id))
            pipeline_run.status = "FAILED"
            pipeline_run.completed_at = datetime.utcnow()
            pipeline_run.errors = [str(e)]
            raise

        finally:
            session.flush()

    # Print summary
    _print_summary(pipeline_run)
    return pipeline_run


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
    print(f"  Findings fetched:  {run.findings_fetched}")
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
