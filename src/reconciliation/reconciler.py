"""Reconciliation engine — state management between Tenable findings and stored data.

This is the core logic that:
1. Compares staged findings (current run) against stored findings (previous runs)
2. Determines the correct state transition for each finding
3. Applies scoring and SLA calculations
4. Populates the Jira action queue
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from src.common.config import AppConfig
from src.common.logging import get_logger
from src.common.models import Finding, FindingStaging, JiraActionQueue, PipelineRun
from src.exclusions.service import apply_policy
from src.ingestion.enrichment import CRITICALITY_SCORES
from src.scoring.engine import score_record
from src.scoring.sla import determine_sla_status

logger = get_logger("reconciler")


def _utcnow() -> datetime:
    """Return current UTC time as a naive datetime (consistent with DB storage)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


@dataclass
class ReconciliationStats:
    """Statistics from a reconciliation run."""

    findings_new: int = 0
    findings_updated: int = 0
    findings_remediated: int = 0
    findings_recurred: int = 0
    findings_stale: int = 0
    jira_actions_created: int = 0
    errors: list[str] = field(default_factory=list)


def reconcile(
    session: Session,
    config: AppConfig,
    run_id: uuid.UUID,
) -> ReconciliationStats:
    """Run the full reconciliation process.

    Staged findings (the current run) are loaded into a lookup keyed by
    tenable_finding_id. Every existing OPEN/STALE finding is then matched
    against that lookup: a match is updated (or marked remediated when Tenable
    reports it fixed), a miss is checked against the stale threshold. Previously
    remediated findings that reappear are reopened as recurrences. Staged
    findings with no stored counterpart become new findings. Scoring and SLA
    are applied to everything new or updated, and the Jira action queue is
    populated as side effects are detected.
    """
    stats = ReconciliationStats()

    staged_findings = session.query(FindingStaging).filter(FindingStaging.run_id == run_id).all()
    staged_lookup: dict[str, FindingStaging] = {sf.tenable_finding_id: sf for sf in staged_findings}
    staged_processed: set[str] = set()

    # An empty or out-of-scope scan must not age out existing findings.
    scoped_asset_ids = _run_asset_scope(session, run_id)
    allow_stale = len(staged_lookup) > 0

    logger.info(
        "reconciliation_start",
        staged_count=len(staged_lookup),
        run_id=str(run_id),
        scoped=scoped_asset_ids is not None,
        stale_enabled=allow_stale,
    )
    if not allow_stale:
        logger.warning("stale_detection_skipped_empty_staged", run_id=str(run_id))

    existing_q = session.query(Finding).filter(Finding.state.in_(["OPEN", "STALE"]))
    if scoped_asset_ids is not None:
        existing_q = existing_q.filter(Finding.tenable_asset_id.in_(list(scoped_asset_ids)))
    existing_findings = existing_q.all()

    for finding in existing_findings:
        staged = staged_lookup.get(finding.tenable_finding_id)

        if staged is not None:
            staged_processed.add(finding.tenable_finding_id)
            _process_existing_with_staged(finding, staged, config, run_id, session, stats)
        elif allow_stale:
            apply_policy(session, finding, config)
            _process_missing_finding(finding, config, run_id, stats)

    remediated_findings = session.query(Finding).filter(Finding.state == "REMEDIATED").all()
    for finding in remediated_findings:
        staged = staged_lookup.get(finding.tenable_finding_id)
        if staged is not None:
            _observe_finding(finding, staged, config, run_id, session)
            staged_processed.add(finding.tenable_finding_id)
            state_upper = (staged.tenable_state or "").upper()
            if state_upper in ("ACTIVE", "RESURFACED", "NEW"):
                _process_recurrence(finding, staged, config, run_id, session, stats)

    for tenable_id, staged in staged_lookup.items():
        if tenable_id not in staged_processed:
            _process_new_finding(staged, config, run_id, session, stats)

    session.flush()
    logger.info(
        "reconciliation_complete",
        new=stats.findings_new,
        updated=stats.findings_updated,
        remediated=stats.findings_remediated,
        recurred=stats.findings_recurred,
        stale=stats.findings_stale,
        jira_actions=stats.jira_actions_created,
        run_id=str(run_id),
    )
    return stats


def _run_asset_scope(session: Session, run_id: uuid.UUID) -> set[str] | None:
    """Return the set of asset_ids this run pulled, or None for a full run.

    Tag-filtered runs persist their asset list on the PipelineRun; stale
    detection must be confined to those assets. A run with no stored asset
    scope (a full/unfiltered run, or no run record) covers all assets.
    """
    run = session.query(PipelineRun).filter(PipelineRun.id == run_id).first()
    if run is None or not run.asset_ids_for_run:
        return None
    stored = run.asset_ids_for_run
    if isinstance(stored, dict):
        ids = stored.get("ids") or []
    elif isinstance(stored, list):
        ids = stored
    else:
        return None
    return set(ids)


def _extract_enrichment(staged: FindingStaging) -> dict:
    """Extract enrichment data from staged finding's tenable_tags."""
    if staged.tenable_tags and isinstance(staged.tenable_tags, dict):
        return staged.tenable_tags.get("_enrichment", {})
    return {}


def _score_and_sla(
    finding: Finding,
    config: AppConfig,
) -> None:
    """Apply scoring and SLA calculation to a finding."""
    if finding.processing_status != "PAUSED":
        score_record(finding, config)


def _apply_enrichment_to_finding(finding: Finding, enrichment: dict) -> None:
    """Apply enrichment data to a finding."""
    if not enrichment:
        return
    finding.portfolio = enrichment.get("portfolio") or finding.portfolio
    finding.service = enrichment.get("service") or finding.service
    finding.environment = enrichment.get("environment") or finding.environment
    finding.data_sensitivity = enrichment.get("data_sensitivity") or finding.data_sensitivity
    finding.asset_criticality = enrichment.get("asset_criticality") or finding.asset_criticality
    finding.asset_criticality_score = enrichment.get("asset_criticality_score") or finding.asset_criticality_score
    finding.service_owner = enrichment.get("service_owner") or finding.service_owner
    finding.service_owner_team = enrichment.get("service_owner_team") or finding.service_owner_team


def _queue_jira_action(
    session: Session,
    run_id: uuid.UUID,
    finding_id: uuid.UUID,
    action: str,
    payload: dict | None = None,
) -> bool:
    """Add an action to the Jira action queue."""
    finding = session.get(Finding, finding_id)
    if finding and finding.processing_status == "PAUSED":
        return False
    if finding and finding.jira_sync_status not in ("RETRY", "UNCERTAIN", "FAILED"):
        finding.jira_next_sync_at = None
    session.add(JiraActionQueue(
        id=uuid.uuid4(),
        run_id=run_id,
        finding_id=finding_id,
        action=action,
        payload=payload or {},
    ))
    return True


def _observe_finding(finding, staged, config, run_id, session):
    """Keep source observations current even when middleware processing is paused."""
    for field_name in (
        "title", "cve_id", "cve_ids", "severity", "source", "plugin_id", "solution",
        "asset_name", "asset_type", "tenable_asset_id", "asset_ip", "asset_hostname",
        "vpr_score", "acr", "aes",
        "epss_score", "exploit_maturity", "cvssv3_score", "tenable_state",
    ):
        value = getattr(staged, field_name)
        if value is not None and value != "":
            setattr(finding, field_name, value)
    finding.last_seen = staged.last_seen or finding.last_seen
    finding.last_observed_at = _utcnow()
    finding.last_run_id = run_id
    _apply_enrichment_to_finding(finding, _extract_enrichment(staged))
    apply_policy(session, finding, config)


def _process_existing_with_staged(
    finding: Finding,
    staged: FindingStaging,
    config: AppConfig,
    run_id: uuid.UUID,
    session: Session,
    stats: ReconciliationStats,
) -> None:
    """Process a finding that exists in both DB and current staging."""
    old_sla_status = finding.sla_status
    old_risk_rating = finding.risk_rating
    _observe_finding(finding, staged, config, run_id, session)
    tenable_state = (staged.tenable_state or "ACTIVE").upper()

    if tenable_state == "FIXED":
        finding.state = "REMEDIATED"
        finding.tenable_state = tenable_state
        finding.remediated_at = _utcnow()
        finding.last_seen = staged.last_seen or finding.last_seen
        finding.last_run_id = run_id

        if finding.first_seen:
            delta = _utcnow() - finding.first_seen
            finding.time_to_fix_days = delta.days

        queued = _queue_jira_action(session, run_id, finding.id, "CLOSE", {
            "reason": "Vulnerability confirmed remediated by Tenable",
            "time_to_fix_days": finding.time_to_fix_days,
        })
        stats.findings_remediated += 1
        stats.jira_actions_created += int(queued)

    else:
        finding.state = "OPEN"
        finding.tenable_state = tenable_state
        finding.last_seen = staged.last_seen or finding.last_seen
        finding.vpr_score = staged.vpr_score or finding.vpr_score
        finding.acr = staged.acr or finding.acr
        finding.aes = staged.aes or finding.aes
        finding.epss_score = staged.epss_score or finding.epss_score
        finding.exploit_maturity = staged.exploit_maturity or finding.exploit_maturity
        finding.cvssv3_score = staged.cvssv3_score or finding.cvssv3_score
        finding.solution = staged.solution or finding.solution
        finding.last_run_id = run_id

        enrichment = _extract_enrichment(staged)
        _apply_enrichment_to_finding(finding, enrichment)

        _score_and_sla(finding, config)
        if finding.processing_status == "PAUSED":
            stats.findings_updated += 1
            return

        new_sla_status = determine_sla_status(finding.sla_due_date, config.sla)
        finding.sla_status = new_sla_status

        if finding.jira_ticket_key and (
            old_sla_status != new_sla_status or old_risk_rating != finding.risk_rating
        ):
            queued = _queue_jira_action(session, run_id, finding.id, "UPDATE", {
                "sla_status_change": f"{old_sla_status} -> {new_sla_status}",
                "risk_score": finding.risk_score,
            })
            stats.jira_actions_created += int(queued)

        stats.findings_updated += 1


def _process_missing_finding(
    finding: Finding,
    config: AppConfig,
    run_id: uuid.UUID,
    stats: ReconciliationStats,
) -> None:
    """Process a finding that's in DB but NOT in current staging (missing from Tenable)."""
    stale_threshold = timedelta(days=config.tenable.stale_threshold_days)
    now = _utcnow()

    if finding.last_seen and (now - finding.last_seen) > stale_threshold:
        if finding.state != "STALE":
            finding.state = "STALE"
            finding.last_run_id = run_id
            stats.findings_stale += 1
            logger.info(
                "finding_marked_stale",
                tenable_finding_id=finding.tenable_finding_id,
                last_seen=str(finding.last_seen),
            )


def _process_recurrence(
    finding: Finding,
    staged: FindingStaging,
    config: AppConfig,
    run_id: uuid.UUID,
    session: Session,
    stats: ReconciliationStats,
) -> None:
    """Process a previously remediated finding that has resurfaced."""
    finding.state = "OPEN"
    finding.tenable_state = staged.tenable_state
    finding.is_recurrence = True
    finding.recurrence_count += 1
    finding.first_seen = staged.first_seen or _utcnow()
    finding.last_seen = staged.last_seen or _utcnow()
    finding.remediated_at = None
    finding.time_to_fix_days = None
    finding.last_run_id = run_id

    finding.vpr_score = staged.vpr_score or finding.vpr_score
    finding.acr = staged.acr or finding.acr
    finding.aes = staged.aes or finding.aes
    finding.severity = staged.severity or finding.severity

    enrichment = _extract_enrichment(staged)
    _apply_enrichment_to_finding(finding, enrichment)

    _score_and_sla(finding, config)

    queued = _queue_jira_action(session, run_id, finding.id, "REOPEN", {
        "reason": "Vulnerability has resurfaced after previous remediation",
        "recurrence_count": finding.recurrence_count,
        "previous_remediation_date": str(finding.jira_closed_at) if finding.jira_closed_at else None,
    })

    stats.findings_recurred += 1
    stats.jira_actions_created += int(queued)
    logger.info(
        "finding_recurrence",
        tenable_finding_id=finding.tenable_finding_id,
        recurrence_count=finding.recurrence_count,
    )


def _process_new_finding(
    staged: FindingStaging,
    config: AppConfig,
    run_id: uuid.UUID,
    session: Session,
    stats: ReconciliationStats,
) -> None:
    """Process a finding that exists in staging but not in the DB (brand new)."""
    enrichment = _extract_enrichment(staged)
    criticality = enrichment.get("asset_criticality")
    criticality_score = enrichment.get("asset_criticality_score")

    if criticality_score is None and criticality:
        criticality_score = CRITICALITY_SCORES.get(criticality.upper(), 0.25)
    elif criticality_score is None:
        criticality_score = 0.25

    finding = Finding(
        id=uuid.uuid4(),
        tenable_finding_id=staged.tenable_finding_id,
        tenable_asset_id=staged.tenable_asset_id,
        title=staged.title,
        cve_id=staged.cve_id,
        cve_ids=staged.cve_ids,
        severity=staged.severity,
        vpr_score=staged.vpr_score,
        acr=staged.acr,
        aes=staged.aes,
        epss_score=staged.epss_score,
        exploit_maturity=staged.exploit_maturity,
        cvssv3_score=staged.cvssv3_score,
        source=staged.source,
        plugin_id=staged.plugin_id,
        solution=staged.solution,
        asset_name=staged.asset_name,
        asset_type=staged.asset_type,
        asset_ip=staged.asset_ip,
        asset_hostname=staged.asset_hostname,
        state="REMEDIATED" if (staged.tenable_state or "").upper() == "FIXED" else "OPEN",
        tenable_state=staged.tenable_state or "Active",
        first_seen=staged.first_seen or _utcnow(),
        last_seen=staged.last_seen or _utcnow(),
        last_run_id=run_id,
        portfolio=enrichment.get("portfolio"),
        service=enrichment.get("service"),
        environment=enrichment.get("environment"),
        data_sensitivity=enrichment.get("data_sensitivity"),
        asset_criticality=criticality,
        asset_criticality_score=criticality_score,
        service_owner=enrichment.get("service_owner"),
        service_owner_team=enrichment.get("service_owner_team"),
    )

    session.add(finding)
    _observe_finding(finding, staged, config, run_id, session)

    _score_and_sla(finding, config)

    if finding.state == "REMEDIATED":
        finding.remediated_at = staged.last_seen or _utcnow()
        if finding.first_seen:
            finding.time_to_fix_days = max(0, (finding.remediated_at - finding.first_seen).days)
        stats.findings_new += 1
        return

    if finding.processing_status == "PAUSED":
        stats.findings_new += 1
        return

    queued = _queue_jira_action(session, run_id, finding.id, "CREATE", {
        "title": finding.title,
        "cve_id": finding.cve_id,
        "risk_rating": finding.risk_rating,
        "risk_score": finding.risk_score,
        "asset_name": finding.asset_name,
        "service_owner": finding.service_owner,
        "sla_due_date": str(finding.sla_due_date) if finding.sla_due_date else None,
    })

    stats.findings_new += 1
    stats.jira_actions_created += int(queued)
