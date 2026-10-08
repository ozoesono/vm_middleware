"""Read-only delivery previews. No credentials or Jira API access required."""

from collections import Counter

from sqlalchemy import func

from src.common.models import CveDetails, Finding, JiraCreationBudget, PipelineRun
from src.integration.payloads import issue_fields
from src.integration.routing import resolve_route, validate_rollout


def preview_routes(session, config, *, team_id=None, limit=100):
    validate_rollout(config)
    if team_id and team_id not in config.jira.teams:
        raise ValueError(f"unknown team: {team_id}")
    run = (
        session.query(PipelineRun)
        .filter(PipelineRun.status.in_(["SUCCESS", "COMPLETED_WITH_ERRORS"]))
        .order_by(PipelineRun.completed_at.desc(), PipelineRun.started_at.desc())
        .first()
    )
    reserved = Counter()
    if run:
        reserved.update(
            {
                b.team_id: b.reserved
                for b in session.query(JiraCreationBudget).filter_by(run_id=run.id)
            }
        )
    query = session.query(Finding)
    if team_id:
        team = config.jira.teams[team_id]
        selectors = [
            func.lower(func.trim(getattr(Finding, key))).in_([v.strip().lower() for v in values])
            for key, values in team.match.items()
        ]
        from sqlalchemy import and_, or_

        query = query.filter(or_(Finding.jira_team_id == team_id, and_(*selectors)))
    rows = []
    for finding in query.order_by(Finding.risk_score.desc(), Finding.id).yield_per(100):
        route = resolve_route(finding, config)
        if team_id and route.team_id != team_id:
            continue
        action = "NONE"
        reason = route.reason
        if route.status == "BOUND":
            action = "RECOVER" if finding.jira_create_started_at else "SYNC"
        elif route.status == "ELIGIBLE":
            if not run:
                reason = "waiting for a completed ingestion run"
            elif (
                reserved[route.team_id] >= route.team.ticketing.max_creates_per_run
                or sum(reserved.values()) >= config.rollout.active_phase.max_tickets_per_run
            ):
                reason = "creation allowance exhausted for ingestion run"
            else:
                action = "CREATE"
                reserved[route.team_id] += 1
        fields = None
        if action != "NONE":
            fields = issue_fields(
                finding,
                route.destination,
                route.instance,
                session.get(CveDetails, finding.cve_id) if finding.cve_id else None,
            )
        rows.append(
            {
                "finding_id": str(finding.id),
                "tenable_finding_id": finding.tenable_finding_id,
                "team_id": route.team_id,
                "route_status": route.status,
                "instance": route.destination.instance if route.destination else None,
                "project": route.destination.project if route.destination else None,
                "action": action,
                "reason": reason,
                "delivery_enabled": config.jira.enabled,
                "ticket_key": finding.jira_ticket_key,
                "sync_status": finding.jira_sync_status,
                "next_sync_at": finding.jira_next_sync_at.isoformat()
                if finding.jira_next_sync_at
                else None,
                "fields": fields,
            }
        )
        if len(rows) >= limit:
            break
    return rows
