"""Bounded Jira delivery from current findings and committed reconciliation events.

PostgreSQL advisory locking serializes CLI and Celery delivery across commits.
A durable marker before CREATE makes an interrupted POST recoverable without
blindly creating a second ticket. SQLite is supported only for isolated tests.
"""

from __future__ import annotations

import uuid
from collections import Counter
from contextlib import ExitStack, contextmanager
from datetime import datetime, timedelta, timezone

from sqlalchemy import case, func, or_, text
from sqlalchemy.orm import Session

from src.common.config import AppConfig
from src.common.models import (
    CveDetails,
    Finding,
    JiraActionQueue,
    JiraCreationBudget,
    JiraInstanceState,
    JiraSyncLog,
    PipelineRun,
)
from src.exclusions.service import apply_policy
from src.integration.jira_client import JiraClient, JiraError
from src.integration.payloads import correlation_label, fields_hash, issue_fields
from src.integration.routing import resolve_route, validate_rollout

LOCK_ID = 0x564D4A495241
ACTIVE_QUEUE_STATUSES = ("PENDING", "PROCESSING")


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


@contextmanager
def delivery_session(engine):
    """Keep a session-level lock on a dedicated connection, including across commits."""
    with engine.connect() as connection:
        postgres = connection.dialect.name == "postgresql"
        if not postgres and connection.dialect.name != "sqlite":
            raise ValueError("Jira delivery requires PostgreSQL")
        locked = (
            not postgres
            or connection.execute(
                text("SELECT pg_try_advisory_lock(:key)"), {"key": LOCK_ID}
            ).scalar()
        )
        connection.commit()
        if not locked:
            yield None
            return
        try:
            with Session(bind=connection, expire_on_commit=False) as session:
                yield session
        finally:
            if postgres:
                try:
                    connection.rollback()
                    connection.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": LOCK_ID})
                    connection.commit()
                except Exception:
                    # Never return a connection with an unknown lock state to the pool.
                    connection.invalidate()
                    raise


def _finish_events(session, ids, status, now):
    if ids:
        session.query(JiraActionQueue).filter(JiraActionQueue.id.in_(ids)).update(
            {"status": status, "processed_at": now}, synchronize_session=False
        )


def _defer(finding, status, reason, now, seconds):
    finding.jira_sync_status = status
    finding.jira_sync_error = reason
    finding.jira_last_checked_at = now
    finding.jira_next_sync_at = now + timedelta(seconds=seconds)


def _bind(finding, route):
    finding.jira_instance_id = route.destination.instance
    finding.jira_team_id = route.team_id
    finding.jira_binding = {
        "destination": route.destination.model_dump(mode="json"),
        "instance": route.instance.model_dump(mode="json"),
    }


def _link(finding, issue, route, now):
    if not issue.get("id") or not issue.get("key"):
        raise JiraError("correlated issue lacks identity")
    if not finding.jira_binding:
        _bind(finding, route)
    finding.jira_issue_id = str(issue["id"])
    finding.jira_ticket_key = issue["key"]
    browse = route.instance.browse_url or route.instance.base_url
    finding.jira_ticket_url = f"{browse}/browse/{issue['key']}"
    finding.jira_created_at = finding.jira_created_at or now
    finding.jira_create_started_at = None


def _reserve_creation(session, run_id, team_id, team_limit, global_limit):
    budget = session.get(JiraCreationBudget, (run_id, team_id))
    total = (
        session.query(func.coalesce(func.sum(JiraCreationBudget.reserved), 0))
        .filter(JiraCreationBudget.run_id == run_id)
        .scalar()
    )
    if (budget.reserved if budget else 0) >= team_limit or total >= global_limit:
        return False
    if budget is None:
        budget = JiraCreationBudget(run_id=run_id, team_id=team_id, reserved=0)
        session.add(budget)
    budget.reserved += 1
    return True


def _sync_existing(session, finding, client, route, fields, action, now):
    issue = client.get_issue(finding.jira_issue_id or finding.jira_ticket_key)
    _link(finding, issue, route, now)
    status = issue["fields"]["status"]
    category = status.get("statusCategory", {}).get("key")
    if category not in ("new", "indeterminate", "done"):
        raise JiraError("Jira issue has no recognized status category")
    finding.jira_ticket_status = status["name"]
    transitions = route.destination.transitions
    active = finding.state == "OPEN" and (finding.tenable_state or "").upper() != "FIXED"
    # Some Jira workflows prohibit editing resolved issues. Reopen first, then
    # update content. Already-resolved fixed/stale issues only have status polled.
    reopened = False
    if active and category == "done":
        action.action = "REOPEN"
        client.transition(finding.jira_issue_id, transitions.reopen, transitions.reopen_fields)
        issue = client.get_issue(finding.jira_issue_id)
        category = issue["fields"]["status"].get("statusCategory", {}).get("key")
        if category not in ("new", "indeterminate"):
            raise JiraError("reopen transition did not leave the Done category")
        reopened = True
    # Refresh fields independently from workflow state. Never move an issue's project.
    digest = fields_hash(fields)
    if digest != finding.jira_synced_hash and category != "done":
        if not reopened:
            action.action = "UPDATE"
        client.update_issue(finding.jira_issue_id, fields, issue["fields"].get("labels", []))
        finding.jira_synced_hash = digest
    if finding.state == "REMEDIATED" and (finding.tenable_state or "").upper() == "FIXED":
        if category != "done":
            action.action = "CLOSE"
            client.transition(finding.jira_issue_id, transitions.close, transitions.close_fields)
            issue = client.get_issue(finding.jira_issue_id)
            if issue["fields"]["status"].get("statusCategory", {}).get("key") != "done":
                raise JiraError("close transition did not reach a Done category")
        finding.jira_closed_at = finding.jira_closed_at or now
    elif active:
        finding.jira_closed_at = None
    # STALE findings never drive close or reopen: absence is not remediation evidence.
    finding.jira_ticket_status = issue["fields"]["status"]["name"]


def sync_jira(engine, config: AppConfig, *, client_factory=JiraClient, now=None) -> dict:
    if not config.jira.enabled:
        return {"skipped": True, "reason": "Jira delivery is disabled"}
    validate_rollout(config)
    with delivery_session(engine) as session:
        if session is None:
            return {"skipped": True, "reason": "another Jira delivery batch is active"}
        return _sync_batch(session, config, client_factory, (lambda: now) if now else utcnow)


def _sync_batch(session, config, client_factory, clock):
    now = clock()
    # One common budget epoch prevents historical queue rows from bypassing caps.
    run = (
        session.query(PipelineRun)
        .filter(PipelineRun.status.in_(["SUCCESS", "COMPLETED_WITH_ERRORS"]))
        .order_by(PipelineRun.completed_at.desc(), PipelineRun.started_at.desc())
        .first()
    )
    if run is None:
        return {"skipped": True, "reason": "no completed ingestion run"}
    run_id = run.id
    pending = (
        session.query(JiraActionQueue.id)
        .filter(
            JiraActionQueue.finding_id == Finding.id,
            JiraActionQueue.status.in_(ACTIVE_QUEUE_STATUSES),
        )
        .exists()
    )
    completed_source = (
        session.query(PipelineRun.id)
        .filter(
            PipelineRun.id == Finding.last_run_id,
            PipelineRun.status.in_(["SUCCESS", "COMPLETED_WITH_ERRORS"]),
        )
        .exists()
    )
    candidates = (
        session.query(Finding.id)
        .filter(
            or_(Finding.last_run_id.is_(None), completed_source),
            or_(
                Finding.state == "OPEN",
                Finding.jira_binding.isnot(None),
                Finding.jira_ticket_key.isnot(None),
                pending,
            ),
            or_(Finding.jira_sync_status.is_(None), Finding.jira_sync_status != "FAILED"),
            or_(Finding.jira_next_sync_at.is_(None), Finding.jira_next_sync_at <= now),
        )
        .order_by(
            case(
                (
                    or_(
                        Finding.jira_ticket_key.isnot(None),
                        Finding.jira_create_started_at.isnot(None),
                    ),
                    0,
                ),
                else_=1,
            ),
            case((pending, 0), else_=1),
            Finding.jira_last_checked_at.asc().nullsfirst(),
            Finding.risk_score.desc(),
            Finding.id,
        )
        .limit(config.jira.batch_size)
        .all()
    )
    counts = Counter()
    with ExitStack() as stack:
        clients = {}
        for (finding_id,) in candidates:
            now = clock()
            finding = session.get(Finding, finding_id)
            if finding is None:
                continue
            event_ids = [
                row.id
                for row in session.query(JiraActionQueue.id)
                .filter(
                    JiraActionQueue.finding_id == finding_id,
                    JiraActionQueue.status.in_(ACTIVE_QUEUE_STATUSES),
                )
                .all()
            ]
            apply_policy(session, finding, config, now=now)
            route = resolve_route(finding, config, now=now)
            finding.jira_last_checked_at = now
            if not finding.jira_binding and not finding.jira_ticket_key:
                finding.jira_team_id = route.team_id
                finding.jira_instance_id = route.destination.instance if route.destination else None
            elif route.team_id:
                finding.jira_team_id = route.team_id
            if route.status not in ("ELIGIBLE", "BOUND"):
                _defer(finding, route.status, route.reason, now, config.jira.refresh_seconds)
                _finish_events(session, event_ids, "DEFERRED", now)
                counts[route.status.lower()] += 1
                session.commit()
                continue
            instance_id = route.destination.instance
            cooldown = session.get(JiraInstanceState, instance_id)
            if cooldown and cooldown.retry_after and cooldown.retry_after > now:
                _defer(
                    finding,
                    "RETRY",
                    "Jira instance cooldown",
                    now,
                    (cooldown.retry_after - now).total_seconds(),
                )
                session.commit()
                counts["deferred"] += 1
                continue
            action = JiraActionQueue(
                id=uuid.uuid4(),
                run_id=run_id,
                finding_id=finding_id,
                action="SYNC",
                status="PROCESSING",
            )
            session.add(action)
            _finish_events(session, event_ids, "SUPERSEDED", now)

            def observe(method, path, status, success):
                session.add(
                    JiraSyncLog(
                        run_id=run_id,
                        finding_id=finding_id,
                        jira_ticket_key=finding.jira_ticket_key,
                        jira_instance_id=instance_id,
                        jira_team_id=route.team_id,
                        action=method,
                        request_payload={"path": path},
                        response_status=status,
                        success=success,
                    )
                )

            try:
                if instance_id not in clients:
                    clients[instance_id] = stack.enter_context(client_factory(route.instance))
                client = clients[instance_id]
                client.observer = observe
                fields = issue_fields(
                    finding,
                    route.destination,
                    route.instance,
                    session.get(CveDetails, finding.cve_id) if finding.cve_id else None,
                )
                if not finding.jira_ticket_key:
                    matches = client.find_correlated(
                        route.destination.project, correlation_label(finding)
                    )
                    if len(matches) > 1:
                        raise JiraError("multiple tickets have this finding's correlation label")
                    if matches:
                        _link(finding, matches[0], route, now)
                        session.commit()
                        counts["recovered"] += 1
                    elif finding.jira_create_started_at:
                        _defer(
                            finding,
                            "UNCERTAIN",
                            "create outcome unknown; awaiting correlation lookup",
                            now,
                            config.jira.refresh_seconds,
                        )
                        action.status = "UNCERTAIN"
                        session.commit()
                        counts["uncertain"] += 1
                        continue
                    elif route.status == "BOUND":
                        # Binding without a ticket/marker is deliberately not a new create.
                        raise JiraError("bound finding has no ticket; operator recovery required")
                    else:
                        client.validate_fields(route.destination, fields)
                        if not _reserve_creation(
                            session,
                            run_id,
                            route.team_id,
                            route.team.ticketing.max_creates_per_run,
                            config.rollout.active_phase.max_tickets_per_run,
                        ):
                            _defer(
                                finding,
                                "CAPPED",
                                "creation allowance exhausted for ingestion run",
                                now,
                                config.jira.refresh_seconds,
                            )
                            action.status = "DEFERRED"
                            session.commit()
                            counts["capped"] += 1
                            continue
                        _bind(finding, route)
                        finding.jira_binding = {
                            **finding.jira_binding,
                            "budget_run_id": str(run_id),
                            "budget_team_id": route.team_id,
                        }
                        finding.jira_create_started_at = now
                        finding.jira_sync_status = "UNCERTAIN"
                        action.action = "CREATE"
                        action.payload = {"fields": fields}
                        # Marker, destination, reservation and action survive worker death.
                        session.commit()
                        try:
                            issue = client.create_issue(fields)
                        except JiraError as exc:
                            if not exc.uncertain:
                                finding.jira_create_started_at = None
                                finding.jira_binding = None
                                budget = session.get(JiraCreationBudget, (run_id, route.team_id))
                                budget.reserved -= 1
                                # Jira rejected the POST: retry may route afresh.
                            raise
                        _link(finding, issue, route, now)
                        finding.jira_synced_hash = fields_hash(fields)
                        session.query(PipelineRun).filter(PipelineRun.id == run_id).update(
                            {
                                PipelineRun.jira_tickets_created: PipelineRun.jira_tickets_created
                                + 1,
                            }
                        )
                        session.commit()
                        counts["created"] += 1
                _sync_existing(session, finding, client, route, fields, action, clock())
                if action.action in ("UPDATE", "CLOSE", "REOPEN"):
                    counts[action.action.lower()] += 1
                    column = (
                        PipelineRun.jira_tickets_closed
                        if action.action == "CLOSE"
                        else PipelineRun.jira_tickets_updated
                    )
                    session.query(PipelineRun).filter(PipelineRun.id == run_id).update(
                        {column: column + 1}
                    )
                now = clock()
                finding.jira_sync_status = "SYNCED"
                finding.jira_sync_error = None
                finding.jira_attempts = 0
                finding.jira_last_synced_at = now
                finding.jira_next_sync_at = now + timedelta(seconds=config.jira.refresh_seconds)
                action.status = "DONE"
                action.processed_at = now
                counts["synced"] += 1
            except JiraError as exc:
                # Retry-After starts when the response arrives, not at batch start.
                now = clock()
                finding.jira_attempts = (finding.jira_attempts or 0) + 1
                uncertain = (
                    finding.jira_create_started_at is not None and not finding.jira_ticket_key
                )
                status = (
                    "UNCERTAIN"
                    if uncertain
                    else "RETRY"
                    if exc.retryable and finding.jira_attempts < config.jira.max_attempts
                    else "FAILED"
                )
                delay = max(
                    exc.retry_after,
                    min(
                        3600,
                        config.jira.retry_base_seconds * 2 ** min(finding.jira_attempts - 1, 10),
                    ),
                )
                _defer(finding, status, str(exc), now, delay)
                action.status = status
                action.error_message = str(exc)
                action.processed_at = now
                if exc.retryable or exc.retry_after or exc.status in (401, 403):
                    cooldown = cooldown or JiraInstanceState(instance_id=instance_id)
                    cooldown.retry_after = now + timedelta(seconds=max(delay, 60))
                    session.add(cooldown)
                counts[status.lower()] += 1
            session.commit()
    return {"skipped": False, "budget_run_id": str(run_id), "checked": len(candidates), **counts}


def retry_finding(engine, finding_id, *, clear_uncertain=False):
    """Explicit operator retry. Clearing an uncertain CREATE requires separate opt-in."""
    with delivery_session(engine) as session:
        if session is None:
            raise ValueError("another Jira delivery batch is active")
        finding = session.get(Finding, finding_id)
        if finding is None:
            raise ValueError("finding does not exist")
        if clear_uncertain:
            if finding.jira_ticket_key:
                raise ValueError("cannot clear a create marker on a linked ticket")
            binding = finding.jira_binding or {}
            if finding.jira_create_started_at and binding.get("budget_run_id"):
                budget = session.get(
                    JiraCreationBudget,
                    (
                        uuid.UUID(binding["budget_run_id"]),
                        binding["budget_team_id"],
                    ),
                )
                if budget:
                    budget.reserved = max(0, budget.reserved - 1)
            finding.jira_create_started_at = None
            finding.jira_binding = None
        finding.jira_attempts = 0
        finding.jira_sync_status = "RETRY"
        finding.jira_sync_error = None
        finding.jira_next_sync_at = None
        session.commit()


def adopt_issue(engine, config, finding_id, team_id, issue_key, *, client_factory=JiraClient):
    """Bind an explicitly selected existing ticket; Jira itself is read-only here."""
    team = config.jira.teams[team_id]
    instance = config.jira.instances[team.jira.instance]
    with delivery_session(engine) as session:
        if session is None:
            raise ValueError("another Jira delivery batch is active")
        finding = session.get(Finding, finding_id)
        if finding is None or finding.jira_issue_id:
            raise ValueError("finding is missing or already bound")
        if finding.jira_binding and (
            finding.jira_instance_id != team.jira.instance
            or finding.jira_binding["destination"]["project"] != team.jira.project
        ):
            raise ValueError("existing create attempt belongs to another destination")
        with client_factory(instance) as client:
            issue = client.get_issue(issue_key)
        if issue["fields"].get("project", {}).get("key") != team.jira.project:
            raise ValueError("ticket belongs to another project")
        if finding.jira_create_started_at and correlation_label(finding) not in issue["fields"].get(
            "labels", []
        ):
            raise ValueError("uncertain create recovery requires the finding correlation label")
        from src.integration.routing import Route

        route = Route("BOUND", "explicit adoption", team_id, team.jira, instance, team)
        _bind(finding, route)
        _link(finding, issue, route, utcnow())
        finding.jira_ticket_status = issue["fields"]["status"]["name"]
        finding.jira_sync_status = "PENDING"
        finding.jira_next_sync_at = None
        session.commit()
