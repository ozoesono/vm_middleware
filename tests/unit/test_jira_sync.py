import csv
import io
import json
from datetime import timedelta

import httpx
import pytest
from sqlalchemy.orm import Session

from src.common.models import Finding, JiraActionQueue, JiraCreationBudget, JiraSyncLog, PipelineRun
from src.integration.jira_sync import retry_finding, sync_jira
from src.integration.preview import preview_routes
from src.maintenance.retention import prune_stale_findings
from src.reporting.csv_reports import generate
from tests.jira_helpers import NOW, JiraServer, config_for_teams, seed_finding, seed_run


@pytest.fixture
def setup_delivery(db_engine, monkeypatch):
    monkeypatch.setenv("TEST_JIRA_TOKEN", "secret-not-for-logs")
    session = Session(db_engine)
    run_id = seed_run(session)
    config = config_for_teams()
    server = JiraServer()
    yield session, run_id, config, server
    session.close()


def run_sync(engine, config, server, seconds=0):
    return sync_jira(
        engine, config, client_factory=server.factory, now=NOW + timedelta(seconds=seconds)
    )


def test_two_instances_backfill_repeated_delivery_and_reports(db_engine, setup_delivery):
    session, run_id, config, server = setup_delivery
    one = seed_finding(session, run_id)
    two = seed_finding(session, run_id, "team-api")
    result = run_sync(db_engine, config, server)
    assert result["created"] == 2
    assert len(server.creates) == 2
    bodies = {r.url.host: json.loads(r.content) for r in server.creates}
    assert isinstance(bodies["one.example.test"]["fields"]["description"], dict)
    assert isinstance(bodies["two.example.test"]["fields"]["description"], str)
    assert {r.url.path for r in server.creates} == {"/rest/api/3/issue", "/rest/api/2/issue"}
    run_sync(db_engine, config, server, 61)
    assert len(server.creates) == 2
    session.expire_all()
    assert session.get(Finding, one).jira_instance_id == "one"
    assert session.get(Finding, two).jira_instance_id == "two"
    assert session.get(Finding, one).jira_issue_id == session.get(Finding, two).jira_issue_id == "1"
    assert session.get(Finding, one).jira_sync_status == "SYNCED"
    report = list(csv.DictReader(io.StringIO(generate(session, "jira-sync", {"team": "team-api"}))))
    assert len(report) == 1
    assert report[0]["jira_ticket_url"].startswith("https://two.example.test/browse/API-")
    summary = list(csv.DictReader(io.StringIO(generate(session, "team-summary"))))
    assert sum(int(r["unticketed_open"]) for r in summary) == 0
    logs = session.query(JiraSyncLog).all()
    assert logs and all(log.jira_instance_id in ("one", "two") for log in logs)
    assert "secret-not-for-logs" not in str([log.request_payload for log in logs])


def test_disabled_delivery_does_not_touch_db_or_jira(setup_delivery):
    _, _, config, server = setup_delivery
    config.jira.enabled = False
    assert sync_jira(None, config, client_factory=server.factory)["skipped"] is True
    assert not server.requests


def test_lost_create_response_recovers_without_duplicate(db_engine, setup_delivery):
    session, run_id, config, server = setup_delivery
    finding_id = seed_finding(session, run_id)
    server.lose_create_response = True
    first = run_sync(db_engine, config, server)
    assert first["uncertain"] == 1
    session.expire_all()
    finding = session.get(Finding, finding_id)
    assert finding.jira_create_started_at is not None
    assert finding.jira_binding["destination"]["project"] == "PLAT"
    second = run_sync(db_engine, config, server, 61)
    assert second["recovered"] == 1
    assert second["synced"] == 1
    assert len(server.creates) == 1
    session.expire_all()
    assert session.get(Finding, finding_id).jira_create_started_at is None


def test_empty_eventually_consistent_search_never_reposts(db_engine, setup_delivery):
    session, run_id, config, server = setup_delivery
    finding_id = seed_finding(session, run_id)
    server.lose_create_response = True
    run_sync(db_engine, config, server)
    server.hide_search = True
    for seconds in (61, 122, 183):
        assert run_sync(db_engine, config, server, seconds)["uncertain"] == 1
    assert len(server.creates) == 1
    session.expire_all()
    assert session.get(Finding, finding_id).jira_sync_status == "UNCERTAIN"


def test_persistent_team_and_global_budgets(db_engine, setup_delivery):
    session, run_id, config, server = setup_delivery
    config.rollout.active_phase.max_tickets_per_run = 2
    config.jira.teams["team-platform"].ticketing.max_creates_per_run = 1
    for _ in range(3):
        seed_finding(session, run_id)
        seed_finding(session, run_id, "team-api")
    run_sync(db_engine, config, server)
    run_sync(db_engine, config, server, 61)
    assert len(server.creates) == 2
    session.expire_all()
    budgets = session.query(JiraCreationBudget).all()
    assert sum(b.reserved for b in budgets) == 2
    assert all(b.reserved <= 1 for b in budgets if b.team_id == "team-platform")


def test_one_instance_failure_does_not_stop_the_other(db_engine, setup_delivery):
    session, run_id, config, server = setup_delivery
    one = seed_finding(session, run_id)
    two = seed_finding(session, run_id, "team-api")
    server.fail_host = "one.example.test"
    server.fail_status = 429
    result = run_sync(db_engine, config, server)
    assert result["created"] == 1
    session.expire_all()
    assert session.get(Finding, one).jira_sync_status == "RETRY"
    assert session.get(Finding, two).jira_sync_status == "SYNCED"
    request_count = len(server.requests)
    run_sync(db_engine, config, server, 30)
    assert len(server.requests) == request_count
    server.fail_host = None
    assert run_sync(db_engine, config, server, 121)["created"] == 1


def test_close_reopen_and_stale_never_closes(db_engine, setup_delivery):
    session, run_id, config, server = setup_delivery
    finding_id = seed_finding(session, run_id)
    run_sync(db_engine, config, server)
    session.expire_all()
    finding = session.get(Finding, finding_id)
    finding.state = "STALE"
    session.commit()
    run_sync(db_engine, config, server, 61)
    assert next(iter(server.issues.values()))["fields"]["status"]["name"] == "To Do"
    session.expire_all()
    finding.state = "REMEDIATED"
    finding.tenable_state = "FIXED"
    session.commit()
    config.jira.teams["team-platform"].enabled = False
    config.rollout.active_phase.max_tickets_per_run = 0
    run_sync(db_engine, config, server, 122)
    session.expire_all()
    assert finding.jira_ticket_status == "Done"
    assert finding.jira_closed_at is not None
    finding.state = "OPEN"
    finding.tenable_state = "RESURFACED"
    finding.is_recurrence = True
    session.commit()
    run_sync(db_engine, config, server, 183)
    session.expire_all()
    assert finding.jira_ticket_status == "To Do"
    assert finding.jira_closed_at is None
    assert len(server.creates) == 1


def test_old_create_for_fixed_finding_is_not_delivered(db_engine, setup_delivery):
    session, run_id, config, server = setup_delivery
    finding_id = seed_finding(session, run_id, state="REMEDIATED", tenable_state="FIXED")
    session.add(JiraActionQueue(run_id=run_id, finding_id=finding_id, action="CREATE"))
    session.commit()
    run_sync(db_engine, config, server)
    assert not server.requests
    session.expire_all()
    assert session.query(JiraActionQueue).one().status == "DEFERRED"


def test_destination_change_does_not_move_existing_tickets(db_engine, setup_delivery):
    session, run_id, config, server = setup_delivery
    seed_finding(session, run_id)
    run_sync(db_engine, config, server)
    config.jira.teams["team-platform"].jira.instance = "two"
    config.jira.teams["team-platform"].jira.project = "NEW"
    run_sync(db_engine, config, server, 61)
    assert len(server.creates) == 1
    assert all(r.url.host == "one.example.test" for r in server.requests)


def test_instance_address_change_blocks_bound_ticket(db_engine, setup_delivery):
    session, run_id, config, server = setup_delivery
    seed_finding(session, run_id)
    run_sync(db_engine, config, server)
    count = len(server.requests)
    config.jira.instances["one"].base_url = "https://different.example.test"
    assert run_sync(db_engine, config, server, 61)["blocked"] == 1
    assert len(server.requests) == count


def test_required_custom_field_failure_and_explicit_retry(db_engine, setup_delivery):
    session, run_id, config, server = setup_delivery
    finding_id = seed_finding(session, run_id)
    server.metadata_extra = [{"fieldId": "customfield_12345", "required": True}]
    assert run_sync(db_engine, config, server)["failed"] == 1
    assert not server.creates
    config.jira.teams["team-platform"].jira.custom_fields = {
        "customfield_12345": {"value": "Security"}
    }
    retry_finding(db_engine, finding_id)
    assert run_sync(db_engine, config, server, 61)["created"] == 1


def test_preview_has_no_side_effects_and_shows_unrouted(db_engine, setup_delivery):
    session, run_id, config, server = setup_delivery
    one = seed_finding(session, run_id)
    seed_finding(session, run_id, "unknown-owner")
    config.jira.enabled = False
    preview = preview_routes(session, config)
    assert {row["action"] for row in preview} == {"CREATE", "NONE"}
    assert any(row["route_status"] == "UNROUTED" for row in preview)
    assert not session.query(JiraActionQueue).count()
    assert not session.query(JiraCreationBudget).count()
    assert session.get(Finding, one).jira_binding is None
    assert not server.requests


def test_retention_preserves_linked_and_pending_work(db_engine, setup_delivery):
    session, run_id, config, server = setup_delivery
    linked = seed_finding(session, run_id)
    run_sync(db_engine, config, server)
    session.expire_all()
    session.get(Finding, linked).state = "STALE"
    session.get(Finding, linked).last_seen = NOW - timedelta(days=200)
    pending = seed_finding(session, run_id, state="STALE", last_seen=NOW - timedelta(days=200))
    session.add(JiraActionQueue(run_id=run_id, finding_id=pending, action="CREATE"))
    session.commit()
    assert prune_stale_findings(session, 180, dry_run=False, now=NOW)["deleted"] == 0


def test_existing_ticket_work_precedes_unrouted_backfill(db_engine, setup_delivery):
    session, run_id, config, server = setup_delivery
    finding_id = seed_finding(session, run_id)
    run_sync(db_engine, config, server)
    session.expire_all()
    finding = session.get(Finding, finding_id)
    finding.state, finding.tenable_state = "REMEDIATED", "FIXED"
    session.commit()
    seed_finding(session, run_id, "unknown-owner", risk_score=1.0)
    config.jira.batch_size = 1
    result = run_sync(db_engine, config, server, 61)
    assert result["close"] == 1
    session.expire_all()
    assert finding.jira_ticket_status == "Done"


def test_updates_preserve_team_labels_and_assignment(db_engine, setup_delivery):
    session, run_id, config, server = setup_delivery
    finding_id = seed_finding(session, run_id)
    run_sync(db_engine, config, server)
    issue = next(iter(server.issues.values()))
    issue["fields"]["labels"].append("team-investigating")
    issue["fields"]["assignee"] = {"accountId": "human-resolver"}
    config.jira.teams["team-platform"].jira.assignee = {"accountId": "initial-owner"}
    config.jira.teams["team-platform"].jira.labels.append("security-reviewed")
    session.expire_all()
    session.get(Finding, finding_id).sla_status = "BREACHED"
    session.commit()
    run_sync(db_engine, config, server, 61)
    assert "team-investigating" in issue["fields"]["labels"]
    assert "security-reviewed" in issue["fields"]["labels"]
    assert issue["fields"]["assignee"] == {"accountId": "human-resolver"}


def test_retryable_errors_stop_at_attempt_limit(db_engine, setup_delivery):
    session, run_id, config, server = setup_delivery
    finding_id = seed_finding(session, run_id)
    config.jira.max_attempts = 2
    server.fail_host = "one.example.test"
    assert run_sync(db_engine, config, server)["retry"] == 1
    assert run_sync(db_engine, config, server, 121)["failed"] == 1
    requests = len(server.requests)
    run_sync(db_engine, config, server, 1000)
    assert len(server.requests) == requests
    session.expire_all()
    assert session.get(Finding, finding_id).jira_attempts == 2


def test_rejected_create_releases_budget_for_retry(db_engine, setup_delivery):
    session, run_id, config, server = setup_delivery
    finding_id = seed_finding(session, run_id)
    config.rollout.active_phase.max_tickets_per_run = 1
    original = server.handle
    rejected = []

    def handler(request):
        if request.method == "POST" and request.url.path.endswith("/issue") and not rejected:
            rejected.append(True)
            return httpx.Response(429, headers={"Retry-After": "60"})
        return original(request)

    server.handle = handler
    assert run_sync(db_engine, config, server)["retry"] == 1
    session.expire_all()
    assert session.query(JiraCreationBudget).one().reserved == 0
    assert session.get(Finding, finding_id).jira_create_started_at is None
    assert run_sync(db_engine, config, server, 61)["created"] == 1
    session.expire_all()
    assert session.query(JiraCreationBudget).one().reserved == 1


def test_retry_after_measured_at_response_time(db_engine, setup_delivery, monkeypatch):
    session, run_id, config, server = setup_delivery
    finding_id = seed_finding(session, run_id)
    clock = [NOW]
    monkeypatch.setattr("src.integration.jira_sync.utcnow", lambda: clock[0])

    def slow_response(request):
        clock[0] += timedelta(seconds=30)
        return httpx.Response(429, headers={"Retry-After": "120"})

    server.handle = slow_response
    sync_jira(db_engine, config, client_factory=server.factory)
    session.expire_all()
    assert session.get(Finding, finding_id).jira_next_sync_at == NOW + timedelta(seconds=150)


def test_clear_uncertain_create_requires_explicit_flag_and_releases_reservation(
    db_engine, setup_delivery
):
    session, run_id, config, server = setup_delivery
    finding_id = seed_finding(session, run_id)
    server.fail_before_create = True
    assert run_sync(db_engine, config, server)["uncertain"] == 1
    retry_finding(db_engine, finding_id)
    session.expire_all()
    assert session.get(Finding, finding_id).jira_create_started_at is not None
    retry_finding(db_engine, finding_id, clear_uncertain=True)
    session.expire_all()
    assert session.get(Finding, finding_id).jira_create_started_at is None
    assert session.query(JiraCreationBudget).one().reserved == 0


def test_new_findings_wait_for_their_ingestion_run_to_complete(db_engine, setup_delivery):
    session, run_id, config, server = setup_delivery
    pending_run = seed_run(session)
    session.get(PipelineRun, pending_run).status = "RUNNING"
    session.commit()
    seed_finding(session, pending_run)
    assert run_sync(db_engine, config, server)["checked"] == 0
    assert not server.requests
    session.get(PipelineRun, pending_run).status = "SUCCESS"
    session.get(PipelineRun, pending_run).completed_at = NOW + timedelta(seconds=10)
    session.commit()
    assert run_sync(db_engine, config, server, 61)["created"] == 1
