import csv
import io
import uuid
from datetime import timedelta, timezone

import pytest
from sqlalchemy.orm import Session

from src.common.models import ExclusionAudit, Finding, FindingStaging, JiraActionQueue, PipelineRun
from src.exclusions.policy import ExclusionPolicy
from src.exclusions.service import apply_policy, refresh_exclusions
from src.integration.jira_sync import sync_jira
from src.maintenance.retention import prune_stale_findings
from src.pipeline import _setup_or_resume_run, _stage_page
from src.reconciliation.reconciler import reconcile
from src.reporting.csv_reports import generate
from tests.jira_helpers import NOW, JiraServer, config_for_teams, seed_finding, seed_run
from tests.unit.test_exclusion_policy import rule


@pytest.fixture
def setup_pause(db_engine, monkeypatch):
    monkeypatch.setenv("TEST_JIRA_TOKEN", "test-token")
    monkeypatch.setattr("src.exclusions.service.utcnow", lambda: NOW.replace(tzinfo=timezone.utc))
    monkeypatch.setattr("src.exclusions.policy.utcnow", lambda: NOW.replace(tzinfo=timezone.utc))
    session = Session(db_engine)
    run_id = seed_run(session)
    config = config_for_teams()
    server = JiraServer()
    yield session, run_id, config, server
    session.close()


def pause(config, *, expires=None, rules=None):
    config.exclusions = ExclusionPolicy.model_validate(
        {
            "rules": rules
            or [
                rule(
                    match={"all": [{"field": "owner_team", "value": "team-platform"}]},
                    expires_at=expires,
                )
            ]
        }
    )


def observation(session, run_id, finding, state="ACTIVE", vpr=9.9):
    staged = FindingStaging(
        id=uuid.uuid4(),
        run_id=run_id,
        tenable_finding_id=finding.tenable_finding_id,
        tenable_asset_id=finding.tenable_asset_id,
        title=finding.title,
        severity="HIGH",
        tenable_state=state,
        vpr_score=vpr,
        first_seen=finding.first_seen,
        last_seen=NOW + timedelta(hours=1),
        tenable_tags={"_enrichment": {"service_owner_team": finding.service_owner_team}},
    )
    session.add(staged)
    session.flush()


def test_tenable_keeps_updating_while_ticket_pauses_then_same_ticket_closes(db_engine, setup_pause):
    session, run_id, config, server = setup_pause
    finding_id = seed_finding(session, run_id)
    sync_jira(db_engine, config, client_factory=server.factory, now=NOW)
    session.expire_all()
    finding = session.get(Finding, finding_id)
    key, first_seen, score = finding.jira_ticket_key, finding.first_seen, finding.risk_score
    pause(config)
    refresh_exclusions(session, config, now=NOW)
    session.commit()
    requests = len(server.requests)
    observation(session, run_id, finding, state="FIXED", vpr=9.9)
    stats = reconcile(session, config, run_id)
    session.commit()
    assert finding.state == "REMEDIATED"
    assert finding.tenable_state == "FIXED"
    assert finding.vpr_score == 9.9
    assert finding.last_observed_at is not None
    assert finding.processing_status == "PAUSED"
    assert finding.risk_score == score
    assert stats.jira_actions_created == 0
    sync_jira(db_engine, config, client_factory=server.factory, now=NOW + timedelta(seconds=61))
    assert len(server.requests) == requests
    assert next(iter(server.issues.values()))["fields"]["status"]["name"] == "To Do"

    config.exclusions.rules[0].enabled = False
    session.expire_all()
    assert refresh_exclusions(session, config, now=NOW + timedelta(days=90))["resumed"] == 1
    session.commit()
    sync_jira(db_engine, config, client_factory=server.factory, now=NOW + timedelta(days=90))
    session.expire_all()
    assert finding.jira_ticket_key == key
    assert finding.first_seen == first_seen
    assert finding.jira_ticket_status == "Done"
    assert len(server.creates) == 1
    assert [
        e.action for e in session.query(ExclusionAudit).order_by(ExclusionAudit.evaluated_at)
    ] == ["PAUSED", "RESUMED"]


@pytest.mark.parametrize("release", ["expiry", "remove", "disable"])
def test_config_release_rescores_latest_observation_without_resetting_dates(setup_pause, release):
    session, run_id, config, server = setup_pause
    finding_id = seed_finding(session, run_id)
    finding = session.get(Finding, finding_id)
    first_seen = finding.first_seen
    expiry = (NOW + timedelta(days=90)).replace(tzinfo=timezone.utc)
    pause(config, expires=expiry)
    apply_policy(session, finding, config, now=NOW)
    session.commit()
    observation(session, run_id, finding, vpr=1.0)
    reconcile(session, config, run_id)
    assert finding.risk_rating == "HIGH"
    assert finding.vpr_score == 1.0
    if release == "remove":
        config.exclusions.rules = []
    elif release == "disable":
        config.exclusions.rules[0].enabled = False
    config.jira.enabled = False
    result = refresh_exclusions(session, config, now=expiry)
    assert result["resumed"] == 1
    assert finding.processing_status == "ACTIVE"
    assert finding.risk_rating == "LOW"
    assert finding.first_seen == first_seen
    assert finding.jira_next_sync_at is None
    assert not server.requests


def test_one_expired_rule_does_not_release_another_matching_rule(setup_pause):
    session, run_id, config, _ = setup_pause
    finding_id = seed_finding(session, run_id, title="Test finding")
    expiry = NOW.replace(tzinfo=timezone.utc) + timedelta(days=90)
    pause(config, rules=[rule(id="temporary", expires_at=expiry), rule(id="permanent")])
    refresh_exclusions(session, config, now=NOW)
    session.commit()
    refresh_exclusions(session, config, now=expiry)
    finding = session.get(Finding, finding_id)
    assert finding.processing_status == "PAUSED"
    assert finding.exclusion_rule_ids == ["permanent"]
    assert refresh_exclusions(session, config, now=expiry)["checked"] == 0


def test_containers_new_to_middleware_are_filtered_but_tracked_ones_keep_updates(setup_pause):
    session, run_id, config, _ = setup_pause
    existing_id = seed_finding(
        session, run_id, tenable_finding_id="old", asset_type="containerImage"
    )
    raw = [
        {
            "id": fid,
            "name": "container vulnerability",
            "state": "FIXED",
            "severity": "HIGH",
            "extra_properties": {"asset_class": "containerImage", "asset_name": "private-image"},
        }
        for fid in ("new", "old")
    ]
    saved, skipped, failed = _stage_page(session, run_id, raw, config=config)
    assert (saved, skipped, failed) == (1, 0, False)
    assert session.query(FindingStaging).one().tenable_finding_id == "old"
    assert session.get(PipelineRun, run_id).findings_excluded == 1
    reconcile(session, config, run_id)
    assert session.get(Finding, existing_id).tenable_state == "FIXED"
    assert session.get(Finding, existing_id).processing_status == "PAUSED"


def test_scoped_rule_waits_for_csv_or_tag_enrichment(setup_pause):
    session, run_id, config, _ = setup_pause
    pause(config)
    raw = [{"id": "new", "name": "test", "severity": "HIGH", "state": "ACTIVE"}]
    assert _stage_page(session, run_id, raw, config=config)[0] == 1
    staged = session.query(FindingStaging).one()
    staged.tenable_tags = {"_enrichment": {"service_owner_team": "team-platform"}}
    reconcile(session, config, run_id)
    finding = session.query(Finding).one()
    assert finding.processing_status == "PAUSED"
    assert finding.risk_rating == "UNSCORED"
    assert not session.query(JiraActionQueue).count()


def test_active_reports_hide_matches_before_materialised_pause_and_allow_diagnostics(setup_pause):
    session, run_id, config, _ = setup_pause
    seed_finding(session, run_id, asset_type="containerImage", asset_name="private-image")
    seed_finding(session, run_id, "team-api", asset_type="device")
    active = list(
        csv.DictReader(
            io.StringIO(generate(session, "findings", exclusion_policy=config.exclusions))
        )
    )
    assert len(active) == 1 and active[0]["asset_type"] == "device"
    all_rows = list(
        csv.DictReader(
            io.StringIO(
                generate(
                    session,
                    "findings",
                    {"include_excluded": True},
                    exclusion_policy=config.exclusions,
                )
            )
        )
    )
    assert len(all_rows) == 2
    excluded = list(
        csv.DictReader(
            io.StringIO(generate(session, "exclusions", exclusion_policy=config.exclusions))
        )
    )
    assert len(excluded) == 1


def test_paused_stale_history_is_retained(setup_pause):
    session, run_id, config, _ = setup_pause
    finding_id = seed_finding(session, run_id, state="STALE", last_seen=NOW - timedelta(days=300))
    pause(config)
    apply_policy(session, session.get(Finding, finding_id), config, now=NOW)
    session.commit()
    assert (
        prune_stale_findings(
            session, 180, dry_run=False, now=NOW, exclusion_policy=config.exclusions
        )["deleted"]
        == 0
    )


def test_rule_change_starts_fresh_instead_of_resuming_a_filtered_checkpoint(setup_pause):
    session, _, config, _ = setup_pause
    run_id, _, _ = _setup_or_resume_run(session, config, start_fresh=True)
    run = session.get(PipelineRun, run_id)
    run.status = "PARTIAL_FAILURE"
    run.last_offset = 10000
    session.commit()
    config.exclusions.rules = []
    new_id, offset, resumed = _setup_or_resume_run(session, config)
    assert new_id != run_id and offset == 0 and not resumed
