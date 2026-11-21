"""Shared assets keep their services but receive one accountable Jira destination."""

import csv
import importlib.util
import io
import json
import uuid
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from unittest.mock import Mock

import pytest
import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy.orm import Session
from pydantic import ValidationError

from src.common.jira_config import JiraConfig
from src.common.models import EnrichmentMapping, Finding, FindingStaging, PipelineRun
from src.common.tag_parser import parse_tags
from src.exclusions.policy import ExclusionPolicy
from src.ingestion.enrichment import apply_asset_tags_enrichment, apply_enrichment
from src.ingestion.tenable_ingestion import normalise_finding
from src.integration.jira_sync import sync_jira
from src.integration.preview import preview_routes
from src.integration.routing import resolve_route
from src.pipeline import run_pipeline
from src.reconciliation.reconciler import reconcile
from src.reporting.csv_reports import generate
from tests.jira_helpers import NOW, JiraServer, config_for_teams, seed_finding, seed_run


@pytest.fixture
def config():
    config = config_for_teams()
    config.jira.teams["team-platform"].match = {"service": ["GSCIP"]}
    config.jira.teams["team-api"].match = {"service": ["Altana"]}
    config.jira = JiraConfig.model_validate(config.jira.model_dump())
    return config


def finding(**kwargs):
    return Finding(state="OPEN", risk_rating="HIGH", tenable_state="ACTIVE", **kwargs)


def test_service_tags_preserve_source_order_and_deduplicate():
    tags = ["Service-GSCIP", "Service-Altana", "Service- gscip "]
    first, _ = parse_tags(tags)
    second, _ = parse_tags(list(reversed(tags)))
    assert first["Service"] == ["GSCIP", "Altana"]
    assert second["Service"] == ["gscip", "Altana"]
    reordered, _ = parse_tags(["Service-Altana", "Service-GSCIP"])
    assert reordered["Service"] == ["Altana", "GSCIP"]


@pytest.mark.parametrize("services,expected", [(["GSCIP"], "team-platform"), (["Altana"], "team-api")])
def test_one_service_infers_team_without_owner(config, services, expected):
    route = resolve_route(finding(services=services), config)
    assert route.status == "ELIGIBLE"
    assert route.team_id == expected


def test_legacy_single_service_still_routes(config):
    assert resolve_route(finding(service=" gscip "), config).team_id == "team-platform"


@pytest.mark.parametrize("services", [["Altana", "GSCIP"], ["GSCIP", "Altana"]])
def test_priority_wins_regardless_of_service_order(config, services):
    config.jira.remediation_team_priority = ["team-platform", "team-api"]
    route = resolve_route(finding(services=services), config)
    assert route.status == "ELIGIBLE"
    assert route.team_id == "team-platform"
    assert "highest-ranked" in route.reason


def test_empty_ranking_uses_first_service_and_ignores_source_owner(config):
    first = finding(services=["Altana", "GSCIP"], service_owner_team="team-platform")
    second = finding(services=["GSCIP", "Altana"], service_owner_team="unknown-team")
    assert resolve_route(first, config).team_id == "team-api"
    assert resolve_route(second, config).team_id == "team-platform"
    assert "first service" in resolve_route(first, config).reason


def test_priority_list_with_no_matching_team_uses_first_service(config):
    data = config.jira.model_dump()
    data["teams"]["team-unrelated"] = {
        **data["teams"]["team-platform"], "team_id": "team-unrelated",
        "match": {"service": ["Unrelated"]},
    }
    data["remediation_team_priority"] = ["team-unrelated"]
    config.jira = JiraConfig.model_validate(data)
    route = resolve_route(finding(services=["Altana", "GSCIP"]), config)
    assert route.team_id == "team-api"
    assert "first service" in route.reason


def test_unmapped_first_service_is_not_silently_skipped(config):
    record = finding(services=["Unmapped", "GSCIP"])
    assert resolve_route(record, config).status == "UNROUTED"
    assert "Unmapped" in resolve_route(record, config).reason
    config.jira.remediation_team_priority = ["team-platform"]
    assert resolve_route(record, config).team_id == "team-platform"


@pytest.mark.parametrize("priorities", [["team-unknown"], ["team-platform", "TEAM-PLATFORM"], [""]])
def test_invalid_rankings_are_rejected(config, priorities):
    data = config.jira.model_dump()
    data["remediation_team_priority"] = priorities
    with pytest.raises(ValidationError, match="remediation_team_priority"):
        JiraConfig.model_validate(data)


def test_ranking_resolves_overlapping_service_team_rules(config):
    data = config.jira.model_dump()
    data["teams"]["team-api"]["match"] = {"service": ["GSCIP"]}
    with pytest.raises(ValidationError, match="overlapping"):
        JiraConfig.model_validate(data)
    data["remediation_team_priority"] = [" Team-API "]
    config.jira = JiraConfig.model_validate(data)
    assert config.jira.remediation_team_priority == ["team-api"]
    assert resolve_route(finding(services=["GSCIP"]), config).team_id == "team-api"


def test_owner_selectors_cannot_disguise_ambiguous_service_mappings(config):
    data = config.jira.model_dump()
    data["teams"]["team-api"]["match"] = {"service": ["GSCIP"], "service_owner_team": ["API"]}
    data["teams"]["team-platform"]["match"]["service_owner_team"] = ["Platform"]
    with pytest.raises(ValidationError, match="overlapping"):
        JiraConfig.model_validate(data)


def test_service_inference_preserves_environment_and_disabled_team_checks(config):
    team = config.jira.teams["team-platform"]
    team.match.update(service_owner_team=["Platform"], environment=["Prod"])
    record = finding(services=["GSCIP"], environment="Dev")
    assert resolve_route(record, config).status == "UNROUTED"
    record.environment = "Prod"
    assert resolve_route(record, config).status == "ELIGIBLE"
    team.enabled = False
    assert resolve_route(record, config).status == "INELIGIBLE"


@pytest.mark.parametrize("restriction", ["disabled", "risk", "rollout"])
def test_ranked_selection_does_not_fall_through_when_delivery_is_ineligible(config, restriction):
    config.jira.remediation_team_priority = ["team-platform"]
    record = finding(services=["Altana", "GSCIP"])
    if restriction == "disabled":
        config.jira.teams["team-platform"].enabled = False
    elif restriction == "risk":
        config.jira.teams["team-platform"].ticketing.risk_ratings = ["CRITICAL"]
    else:
        config.rollout.active_phase.team_filter = ["team-api"]
    route = resolve_route(record, config)
    assert route.team_id == "team-platform"
    assert route.status == "INELIGIBLE"


def test_first_service_preview_does_not_assign_both_teams(db_session, config):
    run_id = seed_run(db_session)
    record_id = seed_finding(db_session, run_id, services=["Altana", "GSCIP"],
                             service_owner_team=None)
    assert preview_routes(db_session, config, team_id="team-platform") == []
    rows = preview_routes(db_session, config, team_id="team-api")
    assert [row["finding_id"] for row in rows] == [str(record_id)]
    assert rows[0]["services"] == ["Altana", "GSCIP"]
    assert rows[0]["accountable_team"] == "team-api"


def test_team_preview_uses_same_ranked_selection_as_delivery(db_session, config):
    config.jira.remediation_team_priority = ["team-platform"]
    config.jira.teams["team-platform"].match["service_owner_team"] = ["Platform"]
    run_id = seed_run(db_session)
    one = seed_finding(db_session, run_id, service_owner_team=None, services=["GSCIP"])
    two = seed_finding(db_session, run_id, services=["Altana", "GSCIP"],
                       service_owner_team="Contradictory-Owner")
    seed_finding(db_session, run_id, services=["Altana"], service_owner_team=None)
    rows = preview_routes(db_session, config, team_id="team-platform")
    assert {row["finding_id"] for row in rows} == {str(one), str(two)}
    for row in rows:
        assert row["accountable_team"] == "team-platform"
        assert row["action"] == "CREATE"
        content = json.dumps(row["fields"]["description"])
        assert "Accountable team: team-platform" in content
    assert db_session.get(Finding, one).jira_team_id is None


def test_membership_filters_and_exclusions_agree_without_double_counting(db_session, config):
    run_id = seed_run(db_session)
    record_id = seed_finding(db_session, run_id, service=None, services=["Altana", "GSCIP"])
    record = db_session.get(Finding, record_id)
    for service in ("Altana", "GSCIP", ["Altana", "GSCIP"]):
        rows = list(csv.DictReader(io.StringIO(generate(db_session, "findings", {"service": service}))))
        assert len(rows) == 1
        assert json.loads(rows[0]["services"]) == ["Altana", "GSCIP"]
    summary = list(csv.DictReader(io.StringIO(generate(db_session, "risk-summary",
                                                      {"service": ["Altana", "GSCIP"]}))))
    assert sum(int(row["count"]) for row in summary) == 1
    policy = ExclusionPolicy.model_validate({"rules": [{
        "id": "pause-altana", "owner": "test", "reason": "Test service pause",
        "match": {"all": [{"field": "service", "value": "Altana"}]},
    }]})
    assert policy.matching_rules(record)
    assert db_session.query(Finding).filter(policy.sql(Finding, "sqlite")).count() == 1
    assert list(csv.DictReader(io.StringIO(generate(db_session, "findings",
                                                    exclusion_policy=policy)))) == []
    # Authoritative membership takes precedence over a stale scalar value.
    record.services, record.service = ["GSCIP"], "Altana"
    db_session.flush()
    assert not policy.matching_rules(record)
    assert db_session.query(Finding).filter(policy.sql(Finding, "sqlite")).count() == 0


def enrich(session, config, tags, *, raw_tags=None):
    session.query(FindingStaging).delete()
    run_id = uuid.uuid4()
    staged = normalise_finding({"id": "one", "asset_id": "asset-1", "name": "Test",
                                "severity": "HIGH", "state": "ACTIVE",
                                "extra_properties": {"tag_names": raw_tags or [], "tag_ids": ["tag"]}}, run_id)
    session.add(staged)
    session.commit()
    apply_asset_tags_enrichment(session, run_id, {"asset-1": tags}, {}, 0.25)
    session.commit()
    apply_enrichment(session, run_id)
    session.commit()
    reconcile(session, config, run_id)
    session.commit()
    session.expire_all()
    return session.query(Finding).filter_by(tenable_finding_id="one").one()


def test_membership_order_survives_database_and_partial_tag_enrichment(db_session, config):
    record = enrich(db_session, config, ["Service-Altana", "Owner-team-api"])
    assert record.service == "Altana"
    record = enrich(db_session, config, ["Service-GSCIP", "Service-Altana"],
                     raw_tags=["Service-Altana", "Owner-team-api"])
    assert record.services == ["GSCIP", "Altana"]
    assert record.service is None
    assert resolve_route(record, config).team_id == "team-platform"
    record = enrich(db_session, config, ["Service-Altana", "Service-GSCIP"])
    assert record.services == ["Altana", "GSCIP"]
    assert resolve_route(record, config).team_id == "team-api"
    record = enrich(db_session, config, ["Service-GSCIP"])
    assert record.service == "GSCIP"
    assert record.services == ["GSCIP"]
    assert resolve_route(record, config).team_id == "team-platform"


def test_csv_owner_metadata_does_not_override_service_ranking(db_session, config):
    config.jira.remediation_team_priority = ["team-api"]
    db_session.add(EnrichmentMapping(asset_identifier="asset-1", identifier_type="asset_id",
                                     service_owner_team="team-platform"))
    db_session.commit()
    record = enrich(db_session, config, ["Service-Altana", "Service-GSCIP",
                                         "Owner-team-api", "Owner-team-platform"])
    assert record.services == ["Altana", "GSCIP"]
    assert record.service_owner_team == "team-platform"
    assert resolve_route(record, config).team_id == "team-api"


def test_one_shared_finding_creates_one_ticket_and_keeps_its_binding(db_engine, config, monkeypatch):
    monkeypatch.setenv("TEST_JIRA_TOKEN", "test-token")
    server = JiraServer()
    config.jira.remediation_team_priority = ["team-platform"]
    with Session(db_engine) as session:
        run_id = seed_run(session)
        record_id = seed_finding(session, run_id, services=["Altana", "GSCIP"],
                                 service_owner_team=None)
        first = sync_jira(db_engine, config, client_factory=server.factory, now=NOW)
        assert first["created"] == 1
        session.expire_all()
        record = session.get(Finding, record_id)
        original_key = record.jira_ticket_key
        assert record.jira_team_id == "team-platform"
        body = json.loads(server.creates[0].content)
        assert "Affected services: Altana, GSCIP" in json.dumps(body)
        config.jira.remediation_team_priority = ["team-api"]
        record.services = ["GSCIP", "Altana"]
        session.commit()
        sync_jira(db_engine, config, client_factory=server.factory, now=NOW + timedelta(seconds=61))
        session.expire_all()
        assert record.jira_team_id == "team-platform"
        assert record.jira_ticket_key == original_key
        assert len(server.creates) == 1


def test_migration_preserves_legacy_scalar_membership():
    path = Path(__file__).parents[2] / "db/migrations/versions/011_shared_services.py"
    spec = importlib.util.spec_from_file_location("shared_services_migration", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    engine = sa.create_engine("sqlite:///:memory:")
    with engine.begin() as connection:
        connection.execute(sa.text("CREATE TABLE findings (id INTEGER, service TEXT, service_owner_team TEXT)"))
        connection.execute(sa.text("INSERT INTO findings VALUES (1, 'GSCIP', 'team-platform'), (2, NULL, NULL)"))
        with Operations.context(MigrationContext.configure(connection)):
            migration.upgrade()
            rows = connection.execute(sa.text("SELECT services, service_owner_team FROM findings ORDER BY id")).all()
            assert json.loads(rows[0][0]) == ["GSCIP"]
            assert rows[0][1] == "team-platform"
            assert rows[1] == (None, None)
            migration.downgrade()
        assert connection.scalar(sa.text("SELECT service FROM findings WHERE id=1")) == "GSCIP"
    engine.dispose()


def test_missing_migration_stops_before_any_tenable_fetch(db_engine, config, monkeypatch):
    with db_engine.begin() as connection:
        connection.execute(sa.text("ALTER TABLE findings DROP COLUMN services"))

    @contextmanager
    def session_scope():
        with Session(db_engine) as session:
            yield session

    fetch = Mock()
    monkeypatch.setattr("src.pipeline.get_session", session_scope)
    monkeypatch.setattr("src.pipeline._run_streaming", fetch)
    with pytest.raises(RuntimeError, match="findings.services"):
        run_pipeline(config)
    fetch.assert_not_called()
    with Session(db_engine) as session:
        assert session.query(PipelineRun).count() == 0
