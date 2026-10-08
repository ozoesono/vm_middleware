import copy

import pytest
import yaml
from pydantic import ValidationError

from src.common.jira_config import JiraConfig, load_jira_config
from src.common.models import Finding
from src.integration.routing import resolve_route
from tests.jira_helpers import config_for_teams


def write_config(path, config):
    data = config.jira.model_dump(mode="json")
    teams = data.pop("teams")
    (path / "jira.yaml").write_text(yaml.safe_dump({"jira": data}))
    (path / "teams").mkdir(exist_ok=True)
    for name, team in teams.items():
        (path / "teams" / f"{name}.yaml").write_text(yaml.safe_dump(team))


def test_new_team_is_a_yaml_change_and_reload(tmp_path):
    config = config_for_teams()
    write_config(tmp_path, config)
    first = load_jira_config(str(tmp_path))
    team = copy.deepcopy(first.teams["team-platform"].model_dump(mode="json"))
    team.update(team_id="payments", match={"service_owner_team": ["Payments"]})
    team["jira"]["project"] = "PAY"
    (tmp_path / "teams" / "payments.yaml").write_text(yaml.safe_dump(team))
    config.jira = load_jira_config(str(tmp_path))
    config.rollout.active_phase.team_filter = []
    finding = Finding(service_owner_team=" payments ", risk_rating="HIGH", state="OPEN")
    route = resolve_route(finding, config)
    assert route.status == "ELIGIBLE"
    assert route.destination.project == "PAY"
    assert "payments" not in first.teams


@pytest.mark.parametrize(
    "case", ["unknown_instance", "overlap", "typo", "empty_match", "secret", "http"]
)
def test_invalid_configuration_fails_closed(case):
    data = config_for_teams().jira.model_dump(mode="json")
    if case == "unknown_instance":
        data["teams"]["team-platform"]["jira"]["instance"] = "missing"
    elif case == "overlap":
        data["teams"]["team-api"]["match"] = {"service_owner_team": ["TEAM-PLATFORM"]}
    elif case == "typo":
        data["teams"]["team-api"]["jira"]["prject"] = "API"
    elif case == "empty_match":
        data["teams"]["team-api"]["match"] = {}
    elif case == "secret":
        data["instances"]["one"]["auth"]["token"] = "inline-secret"
    elif case == "http":
        data["instances"]["one"]["base_url"] = "http://jira.example.test"
    with pytest.raises(ValidationError):
        JiraConfig.model_validate(data)


def test_duplicate_yaml_keys_rejected(tmp_path):
    (tmp_path / "jira.yaml").write_text("jira:\n  enabled: false\n  enabled: true\n")
    with pytest.raises(ValueError, match="duplicate YAML key"):
        load_jira_config(str(tmp_path))


def test_duplicate_team_files_rejected(tmp_path):
    write_config(tmp_path, config_for_teams())
    (tmp_path / "teams" / "duplicate.yml").write_text(
        (tmp_path / "teams" / "team-api.yaml").read_text()
    )
    with pytest.raises(ValueError, match="duplicate team_id"):
        load_jira_config(str(tmp_path))


def test_matching_is_and_across_fields_and_or_within_field():
    config = config_for_teams()
    config.jira.teams["team-api"].match["environment"] = ["prod", "production"]
    finding = Finding(
        service_owner_team="team-api", environment="dev", state="OPEN", risk_rating="HIGH"
    )
    assert resolve_route(finding, config).status == "UNROUTED"
    finding.environment = "Production"
    assert resolve_route(finding, config).status == "ELIGIBLE"


def test_disabled_team_and_risk_filters():
    config = config_for_teams()
    finding = Finding(service_owner_team="team-platform", state="OPEN", risk_rating="LOW")
    assert resolve_route(finding, config).status == "INELIGIBLE"
    finding.risk_rating = "HIGH"
    config.jira.teams["team-platform"].enabled = False
    assert "disabled" in resolve_route(finding, config).reason
