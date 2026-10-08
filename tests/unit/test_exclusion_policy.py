import uuid
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from src.common.models import Finding
from src.exclusions.policy import ExclusionPolicy, load_policy

NOW = datetime(2026, 10, 8, 12, tzinfo=timezone.utc)


def rule(**overrides):
    value = {
        "id": "test-rule",
        "owner": "test-team",
        "reason": "Test exclusion",
        "match": {"all": [{"field": "title", "value": "Test finding"}]},
    }
    value.update(overrides)
    return value


def policy_for(conditions=None, **overrides):
    if conditions is not None:
        overrides["match"] = {"all": conditions}
    return ExclusionPolicy.model_validate({"rules": [rule(**overrides)]})


@pytest.mark.parametrize(
    "conditions,fields,expected",
    [
        (
            [{"field": "asset_kind", "value": "container"}],
            {"asset_type": "containerImage", "asset_name": "internal-image"},
            True,
        ),
        (
            [{"field": "asset_kind", "value": "container"}],
            {"asset_type": None, "asset_name": "ghcr.io/team/app:1"},
            True,
        ),
        (
            [{"field": "asset_kind", "value": "container"}],
            {"asset_type": "device", "asset_name": "ghcr.io/host-name"},
            False,
        ),
        ([{"field": "title", "value": "test finding", "case_sensitive": False}], {}, True),
        ([{"field": "title", "value": "test finding"}], {}, False),
        (
            [{"field": "title", "operator": "contains", "value": "%_"}],
            {"title": "Contains literal %_ text"},
            True,
        ),
        (
            [{"field": "title", "operator": "contains", "value": "%_"}],
            {"title": "ordinary text"},
            False,
        ),
        ([{"field": "title", "operator": "contains", "value": "TEST"}], {}, False),
        (
            [{"field": "asset_name", "operator": "starts_with", "value": "build-"}],
            {"asset_name": "build-123"},
            True,
        ),
        (
            [
                {"field": "owner_team", "operator": "in", "value": ["payments", "api"]},
                {"field": "cve", "value": "CVE-2026-2222"},
            ],
            {
                "service_owner_team": "payments",
                "cve_id": "CVE-2026-1111",
                "cve_ids": ["CVE-2026-1111", "CVE-2026-2222"],
            },
            True,
        ),
        (
            [{"field": "cve", "value": "CVE-2026-1111"}],
            {"cve_id": "CVE-2026-1111", "cve_ids": None},
            True,
        ),
        (
            [{"field": "source", "value": "NESSUS"}, {"field": "detection_id", "value": "abc"}],
            {"source": "OTHER", "plugin_id": "abc"},
            False,
        ),
        ([{"field": "asset_id", "value": "None"}], {"tenable_asset_id": None}, False),
    ],
)
def test_python_and_sql_decisions_agree(db_session, conditions, fields, expected):
    policy = policy_for(conditions)
    finding = Finding(
        id=uuid.uuid4(),
        tenable_finding_id=str(uuid.uuid4()),
        severity="HIGH",
        **({"title": "Test finding"} | fields),
    )
    db_session.add(finding)
    db_session.flush()
    python_match = bool(policy.matching_rules(finding, NOW))
    sql_match = db_session.query(Finding).filter(policy.sql(Finding, "sqlite", NOW)).count() == 1
    assert python_match == sql_match == expected


def test_expiry_is_absolute_utc_and_end_is_exclusive(db_session):
    policy = policy_for(expires_at=NOW.isoformat())
    finding = Finding(
        id=uuid.uuid4(), tenable_finding_id="one", title="Test finding", severity="HIGH"
    )
    db_session.add(finding)
    db_session.flush()
    assert policy.matching_rules(finding, NOW - timedelta(microseconds=1))
    assert not policy.matching_rules(finding, NOW)
    assert db_session.query(Finding).filter(policy.sql(Finding, "sqlite", NOW)).count() == 0


@pytest.mark.parametrize(
    "bad",
    [
        {"match": {"all": []}},
        {"match": {"all": [{"field": "titel", "value": "x"}]}},
        {"match": {"all": [{"field": "title", "value": ""}]}},
        {"match": {"all": [{"field": "cve", "operator": "contains", "value": "CVE"}]}},
        {"match": {"all": [{"field": "title", "operator": "regex", "value": ".*"}]}},
        {"expires_at": "2027-01-08"},
        {"expires_at": "2027-01-08T00:00:00"},
        {"expires_at": 0},
        {"reason": "   "},
        {"match": {"all": [{"field": "asset_kind", "value": "containers"}]}},
        {"enabled": True, "unexpected": "field"},
    ],
)
def test_invalid_rules_fail_validation(bad):
    with pytest.raises(ValidationError):
        policy_for(**bad)


def test_duplicates_are_rejected_across_files(tmp_path):
    import yaml

    (tmp_path / "exclusions.yaml").write_text(yaml.safe_dump({"exclusions": {"rules": [rule()]}}))
    (tmp_path / "exclusions.d").mkdir()
    (tmp_path / "exclusions.d" / "team.yaml").write_text(yaml.safe_dump({"rules": [rule()]}))
    with pytest.raises(ValidationError, match="unique"):
        load_policy(str(tmp_path))


def test_duplicate_yaml_key_is_not_silently_overwritten(tmp_path):
    (tmp_path / "exclusions.yaml").write_text("exclusions:\n  enabled: true\n  enabled: false\n")
    with pytest.raises(ValueError, match="duplicate YAML key"):
        load_policy(str(tmp_path))


def test_any_and_all_and_disabled_rules():
    policy = policy_for(
        match={
            "all": [{"field": "owner_team", "value": "payments"}],
            "any": [{"field": "title", "value": "A"}, {"field": "title", "value": "B"}],
        }
    )
    finding = Finding(title="B", service_owner_team="payments")
    assert policy.matching_rules(finding, NOW)
    finding.service_owner_team = "platform"
    assert not policy.matching_rules(finding, NOW)
    finding.service_owner_team = "payments"
    policy.rules[0].enabled = False
    assert not policy.matching_rules(finding, NOW)
