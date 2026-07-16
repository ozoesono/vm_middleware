"""Tests for the ephemeral-asset exclude filter (keeps CI build images out)."""

from src.ingestion.tenable_ingestion import filter_by_exclude_patterns


def _f(asset_name):
    return {"id": "x", "asset_id": "a", "extra_properties": {"asset_name": asset_name}}


def test_excludes_ephemeral_build_and_branch_tags():
    findings = [
        _f("111.dkr.ecr.eu-west-2.amazonaws.com/app:build-abc123"),
        _f("111.dkr.ecr.eu-west-2.amazonaws.com/app:branch-feature-x"),
        _f("111.dkr.ecr.eu-west-2.amazonaws.com/app:1.2.3"),
        _f("host-server-01"),
    ]
    kept = [f["extra_properties"]["asset_name"]
            for f in filter_by_exclude_patterns(findings, [":build-", ":branch-"])]
    assert kept == ["111.dkr.ecr.eu-west-2.amazonaws.com/app:1.2.3", "host-server-01"]


def test_case_insensitive():
    assert filter_by_exclude_patterns([_f("REPO:BUILD-XYZ")], [":build-"]) == []


def test_no_patterns_keeps_everything():
    findings = [_f("repo:build-1"), _f("host")]
    assert filter_by_exclude_patterns(findings, []) == findings
    assert filter_by_exclude_patterns(findings, None) == findings


def test_missing_asset_name_is_kept():
    findings = [{"id": "x", "asset_id": "a", "extra_properties": {}}]
    assert filter_by_exclude_patterns(findings, [":build-"]) == findings
