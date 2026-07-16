"""Tests for the workstream classifier and summary report."""

import uuid
from datetime import datetime

from src.common.models import Finding
from src.reporting.csv_reports import (
    WORKSTREAM_CONTAINER,
    WORKSTREAM_HOST_CVE,
    WORKSTREAM_MISCONFIG,
    classify_workstream,
    report_workstream_summary,
)


def test_classify_container_across_registries():
    for name in (
        "111.dkr.ecr.eu-west-2.amazonaws.com/app:1.2.3",
        "docker.io/graphistry/streamgl-viz:v2.50.7-12",
        "ghcr.io/org/app:latest",
        "us.gcr.io/proj/app:1",
        "quay.io/org/app:1",
    ):
        assert classify_workstream(name, "CVE-2024-1") == WORKSTREAM_CONTAINER


def test_classify_host_cve_and_misconfig():
    assert classify_workstream("db-temp1", "CVE-2024-1") == WORKSTREAM_HOST_CVE
    assert classify_workstream("workerenv-123-worker", "CVE-2024-2") == WORKSTREAM_HOST_CVE
    assert classify_workstream("some-iam-role", None) == WORKSTREAM_MISCONFIG
    assert classify_workstream(None, None) == WORKSTREAM_MISCONFIG


def _finding(session, **kw):
    defaults = dict(
        id=uuid.uuid4(),
        tenable_finding_id=str(uuid.uuid4()),
        tenable_asset_id="a",
        title="Test Vuln",
        severity="High",
        state="OPEN",
        first_seen=datetime(2026, 1, 1),
        last_seen=datetime(2026, 1, 1),
    )
    defaults.update(kw)
    f = Finding(**defaults)
    session.add(f)
    session.flush()
    return f


def test_workstream_summary_report(db_session):
    # container: 2 findings on 1 image asset (Docker Hub, not ECR)
    _finding(db_session, tenable_asset_id="img1", asset_name="docker.io/org/app:1", cve_id="CVE-1")
    _finding(db_session, tenable_asset_id="img1", asset_name="docker.io/org/app:1", cve_id="CVE-2")
    # host CVE
    _finding(db_session, tenable_asset_id="host1", asset_name="db-temp1", cve_id="CVE-3")
    # misconfig (no CVE): one open, one stale
    _finding(db_session, tenable_asset_id="role1", asset_name="iam-role-x", cve_id=None)
    _finding(db_session, tenable_asset_id="role2", asset_name="iam-role-y", cve_id=None, state="STALE")

    csv_out = report_workstream_summary(db_session)
    rows = {r.split(",")[0]: r.split(",") for r in csv_out.strip().splitlines()[1:]}

    assert set(rows) == {"container_image", "host_cve", "cloud_misconfig"}
    # columns: workstream, open_findings, stale_findings, distinct_assets
    assert rows["container_image"][1] == "2" and rows["container_image"][3] == "1"
    assert rows["host_cve"][1] == "1"
    assert rows["cloud_misconfig"][1] == "1" and rows["cloud_misconfig"][2] == "1"
