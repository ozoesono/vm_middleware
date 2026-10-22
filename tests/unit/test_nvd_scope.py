"""Tests for scoping NVD backfill to non-container (host/VM) CVEs."""

import uuid

from src.common.models import Finding
from src.ingestion.nvd_enrichment import distinct_finding_cves

PATTERNS = [".dkr.ecr.", "docker.io/", "ghcr.io/"]


def _f(session, asset_name, cve_id):
    session.add(Finding(
        id=uuid.uuid4(),
        tenable_finding_id=f"f-{uuid.uuid4()}",
        title=cve_id or "misconfig",
        severity="HIGH",
        state="OPEN",
        asset_name=asset_name,
        cve_id=cve_id,
    ))
    session.flush()


def _seed(session):
    _f(session, "111.dkr.ecr.eu-west-2.amazonaws.com/app:1", "CVE-2024-1")
    _f(session, "workerenv-123-worker", "CVE-2024-2")
    _f(session, "222.dkr.ecr.eu-west-2.amazonaws.com/app:2", "CVE-2024-3")
    _f(session, "db-temp1", "CVE-2024-3")
    _f(session, None, "CVE-2024-4")


def test_all_scope_still_respects_global_exclusions(db_session):
    _seed(db_session)
    got = distinct_finding_cves(db_session, exclude_container=False)
    assert got == {"CVE-2024-2", "CVE-2024-3", "CVE-2024-4"}


def test_non_container_scope_drops_container_only_cves(db_session):
    _seed(db_session)
    got = distinct_finding_cves(db_session, exclude_container=True, container_patterns=PATTERNS)
    assert got == {"CVE-2024-2", "CVE-2024-3", "CVE-2024-4"}


def test_no_optional_patterns_does_not_disable_global_policy(db_session):
    _seed(db_session)
    got = distinct_finding_cves(db_session, exclude_container=True, container_patterns=None)
    assert got == {"CVE-2024-2", "CVE-2024-3", "CVE-2024-4"}
