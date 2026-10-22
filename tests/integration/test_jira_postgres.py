"""Migration and locking checks in a disposable schema on an explicit test database.

VM_JIRA_TEST_DATABASE_URL must point to an isolated PostgreSQL test database.
Without it, these tests skip and the unit suite remains self-contained.
"""

import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from src.common.models import Finding, JiraCreationBudget
from src.integration.jira_sync import LOCK_ID, delivery_session, sync_jira
from tests.jira_helpers import NOW, JiraServer, config_for_teams, seed_finding, seed_run


@pytest.fixture
def migrated_engine(monkeypatch):
    value = os.environ.get("VM_JIRA_TEST_DATABASE_URL")
    if not value:
        pytest.skip("VM_JIRA_TEST_DATABASE_URL is not set")
    url = make_url(value)
    if url.get_backend_name() != "postgresql":
        raise ValueError("PostgreSQL test URL required")
    admin = create_engine(url)
    schema = f"jira_test_{uuid.uuid4().hex}"
    with admin.begin() as conn:
        conn.execute(text(f'CREATE SCHEMA "{schema}"'))
    scoped_url = url.update_query_dict({"options": f"-csearch_path={schema}"})
    engine = create_engine(scoped_url)
    monkeypatch.setenv("DATABASE_URL", scoped_url.render_as_string(hide_password=False))
    cfg = Config(str(Path("db/alembic.ini").resolve()))
    cfg.set_main_option("script_location", str(Path("db/migrations").resolve()))
    try:
        command.upgrade(cfg, "head")
        yield engine, cfg
    finally:
        engine.dispose()
        with admin.begin() as conn:
            conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()


def test_migration_upgrade_downgrade_preserves_existing_findings(migrated_engine):
    engine, cfg = migrated_engine
    with Session(engine) as session:
        run = seed_run(session)
        finding = seed_finding(session, run)
    assert "jira_binding" in {c["name"] for c in inspect(engine).get_columns("findings")}
    command.downgrade(cfg, "007")
    assert "jira_binding" not in {c["name"] for c in inspect(engine).get_columns("findings")}
    command.upgrade(cfg, "head")
    with Session(engine) as session:
        assert session.get(Finding, finding).title == "Patch vulnerable lib"


def test_advisory_lock_survives_commits_and_releases(migrated_engine):
    engine, _ = migrated_engine
    with delivery_session(engine) as session:
        assert session is not None
        session.commit()
        with ThreadPoolExecutor(max_workers=1) as pool:

            def competing_worker():
                with delivery_session(engine) as other:
                    return other is None

            assert pool.submit(competing_worker).result(timeout=10)
    with delivery_session(engine) as session:
        assert session is not None
    with engine.connect() as conn:
        assert conn.execute(text("SELECT pg_try_advisory_lock(:key)"), {"key": LOCK_ID}).scalar()
        conn.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": LOCK_ID})


def test_postgres_delivery_replay_and_budget(migrated_engine, monkeypatch):
    engine, _ = migrated_engine
    monkeypatch.setenv("TEST_JIRA_TOKEN", "integration-test-token")
    config = config_for_teams()
    config.rollout.active_phase.max_tickets_per_run = 1
    with Session(engine) as session:
        run = seed_run(session)
        seed_finding(session, run)
        seed_finding(session, run)
    server = JiraServer()
    assert sync_jira(engine, config, client_factory=server.factory, now=NOW)["created"] == 1
    sync_jira(engine, config, client_factory=server.factory, now=NOW)
    assert len(server.creates) == 1
    with Session(engine) as session:
        assert session.query(JiraCreationBudget).one().reserved == 1


def test_exclusion_migration_pause_json_cve_match_and_resume(migrated_engine):
    from datetime import timedelta, timezone

    from src.common.models import ExclusionAudit
    from src.exclusions.policy import ExclusionPolicy
    from src.exclusions.service import refresh_exclusions

    engine, cfg = migrated_engine
    config = config_for_teams()
    expiry = (NOW + timedelta(days=90)).replace(tzinfo=timezone.utc)
    config.exclusions = ExclusionPolicy.model_validate(
        {
            "rules": [
                {
                    "id": "scoped-cve",
                    "owner": "team-platform",
                    "reason": "Vendor fix pending",
                    "expires_at": expiry,
                    "match": {
                        "all": [
                            {"field": "cve", "value": "CVE-2026-2222"},
                            {"field": "owner_team", "value": "team-platform"},
                        ]
                    },
                }
            ]
        }
    )
    with Session(engine) as session:
        run = seed_run(session)
        fid = seed_finding(
            session, run, cve_id="CVE-2026-1111", cve_ids=["CVE-2026-1111", "CVE-2026-2222"]
        )
        query = session.query(Finding).filter(config.exclusions.sql(Finding, "postgresql", NOW))
        assert query.one().id == fid
        assert refresh_exclusions(session, config, now=NOW)["paused"] == 1
        session.commit()
        assert session.get(Finding, fid).processing_status == "PAUSED"
        assert refresh_exclusions(session, config, now=expiry)["resumed"] == 1
        session.commit()
        assert session.get(Finding, fid).first_seen == NOW
        assert session.query(ExclusionAudit).count() == 2
    command.downgrade(cfg, "008")
    assert "processing_status" not in {c["name"] for c in inspect(engine).get_columns("findings")}
    command.upgrade(cfg, "head")
    with Session(engine) as session:
        assert session.get(Finding, fid).processing_status == "ACTIVE"
