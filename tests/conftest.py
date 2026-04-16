"""Shared test fixtures."""

from __future__ import annotations

import uuid
from datetime import datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from src.common.config import AppConfig, AppSettings, ScoringConfig, SLAConfig
from src.common.db import Base


@pytest.fixture
def db_engine():
    """Create an in-memory SQLite engine for tests."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def db_session(db_engine):
    """Provide a transactional test database session."""
    SessionLocal = sessionmaker(bind=db_engine)
    session = SessionLocal()
    try:
        yield session
        session.rollback()
    finally:
        session.close()


@pytest.fixture
def app_config():
    """Provide a test AppConfig with defaults."""
    settings = AppSettings(
        database_url="sqlite:///:memory:",
        config_dir="config",
        log_level="DEBUG",
    )
    return AppConfig(settings=settings)


@pytest.fixture
def run_id():
    """Provide a test pipeline run ID."""
    return uuid.uuid4()


@pytest.fixture
def sample_finding_data():
    """Return a sample Tenable API finding dict."""
    return {
        "id": "finding-test-001",
        "name": "Test Vulnerability",
        "severity": "High",
        "state": "Active",
        "asset_id": "asset-test-001",
        "extra_properties": {
            "asset_name": "test-server-01",
            "vpr_score": 7.5,
            "cve": "CVE-2024-0001",
            "solution": "Apply the latest patch.",
            "acr": 7,
            "aes": 600,
            "epss_score": 35.0,
            "exploit_maturity": "Functional",
            "cvssv3_base_score": 7.8,
            "source": "CloudSecurity",
            "plugin_id": "100001",
            "first_seen": "2026-04-01T08:00:00Z",
            "last_seen": "2026-04-09T06:00:00Z",
            "asset_type": "EC2",
            "asset_ip": "10.0.1.100",
        },
    }
