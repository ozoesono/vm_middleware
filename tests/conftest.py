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
        "name": "CVE-2024-0001",
        "severity": "HIGH",
        "state": "ACTIVE",
        "asset_id": "asset-test-001",
        "extra_properties": {
            "asset_name": "test-server-01",
            "finding_vpr_score": 7.5,
            "finding_cves": ["CVE-2024-0001"],
            "finding_solution": "Apply the latest patch.",
            "finding_cvss3_base_score": 7.8,
            "finding_detection_id": "det-100001",
            "sensor_type": "CS:AC_AWS",
            "asset_class": "device",
            "first_observed_at": "2026-04-01T08:00:00Z",
            "last_observed_at": "2026-04-09T06:00:00Z",
            "ipv4_addresses": ["10.0.1.100"],
        },
    }
