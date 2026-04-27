"""SQLAlchemy ORM models for the VM Middleware database."""

from __future__ import annotations

import uuid
from datetime import datetime, date

from sqlalchemy import (
    Boolean,
    Column,
    Date,
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSON, UUID

from src.common.db import Base


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


class Finding(Base):
    """Core finding table — scored, enriched vulnerability/misconfiguration records."""

    __tablename__ = "findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenable_finding_id = Column(String(255), nullable=False, unique=True, index=True)
    tenable_asset_id = Column(String(255), nullable=True)

    # Tenable finding data
    title = Column(String(1000), nullable=False)
    cve_id = Column(String(50), nullable=True)
    severity = Column(String(20), nullable=False)  # Critical/High/Medium/Low/Info
    vpr_score = Column(Float, nullable=True)
    acr = Column(Integer, nullable=True)  # Asset Criticality Rating 1-10
    aes = Column(Integer, nullable=True)  # Asset Exposure Score 0-1000
    epss_score = Column(Float, nullable=True)  # 0-100
    exploit_maturity = Column(String(50), nullable=True)
    cvssv3_score = Column(Float, nullable=True)
    source = Column(String(50), nullable=True)  # Nessus/CloudSecurity/WAS
    plugin_id = Column(String(50), nullable=True)
    solution = Column(Text, nullable=True)

    # Asset details
    asset_name = Column(String(500), nullable=True)
    asset_type = Column(String(100), nullable=True)
    asset_ip = Column(String(50), nullable=True)
    asset_hostname = Column(String(500), nullable=True)

    # Enrichment
    portfolio = Column(String(255), nullable=True)
    service = Column(String(255), nullable=True)
    environment = Column(String(50), nullable=True)
    data_sensitivity = Column(String(50), nullable=True)
    asset_criticality = Column(String(20), nullable=True)  # CRITICAL/HIGH/MEDIUM/LOW
    asset_criticality_score = Column(Float, nullable=True, default=0.25)  # 0.25 - 1.0
    service_owner = Column(String(255), nullable=True)
    service_owner_team = Column(String(255), nullable=True)

    # Risk scoring
    risk_model = Column(String(20), nullable=False, default="custom")
    risk_score = Column(Float, nullable=False, default=0.0)
    risk_rating = Column(String(20), nullable=False, default="LOW")
    sla_days = Column(Integer, nullable=False, default=90)
    sla_due_date = Column(Date, nullable=True)
    sla_status = Column(String(20), nullable=False, default="WITHIN_SLA")

    # State management
    state = Column(String(20), nullable=False, default="OPEN")
    tenable_state = Column(String(20), nullable=True)  # Active/Fixed/Resurfaced/New
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    remediated_at = Column(DateTime, nullable=True)
    time_to_fix_days = Column(Integer, nullable=True)
    is_recurrence = Column(Boolean, nullable=False, default=False)
    recurrence_count = Column(Integer, nullable=False, default=0)

    # Jira linkage
    jira_ticket_key = Column(String(50), nullable=True)
    jira_ticket_status = Column(String(50), nullable=True)
    jira_created_at = Column(DateTime, nullable=True)
    jira_closed_at = Column(DateTime, nullable=True)

    # Metadata
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    updated_at = Column(DateTime, nullable=False, server_default=func.now(), onupdate=func.now())
    last_run_id = Column(UUID(as_uuid=True), nullable=True)

    __table_args__ = (
        Index("ix_findings_state_risk_rating", "state", "risk_rating"),
        Index("ix_findings_sla_due_date_status", "sla_due_date", "sla_status"),
        Index("ix_findings_portfolio_service", "portfolio", "service"),
        Index("ix_findings_last_seen", "last_seen"),
        Index("ix_findings_jira_ticket_key", "jira_ticket_key"),
    )


class FindingStaging(Base):
    """Staging table for the current pipeline run's ingested findings."""

    __tablename__ = "findings_staging"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    run_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    tenable_finding_id = Column(String(255), nullable=False, index=True)
    tenable_asset_id = Column(String(255), nullable=True)

    # Raw Tenable data
    title = Column(String(1000), nullable=False)
    cve_id = Column(String(50), nullable=True)
    severity = Column(String(20), nullable=False)
    vpr_score = Column(Float, nullable=True)
    acr = Column(Integer, nullable=True)
    aes = Column(Integer, nullable=True)
    epss_score = Column(Float, nullable=True)
    exploit_maturity = Column(String(50), nullable=True)
    cvssv3_score = Column(Float, nullable=True)
    source = Column(String(50), nullable=True)
    plugin_id = Column(String(50), nullable=True)
    solution = Column(Text, nullable=True)
    tenable_state = Column(String(20), nullable=True)

    # Asset details
    asset_name = Column(String(500), nullable=True)
    asset_type = Column(String(100), nullable=True)
    asset_ip = Column(String(50), nullable=True)
    asset_hostname = Column(String(500), nullable=True)

    # Tenable tags (raw JSON for enrichment processing)
    tenable_tags = Column(JSON, nullable=True)

    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    ingested_at = Column(DateTime, nullable=False, server_default=func.now())


# ---------------------------------------------------------------------------
# Enrichment
# ---------------------------------------------------------------------------


class EnrichmentMapping(Base):
    """Asset-to-business context mappings."""

    __tablename__ = "enrichment_mappings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_identifier = Column(String(500), nullable=False, index=True)
    identifier_type = Column(String(50), nullable=False, default="asset_id")
    portfolio = Column(String(255), nullable=True)
    service = Column(String(255), nullable=True)
    environment = Column(String(50), nullable=True)
    data_sensitivity = Column(String(50), nullable=True)
    asset_criticality = Column(String(20), nullable=True)
    asset_criticality_score = Column(Float, nullable=True)
    service_owner = Column(String(255), nullable=True)
    service_owner_team = Column(String(255), nullable=True)
    source = Column(String(50), nullable=False, default="csv")  # csv / aws_tags / manual
    updated_at = Column(DateTime, nullable=False, server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        UniqueConstraint("asset_identifier", "identifier_type", name="uq_enrichment_asset"),
    )


class EnrichmentOverride(Base):
    """Manual override mappings (uploaded via CSV)."""

    __tablename__ = "enrichment_overrides"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_identifier = Column(String(500), nullable=False, index=True)
    identifier_type = Column(String(50), nullable=False, default="asset_name")
    field_name = Column(String(100), nullable=False)
    field_value = Column(String(500), nullable=False)
    created_at = Column(DateTime, nullable=False, server_default=func.now())


# ---------------------------------------------------------------------------
# Jira
# ---------------------------------------------------------------------------


class JiraActionQueue(Base):
    """Pending Jira actions produced by the reconciliation step."""

    __tablename__ = "jira_action_queue"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    run_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    finding_id = Column(UUID(as_uuid=True), nullable=False)
    action = Column(String(20), nullable=False)  # CREATE / UPDATE / CLOSE / REOPEN
    payload = Column(JSON, nullable=True)  # Action-specific data
    status = Column(String(20), nullable=False, default="PENDING")  # PENDING / DONE / FAILED
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    processed_at = Column(DateTime, nullable=True)


class JiraSyncLog(Base):
    """History of Jira API calls."""

    __tablename__ = "jira_sync_log"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    run_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    finding_id = Column(UUID(as_uuid=True), nullable=False)
    jira_ticket_key = Column(String(50), nullable=True)
    action = Column(String(20), nullable=False)
    request_payload = Column(JSON, nullable=True)
    response_status = Column(Integer, nullable=True)
    response_body = Column(JSON, nullable=True)
    success = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, nullable=False, server_default=func.now())


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


class PipelineRun(Base):
    """Pipeline run metadata and statistics."""

    __tablename__ = "pipeline_runs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    started_at = Column(DateTime, nullable=False, server_default=func.now())
    completed_at = Column(DateTime, nullable=True)
    status = Column(String(20), nullable=False, default="RUNNING")
    trigger = Column(String(20), nullable=False, default="manual")  # manual / scheduled

    # Statistics
    findings_fetched = Column(Integer, nullable=False, default=0)
    findings_new = Column(Integer, nullable=False, default=0)
    findings_updated = Column(Integer, nullable=False, default=0)
    findings_remediated = Column(Integer, nullable=False, default=0)
    findings_recurred = Column(Integer, nullable=False, default=0)
    findings_stale = Column(Integer, nullable=False, default=0)
    jira_tickets_created = Column(Integer, nullable=False, default=0)
    jira_tickets_updated = Column(Integer, nullable=False, default=0)
    jira_tickets_closed = Column(Integer, nullable=False, default=0)
    errors = Column(JSON, nullable=True)

    # Streaming / resume checkpoint
    last_offset = Column(Integer, nullable=False, default=0)
    pages_completed = Column(Integer, nullable=False, default=0)
    total_findings_expected = Column(Integer, nullable=True)
    tag_filter = Column(JSON, nullable=True)


# ---------------------------------------------------------------------------
# Exceptions (risk acceptance)
# ---------------------------------------------------------------------------


class RiskException(Base):
    """Risk acceptance requests and decisions."""

    __tablename__ = "risk_exceptions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    finding_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    tenable_finding_id = Column(String(255), nullable=False)
    requested_by = Column(String(255), nullable=False)
    justification = Column(Text, nullable=False)
    compensating_controls = Column(Text, nullable=True)
    expiry_date = Column(Date, nullable=False)

    # Decision
    status = Column(String(20), nullable=False, default="PENDING")  # PENDING/APPROVED/REJECTED
    decided_by = Column(String(255), nullable=True)
    decision_date = Column(DateTime, nullable=True)
    decision_notes = Column(Text, nullable=True)

    created_at = Column(DateTime, nullable=False, server_default=func.now())
    updated_at = Column(DateTime, nullable=False, server_default=func.now(), onupdate=func.now())
