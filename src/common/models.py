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


class Finding(Base):
    """Core finding table — scored, enriched vulnerability/misconfiguration records."""

    __tablename__ = "findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenable_finding_id = Column(String(255), nullable=False, unique=True, index=True)
    tenable_asset_id = Column(String(255), nullable=True)

    title = Column(String(1000), nullable=False)
    cve_id = Column(String(100), nullable=True)
    cve_ids = Column(JSON(none_as_null=True), nullable=True)
    severity = Column(String(20), nullable=False)
    vpr_score = Column(Float, nullable=True)
    acr = Column(Integer, nullable=True)
    aes = Column(Integer, nullable=True)
    epss_score = Column(Float, nullable=True)
    exploit_maturity = Column(String(50), nullable=True)
    cvssv3_score = Column(Float, nullable=True)
    source = Column(String(100), nullable=True)
    plugin_id = Column(String(500), nullable=True)  # Tenable may supply a composite detection ID.
    solution = Column(Text, nullable=True)

    asset_name = Column(String(500), nullable=True)
    asset_type = Column(String(100), nullable=True)
    asset_ip = Column(String(50), nullable=True)
    asset_hostname = Column(String(500), nullable=True)

    portfolio = Column(String(255), nullable=True)
    service = Column(String(255), nullable=True)
    environment = Column(String(50), nullable=True)
    data_sensitivity = Column(String(50), nullable=True)
    asset_criticality = Column(String(20), nullable=True)
    asset_criticality_score = Column(Float, nullable=True, default=0.25)
    service_owner = Column(String(255), nullable=True)
    service_owner_team = Column(String(255), nullable=True)

    risk_model = Column(String(20), nullable=False, default="custom")
    risk_score = Column(Float, nullable=False, default=0.0)
    risk_rating = Column(String(20), nullable=False, default="LOW")
    sla_days = Column(Integer, nullable=False, default=90)
    sla_due_date = Column(Date, nullable=True)
    sla_status = Column(String(20), nullable=False, default="WITHIN_SLA")

    state = Column(String(20), nullable=False, default="OPEN")
    tenable_state = Column(String(20), nullable=True)
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    remediated_at = Column(DateTime, nullable=True)
    time_to_fix_days = Column(Integer, nullable=True)
    is_recurrence = Column(Boolean, nullable=False, default=False)
    recurrence_count = Column(Integer, nullable=False, default=0)

    # Middleware eligibility is separate from Tenable lifecycle state.
    processing_status = Column(
        String(20), nullable=False, default="ACTIVE", server_default="ACTIVE"
    )
    exclusion_rule_ids = Column(JSON(none_as_null=True), nullable=True)
    exclusion_reason = Column(Text, nullable=True)
    exclusion_until = Column(DateTime, nullable=True)
    exclusion_evaluated_at = Column(DateTime, nullable=True)
    exclusion_policy_hash = Column(String(64), nullable=True)
    last_observed_at = Column(DateTime, nullable=True)

    jira_ticket_key = Column(String(50), nullable=True)
    jira_ticket_status = Column(String(50), nullable=True)
    jira_created_at = Column(DateTime, nullable=True)
    jira_closed_at = Column(DateTime, nullable=True)
    jira_instance_id = Column(String(100), nullable=True)
    jira_team_id = Column(String(100), nullable=True)
    jira_issue_id = Column(String(100), nullable=True)
    jira_ticket_url = Column(String(1000), nullable=True)
    # Connection identity and destination at first delivery; no credential values.
    jira_binding = Column(JSON(none_as_null=True), nullable=True)
    jira_sync_status = Column(String(30), nullable=True)
    jira_sync_error = Column(Text, nullable=True)
    jira_last_synced_at = Column(DateTime, nullable=True)
    jira_last_checked_at = Column(DateTime, nullable=True)
    jira_next_sync_at = Column(DateTime, nullable=True)
    jira_synced_hash = Column(String(64), nullable=True)
    jira_attempts = Column(Integer, nullable=False, default=0, server_default="0")
    # Persisted before CREATE to prevent duplicates after an uncertain response.
    jira_create_started_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, nullable=False, server_default=func.now())
    updated_at = Column(DateTime, nullable=False, server_default=func.now(), onupdate=func.now())
    last_run_id = Column(UUID(as_uuid=True), nullable=True)

    __table_args__ = (
        Index("ix_findings_state_risk_rating", "state", "risk_rating"),
        Index("ix_findings_sla_due_date_status", "sla_due_date", "sla_status"),
        Index("ix_findings_portfolio_service", "portfolio", "service"),
        Index("ix_findings_last_seen", "last_seen"),
        Index("ix_findings_jira_ticket_key", "jira_ticket_key"),
        Index("ix_findings_jira_sync_due", "jira_next_sync_at", "jira_last_checked_at"),
        Index("ix_findings_jira_team_id", "jira_team_id"),
        Index("ix_findings_processing_status", "processing_status"),
        UniqueConstraint("jira_instance_id", "jira_issue_id", name="uq_findings_jira_issue"),
    )


class FindingStaging(Base):
    """Staging table for the current pipeline run's ingested findings."""

    __tablename__ = "findings_staging"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    run_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    tenable_finding_id = Column(String(255), nullable=False, index=True)
    tenable_asset_id = Column(String(255), nullable=True)

    title = Column(String(1000), nullable=False)
    cve_id = Column(String(100), nullable=True)
    cve_ids = Column(JSON(none_as_null=True), nullable=True)
    severity = Column(String(20), nullable=False)
    vpr_score = Column(Float, nullable=True)
    acr = Column(Integer, nullable=True)
    aes = Column(Integer, nullable=True)
    epss_score = Column(Float, nullable=True)
    exploit_maturity = Column(String(50), nullable=True)
    cvssv3_score = Column(Float, nullable=True)
    source = Column(String(100), nullable=True)
    plugin_id = Column(String(500), nullable=True)
    solution = Column(Text, nullable=True)
    tenable_state = Column(String(20), nullable=True)

    asset_name = Column(String(500), nullable=True)
    asset_type = Column(String(100), nullable=True)
    asset_ip = Column(String(50), nullable=True)
    asset_hostname = Column(String(500), nullable=True)

    tenable_tags = Column(JSON, nullable=True)

    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    ingested_at = Column(DateTime, nullable=False, server_default=func.now())


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
    source = Column(String(50), nullable=False, default="csv")
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


class JiraActionQueue(Base):
    """Pending Jira actions produced by the reconciliation step."""

    __tablename__ = "jira_action_queue"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    run_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    finding_id = Column(UUID(as_uuid=True), nullable=False)
    action = Column(String(20), nullable=False)
    payload = Column(JSON, nullable=True)
    status = Column(String(20), nullable=False, default="PENDING")
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    processed_at = Column(DateTime, nullable=True)

    __table_args__ = (Index("ix_jira_queue_finding_status", "finding_id", "status"),)


class JiraCreationBudget(Base):
    """Reserved CREATE attempts per team and completed ingestion run."""

    __tablename__ = "jira_creation_budgets"
    run_id = Column(UUID(as_uuid=True), primary_key=True)
    team_id = Column(String(100), primary_key=True)
    reserved = Column(Integer, nullable=False, default=0)


class JiraInstanceState(Base):
    """Persist rate-limit cooldowns across workers and manual invocations."""

    __tablename__ = "jira_instance_state"
    instance_id = Column(String(100), primary_key=True)
    retry_after = Column(DateTime, nullable=True)


class JiraSyncLog(Base):
    """History of Jira API calls."""

    __tablename__ = "jira_sync_log"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    run_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    finding_id = Column(UUID(as_uuid=True), nullable=False)
    jira_ticket_key = Column(String(50), nullable=True)
    jira_instance_id = Column(String(100), nullable=True)
    jira_team_id = Column(String(100), nullable=True)
    action = Column(String(20), nullable=False)
    request_payload = Column(JSON, nullable=True)
    response_status = Column(Integer, nullable=True)
    response_body = Column(JSON, nullable=True)
    success = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, nullable=False, server_default=func.now())


class PipelineRun(Base):
    """Pipeline run metadata and statistics."""

    __tablename__ = "pipeline_runs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    started_at = Column(DateTime, nullable=False, server_default=func.now())
    completed_at = Column(DateTime, nullable=True)
    status = Column(String(20), nullable=False, default="RUNNING")
    trigger = Column(String(20), nullable=False, default="manual")

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

    last_offset = Column(Integer, nullable=False, default=0)
    pages_completed = Column(Integer, nullable=False, default=0)
    total_findings_expected = Column(Integer, nullable=True)
    tag_filter = Column(JSON, nullable=True)

    asset_ids_for_run = Column(JSON, nullable=True)
    last_batch_idx = Column(Integer, nullable=False, default=0)
    total_batches = Column(Integer, nullable=True)

    findings_skipped = Column(Integer, nullable=False, default=0)
    findings_excluded = Column(Integer, nullable=False, default=0, server_default="0")
    exclusion_policy_hash = Column(String(64), nullable=True)
    pages_failed = Column(Integer, nullable=False, default=0)

    # Use checkpoint time to distinguish abandoned runs from slow ones.
    updated_at = Column(
        DateTime, nullable=True, server_default=func.now(), onupdate=func.now()
    )


class ExclusionAudit(Base):
    """Middleware pause/resume decisions; never marks a finding remediated."""

    __tablename__ = "exclusion_audit"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    finding_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    tenable_finding_id = Column(String(255), nullable=False)
    action = Column(String(20), nullable=False)
    rules = Column(JSON, nullable=False)
    policy_hash = Column(String(64), nullable=False)
    evaluated_at = Column(DateTime, nullable=False)


class CveDetails(Base):
    """Cached CVE detail data from NVD (National Vulnerability Database).

    Tenable's Inventory API doesn't return rich descriptions/solutions for
    Cloud Security findings — only a CVE ID. NVD provides the official
    description, CVSS scoring, weakness type (CWE), and vendor references
    (which contain remediation guidance).

    Findings JOIN this table on cve_id at report time to surface details
    to resolvers without bloating the findings table.
    """

    __tablename__ = "cve_details"

    cve_id = Column(String(50), primary_key=True)
    description = Column(Text, nullable=True)
    cvss_v3_score = Column(Float, nullable=True)
    cvss_v3_severity = Column(String(20), nullable=True)
    cwe_id = Column(String(50), nullable=True)
    cwe_name = Column(String(500), nullable=True)
    published_at = Column(DateTime, nullable=True)
    references = Column(JSON, nullable=True)
    source = Column(String(50), nullable=False, default="nvd")
    last_fetched_at = Column(DateTime, nullable=False, server_default=func.now())


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

    status = Column(String(20), nullable=False, default="PENDING")
    decided_by = Column(String(255), nullable=True)
    decision_date = Column(DateTime, nullable=True)
    decision_notes = Column(Text, nullable=True)

    created_at = Column(DateTime, nullable=False, server_default=func.now())
    updated_at = Column(DateTime, nullable=False, server_default=func.now(), onupdate=func.now())
