"""Initial schema — all Phase 0 tables.

Revision ID: 001
Revises: None
Create Date: 2026-04-09
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSON

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- findings ---
    op.create_table(
        "findings",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenable_finding_id", sa.String(255), nullable=False),
        sa.Column("tenable_asset_id", sa.String(255), nullable=True),
        sa.Column("title", sa.String(1000), nullable=False),
        sa.Column("cve_id", sa.String(50), nullable=True),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("vpr_score", sa.Float, nullable=True),
        sa.Column("acr", sa.Integer, nullable=True),
        sa.Column("aes", sa.Integer, nullable=True),
        sa.Column("epss_score", sa.Float, nullable=True),
        sa.Column("exploit_maturity", sa.String(50), nullable=True),
        sa.Column("cvssv3_score", sa.Float, nullable=True),
        sa.Column("source", sa.String(50), nullable=True),
        sa.Column("plugin_id", sa.String(50), nullable=True),
        sa.Column("solution", sa.Text, nullable=True),
        sa.Column("asset_name", sa.String(500), nullable=True),
        sa.Column("asset_type", sa.String(100), nullable=True),
        sa.Column("asset_ip", sa.String(50), nullable=True),
        sa.Column("asset_hostname", sa.String(500), nullable=True),
        sa.Column("portfolio", sa.String(255), nullable=True),
        sa.Column("service", sa.String(255), nullable=True),
        sa.Column("environment", sa.String(50), nullable=True),
        sa.Column("data_sensitivity", sa.String(50), nullable=True),
        sa.Column("asset_criticality", sa.String(20), nullable=True),
        sa.Column("asset_criticality_score", sa.Float, nullable=True, server_default="0.25"),
        sa.Column("service_owner", sa.String(255), nullable=True),
        sa.Column("service_owner_team", sa.String(255), nullable=True),
        sa.Column("risk_model", sa.String(20), nullable=False, server_default="custom"),
        sa.Column("risk_score", sa.Float, nullable=False, server_default="0.0"),
        sa.Column("risk_rating", sa.String(20), nullable=False, server_default="LOW"),
        sa.Column("sla_days", sa.Integer, nullable=False, server_default="90"),
        sa.Column("sla_due_date", sa.Date, nullable=True),
        sa.Column("sla_status", sa.String(20), nullable=False, server_default="WITHIN_SLA"),
        sa.Column("state", sa.String(20), nullable=False, server_default="OPEN"),
        sa.Column("tenable_state", sa.String(20), nullable=True),
        sa.Column("first_seen", sa.DateTime, nullable=True),
        sa.Column("last_seen", sa.DateTime, nullable=True),
        sa.Column("remediated_at", sa.DateTime, nullable=True),
        sa.Column("time_to_fix_days", sa.Integer, nullable=True),
        sa.Column("is_recurrence", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("recurrence_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("jira_ticket_key", sa.String(50), nullable=True),
        sa.Column("jira_ticket_status", sa.String(50), nullable=True),
        sa.Column("jira_created_at", sa.DateTime, nullable=True),
        sa.Column("jira_closed_at", sa.DateTime, nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("last_run_id", UUID(as_uuid=True), nullable=True),
    )
    op.create_index("ix_findings_tenable_finding_id", "findings", ["tenable_finding_id"], unique=True)
    op.create_index("ix_findings_state_risk_rating", "findings", ["state", "risk_rating"])
    op.create_index("ix_findings_sla_due_date_status", "findings", ["sla_due_date", "sla_status"])
    op.create_index("ix_findings_portfolio_service", "findings", ["portfolio", "service"])
    op.create_index("ix_findings_last_seen", "findings", ["last_seen"])
    op.create_index("ix_findings_jira_ticket_key", "findings", ["jira_ticket_key"])

    # --- findings_staging ---
    op.create_table(
        "findings_staging",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("run_id", UUID(as_uuid=True), nullable=False),
        sa.Column("tenable_finding_id", sa.String(255), nullable=False),
        sa.Column("tenable_asset_id", sa.String(255), nullable=True),
        sa.Column("title", sa.String(1000), nullable=False),
        sa.Column("cve_id", sa.String(50), nullable=True),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("vpr_score", sa.Float, nullable=True),
        sa.Column("acr", sa.Integer, nullable=True),
        sa.Column("aes", sa.Integer, nullable=True),
        sa.Column("epss_score", sa.Float, nullable=True),
        sa.Column("exploit_maturity", sa.String(50), nullable=True),
        sa.Column("cvssv3_score", sa.Float, nullable=True),
        sa.Column("source", sa.String(50), nullable=True),
        sa.Column("plugin_id", sa.String(50), nullable=True),
        sa.Column("solution", sa.Text, nullable=True),
        sa.Column("tenable_state", sa.String(20), nullable=True),
        sa.Column("asset_name", sa.String(500), nullable=True),
        sa.Column("asset_type", sa.String(100), nullable=True),
        sa.Column("asset_ip", sa.String(50), nullable=True),
        sa.Column("asset_hostname", sa.String(500), nullable=True),
        sa.Column("tenable_tags", JSON, nullable=True),
        sa.Column("first_seen", sa.DateTime, nullable=True),
        sa.Column("last_seen", sa.DateTime, nullable=True),
        sa.Column("ingested_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_findings_staging_run_id", "findings_staging", ["run_id"])
    op.create_index("ix_findings_staging_tenable_finding_id", "findings_staging", ["tenable_finding_id"])

    # --- enrichment_mappings ---
    op.create_table(
        "enrichment_mappings",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("asset_identifier", sa.String(500), nullable=False),
        sa.Column("identifier_type", sa.String(50), nullable=False, server_default="asset_id"),
        sa.Column("portfolio", sa.String(255), nullable=True),
        sa.Column("service", sa.String(255), nullable=True),
        sa.Column("environment", sa.String(50), nullable=True),
        sa.Column("data_sensitivity", sa.String(50), nullable=True),
        sa.Column("asset_criticality", sa.String(20), nullable=True),
        sa.Column("asset_criticality_score", sa.Float, nullable=True),
        sa.Column("service_owner", sa.String(255), nullable=True),
        sa.Column("service_owner_team", sa.String(255), nullable=True),
        sa.Column("source", sa.String(50), nullable=False, server_default="csv"),
        sa.Column("updated_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_enrichment_mappings_asset_identifier", "enrichment_mappings", ["asset_identifier"])
    op.create_unique_constraint("uq_enrichment_asset", "enrichment_mappings", ["asset_identifier", "identifier_type"])

    # --- enrichment_overrides ---
    op.create_table(
        "enrichment_overrides",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("asset_identifier", sa.String(500), nullable=False),
        sa.Column("identifier_type", sa.String(50), nullable=False, server_default="asset_name"),
        sa.Column("field_name", sa.String(100), nullable=False),
        sa.Column("field_value", sa.String(500), nullable=False),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_enrichment_overrides_asset_identifier", "enrichment_overrides", ["asset_identifier"])

    # --- jira_action_queue ---
    op.create_table(
        "jira_action_queue",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("run_id", UUID(as_uuid=True), nullable=False),
        sa.Column("finding_id", UUID(as_uuid=True), nullable=False),
        sa.Column("action", sa.String(20), nullable=False),
        sa.Column("payload", JSON, nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="PENDING"),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("processed_at", sa.DateTime, nullable=True),
    )
    op.create_index("ix_jira_action_queue_run_id", "jira_action_queue", ["run_id"])

    # --- jira_sync_log ---
    op.create_table(
        "jira_sync_log",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("run_id", UUID(as_uuid=True), nullable=False),
        sa.Column("finding_id", UUID(as_uuid=True), nullable=False),
        sa.Column("jira_ticket_key", sa.String(50), nullable=True),
        sa.Column("action", sa.String(20), nullable=False),
        sa.Column("request_payload", JSON, nullable=True),
        sa.Column("response_status", sa.Integer, nullable=True),
        sa.Column("response_body", JSON, nullable=True),
        sa.Column("success", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_jira_sync_log_run_id", "jira_sync_log", ["run_id"])

    # --- pipeline_runs ---
    op.create_table(
        "pipeline_runs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("started_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime, nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="RUNNING"),
        sa.Column("trigger", sa.String(20), nullable=False, server_default="manual"),
        sa.Column("findings_fetched", sa.Integer, nullable=False, server_default="0"),
        sa.Column("findings_new", sa.Integer, nullable=False, server_default="0"),
        sa.Column("findings_updated", sa.Integer, nullable=False, server_default="0"),
        sa.Column("findings_remediated", sa.Integer, nullable=False, server_default="0"),
        sa.Column("findings_recurred", sa.Integer, nullable=False, server_default="0"),
        sa.Column("findings_stale", sa.Integer, nullable=False, server_default="0"),
        sa.Column("jira_tickets_created", sa.Integer, nullable=False, server_default="0"),
        sa.Column("jira_tickets_updated", sa.Integer, nullable=False, server_default="0"),
        sa.Column("jira_tickets_closed", sa.Integer, nullable=False, server_default="0"),
        sa.Column("errors", JSON, nullable=True),
    )

    # --- risk_exceptions ---
    op.create_table(
        "risk_exceptions",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("finding_id", UUID(as_uuid=True), nullable=False),
        sa.Column("tenable_finding_id", sa.String(255), nullable=False),
        sa.Column("requested_by", sa.String(255), nullable=False),
        sa.Column("justification", sa.Text, nullable=False),
        sa.Column("compensating_controls", sa.Text, nullable=True),
        sa.Column("expiry_date", sa.Date, nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="PENDING"),
        sa.Column("decided_by", sa.String(255), nullable=True),
        sa.Column("decision_date", sa.DateTime, nullable=True),
        sa.Column("decision_notes", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_risk_exceptions_finding_id", "risk_exceptions", ["finding_id"])


def downgrade() -> None:
    op.drop_table("risk_exceptions")
    op.drop_table("pipeline_runs")
    op.drop_table("jira_sync_log")
    op.drop_table("jira_action_queue")
    op.drop_table("enrichment_overrides")
    op.drop_table("enrichment_mappings")
    op.drop_table("findings_staging")
    op.drop_table("findings")
