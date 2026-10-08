"""Middleware exclusions, full CVE matching and pause/resume history.

Revision ID: 009
Revises: 008
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "009"
down_revision = "008"
branch_labels = None
depends_on = None


def upgrade():
    for table in ("findings", "findings_staging"):
        op.add_column(table, sa.Column("cve_ids", sa.JSON(), nullable=True))
    op.add_column(
        "findings",
        sa.Column("processing_status", sa.String(20), nullable=False, server_default="ACTIVE"),
    )
    for name, kind in (
        ("exclusion_rule_ids", sa.JSON()),
        ("exclusion_reason", sa.Text()),
        ("exclusion_until", sa.DateTime()),
        ("exclusion_evaluated_at", sa.DateTime()),
        ("exclusion_policy_hash", sa.String(64)),
        ("last_observed_at", sa.DateTime()),
    ):
        op.add_column("findings", sa.Column(name, kind, nullable=True))
    op.create_index("ix_findings_processing_status", "findings", ["processing_status"])
    op.add_column(
        "pipeline_runs",
        sa.Column("findings_excluded", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column("pipeline_runs", sa.Column("exclusion_policy_hash", sa.String(64), nullable=True))
    op.create_table(
        "exclusion_audit",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("finding_id", UUID(as_uuid=True), nullable=False),
        sa.Column("tenable_finding_id", sa.String(255), nullable=False),
        sa.Column("action", sa.String(20), nullable=False),
        sa.Column("rules", sa.JSON(), nullable=False),
        sa.Column("policy_hash", sa.String(64), nullable=False),
        sa.Column("evaluated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_exclusion_audit_finding_id", "exclusion_audit", ["finding_id"])


def downgrade():
    op.drop_table("exclusion_audit")
    op.drop_column("pipeline_runs", "findings_excluded")
    op.drop_column("pipeline_runs", "exclusion_policy_hash")
    op.drop_index("ix_findings_processing_status", table_name="findings")
    for name in (
        "processing_status",
        "exclusion_rule_ids",
        "exclusion_reason",
        "exclusion_until",
        "exclusion_evaluated_at",
        "exclusion_policy_hash",
        "last_observed_at",
    ):
        op.drop_column("findings", name)
    for table in ("findings", "findings_staging"):
        op.drop_column(table, "cve_ids")
