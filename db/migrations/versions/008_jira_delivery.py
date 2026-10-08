"""Jira instance bindings, delivery state and durable creation budgets.

Revision ID: 008
Revises: 007
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "008"
down_revision = "007"
branch_labels = None
depends_on = None


def upgrade():
    for name, column_type in (
        ("jira_instance_id", sa.String(100)),
        ("jira_team_id", sa.String(100)),
        ("jira_issue_id", sa.String(100)),
        ("jira_ticket_url", sa.String(1000)),
        ("jira_binding", sa.JSON()),
        ("jira_sync_status", sa.String(30)),
        ("jira_sync_error", sa.Text()),
        ("jira_last_synced_at", sa.DateTime()),
        ("jira_last_checked_at", sa.DateTime()),
        ("jira_next_sync_at", sa.DateTime()),
        ("jira_synced_hash", sa.String(64)),
        ("jira_create_started_at", sa.DateTime()),
    ):
        op.add_column("findings", sa.Column(name, column_type, nullable=True))
    op.add_column(
        "findings", sa.Column("jira_attempts", sa.Integer(), nullable=False, server_default="0")
    )
    op.create_index(
        "ix_findings_jira_sync_due", "findings", ["jira_next_sync_at", "jira_last_checked_at"]
    )
    op.create_index("ix_findings_jira_team_id", "findings", ["jira_team_id"])
    op.create_unique_constraint(
        "uq_findings_jira_issue", "findings", ["jira_instance_id", "jira_issue_id"]
    )
    op.create_index("ix_jira_queue_finding_status", "jira_action_queue", ["finding_id", "status"])
    for name in ("jira_instance_id", "jira_team_id"):
        op.add_column("jira_sync_log", sa.Column(name, sa.String(100), nullable=True))
    op.create_table(
        "jira_creation_budgets",
        sa.Column("run_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("team_id", sa.String(100), primary_key=True),
        sa.Column("reserved", sa.Integer(), nullable=False),
    )
    op.create_table(
        "jira_instance_state",
        sa.Column("instance_id", sa.String(100), primary_key=True),
        sa.Column("retry_after", sa.DateTime(), nullable=True),
    )


def downgrade():
    op.drop_table("jira_instance_state")
    op.drop_table("jira_creation_budgets")
    for name in ("jira_instance_id", "jira_team_id"):
        op.drop_column("jira_sync_log", name)
    op.drop_index("ix_jira_queue_finding_status", table_name="jira_action_queue")
    op.drop_constraint("uq_findings_jira_issue", "findings", type_="unique")
    op.drop_index("ix_findings_jira_team_id", table_name="findings")
    op.drop_index("ix_findings_jira_sync_due", table_name="findings")
    for name in (
        "jira_instance_id",
        "jira_team_id",
        "jira_issue_id",
        "jira_ticket_url",
        "jira_binding",
        "jira_sync_status",
        "jira_sync_error",
        "jira_last_synced_at",
        "jira_last_checked_at",
        "jira_next_sync_at",
        "jira_synced_hash",
        "jira_create_started_at",
        "jira_attempts",
    ):
        op.drop_column("findings", name)
