"""Add checkpoint columns to pipeline_runs for streaming/resume.

Revision ID: 002
Revises: 001
Create Date: 2026-04-28
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Where to resume from on the next run if this one is interrupted
    op.add_column(
        "pipeline_runs",
        sa.Column("last_offset", sa.Integer, nullable=False, server_default="0"),
    )
    op.add_column(
        "pipeline_runs",
        sa.Column("pages_completed", sa.Integer, nullable=False, server_default="0"),
    )
    op.add_column(
        "pipeline_runs",
        sa.Column("total_findings_expected", sa.Integer, nullable=True),
    )
    # Tag filter applied during this run (for resume safety: must match)
    op.add_column(
        "pipeline_runs",
        sa.Column("tag_filter", sa.JSON, nullable=True),
    )


def downgrade() -> None:
    op.drop_column("pipeline_runs", "tag_filter")
    op.drop_column("pipeline_runs", "total_findings_expected")
    op.drop_column("pipeline_runs", "pages_completed")
    op.drop_column("pipeline_runs", "last_offset")
