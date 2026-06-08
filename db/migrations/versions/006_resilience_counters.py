"""Add resilience counters to pipeline_runs.

Revision ID: 006
Revises: 005
Create Date: 2026-05-20
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "006"
down_revision: Union[str, None] = "005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "pipeline_runs",
        sa.Column("findings_skipped", sa.Integer, nullable=False, server_default="0"),
    )
    op.add_column(
        "pipeline_runs",
        sa.Column("pages_failed", sa.Integer, nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_column("pipeline_runs", "pages_failed")
    op.drop_column("pipeline_runs", "findings_skipped")
