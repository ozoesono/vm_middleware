"""Add updated_at heartbeat to pipeline_runs for zombie-run detection.

Revision ID: 007
Revises: 006
Create Date: 2026-07-16
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "007"
down_revision: Union[str, None] = "006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "pipeline_runs",
        sa.Column("updated_at", sa.DateTime, nullable=True, server_default=sa.func.now()),
    )
    # Backfill existing rows so the reaper has a progress timestamp to key off.
    op.execute("UPDATE pipeline_runs SET updated_at = started_at WHERE updated_at IS NULL")


def downgrade() -> None:
    op.drop_column("pipeline_runs", "updated_at")
