"""Add batched-fetch checkpoint columns.

Revision ID: 004
Revises: 003
Create Date: 2026-04-28
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSON

revision: str = "004"
down_revision: Union[str, None] = "003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "pipeline_runs",
        sa.Column("asset_ids_for_run", JSON, nullable=True),
    )
    op.add_column(
        "pipeline_runs",
        sa.Column("last_batch_idx", sa.Integer, nullable=False, server_default="0"),
    )
    op.add_column(
        "pipeline_runs",
        sa.Column("total_batches", sa.Integer, nullable=True),
    )


def downgrade() -> None:
    op.drop_column("pipeline_runs", "total_batches")
    op.drop_column("pipeline_runs", "last_batch_idx")
    op.drop_column("pipeline_runs", "asset_ids_for_run")
