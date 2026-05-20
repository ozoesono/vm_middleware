"""Add cve_details table for NVD-enriched CVE descriptions.

Revision ID: 005
Revises: 004
Create Date: 2026-05-20
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSON

revision: str = "005"
down_revision: Union[str, None] = "004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "cve_details",
        sa.Column("cve_id", sa.String(50), primary_key=True),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("cvss_v3_score", sa.Float, nullable=True),
        sa.Column("cvss_v3_severity", sa.String(20), nullable=True),
        sa.Column("cwe_id", sa.String(50), nullable=True),
        sa.Column("cwe_name", sa.String(500), nullable=True),
        sa.Column("published_at", sa.DateTime, nullable=True),
        sa.Column("references", JSON, nullable=True),
        sa.Column("source", sa.String(50), nullable=False, server_default="nvd"),
        sa.Column("last_fetched_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
    )
    op.create_index(
        "ix_cve_details_last_fetched_at", "cve_details", ["last_fetched_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_cve_details_last_fetched_at", table_name="cve_details")
    op.drop_table("cve_details")
