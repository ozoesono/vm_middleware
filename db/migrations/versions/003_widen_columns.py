"""Widen plugin_id and source columns to fit real Tenable values.

Revision ID: 003
Revises: 002
Create Date: 2026-04-28
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # plugin_id can be long composite IDs like
    # "CLOUD_SCAN:AWSS3BUCKETPUBLICACCESSEXISTSFINDING_CRITICAL"
    op.alter_column("findings", "plugin_id", type_=sa.String(500))
    op.alter_column("findings_staging", "plugin_id", type_=sa.String(500))

    # source can be longer than 50 in some cases
    op.alter_column("findings", "source", type_=sa.String(100))
    op.alter_column("findings_staging", "source", type_=sa.String(100))

    # cve_id occasionally appears with extra qualifiers
    op.alter_column("findings", "cve_id", type_=sa.String(100))
    op.alter_column("findings_staging", "cve_id", type_=sa.String(100))


def downgrade() -> None:
    op.alter_column("findings", "plugin_id", type_=sa.String(50))
    op.alter_column("findings_staging", "plugin_id", type_=sa.String(50))
    op.alter_column("findings", "source", type_=sa.String(50))
    op.alter_column("findings_staging", "source", type_=sa.String(50))
    op.alter_column("findings", "cve_id", type_=sa.String(50))
    op.alter_column("findings_staging", "cve_id", type_=sa.String(50))
