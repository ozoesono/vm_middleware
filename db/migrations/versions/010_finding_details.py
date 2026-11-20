"""Persist Inventory descriptions and detection evidence.

Revision ID: 010
Revises: 009
"""

import sqlalchemy as sa
from alembic import op

revision = "010"
down_revision = "009"
branch_labels = None
depends_on = None


def upgrade():
    for table in ("findings", "findings_staging"):
        op.add_column(table, sa.Column("source_description", sa.Text(), nullable=True))
        op.add_column(table, sa.Column("detection_output", sa.Text(), nullable=True))


def downgrade():
    for table in ("findings", "findings_staging"):
        op.drop_column(table, "detection_output")
        op.drop_column(table, "source_description")
