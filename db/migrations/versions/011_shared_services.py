"""Preserve ordered service memberships on a finding.

Revision ID: 011
Revises: 010
"""

import sqlalchemy as sa
from alembic import op

revision = "011"
down_revision = "010"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("findings", sa.Column("services", sa.JSON(none_as_null=True), nullable=True))
    array = "json_array" if op.get_bind().dialect.name == "sqlite" else "json_build_array"
    op.execute(sa.text(
        f"UPDATE findings SET services = {array}(service) "
        "WHERE service IS NOT NULL AND trim(service) <> ''"
    ))


def downgrade():
    op.drop_column("findings", "services")
