"""initial cerberus schema

Revision ID: 0001_initial
Revises: 
Create Date: 2026-02-12 00:00:00
"""

from alembic import op

from app.db.base import Base
from app.models import schema  # noqa: F401

# revision identifiers, used by Alembic.
revision = '0001_initial'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)


def downgrade() -> None:
    bind = op.get_bind()
    Base.metadata.drop_all(bind=bind)
