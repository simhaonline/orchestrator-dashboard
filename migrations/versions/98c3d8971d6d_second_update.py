"""Second Update.

Revision ID: 98c3d8971d6d
Revises: 98c3d8971d6c
Create Date: 2020-03-04
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '98c3d8971d6d'
down_revision = '98c3d8971d6c'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('deployments', sa.Column('upgradable', sa.Boolean, server_default='0', nullable=False))
    # ### end Alembic commands ###


def downgrade():
    op.drop_column('deployments', 'upgradable')
    # ### end Alembic commands ###
