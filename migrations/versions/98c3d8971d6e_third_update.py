"""Third Update.

Revision ID: 98c3d8971d6e
Revises: 98c3d8971d6d
Create Date: 2020-03-22
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '98c3d8971d6e'
down_revision = '98c3d8971d6d'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('deployments', sa.Column('stinputs', sa.Text, nullable=True))
    # ### end Alembic commands ###


def downgrade():
    op.drop_column('deployments', 'stinputs')
    # ### end Alembic commands ###

