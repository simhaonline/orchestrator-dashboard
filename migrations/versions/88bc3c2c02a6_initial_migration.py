"""Initial migration.

Revision ID: 88bc3c2c02a6
Revises: 
Create Date: 2020-02-28 10:00:42.130743

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '88bc3c2c02a6'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('users',
    sa.Column('sub', sa.String(length=36), nullable=False),
    sa.Column('name', sa.String(length=128), nullable=True),
    sa.Column('username', sa.String(length=64), nullable=False),
    sa.Column('given_name', sa.String(length=64), nullable=True),
    sa.Column('family_name', sa.String(length=64), nullable=True),
    sa.Column('email', sa.String(length=64), nullable=False),
    sa.Column('organisation_name', sa.String(length=64), nullable=True),
    sa.Column('picture', sa.String(length=128), nullable=True),
    sa.Column('role', sa.String(length=32), nullable=True),
    sa.Column('active', sa.Boolean, nullable=False, server_default='1'),
    sa.PrimaryKeyConstraint('sub')
    )
    op.create_table('deployments',
    sa.Column('uuid', sa.String(length=36), nullable=False),
    sa.Column('creation_time', sa.DateTime(), nullable=True),
    sa.Column('update_time', sa.DateTime(), nullable=True),
    sa.Column('physicalId', sa.String(length=36), nullable=True),
    sa.Column('description', sa.String(length=256), nullable=True),
    sa.Column('status', sa.String(length=128), nullable=True),
    sa.Column('status_reason', sa.String(length=256), nullable=True),
    sa.Column('outputs', sa.Text(), nullable=True),
    sa.Column('task', sa.String(length=64), nullable=True),
    sa.Column('links', sa.Text(), nullable=True),
    sa.Column('provider_name', sa.String(length=128), nullable=True),
    sa.Column('endpoint', sa.String(length=256), nullable=True),
    sa.Column('template', sa.Text(), nullable=True),
    sa.Column('inputs', sa.Text(), nullable=True),
    sa.Column('params', sa.Text(), nullable=True),
    sa.Column('locked', sa.Boolean, nullable=False, server_default='0'),
    sa.Column('feedback_required', sa.Boolean, nullable=False, server_default='0'),
    sa.Column('remote', sa.Boolean, nullable=False, server_default='0'),
    sa.Column('issuer', sa.String(length=256), nullable=True),
    sa.Column('storage_encryption', sa.Boolean, nullable=False, server_default='0'),
    sa.Column('vault_secret_uuid', sa.String(length=36), nullable=True),
    sa.Column('vault_secret_key', sa.String(length=36), nullable=True),
    sa.Column('sub', sa.String(length=36), nullable=True),
    sa.PrimaryKeyConstraint('uuid')
    )
    # ### end Alembic commands ###


def downgrade():
    op.drop_table('deployments')
    op.drop_table('users')
    # ### end Alembic commands ###
