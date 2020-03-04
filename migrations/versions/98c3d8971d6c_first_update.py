"""First Update.

Revision ID: 98c3d8971d6c
Revises: 88bc3c2c02a6
Create Date: 2020-02-28 11:18:05.926021

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '98c3d8971d6c'
down_revision = '88bc3c2c02a6'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('deployments', sa.Column('elastic', sa.Boolean, server_default='0', nullable=False))
    op.alter_column('deployments', 'status_reason',
               existing_type=mysql.VARCHAR(length=256),
               type_=mysql.MEDIUMTEXT)
    op.create_foreign_key(None, 'deployments', 'users', ['sub'], ['sub'])
    op.add_column('users', sa.Column('sshkey', sa.Text(), nullable=True))
    op.alter_column('users', 'role',
               existing_type=mysql.VARCHAR(length=32),
               nullable=False)
    # ### end Alembic commands ###


def downgrade():
    op.alter_column('users', 'role',
               existing_type=mysql.VARCHAR(length=32),
               nullable=True)
    op.drop_column('users', 'sshkey')
    op.drop_constraint(None, 'deployments', type_='foreignkey')
    op.alter_column('deployments', 'status_reason',
               existing_type=mysql.MEDIUMTEXT,
               type_=mysql.VARCHAR(256))
    op.drop_column('deployments', 'elastic')
    # ### end Alembic commands ###
