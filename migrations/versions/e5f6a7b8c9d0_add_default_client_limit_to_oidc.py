"""Add default_client_limit to oidc_settings

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-03-25 13:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = 'e5f6a7b8c9d0'
down_revision = 'd4e5f6a7b8c9'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('oidc_settings', schema=None) as batch_op:
        batch_op.add_column(sa.Column('default_client_limit', sa.Integer(), nullable=False, server_default='0'))


def downgrade():
    with op.batch_alter_table('oidc_settings', schema=None) as batch_op:
        batch_op.drop_column('default_client_limit')
