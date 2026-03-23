"""add oidc refresh token

Revision ID: a1b2c3d4e5f6
Revises: 64220130af26
Create Date: 2026-03-23 18:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = '30048d66db9c'
down_revision = '30048d66db8c'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('oidc_users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('refresh_token_encrypted', sa.Text(), nullable=True))


def downgrade():
    with op.batch_alter_table('oidc_users', schema=None) as batch_op:
        batch_op.drop_column('refresh_token_encrypted')
