"""Change fornex_vps_id from Integer to String(50)

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-03-24 13:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = 'c3d4e5f6a7b8'
down_revision = 'b2c3d4e5f6a7'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('servers', schema=None) as batch_op:
        batch_op.alter_column('fornex_vps_id',
                              existing_type=sa.Integer(),
                              type_=sa.String(50),
                              existing_nullable=True)

    with op.batch_alter_table('haproxy_servers', schema=None) as batch_op:
        batch_op.alter_column('fornex_vps_id',
                              existing_type=sa.Integer(),
                              type_=sa.String(50),
                              existing_nullable=True)


def downgrade():
    with op.batch_alter_table('haproxy_servers', schema=None) as batch_op:
        batch_op.alter_column('fornex_vps_id',
                              existing_type=sa.String(50),
                              type_=sa.Integer(),
                              existing_nullable=True)

    with op.batch_alter_table('servers', schema=None) as batch_op:
        batch_op.alter_column('fornex_vps_id',
                              existing_type=sa.String(50),
                              type_=sa.Integer(),
                              existing_nullable=True)
