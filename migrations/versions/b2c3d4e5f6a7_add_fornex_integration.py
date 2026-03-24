"""Add Fornex API integration: fornex_settings, fornex_vps_id, haproxy_stats, net fields

Revision ID: b2c3d4e5f6a7
Revises: 30048d66db9c
Create Date: 2026-03-24 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = 'b2c3d4e5f6a7'
down_revision = '30048d66db9c'
branch_labels = None
depends_on = None


def upgrade():
    # Таблица настроек Fornex API
    op.create_table('fornex_settings',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('api_key_encrypted', sa.Text(), nullable=False),
        sa.Column('api_base_url', sa.String(255), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )

    # Таблица статистики HAProxy серверов
    op.create_table('haproxy_stats',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('haproxy_server_id', sa.Integer(), nullable=False),
        sa.Column('timestamp', sa.DateTime(), nullable=True),
        sa.Column('cpu_usage', sa.Float(), nullable=True),
        sa.Column('memory_usage', sa.Float(), nullable=True),
        sa.Column('load_1min', sa.Float(), nullable=True),
        sa.Column('net_in_bytes', sa.BigInteger(), nullable=True),
        sa.Column('net_out_bytes', sa.BigInteger(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['haproxy_server_id'], ['haproxy_servers.id']),
        sa.PrimaryKeyConstraint('id')
    )

    # fornex_vps_id для VPN серверов
    with op.batch_alter_table('servers', schema=None) as batch_op:
        batch_op.add_column(sa.Column('fornex_vps_id', sa.Integer(), nullable=True))

    # fornex_vps_id для HAProxy серверов
    with op.batch_alter_table('haproxy_servers', schema=None) as batch_op:
        batch_op.add_column(sa.Column('fornex_vps_id', sa.Integer(), nullable=True))

    # Поля сети в server_stats
    with op.batch_alter_table('server_stats', schema=None) as batch_op:
        batch_op.add_column(sa.Column('net_in_bytes', sa.BigInteger(), nullable=True))
        batch_op.add_column(sa.Column('net_out_bytes', sa.BigInteger(), nullable=True))


def downgrade():
    with op.batch_alter_table('server_stats', schema=None) as batch_op:
        batch_op.drop_column('net_out_bytes')
        batch_op.drop_column('net_in_bytes')

    with op.batch_alter_table('haproxy_servers', schema=None) as batch_op:
        batch_op.drop_column('fornex_vps_id')

    with op.batch_alter_table('servers', schema=None) as batch_op:
        batch_op.drop_column('fornex_vps_id')

    op.drop_table('haproxy_stats')
    op.drop_table('fornex_settings')
