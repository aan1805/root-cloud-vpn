"""Add XRay Reality to HaproxyServer and ServerGroup

Revision ID: f6a7b8c9d0e1
Revises: e5f6a7b8c9d0
Create Date: 2026-03-25
"""
from alembic import op
import sqlalchemy as sa

revision = 'f6a7b8c9d0e1'
down_revision = 'e5f6a7b8c9d0'
branch_labels = None
depends_on = None


def upgrade():
    # haproxy_servers: XRay Reality fields
    op.add_column('haproxy_servers', sa.Column('xray_public_key', sa.Text(), nullable=True))
    op.add_column('haproxy_servers', sa.Column('xray_private_key_encrypted', sa.Text(), nullable=True))
    op.add_column('haproxy_servers', sa.Column(
        'xray_status', sa.String(20), nullable=True, server_default='not_installed'
    ))

    # server_groups: Reality per-group fields
    op.add_column('server_groups', sa.Column(
        'reality_enabled', sa.Boolean(), nullable=False, server_default='false'
    ))
    op.add_column('server_groups', sa.Column('reality_port', sa.Integer(), nullable=True))
    op.add_column('server_groups', sa.Column(
        'reality_sni', sa.String(255), nullable=True, server_default='www.microsoft.com'
    ))
    op.add_column('server_groups', sa.Column(
        'reality_haproxy_server_id', sa.Integer(),
        sa.ForeignKey('haproxy_servers.id'), nullable=True
    ))
    op.add_column('server_groups', sa.Column('reality_relay_uuid', sa.String(36), nullable=True))


def downgrade():
    op.drop_column('server_groups', 'reality_relay_uuid')
    op.drop_column('server_groups', 'reality_haproxy_server_id')
    op.drop_column('server_groups', 'reality_sni')
    op.drop_column('server_groups', 'reality_port')
    op.drop_column('server_groups', 'reality_enabled')

    op.drop_column('haproxy_servers', 'xray_status')
    op.drop_column('haproxy_servers', 'xray_private_key_encrypted')
    op.drop_column('haproxy_servers', 'xray_public_key')
