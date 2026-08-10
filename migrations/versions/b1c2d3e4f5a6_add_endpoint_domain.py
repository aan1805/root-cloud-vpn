"""add endpoint_domain to servers and haproxy_servers

Клиентские конфиги раньше содержали голый IP сервера. Конфиг у клиента не
обновляется, поэтому смена адреса или переезд на другую машину ломали все ранее
выданные конфиги. Домен позволяет пережить переезд правкой DNS.

Revision ID: b1c2d3e4f5a6
Revises: a7b8c9d0e1f3
Create Date: 2026-08-10

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b1c2d3e4f5a6'
down_revision = 'a7b8c9d0e1f3'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('servers', sa.Column('endpoint_domain', sa.String(length=255), nullable=True))
    op.add_column('haproxy_servers', sa.Column('endpoint_domain', sa.String(length=255), nullable=True))


def downgrade():
    op.drop_column('haproxy_servers', 'endpoint_domain')
    op.drop_column('servers', 'endpoint_domain')
