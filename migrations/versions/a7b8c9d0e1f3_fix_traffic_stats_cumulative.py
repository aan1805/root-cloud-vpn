"""Fix traffic stats: add cumulative_rx/tx columns for correct daily delta calculation

Revision ID: a7b8c9d0e1f2
Revises: f6a7b8c9d0e1
Create Date: 2026-03-27 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = 'a7b8c9d0e1f3'
down_revision = 'f6a7b8c9d0e1'
branch_labels = None
depends_on = None


def upgrade():
    # Добавляем столбцы для хранения накопительных счётчиков WireGuard
    op.add_column('traffic_stats', sa.Column('cumulative_tx', sa.BigInteger(), nullable=True, server_default='0'))
    op.add_column('traffic_stats', sa.Column('cumulative_rx', sa.BigInteger(), nullable=True, server_default='0'))

    # Заполняем существующие записи: старые bytes_* были накопительными,
    # переносим их в cumulative_* как baseline для корректного вычисления дельты
    op.execute("""
        UPDATE traffic_stats
        SET cumulative_rx = bytes_received,
            cumulative_tx = bytes_sent
        WHERE cumulative_rx = 0 AND cumulative_tx = 0
    """)


def downgrade():
    op.drop_column('traffic_stats', 'cumulative_rx')
    op.drop_column('traffic_stats', 'cumulative_tx')
