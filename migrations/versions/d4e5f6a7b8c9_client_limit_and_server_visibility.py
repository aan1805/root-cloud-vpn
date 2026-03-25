"""Add client_limit to oidc_users, is_public to servers/groups, M2M access tables

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-03-25 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = 'd4e5f6a7b8c9'
down_revision = 'c3d4e5f6a7b8'
branch_labels = None
depends_on = None


def upgrade():
    # is_public для серверов (по умолчанию True — обратная совместимость)
    with op.batch_alter_table('servers', schema=None) as batch_op:
        batch_op.add_column(sa.Column('is_public', sa.Boolean(), nullable=False, server_default=sa.true()))

    # is_public для групп серверов
    with op.batch_alter_table('server_groups', schema=None) as batch_op:
        batch_op.add_column(sa.Column('is_public', sa.Boolean(), nullable=False, server_default=sa.true()))

    # client_limit для пользователей портала (0 = безлимит)
    with op.batch_alter_table('oidc_users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('client_limit', sa.Integer(), nullable=False, server_default='0'))

    # M2M: доступ пользователей к приватным серверам
    op.create_table('oidc_user_servers',
        sa.Column('oidc_user_id', sa.Integer(), nullable=False),
        sa.Column('server_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['oidc_user_id'], ['oidc_users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['server_id'], ['servers.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('oidc_user_id', 'server_id')
    )

    # M2M: доступ пользователей к приватным группам
    op.create_table('oidc_user_groups',
        sa.Column('oidc_user_id', sa.Integer(), nullable=False),
        sa.Column('group_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['oidc_user_id'], ['oidc_users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['group_id'], ['server_groups.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('oidc_user_id', 'group_id')
    )


def downgrade():
    op.drop_table('oidc_user_groups')
    op.drop_table('oidc_user_servers')

    with op.batch_alter_table('oidc_users', schema=None) as batch_op:
        batch_op.drop_column('client_limit')

    with op.batch_alter_table('server_groups', schema=None) as batch_op:
        batch_op.drop_column('is_public')

    with op.batch_alter_table('servers', schema=None) as batch_op:
        batch_op.drop_column('is_public')
