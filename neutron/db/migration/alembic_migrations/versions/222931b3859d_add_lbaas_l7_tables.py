# Copyright 2014 OpenStack Foundation
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

"""Add lbaas l7 tables

Revision ID: 222931b3859d
Revises: 2c98f6c7b373
Create Date: 2014-03-03 15:35:46.974523

"""

# revision identifiers, used by Alembic.
revision = '222931b3859d'
down_revision = '2c98f6c7b373'

from alembic import op
import sqlalchemy as sa

actions = ['block', 'redirect', 'addHeader']
rule_types = ['backendServerId']
rule_compare_types = ['integerEq']


def upgrade():
    op.create_table(
        'l7policies',
        sa.Column('tenant_id', sa.String(length=255), nullable=False),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('pool_id', sa.String(length=36), nullable=True),
        sa.Column('priority', sa.Integer, nullable=False),
        sa.Column('action', sa.Enum(*actions), nullable=False),
        sa.Column('key', sa.String(length=255), nullable=True),
        sa.Column('value', sa.String(length=255), nullable=True),
        sa.Column('admin_state_up', sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['pool_id'], ['pools.id'], ondelete="SET NULL")
    )

    op.create_table(
        'l7rules',
        sa.Column('tenant_id', sa.String(length=255), nullable=False),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('type', sa.Enum(*rule_types), nullable=False),
        sa.Column('admin_state_up', sa.Boolean(), nullable=False),
        sa.Column('compare_type', sa.Enum(*rule_compare_types),
                  nullable=False),
        sa.Column('compare_value', sa.String(length=255), nullable=True),
        sa.Column('key', sa.String(length=255), nullable=True),
        sa.Column('value', sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table(
        'l7policyl7ruleassociations',
        sa.Column('policy_id', sa.String(36), nullable=False),
        sa.Column('rule_id', sa.String(36), nullable=False),
        sa.ForeignKeyConstraint(['policy_id'], ['l7policies.id']),
        sa.ForeignKeyConstraint(['rule_id'], ['l7rules.id']),
        sa.PrimaryKeyConstraint('policy_id', 'rule_id')
    )


def downgrade():
    op.drop_table('l7policyl7ruleassociations')
    op.drop_table('l7rules')
    op.drop_table('l7policies')
