# Copyright (c) 2015 Eayun, Inc.
# All rights reserved.
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

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'portmappings',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('name', sa.String(length=36), nullable=True),
        sa.Column('status', sa.String(length=16), nullable=True),
        sa.Column('admin_state_up', sa.Boolean(), nullable=False),
        sa.Column('protocol', sa.String(length=16), nullable=False),
        sa.Column('router_id', sa.String(length=36), nullable=False),
        sa.Column('router_port', sa.Integer(), nullable=False),
        sa.Column('destination_ip', sa.String(length=64), nullable=False),
        sa.Column('destination_port', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id']),
        sa.PrimaryKeyConstraint('id')
    )


def downgrade():
    op.drop_table('portmappings')
