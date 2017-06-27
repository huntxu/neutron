# Copyright 2017 OpenStack Foundation
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

"""add_es_metering

Revision ID: 2c98f6c7b373
Revises: eayun_pptp_vpn
Create Date: 2017-02-20 11:16:41.306333

"""

# revision identifiers, used by Alembic.
revision = '2c98f6c7b373'
down_revision = 'eayun_pptp_vpn'

from alembic import op
import sqlalchemy as sa


direction = sa.Enum('ingress', 'egress',
                    name='es_metering_label_direction')


def upgrade():
    op.create_table(
        'es_metering_labels',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('tenant_id', sa.String(length=255), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('description', sa.String(length=1024), nullable=True),
        sa.Column('router_id', sa.String(length=36), nullable=False),
        sa.Column('direction', direction, nullable=False),
        sa.Column('internal_ip', sa.String(length=64), nullable=True),
        sa.Column('tcp_port', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['router_id'], ['routers.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )


def downgrade():
    op.drop_table('es_metering_labels')
