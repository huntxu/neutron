# Copyright (c) 2017 Eayun, Inc.
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
#

"""add EayunStack ACL support

Revision ID: 1ec373736f8b
Revises: 0ffcc7f9a449
Create Date: 2017-09-21 14:17:22.862068

"""

# revision identifiers, used by Alembic.
revision = '1ec373736f8b'
down_revision = '0ffcc7f9a449'

from alembic import op
import sqlalchemy as sa


direction = sa.Enum('ingress', 'egress', name='es_acl_rule_direction')
action = sa.Enum('allow', 'deny', name='es_acl_rule_action')


def upgrade():
    op.create_table(
        'es_acls',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('tenant_id', sa.String(length=255), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_table(
        'es_acl_subnet_bindings',
        sa.Column('subnet_id', sa.String(length=36), nullable=False),
        sa.Column('acl_id', sa.String(length=36), nullable=False),
        sa.Column('router_id', sa.String(length=36), nullable=True),
        sa.Column('router_port_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(
            ['subnet_id'], ['subnets.id'],
            name='fk-eayun_acl_subnet_bindings-subnet_id-subents',
            ondelete='CASCADE'),
        sa.ForeignKeyConstraint(
            ['acl_id'], ['es_acls.id'],
            name='fk-eayun_acl_subnet_bindings-acl_id-es_acls'),
        sa.ForeignKeyConstraint(
            ['router_id'], ['routers.id'],
            name='fk-eayun_acl_subnet_bindings-router_id-routers',
            ondelete='SET NULL'),
        sa.ForeignKeyConstraint(
            ['router_port_id'], ['ports.id'],
            name='fk-eayun_acl_subnet_bindings-router_port_id-ports',
            ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('subnet_id')
    )
    op.create_table(
        'es_acl_rules',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('tenant_id', sa.String(length=255), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('acl_id', sa.String(length=36), nullable=True),
        sa.Column('position', sa.Integer(), nullable=True),
        sa.Column('direction', direction, nullable=False),
        sa.Column('protocol', sa.Integer(), nullable=True),
        sa.Column('source_ip_address', sa.String(length=64), nullable=True),
        sa.Column('destination_ip_address', sa.String(length=64),
                  nullable=True),
        sa.Column('source_port_min', sa.Integer(), nullable=True),
        sa.Column('source_port_max', sa.Integer(), nullable=True),
        sa.Column('destination_port_min', sa.Integer(), nullable=True),
        sa.Column('destination_port_max', sa.Integer(), nullable=True),
        sa.Column('action', action, nullable=False),
        sa.ForeignKeyConstraint(
            ['acl_id'], ['es_acls.id'],
            name='fk-eayun_acl_rules-acl_id-es_acls',
            ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )


def downgrade():
    op.drop_table('es_acl_subnet_bindings')
    op.drop_table('es_acl_rules')
    op.drop_table('es_acls')
