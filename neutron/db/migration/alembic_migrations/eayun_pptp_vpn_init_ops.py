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
        'pptp_credentials',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('tenant_id', sa.String(length=255), nullable=False),
        sa.Column('username', sa.String(length=255), nullable=False),
        sa.Column('password', sa.String(length=255), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_table(
        'pptpcredentialserviceassociations',
        sa.Column('pptp_credential_id', sa.String(length=36), nullable=False),
        sa.Column('vpnservice_id', sa.String(length=36), nullable=False),
        sa.Column('port_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(
            ['pptp_credential_id'], ['pptp_credentials.id'],
            ondelete='CASCADE'),
        sa.ForeignKeyConstraint(
            ['vpnservice_id'], ['vpnservices.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(
            ['port_id'], ['ports.id'], ondelete='CASCADE')
    )


def downgrade():
    op.drop_table('pptpcredentialserviceassociations')
    op.drop_table('pptp_credentials')
