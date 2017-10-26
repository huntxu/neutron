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

"""add NAT support to IPSec VPN

Revision ID: 44e812868e6f
Revises: 1ec373736f8b
Create Date: 2017-10-31 16:06:24.427885

"""

# revision identifiers, used by Alembic.
revision = '44e812868e6f'
down_revision = '1ec373736f8b'

from alembic import op
import sqlalchemy as sa



def upgrade():
    op.add_column(
        'ipsec_site_connections',
        sa.Column('local_cidr', sa.String(length=32), nullable=True)
    )


def downgrade():
    op.drop_column('ipsec_site_connections', 'local_cidr')
