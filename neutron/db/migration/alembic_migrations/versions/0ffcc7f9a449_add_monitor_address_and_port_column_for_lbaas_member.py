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

"""add priority column for lbaas member table

Revision ID: 0ffcc7f9a449
Revises: 7dc5a7c3d759
Create Date: 2017-05-11 23:57:10.409817

"""

# revision identifiers, used by Alembic.
revision = '0ffcc7f9a449'
down_revision = '7dc5a7c3d759'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column(
        'members',
        sa.Column('monitor_address', sa.String(64), nullable=True)
    )
    op.add_column(
        'members',
        sa.Column('monitor_port', sa.Integer, nullable=True)
    )


def downgrade():
    op.drop_column('members', 'monitor_address')
    op.drop_column('members', 'monitor_port')
