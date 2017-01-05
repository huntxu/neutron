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

Revision ID: 4798b163fab5
Revises: 1b9cf1809665
Create Date: 2017-01-04 23:57:10.409817

"""

# revision identifiers, used by Alembic.
revision = '4798b163fab5'
down_revision = '1b9cf1809665'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column(
        'members',
        sa.Column('priority', sa.Integer, nullable=False,
                  server_default='256')
    )


def downgrade():
    op.drop_column('members', 'priority')
