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

"""add extra_action for lb vip

Revision ID: 7dc5a7c3d759
Revises: 222931b3859d
Create Date: 2017-02-29 23:57:10.409817

"""

# revision identifiers, used by Alembic.
revision = '7dc5a7c3d759'
down_revision = '222931b3859d'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column(
        'sessionpersistences',
        sa.Column('extra_actions', sa.String(1024), nullable=True)
    )


def downgrade():
    op.drop_column('sessionpersistences', 'extra_actions')
