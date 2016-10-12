# Copyright 2016 OpenStack Foundation
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

"""vpnaas: deprecate two dpd actions

Revision ID: 1b9cf1809665
Revises: 5108f17d7012
Create Date: 2016-09-26 14:00:00.000000

"""

# revision identifiers, used by Alembic.
revision = '1b9cf1809665'
down_revision = '5108f17d7012'

from alembic import op
import sqlalchemy as sa

from neutron.db import migration


def upgrade():
    ipsec_site_connections = sa.sql.table(
        'ipsec_site_connections',
        sa.sql.column('dpd_action'))
    op.execute(
        ipsec_site_connections.update().where(
            ipsec_site_connections.c.dpd_action=='restart-by-peer').values(
                dpd_action='hold'))
    op.execute(
        ipsec_site_connections.update().where(
            ipsec_site_connections.c.dpd_action=='disabled').values(
                dpd_action='hold'))
    migration.alter_column_if_exists(
        'ipsec_site_connections', 'dpd_action',
        type_=sa.Enum('hold', 'clear', 'restart', name='vpn_dpd_actions'),
        nullable=False)


def downgrade():
    pass
