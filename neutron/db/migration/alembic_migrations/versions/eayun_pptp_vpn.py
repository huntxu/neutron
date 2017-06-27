# Copyright (c) 2015 Eayun, Inc.
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

"""eayun_pptp_vpn

Revision ID: eayun_pptp_vpn
Revises: 4798b163fab5
Create Date: 2015-10-26 18:00:00.000000

"""
from neutron.db.migration.alembic_migrations import eayun_pptp_vpn_init_ops


# revision identifiers, used by Alembic.
revision = 'eayun_pptp_vpn'
down_revision = '4798b163fab5'


def upgrade():
    eayun_pptp_vpn_init_ops.upgrade()


def downgrade():
    eayun_pptp_vpn_init_ops.downgrade()
