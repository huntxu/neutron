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

"""eayun_portmapping

Revision ID: eayun_portmapping
Revises: eayun_neutron_qos_db_refine
Create Date: 2015-07-25 23:00:00.000000

"""
from neutron.db.migration.alembic_migrations import eayun_portmapping_init_ops


# revision identifiers, used by Alembic.
revision = 'eayun_portmapping'
down_revision = 'eayun_neutron_qos_db_refine'


def upgrade():
    eayun_portmapping_init_ops.upgrade()


def downgrade():
    eayun_portmapping_init_ops.downgrade()
