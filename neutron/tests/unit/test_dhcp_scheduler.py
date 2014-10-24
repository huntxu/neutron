# Copyright 2014 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import contextlib
import datetime

import mock

from neutron.common import constants
from neutron.common import topics
from neutron import context
from neutron.db import agents_db
from neutron.db import agentschedulers_db as sched_db
from neutron.db import models_v2
from neutron.openstack.common import timeutils
from neutron.scheduler import dhcp_agent_scheduler
from neutron.tests.unit import testlib_api


class DhcpSchedulerTestCase(testlib_api.SqlTestCase):

    def setUp(self):
        super(DhcpSchedulerTestCase, self).setUp()
        self.ctx = context.get_admin_context()
        self.network_id = 'foo_network_id'
        self._save_networks([self.network_id])

    def _get_agents(self, hosts):
        return [
            agents_db.Agent(
                binary='neutron-dhcp-agent',
                host=host,
                topic=topics.DHCP_AGENT,
                configurations="",
                agent_type=constants.AGENT_TYPE_DHCP,
                created_at=timeutils.utcnow(),
                started_at=timeutils.utcnow(),
                heartbeat_timestamp=timeutils.utcnow())
            for host in hosts
        ]

    def _save_agents(self, agents):
        for agent in agents:
            with self.ctx.session.begin(subtransactions=True):
                self.ctx.session.add(agent)

    def _create_and_set_agents_down(self, hosts, down_agent_count=0):
        dhcp_agents = self._get_agents(hosts)
        # bring down the specified agents
        for agent in dhcp_agents[:down_agent_count]:
            old_time = agent['heartbeat_timestamp']
            hour_old = old_time - datetime.timedelta(hours=1)
            agent['heartbeat_timestamp'] = hour_old
            agent['started_at'] = hour_old
        self._save_agents(dhcp_agents)
        return dhcp_agents

    def _save_networks(self, networks):
        for network_id in networks:
            with self.ctx.session.begin(subtransactions=True):
                self.ctx.session.add(models_v2.Network(id=network_id))

    def _test_schedule_bind_network(self, agents, network_id):
        scheduler = dhcp_agent_scheduler.ChanceScheduler()
        scheduler._schedule_bind_network(self.ctx, agents, network_id)
        results = self.ctx.session.query(
            sched_db.NetworkDhcpAgentBinding).filter_by(
            network_id=network_id).all()
        self.assertEqual(len(agents), len(results))
        for result in results:
            self.assertEqual(network_id, result.network_id)

    def test_schedule_bind_network_single_agent(self):
        agents = self._get_agents(['host-a'])
        self._save_agents(agents)
        self._test_schedule_bind_network(agents, self.network_id)

    def test_schedule_bind_network_multi_agents(self):
        agents = self._get_agents(['host-a', 'host-b'])
        self._save_agents(agents)
        self._test_schedule_bind_network(agents, self.network_id)

    def test_schedule_bind_network_multi_agent_fail_one(self):
        agents = self._get_agents(['host-a'])
        self._save_agents(agents)
        self._test_schedule_bind_network(agents, self.network_id)
        with mock.patch.object(dhcp_agent_scheduler.LOG, 'info') as fake_log:
            self._test_schedule_bind_network(agents, self.network_id)
            self.assertEqual(1, fake_log.call_count)

    def test_auto_schedule_networks_no_networks(self):
        plugin = mock.MagicMock()
        plugin.get_networks.return_value = []
        scheduler = dhcp_agent_scheduler.ChanceScheduler()
        self.assertFalse(scheduler.auto_schedule_networks(plugin,
                                                          self.ctx, "host-a"))

    def test_auto_schedule_networks(self):
        plugin = mock.MagicMock()
        plugin.get_subnets.return_value = [{"network_id": self.network_id,
                                            "enable_dhcp": True}]
        agents = self._get_agents(['host-a'])
        self._save_agents(agents)
        scheduler = dhcp_agent_scheduler.ChanceScheduler()

        self.assertTrue(scheduler.auto_schedule_networks(plugin,
                                                         self.ctx, "host-a"))
        results = (
            self.ctx.session.query(agentschedulers_db.NetworkDhcpAgentBinding)
            .all())
        self.assertEqual(1, len(results))

    def test_auto_schedule_networks_network_already_scheduled(self):
        plugin = mock.MagicMock()
        plugin.get_subnets.return_value = [{"network_id": self.network_id,
                                            "enable_dhcp": True}]
        agents = self._get_agents(['host-a'])
        self._save_agents(agents)
        scheduler = dhcp_agent_scheduler.ChanceScheduler()
        self._test_schedule_bind_network(agents, self.network_id)
        self.assertTrue(scheduler.auto_schedule_networks(plugin,
                                                         self.ctx, "host-a"))
        results = (
            self.ctx.session.query(agentschedulers_db.NetworkDhcpAgentBinding)
            .all())
        self.assertEqual(1, len(results))


class TestNetworksFailover(TestDhcpSchedulerBaseTestCase,
                           sched_db.DhcpAgentSchedulerDbMixin):
    def test_reschedule_network_from_down_agent(self):
        plugin = mock.MagicMock()
        plugin.get_subnets.return_value = [{"network_id": self.network_id,
                                            "enable_dhcp": True}]
        agents = self._create_and_set_agents_down(['host-a', 'host-b'], 1)
        self._test_schedule_bind_network([agents[0]], self.network_id)
        self._save_networks(["foo-network-2"])
        self._test_schedule_bind_network([agents[1]], "foo-network-2")
        with contextlib.nested(
            mock.patch.object(self, 'remove_network_from_dhcp_agent'),
            mock.patch.object(self, 'schedule_network',
                              return_value=[agents[1]]),
            mock.patch.object(self, 'get_network', create=True,
                              return_value={'id': self.network_id})
        ) as (rn, sch, getn):
            notifier = mock.MagicMock()
            self.agent_notifiers[constants.AGENT_TYPE_DHCP] = notifier
            self.remove_networks_from_down_agents()
            rn.assert_called_with(mock.ANY, agents[0].id, self.network_id)
            sch.assert_called_with(mock.ANY, {'id': self.network_id})
            notifier.network_added_to_agent.assert_called_with(
                mock.ANY, self.network_id, agents[1].host)

    def test_reschedule_network_from_down_agent_failed(self):
        plugin = mock.MagicMock()
        plugin.get_subnets.return_value = [{"network_id": self.network_id,
                                            "enable_dhcp": True}]
        agents = self._create_and_set_agents_down(['host-a'], 1)
        self._test_schedule_bind_network([agents[0]], self.network_id)
        with contextlib.nested(
            mock.patch.object(self, 'remove_network_from_dhcp_agent'),
            mock.patch.object(self, 'schedule_network',
                              return_value=None),
            mock.patch.object(self, 'get_network', create=True,
                              return_value={'id': self.network_id})
        ) as (rn, sch, getn):
            notifier = mock.MagicMock()
            self.agent_notifiers[constants.AGENT_TYPE_DHCP] = notifier
            self.remove_networks_from_down_agents()
            rn.assert_called_with(mock.ANY, agents[0].id, self.network_id)
            sch.assert_called_with(mock.ANY, {'id': self.network_id})
            self.assertFalse(notifier.network_added_to_agent.called)

    def test_filter_bindings(self):
        bindings = [
            sched_db.NetworkDhcpAgentBinding(network_id='foo1',
                                             dhcp_agent={'id': 'id1'}),
            sched_db.NetworkDhcpAgentBinding(network_id='foo2',
                                             dhcp_agent={'id': 'id1'}),
            sched_db.NetworkDhcpAgentBinding(network_id='foo3',
                                             dhcp_agent={'id': 'id2'}),
            sched_db.NetworkDhcpAgentBinding(network_id='foo4',
                                             dhcp_agent={'id': 'id2'})]
        with mock.patch.object(self, '_agent_starting_up',
                               side_effect=[True, False]):
            res = [b for b in self._filter_bindings(None, bindings)]
            # once per each agent id1 and id2
            self.assertEqual(2, len(res))
            res_ids = [b.network_id for b in res]
            self.assertIn('foo3', res_ids)
            self.assertIn('foo4', res_ids)
