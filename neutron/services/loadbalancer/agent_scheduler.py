# Copyright (c) 2013 OpenStack Foundation.
# All Rights Reserved.
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

import random

import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm import exc
from sqlalchemy.orm import joinedload

from neutron.common import constants
from neutron.db import agents_db
from neutron.db import agentschedulers_db
from neutron.db import model_base
from neutron.db.loadbalancer import loadbalancer_db as lb_db
from neutron.extensions import lbaas_agentscheduler
from neutron.extensions import loadbalancer
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)


class PoolLoadbalancerAgentBinding(model_base.BASEV2):
    """Represents binding between neutron loadbalancer pools and agents."""

    pool_id = sa.Column(sa.String(36),
                        sa.ForeignKey("pools.id", ondelete='CASCADE'),
                        primary_key=True)
    agent = orm.relation(agents_db.Agent)
    agent_id = sa.Column(sa.String(36), sa.ForeignKey("agents.id",
                                                      ondelete='CASCADE'),
                         nullable=False)


class LbaasAgentSchedulerDbMixin(agentschedulers_db.AgentSchedulerDbMixin,
                                 lbaas_agentscheduler
                                 .LbaasAgentSchedulerPluginBase):

    def get_lbaas_agent_hosting_pool(self, context, pool_id, active=None):
        query = context.session.query(PoolLoadbalancerAgentBinding)
        query = query.options(joinedload('agent'))
        binding = query.get(pool_id)

        if (binding and self.is_eligible_agent(
                active, binding.agent)):
            return {'agent': self._make_agent_dict(binding.agent)}

    def get_lbaas_agents(self, context, active=None, filters=None):
        query = context.session.query(agents_db.Agent)
        query = query.filter_by(agent_type=constants.AGENT_TYPE_LOADBALANCER)
        if active is not None:
            query = query.filter_by(admin_state_up=active)
        if filters:
            for key, value in filters.iteritems():
                column = getattr(agents_db.Agent, key, None)
                if column:
                    query = query.filter(column.in_(value))

        return [agent
                for agent in query
                if self.is_eligible_agent(active, agent)]

    def list_pools_on_lbaas_agent(self, context, id):
        query = context.session.query(PoolLoadbalancerAgentBinding.pool_id)
        query = query.filter_by(agent_id=id)
        pool_ids = [item[0] for item in query]
        if pool_ids:
            return {'pools': self.get_pools(context, filters={'id': pool_ids})}
        else:
            return {'pools': []}

    def get_lbaas_agent_candidates(self, device_driver, active_agents):
        candidates = []
        for agent in active_agents:
            agent_conf = self.get_configuration_dict(agent)
            if device_driver in agent_conf['device_drivers']:
                candidates.append(agent)
        return candidates

    def update_lbaas_agent_hosting_pool(self, context, id, agent):
        query = context.session.query(PoolLoadbalancerAgentBinding)
        query = query.filter_by(pool_id=id)
        with context.session.begin(subtransactions=True):
            query[0].agent = agent
            context.session.flush()

    def _get_same_pools_by_pool_id(self, context, pool_id):
        pool = self.get_pool(context, pool_id)
        pools = []
        with context.session.begin(subtransactions=True):
            try:
                vip = self._get_resource(context, lb_db.Vip, pool['vip_id'])
                pools = [_vip.pool_id for _vip in vip.port.vips]
            except loadbalancer.VipNotFound:
                # in this case, pool not bound to a vip
                pass
        return pools

    def _check_pool_can_be_bound_to_agent(self, context, pool_id, agent_id):
        # check pool if has added
        query = context.session.query(PoolLoadbalancerAgentBinding)
        query = query.filter(PoolLoadbalancerAgentBinding.pool_id == pool_id)
        try:
            binding = query.one()
            raise loadbalancer.PoolHasBoundToAgent(
                pool=pool_id,
                agent=binding.agent_id)
        except exc.NoResultFound:
            # not add
            pass

        # check if same pools has bound to same agent
        same_pools = self._get_same_pools_by_pool_id(context, pool_id)
        if len(same_pools) > 1:
            query = context.session.query(PoolLoadbalancerAgentBinding)
            query = query.filter(
                PoolLoadbalancerAgentBinding.pool_id.in_(same_pools))

            agents = [_q.agent_id for _q in query]
            if agents and (set([agent_id]) != set(agents)):
                raise loadbalancer.PoolsBoundToDifferentAgents(
                    pools=same_pools,
                    agents=agents)

    def _bind_pool(self, context, agent_id, pool_id):
        with context.session.begin(subtransactions=True):
            # check if pool could add to the agent
            self._check_pool_can_be_bound_to_agent(context,
                                                   pool_id, agent_id)

            binding = PoolLoadbalancerAgentBinding()
            binding.agent_id = agent_id
            binding.pool_id = pool_id
            context.session.add(binding)

    def add_pool_to_lbaas_agent(self, context, agent_id, pool_id):
        agent = self._get_agent(context, agent_id)
        pool = self.get_pool(context, pool_id)
        self._bind_pool(context, agent_id, pool_id)
        driver = self._get_driver_for_pool(context, pool_id)
        driver.add_pool_to_agent(context, pool, agent)

    def _unbind_pool(self, context, agent, pool):
        with context.session.begin(subtransactions=True):
            query = context.session.query(PoolLoadbalancerAgentBinding)
            query = query.filter(
                PoolLoadbalancerAgentBinding.pool_id == pool,
                PoolLoadbalancerAgentBinding.agent_id == agent)
            try:
                binding = query.one()
            except exc.NoResultFound:
                raise loadbalancer.PoolNotBoundToAgent(pool=pool, agent=agent)
            context.session.delete(binding)

    def remove_pool_from_lbaas_agent(self, context, agent_id, pool_id):
        # unbound the pool
        self._unbind_pool(context, agent_id, pool_id)
        # remove from agent
        agent = self._get_agent(context, agent_id)
        pool = self.get_pool(context, pool_id)
        driver = self._get_driver_for_pool(context, pool_id)
        driver.remove_pool_from_agent(context, pool, agent)
        LOG.info(_('Remove pool %(pool)s from agent %(agent)s'),
                 {'pool': pool_id, 'agent': agent_id})


class ChanceScheduler(object):
    """Allocate a loadbalancer agent for a vip in a random way."""

    def schedule(self, plugin, context, pool, device_driver):
        """Schedule the pool to an active loadbalancer agent if there
        is no enabled agent hosting it.
        """
        with context.session.begin(subtransactions=True):
            lbaas_agent = plugin.get_lbaas_agent_hosting_pool(
                context, pool['id'])
            if lbaas_agent:
                LOG.debug(_('Pool %(pool_id)s has already been hosted'
                            ' by lbaas agent %(agent_id)s'),
                          {'pool_id': pool['id'],
                           'agent_id': lbaas_agent['id']})
                return

            active_agents = plugin.get_lbaas_agents(context, active=True)
            if not active_agents:
                LOG.warn(_('No active lbaas agents for pool %s'), pool['id'])
                return

            candidates = plugin.get_lbaas_agent_candidates(device_driver,
                                                           active_agents)
            if not candidates:
                LOG.warn(_('No lbaas agent supporting device driver %s'),
                         device_driver)
                return

            chosen_agent = random.choice(candidates)
            binding = PoolLoadbalancerAgentBinding()
            binding.agent = chosen_agent
            binding.pool_id = pool['id']
            context.session.add(binding)
            LOG.debug(_('Pool %(pool_id)s is scheduled to '
                        'lbaas agent %(agent_id)s'),
                      {'pool_id': pool['id'],
                       'agent_id': chosen_agent['id']})
            return chosen_agent
