# Copyright (c) 2017 Eayun, Inc.
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

from oslo.config import cfg

from neutron.common import constants
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.common import utils
from neutron.db import es_acl_db
from neutron.openstack.common import log as logging
from neutron.services.es_acl.common import topics as es_acl_topics

LOG = logging.getLogger(__name__)


class EsAclL3Callbacks(n_rpc.RpcCallback):
    RPC_API_VERSION = '1.0'

    def __init__(self, plugin):
        super(EsAclL3Callbacks, self).__init__()
        self.plugin = plugin

    def get_es_acl_by_routers(self, context, router_ids):
        return self.plugin.get_es_acl_by_routers(context, router_ids)

    def internal_port_added_to_router(self, context,
                                      router_id, subnet_id, port_id):
        return self.plugin.internal_port_added_to_router(
            context, router_id, subnet_id, port_id)


class EsAclL3AgentApi(n_rpc.RpcProxy):
    API_VERSION = '1.0'

    def __init__(self, plugin, host):
        super(EsAclL3AgentApi, self).__init__(
            topics.L3_AGENT, self.API_VERSION)
        self.plugin = plugin
        self.host = host

    def _agent_notify_routers_update(self, context, routers):
        adminContext = context.is_admin and context or context.elevated()

        routers_by_host = {}
        for router_id in routers:
            l3_agents = self.plugin._l3_plugin.get_l3_agents_hosting_routers(
                adminContext, [router_id], admin_state_up=True, active=True)
            for l3_agent in l3_agents:
                host = l3_agent['host']
                host_routers = routers_by_host.get(host, [])
                host_routers.append(router_id)
                routers_by_host[host] = host_routers

        for host, host_routers in routers_by_host.items():
            self.cast(context,
                      self.make_msg('routers_updated', routers=host_routers),
                      topic='%s.%s' % (self.topic, host))

    def _fanout_notify_routers_update(self, context, routers):
        self.fanout_cast(
            context, self.make_msg('routers_updated', routers=routers))

    def notify_routers_update(self, context, routers):
        if utils.is_extension_supported(
            self.plugin._l3_plugin, constants.L3_AGENT_SCHEDULER_EXT_ALIAS
        ):
            self._agent_notify_routers_update(context, routers)
        else:
            self._fanout_notify_routers_update(context, routers)


class EsAclL3Plugin(es_acl_db.EsAclDbMixin):

    supported_extension_aliases = ['es-acl']

    def __init__(self):
        self.endpoints = [EsAclL3Callbacks(self)]
        self.conn = n_rpc.create_connection(new=True)
        self.conn.create_consumer(
            es_acl_topics.ES_ACL_PLUGIN, self.endpoints, fanout=False)
        self.conn.consume_in_threads()

        self.agent_rpc = EsAclL3AgentApi(self, cfg.CONF.host)

    def bind_subnets(self, context, es_acl_id, subnet_ids):
        bound_subnets, affected_routers = super(
            EsAclL3Plugin, self
        ).bind_subnets(context, es_acl_id, subnet_ids)

        self.agent_rpc.notify_routers_update(context, affected_routers)

        return bound_subnets

    def unbind_subnets(self, context, es_acl_id, subnet_ids):
        unbound_subnets, affected_routers = super(
            EsAclL3Plugin, self
        ).unbind_subnets(context, es_acl_id, subnet_ids)

        self.agent_rpc.notify_routers_update(context, affected_routers)

        return unbound_subnets

    def create_es_acl_rule(self, context, es_acl_rule):
        rule = super(
            EsAclL3Plugin, self
        ).create_es_acl_rule(context, es_acl_rule)

        routers = self.get_related_routers(context, rule['acl_id'])
        self.agent_rpc.notify_routers_update(context, routers)

        return rule

    @staticmethod
    def _test_rule_changed(old_rule, rule):
        changed_columns = set(
            key for key in rule.keys() if old_rule[key] != rule[key])
        changed_columns.discard('name')
        return len(changed_columns) > 0

    def update_es_acl_rule(self, context, es_acl_rule_id, es_acl_rule):
        old_rule = self.get_es_acl_rule(context, es_acl_rule_id)
        rule = super(
            EsAclL3Plugin, self
        ).update_es_acl_rule(context, es_acl_rule_id, es_acl_rule)

        rule_changed = self._test_rule_changed(old_rule, rule)
        if rule_changed:
            routers = self.get_related_routers(context, rule['acl_id'])
            if old_rule['acl_id'] != rule['acl_id']:
                routers = routers.union(
                    self.get_related_routers(context, old_rule['acl_id']))
            self.agent_rpc.notify_routers_update(context, routers)
        else:
            LOG.warn('Nothing changed for ACL rule %(acl_rule_id)s.',
                     {'acl_rule_id': es_acl_rule_id})

        return rule

    def delete_es_acl_rule(self, context, es_acl_rule_id):
        rule = self.get_es_acl_rule(context, es_acl_rule_id)
        super(EsAclL3Plugin, self).delete_es_acl_rule(context, es_acl_rule_id)

        routers = self.get_related_routers(context, rule['acl_id'])
        self.agent_rpc.notify_routers_update(context, routers)
