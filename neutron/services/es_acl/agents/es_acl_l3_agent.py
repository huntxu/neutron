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

from neutron.common import rpc as n_rpc
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants

from neutron.services.es_acl.common import topics as es_acl_topics

LOG = logging.getLogger(__name__)

EsAclOpts = [
    cfg.BoolOpt('enabled', default=False, help="Enable EayunStack ACL"),
]
cfg.CONF.register_opts(EsAclOpts, 'es_acl')

ES_ACL_INFO_KEY = 'ES_ACL'
ES_ACL_CHAIN_PREFIX = 'acl-'

INGRESS_DIRECTION = 'ingress'
EGRESS_DIRECTION = 'egress'

CHAIN_NAME_PREFIX = {INGRESS_DIRECTION: 'i',
                     EGRESS_DIRECTION: 'o'}

# ACL applied on internal ports.
IPTABLES_DIR = {INGRESS_DIRECTION: '-o',
                EGRESS_DIRECTION: '-i'}
PORT_VALID_PROTOCOLS = (
    6,  # TCP
    17,  # UDP
    33,  # DCCP
    132,  # SCTP
    # 136,  # UDPLite, not yet supported by iptables v1.4.21
)
ACTIONS = {'allow': 'ACCEPT',
           'deny': 'DROP'}


class EsAclPluginApi(n_rpc.RpcProxy):
    API_VERSION = '1.0'

    def __init__(self):
        super(EsAclPluginApi, self).__init__(
            es_acl_topics.ES_ACL_PLUGIN, self.API_VERSION)

    def get_es_acl_by_routers(self, context, router_ids):
        return self.call(
            context,
            self.make_msg('get_es_acl_by_routers', router_ids=router_ids))

    def internal_port_added_to_router(self, context,
                                      router_id, subnet_id, port_id):
        return self.call(
            context,
            self.make_msg(
                'internal_port_added_to_router',
                router_id=router_id, subnet_id=subnet_id, port_id=port_id))


def _run_if_enabled(switch_name, default_ret=None):
    def _decorator(func):
        def _func(*args, **kwargs):
            if getattr(args[0], switch_name, False):
                return func(*args, **kwargs)
            else:
                return default_ret
        return _func
    return _decorator


class EsAclL3AgentMixin(object):

    def init_es_acl(self, conf):
        self.es_acl_enabled = cfg.CONF.es_acl.enabled
        if self.neutron_service_plugins is not None:
            plugin_configured = (
                constants.ES_ACL in self.neutron_service_plugins)
            if plugin_configured and not self.es_acl_enabled:
                LOG.error('EayunStack ACL plugin is configured in the server '
                          'side, but EayunStack ACL is disabled in L3 agent.')
            self.es_acl_enabled = self.es_acl_enabled and plugin_configured
        if self.es_acl_enabled:
            self.es_acl_plugin_api = EsAclPluginApi()

    @property
    def empty_acl_info(self):
        return {'rules': {}, 'ports': {}}

    @_run_if_enabled('es_acl_enabled')
    def es_acl_update_router_info(self, routers):
        router_ids = [router['id'] for router in routers]
        LOG.debug(
            'Getting EayunStack ACL information for routers %s.', router_ids)
        acl_by_routers = self.es_acl_plugin_api.get_es_acl_by_routers(
            self.context, router_ids)
        LOG.debug('Get EayunStack ACL information: %r.' % acl_by_routers)
        acls = acl_by_routers['acls']
        acl_routers = acl_by_routers['routers']

        for router in routers:
            router_id = router['id']
            acl_info = self.empty_acl_info
            for acl_id, ports in acl_routers.get(router_id, {}).items():
                acl_info['ports'][acl_id] = set(ports)
            related_acl_ids = set(acl_info['ports'].keys())
            acl_info['rules'] = {
                acl_id: acls.get(acl_id)
                for acl_id in related_acl_ids
            }
            LOG.debug('EayunStack ACL information for router %(router_id)s: '
                      '%(info)r', {'router_id': router_id, 'info': acl_info})
            router[ES_ACL_INFO_KEY] = acl_info

    @staticmethod
    def _get_es_acl_chain_name(direction, acl_id):
        return "%s%s%s" % (
            ES_ACL_CHAIN_PREFIX, CHAIN_NAME_PREFIX[direction], acl_id)

    @staticmethod
    def _drop_invalid_packets_rule():
        return '-m state --state INVALID -j DROP'

    @staticmethod
    def _allow_established_rule():
        return '-m state --state ESTABLISHED,RELATED -j ACCEPT'

    @staticmethod
    def _default_drop_all_rule():
        return '-j DROP'

    @staticmethod
    def _translate_acl_rule(rule):
        parts = []
        if rule['protocol']:
            parts.append('-p %s' % rule['protocol'])
        if rule['source_ip_address']:
            parts.append('-s %s' % rule['source_ip_address'])
        if rule['destination_ip_address']:
            parts.append('-d %s' % rule['destination_ip_address'])
        if rule['protocol'] in PORT_VALID_PROTOCOLS:
            if rule['source_port']:
                parts.append('--sport %s' % rule['source_port'])
            if rule['destination_port']:
                parts.append('--dport %s' % rule['destination_port'])
        parts.append('-j %s' % ACTIONS[rule['action']])
        return ' '.join(parts)

    @_run_if_enabled('es_acl_enabled')
    def es_acl_process_router(self, ri):
        # Called with ri.iptables_manager.iptables_apply_deferred = True
        im = ri.iptables_manager
        table = im.ipv4['filter']
        acl_info = ri.router.get(ES_ACL_INFO_KEY, self.empty_acl_info)

        LOG.debug('Processing EayunStack ACL information for router '
                  '%(router_id)s: %(info)r.',
                  {'router_id': ri.router_id, 'info': acl_info})
        # Clear all the chains
        acl_chains = set(
            chain for chain in table.chains
            if chain.startswith(ES_ACL_CHAIN_PREFIX))
        for chain in acl_chains:
            table.ensure_remove_chain(chain)

        # Build acl rules
        for acl_id, acl_rules in acl_info['rules'].items():
            ports = acl_info['ports'].get(acl_id, set())
            for direction in (INGRESS_DIRECTION, EGRESS_DIRECTION):
                chain = self._get_es_acl_chain_name(direction, acl_id)
                table.add_chain(chain)

                rules = [self._drop_invalid_packets_rule(),
                         self._allow_established_rule()]
                rules += [
                    self._translate_acl_rule(rule)
                    for rule in acl_rules.get(direction, [])
                ]
                rules.append(self._default_drop_all_rule())
                for rule in rules:
                    table.add_rule(chain, rule)

                for port_id in ports:
                    rule = '%s %s -j $%s' % (
                        IPTABLES_DIR[direction],
                        self.get_internal_device_name(port_id),
                        chain
                    )
                    table.add_rule('FORWARD', rule)

        im.apply()

    @_run_if_enabled('es_acl_enabled')
    def es_acl_remove_from_router_info(self, ri):
        ri.router[ES_ACL_INFO_KEY] = self.empty_acl_info

    @_run_if_enabled('es_acl_enabled')
    def es_acl_internal_network_added(self, ri, port):
        acl_info = ri.router.get(ES_ACL_INFO_KEY, self.empty_acl_info)

        router_id = ri.router_id
        subnet_id = port['subnet']['id']
        port_id = port['id']
        try:
            acls = self.es_acl_plugin_api.internal_port_added_to_router(
                self.context, router_id, subnet_id, port_id)
            LOG.debug(
                'Get EayunStack ACL information for subnet %(subnet_id)s '
                'newly added to router %(router_id)s: %(info)r.',
                {'subnet_id': subnet_id, 'router_id': router_id, 'info': acls})
        except Exception:
            LOG.exception(
                'Failed to fetch EayunStack ACL information for '
                'subnet %(subnet_id)s newly added to router %(router_id)s.',
                {subnet_id: subnet_id, router_id: router_id})
            return

        for acl_id, rules in acls.items():
            if acl_id not in acl_info['rules']:
                acl_info['rules']['acl_id'] = rules
            if acl_id not in acl_info['ports']:
                acl_info['ports'][acl_id] = set()
            acl_info['ports'][acl_id].add(port_id)
