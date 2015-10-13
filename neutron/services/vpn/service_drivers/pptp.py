# Copyright (c) 2015 Eayun, Inc.
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

from neutron.common import rpc as n_rpc
from neutron.openstack.common import log as logging
from neutron.services.vpn.common import topics
from neutron.services.vpn import service_drivers
from neutron.plugins.common import constants


LOG = logging.getLogger(__name__)

PPTP = 'pptp'
BASE_PPTP_VERSION = '1.0'


class PPTPVpnDriverCallBack(n_rpc.RpcCallback):
    """Callback for PPTPVpnDriver rpc."""
    RPC_API_VERSION = BASE_PPTP_VERSION

    def __init__(self, driver):
        super(PPTPVpnDriverCallBack, self).__init__()
        self.driver = driver

    def report_status(self, context, host,
                      pptp_processes_status, credentials, updated_ports):
        plugin = self.driver.service_plugin
        provider = None
        for p in plugin.drivers:
            if plugin.drivers[p] == self.driver:
                provider = p
                break
        plugin.update_pptp_status_by_agent(
            context, host, pptp_processes_status, credentials, updated_ports,
            provider)


class PPTPVpnAgentApi(n_rpc.RpcProxy, n_rpc.RpcCallback):
    """Agent RPC API for PPTPVPNAgent"""
    RPC_API_VERSION = BASE_PPTP_VERSION

    def __init__(self, topic, default_version):
        self.topic = topic
        super(PPTPVpnAgentApi, self).__init__(topic, default_version)

    def _agent_notification(self, context, method, host,
                            version=None, **kwargs):
        LOG.debug(
            _('Notify agent at %(topic)s.%(host)s the message '
              '%(method)s %(args)s'),
            {'topic': self.topic, 'host': host,
             'method': method, 'args': kwargs})
        self.cast(context,
                  self.make_msg(method, **kwargs),
                  version=version or self.RPC_API_VERSION,
                  topic='%s.%s' % (self.topic, host))

    def start_vpnservice(self, context, host, **kwargs):
        self._agent_notification(context, 'start_vpnservice', host, **kwargs)

    def stop_vpnservice(self, context, host, **kwargs):
        self._agent_notification(context, 'stop_vpnservice', host, **kwargs)

    def add_pptp_credential(self, context, host, **kwargs):
        self._agent_notification(
            context, 'add_pptp_credential', host, **kwargs)

    def update_pptp_credential(self, context, host, **kwargs):
        self._agent_notification(
            context, 'update_pptp_credential', host, **kwargs)

    def delete_pptp_credential(self, context, host, **kwargs):
        self._agent_notification(
            context, 'delete_pptp_credential', host, **kwargs)

    def sync_from_server(self, context, host, **kwargs):
        self._agent_notification(
            context, 'sync_from_server', host, **kwargs)


class PPTPVPNDriver(service_drivers.VpnDriver):
    """VPN Service Driver class for PPTP."""

    def __init__(self, service_plugin):
        super(PPTPVPNDriver, self).__init__(service_plugin)
        self.endpoints = [PPTPVpnDriverCallBack(self)]
        self.conn = n_rpc.create_connection(new=True)
        self.conn.create_consumer(
            topics.PPTP_DRIVER_TOPIC, self.endpoints, fanout=False)
        self.conn.consume_in_threads()
        self.agent_rpc = PPTPVpnAgentApi(
            topics.PPTP_AGENT_TOPIC, BASE_PPTP_VERSION)

    @property
    def service_type(self):
        return PPTP

    def _get_hosts_for_vpnservice(self, context, vpnservice):
        admin_context = context.is_admin and context or context.elevated()
        l3_agents = self.l3_plugin.get_l3_agents_hosting_routers(
            admin_context, [vpnservice['router_id']],
            admin_state_up=True,
            active=True)
        return [l3_agent.host for l3_agent in l3_agents]

    def _start_vpnservice(self, context, vpnservice):
        subnet = self.core_plugin.get_subnet(context, vpnservice['subnet_id'])
        localip = subnet['gateway_ip']
        for host in self._get_hosts_for_vpnservice(context, vpnservice):
            self.agent_rpc.start_vpnservice(
                context, host, vpnservice=vpnservice, localip=localip)

    def _stop_vpnservice(self, context, vpnservice, delete=False):
        for host in self._get_hosts_for_vpnservice(context, vpnservice):
            self.agent_rpc.stop_vpnservice(
                context, host, vpnservice=vpnservice, delete=delete)

    def create_vpnservice(self, context, vpnservice):
        self.service_plugin.set_vpnservice_status(
            context, vpnservice['id'], constants.DOWN)
        self._start_vpnservice(context, vpnservice)

    def update_vpnservice(self, context, old_vpnservice, vpnservice):
        if old_vpnservice['admin_state_up'] != vpnservice['admin_state_up']:
            if vpnservice['admin_state_up']:
                self._start_vpnservice(context, vpnservice)
            else:
                self._stop_vpnservice(context, vpnservice)

    def delete_vpnservice(self, context, vpnservice):
        if vpnservice['admin_state_up']:
            self._stop_vpnservice(context, vpnservice, delete=True)

    def sync_from_server(self, context, host, vpnservices, credentials, ports):
        self.agent_rpc.sync_from_server(
            context, host,
            vpnservices=vpnservices, credentials=credentials, ports=ports
        )
