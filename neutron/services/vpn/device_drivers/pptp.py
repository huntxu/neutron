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

import os
import shutil

import jinja2
from oslo.config import cfg
from oslo import messaging

from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
from neutron.common import rpc as n_rpc
from neutron import context
from neutron.openstack.common import lockutils
from neutron.openstack.common import log as logging
from neutron.openstack.common import loopingcall
from neutron.services.vpn.common import topics
from neutron.services.vpn import device_drivers

LOG = logging.getLogger(__name__)
TEMPLATE_PATH = os.path.dirname(__file__)

pptp_opts = [
    cfg.StrOpt(
        'chap_secrets',
        default='/etc/ppp/chap-secrets',
        help=_('Location to store pptp chap secrets')),
    cfg.StrOpt(
        'config_base_dir',
        default='$state_path/pptp',
        help=_('Location to store pptp server config files')),
    cfg.StrOpt(
        'ppp_options_file_template',
        default=os.path.join(
            TEMPLATE_PATH,
            'template/pptp/ppp_options.template'),
        help=_('Template file for pppd options')),
    cfg.IntOpt(
        'pptp_status_check_interval',
        default=60,
        help=_("Interval for checking pptp vpn services status"))
]

cfg.CONF.register_opts(pptp_opts, 'pptp')

JINJA_ENV = None


def _get_template(template_file):
    global JINJA_ENV
    if not JINJA_ENV:
        templateLoader = jinja2.FileSystemLoader(searchpath="/")
        JINJA_ENV = jinja2.Environment(loader=templateLoader)
    return JINJA_ENV.get_template(template_file)


class PPTPProcess(object):
    binary = 'pptpd'

    def __init__(self, conf, root_helper, process_id, localip, namespace):
        self.conf = conf
        self.root_helper = root_helper
        self.id = process_id
        self.namespace = namespace
        self.localip = localip
        self.ports = {}
        self.config_dir = os.path.join(cfg.CONF.pptp.config_base_dir, self.id)
        self.ppp_options_file = os.path.join(self.config_dir, 'ppp_options')
        self.connections_dir = os.path.join(self.config_dir, 'connections')
        self.pid_file = os.path.join(self.config_dir, 'pid')
        self.ensure_config()
        self.enabled = False

    def ensure_config(self):
        self.remove_config()
        os.makedirs(self.config_dir, 0o755)
        os.makedirs(self.connections_dir, 0o755)

        ppp_options_file_template = _get_template(
            self.conf.pptp.ppp_options_file_template)
        utils.replace_file(
            self.ppp_options_file,
            ppp_options_file_template.render(
                {'localip': self.localip, 'name': self.id, 'ipparam': self.id}
            )
        )

    def remove_config(self):
        shutil.rmtree(self.config_dir, ignore_errors=True)

    def _execute(self, cmd, check_exit_code=True, addl_env={}):
        ip_wrapper = ip_lib.IPWrapper(self.root_helper, self.namespace)
        return ip_wrapper.netns.execute(cmd, check_exit_code=check_exit_code,
                                        addl_env=addl_env)

    def start(self):
        self.enabled = True
        if not self.active:
            self._execute([
                self.binary,
                '--noipparam',
                '--option', self.ppp_options_file,
                '--pidfile', self.pid_file,
                '--delegate'
            ])

    def stop(self):
        self.enabled = False
        if self.active:
            self._execute(['kill', '-9', '--', '-%s' % self.pid])

    def update_ports_status(self):
        changed = {}
        connected_ips = self.connected_ips
        for port_id, port in self.ports.iteritems():
            port['was_connected'] = port['connected']
            port['connected'] = port['ip'] in connected_ips
            if port['was_connected'] != port['connected']:
                changed[port_id] = port['connected']
        return changed

    def add_port(self, port_id, port_ip, credential_id):
        port = {'ip': port_ip,
                'credential_id': credential_id,
                'was_connected': None,
                'connected': None}
        self.ports[port_id] = port

    def disconnect_port(self, port_id):
        remote_ip = self.ports[port_id]['ip']
        if remote_ip in self.connected_ips:
            connection_pid = os.path.join(self.connections_dir, remote_ip)
            try:
                with open(connection_pid, 'r') as f:
                    pid = int(f.readline())
            except (IOError, ValueError):
                return
            self._execute(['kill', pid])

    def del_port(self, port_id):
        self.disconnect_port(port_id)
        del self.ports[port_id]

    @property
    def active(self):
        pid = self.pid
        if pid is None:
            return False

        cmdline = '/proc/%s/cmdline' % pid
        try:
            with open(cmdline, 'r') as f:
                return self.ppp_options_file in f.readline()
        except IOError:
            return False

    @property
    def pid(self):
        try:
            with open(self.pid_file, 'r') as f:
                return int(f.readline())
        except (IOError, ValueError):
            return None

    @property
    def connected_ips(self):
        try:
            return os.listdir(self.connections_dir)
        except OSError:
            # This should not happen
            return []


class PPTPVpnDriverApi(n_rpc.RpcProxy):
    """PPTPVpnDriver RPC api."""
    RPC_API_VERSION = '1.0'

    def report_status(self, context, host,
                      pptp_processes_status, credentials, updated_ports):
        self.cast(
            context,
            self.make_msg(
                'report_status',
                host=host,
                pptp_processes_status=pptp_processes_status,
                credentials=credentials,
                updated_ports=updated_ports,
            ),
            version=self.RPC_API_VERSION
        )


class PPTPDriver(device_drivers.DeviceDriver):

    RPC_API_VERSION = '1.0'

    target = messaging.Target(version=RPC_API_VERSION)

    def __init__(self, agent, host):
        self.agent = agent
        self.conf = self.agent.conf
        self.root_helper = self.agent.root_helper
        self.host = host
        self.conn = n_rpc.create_connection(new=True)
        self.context = context.get_admin_context_without_session()
        self.topic = topics.PPTP_AGENT_TOPIC
        node_topic = '%s.%s' % (self.topic, self.host)

        self.processes = {}
        self.credentials = {}

        self.endpoints = [self]
        self.conn.create_consumer(node_topic, self.endpoints, fanout=False)
        self.conn.consume_in_threads()
        self.agent_rpc = PPTPVpnDriverApi(
            topics.PPTP_DRIVER_TOPIC, self.RPC_API_VERSION)
        self.process_status_check = loopingcall.FixedIntervalLoopingCall(
            self.check_and_report, self.context)
        self.process_status_check.start(
            interval=self.conf.pptp.pptp_status_check_interval)

    def check_and_report(self, context):
        pptp_processes_status = {}
        updated_ports = {}

        for process_id, process in self.processes.iteritems():
            # Try to start enabled processes that are not running
            # or unexpected dead
            if process.enabled and not process.active:
                process.start()

            # Check port connection status change
            updated_ports.update(process.update_ports_status())

            process_status = {
                'enabled': process.enabled,
                'active': process.active,
                'ports': process.ports.keys()
            }
            pptp_processes_status[process_id] = process_status

        self.agent_rpc.report_status(
            context, self.host,
            pptp_processes_status, self.credentials, updated_ports)

    def start_process(self, router_id, process_id, localip, enabled):
        namespace = self.agent.get_namespace(router_id)
        if not namespace:
            LOG.warn(
                _('Namespace not ready for vpnservice %(vpnservice_id)s'),
                {'vpnservice_id': process_id})
            return
        process = self.processes.get(process_id)
        if not process:
            process = PPTPProcess(
                self.conf, self.root_helper, process_id, localip, namespace)
            self.processes[process_id] = process
        if enabled:
            process.start()

    def stop_process(self, process_id, delete=True):
        process = self.processes.get(process_id)
        if process:
            process.stop()
            if delete:
                process.remove_config()
                del self.processes[process_id]

    def start_vpnservice(self, context, vpnservice, localip):
        router_id = vpnservice['router_id']
        process_id = vpnservice['id']
        enabled = vpnservice['admin_state_up']
        if not localip:
            LOG.warn(
                _('PPTP VPN service localip is None, so vpnservice '
                  'so vpnservice %(vpnservice_id) cannot be started. '
                  'Maybe connected subnet does not have a valid gateway ip?'),
                {'vpnservice_id': vpnservice['id']})
        else:
            self.start_process(router_id, process_id, localip, enabled)

    def stop_vpnservice(self, context, vpnservice, delete):
        process_id = vpnservice['id']
        self.stop_process(process_id, delete=delete)

    @lockutils.synchronized('pptp-driver', 'neutron-')
    def sync_from_server(self, context, vpnservices, credentials, ports):
        LOG.debug(
            _('Syncing from server: vpnservices: %(vpnservices)s, '
              'credentials: %(credentials)s, '
              'ports: %(ports)s.'),
            {'vpnservices': vpnservices,
             'credentials': credentials,
             'ports': ports})
        for vpnservice in vpnservices['added']:
            localip = vpnservice.pop('localip')
            self.start_vpnservice(context, vpnservice, localip)
        for vpnservice_id in vpnservices['enabled']:
            process = self.processes.get(vpnservice_id)
            if process:
                process.start()
        for vpnservice_id in vpnservices['disabled']:
            self.stop_process(vpnservice_id, deleted=False)
        for vpnservice_id in vpnservices['deleted']:
            self.stop_process(vpnservice_id)

        for credential in credentials['added']:
            self.credentials[credential['id']] = {
                'username': credential['username'],
                'password': credential['password']
            }
        for credential_id in credentials['deleted']:
            if credential_id in self.credentials:
                del self.credentials[credential_id]
        for credential_id, password in credentials['updated'].iteritems():
            if credential_id in self.credentials:
                self.credentials[credential_id]['password'] = password

        for port_id, port in ports['added']:
            process_id = port['vpnservice_id']
            port_ip = port['ip']
            credential_id = port['credential_id']

            process = self.processes.get(process_id)
            if process:
                process.add_port(port_id, port_ip, credential_id)

        to_disconnect = {}
        to_delete = {}
        credential_items = []

        for process_id, process in self.processes.iteritems():
            for port_id, port in process.ports.iteritems():
                if port_id in ports['deleted']:
                    if process_id in to_delete:
                        to_delete[process_id].append(port_id)
                    else:
                        to_delete[process_id] = [port_id]
                    continue
                elif (
                    port['credential_id'] in credentials['updated'] and
                    port_id not in ports['added']
                ):
                    if process_id in to_disconnect:
                        to_disconnect[process_id].append(port_id)
                    else:
                        to_disconnect[process_id] = [port_id]

                credential = self.credentials[port['credential_id']]
                username = credential['username']
                password = credential['password']
                vpnservice_id = process_id
                remote_ip = port['ip']
                credential_items.append('%s %s %s %s' % (
                    username, vpnservice_id, password, remote_ip))

        credential_items.append('\n')  # Add a empty line
        utils.replace_file(self.conf.pptp.chap_secrets,
                           '\n'.join(credential_items))

        for process_id, port_ids in to_disconnect.iteritems():
            process = self.processes.get(process_id)
            if process:
                for port_id in port_ids:
                    process.disconnect_port(port_id)

        for process_id, port_ids in to_delete.iteritems():
            process = self.processes.get(process_id)
            if process:
                for port_id in port_ids:
                    process.del_port(port_id)

    def sync(self, context, routers):
        """
        Agent regularly reports active processes statuses to the server. And
        the server then checks and then ask the agent to start/stop services.
        So we don't need to do anything here.
        """
        pass

    def create_router(self, router_id):
        pass

    def destroy_router(self, router_id):
        pass
