# Copyright 2017 Eayun, Inc.
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

import socket
import struct
import threading
import time
import SocketServer

import eventlet
eventlet.monkey_patch()

from neutron.agent.linux import ovs_lib
from neutron.common import rpc as n_rpc
from neutron.common import utils
from neutron.openstack.common import log as logging
from neutron.openstack.common import loopingcall

LOG = logging.getLogger(__name__)

NETFLOW_V5_HDR_LENGTH = 24
NETFLOW_V5_MSG_LENGTH = 48

NETFLOW_DEFAULT_SERVER = '127.0.0.1'
NETFLOW_DEFAULT_PORT = 2055

LOW_LEVEL_BRIDGE_ENGINE_ID = 1
EXT_BRIDGE_ENGINE_ID = 2

STAT_DELAY_WARN_TIMEOUT = 1

SEND_STAT_TOPIC = 'neutron.netflow.send'
RECV_STAT_TOPIC = 'neutron.netflow.recv'

DEFAULT_EXT_BRIDGE = 'br-ex'


class NetflowV5Header(object):
    def __init__(self, _version, count, _sys_uptime, unix_secs, _unix_nsecs,
            _flow_sequence, _engine_type, engine_id, _sampling_interval):
        self.count = count
        self.unix_secs = unix_secs
        self.engine_id = engine_id

    @classmethod
    def from_data(cls, data):
        return cls(*struct.unpack('!HHIIIIBBH', data))


class NetflowV5Message(object):
    def __init__(self, src_ip, dst_ip, src_num, dst_num,
                 _nexthop, input_port, _output_port,
                 _dpkts, doctets, _first, _last, _src_port, _dst_port,
                 _pad1, _tcp_flags, _protocol, _tos, _src_as, _dst_as,
                 _src_mask, _dst_mask, _pad2):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_num = src_num
        self.dst_num = dst_num
        self.input_port = input_port
        self.doctets = doctets

    @classmethod
    def from_data(cls, data):
        src_ip = socket.inet_ntoa(data[0:4])
        dst_ip = socket.inet_ntoa(data[4:8])
        return cls(src_ip, dst_ip,
                   *struct.unpack('!IIIHHIIIIHHBBBBHHBBH', data))


class NetflowMessageHandler(SocketServer.BaseRequestHandler):

    @staticmethod
    def get_n_messages(count, data):
        ret = []
        for c in range(count):
            offset = c * NETFLOW_V5_MSG_LENGTH
            msg_data = data[offset:offset + NETFLOW_V5_MSG_LENGTH]
            ret.append(NetflowV5Message.from_data(msg_data))
        return ret

    def handle(self):
        data, client_socket = self.request
        header_data = data[:NETFLOW_V5_HDR_LENGTH]
        data = data[NETFLOW_V5_HDR_LENGTH:]

        header = NetflowV5Header.from_data(header_data)
        messages = self.get_n_messages(header.count, data)

        agent = self.server.agent
        recv_stats = {}
        send_stats = {}
        for message in messages:
            if agent.should_add_recv(message.dst_num):
                key = message.dst_ip
                recv_stats[key] = recv_stats.get(key, 0) + message.doctets
            if agent.should_add_send(
                header.engine_id, message.src_num,
                message.src_ip, message.input_port
            ):
                key = message.src_ip
                send_stats[key] = send_stats.get(key, 0) + message.doctets

        if recv_stats or send_stats:
            agent.add_netflow_stats(header.unix_secs, recv_stats, send_stats)


class NetflowListener(SocketServer.ThreadingUDPServer, object):
    def __init__(self, server_address, RequestHandlerClass, agent):
        super(
            NetflowListener, self
        ).__init__(server_address, RequestHandlerClass)
        self.agent = agent


class NetflowAgent(object):

    def __init__(self, context, integ_br, root_helper, bridge_mappings, conf):
        self.context = context
        self.root_helper = root_helper

        self.low_level_bridge = conf.low_level_ingress_bridge
        self.ext_providers = set(conf.ext_network_providers)
        if self.ext_providers:
            # Multiple external networks
            self.ext_bridge = integ_br
        else:
            # Single external network
            self.ext_bridge = DEFAULT_EXT_BRIDGE

        self.recv_stats = {}
        self.send_stats = {}
        self.pool = set()
        self.ofport_ip_mappings = {}

        self.notifier = n_rpc.get_notifier('metering')
        self.report_pool = eventlet.greenpool.GreenPool()
        report_loop = loopingcall.FixedIntervalLoopingCall(self._report_stats)
        report_loop.start(interval=conf.report_interval)

        self._setup_netflow(conf.active_timeout)

        self.netflow_listener = NetflowListener(
            (NETFLOW_DEFAULT_SERVER, NETFLOW_DEFAULT_PORT),
            NetflowMessageHandler, self
        )
        self.listen_thread = threading.Thread(
            target=self.netflow_listener.serve_forever
        )
        self.listen_thread.daemon = True
        self.listen_thread.start()

    def stop(self):
        eventlet.spawn_n(self._destroy_netflow)

    def _setup_netflow(self, active_timeout):
        low_br = ovs_lib.OVSBridge(self.low_level_bridge, self.root_helper)
        low_br.add_netflow(NETFLOW_DEFAULT_SERVER, NETFLOW_DEFAULT_PORT,
                           active_timeout, LOW_LEVEL_BRIDGE_ENGINE_ID)
        ext_br = ovs_lib.OVSBridge(self.ext_bridge, self.root_helper)
        ext_br.add_netflow(NETFLOW_DEFAULT_SERVER, NETFLOW_DEFAULT_PORT,
                           active_timeout, EXT_BRIDGE_ENGINE_ID)

    def _destroy_netflow(self):
        low_br = ovs_lib.OVSBridge(self.low_level_bridge, self.root_helper)
        low_br.clear_netflow()
        ext_br = ovs_lib.OVSBridge(self.ext_bridge, self.root_helper)
        ext_br.clear_netflow()

    def port_bound(self, port, physical_network, fixed_ips):
        if physical_network and physical_network not in self.ext_providers:
            return
        port_id = port.vif_id
        of_port_num = port.ofport
        ip_address = fixed_ips[0]['ip_address']
        ip_num = struct.unpack('!I', socket.inet_aton(ip_address))[0]
        self.pool.add(ip_num)
        self.ofport_ip_mappings[of_port_num] = {
            'id': port_id,
            'address': ip_address,
            'num': ip_num
        }

    def port_unbound(self, port):
        of_port_num = port.ofport
        info = self.ofport_ip_mappings.pop(of_port_num, None)
        if info:
            self.pool.discard(info['num'])

    # Functions for NetFlow message handler

    def _ip_num_in_pool(self, ip_num):
        return ip_num in self.pool

    def should_add_recv(self, dst_num):
        return self._ip_num_in_pool(dst_num)

    def should_add_send(self, engine_id, src_num, src_ip, input_port):
        if engine_id != EXT_BRIDGE_ENGINE_ID:
            return False
        elif not self._ip_num_in_pool(src_num):
            return False
        elif input_port not in self.ofport_ip_mappings:
            return False

        input_port_id = self.ofport_ip_mappings[input_port]['id']
        input_port_address = self.ofport_ip_mappings[input_port]['address']
        if input_port_address != src_ip:
            LOG.warn('Get data from source IP address %(data_addr) on port '
                     '%(port_id)s with IP address %(port_addr)s.',
                     {'data_addr': src_ip,
                      'port_id': input_port_id,
                      'port_addr': input_port_address})
        return True

    @utils.synchronized('netflow')
    def add_netflow_stats(self, timestamp, recv_stats, send_stats):
        for ip, stat in recv_stats.items():
            self.recv_stats[ip] = self.recv_stats.get(ip, 0) + stat

        for ip, stat in send_stats.items():
            self.send_stats[ip] = self.send_stats.get(ip, 0) + stat

        delay = int(time.time()) - timestamp
        if delay > STAT_DELAY_WARN_TIMEOUT:
            LOG.warn('Stat handling delays for %(delay)s seconds.',
                     {'delay': delay})

    @utils.synchronized('netflow')
    def _report_stats(self):
        for ip, octets in self.send_stats.items():
            data = {'ip': ip, 'bytes': octets}
            self.report_pool.spawn_n(
                self.notifier.info, self.context, SEND_STAT_TOPIC, data)
        for ip, octets in self.recv_stats.items():
            data = {'ip': ip, 'bytes': octets}
            self.report_pool.spawn_n(
                self.notifier.info, self.context, RECV_STAT_TOPIC, data)

        self.report_pool.waitall()

        self.send_stats = {}
        self.recv_stats = {}
