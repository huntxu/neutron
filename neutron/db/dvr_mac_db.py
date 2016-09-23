# Copyright 2014 Hewlett-Packard Development Company, L.P.
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

from oslo.db import exception as db_exc

import sqlalchemy as sa

from neutron.common import constants
from neutron.common import exceptions as q_exc
from neutron.common import log
from neutron.common import utils
from neutron.db import model_base
from neutron.extensions import dvr as ext_dvr
from neutron.extensions import portbindings
from neutron import manager
from neutron.openstack.common import log as logging
from oslo.config import cfg
from sqlalchemy.orm import exc

LOG = logging.getLogger(__name__)

dvr_mac_address_opts = [
    cfg.StrOpt('dvr_base_mac',
               default="fa:16:3f:00:00:00",
               help=_('The base mac address used for unique '
                      'DVR instances by Neutron')),
]
cfg.CONF.register_opts(dvr_mac_address_opts)

PORT_NAME_LEN = 14


class DistributedVirtualRouterMacAddress(model_base.BASEV2):
    """Represents a v2 neutron distributed virtual router mac address."""

    __tablename__ = 'dvr_host_macs'

    host = sa.Column(sa.String(255), primary_key=True, nullable=False)
    mac_address = sa.Column(sa.String(32), nullable=False, unique=True)


class DVRDbMixin(ext_dvr.DVRMacAddressPluginBase):
    """Mixin class to add dvr mac address to db_plugin_base_v2."""

    @property
    def plugin(self):
        try:
            if self._plugin is not None:
                return self._plugin
        except AttributeError:
            pass
        self._plugin = manager.NeutronManager.get_plugin()
        return self._plugin

    def _get_dvr_mac_address_by_host(self, context, host):
        try:
            query = context.session.query(DistributedVirtualRouterMacAddress)
            dvrma = query.filter(
                DistributedVirtualRouterMacAddress.host == host).one()
        except exc.NoResultFound:
            raise ext_dvr.DVRMacAddressNotFound(host=host)
        return dvrma

    def _create_dvr_mac_address(self, context, host):
        """Create DVR mac address for a given host."""
        base_mac = cfg.CONF.dvr_base_mac.split(':')
        max_retries = cfg.CONF.mac_generation_retries
        for attempt in reversed(range(max_retries)):
            try:
                with context.session.begin(subtransactions=True):
                    mac_address = utils.get_random_mac(base_mac)
                    dvr_mac_binding = DistributedVirtualRouterMacAddress(
                        host=host, mac_address=mac_address)
                    context.session.add(dvr_mac_binding)
                    LOG.debug("Generated DVR mac for host %(host)s "
                              "is %(mac_address)s",
                              {'host': host, 'mac_address': mac_address})
                dvr_macs = self.get_dvr_mac_address_list(context)
                # TODO(vivek): improve scalability of this fanout by
                # sending a single mac address rather than the entire set
                self.notifier.dvr_mac_address_update(context, dvr_macs)
                return self._make_dvr_mac_address_dict(dvr_mac_binding)
            except db_exc.DBDuplicateEntry:
                LOG.debug("Generated DVR mac %(mac)s exists."
                          " Remaining attempts %(attempts_left)s.",
                          {'mac': mac_address, 'attempts_left': attempt})
        LOG.error(_("MAC generation error after %s attempts"), max_retries)
        raise ext_dvr.MacAddressGenerationFailure(host=host)

    def delete_dvr_mac_address(self, context, host):
        query = context.session.query(DistributedVirtualRouterMacAddress)
        (query.
         filter(DistributedVirtualRouterMacAddress.host == host).
         delete(synchronize_session=False))

    def get_dvr_mac_address_list(self, context):
        with context.session.begin(subtransactions=True):
            return (context.session.
                    query(DistributedVirtualRouterMacAddress).all())

    def get_dvr_mac_address_by_host(self, context, host):
        """Determine the MAC for the DVR port associated to host."""
        if not host:
            return

        try:
            return self._get_dvr_mac_address_by_host(context, host)
        except ext_dvr.DVRMacAddressNotFound:
            return self._create_dvr_mac_address(context, host)

    def _make_dvr_mac_address_dict(self, dvr_mac_entry, fields=None):
        return {'host': dvr_mac_entry['host'],
                'mac_address': dvr_mac_entry['mac_address']}

    @log.log
    def get_ports_on_host_by_subnet(self, context, host, subnet):
        """Returns ports of interest, on a given subnet in the input host

        This method returns ports that need to be serviced by DVR.
        :param context: rpc request context
        :param host: host id to match and extract ports of interest
        :param subnet: subnet id to match and extract ports of interest
        :returns list -- Ports on the given subnet in the input host
        """
        # FIXME(vivek, salv-orlando): improve this query by adding the
        # capability of filtering by binding:host_id
        ports_by_host = []
        filter = {'fixed_ips': {'subnet_id': [subnet]}}
        ports = self.plugin.get_ports(context, filters=filter)
        LOG.debug("List of Ports on subnet %(subnet)s at host %(host)s "
                  "received as %(ports)s",
                  {'subnet': subnet, 'host': host, 'ports': ports})
        for port in ports:
            device_owner = port['device_owner']
            if (utils.is_dvr_serviced(device_owner)):
                if port[portbindings.HOST_ID] == host:
                    port_dict = self.plugin._make_port_dict(port,
                        process_extensions=False)
                    ports_by_host.append(port_dict)
        LOG.debug("Returning list of dvr serviced ports on host %(host)s"
                  " for subnet %(subnet)s ports %(ports)s",
                  {'host': host, 'subnet': subnet,
                   'ports': ports_by_host})
        return ports_by_host

    @log.log
    def get_subnet_for_dvr(self, context, subnet):
        try:
            subnet_info = self.plugin.get_subnet(context, subnet)
        except q_exc.SubnetNotFound:
            return {}
        else:
            # retrieve the gateway port on this subnet
            filter = {'fixed_ips': {'subnet_id': [subnet],
                                    'ip_address': [subnet_info['gateway_ip']]}}
            internal_gateway_ports = self.plugin.get_ports(
                context, filters=filter)
            if not internal_gateway_ports:
                LOG.error(_("Could not retrieve gateway port "
                            "for subnet %s"), subnet_info)
                return {}
            internal_port = internal_gateway_ports[0]
            subnet_info['gateway_mac'] = internal_port['mac_address']
            return subnet_info

    @staticmethod
    def _get_port_name(port_id, device_owner):
        prefix = None
        if device_owner.startswith('compute:'):
            prefix = 'qvo'
        elif device_owner == constants.DEVICE_OWNER_LOADBALANCER:
            prefix = 'tap'
        if prefix:
            return (prefix + port_id)[:PORT_NAME_LEN]
        else:
            return None

    def _get_dvr_subnets_for_port(self, context, port):
        ret = []
        gateway_mac = port['mac_address']
        network = self.plugin.get_network(context, port['network_id'])
        if network.get('provider:network_type', '') == 'vlan':
            for fixed_ip in port['fixed_ips']:
                subnet_id = fixed_ip['subnet_id']
                subnet = self.plugin.get_subnet(context, subnet_id)
                if subnet['ip_version'] == 4 and subnet['gateway_ip']:
                    cidr = subnet['cidr']
                    ret.append({'id': subnet_id,
                                'cidr': cidr,
                                'gateway_mac': gateway_mac,
                                'seg_id': network['provider:segmentation_id'],
                                'ports': {}})
        return ret

    def _get_dvr_ports_for_subnet(self, context, subnet_id):
        ret = {}
        subnet_port_filter = {'fixed_ips': {'subnet_id': [subnet_id]}}
        ports = self.plugin.get_ports(context, filters=subnet_port_filter)
        for port in ports:
            port_id = port['id']
            device_owner = port['device_owner']
            mac_address = port['mac_address']
            binding_host = port['binding:host_id']
            ip_address = None
            for ip in port['fixed_ips']:
                if ip['subnet_id'] == subnet_id:
                    ip_address = ip['ip_address']
                    break
            port_name = self._get_port_name(port_id, device_owner)
            if port_name is not None and ip_address:
                ret[port_id] = {'mac': mac_address, 'ip': ip_address,
                                'host': binding_host, 'name': port_name}
        return ret

    def _get_dvr_subnets(self, context, router_ports, host):
        host_affected = False
        dvr_subnets = {}
        for router_port in router_ports:
            subnets = self._get_dvr_subnets_for_port(
                context, router_port)
            for subnet in subnets:
                subnet_id = subnet.pop('id')
                dvr_subnets[subnet_id] = subnet

        if len(dvr_subnets) < 2:
            # router is not connected to two or more ipv4 subnets
            return None

        for subnet_id in dvr_subnets:
            subnet_ports = self._get_dvr_ports_for_subnet(context, subnet_id)
            dvr_subnets[subnet_id]['ports'] = subnet_ports
            host_affected |= (
                host in set(port['host'] for port in subnet_ports.values()))

        dvr_subnets = {
            subnet_id: subnet
            for subnet_id, subnet in dvr_subnets.iteritems()
            if subnet['ports']
        }

        if host_affected and len(dvr_subnets) > 1:
            return dvr_subnets
        else:
            return None

    @log.log
    def get_openflow_ew_dvrs(self, context, host):
        """
        Returns:
        {
            router1_id: {
                connected_subnet1_id: {
                    'cidr': subnet_cidr,
                    'gateway_mac': subnet_gateway_mac,
                    'seg_id': network's segmentation id
                    'ports': {
                        port1_id: {
                            'mac': port1_mac,
                            'ip': port1_ip,
                            'host': port1_host,
                            'name': port1_name,
                        },
                        port2_id: {...},
                    },
                },
                connected_subnet2_id: {...},
            },
            'router2_id': {...},
        }
        """
        dvrs = {}
        router_ports_filter = {
            'device_owner': [constants.DEVICE_OWNER_ROUTER_INTF]}
        router_ports = self.plugin.get_ports(
            context, filters=router_ports_filter)
        for router_port in router_ports:
            router_id = router_port['device_id']
            if router_id not in dvrs:
                dvrs[router_id] = [router_port]
            else:
                dvrs[router_id].append(router_port)

        dvrs = {
            router_id: self._get_dvr_subnets(context, router_ports, host)
            for router_id, router_ports in dvrs.iteritems()
            if len(router_ports) > 1}
        dvrs = {
            router_id: subnets
            for router_id, subnets in dvrs.iteritems()
            if subnets is not None}
        return dvrs
