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

import six

from neutron.agent.linux import iptables_manager
from neutron.common import constants as constants
from neutron.common import log
from neutron.openstack.common import log as logging
from neutron.services.metering.drivers.iptables import iptables_driver

LOG = logging.getLogger(__name__)
ES_METERING_MARK = 1


class EsRouterWithMetering(iptables_driver.RouterWithMetering):
    """Extend the original RouterWithMetering class."""

    def __init__(self, conf, router):
        super(EsRouterWithMetering, self).__init__(conf, router)
        self.es_metering_labels = {}
        self._update_iptables_manager_for_es_metering()

    def _update_iptables_manager_for_es_metering(self):
        im = self.iptables_manager
        im.ipv4.update(
            {'mangle': iptables_manager.IptablesTable(
                binary_name=iptables_driver.WRAP_NAME)})
        for chain in ['PREROUTING', 'INPUT', 'POSTROUTING']:
            im.ipv4['mangle'].add_chain(chain)
            im.ipv4['mangle'].add_rule(chain, '-j $%s' % (chain), wrap=False)
        # Mark packets from external
        mark_rule = '-i %s+ -j MARK --set-mark %d' % (
            iptables_driver.EXTERNAL_DEV_PREFIX, ES_METERING_MARK)
        im.ipv4['mangle'].add_rule('PREROUTING', mark_rule)

    def iter_metering_labels(self):
        return self.metering_labels.items() + self.es_metering_labels.items()


class EsIptablesMeteringDriver(iptables_driver.IptablesMeteringDriver):
    """Extend the original IptablesMeteringDriver class."""

    def _update_router(self, router):
        """
        In IptablesMeteringDriver, router is initiated with RouterWithMetering,
        we need to change to use EsRouterWithMetering.
        """
        r = self.routers.get(
            router['id'], EsRouterWithMetering(self.conf, router))
        # The router attribute of the RouterWithMetering is only useful
        # in the original class.
        r.router = router
        self.routers[r.id] = r
        return r

    @log.log
    def update_routers(self, context, routers):
        """Deal with the EayunStack metering extension."""
        super(EsIptablesMeteringDriver, self).update_routers(context, routers)

        # The following lines are somehow duplicated with the base class,
        # however they are more clear in this way.

        # Removed routers
        router_ids = set(router['id'] for router in routers)
        for router_id, rm in six.iteritems(self.routers):
            if router_id not in router_ids:
                self._process_disassociate_es_metering_label(rm.router)

        # Added or updated routers
        for router in routers:
            old_rm = self.routers.get(router['id'])
            if old_rm:
                old_es_metering_labels = set(old_rm.es_metering_labels.keys())
                persist_labels = set()
                with iptables_driver.IptablesManagerTransaction(
                    old_rm.iptables_manager
                ):
                    labels = router.get(constants.ES_METERING_LABEL_KEY, [])
                    for label in labels:
                        label_id = label['id']
                        if label_id in old_es_metering_labels:
                            persist_labels.add(label_id)
                        else:
                            self._add_es_metering_label(old_rm, label)

                    for label_id in old_es_metering_labels - persist_labels:
                        self._remove_es_metering_label(old_rm, label_id)

            else:
                self._process_associate_es_metering_label(router)

    @staticmethod
    def _get_es_meter_rule(label, label_chain):
        rule_parts = []
        if label['direction'] == 'ingress':
            rule_parts += ['-m mark --mark %s' % ES_METERING_MARK]
            rule_dir = '-d'
            port_selector = '--dport'
        else:
            rule_parts += ['-o %s+' % iptables_driver.EXTERNAL_DEV_PREFIX]
            rule_dir = '-s'
            port_selector = '--sport'

        if label['internal_ip'] is not None:
            rule_parts += ['%s %s' % (rule_dir, label['internal_ip'])]

        if label['tcp_port'] is not None:
            rule_parts += ['-p tcp %s %s' % (port_selector, label['tcp_port'])]

        rule_parts += ['-j %s' % label_chain]

        return ' '.join(rule_parts)

    @staticmethod
    def _get_label_chain_name(label_id):
        return iptables_manager.get_chain_name(
            iptables_driver.WRAP_NAME + iptables_driver.LABEL + label_id,
            wrap=False)

    def _add_es_metering_label(self, rm, label):
        table = rm.iptables_manager.ipv4['mangle']
        label_id = label['id']
        label_chain = self._get_label_chain_name(label_id)
        table.add_chain(label_chain, wrap=False)
        es_meter_rule = self._get_es_meter_rule(label, label_chain)
        table.add_rule('POSTROUTING', es_meter_rule)
        if label['internal_ip'] is None and label['direction'] == 'ingress':
            # If internal IP is unspecified, we should also count traffic
            # directed to the router itself.
            table.add_rule('INPUT', es_meter_rule)
        table.add_rule(label_chain, '', wrap=False)
        rm.es_metering_labels[label_id] = label

    def _remove_es_metering_label(self, rm, label_id):
        table = rm.iptables_manager.ipv4['mangle']
        if label_id not in rm.es_metering_labels:
            return
        label_chain = self._get_label_chain_name(label_id)
        table.remove_chain(label_chain, wrap=False)

        del rm.es_metering_labels[label_id]

    def _process_associate_es_metering_label(self, router):
        self._update_router(router)
        rm = self.routers.get(router['id'])

        with iptables_driver.IptablesManagerTransaction(rm.iptables_manager):
            labels = router.get(constants.ES_METERING_LABEL_KEY, [])
            for label in labels:
                self._add_es_metering_label(rm, label)

    def _process_disassociate_es_metering_label(self, router):
        rm = self.routers.get(router['id'])
        if not rm:
            return
        with iptables_driver.IptablesManagerTransaction(rm.iptables_manager):
            labels = router.get(constants.ES_METERING_LABEL_KEY, [])
            for label in labels:
                self._remove_es_metering_label(rm, label['id'])

    @log.log
    def add_es_metering_label(self, _context, routers):
        for router in routers:
            self._process_associate_es_metering_label(router)

    @log.log
    def remove_es_metering_label(self, _context, routers):
        for router in routers:
            self._process_disassociate_es_metering_label(router)
