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

import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.ext.orderinglist import ordering_list
from sqlalchemy.orm import exc

from neutron.common import constants
from neutron.common import exceptions as n_exc
from neutron.db import common_db_mixin as base_db
from neutron.db import model_base
from neutron.db import models_v2
from neutron.extensions import es_acl as es_acl
from neutron.openstack.common import uuidutils
from neutron.openstack.common import log as logging

from neutron import manager


LOG = logging.getLogger(__name__)


class EsAclRule(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents an EayunStack ACL rule."""
    __tablename__ = 'es_acl_rules'
    name = sa.Column(sa.String(255))
    acl_id = sa.Column(sa.String(36), sa.ForeignKey('es_acls.id'))
    position = sa.Column(sa.Integer)
    direction = sa.Column(
        sa.Enum('ingress', 'egress', name='es_acl_rule_direction'),
        nullable=False)
    protocol = sa.Column(sa.Integer)
    source_ip_address = sa.Column(sa.String(64))
    destination_ip_address = sa.Column(sa.String(64))
    source_port_min = sa.Column(sa.Integer)
    source_port_max = sa.Column(sa.Integer)
    destination_port_min = sa.Column(sa.Integer)
    destination_port_max = sa.Column(sa.Integer)
    action = sa.Column(
        sa.Enum('allow', 'deny', name='es_acl_rule_action'),
        nullable=False)


class EsAcl(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents an EayunStack ACL."""
    __tablename__ = 'es_acls'
    name = sa.Column(sa.String(255))
    ingress_rules = orm.relationship(
        EsAclRule, order_by='EsAclRule.position', lazy='subquery',
        primaryjoin="and_(EsAclRule.acl_id==EsAcl.id, "
                    "EsAclRule.direction=='ingress')",
        collection_class=ordering_list('position', count_from=1))
    egress_rules = orm.relationship(
        EsAclRule, order_by='EsAclRule.position', lazy='subquery',
        primaryjoin="and_(EsAclRule.acl_id==EsAcl.id, "
                    "EsAclRule.direction=='egress')",
        collection_class=ordering_list('position', count_from=1))


class EsAclSubnetBinding(model_base.BASEV2):
    """Represents a binding between a neutron subnet and an Eayunstack ACL."""
    __tablename__ = 'es_acl_subnet_bindings'
    subnet_id = sa.Column(
        sa.String(36), sa.ForeignKey('subnets.id', ondelete='CASCADE'),
        primary_key=True)
    acl_id = sa.Column(
        sa.String(36), sa.ForeignKey('es_acls.id'), nullable=False)
    router_id = sa.Column(
        sa.String(36), sa.ForeignKey('routers.id', ondelete='SET NULL'))
    router_port_id = sa.Column(
        sa.String(36), sa.ForeignKey('ports.id', ondelete='SET NULL'))

    acl = orm.relationship(
        EsAcl, backref=orm.backref('bindings', lazy='subquery', uselist=True))


class EsAclDbMixin(es_acl.EsAclPluginBase, base_db.CommonDbMixin):

    @property
    def _core_plugin(self):
        return manager.NeutronManager.get_plugin()

    def _get_es_acl(self, context, es_acl_id):
        try:
            return self._get_by_id(context, EsAcl, es_acl_id)
        except exc.NoResultFound:
            raise es_acl.AclNotFound(acl_id=es_acl_id)

    def _make_es_acl_dict(self, acl_db, fields=None):
        res = {'id': acl_db.id,
               'name': acl_db.name,
               'tenant_id': acl_db.tenant_id,
               'subnets': [binding.subnet_id for binding in acl_db.bindings],
               'ingress_rules': [rule.id for rule in acl_db.ingress_rules],
               'egress_rules': [rule.id for rule in acl_db.egress_rules]}
        return self._fields(res, fields)

    def create_es_acl(self, context, es_acl):
        """Create an EayunStack subnet ACL."""
        acl = es_acl['es_acl']
        tenant_id = self._get_tenant_id_for_create(context, acl)
        with context.session.begin(subtransactions=True):
            acl_db = EsAcl(id=uuidutils.generate_uuid(),
                           tenant_id=tenant_id,
                           name=acl['name'])
            context.session.add(acl_db)
        return self._make_es_acl_dict(acl_db)

    def update_es_acl(self, context, es_acl_id, es_acl):
        """Update an EayunStack subnet ACL."""
        acl = es_acl['es_acl']
        acl_db = self._get_es_acl(context, es_acl_id)
        with context.session.begin(subtransactions=True):
            acl_db.update(acl)
        return self._make_es_acl_dict(acl_db)

    def delete_es_acl(self, context, es_acl_id):
        """Delete an EayunStack subnet ACL."""
        acl_db = self._get_es_acl(context, es_acl_id)
        if acl_db.bindings:
            raise es_acl.AclInUse(
                acl_id=es_acl_id,
                subnets=[binding.subnet_id for binding in acl_db.bindings])
        with context.session.begin(subtransactions=True):
            context.session.delete(acl_db)

    def get_es_acl(self, context, es_acl_id, fields=None):
        """Get an EayunStack subnet ACL."""
        acl_db = self._get_es_acl(context, es_acl_id)
        return self._make_es_acl_dict(acl_db, fields)

    def get_es_acls(self, context, filters=None, fields=None,
                    sorts=None, limit=None, marker=None,
                    page_reverse=False):
        """List EayunStack subnet ACLs."""
        marker_object = self._get_marker_obj(context, 'es_acl', limit, marker)
        return self._get_collection(
            context, EsAcl, self._make_es_acl_dict,
            filters=filters, fields=fields, sorts=sorts,
            limit=limit, marker_obj=marker_object, page_reverse=page_reverse)

    def bind_subnets(self, context, es_acl_id, subnet_ids):
        """Bind subnets to ACL."""
        subnet_ids = subnet_ids['subnet_ids']
        bound_subnets = []
        with context.session.begin(subtransactions=True):
            acl_db = self._get_es_acl(context, es_acl_id)
            already_bound = set(
                binding.subnet_id for binding in acl_db.bindings)
            for subnet_id in subnet_ids:
                failed_msg = ('ACL %(acl_id)s failed to bind to subnet '
                              'subnet %(subnet_id)s: %(reason)s.')
                failed_reason = None

                if subnet_id in already_bound:
                    failed_reason = 'already bound'

                if failed_reason is None:
                    try:
                        subnet = self._core_plugin._get_subnet(
                            context, subnet_id)
                    except n_exc.SubnetNotFound:
                        failed_reason = 'subnet not found'

                if failed_reason is None:
                    if acl_db.tenant_id != subnet.tenant_id:
                        failed_reason = 'not the same tenant'

                if failed_reason:
                    LOG.warn(failed_msg, {'acl_id': es_acl_id,
                                          'subnet_id': subnet_id,
                                          'reason': failed_reason})
                    continue

                router_port = self._core_plugin._get_ports_query(
                    context,
                    filters={
                        'fixed_ips': {'subnet_id': [subnet_id],
                                      'ip_address': [subnet.gateway_ip]},
                        'device_owner': [constants.DEVICE_OWNER_ROUTER_INTF]
                    }
                ).first()
                router_id = None
                router_port_id = None
                if router_port:
                    router_id = router_port.routerport.router_id
                    router_port_id = router_port.id
                binding_db = EsAclSubnetBinding(
                    subnet_id=subnet_id,
                    acl_id=es_acl_id,
                    router_id=router_id,
                    router_port_id=router_port_id)
                context.session.add(binding_db)
                bound_subnets.append(subnet_id)
        return {'bound_subnets': bound_subnets}

    def unbind_subnets(self, context, es_acl_id, subnet_ids):
        """Unbind subnets from ACL."""
        subnet_ids = subnet_ids['subnet_ids']
        unbound_subnets = []
        with context.session.begin(subtransactions=True):
            acl_db = self._get_es_acl(context, es_acl_id)
            subnet_ids = set(subnet_ids)
            for binding in acl_db.bindings:
                subnet_id = binding.subnet_id
                if subnet_id in subnet_ids:
                    context.session.delete(binding)
                    subnet_ids.remove(subnet_id)
                    unbound_subnets.append(subnet_id)
            if subnet_ids:
                LOG.warn('ACL %(acl_id)s is not bound to '
                         'subnet(s) %(subnet_ids)s.',
                         {'acl_id': es_acl_id, 'subnet_ids': subnet_ids})
        return {'unbound_subnets': unbound_subnets}

    def _get_es_acl_rule(self, context, es_acl_rule_id):
        try:
            return self._get_by_id(context, EsAclRule, es_acl_rule_id)
        except exc.NoResultFound:
            raise es_acl.AclRuleNotFound(acl_rule_id=es_acl_rule_id)

    @staticmethod
    def _ports_to_range(port_min, port_max):
        if port_min is None:
            return
        elif port_min == port_max:
            return '%d' % port_min
        else:
            return '%d:%d' % (port_min, port_max)

    @staticmethod
    def _range_to_ports(port_range):
        if port_range is not None:
            ports = [int(port) for port in port_range.split(':')]
            return ports[0], ports[-1]
        else:
            return None, None

    def _make_es_acl_rule_dict(self, acl_rule_db, fields=None):
        source_port_range = self._ports_to_range(
            acl_rule_db.source_port_min, acl_rule_db.source_port_max)
        destination_port_range = self._ports_to_range(
            acl_rule_db.destination_port_min, acl_rule_db.destination_port_max)
        # Don't show position if acl_id is None. Case that position is not None
        # when acl_id is, can happen when acl is deleted, acl_id would be set
        # to None while position would not be changed.
        acl_id = acl_rule_db.acl_id
        position = acl_rule_db.position if acl_id is not None else None
        res = {'id': acl_rule_db.id,
               'name': acl_rule_db.name,
               'tenant_id': acl_rule_db.tenant_id,
               'acl_id': acl_id,
               'position': position,
               'direction': acl_rule_db.direction,
               'protocol': acl_rule_db.protocol,
               'source_ip_address': acl_rule_db.source_ip_address,
               'destination_ip_address': acl_rule_db.destination_ip_address,
               'source_port': source_port_range,
               'destination_port': destination_port_range,
               'action': acl_rule_db.action}
        return self._fields(res, fields)

    def _validate_acl(self, context, acl_id, tenant_id):
        if acl_id is not None:
            acl = self._get_es_acl(context, acl_id)
            if acl.tenant_id != tenant_id:
                raise es_acl.AclNotFound(acl_id=acl_id)

    def _process_rule_for_acl(self, context, acl_id, rule_db, position,
                              pos_changed=False, rule_removed=False):
        if not acl_id:
            return
        with context.session.begin(subtransactions=True):
            acl_query = context.session.query(EsAcl).with_lockmode('update')
            acl_db = acl_query.filter_by(id=acl_id).one()
            rules = getattr(acl_db, '%s_rules' % rule_db.direction)
            last_pos = len(rules)
            if rule_removed:
                # Remove a rule from acl
                position = rule_db.position
                rules.pop(position - 1)
                rule_db.update({'position': None})
            elif pos_changed:
                orig_pos = rule_db.position
                new_pos = min(position or last_pos, last_pos)
                if orig_pos != new_pos:
                    rules.pop(orig_pos - 1)
                    if new_pos == last_pos:
                        rules.append(rule_db)
                    else:
                        rules.insert(new_pos - 1, rule_db)
            else:
                # Add a rule to acl
                if position is None or position > last_pos:
                    rules.append(rule_db)
                else:
                    rules.insert(position - 1, rule_db)
            rules.reorder()

    def create_es_acl_rule(self, context, es_acl_rule):
        """Create an EayunStack subnet ACL rule."""
        acl_rule = es_acl_rule['es_acl_rule']
        acl_id = acl_rule['acl_id']
        tenant_id = self._get_tenant_id_for_create(context, acl_rule)
        position = acl_rule['position']
        direction = acl_rule['direction']

        self._validate_acl(context, acl_id, tenant_id)
        if acl_id is None and position is not None:
            LOG.warn('Setting position without specifying acl_id is '
                     'meaningless, ignored.')

        source_port_min, source_port_max = self._range_to_ports(
            acl_rule['source_port'])
        destination_port_min, destination_port_max = self._range_to_ports(
            acl_rule['destination_port'])
        with context.session.begin(subtransactions=True):
            acl_rule_db = EsAclRule(
                id=uuidutils.generate_uuid(),
                tenant_id=tenant_id,
                name=acl_rule['name'],
                direction=direction,
                protocol=acl_rule['protocol'],
                source_ip_address=acl_rule['source_ip_address'],
                destination_ip_address=acl_rule['destination_ip_address'],
                source_port_min=source_port_min,
                source_port_max=source_port_max,
                destination_port_min=destination_port_min,
                destination_port_max=destination_port_max,
                action=acl_rule['action'])
            context.session.add(acl_rule_db)
            self._process_rule_for_acl(context, acl_id, acl_rule_db, position)
        return self._make_es_acl_rule_dict(acl_rule_db)

    def update_es_acl_rule(self, context, es_acl_rule_id, es_acl_rule):
        """Update an EayunStack subnet ACL rule."""
        acl_rule = es_acl_rule['es_acl_rule']

        acl_may_change = 'acl_id' in acl_rule
        acl_id = acl_rule.pop('acl_id', None)
        position = acl_rule.pop('position', None)

        if 'source_port' in acl_rule:
            source_port_min, source_port_max = self._range_to_ports(
                acl_rule.pop['source_port'])
            acl_rule['source_port_min'] = source_port_min
            acl_rule['source_port_max'] = source_port_max
        if 'destination_port' in acl_rule:
            destination_port_min, destination_port_max = self._range_to_ports(
                acl_rule.pop['destination_port'])
            acl_rule['destination_port_min'] = destination_port_min
            acl_rule['destination_port_max'] = destination_port_max

        with context.session.begin(subtransactions=True):
            acl_rule_db = self._get_es_acl_rule(context, es_acl_rule_id)
            self._validate_acl(context, acl_id, acl_rule_db.tenant_id)
            new_direction = acl_rule.get('direction', acl_rule_db.direction)

            _add_rule = False
            if acl_may_change and acl_id != acl_rule_db.acl_id:
                self._process_rule_for_acl(
                    context, acl_rule_db.acl_id, acl_rule_db, None,
                    rule_removed=True)
                _add_rule = True
            elif new_direction != acl_rule_db.direction:
                acl_id = acl_rule_db.acl_id
                self._process_rule_for_acl(
                    context, acl_rule_db.acl_id, acl_rule_db, None,
                    rule_removed=True)
                _add_rule = True
            elif position is not None and position != acl_rule_db.position:
                self._process_rule_for_acl(
                    context, acl_rule_db.acl_id, acl_rule_db,
                    position, pos_changed=True)

            acl_rule_db.update(acl_rule)
            if _add_rule:
                self._process_rule_for_acl(
                    context, acl_id, acl_rule_db, position)
        return self._make_es_acl_rule_dict(acl_rule_db)

    def delete_es_acl_rule(self, context, es_acl_rule_id):
        """Delete an EayunStack subnet ACL rule."""
        acl_rule_db = self._get_es_acl_rule(context, es_acl_rule_id)
        with context.session.begin(subtransactions=True):
            self._process_rule_for_acl(
                context, acl_rule_db.acl_id, acl_rule_db, None,
                rule_removed=True)
            context.session.delete(acl_rule_db)

    def get_es_acl_rule(self, context, es_acl_rule_id, fields=None):
        """Get an EayunStack subnet ACL rule."""
        acl_rule_db = self._get_es_acl_rule(context, es_acl_rule_id)
        return self._make_es_acl_rule_dict(acl_rule_db, fields)

    def get_es_acl_rules(self, context, filters=None, fields=None,
                         sorts=None, limit=None, marker=None,
                         page_reverse=False):
        """List EayunStack subnet ACL rules."""
        marker_object = self._get_marker_obj(
            context, 'es_acl_rule', limit, marker)
        return self._get_collection(
            context, EsAclRule, self._make_es_acl_rule_dict,
            filters=filters, fields=fields, sorts=sorts,
            limit=limit, marker_obj=marker_object, page_reverse=page_reverse)
