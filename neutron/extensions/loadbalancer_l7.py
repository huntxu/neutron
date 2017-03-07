# Copyright 2012 OpenStack Foundation.
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

import abc

from oslo.config import cfg
import six

from neutron.api import extensions
from neutron.api.v2 import attributes as attr
from neutron.api.v2 import base
from neutron.api.v2 import resource_helper
from neutron.common import exceptions as qexception
from neutron import manager
from neutron.plugins.common import constants
from neutron.services import service_base


# Loadbalancer L7 Exceptions
class L7policyNotFound(qexception.NotFound):
    message = _("L7policy %(l7policy_id)s could not be found")


class L7policyInUse(qexception.BadRequest):
    message = _("L7policy %(l7policy_id)s still used by l7rule %(l7rules)s")


class L7policyActionKeyValueNotSupport(qexception.BadRequest):
    message = _("L7policy action %(l7policy_action)s with key %(l7policy_key)s"
                "and value %(l7policy_value)s does not support")


class L7ruleNotFound(qexception.NotFound):
    message = _("L7rule %(l7rule_id)s could not be found")


class L7ruleInUse(qexception.NotFound):
    message = _("L7rule %(l7rule_id)s still in use")


class L7ruleTypeKeyValueNotSupport(qexception.BadRequest):
    message = _("L7rule type %(l7rule_type)s with key %(l7rule_key)s"
                "and value %(l7rule_value)s dose not support")


class L7ruleCompareTypeValueNotSupport(qexception.BadRequest):
    message = _("L7rule compare_type %(l7rule_compare_type)s with "
                "compare value %(l7_rule_compare_value)s dose not support")


class L7policyRuleAssociationExists(qexception.BadRequest):
    message = _("L7policy %(policy_id)s is already associated"
                "with L7rule %(rule_id)s")


class L7policyRuleAssociationNotFound(qexception.NotFound):
    message = _("L7policy %(policy_id)s is not associated"
                "with L7rule %(rule_id)s")


RESOURCE_ATTRIBUTE_MAP = {
    'l7policies': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True,
                      'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'default': '',
                 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string': None},
                        'is_visible': True, 'default': ''},
        'pool_id': {'allow_post': True, 'allow_put': True,
                    'validate': {'type:uuid': None},
                    'is_visible': True},
        'priority': {'allow_post': True, 'allow_put': True,
                     'validate': {'type:range': [0, 255]},
                     'is_visible': True},
        'action': {'allow_post': True, 'allow_put': False,
                   'validate': {
                       'type:values': constants.LOADBALANCER_L7POLICY_ACTIONS
                   },
                   'is_visible': True},
        'key': {'allow_post': True, 'allow_put': False,
                'validate': {'type:string_or_none': None},
                'default': None, 'is_visible': True},
        'value': {'allow_post': True, 'allow_put': False,
                  'validate': {'type:string_or_none': None},
                  'default': None, 'is_visible': True},
        'admin_state_up': {'allow_post': True, 'allow_put': True,
                           'default': True,
                           'convert_to': attr.convert_to_boolean,
                           'is_visible': True},
    },
    'l7rules': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True,
                      'is_visible': True},
        'type': {'allow_post': True, 'allow_put': False,
                 'validate': {
                     'type:values': constants.LOADBALANCER_L7RULE_TYPES
                 },
                 'is_visible': True},
        'compare_type': {'allow_post': True, 'allow_put': False,
                         'validate': {
                             'type:values':
                             constants.LOADBALANCER_L7RULE_COMPARE_TYPES
                         },
                         'is_visible': True},
        'compare_value': {'allow_post': True, 'allow_put': True,
                          'validate': {'type:string_or_none': None},
                          'default': None, 'is_visible': True},
        'key': {'allow_post': True, 'allow_put': False,
                'validate': {'type:string_or_none': None},
                'default': None, 'is_visible': True},
        'value': {'allow_post': True, 'allow_put': True,
                  'validate': {'type:string_or_none': None},
                  'default': None, 'is_visible': True},
        'admin_state_up': {'allow_post': True, 'allow_put': True,
                           'default': True,
                           'convert_to': attr.convert_to_boolean,
                           'is_visible': True},
    },
}

SUB_RESOURCE_ATTRIBUTE_MAP = {
    'l7rules': {
        'parent': {'collection_name': 'l7policies',
                   'member_name': 'l7policy'},
        'parameters': {'id': {'allow_post': True, 'allow_put': False,
                              'validate': {'type:uuid': None},
                              'is_visible': True},
                       'tenant_id': {'allow_post': True, 'allow_put': False,
                                     'validate': {'type:string': None},
                                     'required_by_policy': True,
                                     'is_visible': True},
                       }
    }
}

lbaas_quota_opts = [
    cfg.IntOpt('quota_l7policy',
               default=10,
               help=_('Number of l7policy allowed per tenant. '
                      'A negative value means unlimited.')),
    cfg.IntOpt('quota_l7rule',
               default=10,
               help=_('Number of l7rule allowed per tenant. '
                      'A negative value means unlimited.')),
]
cfg.CONF.register_opts(lbaas_quota_opts, 'QUOTAS')


class Loadbalancer_l7(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "LoadBalancing l7 service"

    @classmethod
    def get_alias(cls):
        return "lbaas_l7"

    @classmethod
    def get_description(cls):
        return "Extension for LoadBalancing l7 service"

    @classmethod
    def get_namespace(cls):
        return "http://wiki.openstack.org/neutron/LBaaS/API_1.0"

    @classmethod
    def get_updated(cls):
        return "2017-02-13T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        l7_plurals = {'l7policies': 'l7policy', 'l7rules': 'l7rule'}
        plural_mappings = resource_helper.build_plural_mappings(
            l7_plurals, RESOURCE_ATTRIBUTE_MAP)
        attr.PLURALS.update(plural_mappings)
        resources = resource_helper.build_resource_info(plural_mappings,
                                                        RESOURCE_ATTRIBUTE_MAP,
                                                        constants.LOADBALANCER,
                                                        register_quota=True)
        plugin = manager.NeutronManager.get_service_plugins()[
            constants.LOADBALANCER]
        for collection_name in SUB_RESOURCE_ATTRIBUTE_MAP:
            # Special handling needed for sub-resources with 'y' ending
            # (e.g. proxies -> proxy)
            resource_name = collection_name[:-1]
            parent = SUB_RESOURCE_ATTRIBUTE_MAP[collection_name].get('parent')
            params = SUB_RESOURCE_ATTRIBUTE_MAP[collection_name].get(
                'parameters')

            controller = base.create_resource(collection_name, resource_name,
                                              plugin, params,
                                              allow_bulk=True,
                                              parent=parent)

            resource = extensions.ResourceExtension(
                collection_name,
                controller, parent,
                path_prefix=constants.COMMON_PREFIXES[constants.LOADBALANCER],
                attr_map=params)
            resources.append(resource)

        return resources

    def update_attributes_map(self, attributes):
        super(Loadbalancer_l7, self).update_attributes_map(
            attributes, extension_attrs_map=RESOURCE_ATTRIBUTE_MAP)

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}


class LoadbalancerL7Base(object):
    """
    Rest API for lbaas l7 policy/rule
    """

    @abc.abstractmethod
    def create_l7policy(self, context, policy):
        pass

    @abc.abstractmethod
    def update_l7policy(self, context, id, policy):
        pass

    @abc.abstractmethod
    def get_l7policy(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def get_l7policies(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def delete_l7policy(self, context, id):
        pass

    @abc.abstractmethod
    def create_l7rule(self, context, rule):
        pass

    @abc.abstractmethod
    def update_l7rule(self, context, id, policy):
        pass

    @abc.abstractmethod
    def get_l7rule(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def get_l7rules(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def delete_l7rule(self, context, id):
        pass

    @abc.abstractmethod
    def delete_l7rule(self, context, id):
        pass

    @abc.abstractmethod
    def create_l7policy_l7rule(self, context, rule, l7policy_id):
        pass

    @abc.abstractmethod
    def delete_l7policy_l7rule(self, context, id, l7policy_id):
        pass

    @abc.abstractmethod
    def get_l7policy_l7rule(self, context, id, l7policy_id, fields=None):
        pass
