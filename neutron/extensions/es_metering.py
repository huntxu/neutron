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

import abc
import six

from neutron.api import extensions
from neutron.api.v2 import attributes as attr
from neutron.api.v2 import resource_helper
from neutron.common import exceptions
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants
from neutron.services import service_base

LOG = logging.getLogger(__name__)


class RouterNotFound(exceptions.NotFound):
    message = _("Router %(router_id)s does not exist.")


class EsMeteringLabelNotFound(exceptions.NotFound):
    message = _("EsMeteringLabel %(label_id)s does not exist.")


def _validate_tcp_port(data, _valid_values=None):
    msg = None
    if data is not None:
        try:
            val = int(data)
        except(ValueError, TypeError):
            msg = _("Port '%s' is not a valid number") % data
        if val <= 0 or val > 65535:
            msg = _("Invalid port '%s'") % data
        if msg:
            LOG.debug(msg)
            return msg


attr.validators['type:tcp_port_or_none'] = _validate_tcp_port

RESOURCE_ATTRIBUTE_MAP = {
    'es_metering_labels': {
        'id': {'allow_post': False, 'allow_put': False,
               'is_visible': True, 'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'is_visible': True, 'default': ''},
        'description': {'allow_post': True, 'allow_put': True,
                        'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'is_visible': True, 'required_by_policy': True},
        'router_id': {'allow_post': True, 'allow_put': False,
                      'is_visible': True, 'required_by_policy': True,
                      'validate': {'type:uuid': None}},
        'direction': {'allow_post': True, 'allow_put': False,
                      'is_visible': True,
                      'validate': {'type:values': ['ingress', 'egress']}},
        'internal_ip': {'allow_post': True, 'allow_put': False,
                        'is_visible': True, 'default': None,
                        'validate': {'type:subnet_or_none': None}},
        'tcp_port': {'allow_post': True, 'allow_put': False,
                     'is_visible': True, 'default': None,
                     'validate': {'type:tcp_port_or_none': None},
                     'convert_to': attr.convert_to_int_if_not_none}
    }
}


class Es_metering(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "EayunStack Neutron Metering"

    @classmethod
    def get_alias(cls):
        return "es-metering"

    @classmethod
    def get_description(cls):
        return "Eayunstack Neutron Metering extension."

    @classmethod
    def get_namespace(cls):
        return "https://github.com/eayunstack"

    @classmethod
    def get_updated(cls):
        return "2017-02-17:00:00-00:00"

    @classmethod
    def get_plugin_interface(cls):
        return EsMeteringPluginBase

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        plural_mappings = resource_helper.build_plural_mappings(
            {}, RESOURCE_ATTRIBUTE_MAP)
        attr.PLURALS.update(plural_mappings)
        # PCM: Metering sets pagination and sorting to True. Do we have cfg
        # entries for these so can be read? Else, must pass in.
        return resource_helper.build_resource_info(plural_mappings,
                                                   RESOURCE_ATTRIBUTE_MAP,
                                                   constants.METERING,
                                                   translate_name=True,
                                                   allow_bulk=True)

    def update_attributes_map(self, extended_attributes,
                              extension_attrs_map=None):
        super(Es_metering, self).update_attributes_map(
            extended_attributes, extension_attrs_map=RESOURCE_ATTRIBUTE_MAP)

    def get_extended_resources(self, version):
        return RESOURCE_ATTRIBUTE_MAP if version == "2.0" else {}


@six.add_metaclass(abc.ABCMeta)
class EsMeteringPluginBase(service_base.ServicePluginBase):

    def get_plugin_name(self):
        return constants.ES_METERING

    def get_plugin_description(self):
        return constants.ES_METERING

    def get_plugin_type(self):
        return constants.ES_METERING

    @abc.abstractmethod
    def create_es_metering_label(self, context, es_metering_label):
        """Create an EayunStack metering label."""
        pass

    @abc.abstractmethod
    def update_es_metering_label(self, context, label_id, es_metering_label):
        """Update an EayunStack metering label."""
        pass

    @abc.abstractmethod
    def delete_es_metering_label(self, context, label_id):
        """Delete an EayunStack metering label."""
        pass

    @abc.abstractmethod
    def get_es_metering_label(self, context, label_id, fields=None):
        """Get an EayunStack metering label."""
        pass

    @abc.abstractmethod
    def get_es_metering_labels(self, context, filters=None, fields=None,
                               sorts=None, limit=None, marker=None,
                               page_reverse=False):
        """List all EayunStack metering labels."""
        pass
