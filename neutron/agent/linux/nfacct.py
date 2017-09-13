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

import json

from neutron.agent.linux import iptables_manager
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)


class NfacctMixin(object):
    """
    The following attributes/methods are not defined in this class:
      * methods
        - self.execute
      * attributes
        - self.root_helper
        - self.namespace
    """
    NFACCT_OBJECT_NAME_LEN = 31

    @staticmethod
    def _get_nfacct_object_name(nfacct_object):
        return nfacct_object[:NfacctMixin.NFACCT_OBJECT_NAME_LEN]

    @staticmethod
    def get_nfacct_rule_part(nfacct_object):
        nfacct_object_name = NfacctMixin._get_nfacct_object_name(nfacct_object)
        return "-m nfacct --nfacct-name %s" % nfacct_object_name

    def _ns_wrap_cmd(self, cmd):
        if self.namespace:
            cmd = ['ip', 'netns', 'exec', self.namespace] + cmd
        return cmd

    def add_nfacct_objects(self, nfacct_objects):
        args_prefix = self._ns_wrap_cmd(['nfacct', 'add'])
        for nfacct_object in nfacct_objects:
            nfacct_object_name = self._get_nfacct_object_name(nfacct_object)
            args = args_prefix + [nfacct_object_name]
            self.execute(args, root_helper=self.root_helper,
                         check_exit_code=False)

    def nfacct_flush(self):
        args = self._ns_wrap_cmd(['nfacct', 'flush'])
        self.execute(args, root_helper=self.root_helper, check_exit_code=False)

    def parse_nfacct_output(self, nfacct_out):
        accs = {}
        for counter in json.loads(nfacct_out)['nfacct_counters']:
            name = counter.pop('name')
            accs[name] = counter
        return accs

    def get_result(self, nfacct_objects):
        args = self._ns_wrap_cmd(['nfacct', 'list', 'reset', 'json'])
        try:
            nfacct_out = self.execute(args, root_helper=self.root_helper)
        except RuntimeError:
            return None

        if not nfacct_out:
            return None

        parsed_accs = self.parse_nfacct_output(nfacct_out)
        ret_accs = {}
        for nfacct_object in nfacct_objects:
            nfacct_object_name = self._get_nfacct_object_name(nfacct_object)
            acc = parsed_accs.get(nfacct_object_name, None)
            if acc:
                ret_accs[nfacct_object] = acc
        return ret_accs


class NfacctIptablesManager(iptables_manager.IptablesManager,
                            NfacctMixin):

    def __init__(self, *args, **kwargs):
        super(NfacctIptablesManager, self).__init__(*args, **kwargs)
        self.nfacct_objects = set()

    def add_nfacct_object(self, object_name):
        self.nfacct_objects.add(object_name)

    def apply(self):
        if self.iptables_apply_deferred:
            return
        self.add_nfacct_objects(self.nfacct_objects)
        self.nfacct_objects = set()
        super(NfacctIptablesManager, self).apply()
        self.nfacct_flush()
