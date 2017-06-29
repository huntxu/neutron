# Copyright 2013 New Dream Network, LLC (DreamHost)
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

import itertools
import netaddr
from six import moves

from neutron.agent.linux import utils
from neutron.openstack.common import jsonutils
from neutron.plugins.common import constants as qconstants
from neutron.services.loadbalancer import constants


PROTOCOL_MAP = {
    constants.PROTOCOL_TCP: 'tcp',
    constants.PROTOCOL_HTTP: 'http',
    constants.PROTOCOL_HTTPS: 'tcp',
}

BALANCE_MAP = {
    constants.LB_METHOD_ROUND_ROBIN: 'roundrobin',
    constants.LB_METHOD_LEAST_CONNECTIONS: 'leastconn',
    constants.LB_METHOD_SOURCE_IP: 'source'
}

STATS_MAP = {
    constants.STATS_ACTIVE_CONNECTIONS: 'scur',
    constants.STATS_MAX_CONNECTIONS: 'smax',
    constants.STATS_CURRENT_SESSIONS: 'scur',
    constants.STATS_MAX_SESSIONS: 'smax',
    constants.STATS_TOTAL_CONNECTIONS: 'stot',
    constants.STATS_TOTAL_SESSIONS: 'stot',
    constants.STATS_IN_BYTES: 'bin',
    constants.STATS_OUT_BYTES: 'bout',
    constants.STATS_CONNECTION_ERRORS: 'econ',
    constants.STATS_RESPONSE_ERRORS: 'eresp'
}

ACL_TYPE_MAP = {
    'backendServerId': 'srv_id',
}

ACL_COMPARE_MAP = {
    'integerEq': 'eq %(compare_value)s',
}

POLICY_ACTION_MAP = {
    'block': 'block',
    'redirect': 'redirect location %(value)s',
    'addHeader': 'rspadd %(value)s',
}

ACTIVE_PENDING_STATUSES = qconstants.ACTIVE_PENDING_STATUSES
INACTIVE = qconstants.INACTIVE
ACL_RULE_ID_LENGTH = 9
ACL_RULE_NAME_LENGTH = 12


def save_config(conf_path, logical_config, socket_path=None,
                user_group='nogroup'):
    """Convert a logical configuration to the HAProxy version."""
    data = []
    data.extend(_build_global(logical_config, socket_path=socket_path,
                              user_group=user_group))
    data.extend(_build_defaults(logical_config))
    data.extend(_build_frontend(logical_config))
    data.extend(_build_backend(logical_config))
    utils.replace_file(conf_path, '\n'.join(data))


def _build_global(config, socket_path=None, user_group='nogroup'):
    opts = [
        'daemon',
        'user nobody',
        'group %s' % user_group,
        'log /dev/log local0',
        'log /dev/log local1 notice'
    ]

    if socket_path:
        opts.append('stats socket %s mode 0666 level user' % socket_path)

    return itertools.chain(['global'], ('\t' + o for o in opts))


def _build_defaults(config):
    opts = [
        'log global',
        'retries 3',
        'option redispatch',
        'timeout connect 5000',
        'timeout client 50000',
        'timeout server 50000',
    ]

    return itertools.chain(['defaults'], ('\t' + o for o in opts))


def _build_frontend(config):
    protocol = config['vip']['protocol']

    opts = [
        'option tcplog',
        'bind %s:%d' % (
            _get_first_ip_from_port(config['vip']['port']),
            config['vip']['protocol_port']
        ),
        'mode %s' % PROTOCOL_MAP[protocol],
        'default_backend %s' % config['pool']['id'],
    ]

    if config['vip']['connection_limit'] >= 0:
        opts.append('maxconn %s' % config['vip']['connection_limit'])

    if protocol == constants.PROTOCOL_HTTP:
        opts.append('option forwardfor')

    return itertools.chain(
        ['frontend %s' % config['vip']['id']],
        ('\t' + o for o in opts)
    )


def _sort_members_by_priority_or_ip_port(members):
    def _cmp_member(a, b):
        return (
            (int(a['priority']) - int(b['priority'])) or
            (int(netaddr.IPAddress(a['address'])) -
             int(netaddr.IPAddress(b['address']))) or
            (int(a['protocol_port']) - int(b['protocol_port']))
        )

    members.sort(cmp=_cmp_member)
    return members


def _get_acl_name(rule):
    return ('acl_' + rule['id'])[:ACL_RULE_NAME_LENGTH]


def _get_acl_member_id(id):
    # Max id is 2**31 -1
    return int(('0x' + id)[:ACL_RULE_ID_LENGTH], base=16)


def _update_backserver_value(rule):
    rule['value'] = _get_acl_member_id(rule['value'])


def _build_acl(rule):
    type_value_convert_map = {
        'backendServerId': _update_backserver_value,
    }

    acl_name = 'acl %s' % _get_acl_name(rule)

    rule_updater = type_value_convert_map.get(rule['type'], lambda rule: rule)
    rule_updater(rule)

    acl_match = ACL_TYPE_MAP[rule['type']] % rule
    acl_compare = ACL_COMPARE_MAP[rule['compare_type']] % rule

    return ' '.join([acl_name, acl_match, acl_compare])


def _build_policy_action(policy, rule):
    kws = {
        'value': policy['value'].replace(' ', '\ ') if policy['value'] else ''
    }
    acl = POLICY_ACTION_MAP[policy['action']] % kws

    # add condition
    acl += ' if %s' % _get_acl_name(rule)
    return acl


def _sort_policy_by_priority(policies):
    def _cmp_policies(a, b):
        return int(a['policy']['priority']) - int(b['policy']['priority'])

    policies.sort(cmp=_cmp_policies)
    return policies


def _build_policy_and_acl(config):
    opts = []
    need_add_server_id = False
    policies = config['l7policies']
    policies = _sort_policy_by_priority(policies)

    for policy in policies:
        for rule in policy['rules']:
            if rule['type'] == 'backendServerId':
                need_add_server_id = True

            opts.append(_build_acl(rule))
            opts.append(_build_policy_action(policy['policy'], rule))
    return need_add_server_id, opts


def _build_extra_action_for_member(extra_action, member):
    opts = []

    # extra_action format: {'set_cookie_for_member': {'max_age': 15}}
    member_cookie_params = extra_action.get('set_cookie_for_member')
    if member_cookie_params and 'max_age' in member_cookie_params:
        # build acl and policy
        # set cookie for member acl and policy template
        rule = {
            'id': member['id'],
            'value': member['id'],
            'type': 'backendServerId',
            'compare_type': 'integerEq',
            'compare_value': _get_acl_member_id(member['id']),
        }
        policy = {
            'action': 'addHeader',
            'value': (
                'Set-Cookie: %(cookie_name)s=%(id)s; Max-Age=%(max_age)s' %
                {'cookie_name': extra_action['cookie_name'],
                 'id': member['id'],
                 'max_age': member_cookie_params['max_age']}),
        }
        opts.append(_build_acl(rule))
        opts.append(_build_policy_action(policy, rule))

    return opts


def _build_backend(config):
    protocol = config['pool']['protocol']
    lb_method = config['pool']['lb_method']

    opts = [
        'mode %s' % PROTOCOL_MAP[protocol],
        'balance %s' % BALANCE_MAP.get(lb_method, 'roundrobin')
    ]
    extra_opts = []

    if protocol == constants.PROTOCOL_HTTP:
        opts.append('option forwardfor')

    # add the first health_monitor (if available)
    server_addon, health_opts = _get_server_health_option(config)
    opts.extend(health_opts)

    # add session persistence (if available)
    extra_action, persist_opts = _get_session_persistence(config)
    opts.extend(persist_opts)

    # backup members need resort
    config['members'] = _sort_members_by_priority_or_ip_port(config['members'])
    # policy and acls
    need_server_id, policy_opts = _build_policy_and_acl(config)
    opts.extend(policy_opts)

    # add the members
    member_opts = []
    for member in config['members']:
        if ((member['status'] in ACTIVE_PENDING_STATUSES or
             member['status'] == INACTIVE)
            and member['admin_state_up']):
            server = (('server %(id)s %(address)s:%(protocol_port)s '
                       'weight %(weight)s') % member) + server_addon
            if member['priority'] < 256:
                server += ' backup'

            if extra_action:
                extra_opts.extend(
                    _build_extra_action_for_member(extra_action, member)
                )
                need_server_id = True

            if need_server_id:
                server += ' id %d' % _get_acl_member_id(member['id'])

            # add health check address and port opt
            if member['monitor_address'] is not None:
                server += ' addr %s' % member['monitor_address']
            if member['monitor_port'] is not None:
                server += ' port %s' % member['monitor_port']

            if _has_http_cookie_persistence(config):
                server += ' cookie %d' % config['members'].index(member)
            member_opts.append(server)

    # add extra action opts
    opts.extend(extra_opts)
    # add member opts
    opts.extend(member_opts)

    return itertools.chain(
        ['backend %s' % config['pool']['id']],
        ('\t' + o for o in opts)
    )


def _get_first_ip_from_port(port):
    for fixed_ip in port['fixed_ips']:
        return fixed_ip['ip_address']


def _get_server_health_option(config):
    """return the first active health option."""
    for monitor in config['healthmonitors']:
        # not checking the status of healthmonitor for two reasons:
        # 1) status field is absent in HealthMonitor model
        # 2) only active HealthMonitors are fetched with
        # LoadBalancerCallbacks.get_logical_device
        if monitor['admin_state_up']:
            break
    else:
        return '', []

    server_addon = ' check inter %(delay)ds fall %(max_retries)d' % monitor
    opts = [
        'timeout check %ds' % monitor['timeout']
    ]

    if monitor['type'] in (constants.HEALTH_MONITOR_HTTP,
                           constants.HEALTH_MONITOR_HTTPS):
        opts.append('option httpchk %(http_method)s %(url_path)s' % monitor)
        opts.append(
            'http-check expect rstatus %s' %
            '|'.join(_expand_expected_codes(monitor['expected_codes']))
        )

    if monitor['type'] == constants.HEALTH_MONITOR_HTTPS:
        opts.append('option ssl-hello-chk')

    return server_addon, opts


def _get_session_persistence(config):
    persistence = config['vip'].get('session_persistence')
    extra_action = {}

    if not persistence:
        return extra_action, []

    opts = []
    if persistence['type'] == constants.SESSION_PERSISTENCE_SOURCE_IP:
        opts.append('stick-table type ip size 10k')
        opts.append('stick on src')
    elif (persistence['type'] == constants.SESSION_PERSISTENCE_HTTP_COOKIE and
          config.get('members')):
        opts.append('cookie SRV insert indirect nocache')
    elif (persistence['type'] == constants.SESSION_PERSISTENCE_APP_COOKIE and
          persistence.get('cookie_name')):
        opts.append('appsession %s len 56 timeout 3h' %
                    persistence['cookie_name'])

        # convert to dict if exists
        if persistence.get('extra_actions'):
            extra_action = jsonutils.loads(persistence.get('extra_actions'))
            # push cookie_name to extra_action
            extra_action['cookie_name'] = persistence.get('cookie_name')

    return extra_action, opts


def _has_http_cookie_persistence(config):
    return (config['vip'].get('session_persistence') and
            config['vip']['session_persistence']['type'] ==
            constants.SESSION_PERSISTENCE_HTTP_COOKIE)


def _expand_expected_codes(codes):
    """Expand the expected code string in set of codes.

    200-204 -> 200, 201, 202, 204
    200, 203 -> 200, 203
    """

    retval = set()
    for code in codes.replace(',', ' ').split(' '):
        code = code.strip()

        if not code:
            continue
        elif '-' in code:
            low, hi = code.split('-')[:2]
            retval.update(str(i) for i in moves.xrange(int(low), int(hi) + 1))
        else:
            retval.add(code)
    return retval
