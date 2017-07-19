from neutron.common import rpc as n_rpc
from neutron.common import constants as n_constants
from neutron.plugins.common import constants


class Notifier(object):
    __notifier = None

    @classmethod
    def status_changed(cls, context, resource, resource_id, status):
        if not cls.__notifier:
            Notifier.__notifier = n_rpc.get_notifier('eayun')
        Notifier.__notifier.info(
            context, resource + '.status.changed',
            {resource: {'id': resource_id, 'status': status}})


def eayun_notify(service, obj_model=None):
    def handle_func(func):
        def handle_firewall(
                fw_rpc_callback, context, firewall_id, status, **kwargs
        ):
            ret = func(
                fw_rpc_callback, context, firewall_id, status, **kwargs)
            Notifier.status_changed(context, 'firewall', firewall_id, status)
            return ret

        def handle_ipsec_vpns(
                vpn_plugin, context, service_status_info_list
        ):
            func(vpn_plugin, context, service_status_info_list)
            for vpnservice in service_status_info_list:
                Notifier.status_changed(
                    context, 'vpnservice',
                    vpnservice['id'], vpnservice['status'])
                for conn_id, conn in vpnservice[
                        'ipsec_site_connections'
                ].items():
                    Notifier.status_changed(
                        context, 'ipsec_site_connection',
                        conn_id, conn['status'])

        def handle_loadbalancer(
                lb_rpc_callback, context, obj_type, obj_id, status
        ):
            func(lb_rpc_callback, context, obj_type, obj_id, status)
            if obj_type != 'member':
                Notifier.status_changed(context, obj_type, obj_id, status)

        def handle_lb_member(
                lb_plugin, context, model, obj_id, status, **kwargs
        ):
            func(lb_plugin, context, model, obj_id, status, **kwargs)
            if issubclass(model, obj_model):
                Notifier.status_changed(context, 'member', obj_id, status)

        def handle_pptp_vpn(
                vpn_plugin, context, vpnservice_id, status
        ):
            func(vpn_plugin, context, vpnservice_id, status)
            Notifier.status_changed(
                context, 'vpnservice', vpnservice_id, status)

        def handle_pptp_ports(
                vpn_plugin, context, host, pptp_processes_status,
                credentials, updated_ports, provider
        ):
            func(vpn_plugin, context, host, pptp_processes_status,
                 credentials, updated_ports, provider)
            for port_id, status in updated_ports.iteritems():
                port_status = n_constants.PORT_STATUS_DOWN
                if status:
                    port_status = n_constants.PORT_STATUS_ACTIVE
                Notifier.status_changed(
                    context, 'pptp_port', port_id, port_status)

        if service == constants.FIREWALL:
            return handle_firewall
        elif service == constants.VPN:
            return handle_ipsec_vpns
        elif service == constants.LOADBALANCER:
            return handle_loadbalancer
        elif service == 'LB_MEMBER':
            return handle_lb_member
        elif service == 'PPTP':
            return handle_pptp_vpn
        elif service == 'PPTP_ports':
            return handle_pptp_ports
        else:
            raise NotImplementedError
    return handle_func
