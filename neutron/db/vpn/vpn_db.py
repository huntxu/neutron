#    (c) Copyright 2013 Hewlett-Packard Development Company, L.P.
#    All Rights Reserved.
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

import netaddr
import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm import exc

from neutron.api.v2 import attributes as attr
from neutron.common import constants as n_constants
from neutron.common import exceptions as n_exc
from neutron.db import common_db_mixin as base_db
from neutron.db import l3_agentschedulers_db as l3_agent_db
from neutron.db import l3_db
from neutron.db import model_base
from neutron.db import models_v2
from neutron.db import servicetype_db as st_db
from neutron.db.vpn import vpn_validator
from neutron.extensions import vpnaas
from neutron import manager
from neutron.openstack.common import excutils
from neutron.openstack.common import log as logging
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants
from neutron.plugins.common import utils

LOG = logging.getLogger(__name__)


class IPsecPeerCidr(model_base.BASEV2):
    """Internal representation of a IPsec Peer Cidrs."""

    cidr = sa.Column(sa.String(32), nullable=False, primary_key=True)
    ipsec_site_connection_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('ipsec_site_connections.id',
                      ondelete="CASCADE"),
        primary_key=True)


class IPsecPolicy(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a v2 IPsecPolicy Object."""
    __tablename__ = 'ipsecpolicies'
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(255))
    transform_protocol = sa.Column(sa.Enum("esp", "ah", "ah-esp",
                                           name="ipsec_transform_protocols"),
                                   nullable=False)
    auth_algorithm = sa.Column(sa.Enum("sha1",
                                       name="vpn_auth_algorithms"),
                               nullable=False)
    encryption_algorithm = sa.Column(sa.Enum("3des", "aes-128",
                                             "aes-256", "aes-192",
                                             name="vpn_encrypt_algorithms"),
                                     nullable=False)
    encapsulation_mode = sa.Column(sa.Enum("tunnel", "transport",
                                           name="ipsec_encapsulations"),
                                   nullable=False)
    lifetime_units = sa.Column(sa.Enum("seconds", "kilobytes",
                                       name="vpn_lifetime_units"),
                               nullable=False)
    lifetime_value = sa.Column(sa.Integer, nullable=False)
    pfs = sa.Column(sa.Enum("group2", "group5", "group14",
                            name="vpn_pfs"), nullable=False)


class IKEPolicy(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a v2 IKEPolicy Object."""
    __tablename__ = 'ikepolicies'
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(255))
    auth_algorithm = sa.Column(sa.Enum("sha1",
                                       name="vpn_auth_algorithms"),
                               nullable=False)
    encryption_algorithm = sa.Column(sa.Enum("3des", "aes-128",
                                             "aes-256", "aes-192",
                                             name="vpn_encrypt_algorithms"),
                                     nullable=False)
    phase1_negotiation_mode = sa.Column(sa.Enum("main",
                                                name="ike_phase1_mode"),
                                        nullable=False)
    lifetime_units = sa.Column(sa.Enum("seconds", "kilobytes",
                                       name="vpn_lifetime_units"),
                               nullable=False)
    lifetime_value = sa.Column(sa.Integer, nullable=False)
    ike_version = sa.Column(sa.Enum("v1", "v2", name="ike_versions"),
                            nullable=False)
    pfs = sa.Column(sa.Enum("group2", "group5", "group14",
                            name="vpn_pfs"), nullable=False)


class IPsecSiteConnection(model_base.BASEV2,
                          models_v2.HasId, models_v2.HasTenant):
    """Represents a IPsecSiteConnection Object."""
    __tablename__ = 'ipsec_site_connections'
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(255))
    peer_address = sa.Column(sa.String(255), nullable=False)
    peer_id = sa.Column(sa.String(255), nullable=False)
    route_mode = sa.Column(sa.String(8), nullable=False)
    mtu = sa.Column(sa.Integer, nullable=False)
    initiator = sa.Column(sa.Enum("bi-directional", "response-only",
                                  name="vpn_initiators"), nullable=False)
    auth_mode = sa.Column(sa.String(16), nullable=False)
    psk = sa.Column(sa.String(255), nullable=False)
    dpd_action = sa.Column(sa.Enum("hold", "clear", "restart",
                                   name="vpn_dpd_actions"),
                           nullable=False)
    dpd_interval = sa.Column(sa.Integer, nullable=False)
    dpd_timeout = sa.Column(sa.Integer, nullable=False)
    status = sa.Column(sa.String(16), nullable=False)
    admin_state_up = sa.Column(sa.Boolean(), nullable=False)
    vpnservice_id = sa.Column(sa.String(36),
                              sa.ForeignKey('vpnservices.id'),
                              nullable=False)
    ipsecpolicy_id = sa.Column(sa.String(36),
                               sa.ForeignKey('ipsecpolicies.id'),
                               nullable=False)
    ikepolicy_id = sa.Column(sa.String(36),
                             sa.ForeignKey('ikepolicies.id'),
                             nullable=False)
    ipsecpolicy = orm.relationship(
        IPsecPolicy, backref='ipsec_site_connection')
    ikepolicy = orm.relationship(IKEPolicy, backref='ipsec_site_connection')
    peer_cidrs = orm.relationship(IPsecPeerCidr,
                                  backref='ipsec_site_connection',
                                  lazy='joined',
                                  cascade='all, delete, delete-orphan')


class VPNService(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a v2 VPNService Object."""
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(255))
    status = sa.Column(sa.String(16), nullable=False)
    admin_state_up = sa.Column(sa.Boolean(), nullable=False)
    subnet_id = sa.Column(sa.String(36), sa.ForeignKey('subnets.id'),
                          nullable=False)
    router_id = sa.Column(sa.String(36), sa.ForeignKey('routers.id'),
                          nullable=False)
    subnet = orm.relationship(models_v2.Subnet)
    router = orm.relationship(l3_db.Router)
    ipsec_site_connections = orm.relationship(
        IPsecSiteConnection,
        backref='vpnservice',
        cascade="all, delete-orphan")
    provider = orm.relationship(
        st_db.ProviderResourceAssociation,
        uselist=False,
        lazy="joined",
        primaryjoin="VPNService.id==ProviderResourceAssociation.resource_id",
        foreign_keys=[st_db.ProviderResourceAssociation.resource_id]
    )


class PPTPCredential(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a PPTPCredential object."""
    __tablename__ = 'pptp_credentials'
    username = sa.Column(sa.String(255), nullable=False)
    password = sa.Column(sa.String(255), nullable=False)


class PPTPCredentialServiceAssociation(model_base.BASEV2):
    """Many-to-many association between PPTP credential and VPN service."""
    pptp_credential_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('pptp_credentials.id', ondelete='CASCADE'),
        primary_key=True)
    vpnservice_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('vpnservices.id', ondelete='CASCADE'),
        primary_key=True)
    port_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('ports.id', ondelete='CASCADE'),
        primary_key=True)
    pptp_credentials = orm.relationship(
        PPTPCredential,
        backref=orm.backref('associations',
                            lazy='joined', cascade='delete'))


class VPNPluginDb(vpnaas.VPNPluginBase, base_db.CommonDbMixin):
    """VPN plugin database class using SQLAlchemy models."""

    @property
    def _core_plugin(self):
        return manager.NeutronManager.get_plugin()

    def _get_validator(self, provider=None):
        """Obtain validator to use for attribute validation.

        Subclasses may override this with a different valdiator, as needed.
        Note: some UTs will directly create a VPNPluginDb object and then
        call its methods, instead of creating a VPNDriverPlugin, which
        will have a service driver associated that will provide a
        validator object. As a result, we use the reference validator here.
        """
        return vpn_validator.VpnReferenceValidator()

    def update_status(self, context, model, v_id, status):
        with context.session.begin(subtransactions=True):
            v_db = self._get_resource(context, model, v_id)
            v_db.update({'status': status})

    def _get_resource(self, context, model, v_id):
        try:
            r = self._get_by_id(context, model, v_id)
        except exc.NoResultFound:
            with excutils.save_and_reraise_exception(reraise=False) as ctx:
                if issubclass(model, IPsecSiteConnection):
                    raise vpnaas.IPsecSiteConnectionNotFound(
                        ipsec_site_conn_id=v_id
                    )
                elif issubclass(model, IKEPolicy):
                    raise vpnaas.IKEPolicyNotFound(ikepolicy_id=v_id)
                elif issubclass(model, IPsecPolicy):
                    raise vpnaas.IPsecPolicyNotFound(ipsecpolicy_id=v_id)
                elif issubclass(model, VPNService):
                    raise vpnaas.VPNServiceNotFound(vpnservice_id=v_id)
                ctx.reraise = True
        return r

    def assert_update_allowed(self, obj):
        status = getattr(obj, 'status', None)
        _id = getattr(obj, 'id', None)
        if utils.in_pending_status(status):
            raise vpnaas.VPNStateInvalidToUpdate(id=_id, state=status)

    def _make_ipsec_site_connection_dict(self, ipsec_site_conn, fields=None):

        res = {'id': ipsec_site_conn['id'],
               'tenant_id': ipsec_site_conn['tenant_id'],
               'name': ipsec_site_conn['name'],
               'description': ipsec_site_conn['description'],
               'peer_address': ipsec_site_conn['peer_address'],
               'peer_id': ipsec_site_conn['peer_id'],
               'route_mode': ipsec_site_conn['route_mode'],
               'mtu': ipsec_site_conn['mtu'],
               'auth_mode': ipsec_site_conn['auth_mode'],
               'psk': ipsec_site_conn['psk'],
               'initiator': ipsec_site_conn['initiator'],
               'dpd': {
                   'action': ipsec_site_conn['dpd_action'],
                   'interval': ipsec_site_conn['dpd_interval'],
                   'timeout': ipsec_site_conn['dpd_timeout']
               },
               'admin_state_up': ipsec_site_conn['admin_state_up'],
               'status': ipsec_site_conn['status'],
               'vpnservice_id': ipsec_site_conn['vpnservice_id'],
               'ikepolicy_id': ipsec_site_conn['ikepolicy_id'],
               'ipsecpolicy_id': ipsec_site_conn['ipsecpolicy_id'],
               'peer_cidrs': [pcidr['cidr']
                              for pcidr in ipsec_site_conn['peer_cidrs']]
               }

        return self._fields(res, fields)

    def _get_subnet_ip_version(self, context, vpnservice_id):
        vpn_service_db = self._get_vpnservice(context, vpnservice_id)
        subnet = vpn_service_db.subnet['cidr']
        ip_version = netaddr.IPNetwork(subnet).version
        return ip_version

    def create_ipsec_site_connection(self, context, ipsec_site_connection,
                                     validator=None):
        ipsec_sitecon = ipsec_site_connection['ipsec_site_connection']
        validator = validator or self._get_validator()
        validator.assign_sensible_ipsec_sitecon_defaults(ipsec_sitecon)
        tenant_id = self._get_tenant_id_for_create(context, ipsec_sitecon)
        with context.session.begin(subtransactions=True):
            #Check permissions
            self._get_resource(context,
                               VPNService,
                               ipsec_sitecon['vpnservice_id'])
            self._get_resource(context,
                               IKEPolicy,
                               ipsec_sitecon['ikepolicy_id'])
            self._get_resource(context,
                               IPsecPolicy,
                               ipsec_sitecon['ipsecpolicy_id'])
            vpnservice_id = ipsec_sitecon['vpnservice_id']
            ip_version = self._get_subnet_ip_version(context, vpnservice_id)
            validator.validate_ipsec_site_connection(context,
                                                     ipsec_sitecon,
                                                     ip_version)
            ipsec_site_conn_db = IPsecSiteConnection(
                id=uuidutils.generate_uuid(),
                tenant_id=tenant_id,
                name=ipsec_sitecon['name'],
                description=ipsec_sitecon['description'],
                peer_address=ipsec_sitecon['peer_address'],
                peer_id=ipsec_sitecon['peer_id'],
                route_mode='static',
                mtu=ipsec_sitecon['mtu'],
                auth_mode='psk',
                psk=ipsec_sitecon['psk'],
                initiator=ipsec_sitecon['initiator'],
                dpd_action=ipsec_sitecon['dpd_action'],
                dpd_interval=ipsec_sitecon['dpd_interval'],
                dpd_timeout=ipsec_sitecon['dpd_timeout'],
                admin_state_up=ipsec_sitecon['admin_state_up'],
                status=constants.PENDING_CREATE,
                vpnservice_id=vpnservice_id,
                ikepolicy_id=ipsec_sitecon['ikepolicy_id'],
                ipsecpolicy_id=ipsec_sitecon['ipsecpolicy_id']
            )
            context.session.add(ipsec_site_conn_db)
            for cidr in ipsec_sitecon['peer_cidrs']:
                peer_cidr_db = IPsecPeerCidr(
                    cidr=cidr,
                    ipsec_site_connection_id=ipsec_site_conn_db['id']
                )
                context.session.add(peer_cidr_db)
        return self._make_ipsec_site_connection_dict(ipsec_site_conn_db)

    def update_ipsec_site_connection(
            self, context,
            ipsec_site_conn_id, ipsec_site_connection, validator=None):
        ipsec_sitecon = ipsec_site_connection['ipsec_site_connection']
        changed_peer_cidrs = False
        validator = validator or self._get_validator()
        with context.session.begin(subtransactions=True):
            ipsec_site_conn_db = self._get_resource(
                context,
                IPsecSiteConnection,
                ipsec_site_conn_id)
            vpnservice_id = ipsec_site_conn_db['vpnservice_id']
            ip_version = self._get_subnet_ip_version(context, vpnservice_id)
            validator.assign_sensible_ipsec_sitecon_defaults(
                ipsec_sitecon, ipsec_site_conn_db)
            validator.validate_ipsec_site_connection(
                context,
                ipsec_sitecon,
                ip_version)
            self.assert_update_allowed(ipsec_site_conn_db)

            if "peer_cidrs" in ipsec_sitecon:
                changed_peer_cidrs = True
                old_peer_cidr_list = ipsec_site_conn_db['peer_cidrs']
                old_peer_cidr_dict = dict(
                    (peer_cidr['cidr'], peer_cidr)
                    for peer_cidr in old_peer_cidr_list)
                new_peer_cidr_set = set(ipsec_sitecon["peer_cidrs"])
                old_peer_cidr_set = set(old_peer_cidr_dict)

                new_peer_cidrs = list(new_peer_cidr_set)
                for peer_cidr in old_peer_cidr_set - new_peer_cidr_set:
                    context.session.delete(old_peer_cidr_dict[peer_cidr])
                for peer_cidr in new_peer_cidr_set - old_peer_cidr_set:
                    pcidr = IPsecPeerCidr(
                        cidr=peer_cidr,
                        ipsec_site_connection_id=ipsec_site_conn_id)
                    context.session.add(pcidr)
                del ipsec_sitecon["peer_cidrs"]
            if ipsec_sitecon:
                ipsec_site_conn_db.update(ipsec_sitecon)
        result = self._make_ipsec_site_connection_dict(ipsec_site_conn_db)
        if changed_peer_cidrs:
            result['peer_cidrs'] = new_peer_cidrs
        return result

    def delete_ipsec_site_connection(self, context, ipsec_site_conn_id):
        with context.session.begin(subtransactions=True):
            ipsec_site_conn_db = self._get_resource(
                context, IPsecSiteConnection, ipsec_site_conn_id
            )
            context.session.delete(ipsec_site_conn_db)

    def _get_ipsec_site_connection(
            self, context, ipsec_site_conn_id):
        return self._get_resource(
            context, IPsecSiteConnection, ipsec_site_conn_id)

    def get_ipsec_site_connection(self, context,
                                  ipsec_site_conn_id, fields=None):
        ipsec_site_conn_db = self._get_ipsec_site_connection(
            context, ipsec_site_conn_id)
        return self._make_ipsec_site_connection_dict(
            ipsec_site_conn_db, fields)

    def get_ipsec_site_connections(self, context, filters=None, fields=None):
        return self._get_collection(context, IPsecSiteConnection,
                                    self._make_ipsec_site_connection_dict,
                                    filters=filters, fields=fields)

    def update_ipsec_site_conn_status(self, context, conn_id, new_status):
        with context.session.begin():
            self._update_connection_status(context, conn_id, new_status, True)

    def _update_connection_status(self, context, conn_id, new_status,
                                  updated_pending):
        """Update the connection status, if changed.

        If the connection is not in a pending state, unconditionally update
        the status. Likewise, if in a pending state, and have an indication
        that the status has changed, then update the database.
        """
        try:
            conn_db = self._get_ipsec_site_connection(context, conn_id)
        except vpnaas.IPsecSiteConnectionNotFound:
            return
        if not utils.in_pending_status(conn_db.status) or updated_pending:
            conn_db.status = new_status

    def _make_ikepolicy_dict(self, ikepolicy, fields=None):
        res = {'id': ikepolicy['id'],
               'tenant_id': ikepolicy['tenant_id'],
               'name': ikepolicy['name'],
               'description': ikepolicy['description'],
               'auth_algorithm': ikepolicy['auth_algorithm'],
               'encryption_algorithm': ikepolicy['encryption_algorithm'],
               'phase1_negotiation_mode': ikepolicy['phase1_negotiation_mode'],
               'lifetime': {
                   'units': ikepolicy['lifetime_units'],
                   'value': ikepolicy['lifetime_value'],
               },
               'ike_version': ikepolicy['ike_version'],
               'pfs': ikepolicy['pfs']
               }

        return self._fields(res, fields)

    def create_ikepolicy(self, context, ikepolicy):
        ike = ikepolicy['ikepolicy']
        tenant_id = self._get_tenant_id_for_create(context, ike)
        lifetime_info = ike.get('lifetime', [])
        lifetime_units = lifetime_info.get('units', 'seconds')
        lifetime_value = lifetime_info.get('value', 3600)

        with context.session.begin(subtransactions=True):
            ike_db = IKEPolicy(
                id=uuidutils.generate_uuid(),
                tenant_id=tenant_id,
                name=ike['name'],
                description=ike['description'],
                auth_algorithm=ike['auth_algorithm'],
                encryption_algorithm=ike['encryption_algorithm'],
                phase1_negotiation_mode=ike['phase1_negotiation_mode'],
                lifetime_units=lifetime_units,
                lifetime_value=lifetime_value,
                ike_version=ike['ike_version'],
                pfs=ike['pfs']
            )

            context.session.add(ike_db)
        return self._make_ikepolicy_dict(ike_db)

    def update_ikepolicy(self, context, ikepolicy_id, ikepolicy):
        ike = ikepolicy['ikepolicy']
        with context.session.begin(subtransactions=True):
            ikepolicy = context.session.query(IPsecSiteConnection).filter_by(
                ikepolicy_id=ikepolicy_id).first()
            if ikepolicy:
                raise vpnaas.IKEPolicyInUse(ikepolicy_id=ikepolicy_id)
            ike_db = self._get_resource(context, IKEPolicy, ikepolicy_id)
            if ike:
                lifetime_info = ike.get('lifetime')
                if lifetime_info:
                    if lifetime_info.get('units'):
                        ike['lifetime_units'] = lifetime_info['units']
                    if lifetime_info.get('value'):
                        ike['lifetime_value'] = lifetime_info['value']
                ike_db.update(ike)
        return self._make_ikepolicy_dict(ike_db)

    def delete_ikepolicy(self, context, ikepolicy_id):
        with context.session.begin(subtransactions=True):
            ikepolicy = context.session.query(IPsecSiteConnection).filter_by(
                ikepolicy_id=ikepolicy_id).first()
            if ikepolicy:
                raise vpnaas.IKEPolicyInUse(ikepolicy_id=ikepolicy_id)
            ike_db = self._get_resource(context, IKEPolicy, ikepolicy_id)
            context.session.delete(ike_db)

    def get_ikepolicy(self, context, ikepolicy_id, fields=None):
        ike_db = self._get_resource(context, IKEPolicy, ikepolicy_id)
        return self._make_ikepolicy_dict(ike_db, fields)

    def get_ikepolicies(self, context, filters=None, fields=None):
        return self._get_collection(context, IKEPolicy,
                                    self._make_ikepolicy_dict,
                                    filters=filters, fields=fields)

    def _make_ipsecpolicy_dict(self, ipsecpolicy, fields=None):

        res = {'id': ipsecpolicy['id'],
               'tenant_id': ipsecpolicy['tenant_id'],
               'name': ipsecpolicy['name'],
               'description': ipsecpolicy['description'],
               'transform_protocol': ipsecpolicy['transform_protocol'],
               'auth_algorithm': ipsecpolicy['auth_algorithm'],
               'encryption_algorithm': ipsecpolicy['encryption_algorithm'],
               'encapsulation_mode': ipsecpolicy['encapsulation_mode'],
               'lifetime': {
                   'units': ipsecpolicy['lifetime_units'],
                   'value': ipsecpolicy['lifetime_value'],
               },
               'pfs': ipsecpolicy['pfs']
               }

        return self._fields(res, fields)

    def create_ipsecpolicy(self, context, ipsecpolicy):
        ipsecp = ipsecpolicy['ipsecpolicy']
        tenant_id = self._get_tenant_id_for_create(context, ipsecp)
        lifetime_info = ipsecp['lifetime']
        lifetime_units = lifetime_info.get('units', 'seconds')
        lifetime_value = lifetime_info.get('value', 3600)

        with context.session.begin(subtransactions=True):
            ipsecp_db = IPsecPolicy(id=uuidutils.generate_uuid(),
                                    tenant_id=tenant_id,
                                    name=ipsecp['name'],
                                    description=ipsecp['description'],
                                    transform_protocol=ipsecp['transform_'
                                                              'protocol'],
                                    auth_algorithm=ipsecp['auth_algorithm'],
                                    encryption_algorithm=ipsecp['encryption_'
                                                                'algorithm'],
                                    encapsulation_mode=ipsecp['encapsulation_'
                                                              'mode'],
                                    lifetime_units=lifetime_units,
                                    lifetime_value=lifetime_value,
                                    pfs=ipsecp['pfs'])
            context.session.add(ipsecp_db)
        return self._make_ipsecpolicy_dict(ipsecp_db)

    def update_ipsecpolicy(self, context, ipsecpolicy_id, ipsecpolicy):
        ipsecp = ipsecpolicy['ipsecpolicy']
        with context.session.begin(subtransactions=True):
            ipsecpolicy = context.session.query(IPsecSiteConnection).filter_by(
                ipsecpolicy_id=ipsecpolicy_id).first()
            if ipsecpolicy:
                raise vpnaas.IPsecPolicyInUse(ipsecpolicy_id=ipsecpolicy_id)
            ipsecp_db = self._get_resource(context,
                                           IPsecPolicy,
                                           ipsecpolicy_id)
            if ipsecp:
                lifetime_info = ipsecp.get('lifetime')
                if lifetime_info:
                    if lifetime_info.get('units'):
                        ipsecp['lifetime_units'] = lifetime_info['units']
                    if lifetime_info.get('value'):
                        ipsecp['lifetime_value'] = lifetime_info['value']
                ipsecp_db.update(ipsecp)
        return self._make_ipsecpolicy_dict(ipsecp_db)

    def delete_ipsecpolicy(self, context, ipsecpolicy_id):
        with context.session.begin(subtransactions=True):
            ipsecpolicy = context.session.query(IPsecSiteConnection).filter_by(
                ipsecpolicy_id=ipsecpolicy_id).first()
            if ipsecpolicy:
                raise vpnaas.IPsecPolicyInUse(ipsecpolicy_id=ipsecpolicy_id)
            ipsec_db = self._get_resource(context, IPsecPolicy, ipsecpolicy_id)
            context.session.delete(ipsec_db)

    def get_ipsecpolicy(self, context, ipsecpolicy_id, fields=None):
        ipsec_db = self._get_resource(context, IPsecPolicy, ipsecpolicy_id)
        return self._make_ipsecpolicy_dict(ipsec_db, fields)

    def get_ipsecpolicies(self, context, filters=None, fields=None):
        return self._get_collection(context, IPsecPolicy,
                                    self._make_ipsecpolicy_dict,
                                    filters=filters, fields=fields)

    def _make_vpnservice_dict(self, vpnservice, fields=None):
        res = {'id': vpnservice['id'],
               'name': vpnservice['name'],
               'description': vpnservice['description'],
               'tenant_id': vpnservice['tenant_id'],
               'subnet_id': vpnservice['subnet_id'],
               'router_id': vpnservice['router_id'],
               'admin_state_up': vpnservice['admin_state_up'],
               'status': vpnservice['status']}
        if vpnservice.provider:
            res['provider'] = vpnservice.provider.provider_name
        return self._fields(res, fields)

    def create_vpnservice(self, context, vpnservice, validator=None):
        vpns = vpnservice['vpnservice']
        tenant_id = self._get_tenant_id_for_create(context, vpns)
        validator = validator or self._get_validator()
        with context.session.begin(subtransactions=True):
            validator.validate_vpnservice(context, vpns)
            vpnservice_db = VPNService(id=uuidutils.generate_uuid(),
                                       tenant_id=tenant_id,
                                       name=vpns['name'],
                                       description=vpns['description'],
                                       subnet_id=vpns['subnet_id'],
                                       router_id=vpns['router_id'],
                                       admin_state_up=vpns['admin_state_up'],
                                       status=constants.PENDING_CREATE)
            context.session.add(vpnservice_db)
        return self._make_vpnservice_dict(vpnservice_db)

    def update_vpnservice(self, context, vpnservice_id, vpnservice):
        vpns = vpnservice['vpnservice']
        with context.session.begin(subtransactions=True):
            vpns_db = self._get_resource(context, VPNService, vpnservice_id)
            self.assert_update_allowed(vpns_db)
            if vpns:
                vpns_db.update(vpns)
        return self._make_vpnservice_dict(vpns_db)

    def delete_vpnservice(self, context, vpnservice_id):
        with context.session.begin(subtransactions=True):
            if context.session.query(IPsecSiteConnection).filter_by(
                vpnservice_id=vpnservice_id
            ).first():
                raise vpnaas.VPNServiceInUse(vpnservice_id=vpnservice_id)
            vpns_db = self._get_resource(context, VPNService, vpnservice_id)
            associations = context.session.query(
                PPTPCredentialServiceAssociation
            ).filter_by(vpnservice_id=vpnservice_id).all()
            for association in associations:
                self._core_plugin.delete_port(
                    context, association.port_id, l3_port_check=False)
            context.session.delete(vpns_db)

    def _get_vpnservice(self, context, vpnservice_id):
        return self._get_resource(context, VPNService, vpnservice_id)

    def get_vpnservice(self, context, vpnservice_id, fields=None):
        vpns_db = self._get_resource(context, VPNService, vpnservice_id)
        return self._make_vpnservice_dict(vpns_db, fields)

    def get_vpnservices(self, context, filters=None, fields=None):
        return self._get_collection(context, VPNService,
                                    self._make_vpnservice_dict,
                                    filters=filters, fields=fields)

    def check_router_in_use(self, context, router_id):
        vpnservices = self.get_vpnservices(
            context, filters={'router_id': [router_id]})
        if vpnservices:
            raise vpnaas.RouterInUseByVPNService(
                router_id=router_id,
                vpnservice_id=vpnservices[0]['id'])

    def _make_pptp_credential_dict(self, pptp_credential, fields=None):
        res = {'id': pptp_credential['id'],
               'tenant_id': pptp_credential['tenant_id'],
               'username': pptp_credential['username'],
               'password': pptp_credential['password'],
               'vpnservices': [association.vpnservice_id for association in
                               pptp_credential['associations']]}
        return self._fields(res, fields)

    def _username_already_exists(self, context, username):
        query = self._model_query(context, PPTPCredential)
        return len(query.filter_by(username=username).all()) > 0

    def _create_port_for_vpnservice(self, context,
                                    vpnservice_id, pptp_credential_id):
        vpns_db = self._get_resource(context, VPNService, vpnservice_id)
        subnet_id = vpns_db['subnet_id']
        subnet = self._core_plugin._get_subnet(context, subnet_id)
        port = {
            'port': {
                'tenant_id': subnet['tenant_id'],
                'network_id': subnet['network_id'],
                'fixed_ips': [{'subnet_id': subnet_id}],
                'mac_address': attr.ATTR_NOT_SPECIFIED,
                'admin_state_up': True,
                'status': n_constants.PORT_STATUS_DOWN,
                'device_id': vpnservice_id,
                'device_owner': constants.VPN,
                'name': pptp_credential_id
            }
        }
        port = self._core_plugin.create_port(context, port)
        if port['fixed_ips']:
            return port['id']

        # Port creation failed
        self._core_plugin.delete_port(context, port['id'], l3_port_check=False)
        return None

    def create_pptp_credential(self, context, pptp_credential):
        pptp_credential = pptp_credential['pptp_credential']
        tenant_id = self._get_tenant_id_for_create(context, pptp_credential)
        pptp_credential_id = uuidutils.generate_uuid()
        with context.session.begin(subtransactions=True):
            username = pptp_credential['username']
            if self._username_already_exists(context, username):
                raise vpnaas.PPTPUsernameAlreadyExists(username=username)
            pptp_credential_db = PPTPCredential(
                id=pptp_credential_id,
                tenant_id=tenant_id,
                username=username,
                password=pptp_credential['password']
            )
            context.session.add(pptp_credential_db)
            if attr.is_attr_set(pptp_credential['vpnservices']):
                for vpnservice_id in pptp_credential['vpnservices']:
                    port_id = self._create_port_for_vpnservice(
                        context, vpnservice_id, pptp_credential_id)
                    if not port_id:
                        LOG.warn(
                            _("Cannot create port for vpnservice "
                              "%(vpnservice_id)s and pptp_credential "
                              "%(pptp_credential_id)s."),
                            {'vpnservice_id': vpnservice_id,
                             'pptp_credential_id': pptp_credential_id})
                        continue
                    association = PPTPCredentialServiceAssociation(
                        pptp_credential_id=pptp_credential_id,
                        vpnservice_id=vpnservice_id,
                        port_id=port_id
                    )
                    context.session.add(association)
        return self._make_pptp_credential_dict(pptp_credential_db)

    def update_pptp_credential(self, context, pptp_credential_id,
                               pptp_credential):
        pptp_credential = pptp_credential['pptp_credential']
        vpnservices = pptp_credential.pop('vpnservices', None)
        with context.session.begin(subtransactions=True):
            pptp_credential_db = self._get_resource(
                context, PPTPCredential, pptp_credential_id)
            pptp_credential_db.update(pptp_credential)
            if attr.is_attr_set(vpnservices):
                new_services = set(vpnservices)
                for association in pptp_credential_db['associations']:
                    if association.vpnservice_id in new_services:
                        new_services.remove(association.vpnservice_id)
                    else:
                        self._core_plugin.delete_port(
                            context, association.port_id, l3_port_check=False)
                        context.session.delete(association)
                for service_id in new_services:
                    port_id = self._create_port_for_vpnservice(
                        context, service_id, pptp_credential_id)
                    if not port_id:
                        LOG.warn(
                            _("Cannot create port for vpnservice "
                              "%(vpnservice_id)s and pptp_credential "
                              "%(pptp_credential_id)s."),
                            {'vpnservice_id': service_id,
                             'pptp_credential_id': pptp_credential_id})
                        continue
                    association = PPTPCredentialServiceAssociation(
                        pptp_credential_id=pptp_credential_id,
                        vpnservice_id=service_id,
                        port_id=port_id
                    )
                    context.session.add(association)
        return self._make_pptp_credential_dict(pptp_credential_db)

    def delete_pptp_credential(self, context, pptp_credential_id):
        with context.session.begin(subtransactions=True):
            pptp_credential = self._get_resource(
                context, PPTPCredential, pptp_credential_id)
            for association in pptp_credential['associations']:
                self._core_plugin.delete_port(
                    context, association.port_id, l3_port_check=False)
            context.session.delete(pptp_credential)

    def get_pptp_credential(self, context, pptp_credential_id, fields=None):
        pptp_credential = self._get_resource(
            context, PPTPCredential, pptp_credential_id)
        return self._make_pptp_credential_dict(pptp_credential, fields)

    def get_pptp_credentials(self, context, filters=None, fields=None):
        return self._get_collection(context, PPTPCredential,
                                    self._make_pptp_credential_dict,
                                    filters=filters, fields=fields)


class VPNPluginRpcDbMixin():
    def _get_agent_hosting_vpn_services(self, context, host, provider):

        plugin = manager.NeutronManager.get_plugin()
        agent = plugin._get_agent_by_type_and_host(
            context, n_constants.AGENT_TYPE_L3, host)
        if not agent.admin_state_up:
            return []
        query = context.session.query(VPNService)
        query = query.join(
            st_db.ProviderResourceAssociation,
            st_db.ProviderResourceAssociation.provider_name == provider)
        query = query.filter(
            st_db.ProviderResourceAssociation.resource_id == VPNService.id)
        query = query.join(IPsecSiteConnection)
        query = query.join(IKEPolicy)
        query = query.join(IPsecPolicy)
        query = query.join(IPsecPeerCidr)
        query = query.join(l3_agent_db.RouterL3AgentBinding,
                           l3_agent_db.RouterL3AgentBinding.router_id ==
                           VPNService.router_id)
        query = query.filter(
            l3_agent_db.RouterL3AgentBinding.l3_agent_id == agent.id)
        return query

    def update_status_by_agent(self, context, service_status_info_list):
        """Updating vpnservice and vpnconnection status.

        :param context: context variable
        :param service_status_info_list: list of status
        The structure is
        [{id: vpnservice_id,
          status: ACTIVE|DOWN|ERROR,
          updated_pending_status: True|False
          ipsec_site_connections: {
              ipsec_site_connection_id: {
                  status: ACTIVE|DOWN|ERROR,
                  updated_pending_status: True|False
              }
          }]
        The agent will set updated_pending_status as True,
        when agent update any pending status.
        """
        with context.session.begin(subtransactions=True):
            for vpnservice in service_status_info_list:
                try:
                    vpnservice_db = self._get_vpnservice(
                        context, vpnservice['id'])
                except vpnaas.VPNServiceNotFound:
                    LOG.warn(_('vpnservice %s in db is already deleted'),
                             vpnservice['id'])
                    continue

                if (not utils.in_pending_status(vpnservice_db.status)
                    or vpnservice['updated_pending_status']):
                    vpnservice_db.status = vpnservice['status']
                for conn_id, conn in vpnservice[
                    'ipsec_site_connections'].items():
                    self._update_connection_status(
                        context, conn_id, conn['status'],
                        conn['updated_pending_status'])

    def set_vpnservice_status(self, context, vpnservice_id, status):
        with context.session.begin(subtransactions=True):
            try:
                vpnservice_db = self._get_vpnservice(context, vpnservice_id)
                vpnservice_db.status = status
            except vpnaas.VPNServiceNotFound:
                LOG.warn(_('vpnservice %s in db is already deleted'),
                         vpnservice_db['id'])

    def update_pptp_status_by_agent(
            self, context, host,
            pptp_processes_status, credentials, updated_ports,
            provider):

        notify_vpnservices = {
            'enabled': [],
            'disabled': [],
            'deleted': [],
            'added': []
        }
        notify_credentials = {
            'added': [],
            'deleted': [],
            'updated': {}
        }
        notify_ports = {
            'added': {},
            'deleted': []
        }

        # First, get vpnservices running on the specified host
        plugin = manager.NeutronManager.get_plugin()
        agent = plugin._get_agent_by_type_and_host(
            context, n_constants.AGENT_TYPE_L3, host)
        vpnservices = {}
        if agent.admin_state_up:
            query = context.session.query(VPNService)
            query = query.join(
                st_db.ProviderResourceAssociation,
                st_db.ProviderResourceAssociation.provider_name == provider)
            query = query.filter(
                st_db.ProviderResourceAssociation.resource_id == VPNService.id)
            query = query.join(l3_agent_db.RouterL3AgentBinding,
                               l3_agent_db.RouterL3AgentBinding.router_id ==
                               VPNService.router_id)
            query = query.filter(
                l3_agent_db.RouterL3AgentBinding.l3_agent_id == agent.id)
            for vpnservice in query.all():
                vpnservices[vpnservice['id']] = self._make_vpnservice_dict(
                    vpnservice)

        # Second, obtain pptp_credentials and ports for the vpnservices
        pptp_credentials = {}
        ports = {}
        for vpnservice_id in vpnservices.keys():
            ports[vpnservice_id] = {}
            for association in context.session.query(
                PPTPCredentialServiceAssociation
            ).filter_by(vpnservice_id=vpnservice_id).all():
                if association.pptp_credential_id not in pptp_credentials:
                    pptp_credential_db = self._get_resource(
                        context, PPTPCredential,
                        association.pptp_credential_id)
                    pptp_credentials[association.pptp_credential_id] = {
                        'id': pptp_credential_db['id'],
                        'username': pptp_credential_db['username'],
                        'password': pptp_credential_db['password']
                    }
                port_db = self._core_plugin._get_port(
                    context, association.port_id
                )
                ports[vpnservice_id][association.port_id] = {
                    'vpnservice_id': vpnservice_id,
                    'ip': port_db.fixed_ips[0]['ip_address'],
                    'credential_id': association.pptp_credential_id
                }

        with context.session.begin(subtransactions=True):
            # Update port status
            for port_id, status in updated_ports.iteritems():
                try:
                    port_db = self._core_plugin._get_port(context, port_id)
                except n_exc.PortNotFound:
                    LOG.warn(_('port %s in db is already deleted', port_id))
                    continue
                if status:
                    port_db.status = n_constants.PORT_STATUS_ACTIVE
                else:
                    port_db.status = n_constants.PORT_STATUS_DOWN

        # Update vpnservice status
        for vpnservice_id, status in pptp_processes_status.iteritems():
            if vpnservice_id not in vpnservices:
                notify_vpnservices['deleted'].append(vpnservice_id)
                continue
            s = constants.ACTIVE if status['active'] else constants.DOWN
            self.set_vpnservice_status(context, vpnservice_id, s)
            vpnservice = vpnservices.pop(vpnservice_id)
            # Sync vpnservice process status
            if vpnservice['admin_state_up'] != status['enabled']:
                notify_vpnservices[
                    'enabled' if vpnservice['admin_state_up'] else 'disabled'
                ].append(vpnservice_id)
            for port_id in status['ports']:
                if port_id not in ports[vpnservice_id]:
                    notify_ports['deleted'].append(port_id)
                    continue
                ports[vpnservice_id].pop(port_id)

        # Update pptp_credential status
        for credential_id, credential in credentials.iteritems():
            if credential_id not in pptp_credentials:
                notify_credentials['deleted'].append(credential_id)
                continue
            c = pptp_credentials.pop(credential_id)
            if c['password'] != credential['password']:
                notify_credentials['updated'][credential_id] = c['password']

        # Handle added vpnservices
        for vpnservice_id, vpnservice in vpnservices.iteritems():
            subnet = self._core_plugin.get_subnet(
                context, vpnservice['subnet_id']
            )
            vpnservice['localip'] = subnet['gateway_ip']
            notify_vpnservices['added'].append(vpnservice)

        # Handle added credentials
        for credential_id, credential in pptp_credentials.iteritems():
            notify_credentials['added'].append(credential)

        # Handle added ports
        for vpnservice_id, ports in ports.iteritems():
            notify_ports['added'].update(ports)

        driver = self.drivers[provider]
        driver.sync_from_server(
            context, host, notify_vpnservices, notify_credentials, notify_ports
        )
