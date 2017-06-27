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
from sqlalchemy.orm import exc

from neutron.common import constants
from neutron.db import common_db_mixin as base_db
from neutron.db import model_base
from neutron.db import models_v2
from neutron.db.l3_db import Router
from neutron.extensions import es_metering
from neutron.openstack.common import log as logging
from neutron.openstack.common import uuidutils


LOG = logging.getLogger(__name__)


class EsMeteringLabel(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    __tablename__ = 'es_metering_labels'

    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(1024))
    router_id = sa.Column(
        sa.String(36), sa.ForeignKey('routers.id', ondelete='CASCADE'),
        nullable=False)
    direction = sa.Column(
        sa.Enum('ingress', 'egress', name='es_metering_label_direction'),
        nullable=False)
    internal_ip = sa.Column(sa.String(64))
    tcp_port = sa.Column(sa.Integer)
    router = orm.relationship(
        Router,
        backref=orm.backref("es_metering_labels", lazy='joined', uselist=True)
    )


class EsMeteringDbMixin(es_metering.EsMeteringPluginBase,
                        base_db.CommonDbMixin):

    def _get_es_metering_label(self, context, label_id):
        try:
            es_metering_label = self._get_by_id(
                context, EsMeteringLabel, label_id)
        except exc.NoResultFound:
            raise es_metering.EsMeteringLabelNotFound(label_id=label_id)
        return es_metering_label

    def _make_es_metering_label_dict(self, es_metering_label, fields=None):
        res = {'id': es_metering_label['id'],
               'tenant_id': es_metering_label['tenant_id'],
               'name': es_metering_label['name'],
               'description': es_metering_label['description'],
               'router_id': es_metering_label['router_id'],
               'direction': es_metering_label['direction'],
               'internal_ip': es_metering_label['internal_ip'],
               'tcp_port': es_metering_label['tcp_port']}
        return self._fields(res, fields)

    def create_es_metering_label(self, context, es_metering_label):
        label = es_metering_label['es_metering_label']
        tenant_id = self._get_tenant_id_for_create(context, label)
        try:
            self._get_by_id(context, Router, label['router_id'])
        except exc.NoResultFound:
            raise es_metering.RouterNotFound(router_id=label['router_id'])
        with context.session.begin(subtransactions=True):
            es_metering_label_db = EsMeteringLabel(
                id=uuidutils.generate_uuid(),
                tenant_id=tenant_id,
                name=label['name'], description=label['description'],
                router_id=label['router_id'], direction=label['direction'],
                internal_ip=label['internal_ip'], tcp_port=label['tcp_port'])
            context.session.add(es_metering_label_db)
        return self._make_es_metering_label_dict(es_metering_label_db)

    def update_es_metering_label(self, context, label_id, es_metering_label):
        label = es_metering_label['es_metering_label']
        with context.session.begin(subtransactions=True):
            es_metering_label_db = self._get_es_metering_label(
                context, label_id)
            es_metering_label_db.updte(label)
        return self._make_es_metering_label_dict(es_metering_label_db)

    def delete_es_metering_label(self, context, label_id):
        with context.session.begin(subtransactions=True):
            es_metering_label_db = self._get_es_metering_label(
                context, label_id)
            context.session.delete(es_metering_label_db)

    def get_es_metering_label(self, context, label_id, fields=None):
        es_metering_label_db = self._get_es_metering_label(context, label_id)
        return self._make_es_metering_label_dict(es_metering_label_db, fields)

    def get_es_metering_labels(self, context, filters=None, fields=None,
                               sorts=None, limit=None, marker=None,
                               page_reverse=False):
        marker_obj = self._get_marker_obj(
            context, 'es_metering_labels', limit, marker)
        return self._get_collection(context, EsMeteringLabel,
                                    self._make_es_metering_label_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts, limit=limit,
                                    marker_obj=marker_obj,
                                    page_reverse=page_reverse)

    @staticmethod
    def _label_dict(label):
        return {'id': label['id'],
                'direction': label['direction'],
                'internal_ip': label['internal_ip'],
                'tcp_port': label['tcp_port']}

    def get_sync_data_metering(self, context, label_id=None, router_ids=None):
        ret = []
        if not router_ids:
            router_ids = set()
            labels = context.session.query(EsMeteringLabel)
            if label_id:
                labels = labels.filter(EsMeteringLabel.id == label_id)
            for label in labels:
                router_ids.add(label.router_id)

        for router_id in router_ids:
            try:
                router = self._get_by_id(context, Router, router_id)
                if router['admin_state_up']:
                    ret.append({
                        'id': router['id'],
                        'name': router['name'],
                        'tenant_id': router['tenant_id'],
                        'admin_state_up': router['admin_state_up'],
                        'status': router['status'],
                        'gw_port_id': router['gw_port_id'],
                        constants.ES_METERING_LABEL_KEY: [
                            self._label_dict(label)
                            for label in router.es_metering_labels
                            if label_id is None or label['id'] == label_id
                        ]
                    })
            except exc.NoResultFound:
                pass

        return ret

    def update_es_metering_labels_for_router(self, context, router):
        try:
            router_db = self._get_by_id(context, Router, router['id'])
            if router_db.es_metering_labels:
                router[constants.ES_METERING_LABEL_KEY] = [
                    self._label_dict(label)
                    for label in router_db.es_metering_labels
                ]
        except exc.NoResultFound:
            pass
