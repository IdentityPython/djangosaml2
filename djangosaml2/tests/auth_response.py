# Copyright (C) 2011-2012 Yaco Sistemas (http://www.yaco.es)
# Copyright (C) 2010 Lorenzo Gil Sanchez <lorenzo.gil.sanchez@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#            http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os

from saml2 import saml
from saml2.config import IdPConfig
from saml2.s_utils import success_status_factory
from saml2.server import Identifier, Server
from saml2.sigver import response_factory

BASEDIR = os.path.dirname(os.path.abspath(__file__))


class FakeDb(dict):

    def sync(self):
        pass


def auth_response(identity, in_response_to, sp_conf):
    """Generates a fresh signed authentication response"""
    sp_entity_id = sp_conf.entityid
    idp_entity_id = sp_conf.idps().keys()[0]
    acs = sp_conf.endpoint('assertion_consumer_service')[0]
    issuer = saml.Issuer(text=idp_entity_id, format=saml.NAMEID_FORMAT_ENTITY)
    response = response_factory(issuer=issuer,
                                in_response_to=in_response_to,
                                destination=acs,
                                status=success_status_factory())
    idp_conf = IdPConfig()
    name_form = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
    idp_conf.load({
            'entityid': idp_entity_id,
            'xmlsec_binary': sp_conf.xmlsec_binary,
            'attribute_map_dir': os.path.join(BASEDIR, 'attribute-maps'),
            'service': {
                'idp': {
                    'endpoints': tuple(),
                    'policy':  {
                        'default': {
                            "lifetime": {"minutes": 15},
                            "attribute_restrictions": None,
                            "name_form": name_form,
                            }
                        }
                    },
                },
            'key_file': os.path.join(BASEDIR, 'idpcert.key'),
            'cert_file': os.path.join(BASEDIR, 'idpcert.pem'),
            'metadata': {
                'local': [os.path.join(BASEDIR, 'sp_metadata.xml')],
                },
            })
    server = Server("", idp_conf)
    server.ident = Identifier(FakeDb())

    userid = 'irrelevant'
    response = server.authn_response(identity, in_response_to, acs,
                                     sp_entity_id, None, userid)
    return '\n'.join(response)
