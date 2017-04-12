# Copyright (C) 2012 Yaco Sistemas (http://www.yaco.es)
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

from django.conf import settings
from saml2.s_utils import UnknownSystemEntity


def get_custom_setting(name, default=None):
    return getattr(settings, name, default)


def available_idps(config, langpref=None):
    if langpref is None:
        langpref = "en"

    idps = set()

    for metadata_name, metadata in config.metadata.metadata.items():
        result = metadata.any('idpsso_descriptor', 'single_sign_on_service')
        if result:
            idps = idps.union(set(result.keys()))

    return dict([(idp, config.metadata.name(idp, langpref)) for idp in idps])


def get_idp_sso_supported_bindings(idp_entity_id=None):
    """Returns the list of bindings supported by an IDP
    This is not clear in the pysaml2 code, so wrapping it in a util"""
    # avoid circular import
    from djangosaml2.conf import get_config
    # load metadata store from config
    config = get_config()
    meta = getattr(config, 'metadata', {})
    # if idp is None, assume only one exists so just use that
    idp_entity_id = available_idps(config).keys().pop()
    try:
        return meta.service(idp_entity_id, 'idpsso_descriptor', 'single_sign_on_service').keys()
    except UnknownSystemEntity:
        return []


def get_location(http_info):
    """Extract the redirect URL from a pysaml2 http_info object"""
    assert 'headers' in http_info
    headers = http_info['headers']

    assert len(headers) == 1
    header_name, header_value = headers[0]
    assert header_name == 'Location'
    return header_value
