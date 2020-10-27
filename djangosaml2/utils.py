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
import base64
import re
import urllib
import zlib

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils.http import is_safe_url
from django.utils.module_loading import import_string
from saml2.s_utils import UnknownSystemEntity

from datetime import timedelta
from deming.time_utils import TimeUtils
from twd_integration.models import QualityEventOccurrence, TwdQualityEvent


def get_custom_setting(name, default=None):
    return getattr(settings, name, default)


def available_idps(config, langpref=None):
    if langpref is None:
        langpref = "en"

    idps = set()

    for metadata_name, metadata in config.metadata.metadata.items():
        result = metadata.any('idpsso_descriptor', 'single_sign_on_service')
        if result:
            idps.update(result.keys())

    return {
        idp: config.metadata.name(idp, langpref)
        for idp in idps
    }


def get_idp_sso_supported_bindings(idp_entity_id=None, config=None):
    """Returns the list of bindings supported by an IDP
    This is not clear in the pysaml2 code, so wrapping it in a util"""
    if config is None:
        # avoid circular import
        from .conf import get_config
        config = get_config()
    # load metadata store from config
    meta = getattr(config, 'metadata', {})
    # if idp is None, assume only one exists so just use that
    if idp_entity_id is None:
        try:
            idp_entity_id = list(available_idps(config).keys())[0]
        except IndexError:
            raise ImproperlyConfigured("No IdP configured!")
    try:
        return meta.service(idp_entity_id, 'idpsso_descriptor', 'single_sign_on_service').keys()
    except UnknownSystemEntity:
        return []


def get_location(http_info):
    """Extract the redirect URL from a pysaml2 http_info object"""
    try:
        headers = dict(http_info['headers'])
        return headers['Location']
    except KeyError:
        return http_info['url']


def fail_acs_response(request, *args, **kwargs):
    """ Serves as a common mechanism for ending ACS in case of any SAML related failure.
    Handling can be configured by setting the SAML_ACS_FAILURE_RESPONSE_FUNCTION as
    suitable for the project.

    The default behavior uses SAML specific template that is rendered on any ACS error,
    but this can be simply changed so that PermissionDenied exception is raised instead.
    """
    failure_function = import_string(get_custom_setting('SAML_ACS_FAILURE_RESPONSE_FUNCTION',
                                                        'djangosaml2.acs_failures.template_failure'))
    return failure_function(request, *args, **kwargs)


def validate_referral_url(request, url):
    # Ensure the user-originating redirection url is safe.
    # By setting SAML_ALLOWED_HOSTS in settings.py the user may provide a list of "allowed"
    # hostnames for post-login redirects, much like one would specify ALLOWED_HOSTS .
    # If this setting is absent, the default is to use the hostname that was used for the current
    # request.
    saml_allowed_hosts = set(getattr(settings, 'SAML_ALLOWED_HOSTS', [request.get_host()]))

    if not is_safe_url(url=url, allowed_hosts=saml_allowed_hosts):
        return settings.LOGIN_REDIRECT_URL
    else:
        return url


def saml2_from_httpredirect_request(url):
    urlquery = urllib.parse.urlparse(url).query
    b64_inflated_saml2req = urllib.parse.parse_qs(urlquery)['SAMLRequest'][0]

    inflated_saml2req = base64.b64decode(b64_inflated_saml2req)
    deflated_saml2req = zlib.decompress(inflated_saml2req, -15)
    return deflated_saml2req

def get_session_id_from_saml2(saml2_xml):
    saml2_xml = saml2_xml.encode() if isinstance(saml2_xml, str) else saml2_xml
    return re.findall(b'ID="([a-z0-9\-]*)"', saml2_xml, re.I)[0].decode()

def get_subject_id_from_saml2(saml2_xml):
    saml2_xml = saml2_xml if isinstance(saml2_xml, str) else saml2_xml.decode()
    re.findall('">([a-z0-9]+)</saml:NameID>', saml2_xml)[0]


def build_redirect_url(relay_state):
    """Builds Redirect URL from relay state which holds
    the value for external event ID.

    Returns None if no matching data found or relative url(str)
    to redirect to.
    """
    try:
        eventOccurence = QualityEventOccurrence.objects.get(twd_event_id=relay_state)
    except QualityEventOccurrence.DoesNotExist:
        eventOccurence = None
    try:
        qualityEvent = TwdQualityEvent.objects.get(twd_event_id=relay_state)
    except TwdQualityEvent.DoesNotExist:
        qualityEvent = None
    if eventOccurence:
        asset_id = eventOccurence.rule_break.rule_definition.asset.id
        end_data = TimeUtils.to_epoch(eventOccurence.rule_break.stop_time)
        start_date = TimeUtils.to_epoch(eventOccurence.rule_break.start_time)
        if eventOccurence.rule_break.rule_definition.product:
            product = eventOccurence.rule_break.rule_definition.product.id 
            return f'/quality/quality-events/?asset_id={asset_id}&end_date={end_data}&product={product}&start_date={start_date}&tab_id=quality-events'
        return f'/quality/quality-events/?asset_id={asset_id}&end_date={end_data}&start_date={start_date}&tab_id=quality-events'
    elif qualityEvent:
        end_data = TimeUtils.to_epoch(qualityEvent.created_at + timedelta(days=1))
        start_date = TimeUtils.to_epoch(qualityEvent.created_at)
        product = qualityEvent.product.id
        return f'/quality/quality-events/?end_date={end_data}&product={product}&start_date={start_date}&tab_id=quality-events'
    return None
