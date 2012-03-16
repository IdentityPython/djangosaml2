# Copyright (C) 2010-2011 Yaco Sistemas (http://www.yaco.es)
# Copyright (C) 2009 Lorenzo Gil Sanchez <lorenzo.gil.sanchez@gmail.com>
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

import logging

try:
    from xml.etree import ElementTree
except ImportError:
    from elementtree import ElementTree

from django.conf import settings
from django.contrib import auth
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import logout as django_logout
from django.http import Http404, HttpResponse, HttpResponseRedirect
from django.shortcuts import render_to_response
from django.template import RequestContext
try:
    from django.views.decorators.csrf import csrf_exempt
except ImportError:
    # Django 1.0 compatibility
    def csrf_exempt(view_func):
        return view_func

from saml2 import BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.metadata import entity_descriptor

from djangosaml2.cache import IdentityCache, OutstandingQueriesCache
from djangosaml2.cache import StateCache
from djangosaml2.conf import config_settings_loader
from djangosaml2.signals import post_authenticated


logger = logging.getLogger('djangosaml2')


def _set_subject_id(session, subject_id):
    session['_saml2_subject_id'] = subject_id


def _get_subject_id(session):
    return session['_saml2_subject_id']


def get_custom_setting(name, default=None):
    if hasattr(settings, name):
        return getattr(settings, name)
    else:
        return default


def login(request,
          config_loader=config_settings_loader,
          wayf_template='djangosaml2/wayf.html',
          authorization_error_template='djangosaml2/auth_error.html'):
    """SAML Authorization Request initiator

    This view initiates the SAML2 Authorization handshake
    using the pysaml2 library to create the AuthnRequest.
    It uses the SAML 2.0 Http Redirect protocol binding.
    """
    logger.debug('Login process started')

    came_from = request.GET.get('next', settings.LOGIN_REDIRECT_URL)

    if not request.user.is_anonymous():
        logger.debug('User is already logged in')
        return render_to_response(authorization_error_template, {
                'came_from': came_from,
                }, context_instance=RequestContext(request))

    selected_idp = request.GET.get('idp', None)
    conf = config_loader()

    # is a embedded wayf needed?
    idps = conf.idps()
    if selected_idp is None and len(idps) > 1:
        logger.debug('A discovery process is needed')
        return render_to_response(wayf_template, {
                'available_idps': idps.items(),
                'came_from': came_from,
                }, context_instance=RequestContext(request))

    client = Saml2Client(conf, logger=logger)
    try:
        (session_id, result) = client.authenticate(
            entityid=selected_idp, relay_state=came_from,
            binding=BINDING_HTTP_REDIRECT,
            )
    except TypeError, e:
        logger.error('Unable to know which IdP to use')
        return HttpResponse(unicode(e))

    assert len(result) == 2
    assert result[0] == 'Location'
    location = result[1]

    logger.debug('Saving the session_id in the OutstandingQueries cache')
    oq_cache = OutstandingQueriesCache(request.session)
    oq_cache.set(session_id, came_from)

    logger.debug('Redirecting the user to the IdP')
    return HttpResponseRedirect(location)


DEFAULT_ATTRIBUTE_MAPPING = get_custom_setting('SAML_ATTRIBUTE_MAPPING',
                                               {'uid': ('username', )})
DEFAULT_CREATE_UNKNOWN_USER = get_custom_setting('SAML_CREATE_UNKNOWN_USER',
                                                 True)


@csrf_exempt
def assertion_consumer_service(request, config_loader=config_settings_loader,
                               attribute_mapping=DEFAULT_ATTRIBUTE_MAPPING,
                               create_unknown_user=DEFAULT_CREATE_UNKNOWN_USER):
    """SAML Authorization Response endpoint

    The IdP will send its response to this view, which
    will process it with pysaml2 help and log the user
    in using the custom Authorization backend
    djangosaml2.backends.Saml2Backend that should be
    enabled in the settings.py
    """
    logger.debug('Assertion Consumer Service started')

    conf = config_loader()
    post = {'SAMLResponse': request.POST['SAMLResponse']}
    client = Saml2Client(conf, identity_cache=IdentityCache(request.session),
                         logger=logger)

    oq_cache = OutstandingQueriesCache(request.session)
    outstanding_queries = oq_cache.outstanding_queries()

    # process the authentication response
    response = client.response(post, outstanding_queries)
    if response is None:
        logger.error('SAML response is None')
        return HttpResponse("SAML response has errors. Please check the logs")

    session_id = response.session_id()
    oq_cache.delete(session_id)

    # authenticate the remote user
    session_info = response.session_info()

    if 'djangosaml2.backends.Saml2Backend' not in settings.AUTHENTICATION_BACKENDS:
        logger.debug('Prepend djangosaml2 backend to the Authentication Backends')
        settings.AUTHENTICATION_BACKENDS = (('djangosaml2.backends.Saml2Backend', )
                                            + settings.AUTHENTICATION_BACKENDS)

    if callable(attribute_mapping):
        attribute_mapping = attribute_mapping()
    if callable(create_unknown_user):
        create_unknown_user = create_unknown_user()

    logger.debug('Trying to authenticate the user')
    user = auth.authenticate(session_info=session_info,
                             attribute_mapping=attribute_mapping,
                             create_unknown_user=create_unknown_user)
    if user is None:
        logger.error('The user is None')
        return HttpResponse("There were problems trying to authenticate the user")

    auth.login(request, user)
    _set_subject_id(request.session, session_info['name_id'])

    logger.debug('Sending the post_authenticated signal')
    post_authenticated.send_robust(sender=user, session_info=session_info)

    # redirect the user to the view where he came from
    relay_state = request.POST.get('RelayState', '/')
    logger.debug('Redirecting to the RelayState: ' + relay_state)
    return HttpResponseRedirect(relay_state)


@login_required
def echo_attributes(request,
                    config_loader=config_settings_loader,
                    template='djangosaml2/echo_attributes.html'):
    """Example view that echo the SAML attributes of an user"""
    state = StateCache(request.session)
    client = Saml2Client(config_loader(), state_cache=state,
                         identity_cache=IdentityCache(request.session),
                         logger=logger)
    subject_id = _get_subject_id(request.session)
    identity = client.users.get_identity(subject_id,
                                         check_not_on_or_after=False)
    return render_to_response(template, {'attributes': identity[0]},
                              context_instance=RequestContext(request))


@login_required
def logout(request, config_loader=config_settings_loader):
    """SAML Logout Request initiator

    This view initiates the SAML2 Logout request
    using the pysaml2 library to create the LogoutRequest.
    """
    logger.debug('Logout process started')
    state = StateCache(request.session)
    client = Saml2Client(config_loader(), state_cache=state,
                         identity_cache=IdentityCache(request.session),
                         logger=logger)
    subject_id = _get_subject_id(request.session)
    session_id, code, head, body = client.global_logout(subject_id)
    headers = dict(head)
    state.sync()
    logger.debug('Redirecting to the IdP to continue the logout process')
    return HttpResponseRedirect(headers['Location'])


def logout_service(request, config_loader=config_settings_loader,
                   next_page=None):
    """SAML Logout Response endpoint

    The IdP will send the logout response to this view,
    which will process it with pysaml2 help and log the user
    out.
    Note that the IdP can request a logout even when
    we didn't initiate the process as a single logout
    request started by another SP.
    """
    logger.debug('Logout service started')
    conf = config_loader()
    state = StateCache(request.session)
    client = Saml2Client(conf, state_cache=state,
                         identity_cache=IdentityCache(request.session),
                         logger=logger)

    if 'SAMLResponse' in request.GET:  # we started the logout
        logger.debug('Receiving a logout response from the IdP')
        response = client.logout_response(request.GET['SAMLResponse'],
                                          binding=BINDING_HTTP_REDIRECT)
        state.sync()
        if response and response[1] == '200 Ok':
            return django_logout(request, next_page=next_page)
        else:
            logger.error('Unknown error during the logout')
            return HttpResponse('Error during logout')

    elif 'SAMLRequest' in request.GET:  # logout started by the IdP
        logger.debug('Receiving a logout request from the IdP')
        subject_id = _get_subject_id(request.session)
        response, success = client.logout_request(request.GET, subject_id)
        state.sync()
        if success:
            auth.logout(request)
            assert response[0][0] == 'Location'
            url = response[0][1]
            return HttpResponseRedirect(url)
        elif response is not None:
            assert response[0][0] == 'Location'
            url = response[0][1]
            return HttpResponseRedirect(url)
        else:
            logger.error('Unknown error during the logout')
            return HttpResponse('Error during logout')
    else:
        logger.error('No SAMLResponse or SAMLRequest parameter found')
        raise Http404('No SAMLResponse or SAMLRequest parameter found')


DEFAULT_VALID_FOR = get_custom_setting('SAML_VALID_FOR', 24)

def metadata(request, config_loader=config_settings_loader,
             valid_for=DEFAULT_VALID_FOR):
    """Returns an XML with the SAML 2.0 metadata for this
    SP as configured in the settings.py file.
    """
    conf = config_loader()
    metadata = entity_descriptor(conf, valid_for)
    return HttpResponse(content=str(metadata),
                        content_type="text/xml; charset=utf8")


def register_namespace_prefixes():
    from saml2 import md, saml, samlp
    import xmlenc
    import xmldsig
    prefixes = (('saml', saml.NAMESPACE),
                ('samlp', samlp.NAMESPACE),
                ('md', md.NAMESPACE),
                ('ds', xmldsig.NAMESPACE),
                ('xenc', xmlenc.NAMESPACE))
    if hasattr(ElementTree, 'register_namespace'):
        for prefix, namespace in prefixes:
            ElementTree.register_namespace(prefix, namespace)
    else:
        for prefix, namespace in prefixes:
            ElementTree._namespace_map[namespace] = prefix

register_namespace_prefixes()
