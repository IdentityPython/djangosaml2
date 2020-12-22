# Copyright (C) 2010-2013 Yaco Sistemas (http://www.yaco.es)
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

import base64
import logging

from django.conf import settings
from django.contrib import auth
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import LogoutView as AuthLogoutView
from django.core.exceptions import PermissionDenied, SuspiciousOperation
from django.http import (HttpRequest, HttpResponse, HttpResponseBadRequest,
                         HttpResponseRedirect, HttpResponseServerError)
from django.shortcuts import render
from django.template import TemplateDoesNotExist
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import View
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.client_base import LogoutError
from saml2.config import SPConfig
from saml2.ident import code, decode
from saml2.mdstore import SourceNotFound
from saml2.metadata import entity_descriptor
from saml2.response import (SignatureError, StatusAuthnFailed, StatusError,
                            StatusNoAuthnContext, StatusRequestDenied,
                            UnsolicitedResponse)
from saml2.s_utils import UnsupportedBinding
from saml2.samlp import AuthnRequest
from saml2.sigver import MissingKey
from saml2.validate import ResponseLifetimeExceed, ToEarly
from saml2.xmldsig import (  # support for SHA1 is required by spec
    SIG_RSA_SHA1, SIG_RSA_SHA256)

from .cache import IdentityCache, OutstandingQueriesCache, StateCache
from .conf import get_config
from .exceptions import IdPConfigurationMissing
from .overrides import Saml2Client
from .utils import (available_idps, get_custom_setting,
                    get_idp_sso_supported_bindings, get_location,
                    validate_referral_url)

logger = logging.getLogger('djangosaml2')


def _set_subject_id(session, subject_id):
    session['_saml2_subject_id'] = code(subject_id)


def _get_subject_id(session):
    try:
        return decode(session['_saml2_subject_id'])
    except KeyError:
        return None


class SPConfigMixin:
    """ Mixin for some of the SAML views with re-usable methods.
    """

    config_loader_path = None

    def get_config_loader_path(self, request: HttpRequest):
        return self.config_loader_path

    def get_sp_config(self, request: HttpRequest) -> SPConfig:
        return get_config(self.get_config_loader_path(request), request)

    def get_state_client(self, request: HttpRequest):
        conf = self.get_sp_config(request)
        state = StateCache(request.saml_session)
        client = Saml2Client(conf, state_cache=state, identity_cache=IdentityCache(request.saml_session))
        return state, client


class LoginView(SPConfigMixin, View):
    """ SAML Authorization Request initiator.

        This view initiates the SAML2 Authorization handshake
        using the pysaml2 library to create the AuthnRequest.

        post_binding_form_template is a path to a template containing HTML form with
        hidden input elements, used to send the SAML message data when HTTP POST
        binding is being used. You can customize this template to include custom
        branding and/or text explaining the automatic redirection process. Please
        see the example template in templates/djangosaml2/example_post_binding_form.html
        If set to None or nonexistent template, default form from the saml2 library
        will be rendered.
    """
    logger.debug('Login process started')

    wayf_template = 'djangosaml2/wayf.html'
    authorization_error_template = 'djangosaml2/auth_error.html'
    post_binding_form_template = 'djangosaml2/post_binding_form.html'

    def get_next_path(self, request: HttpRequest) -> str:
        ''' Returns the path to put in the RelayState to redirect the user to after having logged in.
            If the user is already logged in (and if allowed), he will redirect to there immediately.
        '''

        next_path = settings.LOGIN_REDIRECT_URL
        if 'next' in request.GET:
            next_path = request.GET['next']
        elif 'RelayState' in request.GET:
            next_path = request.GET['RelayState']

        next_path = validate_referral_url(request, next_path)
        return next_path

    def get(self, request, *args, **kwargs):
        logger.debug('Login process started')

        next_path = self.get_next_path(request)

        # if the user is already authenticated that maybe because of two reasons:
        # A) He has this URL in two browser windows and in the other one he
        #    has already initiated the authenticated session.
        # B) He comes from a view that (incorrectly) send him here because
        #    he does not have enough permissions. That view should have shown
        #    an authorization error in the first place.
        # We can only make one thing here and that is configurable with the
        # SAML_IGNORE_AUTHENTICATED_USERS_ON_LOGIN setting. If that setting
        # is True (default value) we will redirect him to the next_path path.
        # Otherwise, we will show an (configurable) authorization error.
        if request.user.is_authenticated:
            if get_custom_setting('SAML_IGNORE_AUTHENTICATED_USERS_ON_LOGIN', True):
                return HttpResponseRedirect(next_path)
            logger.debug('User is already logged in')
            return render(request, self.authorization_error_template, {
                    'came_from': next_path,
                    })

        try:
            conf = self.get_sp_config(request)
        except SourceNotFound as excp:
            msg = ('Error, IdP EntityID was not found in metadata: {}')
            logger.exception(msg.format(excp))
            return HttpResponse(msg.format('Please contact technical support.'), status=500)

        # is a embedded wayf or DiscoveryService needed?
        configured_idps = available_idps(conf)
        selected_idp = request.GET.get('idp', None)

        # Do we have a Discovery Service?
        if not selected_idp:
            discovery_service = getattr(settings, 'SAML2_DISCO_URL', None)
            if discovery_service:
                # We have to build the URL to redirect to with all the information
                # for the Discovery Service to know how to send the flow back to us
                logger.debug(("A discovery process is needed trough a"
                              "Discovery Service: {}").format(discovery_service))
                login_url = request.build_absolute_uri(reverse('saml2_login'))
                login_url = '{0}?next={1}'.format(login_url,
                                                  urlquote(came_from, safe=''))
                ds_url = '{0}?entityID={1}&return={2}&returnIDParam=idp'
                ds_url = ds_url.format(discovery_service,
                                       urlquote(getattr(conf,'entityid'), safe=''),
                                       urlquote(login_url, safe=''))
                return HttpResponseRedirect(ds_url)

            elif len(configured_idps) > 1:
                logger.debug('A discovery process trough WAYF page is needed')
                return render(request, self.wayf_template, {
                        'available_idps': configured_idps.items(),
                        'came_from': next_path,
                        })

        # is the first one, otherwise next logger message will print None
        if not configured_idps:
            raise IdPConfigurationMissing(('IdP configuration is missing or its metadata is expired.'))
        if selected_idp is None:
            selected_idp = list(configured_idps.keys())[0]

        # choose a binding to try first
        sign_requests = getattr(conf, '_sp_authn_requests_signed', False)
        binding = BINDING_HTTP_POST if sign_requests else BINDING_HTTP_REDIRECT
        logger.debug('Trying binding %s for IDP %s', binding, selected_idp)

        # ensure our selected binding is supported by the IDP
        supported_bindings = get_idp_sso_supported_bindings(selected_idp, config=conf)
        if binding not in supported_bindings:
            logger.debug('Binding %s not in IDP %s supported bindings: %s', binding, selected_idp, supported_bindings)
            if binding == BINDING_HTTP_POST:
                logger.warning('IDP %s does not support %s,  trying %s', selected_idp, binding, BINDING_HTTP_REDIRECT)
                binding = BINDING_HTTP_REDIRECT
            else:
                logger.warning('IDP %s does not support %s,  trying %s', selected_idp, binding, BINDING_HTTP_POST)
                binding = BINDING_HTTP_POST
            # if switched binding still not supported, give up
            if binding not in supported_bindings:
                raise UnsupportedBinding('IDP %s does not support %s or %s', selected_idp, BINDING_HTTP_POST, BINDING_HTTP_REDIRECT)

        client = Saml2Client(conf)
        http_response = None

        kwargs = {}
        # pysaml needs a string otherwise: "cannot serialize True (type bool)"
        if getattr(conf, '_sp_force_authn', False):
            kwargs['force_authn'] = "true"
        if getattr(conf, '_sp_allow_create', False):
            kwargs['allow_create'] = "true"

        logger.debug('Redirecting user to the IdP via %s binding.', binding)
        if binding == BINDING_HTTP_REDIRECT:
            try:
                nsprefix = get_namespace_prefixes()
                if sign_requests:
                    # do not sign the xml itself, instead use the sigalg to
                    # generate the signature as a URL param
                    sig_alg_option_map = {'sha1': SIG_RSA_SHA1, 'sha256': SIG_RSA_SHA256}
                    sig_alg_option = getattr(conf, '_sp_authn_requests_signed_alg', 'sha1')
                    kwargs["sigalg"] = sig_alg_option_map[sig_alg_option]
                session_id, result = client.prepare_for_authenticate(
                    entityid=selected_idp, relay_state=next_path,
                    binding=binding, sign=sign_requests, nsprefix=nsprefix,
                    **kwargs)
            except TypeError as e:
                logger.error('Unable to know which IdP to use')
                return HttpResponse(str(e))
            else:
                http_response = HttpResponseRedirect(get_location(result))
        elif binding == BINDING_HTTP_POST:
            if self.post_binding_form_template:
                # get request XML to build our own html based on the template
                try:
                    location = client.sso_location(selected_idp, binding)
                except TypeError as e:
                    logger.error('Unable to know which IdP to use')
                    return HttpResponse(str(e))
                session_id, request_xml = client.create_authn_request(
                    location,
                    binding=binding,
                    **kwargs)
                try:
                    if isinstance(request_xml, AuthnRequest):
                        # request_xml will be an instance of AuthnRequest if the message is not signed
                        request_xml = str(request_xml)
                    saml_request = base64.b64encode(bytes(request_xml, 'UTF-8')).decode('utf-8')

                    http_response = render(request, self.post_binding_form_template, {
                        'target_url': location,
                        'params': {
                            'SAMLRequest': saml_request,
                            'RelayState': next_path,
                            },
                        })
                except TemplateDoesNotExist:
                    pass

            if not http_response:
                # use the html provided by pysaml2 if no template was specified or it didn't exist
                try:
                    session_id, result = client.prepare_for_authenticate(
                        entityid=selected_idp, relay_state=next_path,
                        binding=binding)
                except TypeError as e:
                    logger.error('Unable to know which IdP to use')
                    return HttpResponse(str(e))
                else:
                    http_response = HttpResponse(result['data'])
        else:
            raise UnsupportedBinding('Unsupported binding: %s', binding)

        # success, so save the session ID and return our response
        oq_cache = OutstandingQueriesCache(request.saml_session)
        oq_cache.set(session_id, next_path)
        logger.debug('Saving the session_id "%s" in the OutstandingQueries cache', oq_cache.__dict__)
        return http_response


@method_decorator(csrf_exempt, name='dispatch')
class AssertionConsumerServiceView(SPConfigMixin, View):
    """ The IdP will send its response to this view, which will process it using pysaml2 and
        log the user in using whatever SAML authentication backend has been enabled in
        settings.py. The `djangosaml2.backends.Saml2Backend` can be used for this purpose,
        though some implementations may instead register their own subclasses of Saml2Backend.
    """

    def handle_acs_failure(self, request, exception=None, status=403, **kwargs):
        """ Error handler if the login attempt fails. Override this to customize the error response.
        """

        # Backwards compatibility: if a custom setting was defined, use that one
        custom_failure_function = get_custom_setting('SAML_ACS_FAILURE_RESPONSE_FUNCTION')
        if custom_failure_function:
            failure_function = custom_failure_function if callable(custom_failure_function) else import_string(custom_failure_function)
            return failure_function(request, exception, status, **kwargs)

        return render(request, 'djangosaml2/login_error.html', {'exception': exception}, status=status)

    def post(self, request, attribute_mapping=None, create_unknown_user=None):
        """ SAML Authorization Response endpoint
        """

        if 'SAMLResponse' not in request.POST:
            logger.warning('Missing "SAMLResponse" parameter in POST data.')
            return HttpResponseBadRequest('Missing "SAMLResponse" parameter in POST data.')

        attribute_mapping = attribute_mapping or get_custom_setting('SAML_ATTRIBUTE_MAPPING', {'uid': ('username', )})
        create_unknown_user = create_unknown_user or get_custom_setting('SAML_CREATE_UNKNOWN_USER', True)
        conf = self.get_sp_config(request)

        client = Saml2Client(conf, identity_cache=IdentityCache(request.saml_session))
        oq_cache = OutstandingQueriesCache(request.saml_session)
        oq_cache.sync()
        outstanding_queries = oq_cache.outstanding_queries()

        _exception = None
        try:
            response = client.parse_authn_request_response(request.POST['SAMLResponse'],
                                                           BINDING_HTTP_POST,
                                                           outstanding_queries)
        except (StatusError, ToEarly) as e:
            _exception = e
            logger.exception("Error processing SAML Assertion.")
        except ResponseLifetimeExceed as e:
            _exception = e
            logger.info(("SAML Assertion is no longer valid. Possibly caused by network delay or replay attack."), exc_info=True)
        except SignatureError as e:
            _exception = e
            logger.info("Invalid or malformed SAML Assertion.", exc_info=True)
        except StatusAuthnFailed as e:
            _exception = e
            logger.info("Authentication denied for user by IdP.", exc_info=True)
        except StatusRequestDenied as e:
            _exception = e
            logger.warning("Authentication interrupted at IdP.", exc_info=True)
        except StatusNoAuthnContext as e:
            _exception = e
            logger.warning("Missing Authentication Context from IdP.", exc_info=True)
        except MissingKey as e:
            _exception = e
            logger.exception("SAML Identity Provider is not configured correctly: certificate key is missing!")
        except UnsolicitedResponse as e:
            _exception = e
            logger.exception("Received SAMLResponse when no request has been made.")

        if _exception:
            return self.handle_acs_failure(request, exception=_exception)
        elif response is None:
            logger.warning("Invalid SAML Assertion received (unknown error).")
            return self.handle_acs_failure(request, status=400, exception=SuspiciousOperation('Unknown SAML2 error'))

        session_id = response.session_id()
        oq_cache.delete(session_id)

        # authenticate the remote user
        session_info = response.session_info()

        if callable(attribute_mapping):
            attribute_mapping = attribute_mapping()
        if callable(create_unknown_user):
            create_unknown_user = create_unknown_user()

        logger.debug('Trying to authenticate the user. Session info: %s', session_info)
        user = auth.authenticate(request=request,
                                 session_info=session_info,
                                 attribute_mapping=attribute_mapping,
                                 create_unknown_user=create_unknown_user)
        if user is None:
            logger.warning("Could not authenticate user received in SAML Assertion. Session info: %s", session_info)
            return self.handle_acs_failure(request, exception=PermissionDenied('No user could be authenticated.'))

        auth.login(self.request, user)
        _set_subject_id(request.saml_session, session_info['name_id'])
        logger.debug("User %s authenticated via SSO.", user)

        self.post_login_hook(request, user, session_info)
        self.customize_session(user, session_info)

        relay_state = self.build_relay_state()
        custom_redirect_url = self.custom_redirect(user, relay_state, session_info)
        if custom_redirect_url:
            return HttpResponseRedirect(custom_redirect_url)
        relay_state = validate_referral_url(request, relay_state)
        logger.debug('Redirecting to the RelayState: %s', relay_state)
        return HttpResponseRedirect(relay_state)

    def post_login_hook(self, request: HttpRequest, user: settings.AUTH_USER_MODEL, session_info: dict) -> None:
        """ If desired, a hook to add logic after a user has succesfully logged in.
        """
        pass

    def build_relay_state(self) -> str:
        """ The relay state is a URL used to redirect the user to the view where they came from.
        """
        default_relay_state = get_custom_setting('ACS_DEFAULT_REDIRECT_URL', settings.LOGIN_REDIRECT_URL)
        relay_state = self.request.POST.get('RelayState', '/')
        relay_state = self.customize_relay_state(relay_state)
        if not relay_state:
            logger.warning('The RelayState parameter exists but is empty')
            relay_state = default_relay_state
        return relay_state

    def customize_session(self, user, session_info: dict):
        """ Subclasses can use this for customized functionality around user sessions.
        """
        pass

    def customize_relay_state(self, relay_state: str) -> str:
        """ Subclasses may override this method to implement custom logic for relay state.
        """
        return relay_state

    def custom_redirect(self, user, relay_state: str, session_info) -> str:
        """ Subclasses may override this method to implement custom logic for redirect.

            For example, some sites may require user registration if the user has not
            yet been provisioned.
        """
        return None


class EchoAttributesView(LoginRequiredMixin, SPConfigMixin, View):
    """Example view that echo the SAML attributes of an user
    """

    def get(self, request, *args, **kwargs):
        state, client = self.get_state_client(request)

        subject_id = _get_subject_id(request.saml_session)
        try:
            identity = client.users.get_identity(subject_id, check_not_on_or_after=False)
        except AttributeError:
            return HttpResponse("No active SAML identity found. Are you sure you have logged in via SAML?")

        return render(request, 'djangosaml2/echo_attributes.html', {'attributes': identity[0]})


class LogoutInitView(LoginRequiredMixin, SPConfigMixin, View):
    """ SAML Logout Request initiator

        This view initiates the SAML2 Logout request
        using the pysaml2 library to create the LogoutRequest.
    """

    def get(self, request, *args, **kwargs):
        state, client = self.get_state_client(request)

        subject_id = _get_subject_id(request.saml_session)
        if subject_id is None:
            logger.warning('The session does not contain the subject id for user %s', request.user)

        try:
            result = client.global_logout(subject_id)
        except LogoutError as exp:
            logger.exception('Error Handled - SLO not supported by IDP: {}'.format(exp))
            auth.logout(request)
            state.sync()
            return HttpResponseRedirect(settings.LOGOUT_REDIRECT_URL)

        auth.logout(request)
        state.sync()

        if not result:
            logger.error("Looks like the user %s is not logged in any IdP/AA", subject_id)
            return HttpResponseBadRequest("You are not logged in any IdP/AA")

        if len(result) > 1:
            logger.error('Sorry, I do not know how to logout from several sources. I will logout just from the first one')

        for entityid, logout_info in result.items():
            if isinstance(logout_info, tuple):
                binding, http_info = logout_info
                if binding == BINDING_HTTP_POST:
                    logger.debug('Returning form to the IdP to continue the logout process')
                    body = ''.join(http_info['data'])
                    return HttpResponse(body)
                elif binding == BINDING_HTTP_REDIRECT:
                    logger.debug('Redirecting to the IdP to continue the logout process')
                    return HttpResponseRedirect(get_location(http_info))
                else:
                    logger.error('Unknown binding: %s', binding)
                    return HttpResponseServerError('Failed to log out')
            # We must have had a soap logout
            return finish_logout(request, logout_info)

        logger.error('Could not logout because there only the HTTP_REDIRECT is supported')
        return HttpResponseServerError('Logout Binding not supported')


@method_decorator(csrf_exempt, name='dispatch')
class LogoutView(SPConfigMixin, View):
    """ SAML Logout Response endpoint

        The IdP will send the logout response to this view,
        which will process it with pysaml2 help and log the user
        out.
        Note that the IdP can request a logout even when
        we didn't initiate the process as a single logout
        request started by another SP.
    """

    logout_error_template = 'djangosaml2/logout_error.html'

    def get(self, request, *args, **kwargs):
        return self.do_logout_service(request, request.GET, BINDING_HTTP_REDIRECT, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        return self.do_logout_service(request, request.POST, BINDING_HTTP_POST, *args, **kwargs)

    def do_logout_service(self, request, data, binding):
        logger.debug('Logout service started')

        state, client = self.get_state_client(request)

        if 'SAMLResponse' in data:  # we started the logout
            logger.debug('Receiving a logout response from the IdP')
            try:
                response = client.parse_logout_request_response(data['SAMLResponse'], binding)
            except StatusError as e:
                response = None
                logger.warning("Error logging out from remote provider: " + str(e))
            state.sync()
            return finish_logout(request, response)

        elif 'SAMLRequest' in data:  # logout started by the IdP
            logger.debug('Receiving a logout request from the IdP')
            subject_id = _get_subject_id(request.saml_session)

            if subject_id is None:
                logger.warning(
                    'The session does not contain the subject id for user %s. Performing local logout',
                    request.user)
                auth.logout(request)
                return render(request, self.logout_error_template, status=403)

            http_info = client.handle_logout_request(
                data['SAMLRequest'],
                subject_id,
                binding,
                relay_state=data.get('RelayState', ''))
            state.sync()
            auth.logout(request)
            if (
                http_info.get('method', 'GET') == 'POST' and
                'data' in http_info and
                ('Content-type', 'text/html') in http_info.get('headers', [])
            ):
                # need to send back to the IDP a signed POST response with user session
                # return HTML form content to browser with auto form validation
                # to finally send request to the IDP
                return HttpResponse(http_info['data'])
            return HttpResponseRedirect(get_location(http_info))
        logger.error('No SAMLResponse or SAMLRequest parameter found')
        return HttpResponseBadRequest('No SAMLResponse or SAMLRequest parameter found')


def finish_logout(request, response, next_page=None):
    if (getattr(settings, 'SAML_IGNORE_LOGOUT_ERRORS', False) or (response and response.status_ok())):
        if next_page is None and hasattr(settings, 'LOGOUT_REDIRECT_URL'):
            next_page = settings.LOGOUT_REDIRECT_URL
        logger.debug('Performing django logout with a next_page of %s', next_page)
        return AuthLogoutView.as_view()(request, next_page=next_page)
    logger.error('Unknown error during the logout')
    return render(request, "djangosaml2/logout_error.html", {})


class MetadataView(SPConfigMixin, View):
    """ Returns an XML with the SAML 2.0 metadata for this SP as configured in the settings.py file.
    """

    def get(self, request, *args, **kwargs):
        conf = self.get_sp_config(request)
        metadata = entity_descriptor(conf)
        return HttpResponse(content=str(metadata).encode('utf-8'), content_type="text/xml; charset=utf-8")


def get_namespace_prefixes():
    from saml2 import md, saml, samlp, xmlenc, xmldsig
    return {'saml': saml.NAMESPACE,
            'samlp': samlp.NAMESPACE,
            'md': md.NAMESPACE,
            'ds': xmldsig.NAMESPACE,
            'xenc': xmlenc.NAMESPACE}
