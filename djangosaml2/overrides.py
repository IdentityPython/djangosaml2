import logging

from django.conf import settings

from pygamlastan.compat.saml2.client import Saml2Client as BaseSaml2Client

logger = logging.getLogger("djangosaml2")


class Saml2Client(BaseSaml2Client):
    """
    Custom Saml2Client that adds a choice of preference for binding used with
    SAML Logout Requests. The preferred binding can be configured via
    SAML_LOGOUT_REQUEST_PREFERRED_BINDING settings variable.
    The base client supports browser bindings only; this override lets a Django
    setting choose which one is attempted first.
    """

    def do_logout(self, *args, **kwargs):
        if not kwargs.get("expected_binding"):
            try:
                kwargs["expected_binding"] = (
                    settings.SAML_LOGOUT_REQUEST_PREFERRED_BINDING
                )
            except AttributeError:
                logger.warning(
                    "SAML_LOGOUT_REQUEST_PREFERRED_BINDING setting is"
                    " not defined. Default binding will be used."
                )
        return super().do_logout(*args, **kwargs)
