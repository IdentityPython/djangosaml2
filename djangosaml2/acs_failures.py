# -*- coding: utf-8 -*-
#
# This module defines a set of useful ACS failure functions that are used to
# produce an output suitable for end user in case of SAML failure.
#
from __future__ import unicode_literals

from django.shortcuts import render


def template_failure(request, exception=None, **kwargs):
    """ Renders a simple template with an error message. """
    return render(request, 'djangosaml2/login_error.html', {'exception': exception}, status=kwargs.get('status', 403))
