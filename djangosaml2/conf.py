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

import copy

from django.conf import settings
from django.utils import importlib

from saml2.config import SPConfig


def config_settings_loader():
    """Utility function to load the pysaml2 configuration"""
    if getattr(settings, 'DJANGOSAML2_CONF_LOADER', None):
        module, func = settings.DJANGOSAML2_CONF_LOADER.rsplit('.', 1)
        module = importlib.import_module(module)
        return getattr(module, func)()
    else:
        conf = SPConfig()
        conf.load(copy.deepcopy(settings.SAML_CONFIG))
        return conf
