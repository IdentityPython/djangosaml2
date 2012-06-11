#!/usr/bin/env python

import os, os.path
import sys
import pprint

path, scriptname = os.path.split(__file__)

sys.path.append(os.path.abspath(path))
sys.path.append(os.path.abspath(os.path.join(path, '..')))

os.environ['DJANGO_SETTINGS_MODULE'] = 'tests.settings'

from django.core import management

management.call_command('test', 'djangosaml2')

