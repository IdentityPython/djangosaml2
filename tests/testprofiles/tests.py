# Copyright (C) 2012 Sam Bull (lsb@pocketuniverse.ca)
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
import shutil
import sys
import time
from contextlib import contextmanager
from datetime import timedelta
from http.client import HTTPResponse
from tempfile import NamedTemporaryFile, mkdtemp
try:
    from unittest import mock
except ImportError:
    import mock

from defusedxml.ElementTree import ParseError
from django.contrib.auth import get_user_model
from django.contrib.auth.models import User as DjangoUserModel
from django.core.management import call_command
from django.test import TestCase, override_settings
from six import StringIO

from djangosaml2.backends import Saml2Backend
from djangosaml2.management.commands.fetch_metadata import UnexpectedStatusCode

User = get_user_model()

if sys.version_info < (3, 4):
    # Monkey-patch TestCase to add the assertLogs method introduced in
    # Python 3.4
    from unittest2.case import _AssertLogsContext

    class LoggerTestCase(TestCase):
        def assertLogs(self, logger=None, level=None):
            return _AssertLogsContext(self, logger, level)

    TestCase = LoggerTestCase


class Saml2BackendTests(TestCase):
    def test_update_user(self):
        # we need a user
        user = User.objects.create(username='john')

        backend = Saml2Backend()

        attribute_mapping = {
            'uid': ('username', ),
            'mail': ('email', ),
            'cn': ('first_name', ),
            'sn': ('last_name', ),
            }
        attributes = {
            'uid': ('john', ),
            'mail': ('john@example.com', ),
            'cn': ('John', ),
            'sn': ('Doe', ),
            }
        backend.update_user(user, attributes, attribute_mapping)
        self.assertEqual(user.email, 'john@example.com')
        self.assertEqual(user.first_name, 'John')
        self.assertEqual(user.last_name, 'Doe')

        attribute_mapping['saml_age'] = ('age', )
        attributes['saml_age'] = ('22', )
        backend.update_user(user, attributes, attribute_mapping)
        self.assertEqual(user.age, '22')

    def test_update_user_callable_attributes(self):
        user = User.objects.create(username='john')

        backend = Saml2Backend()
        attribute_mapping = {
            'uid': ('username', ),
            'mail': ('email', ),
            'cn': ('process_first_name', ),
            'sn': ('last_name', ),
            }
        attributes = {
            'uid': ('john', ),
            'mail': ('john@example.com', ),
            'cn': ('John', ),
            'sn': ('Doe', ),
            }
        backend.update_user(user, attributes, attribute_mapping)
        self.assertEqual(user.email, 'john@example.com')
        self.assertEqual(user.first_name, 'John')
        self.assertEqual(user.last_name, 'Doe')

    def test_update_user_empty_attribute(self):
        user = User.objects.create(username='john', last_name='Smith')

        backend = Saml2Backend()
        attribute_mapping = {
            'uid': ('username', ),
            'mail': ('email', ),
            'cn': ('first_name', ),
            'sn': ('last_name', ),
            }
        attributes = {
            'uid': ('john', ),
            'mail': ('john@example.com', ),
            'cn': ('John', ),
            'sn': (),
            }
        with self.assertLogs('djangosaml2', level='DEBUG') as logs:
            backend.update_user(user, attributes, attribute_mapping)
        self.assertEqual(user.email, 'john@example.com')
        self.assertEqual(user.first_name, 'John')
        # empty attribute list: no update
        self.assertEqual(user.last_name, 'Smith')
        self.assertIn(
            'DEBUG:djangosaml2:Could not find value for "sn", not '
            'updating fields "(\'last_name\',)"',
            logs.output,
        )

    def test_invalid_model_attribute_log(self):
        backend = Saml2Backend()

        attribute_mapping = {
            'uid': ['username'],
            'cn': ['nonexistent'],
        }
        attributes = {
            'uid': ['john'],
            'cn': ['John'],
        }

        with self.assertLogs('djangosaml2', level='DEBUG') as logs:
            backend.get_saml2_user(True, 'john', attributes, attribute_mapping)

        self.assertIn(
            'DEBUG:djangosaml2:Could not find attribute "nonexistent" on user "john"',
            logs.output,
        )

    def test_django_user_main_attribute(self):
        backend = Saml2Backend()

        old_username_field = User.USERNAME_FIELD
        User.USERNAME_FIELD = 'slug'
        self.assertEqual(backend.get_django_user_main_attribute(), 'slug')
        User.USERNAME_FIELD = old_username_field

        with override_settings(AUTH_USER_MODEL='auth.User'):
            self.assertEqual(
                DjangoUserModel.USERNAME_FIELD,
                backend.get_django_user_main_attribute())

        with override_settings(
                AUTH_USER_MODEL='testprofiles.StandaloneUserModel'):
            self.assertEqual(
                backend.get_django_user_main_attribute(),
                'username')

        with override_settings(SAML_DJANGO_USER_MAIN_ATTRIBUTE='foo'):
            self.assertEqual(backend.get_django_user_main_attribute(), 'foo')

    def test_django_user_main_attribute_lookup(self):
        backend = Saml2Backend()

        self.assertEqual(backend.get_django_user_main_attribute_lookup(), '')

        with override_settings(
                SAML_DJANGO_USER_MAIN_ATTRIBUTE_LOOKUP='__iexact'):
            self.assertEqual(
                backend.get_django_user_main_attribute_lookup(),
                '__iexact')


class LowerCaseSaml2Backend(Saml2Backend):
    def clean_attributes(self, attributes):
        return dict([k.lower(), v] for k, v in attributes.items())


class LowerCaseSaml2BackendTest(TestCase):
    def test_update_user_clean_attributes(self):
        user = User.objects.create(username='john')
        attribute_mapping = {
            'uid': ('username', ),
            'mail': ('email', ),
            'cn': ('first_name', ),
            'sn': ('last_name', ),
            }
        attributes = {
            'UID': ['john'],
            'MAIL': ['john@example.com'],
            'CN': ['John'],
            'SN': [],
        }

        backend = LowerCaseSaml2Backend()
        user = backend.authenticate(
            None,
            session_info={'ava': attributes},
            attribute_mapping=attribute_mapping,
        )
        self.assertIsNotNone(user)


@contextmanager
def fake_url_open(text=b'OK', status=200):
    response = mock.Mock(spec=HTTPResponse)
    response.status = status

    class FakeReader(object):
        has_read = False
        def read(self, *args, **kwargs):
            response_text = text if not self.has_read else b''
            self.has_read = True
            return response_text

    response.read = FakeReader().read
    yield response


class FetchMetadataTests(TestCase):
    def setUp(self):
        super(FetchMetadataTests, self).setUp()
        self.wd = mkdtemp()
        self.addCleanup(shutil.rmtree, self.wd)

    @mock.patch('djangosaml2.management.commands.fetch_metadata.urlopen',
                return_value=fake_url_open(text=b'Not found', status=404))
    def test_url_bad_status_code_is_logged(self, urlopen_mock):
        with self.assertRaisesMessage(
            UnexpectedStatusCode,
            'Unexpected HTTP status code when downloading metadata file: 404'
        ):
            call_command('fetch_metadata', 'mocked', os.path.join(self.wd, 'test.xml'))

    @mock.patch('djangosaml2.management.commands.fetch_metadata.urlopen',
                return_value=fake_url_open(text=b'<xml>OK</xml>'))
    def test_create_metadata_file(self, urlopen_mock):
        out = StringIO()
        test_file = os.path.join(self.wd, 'test.xml')
        call_command('fetch_metadata', 'mocked', test_file, stdout=out)
        self.assertEqual(open(test_file, 'rb').read(), b'<xml>OK</xml>')
        self.assertEqual(out.getvalue(), '')

    def test_create_metadata_file_verbosity(self):
        test_file = os.path.join(self.wd, 'test.xml')

        out = StringIO()
        with mock.patch('djangosaml2.management.commands.fetch_metadata.urlopen',
                        return_value=fake_url_open(text=b'<xml>OK</xml>')):
            call_command('fetch_metadata', 'mocked', test_file, stdout=out, verbosity=0)
        self.assertEqual(out.getvalue(), '')
        os.unlink(test_file)

        out = StringIO()
        with mock.patch('djangosaml2.management.commands.fetch_metadata.urlopen',
                        return_value=fake_url_open(text=b'<xml>OK</xml>')):
            call_command('fetch_metadata', 'mocked', test_file, stdout=out, verbosity=1)
        self.assertEqual(out.getvalue(), '')
        os.unlink(test_file)

        out = StringIO()
        with mock.patch('djangosaml2.management.commands.fetch_metadata.urlopen',
                        return_value=fake_url_open(text=b'<xml>OK</xml>')):
            call_command('fetch_metadata', 'mocked', test_file, stdout=out, verbosity=2)
        self.assertEqual(
            out.getvalue(),
            'Metadata file "%s" does not exist, creating it.\n'
            'Metadata successfully saved as "%s".\n'
            % (test_file, test_file))
        os.unlink(test_file)

        out = StringIO()
        with mock.patch('djangosaml2.management.commands.fetch_metadata.urlopen',
                        return_value=fake_url_open(text=b'<xml>OK</xml>')):
            call_command('fetch_metadata', 'mocked', test_file, stdout=out, verbosity=3)
        self.assertEqual(
            out.getvalue(),
            'Metadata file "%s" does not exist, creating it.\n'
            'Metadata successfully saved as "%s".\n'
            % (test_file, test_file))
        os.unlink(test_file)

    @mock.patch('djangosaml2.management.commands.fetch_metadata.urlopen',
                return_value=fake_url_open(text=b'<xml>OK</xml>'))
    def test_update_metadata_file(self, urlopen_mock):
        with NamedTemporaryFile(dir=self.wd, delete=False) as existing_metadata:
            pass
        with mock.patch(
            'djangosaml2.management.commands.fetch_metadata.os.path.getmtime',
            return_value=time.time() - timedelta(days=5).total_seconds()
        ):
            call_command('fetch_metadata', 'mocked', existing_metadata.name, max_age=24 * 60 * 60)

        self.assertEqual(open(existing_metadata.name, 'rb').read(), b'<xml>OK</xml>')
        os.unlink(existing_metadata.name)

    @mock.patch(
        'djangosaml2.management.commands.fetch_metadata.os.path.getmtime',
        return_value=time.time() - timedelta(days=5).total_seconds())
    def test_update_outdated_metadata_file_verbosity(self, getmtime_mock):
        with NamedTemporaryFile(dir=self.wd, delete=False) as existing_metadata:
            pass
        test_file = existing_metadata.name

        out = StringIO()
        with mock.patch('djangosaml2.management.commands.fetch_metadata.urlopen',
                        return_value=fake_url_open(text=b'<xml>OK</xml>')):
            call_command('fetch_metadata', 'mocked', test_file, stdout=out, verbosity=0)
        self.assertEqual(out.getvalue(), '')

        out = StringIO()
        with mock.patch('djangosaml2.management.commands.fetch_metadata.urlopen',
                        return_value=fake_url_open(text=b'<xml>OK</xml>')):
            call_command('fetch_metadata', 'mocked', test_file, stdout=out, verbosity=1)
        self.assertEqual(out.getvalue(), '')

        out = StringIO()
        with mock.patch('djangosaml2.management.commands.fetch_metadata.urlopen',
                        return_value=fake_url_open(text=b'<xml>OK</xml>')):
            call_command('fetch_metadata', 'mocked', test_file, stdout=out, verbosity=2)
        self.assertEqual(
            out.getvalue(),
            'Metadata file "%s" is outdated, updating it.\n'
            'Metadata successfully saved as "%s".\n' % (
                test_file, test_file))

        out = StringIO()
        with mock.patch('djangosaml2.management.commands.fetch_metadata.urlopen',
                        return_value=fake_url_open(text=b'<xml>OK</xml>')):
            call_command('fetch_metadata', 'mocked', test_file, stdout=out, verbosity=3)
        self.assertEqual(
            out.getvalue(),
            'Metadata file "%s" is outdated, updating it.\n'
            'Metadata successfully saved as "%s".\n' % (
                test_file, test_file))

        os.unlink(test_file)

    @mock.patch(
        'djangosaml2.management.commands.fetch_metadata.os.path.getmtime',
        return_value=time.time() - timedelta(seconds=1).total_seconds())
    def test_update_recent_metadata_file_verbosity(self, getmtime_mock):
        with NamedTemporaryFile(dir=self.wd, delete=False) as existing_metadata:
            pass
        test_file = existing_metadata.name

        out = StringIO()
        with mock.patch('djangosaml2.management.commands.fetch_metadata.urlopen',
                        return_value=fake_url_open(text=b'<xml>OK</xml>')):
            call_command('fetch_metadata', 'mocked', test_file, stdout=out, verbosity=0)
        self.assertEqual(out.getvalue(), '')

        out = StringIO()
        with mock.patch('djangosaml2.management.commands.fetch_metadata.urlopen',
                        return_value=fake_url_open(text=b'<xml>OK</xml>')):
            call_command('fetch_metadata', 'mocked', test_file, stdout=out, verbosity=1)
        self.assertEqual(out.getvalue(), '')

        out = StringIO()
        with mock.patch('djangosaml2.management.commands.fetch_metadata.urlopen',
                        return_value=fake_url_open(text=b'<xml>OK</xml>')):
            call_command('fetch_metadata', 'mocked', test_file, stdout=out, verbosity=2)
        self.assertEqual(
            out.getvalue(),
            'Metadata file "%s" is recent enough, skipping.\n' % test_file)

        out = StringIO()
        with mock.patch('djangosaml2.management.commands.fetch_metadata.urlopen',
                        return_value=fake_url_open(text=b'<xml>OK</xml>')):
            call_command('fetch_metadata', 'mocked', test_file, stdout=out, verbosity=3)
        self.assertEqual(
            out.getvalue(),
            'Metadata file "%s" is recent enough, skipping.\n' % test_file)

        os.unlink(test_file)

    @mock.patch('djangosaml2.management.commands.fetch_metadata.urlopen',
                return_value=fake_url_open(text=b'<xml>OK</xml>'))
    def test_update_metadata_max_age(self, urlopen_mock):
        max_age = 4 * 60 * 60  # 4 hours
        with NamedTemporaryFile(dir=self.wd, delete=False) as existing_metadata:
            pass
        with mock.patch(
            'djangosaml2.management.commands.fetch_metadata.os.path.getmtime',
            return_value=time.time() - timedelta(hours=3, minutes=59, seconds=59).total_seconds()
        ):
            call_command('fetch_metadata', 'mocked', existing_metadata.name, max_age=max_age)
        # Less than max-age, metadata file is not updated.
        self.assertEqual(open(existing_metadata.name, 'rb').read(), b'')

        with mock.patch(
            'djangosaml2.management.commands.fetch_metadata.os.path.getmtime',
            return_value=time.time() - timedelta(hours=4).total_seconds()
        ):
            call_command('fetch_metadata', 'mocked', existing_metadata.name, max_age=max_age)
        # After max-age, metadata file is updated.
        self.assertEqual(open(existing_metadata.name, 'rb').read(), b'<xml>OK</xml>')
        os.unlink(existing_metadata.name)

    @mock.patch('djangosaml2.management.commands.fetch_metadata.urlopen',
                return_value=fake_url_open(text=b'invalid xml content'))
    def test_invalid_xml(self, urlopen_mock):
        test_file = os.path.join(self.wd, 'test.xml')
        with self.assertRaises(ParseError):
            call_command('fetch_metadata', 'mocked', test_file)
