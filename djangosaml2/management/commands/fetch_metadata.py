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

from __future__ import unicode_literals

import errno
import os
import shutil
import time
from http.client import HTTPException
from tempfile import NamedTemporaryFile
from defusedxml import ElementTree

from django.core.management.base import BaseCommand
from six.moves.urllib.request import urlopen


class UnexpectedStatusCode(HTTPException):
    pass


class Command(BaseCommand):
    help = """Refreshes local metadata cache.

    Downloads metadata from URL and caches the result in output file. The cache
    is valid for max-age seconds.
    The file age is considered to be the last modification time.
    """
    requires_system_checks = False

    def add_arguments(self, parser):
        parser.add_argument('metadata_url', help="URL to download the metadata XML file from.")
        parser.add_argument('output_file', help="Metadata file destination.")
        default_max_age_seconds = 24 * 3600
        parser.add_argument(
            '-m', '--max-age', default=default_max_age_seconds, type=int,
            help=(
                "Refresh file if older than max-age seconds. "
                "Default: %d seconds (%d hours)" % (
                    default_max_age_seconds,
                    default_max_age_seconds / 3600,
                )
            )
        )

    def handle(self, *args, **options):
        fetch = False
        try:
            mtime = os.path.getmtime(options['output_file'])
        except OSError as e:
            # Use FileNotFoundError when Python 2 support is dropped
            if e.errno == errno.ENOENT:
                fetch = True
                if options['verbosity'] >= 2:
                    self.stdout.write(
                        'Metadata file "%s" does not exist, creating it.\n' %
                        options['output_file'])
            else:
                raise
        else:
            fetch = mtime + options['max_age'] < time.time()
            if options['verbosity'] >= 2:
                if fetch:
                    self.stdout.write(
                        'Metadata file "%s" is outdated, updating it.\n' %
                        options['output_file'])
                else:
                    self.stdout.write(
                        'Metadata file "%s" is recent enough, skipping.\n' %
                        options['output_file'])

        if fetch:
            with NamedTemporaryFile(delete=False) as downloaded_file:
                with urlopen(options['metadata_url']) as infile:
                    if infile.status != 200:
                        raise UnexpectedStatusCode(
                            'Unexpected HTTP status code when downloading '
                            'metadata file: %s' % infile.status)

                    chunk = True
                    while chunk:
                        chunk = infile.read(8192)
                        downloaded_file.write(chunk)

            with open(downloaded_file.name, 'rb') as metadata_file:
                # Verify that metadata XML is valid
                ElementTree.parse(metadata_file)

            # Install new metadata file
            shutil.move(downloaded_file.name, options['output_file'])
            if options['verbosity'] >= 2:
                self.stdout.write(
                    'Metadata successfully saved as "%s".\n' %
                    options['output_file'])
