# Copyright (C) 2010-2012 Yaco Sistemas (http://www.yaco.es)
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

from django.conf import settings
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import User, SiteProfileNotAvailable
from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned

logger = logging.getLogger('djangosaml2')


class Saml2Backend(ModelBackend):

    def authenticate(self, session_info=None, attribute_mapping=None,
                     create_unknown_user=True):
        if session_info is None or attribute_mapping is None:
            logger.error('Session info or attribute mapping are None')
            return None

        if not 'ava' in session_info:
            logger.error('"ava" key not found in session_info')
            return None

        attributes = session_info['ava']
        if not attributes:
            logger.error('The attributes dictionary is empty')

        django_user_main_attribute = getattr(
            settings, 'SAML_DJANGO_USER_MAIN_ATTRIBUTE', 'username')

        logger.debug('attributes: %s' % attributes)
        logger.debug('attribute_mapping: %s' % attribute_mapping)
        saml_user = None
        for saml_attr, django_fields in attribute_mapping.items():
            if (django_user_main_attribute in django_fields
                and saml_attr in attributes):
                saml_user = attributes[saml_attr][0]

        if saml_user is None:
            logger.error('Could not find saml_user value')
            return None

        user = None
        main_attribute = self.clean_user_main_attribute(saml_user)

        user_query_args = {django_user_main_attribute: main_attribute}

        # Note that this could be accomplished in one try-except clause, but
        # instead we use get_or_create when creating unknown users since it has
        # built-in safeguards for multiple threads.
        if create_unknown_user:
            logger.debug('Check if the user "%s" exists or create otherwise'
                         % main_attribute)
            try:
                user, created = User.objects.get_or_create(**user_query_args)
            except MultipleObjectsReturned:
                logger.error("There are more than one user with %s = %s" %
                             (django_user_main_attribute, main_attribute))
                return None

            if created:
                logger.debug('New user created')
                user = self.configure_user(user, attributes, attribute_mapping)
            else:
                logger.debug('User updated')
                user = self.update_user(user, attributes, attribute_mapping)
        else:
            logger.debug('Retrieving existing user "%s"' % main_attribute)
            try:
                user = User.objects.get(**user_query_args)
                user = self.update_user(user, attributes, attribute_mapping)
            except User.DoesNotExist:
                logger.error('The user "%s" does not exist' % main_attribute)
                return None
            except MultipleObjectsReturned:
                logger.error("There are more than one user with %s = %s" %
                             (django_user_main_attribute, main_attribute))
                return None

        return user

    def clean_user_main_attribute(self, main_attribute):
        """Performs any cleaning on the user main attribute (which
        usually is "username") prior to using it to get or
        create the user object.  Returns the cleaned attribute.

        By default, returns the attribute unchanged.
        """
        return main_attribute

    def configure_user(self, user, attributes, attribute_mapping):
        """Configures a user after creation and returns the updated user.

        By default, returns the user with his attributes updated.
        """
        user.set_unusable_password()
        return self.update_user(user, attributes, attribute_mapping,
                                force_save=True)

    def update_user(self, user, attributes, attribute_mapping,
                    force_save=False):
        """Update a user with a set of attributes and returns the updated user.

        By default it uses a mapping defined in the settings constant
        SAML_ATTRIBUTE_MAPPING. For each attribute, if the user object has
        that field defined it will be set, otherwise it will try to set
        it in the profile object.
        """
        if not attribute_mapping:
            return user

        try:
            profile = user.get_profile()
        except ObjectDoesNotExist:
            profile = None
        except SiteProfileNotAvailable:
            profile = None

        user_modified = False
        profile_modified = False
        for saml_attr, django_attrs in attribute_mapping.items():
            try:
                for attr in django_attrs:
                    if hasattr(user, attr):
                        setattr(user, attr, attributes[saml_attr][0])
                        user_modified = True

                    elif profile is not None and hasattr(profile, attr):
                        setattr(profile, attr, attributes[saml_attr][0])
                        profile_modified = True

            except KeyError:
                # the saml attribute is missing
                pass

        if user_modified or force_save:
            user.save()

        if profile is not None and (profile_modified or force_save):
            profile.save()

        return user
