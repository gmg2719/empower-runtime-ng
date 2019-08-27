#!/usr/bin/env python3
#
# Copyright (c) 2019 Roberto Riggio
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.

"""Extra PyMODM types."""

from pymodm.errors import ValidationError
from pymodm.base.fields import MongoBaseField

from empower.core.etheraddress import EtherAddress
from empower.core.plmnid import PLMNID
from empower.core.ssid import SSID


class SSIDField(MongoBaseField):
    """A field that stores SSIDs."""

    def __init__(self, verbose_name=None, mongo_name=None, **kwargs):

        super(SSIDField, self).__init__(verbose_name=verbose_name,
                                        mongo_name=mongo_name,
                                        **kwargs)

        def validate_ssid(value):

            try:
                SSID(value)
            except ValueError:
                msg = '%r is not a valid SSID.' % value
                raise ValidationError(msg)

        self.validators.append(validate_ssid)

    @classmethod
    def to_mongo(cls, value):
        """Convert value for storage."""

        try:
            return str(value)
        except ValueError:
            msg = '%r is not a valid SSID.' % value
            raise ValidationError(msg)

    @classmethod
    def to_python(cls, value):
        """Convert value back to Python."""

        try:
            return SSID(value)
        except ValueError:
            msg = '%r is not a valid SSID.' % value
            raise ValidationError(msg)


class EtherAddressField(MongoBaseField):
    """A field that stores EtherAddresses."""

    def __init__(self, verbose_name=None, mongo_name=None, **kwargs):

        super(EtherAddressField, self).__init__(verbose_name=verbose_name,
                                                mongo_name=mongo_name,
                                                **kwargs)

        def validate_ethernet_address(value):

            try:
                EtherAddress(value)
            except ValueError:
                msg = '%r is not a valid Ethernet address.' % value
                raise ValidationError(msg)

        self.validators.append(validate_ethernet_address)

    @classmethod
    def to_mongo(cls, value):
        """Convert value for storage."""

        try:
            return str(value)
        except ValueError:
            msg = '%r is not a valid Ethernet address.' % value
            raise ValidationError(msg)

    @classmethod
    def to_python(cls, value):
        """Convert value back to Python."""

        try:
            return EtherAddress(value)
        except ValueError:
            msg = '%r is not a valid Ethernet address.' % value
            raise ValidationError(msg)


class PLMNIDField(MongoBaseField):
    """A field that stores PLMNIDs."""

    def __init__(self, verbose_name=None, mongo_name=None, **kwargs):

        super(PLMNIDField, self).__init__(verbose_name=verbose_name,
                                          mongo_name=mongo_name,
                                          **kwargs)

        def validate_plmnid(value):

            try:
                PLMNID(value)
            except ValueError:
                msg = '%r is not a valid PLMN id.' % value
                raise ValidationError(msg)

        self.validators.append(validate_plmnid)

    @classmethod
    def to_mongo(cls, value):
        """Convert value for storage."""

        try:
            return str(value)
        except ValueError:
            msg = '%r is not a valid PLMN id.' % value
            raise ValidationError(msg)

    @classmethod
    def to_python(cls, value):
        """Convert value back to Python."""

        try:
            return PLMNID(value)
        except ValueError:
            msg = '%r is not a valid PLMN id.' % value
            raise ValidationError(msg)
