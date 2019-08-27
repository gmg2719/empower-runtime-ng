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

"""Wi-Fi Service Set Identifier (SSID)."""

import re

WIFI_NWID_MAXSIZE = 32


class SSID:
    """Wi-Fi Service Set Identifier (SSID)."""

    def __init__(self, ssid=None):

        if not ssid:
            ssid = ""

        if isinstance(ssid, bytes):
            self.ssid = ssid.decode('UTF-8').rstrip('\0')
        elif isinstance(ssid, str):
            allowed = re.compile(r'^[a-zA-Z0-9_]*$',
                                 re.VERBOSE | re.IGNORECASE)
            if allowed.match(ssid) is None:
                raise ValueError("Invalid SSID name")
            self.ssid = ssid
        elif isinstance(ssid, SSID):
            self.ssid = str(ssid)
        else:
            raise ValueError("SSID must be a string or an array of UTF-8 "
                             "encoded bytes array of UTF-8 encoded bytes")

    def to_raw(self):
        """ Return the bytes represenation of the SSID """

        bytes_ssid = self.ssid.encode('UTF-8')
        return bytes_ssid + b'\0' * (WIFI_NWID_MAXSIZE + 1 - len(bytes_ssid))

    def to_str(self):
        """Return an ASCII representation of the object."""

        return self.ssid

    def __bool__(self):
        return bool(self.ssid)

    def __str__(self):
        return self.to_str()

    def __len__(self):
        return len(self.ssid)

    def __hash__(self):
        return hash(self.ssid)

    def __eq__(self, other):
        if isinstance(other, SSID):
            return self.ssid == other.ssid
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __repr__(self):
        return self.__class__.__name__ + "('" + self.to_str() + "')"
