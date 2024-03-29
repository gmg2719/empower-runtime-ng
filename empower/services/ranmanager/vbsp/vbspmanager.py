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

"""VBSP RAN Manager."""

import empower.services.ranmanager.vbsp as vbsp

from empower.services.ranmanager.ranmanager import RANManager
from empower.services.ranmanager.vbsp.vbsphandlers import VBSHandler
from empower.services.ranmanager.vbsp.vbspconnection import VBSPConnection
from empower.core.vbs import VBS

DEFAULT_PORT = 5533


class VBSPManager(RANManager):
    """VBSP RAN Manager

    Parameters:
        port: the port on which the TCP server should listen (optional,
            default: 5533)
    """

    HANDLERS = [VBSHandler]

    def __init__(self, **kwargs):

        if 'port' not in kwargs:
            kwargs['port'] = DEFAULT_PORT

        super().__init__(device_type=VBS,
                         connection_type=VBSPConnection,
                         proto=vbsp,
                         **kwargs)

        self.ueqs = {}


def launch(**kwargs):
    """Start VBSP Server Module."""

    return VBSPManager(**kwargs)
