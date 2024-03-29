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

"""Base worker class."""

from uuid import UUID

from empower.main import srv_or_die
from empower.core.service import EService


class EWorker(EService):
    """Base worker class."""

    def __init__(self, service_id, **kwargs):

        if 'every' not in kwargs:
            kwargs['every'] = 2000

        super().__init__(service_id=service_id, **kwargs)

    def start(self, load=True):
        """Start worker."""

        # Set pointer to context
        conf_manager = srv_or_die("empower.services.confmanager.confmanager")
        self.context = conf_manager.conf

        # start the service
        super().start(load)

    @property
    def project_id(self):
        """Return project_id."""

        return self.params["project_id"]

    @project_id.setter
    def project_id(self, value):
        """Set project_id."""

        if "project_id" in self.params and self.params["project_id"]:
            raise ValueError("Param project_id can not be changed")

        if not isinstance(value, UUID):
            value = UUID(value)

        self.params["project_id"] = value
