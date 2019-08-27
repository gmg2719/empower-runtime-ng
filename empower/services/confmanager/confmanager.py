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

"""Conf manager."""

import uuid

from empower.core.service import EService

from empower.services.confmanager.confhandler import WorkersHandler, \
    WorkerAttributesHandler, CatalogHandler, DocHandler, ServicesHandler
from empower.services.confmanager.conf import Conf


class ConfManager(EService):
    """Projects manager."""

    HANDLERS = [WorkersHandler, WorkerAttributesHandler, CatalogHandler,
                DocHandler, ServicesHandler]

    conf = {}

    def start(self, load=True):
        """Start configuration manager."""

        super().start(load)

        if not Conf.objects.all().count():
            Conf(project_id=uuid.uuid4()).save()

        self.conf = Conf.objects.first()

        self.conf.start_services()


def launch(**kwargs):
    """Start project manager."""

    return ConfManager(**kwargs)
