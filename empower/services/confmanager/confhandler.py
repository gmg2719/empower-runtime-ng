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

"""Exposes a RESTful interface ."""

import uuid
import pkgutil
import inspect

import empower.workers
import empower.services.apimanager.apimanager as apimanager

from empower.main import srv_or_die
from empower.main import SERVICES


BOILER_PLATE = """# EmPOWER REST API

The EmPOWER API consists of a set of RESTful resources and their attributes.
The base URL for the EmPOWER REST API is the following:

    http{s}://{username}:{password}@{hostname}:{port}/api/v1/{resource}

Of course you need to replace hostname and port with the hostname/port
combination for your controller.

The current (and only) version of the API is v1.

5G-EmPOWER uses HTTP basic authentication in order to control and limit access
to RESTful resource.

Notice that there are two kinds of accounts:

 * user accounts, which have complete CRUD access only to all the URLs that
 beging with /api/v1/projects/{project_id}, where 'project_id' is the id of a
 Project that belongs to the user making the request specified in the HTTP
 basic authentication.

 * root account, which has complete CRUD access to all URLs. All the URLs that
 DO NOT start with /api/v1/projects/{project_id} require a root account to
 be accessed. The only exception is the URL /api/v1/accounts/{user_id} which
 is fully accessible to all users.
 """


# pylint: disable=W0223
class DocHandler(apimanager.EmpowerAPIHandler):
    """Generates markdown documentation."""

    URLS = [r"/api/v1/doc/?"]

    def get(self, *args, **kwargs):
        """Generates markdown documentation.

        Args:

            None

        Example URLs:

            GET /api/v1/doc
        """

        # Register handlers for this services
        api_manager = srv_or_die("empower.services.apimanager.apimanager")

        exclude_list = ["StaticFileHandler", "DocHandler"]
        handlers = set()
        accum = [BOILER_PLATE]

        for rule in api_manager.application.default_router.rules:
            handlers.add(rule.target.rules[0].target)

        handlers = sorted(handlers, key=lambda x: x.__name__)

        accum.append("## <a name='handlers'></a>Handlers\n")

        for handler in handlers:

            if handler.__name__ in exclude_list:
                continue

            accum.append(" * [%s](#%s)" %
                         (handler.__name__, handler.__name__))

        accum.append("\n")

        for handler in handlers:

            if handler.__name__ in exclude_list:
                continue

            accum.append("# <a name='%s'></a>%s ([Top](#handlers))\n" %
                         (handler.__name__, handler.__name__))

            accum.append("%s\n" % inspect.getdoc(handler))

            if hasattr(handler, "URLS") and handler.URLS:
                accum.append("### URLs\n")
                for url in handler.URLS:
                    accum.append("    %s" % url)

            accum.append("\n")

            if hasattr(handler, "get"):
                doc = inspect.getdoc(getattr(handler, "get"))
                if doc:
                    accum.append("### GET\n")
                    accum.append(doc)
                    accum.append("\n")

            if hasattr(handler, "put"):
                doc = inspect.getdoc(getattr(handler, "put"))
                if doc:
                    accum.append("### PUT\n")
                    accum.append(doc)
                    accum.append("\n")

            if hasattr(handler, "post"):
                doc = inspect.getdoc(getattr(handler, "post"))
                if doc:
                    accum.append("### POST\n")
                    accum.append(doc)
                    accum.append("\n")

            if hasattr(handler, "delete"):
                doc = inspect.getdoc(getattr(handler, "delete"))
                if doc:
                    accum.append("### DELETE\n")
                    accum.append(doc)
                    accum.append("\n")

        self.write('\n'.join(accum))


# pylint: disable=W0223
class CatalogHandler(apimanager.EmpowerAPIHandler):
    """Access the workers catalog."""

    URLS = [r"/api/v1/catalog/?"]

    @classmethod
    def __walk_module(cls, package):

        results = {}

        pkgs = pkgutil.walk_packages(package.__path__)

        for _, module_name, is_pkg in pkgs:

            __import__(package.__name__ + "." + module_name)

            if not is_pkg:
                continue

            if not hasattr(package, module_name):
                continue

            module = getattr(package, module_name)

            if not hasattr(module, "MANIFEST"):
                continue

            manifest = getattr(module, "MANIFEST")

            name = package.__name__ + "." + module_name + "." + module_name

            manifest['name'] = name
            manifest['desc'] = module.__doc__

            results[name] = manifest

        return results

    @apimanager.validate(min_args=0, max_args=0)
    def get(self, *args, **kwargs):
        """List of available workers.

        Example URLs:

             GET /api/v1/catalog

            [
                {
                    "name":
                        "empower.workers.wifichannelstats.wifichannelstats",
                    "params": {
                        "every": 2000,
                        "project_id": "4cd2bca2-8c28-4e66-9c8a-7cbd1ba4e6f9",
                        "service_id": "0f91e8ad-1c2a-4b06-97f9-e34097c4c1d0"
                    }
                }
            ]
        """

        return self.__walk_module(empower.workers).values()


# pylint: disable=W0223
class ServicesHandler(apimanager.EmpowerAPIHandler):
    """Access the system services."""

    URLS = [r"/api/v1/services/?",
            r"/api/v1/services/([a-zA-Z0-9.]*)/?"]

    @apimanager.validate(min_args=0, max_args=1)
    def get(self, *args, **kwargs):
        """List of running services.

        Example URLs:

             GET /api/v1/services

            [
                {
                    "name":
                        "empower.workers.wifichannelstats.wifichannelstats",
                    "params": {
                        "every": 2000,
                        "project_id": "4cd2bca2-8c28-4e66-9c8a-7cbd1ba4e6f9",
                        "service_id": "0f91e8ad-1c2a-4b06-97f9-e34097c4c1d0"
                    }
                }
            ]
        """

        return SERVICES.values() if not args else SERVICES[args[0]]


# pylint: disable=W0223
class WorkerAttributesHandler(apimanager.EmpowerAPIHandler):
    """Access workers' attributes."""

    URLS = [r"/api/v1/workers/([a-zA-Z0-9-]*)/([a-zA-Z0-9_]*)/?"]

    @apimanager.validate(min_args=2, max_args=2)
    def get(self, *args, **kwargs):
        """Access a particular property of a worker.

        Args:

            [0]: the worker id (mandatory)
            [1]: the attribute of the worker to be accessed (mandatory)

        Example URLs:

            GET /api/v1/workers/0f91e8ad-1c2a-4b06-97f9-e34097c4c1d0/every

            [
                2000
            ]
        """

        conf = self.service.conf

        service_id = uuid.UUID(args[0])

        service = conf.services[service_id]

        if not hasattr(service, args[1]):
            raise KeyError("'%s' object has no attribute '%s'" %
                           (service.__class__.__name__, args[1]))

        return [getattr(service, args[1])]

    @apimanager.validate(returncode=204, min_args=2, max_args=2)
    def put(self, *args, **kwargs):
        """Set a particular property of a worker.

        Args:

            [0]: the worker id (mandatory)
            [1]: the attribute of the worker to be accessed (mandatory)

        Example URLs:

            PUT /api/v1/workers/7069c865-8849-4840-9d96-e028663a5dcf/every
            {
                "version": "1.0",
                "value": 2000
            }
        """

        conf = self.service.conf

        service_id = uuid.UUID(args[0])
        service = conf.services[service_id]

        if not hasattr(service, args[1]):
            raise KeyError("'%s' object has no attribute '%s'" %
                           (service.__class__.__name__, args[1]))

        return setattr(service, args[1], kwargs["value"])


# pylint: disable=W0223
class WorkersHandler(apimanager.EmpowerAPIHandler):
    """Workers handler."""

    URLS = [r"/api/v1/workers/?",
            r"/api/v1/workers/([a-zA-Z0-9-]*)/?"]

    @apimanager.validate(min_args=0, max_args=1)
    def get(self, *args, **kwargs):
        """List the workers.

        Args:

            [0]: the worker id (optional)

        Example URLs:

            GET /api/v1/workers

            [
                {
                    "name":
                        "empower.workers.wifichannelstats.wifichannelstats",
                    "params": {
                        "every": 2000,
                        "project_id": "4cd2bca2-8c28-4e66-9c8a-7cbd1ba4e6f9",
                        "service_id": "0f91e8ad-1c2a-4b06-97f9-e34097c4c1d0"
                    }
                }
            ]

            GET /api/v1/workers/0f91e8ad-1c2a-4b06-97f9-e34097c4c1d0

            {
                "name": "empower.workers.wifichannelstats.wifichannelstats",
                "params": {
                    "every": 2000,
                    "project_id": "4cd2bca2-8c28-4e66-9c8a-7cbd1ba4e6f9",
                    "service_id": "0f91e8ad-1c2a-4b06-97f9-e34097c4c1d0"
                }
            }
        """

        return self.service.conf.services.values() \
            if not args else self.service.conf.services[uuid.UUID(args[0])]

    @apimanager.validate(returncode=201, min_args=0, max_args=0)
    def post(self, *args, **kwargs):
        """Start a new worker.

        Request:

            version: protocol version (1.0)
            name: the name of the worker (mandatory)
            params: the list of parmeters to be set (optional)

        Example URLs:

            POST /api/v1/workers
            {
                "version": "1.0",
                "name": "empower.workers.wifichannelstats.wifichannelstats",
                "params": {
                    "every": 5000
                }
            }
        """

        conf = self.service.conf

        service_id = uuid.UUID(args[0]) if args else uuid.uuid4()
        params = kwargs['params'] if 'params' in kwargs else {}

        service = conf.register_service(service_id=service_id,
                                        name=kwargs['name'],
                                        params=params)

        self.set_header("Location", "/api/v1/workers/%s" % service.service_id)

    @apimanager.validate(returncode=204, min_args=1, max_args=1)
    def put(self, *args, **kwargs):
        """Update the configuration of a worker.

        Args:

            [0], the worker id (mandatory)

        Request:

            version: protocol version (1.0)
            params: the list of parmeters to be set (optional)

        Example URLs:

            PUT /api/v1/workers/08e14f40-6ebf-47a0-8baa-11d7f44cc228
            {
                "version": "1.0",
                "params":
                {
                    "every": 5000
                }
            }
        """

        conf = self.service.conf

        service_id = uuid.UUID(args[0])
        params = kwargs['params'] if 'params' in kwargs else {}

        conf.reconfigure_service(service_id=service_id, params=params)

    @apimanager.validate(returncode=204, min_args=1, max_args=1)
    def delete(self, *args, **kwargs):
        """Stop a worker.

        Args:

            [0], the worker id

        Example URLs:

            DELETE /api/v1/workers/08e14f40-6ebf-47a0-8baa-11d7f44cc228
        """

        service_id = uuid.UUID(args[0])

        self.service.conf.unregister_service(service_id=service_id)
