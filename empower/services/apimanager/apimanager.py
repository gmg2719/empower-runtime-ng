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

"""API Manager (REST Northbound Interface)."""

import json
import base64
import re
import os

from uuid import UUID

import tornado.web
import tornado.httpserver

from tornado.web import Application
from pymodm.errors import ValidationError

from empower.core.jsonserializer import JSONSerializer
from empower.core.service import EService

from empower.main import srv_or_die

DIRNAME = os.path.dirname(__file__)
ROOT_PATH = os.path.normpath(os.path.join(DIRNAME, '..'))
TEMPLATE_PATH = os.path.join(DIRNAME, 'templates')
STATIC_PATH = os.path.join(DIRNAME, 'static')
DEBUG = True
DEFAULT_PORT = 8888
COOKIE_SECRET = b'xyRTvZpRSUyk8/9/McQAvsQPB4Rqv0w9mBtIpH9lf1o='
LOGIN_URL = "/auth/login"


def validate(returncode=200, min_args=0, max_args=0):
    """Validate REST method."""

    def decorator(func):

        def magic(self, *args):

            try:

                if len(args) < min_args or len(args) > max_args:
                    msg = "Invalid url (%u, %u)" % (min_args, max_args)
                    raise ValueError(msg)

                params = {}

                if self.request.body and \
                        tornado.escape.json_decode(self.request.body):

                    params = tornado.escape.json_decode(self.request.body)

                if "version" in params:
                    del params["version"]

                output = func(self, *args, **params)

                if returncode == 200:
                    self.write_as_json(output)

            except KeyError as ex:
                self.send_error(404, message=ex)

            except ModuleNotFoundError as ex:
                self.send_error(404, message=ex)

            except ValueError as ex:
                self.send_error(400, message=ex)

            except AttributeError as ex:
                self.send_error(400, message=ex)

            except TypeError as ex:
                self.send_error(400, message=ex)

            except ValidationError as ex:
                self.send_error(400, message=ex)

            self.set_status(returncode, None)

        magic.__doc__ = func.__doc__

        return magic

    return decorator


# pylint: disable=W0223
class BaseHandler(tornado.web.RequestHandler):
    """Base Handler."""

    # service associated to this handler
    service = None

    URLS = []

    def get_current_user(self):
        """Return username of the currently logged user or None."""

        return self.get_secure_cookie("username")


class IndexHandler(BaseHandler):
    """Index page handler."""

    URLS = [r"/", r"/index.html"]

    @tornado.web.authenticated
    def get(self, *args, **kwargs):
        """Render index page."""

        username = self.get_secure_cookie("username").decode('UTF-8')
        account = self.service.accounts_manager.accounts[username]

        self.render("index.html",
                    username=username,
                    password=account.password,
                    name=account.name,
                    email=account.email)


class AuthLoginHandler(BaseHandler):
    """Login page handler."""

    URLS = [r"/auth/login"]

    def get(self, *args, **kwargs):
        """Render login page."""

        if self.get_current_user():
            self.redirect('/')
            return

        self.render("login.html", error=self.get_argument("error", ""))

    def post(self, *args, **kwargs):
        """Process login credentials."""

        username = self.get_argument("username", "")
        password = self.get_argument("password", "")

        if self.service.accounts_manager.check_permission(username, password):
            self.set_secure_cookie("username", username)
            self.redirect("/index.html")
        else:
            self.clear_cookie("username")
            self.redirect("/auth/login?error=Wrong Password")


class AuthLogoutHandler(BaseHandler):
    """Logout page handler."""

    URLS = [r"/auth/logout"]

    def get(self, *args, **kwargs):
        """Process logout request."""

        self.clear_cookie("username")
        self.redirect("/auth/login")


class EmpowerAPIHandler(tornado.web.RequestHandler):
    """Base class for all the REST calls."""

    # service associated to this handler
    service = None

    def write_error(self, status_code, **kwargs):
        """Write error as JSON message."""

        self.set_header('Content-Type', 'application/json')

        out = {"status_code": status_code, "reason": self._reason}

        if "message" in kwargs:
            out["message"] = str(kwargs["message"])

        self.finish(json.dumps(out))

    def write_as_json(self, value):
        """Return reply as a json document."""

        self.write(json.dumps(value, sort_keys=True, indent=4,
                              cls=JSONSerializer))

    def prepare(self):
        """Prepare to handler reply."""

        self.set_header('Content-Type', 'application/json')

        # get requests do not require authentication
        if self.request.method == "GET":
            return

        accounts_manager = \
            srv_or_die("empower.services.accountsmanager.accountsmanager")

        projects_manager = \
            srv_or_die("empower.services.projectsmanager.projectsmanager")

        auth_header = self.request.headers.get('Authorization')

        if auth_header is None or not auth_header.startswith('Basic '):
            self.set_header('WWW-Authenticate', 'Basic realm=Restricted')
            self.send_error(401)
            return

        auth_bytes = bytes(auth_header[6:], 'utf-8')
        auth_decoded = base64.b64decode(auth_bytes).decode()
        username, password = auth_decoded.split(':', 2)

        # account does not exists
        if not accounts_manager.check_permission(username, password):
            self.send_error(401)
            return

        account = accounts_manager.accounts[username]

        if account.username == "root":
            return

        if self.request.uri.startswith("/api/v1/accounts"):

            pattern = re.compile("/api/v1/accounts/([a-zA-Z0-9:-]*)/?")
            match = pattern.match(self.request.uri)

            if match and match.group(1):
                username = match.group(1)
                if username in accounts_manager.accounts:
                    incoming = accounts_manager.accounts[username]
                    if account.username == incoming.username:
                        return

        if self.request.uri.startswith("/api/v1/projects"):

            pattern = re.compile("/api/v1/projects/([a-zA-Z0-9-]*)/?")
            match = pattern.match(self.request.uri)

            if match and match.group(1):
                uuid = UUID(match.group(1))
                if uuid in projects_manager.projects:
                    project = projects_manager.projects[uuid]
                    if account.username == project.owner:
                        return

        self.send_error(401)


class APIManager(EService):
    """Service exposing the 5G-EmPOWER REST API

    This service exposes the 5G-EmPOWER REST API, the 'port' parameter
    specifies on which port the HTTP server should listen.

    Parameters:
        port: the port on which the HTTP server should listen (optional,
            default: 8888)
    """

    HANDLERS = [IndexHandler, AuthLoginHandler, AuthLogoutHandler]

    def __init__(self, **kwargs):

        if 'port' not in kwargs:
            kwargs['port'] = DEFAULT_PORT

        super().__init__(**kwargs)

        self.accounts_manager = None

        self.projects_manager = None

        settings = {
            "static_path": STATIC_PATH,
            "cookie_secret": COOKIE_SECRET,
            "template_path": TEMPLATE_PATH,
            "login_url": LOGIN_URL,
            "debug": DEBUG,
        }

        self.application = Application([], **settings)

        self.http_server = tornado.httpserver.HTTPServer(self.application)

    @property
    def port(self):
        """Return port."""

        return self.params["port"]

    @port.setter
    def port(self, value):
        """Set port."""

        if "port" in self.params and self.params["port"]:
            raise ValueError("Param port can not be changed")

        self.params["port"] = int(value)

    def start(self, load=True):
        """Start api manager."""

        super().start(load)

        self.accounts_manager = \
            srv_or_die("empower.services.accountsmanager.accountsmanager")

        self.projects_manager = \
            srv_or_die("empower.services.projectsmanager.projectsmanager")

        self.http_server.listen(self.port)

        self.log.info("%s: listening on port %u",
                      self.__class__.__name__, self.port)

        self.http_server.start()

    def register_handler(self, handler):
        """Add a new handler class."""

        for url in handler.URLS:
            self.log.info("Registering URL: %s", url)
            self.application.add_handlers(r".*$", [(url, handler)])


def launch(**kwargs):
    """ Start REST Server module. """

    return APIManager(**kwargs)
