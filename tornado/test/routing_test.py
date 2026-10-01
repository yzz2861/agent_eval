# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import asyncio
import unittest
import uuid
import typing

from tornado import httputil
from tornado.httputil import (
    HTTPHeaders,
    HTTPMessageDelegate,
    HTTPServerConnectionDelegate,
    RequestStartLine,
    ResponseStartLine,
)
from tornado.routing import (
    HostMatches,
    PathMatches,
    PathConverter,
    PathTemplateMatches,
    ReversibleRuleRouter,
    ReversibleRouter,
    Router,
    Rule,
    RuleRouter,
)
from tornado.web import Application, HTTPError, RequestHandler
from tornado.wsgi import WSGIContainer


from tornado.test.util import AsyncHTTPTestCase


def _path_request(path):
    return httputil.HTTPServerRequest(
        start_line=RequestStartLine("GET", path, "HTTP/1.1"),
        headers=HTTPHeaders({"Host": "www.example.com"}),
        connection=object(),
    )


class EvenConverter(PathConverter):
    regex = "[0-9]+"

    def to_python(self, value):
        number = int(value)
        if number % 2:
            raise ValueError("must be even")
        return number

    def to_url(self, value):
        if not isinstance(value, int) or isinstance(value, bool) or value % 2:
            raise ValueError("must be even")
        return str(value)


class BrokenConverter(PathConverter):
    regex = "[0-9]+"

    def to_python(self, value):
        raise RuntimeError("programming error")

    def to_url(self, value):
        raise RuntimeError("programming error")


class OneWayConverter(PathConverter):
    regex = "[a-z]+"

    def to_python(self, value):
        return value + "x"

    def to_url(self, value):
        return value


class BasicRouter(Router):
    def find_handler(self, request, **kwargs):
        class MessageDelegate(HTTPMessageDelegate):
            def __init__(self, connection):
                self.connection = connection

            def finish(self):
                self.connection.write_headers(
                    ResponseStartLine("HTTP/1.1", 200, "OK"),
                    HTTPHeaders({"Content-Length": "2"}),
                    b"OK",
                )
                self.connection.finish()

        return MessageDelegate(request.connection)


class BasicRouterTestCase(AsyncHTTPTestCase):
    def get_app(self):
        return BasicRouter()

    def test_basic_router(self):
        response = self.fetch("/any_request")
        self.assertEqual(response.body, b"OK")


resources: dict[str, bytes] = {}


class GetResource(RequestHandler):
    def get(self, path):
        if path not in resources:
            raise HTTPError(404)

        self.finish(resources[path])


class PostResource(RequestHandler):
    def post(self, path):
        resources[path] = self.request.body


class HTTPMethodRouter(Router):
    def __init__(self, app):
        self.app = app

    def find_handler(self, request, **kwargs):
        handler = GetResource if request.method == "GET" else PostResource
        return self.app.get_handler_delegate(request, handler, path_args=[request.path])


class HTTPMethodRouterTestCase(AsyncHTTPTestCase):
    def get_app(self):
        return HTTPMethodRouter(Application())

    def test_http_method_router(self):
        response = self.fetch("/post_resource", method="POST", body="data")
        self.assertEqual(response.code, 200)

        response = self.fetch("/get_resource")
        self.assertEqual(response.code, 404)

        response = self.fetch("/post_resource")
        self.assertEqual(response.code, 200)
        self.assertEqual(response.body, b"data")


def _get_named_handler(handler_name):
    class Handler(RequestHandler):
        def get(self, *args, **kwargs):
            if self.application.settings.get("app_name") is not None:
                self.write(self.application.settings["app_name"] + ": ")

            self.finish(handler_name + ": " + self.reverse_url(handler_name))

    return Handler


FirstHandler = _get_named_handler("first_handler")
SecondHandler = _get_named_handler("second_handler")


class PathTemplateFileHandler(RequestHandler):
    def get(self, id, path=None):
        self.write({"id": str(id), "path": path})


class CaptureHandler(RequestHandler):
    captured = None

    def get(self, id, path=None):
        CaptureHandler.captured = {"id": id, "path": path}
        self._finished = True


class CustomRouter(ReversibleRouter):
    def __init__(self):
        super().__init__()
        self.routes: dict[str, typing.Any] = {}

    def add_routes(self, routes):
        self.routes.update(routes)

    def find_handler(self, request, **kwargs):
        if request.path in self.routes:
            app, handler = self.routes[request.path]
            return app.get_handler_delegate(request, handler)

    def reverse_url(self, name, *args, **kwargs):
        handler_path = "/" + name
        return handler_path if handler_path in self.routes else None


class CustomRouterTestCase(AsyncHTTPTestCase):
    def get_app(self):
        router = CustomRouter()

        class CustomApplication(Application):
            def reverse_url(self, name, *args, **kwargs):
                return router.reverse_url(name, *args, **kwargs)

        app1 = CustomApplication(app_name="app1")
        app2 = CustomApplication(app_name="app2")

        router.add_routes(
            {
                "/first_handler": (app1, FirstHandler),
                "/second_handler": (app2, SecondHandler),
                "/first_handler_second_app": (app2, FirstHandler),
            }
        )

        return router

    def test_custom_router(self):
        response = self.fetch("/first_handler")
        self.assertEqual(response.body, b"app1: first_handler: /first_handler")
        response = self.fetch("/second_handler")
        self.assertEqual(response.body, b"app2: second_handler: /second_handler")
        response = self.fetch("/first_handler_second_app")
        self.assertEqual(response.body, b"app2: first_handler: /first_handler")


class ConnectionDelegate(HTTPServerConnectionDelegate):
    def start_request(self, server_conn, request_conn):
        class MessageDelegate(HTTPMessageDelegate):
            def __init__(self, connection):
                self.connection = connection

            def finish(self):
                response_body = b"OK"
                self.connection.write_headers(
                    ResponseStartLine("HTTP/1.1", 200, "OK"),
                    HTTPHeaders({"Content-Length": str(len(response_body))}),
                )
                self.connection.write(response_body)
                self.connection.finish()

        return MessageDelegate(request_conn)


class RuleRouterTest(AsyncHTTPTestCase):
    def get_app(self):
        app = Application()

        def request_callable(request):
            request.connection.write_headers(
                ResponseStartLine("HTTP/1.1", 200, "OK"),
                HTTPHeaders({"Content-Length": "2"}),
            )
            request.connection.write(b"OK")
            request.connection.finish()

        router = CustomRouter()
        router.add_routes(
            {"/nested_handler": (app, _get_named_handler("nested_handler"))}
        )

        app.add_handlers(
            ".*",
            [
                (
                    HostMatches("www.example.com"),
                    [
                        (
                            PathMatches("/first_handler"),
                            "tornado.test.routing_test.SecondHandler",
                            {},
                            "second_handler",
                        )
                    ],
                ),
                Rule(PathMatches("/.*handler"), router),
                Rule(PathMatches("/first_handler"), FirstHandler, name="first_handler"),
                Rule(PathMatches("/request_callable"), request_callable),
                ("/connection_delegate", ConnectionDelegate()),
            ],
        )

        return app

    def test_rule_based_router(self):
        response = self.fetch("/first_handler")
        self.assertEqual(response.body, b"first_handler: /first_handler")

        response = self.fetch("/first_handler", headers={"Host": "www.example.com"})
        self.assertEqual(response.body, b"second_handler: /first_handler")

        response = self.fetch("/nested_handler")
        self.assertEqual(response.body, b"nested_handler: /nested_handler")

        response = self.fetch("/nested_not_found_handler")
        self.assertEqual(response.code, 404)

        response = self.fetch("/connection_delegate")
        self.assertEqual(response.body, b"OK")

        response = self.fetch("/request_callable")
        self.assertEqual(response.body, b"OK")

        response = self.fetch("/404")
        self.assertEqual(response.code, 404)


class PathTemplateApplicationTest(unittest.TestCase):
    def setUp(self):
        nested_router = ReversibleRuleRouter(
            [
                Rule(
                    PathTemplateMatches("/files/{id:uuid}/{path:path?}"),
                    PathTemplateFileHandler,
                    name="file",
                )
            ]
        )
        self.app = Application(
            [
                Rule(
                    PathTemplateMatches("/simple/{id:int}"),
                    PathTemplateFileHandler,
                    name="simple",
                ),
                Rule(HostMatches(".*"), nested_router),
            ]
        )

    def test_named_route_handler_and_nested_routing(self):
        file_id = uuid.UUID("12345678-1234-5678-1234-567890abcdef")
        path = "dir/100% café.txt"
        url = self.app.reverse_url("file", id=file_id, path=path)

        delegate = self.app.find_handler(_path_request(url))
        self.assertEqual(delegate.path_kwargs, {"id": file_id, "path": path})

        optional_url = self.app.reverse_url("file", id=file_id)
        delegate = self.app.find_handler(_path_request(optional_url))
        self.assertEqual(delegate.path_kwargs, {"id": file_id, "path": None})

        self.assertEqual(self.app.reverse_url("simple", id=42), "/simple/42")

        handler = object.__new__(PathTemplateFileHandler)
        handler.application = self.app
        self.assertEqual(
            handler.reverse_url("file", id=file_id, path=path),
            url,
        )

    def test_nested_route(self):
        nested_rules = [
            Rule(
                PathTemplateMatches("/items/{item_id:int}"),
                PathTemplateFileHandler,
                name="item",
            )
        ]
        app = Application([Rule(HostMatches(".*"), nested_rules)])

        delegate = app.find_handler(_path_request("/items/42"))
        self.assertEqual(delegate.path_kwargs, {"item_id": 42})
        self.assertEqual(app.reverse_url("item", item_id=42), "/items/42")

    def test_handler_receives_converted_values(self):
        CaptureHandler.captured = None
        file_id = uuid.UUID("12345678-1234-5678-1234-567890abcdef")
        nested_router = ReversibleRuleRouter(
            [Rule(PathTemplateMatches("/files/{id:uuid}/{path:path?}"), CaptureHandler)]
        )
        app = Application([Rule(HostMatches(".*"), nested_router)])
        delegate = app.find_handler(
            _path_request("/files/" + str(file_id) + "/caf%C3%A9.txt")
        )

        handler = CaptureHandler.__new__(CaptureHandler)
        handler.application = app
        handler.request = delegate.request
        handler._prepared_future = None
        handler._finished = False
        handler._auto_finish = False
        asyncio.run(handler._execute([], **delegate.path_kwargs))

        self.assertEqual(
            CaptureHandler.captured,
            {"id": file_id, "path": "café.txt"},
        )


class WSGIContainerTestCase(AsyncHTTPTestCase):
    def get_app(self):
        wsgi_app = WSGIContainer(self.wsgi_app)

        class Handler(RequestHandler):
            def get(self, *args, **kwargs):
                self.finish(self.reverse_url("tornado"))

        return RuleRouter(
            [
                (
                    PathMatches("/tornado.*"),
                    Application([(r"/tornado/test", Handler, {}, "tornado")]),
                ),
                (PathMatches("/wsgi"), wsgi_app),
            ]
        )

    def wsgi_app(self, environ, start_response):
        start_response("200 OK", [])
        return [b"WSGI"]

    def test_wsgi_container(self):
        response = self.fetch("/tornado/test")
        self.assertEqual(response.body, b"/tornado/test")

        response = self.fetch("/wsgi")
        self.assertEqual(response.body, b"WSGI")

    def test_delegate_not_found(self):
        response = self.fetch("/404")
        self.assertEqual(response.code, 404)


class PathTemplateMatchesTest(unittest.TestCase):
    def setUp(self):
        self.original_converters = dict(PathTemplateMatches.converters)

    def tearDown(self):
        PathTemplateMatches.converters = self.original_converters

    def test_named_parameters_and_registered_converter(self):
        matcher = PathTemplateMatches(
            "/items/{item_id:even}", {"even": EvenConverter()}
        )

        match = matcher.match(_path_request("/items/42"))
        self.assertEqual(match["path_kwargs"], {"item_id": 42})
        self.assertIsNone(matcher.match(_path_request("/items/41")))
        self.assertEqual(matcher.reverse(item_id=42), "/items/42")

    def test_class_registered_converter(self):
        PathTemplateMatches.register_converter("even", EvenConverter())
        matcher = PathTemplateMatches("/items/{item_id:even}")

        self.assertEqual(
            matcher.match(_path_request("/items/42"))["path_kwargs"],
            {"item_id": 42},
        )

    def test_optional_trailing_path(self):
        matcher = PathTemplateMatches("/files/{id:uuid}/{path:path?}")
        value = uuid.UUID("12345678-1234-5678-1234-567890abcdef")

        self.assertEqual(
            matcher.match(_path_request("/files/12345678-1234-5678-1234-567890ABCDEF"))[
                "path_kwargs"
            ],
            {"id": value, "path": None},
        )
        self.assertEqual(
            matcher.match(
                _path_request("/files/12345678-1234-5678-1234-567890abcdef/a/b.png")
            )["path_kwargs"],
            {"id": value, "path": "a/b.png"},
        )
        self.assertEqual(
            matcher.match(
                _path_request("/files/12345678-1234-5678-1234-567890abcdef/")
            )["path_kwargs"],
            {"id": value, "path": ""},
        )
        self.assertEqual(matcher.reverse(id=value), "/files/%s" % value)

    def test_percent_and_unicode_round_trip(self):
        matcher = PathTemplateMatches("/files/{name}")
        value = "100% café/é.txt"
        url = matcher.reverse(name=value)

        self.assertEqual(url, "/files/100%25%20caf%C3%A9%2F%C3%A9.txt")
        self.assertEqual(
            matcher.match(_path_request(url))["path_kwargs"]["name"], value
        )

        path_matcher = PathTemplateMatches("/files/{name:path}")
        path_url = path_matcher.reverse(name=value)
        self.assertEqual(path_url, "/files/100%25%20caf%C3%A9/%C3%A9.txt")
        self.assertEqual(
            path_matcher.match(_path_request(path_url))["path_kwargs"]["name"],
            value,
        )

    def test_reverse_requires_exact_parameters(self):
        matcher = PathTemplateMatches("/users/{user_id:int}/{path:path?}")

        with self.assertRaises(ValueError):
            matcher.reverse()
        with self.assertRaises(ValueError):
            matcher.reverse(user_id=1, extra="x")
        with self.assertRaises(ValueError):
            matcher.reverse(1, "a", "b")
        self.assertEqual(matcher.reverse(user_id=1), "/users/1")
        self.assertEqual(matcher.reverse(user_id=1, path="a/b"), "/users/1/a/b")

    def test_reverse_rejects_non_reversible_value(self):
        matcher = PathTemplateMatches("/values/{value:one}", {"one": OneWayConverter()})

        with self.assertRaises(ValueError):
            matcher.reverse(value="ABC")

    def test_conversion_failure_is_not_match(self):
        matcher = PathTemplateMatches("/items/{item_id:int}")

        self.assertIsNone(matcher.match(_path_request("/items/abc")))

    def test_converter_programming_error_propagates(self):
        matcher = PathTemplateMatches(
            "/items/{item_id:broken}", {"broken": BrokenConverter()}
        )

        with self.assertRaises(RuntimeError):
            matcher.match(_path_request("/items/1"))

    def test_reverse_programming_error_propagates(self):
        matcher = PathTemplateMatches(
            "/items/{item_id:broken}", {"broken": BrokenConverter()}
        )

        with self.assertRaises(RuntimeError):
            matcher.reverse(item_id=1)

    def test_optional_parameter_must_be_final(self):
        with self.assertRaises(ValueError):
            PathTemplateMatches("/files/{name?}/info")
