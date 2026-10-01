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

import json
import typing
import unittest
import uuid

from tornado.httputil import (
    HTTPHeaders,
    HTTPMessageDelegate,
    HTTPServerConnectionDelegate,
    ResponseStartLine,
)
from tornado.routing import (
    Converter,
    HostMatches,
    PathMatches,
    PathTemplate,
    ReversibleRouter,
    ReversibleRuleRouter,
    Router,
    Rule,
    RuleRouter,
)
from tornado.web import Application, HTTPError, RequestHandler
from tornado.wsgi import WSGIContainer


from tornado.test.util import AsyncHTTPTestCase


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

    def reverse_url(self, name, *args):
        handler_path = "/" + name
        return handler_path if handler_path in self.routes else None


class CustomRouterTestCase(AsyncHTTPTestCase):
    def get_app(self):
        router = CustomRouter()

        class CustomApplication(Application):
            def reverse_url(self, name, *args):
                return router.reverse_url(name, *args)

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


class _FakeRequest:
    def __init__(self, path):
        self.path = path


def _match(template, path):
    return template.match(_FakeRequest(path))


class PathTemplateMatcherTest(unittest.TestCase):
    def test_named_parameters(self):
        template = PathTemplate("/users/<int:user_id>")
        self.assertEqual(
            _match(template, "/users/42"), {"path_kwargs": {"user_id": 42}}
        )
        self.assertIsNone(_match(template, "/users/abc"))
        self.assertIsNone(_match(template, "/users/42/extra"))
        self.assertIsNone(_match(template, "/users"))

    def test_default_converter_is_str(self):
        template = PathTemplate("/users/<name>")
        self.assertEqual(
            _match(template, "/users/bob"), {"path_kwargs": {"name": "bob"}}
        )
        self.assertIsNone(_match(template, "/users/a/b"))

    def test_path_parameter_with_slashes(self):
        template = PathTemplate("/files/<path:file_path>")
        self.assertEqual(
            _match(template, "/files/a/b/c"),
            {"path_kwargs": {"file_path": "a/b/c"}},
        )
        self.assertIsNone(_match(template, "/files"))

    def test_optional_trailing_segment(self):
        template = PathTemplate("/files/<path:file_path>?")
        self.assertEqual(
            _match(template, "/files"), {"path_kwargs": {"file_path": None}}
        )
        self.assertEqual(
            _match(template, "/files/a/b"),
            {"path_kwargs": {"file_path": "a/b"}},
        )
        self.assertIsNone(_match(template, "/files/"))

    def test_percent_encoded_and_unicode_values(self):
        template = PathTemplate("/dl/<path:name>")
        self.assertEqual(
            _match(template, "/dl/100%25%20%E6%96%87%E4%BB%B6.txt"),
            {"path_kwargs": {"name": "100% \u6587\u4ef6.txt"}},
        )

    def test_conversion_failure_is_not_a_match(self):
        template = PathTemplate("/x/<int:value>")
        self.assertIsNone(_match(template, "/x/abc"))

    def test_converter_programming_error_propagates(self):
        class BuggyConverter(Converter):
            def to_python(self, value):
                raise RuntimeError("bug in converter")

        template = PathTemplate(
            "/x/<buggy:value>", converters={"buggy": BuggyConverter()}
        )
        with self.assertRaises(RuntimeError):
            _match(template, "/x/1")

    def test_custom_converter(self):
        class UpperConverter(Converter):
            def to_python(self, value):
                return value.upper()

            def to_url(self, value):
                return str(value).lower()

        template = PathTemplate(
            "/x/<upper:value>", converters={"upper": UpperConverter()}
        )
        self.assertEqual(
            _match(template, "/x/abc"), {"path_kwargs": {"value": "ABC"}}
        )
        self.assertEqual(template.reverse("ABC"), "/x/abc")

    def test_register_converter(self):
        class UpperConverter(Converter):
            def to_python(self, value):
                return value.upper()

        PathTemplate.register_converter("upper", UpperConverter())
        try:
            template = PathTemplate("/x/<upper:value>")
            self.assertEqual(
                _match(template, "/x/abc"), {"path_kwargs": {"value": "ABC"}}
            )
        finally:
            del PathTemplate.default_converters["upper"]

    def test_invalid_templates(self):
        with self.assertRaises(ValueError):
            PathTemplate("/x/<unknown:value>")
        with self.assertRaises(ValueError):
            PathTemplate("/x/<value>/<value>")
        with self.assertRaises(ValueError):
            PathTemplate("/x/<a?>/<b>")
        with self.assertRaises(ValueError):
            PathTemplate("/x/<a>/<b?>trailing")
        with self.assertRaises(ValueError):
            PathTemplate("/x/<a")

    def test_reverse(self):
        template = PathTemplate("/users/<int:user_id>")
        self.assertEqual(template.reverse(42), "/users/42")
        self.assertEqual(template.reverse("42"), "/users/42")

    def test_reverse_optional_parameter(self):
        template = PathTemplate("/files/<name>?")
        self.assertEqual(template.reverse("a"), "/files/a")
        self.assertEqual(template.reverse(), "/files")
        self.assertEqual(template.reverse(None), "/files")

    def test_reverse_missing_argument(self):
        template = PathTemplate("/users/<int:user_id>")
        with self.assertRaises(ValueError):
            template.reverse()
        with self.assertRaises(ValueError):
            template.reverse(None)

    def test_reverse_extra_argument(self):
        template = PathTemplate("/users/<int:user_id>")
        with self.assertRaises(ValueError):
            template.reverse(1, 2)

    def test_reverse_rejects_values_that_cannot_round_trip(self):
        template = PathTemplate("/files/<name>")
        with self.assertRaises(ValueError):
            template.reverse("a/b")

    def test_reverse_does_not_double_encode(self):
        template = PathTemplate("/dl/<path:name>")
        self.assertEqual(template.reverse("100%"), "/dl/100%25")
        self.assertEqual(template.reverse("a/b"), "/dl/a/b")

    def test_reverse_round_trip(self):
        template = PathTemplate("/dl/<path:name>")
        for name in ["100%.txt", "\u6587\u4ef6 \u540d.txt", "a/b/c", "a+b"]:
            url = template.reverse(name)
            self.assertEqual(
                _match(template, url), {"path_kwargs": {"name": name}}
            )

    def test_reversible_rule_router(self):
        router = ReversibleRuleRouter(
            [Rule(PathTemplate("/users/<int:user_id>"), object(), name="user")]
        )
        self.assertEqual(router.reverse_url("user", 42), "/users/42")


class TemplateUserHandler(RequestHandler):
    def get(self, user_id):
        self.finish("%s:%s" % (type(user_id).__name__, user_id))


class TemplateReverseUserHandler(RequestHandler):
    def get(self, user_id):
        self.finish(self.reverse_url("user", user_id))


class TemplateFileHandler(RequestHandler):
    def get(self, file_id, file_path):
        self.write(
            {
                "file_id": str(file_id),
                "file_id_type": type(file_id).__name__,
                "file_path": file_path,
                "reversed": self.reverse_url("file", file_id, file_path),
            }
        )


class LegacyRegexHandler(RequestHandler):
    def get(self, user_id):
        self.finish("legacy:%s" % user_id)


class PathTemplateTest(AsyncHTTPTestCase):
    def get_app(self):
        return Application(
            [
                (r"/legacy/([0-9]+)", LegacyRegexHandler, {}, "legacy"),
                (PathTemplate("/users/<int:user_id>"), TemplateUserHandler, {}, "user"),
                (
                    PathTemplate("/files/<uuid:file_id>/<path:file_path>?"),
                    TemplateFileHandler,
                    {},
                    "file",
                ),
            ]
        )

    def test_named_parameter_conversion(self):
        response = self.fetch("/users/42")
        self.assertEqual(response.body, b"int:42")

    def test_coexists_with_regex_rules(self):
        response = self.fetch("/legacy/42")
        self.assertEqual(response.body, b"legacy:42")

    def test_conversion_failure_is_not_matched(self):
        response = self.fetch("/users/abc")
        self.assertEqual(response.code, 404)

    def test_uuid_and_optional_file_path(self):
        file_id = uuid.uuid4()
        data = json.loads(self.fetch("/files/%s" % file_id).body)
        self.assertEqual(data["file_id"], str(file_id))
        self.assertEqual(data["file_id_type"], "UUID")
        self.assertIsNone(data["file_path"])
        self.assertEqual(data["reversed"], "/files/%s" % file_id)

        data = json.loads(self.fetch("/files/%s/a/b/c" % file_id).body)
        self.assertEqual(data["file_path"], "a/b/c")
        self.assertEqual(data["reversed"], "/files/%s/a/b/c" % file_id)

    def test_reverse_url(self):
        file_id = uuid.uuid4()
        app = self.get_app()
        self.assertEqual(app.reverse_url("user", 42), "/users/42")
        self.assertEqual(
            app.reverse_url("file", file_id), "/files/%s" % file_id
        )
        self.assertEqual(
            app.reverse_url("file", file_id, "a/b"),
            "/files/%s/a/b" % file_id,
        )
        with self.assertRaises(ValueError):
            app.reverse_url("file")
        with self.assertRaises(ValueError):
            app.reverse_url("file", file_id, "a", "b")

    def test_percent_and_unicode_file_name_round_trip(self):
        file_id = uuid.uuid4()
        app = self.get_app()
        for file_path in ["100%.txt", "\u6587\u4ef6 \u540d.txt", "a/b/c.txt"]:
            url = app.reverse_url("file", file_id, file_path)
            # Percent signs and slashes in the value are encoded exactly
            # once.
            self.assertNotIn("%2525", url)
            data = json.loads(self.fetch(url).body)
            self.assertEqual(data["file_id"], str(file_id))
            self.assertEqual(data["file_path"], file_path)
            # The url reversed while handling the request matches again
            # and yields the same parameter value.
            data = json.loads(self.fetch(data["reversed"]).body)
            self.assertEqual(data["file_path"], file_path)


class NestedPathTemplateTest(AsyncHTTPTestCase):
    def get_app(self):
        app = Application(
            [
                (
                    PathTemplate("/app/users/<int:user_id>"),
                    TemplateReverseUserHandler,
                    {},
                    "user",
                )
            ]
        )
        return RuleRouter([Rule(PathMatches("/app.*"), app)])

    def test_nested_application(self):
        response = self.fetch("/app/users/42")
        self.assertEqual(response.body, b"/app/users/42")
