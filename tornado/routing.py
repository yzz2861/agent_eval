# Copyright 2015 The Tornado Authors
#
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

"""Flexible routing implementation.

Tornado routes HTTP requests to appropriate handlers using `Router`
class implementations. The `tornado.web.Application` class is a
`Router` implementation and may be used directly, or the classes in
this module may be used for additional flexibility. The `RuleRouter`
class can match on more criteria than `.Application`, or the `Router`
interface can be subclassed for maximum customization.

`Router` interface extends `~.httputil.HTTPServerConnectionDelegate`
to provide additional routing capabilities. This also means that any
`Router` implementation can be used directly as a ``request_callback``
for `~.httpserver.HTTPServer` constructor.

`Router` subclass must implement a ``find_handler`` method to provide
a suitable `~.httputil.HTTPMessageDelegate` instance to handle the
request:

.. code-block:: python

    class CustomRouter(Router):
        def find_handler(self, request, **kwargs):
            # some routing logic providing a suitable HTTPMessageDelegate instance
            return MessageDelegate(request.connection)

    class MessageDelegate(HTTPMessageDelegate):
        def __init__(self, connection):
            self.connection = connection

        def finish(self):
            self.connection.write_headers(
                ResponseStartLine("HTTP/1.1", 200, "OK"),
                HTTPHeaders({"Content-Length": "2"}),
                b"OK")
            self.connection.finish()

    router = CustomRouter()
    server = HTTPServer(router)

The main responsibility of `Router` implementation is to provide a
mapping from a request to `~.httputil.HTTPMessageDelegate` instance
that will handle this request. In the example above we can see that
routing is possible even without instantiating an `~.web.Application`.

For routing to `~.web.RequestHandler` implementations we need an
`~.web.Application` instance. `~.web.Application.get_handler_delegate`
provides a convenient way to create `~.httputil.HTTPMessageDelegate`
for a given request and `~.web.RequestHandler`.

Here is a simple example of how we can we route to
`~.web.RequestHandler` subclasses by HTTP method:

.. code-block:: python

    resources = {}

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

    router = HTTPMethodRouter(Application())
    server = HTTPServer(router)

`ReversibleRouter` interface adds the ability to distinguish between
the routes and reverse them to the original urls using route's name
and additional arguments. `~.web.Application` is itself an
implementation of `ReversibleRouter` class.

`RuleRouter` and `ReversibleRuleRouter` are implementations of
`Router` and `ReversibleRouter` interfaces and can be used for
creating rule-based routing configurations.

Rules are instances of `Rule` class. They contain a `Matcher`, which
provides the logic for determining whether the rule is a match for a
particular request and a target, which can be one of the following.

1) An instance of `~.httputil.HTTPServerConnectionDelegate`:

.. code-block:: python

    router = RuleRouter([
        Rule(PathMatches("/handler"), ConnectionDelegate()),
        # ... more rules
    ])

    class ConnectionDelegate(HTTPServerConnectionDelegate):
        def start_request(self, server_conn, request_conn):
            return MessageDelegate(request_conn)

2) A callable accepting a single argument of `~.httputil.HTTPServerRequest` type:

.. code-block:: python

    router = RuleRouter([
        Rule(PathMatches("/callable"), request_callable)
    ])

    def request_callable(request):
        request.write(b"HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\n\\r\\nOK")
        request.finish()

3) Another `Router` instance:

.. code-block:: python

    router = RuleRouter([
        Rule(PathMatches("/router.*"), CustomRouter())
    ])

Of course a nested `RuleRouter` or a `~.web.Application` is allowed:

.. code-block:: python

    router = RuleRouter([
        Rule(HostMatches("example.com"), RuleRouter([
            Rule(PathMatches("/app1/.*"), Application([(r"/app1/handler", Handler)])),
        ]))
    ])

    server = HTTPServer(router)

In the example below `RuleRouter` is used to route between applications:

.. code-block:: python

    app1 = Application([
        (r"/app1/handler", Handler1),
        # other handlers ...
    ])

    app2 = Application([
        (r"/app2/handler", Handler2),
        # other handlers ...
    ])

    router = RuleRouter([
        Rule(PathMatches("/app1.*"), app1),
        Rule(PathMatches("/app2.*"), app2)
    ])

    server = HTTPServer(router)

For more information on application-level routing see docs for `~.web.Application`.

.. versionadded:: 4.5

"""

import re
import uuid
from collections.abc import Awaitable, Sequence
from functools import partial
from re import Pattern
from typing import (
    Any,
    NamedTuple,
    Union,
    overload,
)

from tornado import httputil
from tornado.escape import url_escape, url_unescape, utf8
from tornado.httpserver import _CallableAdapter
from tornado.log import app_log
from tornado.util import basestring_type, import_object, re_unescape, unicode_type


class Router(httputil.HTTPServerConnectionDelegate):
    """Abstract router interface."""

    def find_handler(
        self, request: httputil.HTTPServerRequest, **kwargs: Any
    ) -> httputil.HTTPMessageDelegate | None:
        """Must be implemented to return an appropriate instance of `~.httputil.HTTPMessageDelegate`
        that can serve the request.
        Routing implementations may pass additional kwargs to extend the routing logic.

        :arg httputil.HTTPServerRequest request: current HTTP request.
        :arg kwargs: additional keyword arguments passed by routing implementation.
        :returns: an instance of `~.httputil.HTTPMessageDelegate` that will be used to
            process the request.
        """
        raise NotImplementedError()

    def start_request(
        self, server_conn: object, request_conn: httputil.HTTPConnection
    ) -> httputil.HTTPMessageDelegate:
        return _RoutingDelegate(self, server_conn, request_conn)


class ReversibleRouter(Router):
    """Abstract router interface for routers that can handle named routes
    and support reversing them to original urls.
    """

    def reverse_url(self, name: str, *args: Any) -> str | None:
        """Returns url string for a given route name and arguments
        or ``None`` if no match is found.

        :arg str name: route name.
        :arg args: url parameters.
        :returns: parametrized url string for a given route name (or ``None``).
        """
        raise NotImplementedError()


class _RoutingDelegate(httputil.HTTPMessageDelegate):
    def __init__(
        self, router: Router, server_conn: object, request_conn: httputil.HTTPConnection
    ) -> None:
        self.server_conn = server_conn
        self.request_conn = request_conn
        self.delegate: httputil.HTTPMessageDelegate | None = None
        self.router: Router = router

    def headers_received(
        self,
        start_line: httputil.RequestStartLine | httputil.ResponseStartLine,
        headers: httputil.HTTPHeaders,
    ) -> Awaitable[None] | None:
        assert isinstance(start_line, httputil.RequestStartLine)
        request = httputil.HTTPServerRequest(
            connection=self.request_conn,
            server_connection=self.server_conn,
            start_line=start_line,
            headers=headers,
        )

        self.delegate = self.router.find_handler(request)
        if self.delegate is None:
            app_log.debug(
                "Delegate for %s %s request not found",
                start_line.method,
                start_line.path,
            )
            self.delegate = _DefaultMessageDelegate(self.request_conn)

        return self.delegate.headers_received(start_line, headers)

    def data_received(self, chunk: bytes) -> Awaitable[None] | None:
        assert self.delegate is not None
        return self.delegate.data_received(chunk)

    def finish(self) -> None:
        assert self.delegate is not None
        self.delegate.finish()

    def on_connection_close(self) -> None:
        if self.delegate is not None:
            self.delegate.on_connection_close()


class _DefaultMessageDelegate(httputil.HTTPMessageDelegate):
    def __init__(self, connection: httputil.HTTPConnection) -> None:
        self.connection = connection

    def finish(self) -> None:
        self.connection.write_headers(
            httputil.ResponseStartLine("HTTP/1.1", 404, "Not Found"),
            httputil.HTTPHeaders(),
        )
        self.connection.finish()


# _RuleList can either contain pre-constructed Rules or a sequence of
# arguments to be passed to the Rule constructor.
_RuleList = Sequence[
    Union[
        "Rule",
        list[Any],  # Can't do detailed typechecking of lists.
        tuple[Union[str, "Matcher"], Any],
        tuple[Union[str, "Matcher"], Any, dict[str, Any]],
        tuple[Union[str, "Matcher"], Any, dict[str, Any], str],
    ]
]


class RuleRouter(Router):
    """Rule-based router implementation."""

    def __init__(self, rules: _RuleList | None = None) -> None:
        """Constructs a router from an ordered list of rules::

            RuleRouter([
                Rule(PathMatches("/handler"), Target),
                # ... more rules
            ])

        You can also omit explicit `Rule` constructor and use tuples of arguments::

            RuleRouter([
                (PathMatches("/handler"), Target),
            ])

        `PathMatches` is a default matcher, so the example above can be simplified::

            RuleRouter([
                ("/handler", Target),
            ])

        In the examples above, ``Target`` can be a nested `Router` instance, an instance of
        `~.httputil.HTTPServerConnectionDelegate` or an old-style callable,
        accepting a request argument.

        :arg rules: a list of `Rule` instances or tuples of `Rule`
            constructor arguments.
        """
        self.rules: list[Rule] = []
        if rules:
            self.add_rules(rules)

    def add_rules(self, rules: _RuleList) -> None:
        """Appends new rules to the router.

        :arg rules: a list of Rule instances (or tuples of arguments, which are
            passed to Rule constructor).
        """
        for rule in rules:
            if isinstance(rule, (tuple, list)):
                assert len(rule) in (2, 3, 4)
                if isinstance(rule[0], basestring_type):
                    rule = Rule(PathMatches(rule[0]), *rule[1:])
                else:
                    rule = Rule(*rule)

            self.rules.append(self.process_rule(rule))

    def process_rule(self, rule: "Rule") -> "Rule":
        """Override this method for additional preprocessing of each rule.

        :arg Rule rule: a rule to be processed.
        :returns: the same or modified Rule instance.
        """
        return rule

    def find_handler(
        self, request: httputil.HTTPServerRequest, **kwargs: Any
    ) -> httputil.HTTPMessageDelegate | None:
        for rule in self.rules:
            target_params = rule.matcher.match(request)
            if target_params is not None:
                if rule.target_kwargs:
                    target_params["target_kwargs"] = rule.target_kwargs

                delegate = self.get_target_delegate(
                    rule.target, request, **target_params
                )

                if delegate is not None:
                    return delegate

        return None

    def get_target_delegate(
        self, target: Any, request: httputil.HTTPServerRequest, **target_params: Any
    ) -> httputil.HTTPMessageDelegate | None:
        """Returns an instance of `~.httputil.HTTPMessageDelegate` for a
        Rule's target. This method is called by `~.find_handler` and can be
        extended to provide additional target types.

        :arg target: a Rule's target.
        :arg httputil.HTTPServerRequest request: current request.
        :arg target_params: additional parameters that can be useful
            for `~.httputil.HTTPMessageDelegate` creation.
        """
        if isinstance(target, Router):
            return target.find_handler(request, **target_params)

        elif isinstance(target, httputil.HTTPServerConnectionDelegate):
            assert request.connection is not None
            return target.start_request(request.server_connection, request.connection)

        elif callable(target):
            assert request.connection is not None
            return _CallableAdapter(
                partial(target, **target_params), request.connection
            )

        return None


class ReversibleRuleRouter(ReversibleRouter, RuleRouter):
    """A rule-based router that implements ``reverse_url`` method.

    Each rule added to this router may have a ``name`` attribute that can be
    used to reconstruct an original uri. The actual reconstruction takes place
    in a rule's matcher (see `Matcher.reverse`).
    """

    def __init__(self, rules: _RuleList | None = None) -> None:
        self.named_rules: dict[str, Any] = {}
        super().__init__(rules)

    def process_rule(self, rule: "Rule") -> "Rule":
        rule = super().process_rule(rule)

        if rule.name:
            if rule.name in self.named_rules:
                app_log.warning(
                    "Multiple handlers named %s; replacing previous value", rule.name
                )
            self.named_rules[rule.name] = rule

        return rule

    def reverse_url(self, name: str, *args: Any) -> str | None:
        if name in self.named_rules:
            return self.named_rules[name].matcher.reverse(*args)

        for rule in self.rules:
            if isinstance(rule.target, ReversibleRouter):
                reversed_url = rule.target.reverse_url(name, *args)
                if reversed_url is not None:
                    return reversed_url

        return None


class Rule:
    """A routing rule."""

    def __init__(
        self,
        matcher: "Matcher",
        target: Any,
        target_kwargs: dict[str, Any] | None = None,
        name: str | None = None,
    ) -> None:
        """Constructs a Rule instance.

        :arg Matcher matcher: a `Matcher` instance used for determining
            whether the rule should be considered a match for a specific
            request.
        :arg target: a Rule's target (typically a ``RequestHandler`` or
            `~.httputil.HTTPServerConnectionDelegate` subclass or even a nested `Router`,
            depending on routing implementation).
        :arg dict target_kwargs: a dict of parameters that can be useful
            at the moment of target instantiation (for example, ``status_code``
            for a ``RequestHandler`` subclass). They end up in
            ``target_params['target_kwargs']`` of `RuleRouter.get_target_delegate`
            method.
        :arg str name: the name of the rule that can be used to find it
            in `ReversibleRouter.reverse_url` implementation.
        """
        if isinstance(target, str):
            # import the Module and instantiate the class
            # Must be a fully qualified name (module.ClassName)
            target = import_object(target)

        self.matcher: Matcher = matcher
        self.target = target
        self.target_kwargs = target_kwargs if target_kwargs else {}
        self.name = name

    def reverse(self, *args: Any) -> str | None:
        return self.matcher.reverse(*args)

    def __repr__(self) -> str:
        return "{}({!r}, {}, kwargs={!r}, name={!r})".format(
            self.__class__.__name__,
            self.matcher,
            self.target,
            self.target_kwargs,
            self.name,
        )


class Matcher:
    """Represents a matcher for request features."""

    def match(self, request: httputil.HTTPServerRequest) -> dict[str, Any] | None:
        """Matches current instance against the request.

        :arg httputil.HTTPServerRequest request: current HTTP request
        :returns: a dict of parameters to be passed to the target handler
            (for example, ``handler_kwargs``, ``path_args``, ``path_kwargs``
            can be passed for proper `~.web.RequestHandler` instantiation).
            An empty dict is a valid (and common) return value to indicate a match
            when the argument-passing features are not used.
            ``None`` must be returned to indicate that there is no match."""
        raise NotImplementedError()

    def reverse(self, *args: Any) -> str | None:
        """Reconstructs full url from matcher instance and additional arguments."""
        return None


class AnyMatches(Matcher):
    """Matches any request."""

    def match(self, request: httputil.HTTPServerRequest) -> dict[str, Any] | None:
        return {}


class HostMatches(Matcher):
    """Matches requests from hosts specified by ``host_pattern`` regex."""

    def __init__(self, host_pattern: str | Pattern) -> None:
        if isinstance(host_pattern, basestring_type):
            if not host_pattern.endswith("$"):
                host_pattern += "$"
            self.host_pattern = re.compile(host_pattern)
        else:
            self.host_pattern = host_pattern

    def match(self, request: httputil.HTTPServerRequest) -> dict[str, Any] | None:
        if self.host_pattern.match(request.host_name):
            return {}

        return None


class DefaultHostMatches(Matcher):
    """Matches requests from host that is equal to application's default_host.
    Always returns no match if ``X-Real-Ip`` header is present.
    """

    def __init__(self, application: Any, host_pattern: Pattern) -> None:
        self.application = application
        self.host_pattern = host_pattern

    def match(self, request: httputil.HTTPServerRequest) -> dict[str, Any] | None:
        # Look for default host if not behind load balancer (for debugging)
        if "X-Real-Ip" not in request.headers:
            if self.host_pattern.match(self.application.default_host):
                return {}
        return None


class PathMatches(Matcher):
    """Matches requests with paths specified by ``path_pattern`` regex."""

    def __init__(self, path_pattern: str | Pattern) -> None:
        if isinstance(path_pattern, basestring_type):
            if not path_pattern.endswith("$"):
                path_pattern += "$"
            self.regex = re.compile(path_pattern)
        else:
            self.regex = path_pattern

        assert len(self.regex.groupindex) in (0, self.regex.groups), (
            "groups in url regexes must either be all named or all "
            "positional: %r" % self.regex.pattern
        )

        self._path, self._group_count = self._find_groups()

    def match(self, request: httputil.HTTPServerRequest) -> dict[str, Any] | None:
        match = self.regex.match(request.path)
        if match is None:
            return None
        if not self.regex.groups:
            return {}

        path_args: list[bytes] = []
        path_kwargs: dict[str, bytes] = {}

        # Pass matched groups to the handler.  Since
        # match.groups() includes both named and
        # unnamed groups, we want to use either groups
        # or groupdict but not both.
        if self.regex.groupindex:
            path_kwargs = {
                str(k): _unquote_or_none(v) for (k, v) in match.groupdict().items()
            }
        else:
            path_args = [_unquote_or_none(s) for s in match.groups()]

        return dict(path_args=path_args, path_kwargs=path_kwargs)

    def reverse(self, *args: Any) -> str | None:
        if self._path is None:
            raise ValueError("Cannot reverse url regex " + self.regex.pattern)
        assert len(args) == self._group_count, (
            "required number of arguments " "not found"
        )
        if not len(args):
            return self._path
        converted_args = []
        for a in args:
            if not isinstance(a, (unicode_type, bytes)):
                a = str(a)
            converted_args.append(url_escape(utf8(a), plus=False))
        return self._path % tuple(converted_args)

    def _find_groups(self) -> tuple[str | None, int | None]:
        """Returns a tuple (reverse string, group count) for a url.

        For example: Given the url pattern /([0-9]{4})/([a-z-]+)/, this method
        would return ('/%s/%s/', 2).
        """
        pattern = self.regex.pattern
        if pattern.startswith("^"):
            pattern = pattern[1:]
        if pattern.endswith("$"):
            pattern = pattern[:-1]

        if self.regex.groups != pattern.count("("):
            # The pattern is too complicated for our simplistic matching,
            # so we can't support reversing it.
            return None, None

        pieces = []
        for fragment in pattern.split("("):
            if ")" in fragment:
                paren_loc = fragment.index(")")
                if paren_loc >= 0:
                    try:
                        unescaped_fragment = re_unescape(fragment[paren_loc + 1 :])
                    except ValueError:
                        # If we can't unescape part of it, we can't
                        # reverse this url.
                        return (None, None)
                    pieces.append("%s" + unescaped_fragment)
            else:
                try:
                    unescaped_fragment = re_unescape(fragment)
                except ValueError:
                    # If we can't unescape part of it, we can't
                    # reverse this url.
                    return (None, None)
                pieces.append(unescaped_fragment)

        return "".join(pieces), self.regex.groups


class Converter:
    """Base class for `PathTemplate` parameter converters.

    A converter is responsible for translating a path parameter in both
    directions: ``to_python`` transforms the (percent-decoded) string
    captured from the request path into the value passed to the handler,
    and ``to_url`` transforms a value passed to ``reverse_url`` back into
    the string that will be placed (after percent-encoding) into the url.

    Subclasses must set ``regex`` to a regular expression fragment that
    matches the *percent-encoded* form of the parameter within the
    request path (it must not contain any capturing groups; lookaround
    and non-capturing groups are fine).

    Conversion failures must be reported by raising `ValueError`, which
    is treated as "this rule does not match" (or, when reversing, as an
    invalid argument). Any other exception is considered a programming
    error in the converter itself and is propagated to the caller.

    .. versionadded:: 6.6
    """

    regex = "[^/]+"

    def to_python(self, value: str) -> Any:
        """Converts a string captured from the request path to a Python value."""
        return value

    def to_url(self, value: Any) -> str:
        """Converts a Python value to its canonical string form for use in a url."""
        return str(value)


class StringConverter(Converter):
    """The default converter; matches a single path segment."""

    regex = "[^/]+"

    def to_python(self, value: str) -> str:
        return value

    def to_url(self, value: Any) -> str:
        if not isinstance(value, str):
            value = str(value)
        return value


class IntConverter(Converter):
    """Matches a non-negative integer and converts it to `int`."""

    regex = "[0-9]+"

    def to_python(self, value: str) -> int:
        return int(value)

    def to_url(self, value: Any) -> str:
        return str(int(value))


class UUIDConverter(Converter):
    """Matches a canonical UUID string and converts it to `uuid.UUID`."""

    regex = (
        "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
        "-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    )

    def to_python(self, value: str) -> uuid.UUID:
        return uuid.UUID(value)

    def to_url(self, value: Any) -> str:
        if isinstance(value, uuid.UUID):
            return str(value)
        return str(uuid.UUID(str(value)))


class PathConverter(Converter):
    """Matches the rest of the path, including any slashes."""

    regex = ".+"

    def to_python(self, value: str) -> str:
        return value

    def to_url(self, value: Any) -> str:
        if not isinstance(value, str):
            value = str(value)
        return value


class _TemplateParameter(NamedTuple):
    name: str
    converter: Converter
    optional: bool


class PathTemplate(Matcher):
    """Matches request paths against a template with named parameters.

    A template is a path in which ``<name>`` or ``<converter:name>``
    placeholders match a single path segment and capture it as a named
    parameter::

        Rule(PathTemplate("/users/<int:user_id>"), UserHandler, name="user")

    The final parameter may be marked optional with a trailing ``?``,
    which makes the whole final path segment optional (the parameter is
    passed as ``None`` when it is absent)::

        Rule(PathTemplate("/files/<uuid:file_id>/<path:file_path>?"), FileHandler)

    Matched values are converted by the parameter's `Converter` and the
    resulting Python objects (not byte strings) are passed to the
    handler, so ``user_id`` above arrives as an `int`. If a converter
    raises `ValueError` the rule simply does not match.

    The following converters are registered by default: ``str`` (the
    default when no converter is given), ``int``, ``uuid`` and ``path``
    (which matches the rest of the path including slashes). Additional
    converters may be registered with `register_converter` or passed to
    the constructor.

    Templates are reversible: `~.ReversibleRuleRouter.reverse_url` (and
    therefore `tornado.web.Application.reverse_url` and
    `tornado.web.RequestHandler.reverse_url`) builds the url from the
    parameter values, validating each value with its converter and
    percent-encoding it exactly once. Reversing fails with a
    `ValueError` if a required parameter is missing, if too many
    arguments are given, or if a value cannot round-trip through the
    template (for example a ``str`` parameter containing a slash).

    .. versionadded:: 6.6
    """

    default_converters: dict[str, Converter] = {
        "str": StringConverter(),
        "int": IntConverter(),
        "uuid": UUIDConverter(),
        "path": PathConverter(),
    }

    _parameter_re = re.compile(
        r"<(?:([A-Za-z_][A-Za-z0-9_]*):)?([A-Za-z_][A-Za-z0-9_]*)>(\?)?"
    )

    @classmethod
    def register_converter(cls, name: str, converter: Converter) -> None:
        """Registers a converter under ``name`` for all templates created
        afterwards."""
        cls.default_converters[name] = converter

    def __init__(
        self,
        template: str,
        converters: dict[str, Converter] | None = None,
    ) -> None:
        self.template = template
        self.converters = dict(self.default_converters)
        if converters:
            self.converters.update(converters)

        # Tokenize the template into ("lit", text) and ("param", parameter)
        # tokens. Literal and parameter tokens always alternate.
        self._tokens: list[tuple[str, Any]] = []
        self._params: list[_TemplateParameter] = []
        pos = 0
        for match in self._parameter_re.finditer(template):
            self._add_literal(template[pos : match.start()])
            converter_name, name, optional = match.groups()
            try:
                converter = self.converters[converter_name or "str"]
            except KeyError:
                raise ValueError(
                    "unknown converter %r in url template %r"
                    % (converter_name, template)
                ) from None
            param = _TemplateParameter(name, converter, optional is not None)
            if any(p.name == name for p in self._params):
                raise ValueError(
                    "duplicate parameter %r in url template %r" % (name, template)
                )
            self._params.append(param)
            self._tokens.append(("param", param))
            pos = match.end()
        self._add_literal(template[pos:])

        optional_params = [p for p in self._params if p.optional]
        if optional_params:
            # The tokens always end with a (possibly empty) literal, so
            # the final parameter is the last or next-to-last token.
            last_param = self._tokens[-1]
            if last_param == ("lit", ""):
                last_param = self._tokens[-2]
            if len(optional_params) > 1 or last_param != (
                "param",
                optional_params[0],
            ):
                raise ValueError(
                    "only the final parameter of a url template "
                    "may be optional: %r" % template
                )

        # Compile the template into a regular expression. The optional
        # trailing parameter, together with the "/" that introduces
        # its segment (if any), is wrapped in a non-capturing optional
        # group.
        parts = []
        for kind, value in self._tokens:
            if kind == "lit":
                parts.append(re.escape(value))
            else:
                group = "(?P<%s>%s)" % (value.name, value.converter.regex)
                if value.optional:
                    prefix = ""
                    if parts and parts[-1].endswith("/"):
                        parts[-1] = parts[-1][:-1]
                        prefix = "/"
                    parts.append("(?:%s%s)?" % (prefix, group))
                else:
                    parts.append(group)
        self.regex = re.compile("^%s$" % "".join(parts))

    def _add_literal(self, text: str) -> None:
        if "<" in text or ">" in text:
            raise ValueError(
                "malformed parameter in url template %r" % self.template
            )
        self._tokens.append(("lit", text))

    def match(self, request: httputil.HTTPServerRequest) -> dict[str, Any] | None:
        return self._match_path(request.path)

    def _match_path(self, path: str) -> dict[str, Any] | None:
        match = self.regex.match(path)
        if match is None:
            return None
        path_kwargs: dict[str, Any] = {}
        for param in self._params:
            raw = match.group(param.name)
            if raw is None:
                # The optional trailing parameter is absent.
                value = None
            else:
                unquoted = url_unescape(raw, encoding="utf-8", plus=False)
                try:
                    value = param.converter.to_python(unquoted)
                except ValueError:
                    # Conversion failure means this rule does not match.
                    # Other exceptions are programming errors in the
                    # converter and are propagated.
                    return None
            path_kwargs[param.name] = value
        return dict(path_kwargs=path_kwargs)

    def reverse(self, *args: Any) -> str | None:
        required = [p for p in self._params if not p.optional]
        if len(args) < len(required):
            raise ValueError(
                "not enough arguments for url template %r: "
                "expected at least %d, got %d"
                % (self.template, len(required), len(args))
            )
        if len(args) > len(self._params):
            raise ValueError(
                "too many arguments for url template %r: "
                "expected at most %d, got %d"
                % (self.template, len(self._params), len(args))
            )

        values: dict[str, str | None] = {}
        for param in self._params[len(args) :]:
            values[param.name] = None
        for param, arg in zip(self._params, args):
            if arg is None:
                if not param.optional:
                    raise ValueError(
                        "parameter %r of url template %r is not optional"
                        % (param.name, self.template)
                    )
                values[param.name] = None
            else:
                values[param.name] = param.converter.to_url(arg)

        # Build the path, percent-encoding each parameter value exactly
        # once (literal template text is used as-is).
        parts = []
        for kind, value in self._tokens:
            if kind == "lit":
                parts.append(value)
            else:
                encoded = values[value.name]
                if encoded is None:
                    # An omitted optional parameter: drop the "/"
                    # that introduces its segment (if any).
                    if parts and parts[-1].endswith("/"):
                        parts[-1] = parts[-1][:-1]
                        if not parts[-1]:
                            parts.pop()
                else:
                    parts.append(url_escape(utf8(encoded), plus=False))
        path = "".join(parts)

        # Verify that the built url maps back to the same parameter
        # values, rejecting values that cannot round-trip (such as a
        # slash in a single-segment parameter).
        matched = self._match_path(path)
        if matched is not None:
            matched_kwargs = matched["path_kwargs"]
            for param, arg in zip(self._params, args):
                encoded = values[param.name]
                if encoded is None:
                    continue
                round_tripped = matched_kwargs[param.name]
                if round_tripped == arg:
                    continue
                if round_tripped == param.converter.to_python(encoded):
                    continue
                matched = None
                break
        if matched is None:
            raise ValueError(
                "arguments %r cannot be reversed with url template %r"
                % (args, self.template)
            )
        return path

    def __repr__(self) -> str:
        return "%s(%r)" % (self.__class__.__name__, self.template)


class URLSpec(Rule):
    """Specifies mappings between URLs and handlers.

    .. versionchanged: 4.5
       `URLSpec` is now a subclass of a `Rule` with `PathMatches` matcher and is preserved for
       backwards compatibility.
    """

    def __init__(
        self,
        pattern: str | Pattern,
        handler: Any,
        kwargs: dict[str, Any] | None = None,
        name: str | None = None,
    ) -> None:
        """Parameters:

        * ``pattern``: Regular expression to be matched. Any capturing
          groups in the regex will be passed in to the handler's
          get/post/etc methods as arguments (by keyword if named, by
          position if unnamed. Named and unnamed capturing groups
          may not be mixed in the same rule).

        * ``handler``: `~.web.RequestHandler` subclass to be invoked.

        * ``kwargs`` (optional): A dictionary of additional arguments
          to be passed to the handler's constructor.

        * ``name`` (optional): A name for this handler.  Used by
          `~.web.Application.reverse_url`.

        """
        matcher = PathMatches(pattern)
        super().__init__(matcher, handler, kwargs, name)

        self.regex = matcher.regex
        self.handler_class = self.target
        self.kwargs = kwargs

    def __repr__(self) -> str:
        return "{}({!r}, {}, kwargs={!r}, name={!r})".format(
            self.__class__.__name__,
            self.regex.pattern,
            self.handler_class,
            self.kwargs,
            self.name,
        )


@overload
def _unquote_or_none(s: str) -> bytes:
    pass


@overload
def _unquote_or_none(s: None) -> None:
    pass


def _unquote_or_none(s: str | None) -> bytes | None:
    """None-safe wrapper around url_unescape to handle unmatched optional
    groups correctly.

    Note that args are passed as bytes so the handler can decide what
    encoding to use.
    """
    if s is None:
        return s
    return url_unescape(s, encoding=None, plus=False)
