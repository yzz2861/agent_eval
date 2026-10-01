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
import urllib.parse
import uuid
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Sequence
from functools import partial
from re import Pattern
from typing import (
    Any,
    ClassVar,
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

    def reverse_url(self, name: str, *args: Any, **kwargs: Any) -> str | None:
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
                    return self._merge_inherited_target_params(delegate, **kwargs)

        return None

    def _merge_inherited_target_params(
        self, delegate: httputil.HTTPMessageDelegate, **kwargs: Any
    ) -> httputil.HTTPMessageDelegate:
        inherited_path_args = kwargs.get("path_args", [])
        inherited_path_kwargs = kwargs.get("path_kwargs", {})
        if inherited_path_args or inherited_path_kwargs:
            delegate_vars = vars(delegate)
            if "path_args" not in delegate_vars or "path_kwargs" not in delegate_vars:
                return delegate
            duplicate_kwargs = set(inherited_path_kwargs) & set(
                delegate_vars.get("path_kwargs", {})
            )
            if duplicate_kwargs:
                raise ValueError(
                    "Duplicate path parameters: %s"
                    % ", ".join(sorted(duplicate_kwargs))
                )
            delegate_vars["path_args"] = list(inherited_path_args) + list(
                delegate_vars.get("path_args", [])
            )
            delegate_vars["path_kwargs"] = {
                **inherited_path_kwargs,
                **delegate_vars.get("path_kwargs", {}),
            }
        return delegate

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

    def reverse_url(self, name: str, *args: Any, **kwargs: Any) -> str | None:
        if name in self.named_rules:
            return self._reverse_rule_chain(
                [(self, self.named_rules[name])], *args, **kwargs
            )

        for rule in self.rules:
            if isinstance(rule.target, ReversibleRouter):
                reversed_url = self._reverse_nested_url(rule, name, *args, **kwargs)
                if reversed_url is not None:
                    return reversed_url

        return None

    def _find_named_rule_chain(
        self, name: str
    ) -> list[tuple["ReversibleRuleRouter", "Rule"]] | None:
        if name in self.named_rules:
            return [(self, self.named_rules[name])]

        for rule in self.rules:
            if isinstance(rule.target, ReversibleRuleRouter):
                chain = rule.target._find_named_rule_chain(name)
                if chain is not None:
                    return [(self, rule), *chain]
        return None

    def _reverse_nested_url(
        self, rule: "Rule", name: str, *args: Any, **kwargs: Any
    ) -> str | None:
        if not isinstance(rule.target, ReversibleRuleRouter):
            return rule.target.reverse_url(name, *args, **kwargs)

        chain = rule.target._find_named_rule_chain(name)
        if chain is None:
            return None
        return self._reverse_rule_chain([(self, rule), *chain], *args, **kwargs)

    def _reverse_rule_chain(
        self,
        chain: list[tuple["ReversibleRuleRouter", "Rule"]],
        *args: Any,
        **kwargs: Any,
    ) -> str:
        final_matcher = chain[-1][1].matcher
        if not isinstance(final_matcher, PathTemplateMatches):
            return final_matcher.reverse(*args, **kwargs)

        template_matchers = []
        for _, rule in chain:
            matcher = rule.matcher
            if isinstance(matcher, (HostMatches, AnyMatches)):
                continue
            if isinstance(matcher, PathTemplateMatches):
                template_matchers.append(matcher)
                continue
            return final_matcher.reverse(*args)

        parameters = [
            (name, converter, optional)
            for matcher in template_matchers
            for name, converter, optional in matcher.parameters
        ]
        names = [name for name, _, _ in parameters]
        if len(names) != len(set(names)):
            duplicate_names = sorted({name for name in names if names.count(name) > 1})
            raise ValueError(
                "Duplicate path parameters: %s" % ", ".join(duplicate_names)
            )

        if args and kwargs:
            raise ValueError("Cannot mix positional and keyword arguments")
        if len(args) > len(parameters):
            raise ValueError("Too many path arguments")
        if args:
            matcher_kwargs = {
                name: value
                for (name, _, _), value in zip(parameters, args, strict=False)
            }
        else:
            extra = set(kwargs) - set(names)
            if extra:
                raise ValueError(
                    "Unexpected path arguments: %s" % ", ".join(sorted(extra))
                )
            matcher_kwargs = dict(kwargs)

        reversed_parts = []
        for matcher in template_matchers:
            matcher_names = {name for name, _, _ in matcher.parameters}
            if args:
                matcher_args = [matcher_kwargs[name] for name in matcher_names]
                reversed_parts.append(matcher.reverse(*matcher_args))
            else:
                reversed_parts.append(
                    matcher.reverse(
                        **{
                            name: value
                            for name, value in matcher_kwargs.items()
                            if name in matcher_names
                        }
                    )
                )
        return "".join(reversed_parts)


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

    def reverse(self, *args: Any, **kwargs: Any) -> str | None:
        return self.matcher.reverse(*args, **kwargs)

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

    def reverse(self, *args: Any, **kwargs: Any) -> str | None:
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


class PathConverter(ABC):
    """Converts values between Python objects and path template strings."""

    regex: str = "[^/]+"
    safe: str = ""

    @abstractmethod
    def to_python(self, value: str) -> Any:
        """Converts a matched path segment to a Python value."""

    @abstractmethod
    def to_url(self, value: Any) -> str:
        """Converts a Python value to an unencoded path segment."""


class StringConverter(PathConverter):
    """Matches one path segment and returns it as a string."""

    regex = "[^/]+"
    safe = ""

    def to_python(self, value: str) -> str:
        return value

    def to_url(self, value: Any) -> str:
        if not isinstance(value, unicode_type):
            raise ValueError("Expected a string")
        return value


class IntegerConverter(PathConverter):
    """Matches a signed decimal integer and returns an `int`."""

    regex = "-?[0-9]+"
    safe = ""

    def to_python(self, value: str) -> int:
        return int(value)

    def to_url(self, value: Any) -> str:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("Expected an integer")
        return str(value)


class RemainingPathConverter(PathConverter):
    """Matches the remainder of a path, including slashes."""

    regex = ".*"
    safe = "/"

    def to_python(self, value: str) -> str:
        return value

    def to_url(self, value: Any) -> str:
        if not isinstance(value, unicode_type):
            raise ValueError("Expected a string")
        return value


class UUIDConverter(PathConverter):
    """Matches a UUID and returns a `uuid.UUID` instance."""

    regex = (
        "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-" "[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    )
    safe = "-"

    def to_python(self, value: str) -> uuid.UUID:
        return uuid.UUID(value)

    def to_url(self, value: Any) -> str:
        if not isinstance(value, uuid.UUID):
            raise ValueError("Expected a UUID")
        return str(value)


_DEFAULT_CONVERTERS: dict[str, PathConverter] = {
    "str": StringConverter(),
    "int": IntegerConverter(),
    "path": RemainingPathConverter(),
    "uuid": UUIDConverter(),
}


class PathTemplateMatches(Matcher):
    """Matches paths using named parameter templates.

    Parameters are written as ``{name}`` or ``{name:converter}``. A
    trailing parameter may include slashes with the ``path`` converter, and
    a trailing parameter may be marked optional with ``?``, for example
    ``/files/{id:uuid}/{path:path?}``.
    """

    converters: ClassVar[dict[str, PathConverter]] = dict(_DEFAULT_CONVERTERS)

    def __init__(
        self,
        path_template: str,
        converters: dict[str, PathConverter] | None = None,
    ) -> None:
        self.path_template = path_template
        self.converters = dict(type(self).converters)
        if converters is not None:
            self.converters.update(converters)

        self.parameters: list[tuple[str, PathConverter, bool]] = []
        pattern, self._template_parts = self._parse(path_template)
        self.regex = re.compile("^" + pattern + "$")

    @classmethod
    def register_converter(cls, name: str, converter: PathConverter) -> None:
        """Registers a converter with subsequently created template matchers."""
        cls.converters[name] = converter

    def match(self, request: httputil.HTTPServerRequest) -> dict[str, Any] | None:
        match = self.regex.match(request.path)
        if match is None:
            return None

        path_kwargs = {}
        for name, converter, optional in self.parameters:
            raw_value = match.group(name)
            if raw_value is None:
                if not optional:
                    return None
                path_kwargs[name] = None
                continue

            try:
                decoded_value = _path_unescape(raw_value)
                path_kwargs[name] = converter.to_python(decoded_value)
            except ValueError:
                return None

        return dict(path_args=[], path_kwargs=path_kwargs)

    def reverse(self, *args: Any, **kwargs: Any) -> str:
        values = self._reverse_values(*args, **kwargs)
        parts = []
        for kind, part_value in self._template_parts:
            if kind == "literal":
                parts.append(part_value)
            elif kind == "slash":
                parts.append("/" if part_value in values else "")
            else:
                parts.append(values.get(part_value, ""))
        return "".join(parts)

    def _reverse_values(self, *args: Any, **kwargs: Any) -> dict[str, str]:
        if args and kwargs:
            raise ValueError("Cannot mix positional and keyword arguments")
        if len(args) > len(self.parameters):
            raise ValueError("Too many path arguments")
        if args:
            values = {
                name: value
                for (name, _, _), value in zip(self.parameters, args, strict=False)
            }
        else:
            names = {name for name, _, _ in self.parameters}
            extra = set(kwargs) - names
            if extra:
                raise ValueError(
                    "Unexpected path arguments: %s" % ", ".join(sorted(extra))
                )
            values = dict(kwargs)

        converted_values = {}
        encoded_parts = {}
        for name, converter, optional in self.parameters:
            if name not in values:
                if not optional:
                    raise ValueError("Missing path argument: %s" % name)
                continue

            value = values[name]
            if value is None:
                if not optional:
                    raise ValueError("Path argument cannot be None: %s" % name)
                continue

            try:
                raw_value = converter.to_url(value)
                encoded_value = _path_quote(
                    raw_value, safe=converter.safe, safe_percent=False
                )
                if re.fullmatch(converter.regex, encoded_value) is None:
                    raise ValueError(
                        "Encoded value for path argument %r is not valid: %r"
                        % (name, encoded_value)
                    )
                matched_value = converter.to_python(_path_unescape(encoded_value))
            except ValueError:
                raise
            if matched_value != value:
                raise ValueError(
                    "Value for path argument %r is not reversible: %r" % (name, value)
                )
            converted_values[name] = value
            encoded_parts[name] = encoded_value

        if args:
            required_count = sum(
                1 for _, _, optional in self.parameters if not optional
            )
            if len(args) < required_count:
                raise ValueError("Not enough path arguments")
        return encoded_parts

    def _parse(self, template: str) -> tuple[str, list[tuple[str, str]]]:
        regex_parts = []
        template_parts: list[tuple[str, str]] = []
        position = 0
        path_converter_end: int | None = None
        optional_end: int | None = None

        while position < len(template):
            open_loc = template.find("{", position)
            if open_loc < 0:
                literal = template[position:]
                if "}" in literal:
                    raise ValueError("Unbalanced path template: %r" % template)
                encoded_literal = _path_template_literal(literal)
                regex_parts.append(re.escape(encoded_literal))
                template_parts.append(("literal", encoded_literal))
                break

            close_loc = template.find("}", open_loc + 1)
            if close_loc < 0:
                raise ValueError("Unbalanced path template: %r" % template)

            expression = template[open_loc + 1 : close_loc]
            optional = expression.endswith("?")
            if optional:
                expression = expression[:-1]
            literal = template[position:open_loc]
            if "}" in literal:
                raise ValueError("Unbalanced path template: %r" % template)
            optional_slash = optional and literal.endswith("/")
            if optional_slash:
                literal = literal[:-1]
            encoded_literal = _path_template_literal(literal)
            regex_parts.append(re.escape(encoded_literal))
            template_parts.append(("literal", encoded_literal))
            if ":" in expression:
                name, converter_name = expression.split(":", 1)
            else:
                name, converter_name = expression, "str"

            if any(existing_optional for _, _, existing_optional in self.parameters):
                raise ValueError("Only the final path parameter may be optional")

            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                raise ValueError("Invalid path parameter name: %r" % name)
            if name in {parameter_name for parameter_name, _, _ in self.parameters}:
                raise ValueError("Duplicate path parameter: %s" % name)
            if converter_name not in self.converters:
                raise ValueError("Unknown path converter: %s" % converter_name)
            converter = self.converters[converter_name]
            if any(
                existing_converter.regex == ".*"
                for _, existing_converter, _ in self.parameters
            ):
                raise ValueError("A path converter parameter must be final")
            if not isinstance(converter.regex, str) or not converter.regex:
                raise ValueError("Path converter regex must be a non-empty string")
            if re.compile("(?:%s)" % converter.regex).groups:
                raise ValueError("Path converter regexes may not contain groups")

            if optional:
                regex_parts.append("(?:/" if optional_slash else "(?:")
                if optional_slash:
                    template_parts.append(("slash", name))

            regex_parts.append("(?P<%s>%s)" % (name, converter.regex))
            template_parts.append(("parameter", name))
            self.parameters.append((name, converter, optional))
            position = close_loc + 1
            if optional:
                optional_end = position
            if converter.regex == ".*":
                path_converter_end = position
            if optional:
                regex_parts.append(")?")

        result = "".join(regex_parts), template_parts
        if path_converter_end is not None and path_converter_end != len(template):
            raise ValueError("A path converter parameter must be final")
        if optional_end is not None and optional_end != len(template):
            raise ValueError("Only the final path parameter may be optional")
        for index, (_, converter, _) in enumerate(self.parameters):
            if converter.regex == ".*" and index != len(self.parameters) - 1:
                raise ValueError("A path converter parameter must be final")
        return result


def _path_template_literal(value: str) -> str:
    return _path_quote(value, safe="/%")


def _path_quote(value: str, safe: str = "", safe_percent: bool = True) -> str:
    slash = "/" if "/" in safe else ""
    return urllib.parse.quote(
        value,
        safe=slash + ":@!$&'()*+,;=~" + safe + ("%" if safe_percent else ""),
        encoding="utf-8",
        errors="strict",
    )


def _path_unescape(value: str) -> str:
    return urllib.parse.unquote(value, encoding="utf-8", errors="strict")


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
