"""Optional helpers for projecting response media onto selected fields."""

from __future__ import annotations

from collections.abc import Mapping
from functools import wraps
from inspect import iscoroutinefunction
import re
from typing import Any

from falcon.errors import HTTPBadRequest

__all__ = ('FieldProjection',)

_NAME_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_-]*')
_WHITESPACE = ' \t'

_MISSING = object()


def _invalid_expression(description: str) -> HTTPBadRequest:
    return HTTPBadRequest(title='Invalid fields expression', description=description)


def _merge_field(
    selection: dict[str, Any],
    name: str,
    children: dict[str, Any] | None,
    path: tuple[str, ...],
) -> None:
    if name not in selection:
        selection[name] = children
        return

    existing = selection[name]
    if existing is None or children is None:
        if existing is None and children is None:
            # NOTE: An exact duplicate simply merges into itself.
            return

        dotted = '.'.join(path + (name,))
        raise _invalid_expression("Conflicting selections for field: '%s'." % dotted)

    _merge_selection(existing, children, path + (name,))


def _merge_selection(
    target: dict[str, Any], source: dict[str, Any], path: tuple[str, ...]
) -> None:
    for name, children in source.items():
        _merge_field(target, name, children, path)


class _ExpressionParser:
    """Recursive-descent parser for the finite fields expression grammar."""

    def __init__(self, expression: str, max_depth: int):
        self._expression = expression
        self._length = len(expression)
        self._pos = 0
        self._max_depth = max_depth

    def parse(self) -> dict[str, Any]:
        self._skip_whitespace()
        if self._pos >= self._length:
            raise _invalid_expression('The expression is empty.')

        selection = self._parse_selection((), 1)

        self._skip_whitespace()
        if self._pos < self._length:
            raise _invalid_expression(
                "Unexpected character: '%s'." % self._expression[self._pos]
            )

        return selection

    def _parse_selection(self, path: tuple[str, ...], depth: int) -> dict[str, Any]:
        selection: dict[str, Any] = {}

        while True:
            self._skip_whitespace()
            name = self._parse_name()

            self._skip_whitespace()
            children = None
            if self._peek() == '(':
                if depth >= self._max_depth:
                    raise _invalid_expression(
                        'The expression exceeds the maximum nesting '
                        'depth of %d.' % self._max_depth
                    )
                self._pos += 1
                children = self._parse_selection(path + (name,), depth + 1)
                self._skip_whitespace()
                self._expect(')')

            _merge_field(selection, name, children, path)

            self._skip_whitespace()
            if self._peek() != ',':
                break

            self._pos += 1

        return selection

    def _parse_name(self) -> str:
        match = _NAME_RE.match(self._expression, self._pos)
        if match is None:
            raise _invalid_expression(
                'Expected a field name at position %d.' % self._pos
            )

        self._pos = match.end()
        return match.group()

    def _expect(self, char: str) -> None:
        if self._peek() != char:
            raise _invalid_expression(
                "Expected '%s' at position %d." % (char, self._pos)
            )
        self._pos += 1

    def _peek(self) -> str | None:
        if self._pos >= self._length:
            return None
        return self._expression[self._pos]

    def _skip_whitespace(self) -> None:
        while self._pos < self._length and self._expression[self._pos] in _WHITESPACE:
            self._pos += 1


def _expand(node: Any) -> Any:
    if node is None:
        return None
    return {name: _expand(child) for name, child in node.items()}


def _project(value: Any, selection: dict[str, Any] | None) -> Any:
    if selection is None:
        return value

    if isinstance(value, Mapping):
        return {
            name: _project(value[name], subselection)
            for name, subselection in selection.items()
            if name in value
        }

    if isinstance(value, (list, tuple)):
        return [_project(item, selection) for item in value]

    return value


class FieldProjection:
    """Projects response media onto a client-selected subset of fields.

    A field projection is declared by the responder as a tree of field
    names that are safe to expose, and clients pick a subset of that tree
    with a finite expression syntax such as::

        fields=name,orders(id,total)

    The expression grammar is intentionally limited to comma-separated
    field names with optional parenthesized sub-selections; it is parsed
    by hand (never via ``eval()``) and is not a general JSONPath
    implementation.

    Selecting a parent field without a sub-selection, e.g. ``orders``,
    expands to the fields declared for that parent in the tree. Note that
    allowing a parent field does not imply that all of its children are
    exposable: only the declared children are ever projected. Duplicate
    selections are merged, while unknown fields, conflicting selections
    (selecting a field both wholly and partially), malformed expressions,
    and expressions nested deeper than ``max_depth`` are rejected with a
    :class:`~falcon.HTTPBadRequest` error.

    The projected result is always built from new containers; the source
    object is never modified in place, so objects that are cached or
    shared between requests remain intact.

    Example::

        projection = FieldProjection({
            'name': True,
            'orders': {
                'id': True,
                'total': True,
            },
        })

        class ItemResource:
            @projection
            def on_get(self, req, resp):
                resp.media = get_item()

    Args:
        fields (Mapping): Tree of field names that may be projected. Each
            value is either a mapping declaring the allowed children of
            that field, or any other value (conventionally ``True``) to
            mark a leaf that is projected as-is.
        max_depth (int): Maximum nesting depth of a fields expression
            (default ``8``).
        param (str): Name of the query parameter carrying the fields
            expression (default ``'fields'``).
    """

    def __init__(self, fields: Mapping, *, max_depth: int = 8, param: str = 'fields'):
        if max_depth < 1:
            raise ValueError('max_depth must be at least 1')

        self._tree = self._normalize_tree(fields)
        self._max_depth = max_depth
        self._param = param

    @property
    def max_depth(self) -> int:
        """Maximum nesting depth allowed in a fields expression."""
        return self._max_depth

    @property
    def param(self) -> str:
        """Name of the query parameter carrying the fields expression."""
        return self._param

    def parse(self, expression: str) -> dict[str, Any]:
        """Compile a fields expression into a selection tree.

        Args:
            expression (str): A fields expression such as
                ``'name,orders(id,total)'``.

        Returns:
            dict: A selection tree suitable for :meth:`project`, in which
            each field maps either to ``None`` (project the value as-is)
            or to a nested selection tree.

        Raises:
            TypeError: ``expression`` is not a string.
            HTTPBadRequest: The expression is malformed, references an
                unknown field, contains conflicting selections, or exceeds
                the maximum nesting depth.
        """
        if not isinstance(expression, str):
            raise TypeError('expression must be a string')

        selection = _ExpressionParser(expression, self._max_depth).parse()
        self._resolve(selection, self._tree, ())
        return selection

    def parse_request(
        self, req: Any, param: str | None = None
    ) -> dict[str, Any] | None:
        """Parse the fields expression from a request, if present.

        Args:
            req: The request object to inspect.
            param (str): Query parameter name to read instead of the
                default one.

        Returns:
            A selection tree suitable for :meth:`project`, or ``None``
            when the request does not select any fields.

        Raises:
            HTTPBadRequest: The fields expression is invalid.
        """
        expression = req.get_param(param or self._param)
        if expression is None:
            return None

        expression = expression.strip()
        if not expression:
            return None

        return self.parse(expression)

    def project(self, data: Any, selection: dict[str, Any] | None) -> Any:
        """Return a projected copy of ``data`` per the selection tree.

        Nested mappings and iterables of mappings (such as lists of
        objects) are projected with the same selection tree. Selected
        fields that are missing from the data are skipped. The source
        object is never modified; new containers are created for the
        projected result.

        Args:
            data: The object to project, typically a dict or a list of
                dicts.
            selection: A selection tree as returned by :meth:`parse` or
                :meth:`parse_request`. ``None`` returns ``data`` as-is.

        Returns:
            The projected copy of ``data``.
        """
        return _project(data, selection)

    def select(self, expression: str, data: Any) -> Any:
        """Parse ``expression`` and project ``data`` in a single step.

        Args:
            expression (str): A fields expression.
            data: The object to project.

        Returns:
            The projected copy of ``data``.

        Raises:
            HTTPBadRequest: The fields expression is invalid.
        """
        return self.project(data, self.parse(expression))

    def __call__(self, responder: Any) -> Any:
        """Decorate a responder to project ``resp.media`` when requested.

        The fields expression is parsed before the responder runs, so
        invalid expressions are rejected with a
        :class:`~falcon.HTTPBadRequest` error before any business logic
        executes. After the responder returns, ``resp.media`` is replaced
        by its projected copy, ensuring that the rendered body, and hence
        the Content-Length header and any representation validators, are
        derived from the data that is actually output. Both sync and
        async responders are supported.
        """
        if iscoroutinefunction(responder):

            @wraps(responder)
            async def async_responder(obj, req, resp, *args, **kwargs):
                selection = self.parse_request(req)
                await responder(obj, req, resp, *args, **kwargs)
                if selection is not None and resp.media is not None:
                    resp.media = self.project(resp.media, selection)

            return async_responder

        @wraps(responder)
        def sync_responder(obj, req, resp, *args, **kwargs):
            selection = self.parse_request(req)
            responder(obj, req, resp, *args, **kwargs)
            if selection is not None and resp.media is not None:
                resp.media = self.project(resp.media, selection)

        return sync_responder

    @staticmethod
    def _normalize_tree(fields: Mapping) -> dict[str, Any]:
        if not isinstance(fields, Mapping):
            raise TypeError('fields must be a mapping of field names')

        tree = {}
        for name, node in fields.items():
            if not isinstance(name, str):
                raise TypeError('field names must be strings')

            if isinstance(node, Mapping) and node:
                tree[name] = FieldProjection._normalize_tree(node)
            else:
                # NOTE: An empty mapping is equivalent to a leaf marker.
                tree[name] = None

        return tree

    def _resolve(
        self,
        selection: dict[str, Any],
        subtree: dict[str, Any],
        path: tuple[str, ...],
    ) -> None:
        for name, children in selection.items():
            node = subtree.get(name, _MISSING)
            if node is _MISSING:
                dotted = '.'.join(path + (name,))
                raise _invalid_expression("Unknown field: '%s'." % dotted)

            if children is None:
                # NOTE: A bare field expands to the whole allowed subtree,
                #   so that only declared children are ever exposed.
                selection[name] = _expand(node)
            elif node is None:
                dotted = '.'.join(path + (name,))
                raise _invalid_expression(
                    "Field '%s' does not support a sub-selection." % dotted
                )
            else:
                self._resolve(children, node, path + (name,))
