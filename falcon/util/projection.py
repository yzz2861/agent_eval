"""Allowlist-based response field projection utilities.

This module implements an optional helper that lets clients select a
subset of fields to include in a response, using a limited expression
syntax such as::

    ?fields=name,orders(id,total)

The fields that may be projected are declared up front by the app as a
field tree, so that allowing a parent field does not automatically
expose all of its children.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

__all__ = ('FieldSelector',)


# Sentinel marking a field that was selected as a whole, i.e. all of its
# allowed descendants are projected.
_ALL = object()


class FieldSelector:
    """Declarative allowlist for projecting response fields.

    A ``FieldSelector`` is initialized with a tree of fields that are
    allowed to be projected, and can then parse a ``fields`` expression
    (such as ``name,orders(id,total)``) supplied by the client, validate
    it against the allowlist, and project a document accordingly.

    The expression syntax is intentionally limited; it is neither
    evaluated as code nor treated as a general-purpose query language:

    *   A bare field name selects that field. When the field has
        allowed children, all of them (and only them) are selected
        recursively.
    *   ``field(child,...)`` selects specific children of a field.
        Nested objects and items of object arrays are projected using
        the same subtree.
    *   Selections are separated by commas; duplicates are merged.

    Unknown fields, conflicting selections (a field selected both as a
    whole and with a nested selection), malformed expressions, and
    expressions nested deeper than *max_depth* are rejected by
    :meth:`~FieldSelector.parse` with a `400 Bad Request` error, before
    any business logic needs to run.

    Projection never modifies the source document; a new structure is
    returned so that documents that are cached or shared between
    requests keep all of their original fields. Because the projected
    copy is what gets assigned to ``resp.media``, the response
    ``Content-Length`` and any representation validators (such as
    ``ETag``) computed from the outgoing document are based on the data
    that is actually sent.

    Example::

        import falcon


        class OrderResource:
            _fields = falcon.FieldSelector({
                'number': None,
                'customer': {'name': None},
                'lines': {'sku': None, 'quantity': None},
            })

            def on_get(self, req, resp):
                # Raises HTTPBadRequest for invalid expressions, before
                # any business logic is executed.
                selection = self._fields.parse(req.get_param('fields'))

                order = get_order()  # May be cached/shared.

                resp.media = self._fields.project(order, selection)

    Args:
        fields (Mapping): Allowlist of fields that may be projected,
            declared as a mapping of field names. Each name maps either
            to ``None`` (a leaf field) or to a nested mapping declaring
            the children that may be projected.
        max_depth (int): Maximum nesting depth allowed in a ``fields``
            expression (default ``8``). Deeper expressions are rejected.
        param_name (str): Name of the query parameter carrying the
            expression, used in error descriptions (default
            ``'fields'``).
    """

    __slots__ = ('_fields', '_max_depth', '_param_name')

    def __init__(
        self,
        fields: Mapping[str, Any],
        max_depth: int = 8,
        param_name: str = 'fields',
    ) -> None:
        self._fields = _validate_fields(fields)
        self._max_depth = max_depth
        self._param_name = param_name

    def parse(self, expression: str | None) -> dict[str, Any] | None:
        """Parse and validate a ``fields`` expression.

        Args:
            expression (str): The expression to parse, as obtained, for
                example, from ``req.get_param('fields')``. ``None`` and
                blank expressions are treated as "no projection
                requested".

        Returns:
            dict: A resolved selection tree suitable for
                :meth:`~FieldSelector.project`, or ``None`` when no
                projection was requested.

        Raises:
            HTTPInvalidParam: The expression is malformed, selects an
                unknown field, contains conflicting selections, or
                exceeds the maximum nesting depth.
        """
        if expression is None:
            return None

        expression = expression.strip()
        if not expression:
            return None

        parser = _ExpressionParser(self, expression)
        return _resolve(parser.parse(), self._fields)

    def project(self, data: Any, selection: dict[str, Any] | None) -> Any:
        """Return a copy of *data* projected according to *selection*.

        The source object is never modified; nested mappings and
        sequences that survive the projection are copied, so documents
        that are cached or shared between requests are left intact.

        Args:
            data: The document to project. Mappings are projected key
                by key; items of lists and tuples are projected with
                the same subtree; any other value is returned as-is.
            selection (dict): A selection tree as returned by
                :meth:`~FieldSelector.parse`. When ``None``, *data* is
                returned unchanged.

        Returns:
            The projected document.
        """
        if selection is None:
            return data

        return _project(data, selection)


class _ExpressionParser:
    """Recursive descent parser for the limited fields syntax."""

    __slots__ = ('_length', '_pos', '_selector', '_text')

    def __init__(self, selector: FieldSelector, expression: str) -> None:
        self._selector = selector
        self._text = expression
        self._pos = 0
        self._length = len(expression)

    def parse(self) -> dict[str, Any]:
        tree = self._parse_fields(self._selector._fields, (), 1)
        if self._pos != self._length:
            self._error('unexpected character %r' % self._text[self._pos])
        return tree

    def _error(self, message: str) -> None:
        # Imported here to avoid a circular import at package load time.
        from falcon.errors import HTTPInvalidParam

        raise HTTPInvalidParam(
            'Invalid fields expression: %s.' % message,
            self._selector._param_name,
        )

    def _skip_whitespace(self) -> None:
        text = self._text
        while self._pos < self._length and text[self._pos].isspace():
            self._pos += 1

    def _parse_name(self) -> str:
        text = self._text
        start = self._pos
        while self._pos < self._length:
            char = text[self._pos]
            if char in ',()' or char.isspace():
                break
            self._pos += 1

        name = text[start : self._pos]
        if not name:
            self._error('expected a field name')
        return name

    def _parse_fields(
        self, spec: Mapping[str, Any], path: tuple[str, ...], depth: int
    ) -> dict[str, Any]:
        if depth > self._selector._max_depth:
            self._error(
                'the expression exceeds the maximum nesting depth of %d'
                % self._selector._max_depth
            )

        tree: dict[str, Any] = {}
        while True:
            self._skip_whitespace()
            name = self._parse_name()
            self._skip_whitespace()

            field_path = path + (name,)
            if name not in spec:
                self._error('unknown field %r' % '.'.join(field_path))

            child_spec = spec[name]
            if self._pos < self._length and self._text[self._pos] == '(':
                if child_spec is None:
                    self._error(
                        'field %r does not support nested selection'
                        % '.'.join(field_path)
                    )
                self._pos += 1
                node = self._parse_fields(child_spec, field_path, depth + 1)
                self._skip_whitespace()
                if self._pos == self._length or self._text[self._pos] != ')':
                    self._error(
                        'unbalanced parenthesis after field %r' % '.'.join(field_path)
                    )
                self._pos += 1
            elif child_spec is None:
                node = None
            else:
                node = _ALL

            if name in tree:
                tree[name] = self._merge(tree[name], node, field_path)
            else:
                tree[name] = node

            self._skip_whitespace()
            if self._pos == self._length or self._text[self._pos] != ',':
                break
            self._pos += 1

        return tree

    def _merge(self, existing: Any, node: Any, path: tuple[str, ...]) -> Any:
        if existing is None:
            # A leaf field selected again can only yield another leaf
            # node, so duplicate leaf selections simply merge.
            return None

        if existing is _ALL or node is _ALL:
            if existing is not node:
                self._error('conflicting selections for field %r' % '.'.join(path))
            return _ALL

        for child_name, child_node in node.items():
            child_path = path + (child_name,)
            if child_name in existing:
                existing[child_name] = self._merge(
                    existing[child_name], child_node, child_path
                )
            else:
                existing[child_name] = child_node

        return existing


def _validate_fields(fields: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(fields, Mapping):
        raise TypeError('fields must be a mapping of field names to child field specs')

    normalized = {}
    for name, spec in fields.items():
        if spec is None:
            normalized[name] = None
        elif isinstance(spec, Mapping):
            normalized[name] = _validate_fields(spec)
        else:
            raise ValueError(
                'field spec for %r must be None or a mapping of child '
                'field specs' % (name,)
            )

    return normalized


def _resolve(tree: dict[str, Any], spec: Mapping[str, Any]) -> dict[str, Any]:
    resolved = {}
    for name, node in tree.items():
        if node is None:
            resolved[name] = None
        elif node is _ALL:
            resolved[name] = _expand(spec[name])
        else:
            resolved[name] = _resolve(node, spec[name])

    return resolved


def _expand(spec: Mapping[str, Any]) -> dict[str, Any]:
    return {
        name: None if child is None else _expand(child) for name, child in spec.items()
    }


def _project(value: Any, tree: dict[str, Any] | None) -> Any:
    if tree is None:
        return value

    if isinstance(value, Mapping):
        return {
            name: _project(value[name], subtree)
            for name, subtree in tree.items()
            if name in value
        }

    if isinstance(value, (list, tuple)):
        return [_project(item, tree) for item in value]

    return value
