"""
JSON Patch (RFC 6902) support.

Provides `apply_json_patch()`, an entry point that applies a JSON Patch
document to the instance bound to a serializer.  Patch paths are
interpreted against the serializer's *external* field names, exactly as
they appear in `serializer.data`, so `source` mappings, nested
serializers and `read_only` fields are all respected.  Every operation
is validated through the serializer, and `.save()` is only ever called
once every operation has succeeded.
"""

import copy

from django.utils.translation import gettext_lazy as _

from rest_framework import status
from rest_framework.exceptions import APIException
from rest_framework.fields import ListField
from rest_framework.serializers import (
    BaseSerializer, ListSerializer, Serializer
)
from rest_framework.utils.encoders import JSONEncoder
from rest_framework.utils.json import json

__all__ = ['JSONPatchError', 'apply_json_patch']

OPERATIONS = ('add', 'remove', 'replace', 'move', 'copy', 'test')


class JSONPatchError(APIException):
    """
    Raised when a JSON Patch operation cannot be applied.

    Carries the index of the failing operation, the operation's path and
    a validation code, so clients can locate the exact operation that
    failed.  When serializer validation failed, the serializer errors
    are available on `.errors`.
    """
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = _('Invalid JSON patch.')
    default_code = 'invalid'

    def __init__(self, index, path, detail=None, code=None, errors=None):
        self.index = index
        self.path = path
        self.errors = errors
        super().__init__(detail=detail, code=code)


def _parse_pointer(pointer, index):
    """
    Parse an RFC 6901 JSON pointer into a list of reference tokens.
    """
    if pointer == '':
        return []
    if not isinstance(pointer, str) or not pointer.startswith('/'):
        raise JSONPatchError(
            index, pointer,
            detail='Invalid JSON pointer: %r.' % (pointer,),
            code='invalid_pointer',
        )
    return [
        token.replace('~1', '/').replace('~0', '~')
        for token in pointer.split('/')[1:]
    ]


def _parse_list_index(token, index, path, allow_append=False):
    if allow_append and token == '-':
        return '-'
    if not token.isdigit() or (token != '0' and token.startswith('0')):
        raise JSONPatchError(
            index, path,
            detail='Invalid list index: %r.' % (token,),
            code='invalid_index',
        )
    return int(token)


def _resolve_parent(document, tokens, index, path):
    """
    Walk `tokens[:-1]` from the document root, returning `(parent, key)`
    where `key` is the final token.  Raises `JSONPatchError` if any
    intermediate value does not exist.
    """
    current = document
    for token in tokens[:-1]:
        if isinstance(current, list):
            key = _parse_list_index(token, index, path)
            if key >= len(current):
                raise JSONPatchError(
                    index, path,
                    detail='List index %r is out of range.' % (token,),
                    code='does_not_exist',
                )
            current = current[key]
        elif isinstance(current, dict):
            if token not in current:
                raise JSONPatchError(
                    index, path,
                    detail='Object member %r does not exist.' % (token,),
                    code='does_not_exist',
                )
            current = current[token]
        else:
            raise JSONPatchError(
                index, path,
                detail='Cannot traverse into a scalar value.',
                code='does_not_exist',
            )
    if not tokens:
        return None, None
    return current, tokens[-1]


def _get_value(document, tokens, index, path):
    parent, key = _resolve_parent(document, tokens, index, path)
    if parent is None:
        return document
    if isinstance(parent, list):
        position = _parse_list_index(key, index, path)
        if position >= len(parent):
            raise JSONPatchError(
                index, path,
                detail='List index %r is out of range.' % (key,),
                code='does_not_exist',
            )
        return parent[position]
    if isinstance(parent, dict):
        if key not in parent:
            raise JSONPatchError(
                index, path,
                detail='Object member %r does not exist.' % (key,),
                code='does_not_exist',
            )
        return parent[key]
    raise JSONPatchError(
        index, path,
        detail='Cannot traverse into a scalar value.',
        code='does_not_exist',
    )


def _add_value(document, tokens, value, index, path):
    parent, key = _resolve_parent(document, tokens, index, path)
    if parent is None:
        return value
    if isinstance(parent, list):
        position = _parse_list_index(key, index, path, allow_append=True)
        if position == '-':
            parent.append(value)
        elif position > len(parent):
            raise JSONPatchError(
                index, path,
                detail='List index %r is out of range.' % (key,),
                code='does_not_exist',
            )
        else:
            parent.insert(position, value)
    elif isinstance(parent, dict):
        parent[key] = value
    else:
        raise JSONPatchError(
            index, path,
            detail='Cannot add to a scalar value.',
            code='invalid_target',
        )
    return document


def _remove_value(document, tokens, index, path):
    parent, key = _resolve_parent(document, tokens, index, path)
    if parent is None:
        return None, document
    if isinstance(parent, list):
        position = _parse_list_index(key, index, path)
        if position >= len(parent):
            raise JSONPatchError(
                index, path,
                detail='List index %r is out of range.' % (key,),
                code='does_not_exist',
            )
        return parent.pop(position), document
    if isinstance(parent, dict):
        if key not in parent:
            raise JSONPatchError(
                index, path,
                detail='Object member %r does not exist.' % (key,),
                code='does_not_exist',
            )
        return parent.pop(key), document
    raise JSONPatchError(
        index, path,
        detail='Cannot remove from a scalar value.',
        code='invalid_target',
    )


def _child_fields(field):
    """
    Return `(fields, in_list)` for descending into a serializer field,
    where `fields` is the child field mapping or `None` if the field
    cannot be introspected any further.
    """
    if isinstance(field, ListSerializer):
        child = field.child
        return (child.fields if isinstance(child, Serializer) else None), True
    if isinstance(field, Serializer):
        return field.fields, False
    if isinstance(field, ListField):
        child = field.child
        if isinstance(child, BaseSerializer):
            return child.fields, True
        return None, True
    return None, False


def _check_writable(serializer, tokens, index, path):
    """
    Ensure a write operation targeting `tokens` does not bypass
    `read_only` fields, and that each traversed member is a declared
    external field name.  Internal attribute names (eg. `source`
    targets) are not part of the field mapping and are rejected.
    """
    fields = serializer.fields
    in_list = False
    for token in tokens:
        if in_list:
            in_list = False
            continue
        if fields is None:
            return
        field = fields.get(token)
        if field is None:
            raise JSONPatchError(
                index, path,
                detail='Unknown field: %r.' % (token,),
                code='does_not_exist',
            )
        if field.read_only:
            raise JSONPatchError(
                index, path,
                detail='Field %r is read-only.' % (token,),
                code='read_only',
            )
        fields, in_list = _child_fields(field)


def _first_error_code(errors):
    if isinstance(errors, (list, tuple)):
        for item in errors:
            code = _first_error_code(item)
            if code is not None:
                return code
        return None
    if isinstance(errors, dict):
        for value in errors.values():
            code = _first_error_code(value)
            if code is not None:
                return code
        return None
    return getattr(errors, 'code', None)


def _validate_document(serializer, document, index, path):
    """
    Validate the patched document through the serializer, raising
    `JSONPatchError` with the serializer's validation code on failure.
    """
    trial = serializer.__class__(
        instance=serializer.instance, data=document,
        partial=True, context=serializer.context,
    )
    if not trial.is_valid():
        raise JSONPatchError(
            index, path,
            detail='Validation failed for patched document.',
            code=_first_error_code(trial.errors) or 'invalid',
            errors=trial.errors,
        )


def _apply_operation(serializer, document, operation, index):
    if not isinstance(operation, dict):
        raise JSONPatchError(
            index, None,
            detail='Operations must be objects.',
            code='invalid_operation',
        )

    op = operation.get('op')
    path = operation.get('path')
    if op not in OPERATIONS or not isinstance(path, str):
        raise JSONPatchError(
            index, path if isinstance(path, str) else None,
            detail='Operation must include a valid "op" and "path".',
            code='invalid_operation',
        )

    tokens = _parse_pointer(path, index)

    if op == 'test':
        if 'value' not in operation:
            raise JSONPatchError(
                index, path,
                detail='Operation "test" requires a "value" member.',
                code='invalid_operation',
            )
        if _get_value(document, tokens, index, path) != operation['value']:
            raise JSONPatchError(
                index, path,
                detail='Test operation failed.',
                code='test_failed',
            )
        return document

    if op in ('move', 'copy'):
        from_pointer = operation.get('from')
        if not isinstance(from_pointer, str):
            raise JSONPatchError(
                index, path,
                detail='Operation "%s" requires a "from" member.' % op,
                code='invalid_operation',
            )
        from_tokens = _parse_pointer(from_pointer, index)
        is_child = (
            len(tokens) > len(from_tokens)
            and tokens[:len(from_tokens)] == from_tokens
        )
        if op == 'move' and is_child:
            raise JSONPatchError(
                index, path,
                detail='Cannot move a value into one of its children.',
                code='invalid_operation',
            )
        value = _get_value(document, from_tokens, index, from_pointer)
        if op == 'copy':
            value = copy.deepcopy(value)
        _check_writable(serializer, tokens, index, path)
        if op == 'move':
            _, document = _remove_value(
                document, from_tokens, index, from_pointer
            )
        document = _add_value(document, tokens, value, index, path)
        _validate_document(serializer, document, index, path)
        return document

    if op in ('add', 'replace'):
        if 'value' not in operation:
            raise JSONPatchError(
                index, path,
                detail='Operation "%s" requires a "value" member.' % op,
                code='invalid_operation',
            )
        _check_writable(serializer, tokens, index, path)
        if op == 'replace':
            # "replace" requires the target location to exist.
            _get_value(document, tokens, index, path)
            _, document = _remove_value(document, tokens, index, path)
        document = _add_value(
            document, tokens, operation['value'], index, path
        )
        _validate_document(serializer, document, index, path)
        return document

    # op == 'remove'
    _check_writable(serializer, tokens, index, path)
    _, document = _remove_value(document, tokens, index, path)
    _validate_document(serializer, document, index, path)
    return document


def apply_json_patch(serializer, operations):
    """
    Apply an RFC 6902 JSON Patch document to `serializer.instance`.

    `serializer` must be a serializer bound to an existing instance.
    Paths are interpreted against the serializer's external field names.
    Operations are applied sequentially to a detached copy of the
    serialized representation, and each mutation is validated through
    the serializer.  Only when every operation has succeeded is
    `.save()` called, so a failing patch never leaves partial changes
    on the original object.

    Returns the saved instance.  Raises `JSONPatchError` otherwise.
    """
    if not isinstance(serializer, Serializer):
        raise TypeError('apply_json_patch() requires a Serializer instance.')
    if serializer.instance is None:
        raise TypeError('apply_json_patch() requires a bound instance.')
    if not isinstance(operations, list):
        raise JSONPatchError(
            None, None,
            detail='A JSON patch document must be a list of operations.',
            code='invalid_operation',
        )

    # Work on a JSON-normalized deep copy of the representation so that
    # no mutation (including mutations of nested lists) can leak back
    # onto the original object, and so `test` compares plain JSON values.
    document = json.loads(json.dumps(serializer.data, cls=JSONEncoder))

    for index, operation in enumerate(operations):
        document = _apply_operation(serializer, document, operation, index)

    patched = serializer.__class__(
        instance=serializer.instance, data=document,
        partial=True, context=serializer.context,
    )
    patched.is_valid(raise_exception=True)
    return patched.save()
