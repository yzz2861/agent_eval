"""
RFC 6902 JSON Patch support for serializers.
"""
import copy
from collections.abc import Mapping

from rest_framework.exceptions import ValidationError
from rest_framework.fields import DictField, ListField
from rest_framework.serializers import ListSerializer


JSON_PATCH_MEDIA_TYPE = 'application/json-patch+json'


class JsonPatchError(ValidationError):
    default_detail = 'JSON Patch operation failed.'
    default_code = 'invalid_patch'

    def __init__(self, index, operation, code, detail=None, path=None):
        self.index = index
        self.operation = index
        self.op = operation.get('op') if isinstance(operation, Mapping) else None
        self.path = path if path is not None else operation.get('path')
        self.code = code
        self.detail = {
            'index': index,
            'operation': index,
            'op': self.op,
            'path': self.path,
            'code': code,
            'detail': detail or self.default_detail,
        }


class _Location:
    def __init__(self, container, token, field, append=False):
        self.container = container
        self.token = token
        self.field = field
        self.append = append


def is_json_patch_request(request):
    content_type = getattr(request, 'content_type', '') or ''
    return content_type.split(';', 1)[0].strip().lower() == JSON_PATCH_MEDIA_TYPE


def _operation_path(operation):
    return operation.get('path') if isinstance(operation, Mapping) else None


def _error(index, operation, code, detail):
    return JsonPatchError(index, operation, code, detail, path=_operation_path(operation))


def _parse_pointer(pointer, index=-1, operation=None):
    if not isinstance(pointer, str):
        raise JsonPatchError(index, operation or {}, 'invalid',
                             'Patch path must be a string.', path=pointer)
    if pointer == '':
        return []
    if not pointer.startswith('/'):
        raise JsonPatchError(index, operation or {}, 'invalid_pointer',
                             'Patch path must start with a slash.', path=pointer)

    return [
        token.replace('~1', '/').replace('~0', '~')
        for token in pointer[1:].split('/')
    ]


def _array_index(token, length, *, index=-1, operation=None):
    if token == '-':
        code = 'invalid_index'
    elif token.isascii() and token.isdigit() and (token == '0' or not token.startswith('0')):
        value = int(token)
        if value < length:
            return value
        code = 'not_found'
    else:
        code = 'invalid_index'

    raise JsonPatchError(index, operation, code, 'Invalid array index.',
                         path=_operation_path(operation))


def _array_insert_index(token, length, *, index=-1, operation=None):
    if token == '-':
        return length
    if token.isascii() and token.isdigit() and (token == '0' or not token.startswith('0')):
        value = int(token)
        if value <= length:
            return value
    raise JsonPatchError(index, operation, 'invalid_index', 'Invalid array index.',
                         path=_operation_path(operation))


def _resolve(serializer, value, tokens, *, mutable=False, allow_missing=False,
             index=-1, operation=None):
    if not tokens:
        return _Location(None, None, serializer)

    if mutable and getattr(serializer, 'read_only', False) and hasattr(serializer, 'fields'):
        raise _error(index, operation, 'read_only', 'Field is read only.')

    token = tokens[0]
    remaining = tokens[1:]

    if isinstance(value, Mapping) and hasattr(serializer, 'fields'):
        field = serializer.fields.get(token)
        if field is None:
            raise _error(index, operation, 'unknown_field', 'Unknown serializer field.')
        if mutable and field.read_only:
            raise _error(index, operation, 'read_only', 'Field is read only.')
        if token not in value:
            if allow_missing and not remaining:
                return _Location(value, token, field)
            raise _error(index, operation, 'not_found', 'Patch target does not exist.')
        if not remaining:
            return _Location(value, token, field)

        return _resolve_field(
            field, value[token], remaining, mutable=mutable,
            allow_missing=allow_missing, index=index, operation=operation,
        )

    if isinstance(value, list) and hasattr(serializer, 'child'):
        if mutable and getattr(serializer, 'read_only', False):
            raise _error(index, operation, 'read_only', 'Field is read only.')
        if allow_missing and not remaining:
            array_index = _array_insert_index(token, len(value), index=index, operation=operation)
            return _Location(value, array_index, serializer.child,
                             append=array_index == len(value))
        array_index = _array_index(token, len(value), index=index, operation=operation)
        if not remaining:
            return _Location(value, array_index, serializer.child)
        return _resolve_field(
            serializer.child, value[array_index], remaining, mutable=mutable,
            allow_missing=allow_missing, index=index, operation=operation,
        )

    if isinstance(value, Mapping) and hasattr(serializer, 'child'):
        if mutable and getattr(serializer, 'read_only', False):
            raise _error(index, operation, 'read_only', 'Field is read only.')
        if token not in value:
            if allow_missing and not remaining:
                return _Location(value, token, serializer.child)
            raise _error(index, operation, 'not_found', 'Patch target does not exist.')
        if not remaining:
            return _Location(value, token, serializer.child)
        return _resolve_field(
            serializer.child, value[token], remaining, mutable=mutable,
            allow_missing=allow_missing, index=index, operation=operation,
        )

    if isinstance(value, Mapping):
        if token not in value:
            if allow_missing and not remaining:
                return _Location(value, token, None)
            raise _error(index, operation, 'not_found', 'Patch target does not exist.')
        if not remaining:
            return _Location(value, token, None)
        value = value[token]
    elif isinstance(value, list):
        if allow_missing and not remaining:
            array_index = _array_insert_index(token, len(value), index=index, operation=operation)
            return _Location(value, array_index, None, append=array_index == len(value))
        array_index = _array_index(token, len(value), index=index, operation=operation)
        if not remaining:
            return _Location(value, array_index, None)
        value = value[array_index]
    else:
        raise _error(index, operation, 'invalid_path', 'Cannot traverse a scalar value.')

    return _resolve(None, value, remaining, mutable=mutable,
                    allow_missing=allow_missing, index=index, operation=operation)


def _resolve_field(field, value, tokens, **kwargs):
    if not tokens:
        return _Location(None, None, field)

    if hasattr(field, 'fields'):
        return _resolve(field, value, tokens, **kwargs)
    if hasattr(field, 'child') and isinstance(value, (Mapping, list)):
        return _resolve(field, value, tokens, **kwargs)
    if isinstance(field, ListField) and isinstance(value, list):
        return _resolve(field, value, tokens, **kwargs)
    if isinstance(field, DictField) and isinstance(value, Mapping):
        return _resolve(field, value, tokens, **kwargs)
    if isinstance(value, (Mapping, list)):
        return _resolve(None, value, tokens, **kwargs)
    raise _error(kwargs['index'], kwargs['operation'], 'invalid_path',
                 'Cannot traverse a scalar value.')


def _normalized_operations(patch):
    operations = []
    for index, operation in enumerate(patch):
        if not isinstance(operation, Mapping):
            raise JsonPatchError(index, {}, 'invalid_operation',
                                 'Patch operation must be an object.')

        op_name = operation.get('op')
        if op_name not in {'add', 'remove', 'replace', 'move', 'copy', 'test'}:
            raise JsonPatchError(index, operation, 'invalid_operation',
                                 'Unsupported patch operation.')
        if not isinstance(operation.get('path'), str):
            raise JsonPatchError(index, operation, 'invalid_path',
                                 'Patch path must be a string.')
        if op_name in {'move', 'copy'} and not isinstance(operation.get('from'), str):
            raise JsonPatchError(index, operation, 'invalid_from',
                                 'Patch from path must be a string.')
        if op_name in {'add', 'replace', 'test'} and 'value' not in operation:
            raise JsonPatchError(index, operation, 'missing_value',
                                 'Patch operation requires a value.')

        normalized = dict(operation)
        normalized['index'] = index
        normalized['path_tokens'] = _parse_pointer(operation['path'], index, operation)
        if 'from' in operation:
            normalized['from_tokens'] = _parse_pointer(operation['from'], index, operation)
        operations.append(normalized)

    return operations


def _serializer_for_instance(serializer, instance, document, *, partial=True):
    if isinstance(serializer, ListSerializer):
        return serializer.__class__(
            instance=instance,
            data=document,
            partial=partial,
            context=serializer._context,
            child=copy.deepcopy(serializer.child),
            allow_empty=serializer.allow_empty,
            max_length=serializer.max_length,
            min_length=serializer.min_length,
        )
    return serializer.__class__(
        instance,
        data=document,
        partial=partial,
        context=serializer._context,
    )


def _first_error_code(detail):
    if isinstance(detail, Mapping):
        for value in detail.values():
            code = _first_error_code(value)
            if code is not None:
                return code
    elif isinstance(detail, (list, tuple)):
        for value in detail:
            code = _first_error_code(value)
            if code is not None:
                return code
    else:
        return getattr(detail, 'code', None) or 'invalid'
    return 'invalid'


def _error_code_for_path(detail, tokens):
    current = detail
    for token in tokens:
        if not isinstance(current, Mapping) or token not in current:
            break
        current = current[token]
    else:
        return _first_error_code(current)
    return _first_error_code(detail)


def _validate_document(serializer, document, index, operation):
    candidate = _serializer_for_instance(serializer, serializer.instance, document)
    if not candidate.is_valid():
        code = _error_code_for_path(candidate.errors, operation['path_tokens'])
        raise _error(index, operation, code, 'Patch operation failed validation.')
    return candidate


def _validate_final_document(serializer, document, operation):
    candidate = _serializer_for_instance(serializer, serializer.instance, document, partial=False)
    if not candidate.is_valid():
        tokens = operation['path_tokens']
        code = _error_code_for_path(candidate.errors, tokens)
        raise _error(
            _operation_index(operation), operation, code,
            'JSON Patch failed final validation.',
        )
    return candidate


def _operation_index(operation):
    return operation.get('index', -1)


def _exists(location):
    if location.container is None:
        return True
    if isinstance(location.container, list):
        return not location.append and 0 <= location.token < len(location.container)
    return location.token in location.container


def _json_equal(left, right):
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is type(right) and left == right
    if isinstance(left, Mapping) or isinstance(right, Mapping):
        return (
            isinstance(left, Mapping) and isinstance(right, Mapping)
            and set(left.keys()) == set(right.keys())
            and all(_json_equal(left[key], right[key]) for key in left)
        )
    if isinstance(left, (list, tuple)) or isinstance(right, (list, tuple)):
        return (
            isinstance(left, (list, tuple)) and isinstance(right, (list, tuple))
            and len(left) == len(right)
            and all(
                _json_equal(left_item, right_item)
                for left_item, right_item in zip(left, right)
            )
        )
    return (
        not isinstance(left, bool) and not isinstance(right, bool)
        and left == right
    )


def _set_value(document, location, value):
    if location.container is None:
        return value
    if location.append:
        location.container.insert(location.token, value)
    else:
        location.container[location.token] = value
    return document


def _delete_value(document, location):
    if location.container is None:
        raise JsonPatchError(-1, {}, 'invalid_path',
                             'The root value cannot be removed.', path='')
    if isinstance(location.container, list):
        del location.container[location.token]
    else:
        del location.container[location.token]
    return document


def _normalize_apply(serializer, patch):
    if not isinstance(patch, list):
        raise ValidationError('JSON Patch must be a list of operations.',
                              code='not_a_list')

    operations = _normalized_operations(patch)
    representation = serializer.to_representation(serializer.instance)
    document = copy.deepcopy(representation)
    mutated = False

    for index, operation in enumerate(operations):
        op_name = operation['op']
        path_tokens = operation['path_tokens']

        if op_name == 'test':
            location = _resolve(serializer, document, path_tokens,
                                index=index, operation=operation)
            actual = document if location.container is None else location.container[location.token]
            if not _json_equal(actual, operation['value']):
                raise _error(index, operation, 'test_failed', 'Test operation failed.')
            continue

        if op_name in {'add', 'replace'}:
            allow_missing = op_name == 'add'
            location = _resolve(
                serializer, document, path_tokens, mutable=True,
                allow_missing=allow_missing, index=index, operation=operation,
            )
            if op_name == 'replace' and not _exists(location):
                raise _error(index, operation, 'not_found', 'Patch target does not exist.')
            document = _set_value(document, location, copy.deepcopy(operation['value']))

        elif op_name == 'remove':
            location = _resolve(serializer, document, path_tokens, mutable=True,
                                index=index, operation=operation)
            document = _delete_value(document, location)

        elif op_name in {'move', 'copy'}:
            from_tokens = operation['from_tokens']
            if (
                op_name == 'move' and from_tokens
                and path_tokens[:len(from_tokens)] == from_tokens
            ):
                raise _error(index, operation, 'invalid_patch',
                             'Cannot move a value into its own child.')

            source = _resolve(
                serializer, document, from_tokens, mutable=op_name == 'move',
                index=index, operation=operation,
            )
            value = document if source.container is None else source.container[source.token]
            if op_name == 'move':
                document = _delete_value(document, source)
            value = copy.deepcopy(value)

            target = _resolve(
                serializer, document, path_tokens, mutable=True,
                allow_missing=True, index=index, operation=operation,
            )
            document = _set_value(document, target, value)

        mutated = True
        _validate_document(serializer, document, index, operation)

    final_operation = next((op for op in reversed(operations) if op['op'] != 'test'), None)
    if final_operation is None:
        final_serializer = _serializer_for_instance(
            serializer, serializer.instance, document, partial=False,
        )
        final_serializer.is_valid(raise_exception=True)
    else:
        final_serializer = _validate_final_document(serializer, document, final_operation)
    final_serializer._data = document
    return final_serializer, mutated


def apply_json_patch(serializer, patch, *, save=False, **save_kwargs):
    """
    Apply an RFC 6902 patch through a serializer's public field schema.
    """
    patched_serializer, _ = _normalize_apply(serializer, patch)
    if save:
        patched_serializer = _serializer_for_instance(
            serializer, serializer.instance, patched_serializer.initial_data, partial=False,
        )
        patched_serializer.is_valid(raise_exception=True)
        patched_serializer.save(**save_kwargs)
    return patched_serializer
