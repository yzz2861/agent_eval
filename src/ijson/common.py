'''
Backend independent higher level interfaces, common exceptions.
'''
import decimal
import inspect
import io
import warnings

from ijson import compat, utils, utils35
from ijson.duplicates import (
    DuplicateKeyPolicy,
    DuplicateKeys,
    DuplicateKeyStrategy,
    EventPosition,
    join_path,
    normalize_duplicate_keys,
)


_DUPLICATE_KEY_ALIASES = (
    'duplicate_key_policy',
    'duplicate_key_strategy',
    'on_duplicate_keys',
)


def _resolve_duplicate_keys(duplicate_keys, config):
    '''Resolve the canonical option plus accepted aliases from a config dict.'''
    aliases = []
    for name in _DUPLICATE_KEY_ALIASES:
        if name in config:
            aliases.append(config.pop(name))
    for value in aliases:
        if value is None:
            continue
        if duplicate_keys is not None:
            current = normalize_duplicate_keys(duplicate_keys)
            if current != normalize_duplicate_keys(value):
                raise ValueError(
                    'conflicting duplicate-key policy options: %r and %r'
                    % (duplicate_keys, value)
                )
        duplicate_keys = value
    return normalize_duplicate_keys(duplicate_keys)


class JSONError(Exception):
    '''
    Base exception for all parsing errors.
    '''
    pass


class IncompleteJSONError(JSONError):
    '''
    Raised when the parser can't read expected data from a stream.
    '''
    pass


class DuplicateKeyError(JSONError):
    '''
    Raised by ``items``/``kvitems`` when ``duplicate_keys='reject'`` finds the
    same key twice in one JSON object.

    ``path`` is the full dotted path to the duplicated key (including the key
    itself), ``map_path`` is the path to the containing object, and
    ``first_position``/``second_position`` identify the event-stream positions
    where the two values first appeared.  Position objects also compare equal
    to their zero-based event index for convenience.
    '''
    def __init__(self, key, path, map_path, first_position, second_position,
                 first_key_position=None, second_key_position=None):
        self.key = key
        self.path = path
        self.map_path = map_path
        self.first_position = first_position
        self.second_position = second_position
        self.first_key_position = first_key_position
        self.second_key_position = second_key_position
        self.first = first_position
        self.second = second_position
        self.first_value_position = first_position
        self.second_value_position = second_position
        self.first_occurrence = first_position
        self.second_occurrence = second_position
        self.first_index = getattr(first_position, 'index', first_position)
        self.second_index = getattr(second_position, 'index', second_position)
        self.duplicate_key = key
        self.positions = (first_position, second_position)
        message = (
            "Duplicate key %r at path %r (map path %r): "
            "first value at event %s, second value at event %s" % (
                key, path, map_path,
                getattr(first_position, 'index', first_position),
                getattr(second_position, 'index', second_position),
            )
        )
        super(DuplicateKeyError, self).__init__(message)


@utils.coroutine
def parse_basecoro(target):
    '''
    A coroutine dispatching parsing events with the information about their
    location with the JSON object tree. Events are tuples
    ``(prefix, type, value)``.

    Available types and values are:

    ('null', None)
    ('boolean', <True or False>)
    ('number', <int or Decimal>)
    ('string', <unicode>)
    ('map_key', <str>)
    ('start_map', None)
    ('end_map', None)
    ('start_array', None)
    ('end_array', None)

    Prefixes represent the path to the nested elements from the root of the JSON
    document. For example, given this document::

        {
          "array": [1, 2],
          "map": {
            "key": "value"
          }
        }

    the parser would yield events:

      ('', 'start_map', None)
      ('', 'map_key', 'array')
      ('array', 'start_array', None)
      ('array.item', 'number', 1)
      ('array.item', 'number', 2)
      ('array', 'end_array', None)
      ('', 'map_key', 'map')
      ('map', 'start_map', None)
      ('map', 'map_key', 'key')
      ('map.key', 'string', u'value')
      ('map', 'end_map', None)
      ('', 'end_map', None)

    '''
    path = []
    while True:
        event, value = yield
        if event == 'map_key':
            prefix = '.'.join(path[:-1])
            path[-1] = value
        elif event == 'start_map':
            prefix = '.'.join(path)
            path.append(None)
        elif event == 'end_map':
            path.pop()
            prefix = '.'.join(path)
        elif event == 'start_array':
            prefix = '.'.join(path)
            path.append('item')
        elif event == 'end_array':
            path.pop()
            prefix = '.'.join(path)
        else: # any scalar value
            prefix = '.'.join(path)
        target.send((prefix, event, value))


class _BuilderFrame:
    __slots__ = (
        'kind', 'path', 'container', 'seen', 'key', 'value_path', 'entry',
        'pending_duplicate'
    )

    def __init__(self, kind, path, container, track_duplicates=False):
        self.kind = kind
        self.path = path
        self.container = container
        self.seen = {} if kind == 'map' and track_duplicates else None
        self.key = None
        self.value_path = None
        self.entry = None
        self.pending_duplicate = None


class ObjectBuilder:
    '''
    Incrementally builds an object from JSON parser events. Events are passed
    into the `event` function that accepts two parameters: event type and
    value. The object being built is available at any time from the `value`
    attribute.

    Example::

        >>> from io import BytesIO
        >>> from ijson import basic_parse
        >>> from ijson.common import ObjectBuilder

        >>> builder = ObjectBuilder()
        >>> f = BytesIO(b'{"key": "value"}')
        >>> for event, value in basic_parse(f):
        ...     builder.event(event, value)
        >>> builder.value == {'key': 'value'}
        True

    '''
    def __init__(self, map_type=None, duplicate_keys=None, path=''):
        self.value = None
        self.containers = []
        self.map_type = map_type or dict
        self.duplicate_keys = normalize_duplicate_keys(duplicate_keys)
        self.path = path
        self.key = None
        self._frames = []
        self._skip_depth = None
        self._event_index = 0

    def _make_position(self, index, path, key, event):
        return EventPosition(index, path, key, event)

    def _current_value_path(self):
        if not self._frames:
            return self.path
        frame = self._frames[-1]
        if frame.kind == 'array':
            return join_path(frame.path, 'item')
        return frame.value_path

    def _add(self, value):
        # Storing the in-progress containers themselves (rather than setter
        # closures, which would reference back to self and create reference
        # cycles) keeps the builder collectable by plain refcounting
        if not self.containers:
            self.value = value
        else:
            top = self.containers[-1]
            if isinstance(top, list):
                top.append(value)
            else:
                top[self.key] = value

    def _record_value_position(self, position):
        frame = self._frames[-1] if self._frames else None
        if frame is None or frame.kind != 'map' or frame.entry is None:
            return
        if frame.entry['value_position'] is None:
            frame.entry['value_position'] = position

    def _handle_skipped_value(self, event):
        if self._skip_depth is None:
            return False
        if event in ('start_map', 'start_array'):
            self._skip_depth += 1
        elif event in ('end_map', 'end_array'):
            self._skip_depth -= 1
            if self._skip_depth <= 0:
                self._skip_depth = None
        elif event == 'map_key':
            if self._skip_depth == 0:
                # Malformed/user-supplied event stream with a key but no value.
                self._skip_depth = None
                return False
        elif self._skip_depth == 0:
            self._skip_depth = None
        return True

    def _raise_duplicate(self, frame, entry, second_position, second_event):
        first_position = entry['value_position'] or entry['key_position']
        key = entry['key']
        if second_position is None:
            second_position = frame.pending_duplicate['key_position']
        second = self._make_position(
            second_position, frame.value_path, key, second_event
        )
        raise DuplicateKeyError(
            key=key,
            path=frame.value_path,
            map_path=frame.path,
            first_position=first_position,
            second_position=second,
            first_key_position=entry['key_position'],
            second_key_position=frame.pending_duplicate['key_position'],
        )

    def event(self, event, value, position=None):
        if position is None:
            position = self._event_index
        self._event_index += 1

        if self._handle_skipped_value(event):
            return

        if event == 'map_key':
            frame = self._frames[-1] if self._frames else None
            if frame is not None and frame.kind == 'map':
                key = value
                if frame.seen is None:
                    frame.value_path = join_path(frame.path, key)
                    self.key = key
                    return
                value_path = join_path(frame.path, key)
                frame.value_path = value_path
                entry = frame.seen.get(key)
                if entry is None:
                    entry = {
                        'key': key,
                        'key_position': self._make_position(
                            position, value_path, key, event
                        ),
                        'value_position': None,
                    }
                    frame.seen[key] = entry
                    frame.entry = entry
                else:
                    frame.entry = entry
                    if self.duplicate_keys == DuplicateKeyPolicy.REJECT:
                        second_key_position = self._make_position(
                            position, value_path, key, event
                        )
                        frame.pending_duplicate = {
                            'key_position': second_key_position,
                        }
                        self.key = key
                        return
                    if self.duplicate_keys == DuplicateKeyPolicy.FIRST:
                        self._skip_depth = 0
                        self.key = key
                        return
                # LAST (and the legacy default) lets the assignment happen;
                # assigning to an existing dict key does not move its position.
                self.key = key
                return
            self.key = value
        elif event == 'start_map':
            if self._frames and self._frames[-1].pending_duplicate is not None:
                self._raise_duplicate(
                    self._frames[-1], self._frames[-1].entry,
                    position, event
                )
            value_path = self._current_value_path()
            self._record_value_position(
                self._make_position(position, value_path, self.key, event)
            )
            mappable = self.map_type()
            self._add(mappable)
            self.containers.append(mappable)
            self._frames.append(_BuilderFrame(
                'map', value_path, mappable,
                track_duplicates=self.duplicate_keys is not None
            ))
        elif event == 'start_array':
            if self._frames and self._frames[-1].pending_duplicate is not None:
                self._raise_duplicate(
                    self._frames[-1], self._frames[-1].entry,
                    position, event
                )
            value_path = self._current_value_path()
            self._record_value_position(
                self._make_position(position, value_path, self.key, event)
            )
            array = []
            self._add(array)
            self.containers.append(array)
            self._frames.append(_BuilderFrame('array', value_path, array))
        elif event == 'end_array' or event == 'end_map':
            if self._frames:
                frame = self._frames[-1]
                if frame.kind == 'map' and frame.pending_duplicate is not None:
                    self._raise_duplicate(
                        frame, frame.entry, None, event
                    )
            self.containers.pop()
            self._frames.pop()
        else:
            if self._frames and self._frames[-1].pending_duplicate is not None:
                self._raise_duplicate(
                    self._frames[-1], self._frames[-1].entry,
                    position, event
                )
            value_path = self._current_value_path()
            self._record_value_position(
                self._make_position(position, value_path, self.key, event)
            )
            self._add(value)


@utils.coroutine
def items_basecoro(target, prefix, map_type=None, duplicate_keys=None):
    '''
    An couroutine dispatching native Python objects constructed from the events
    under a given prefix.
    '''
    event_index = 0
    while True:
        current, event, value = (yield)
        position = event_index
        event_index += 1
        if current == prefix:
            if event in ('start_map', 'start_array'):
                object_depth = 1
                builder = ObjectBuilder(
                    map_type=map_type, duplicate_keys=duplicate_keys,
                    path=prefix
                )
                while object_depth:
                    builder.event(event, value, position)
                    current, event, value = (yield)
                    position = event_index
                    event_index += 1
                    if event in ('start_map', 'start_array'):
                        object_depth += 1
                    elif event in ('end_map', 'end_array'):
                        object_depth -= 1
                target.send(builder.value)
            else:
                target.send(value)


@utils.coroutine
def kvitems_basecoro(target, prefix, map_type=None, duplicate_keys=None):
    '''
    An coroutine dispatching (key, value) pairs constructed from the events
    under a given prefix. The prefix should point to JSON objects
    '''
    policy = normalize_duplicate_keys(duplicate_keys)
    event_index = 0
    outer_seen = None
    pending_pairs = None
    while True:
        path, event, value = (yield)
        position = event_index
        event_index += 1
        if path == prefix:
            if event == 'start_map':
                outer_seen = {}
                pending_pairs = {} if policy == DuplicateKeyPolicy.LAST else None
            elif event == 'end_map':
                if pending_pairs is not None:
                    for pending_key, pending_value in pending_pairs.items():
                        target.send((pending_key, pending_value))
                    pending_pairs = None
                outer_seen = None
        while path == prefix and event == 'map_key':
            object_depth = 0
            key = value
            if outer_seen is None:
                outer_seen = {}
            if policy == DuplicateKeyPolicy.LAST and pending_pairs is None:
                pending_pairs = {}
            key_path = join_path(prefix, key)
            outer_entry = outer_seen.get(key)
            duplicate = outer_entry is not None
            if not duplicate:
                outer_entry = {
                    'key_position': EventPosition(
                        position, key_path, key, event
                    ),
                    'value_position': None,
                }
                outer_seen[key] = outer_entry
            builder = ObjectBuilder(
                map_type=map_type, duplicate_keys=duplicate_keys,
                path=key_path
            )
            second_key_position = EventPosition(
                position, key_path, key, event
            ) if duplicate else None
            path, event, value = (yield)
            position = event_index
            event_index += 1
            if duplicate and policy == DuplicateKeyPolicy.REJECT:
                first_position = (
                    outer_entry['value_position']
                    or outer_entry['key_position']
                )
                raise DuplicateKeyError(
                    key=key,
                    path=key_path,
                    map_path=prefix,
                    first_position=first_position,
                    second_position=EventPosition(
                        position, key_path, key, event
                    ),
                    first_key_position=outer_entry['key_position'],
                    second_key_position=second_key_position,
                )
            if not duplicate or outer_entry['value_position'] is None:
                outer_entry['value_position'] = EventPosition(
                    position, key_path, key, event
                )
            if event == 'start_map':
                object_depth += 1
            while (
                (event != 'map_key' or object_depth != 0) and
                (event != 'end_map' or object_depth != -1)):
                builder.event(event, value, position)
                path, event, value = (yield)
                position = event_index
                event_index += 1
                if event == 'start_map':
                    object_depth += 1
                elif event == 'end_map':
                    object_depth -= 1
            if duplicate and policy == DuplicateKeyPolicy.FIRST:
                pass
            elif policy == DuplicateKeyPolicy.LAST:
                pending_pairs[key] = builder.value
            else:
                target.send((key, builder.value))
            if (pending_pairs is not None and event == 'end_map' and
                    object_depth == -1):
                for pending_key, pending_value in pending_pairs.items():
                    target.send((pending_key, pending_value))
                pending_pairs = None
                outer_seen = None


def integer_or_decimal(str_value):
    '''
    Converts string with a numeric value into an int or a Decimal.
    Used in different backends for consistent number representation.
    '''
    if not ('.' in str_value or 'e' in str_value or 'E' in str_value):
        return int(str_value)
    return decimal.Decimal(str_value)

def integer_or_float(str_value):
    '''
    Converts string with a numeric value into an int or a float.
    Used in different backends for consistent number representation.
    '''
    if not ('.' in str_value or 'e' in str_value or 'E' in str_value):
        return int(str_value)
    return float(str_value)

def number(str_value):
    warnings.warn("number() function will be removed in a later release", DeprecationWarning)
    return integer_or_decimal(str_value)

def file_source(f, buf_size=64*1024):
    '''A generator that yields data from a file-like object'''
    f = compat.bytes_reader(f)
    while True:
        data = f.read(buf_size)
        yield data
        if not data:
            break


def _basic_parse_pipeline(backend, config):
    _resolve_duplicate_keys(None, config)
    return (
        (backend['basic_parse_basecoro'], [], config),
    )


def _parse_pipeline(backend, config):
    _resolve_duplicate_keys(None, config)
    return (
        (backend['parse_basecoro'], [], {}),
        (backend['basic_parse_basecoro'], [], config)
    )


def _items_pipeline(backend, prefix, map_type, config, duplicate_keys=None):
    duplicate_keys = _resolve_duplicate_keys(duplicate_keys, config)
    kwargs = {'map_type': map_type}
    if duplicate_keys is not None:
        kwargs['duplicate_keys'] = duplicate_keys
    return (
        (backend['items_basecoro'], (prefix,), kwargs),
        (backend['parse_basecoro'], [], {}),
        (backend['basic_parse_basecoro'], [], config)
    )


def _kvitems_pipeline(backend, prefix, map_type, config, duplicate_keys=None):
    duplicate_keys = _resolve_duplicate_keys(duplicate_keys, config)
    kwargs = {'map_type': map_type}
    if duplicate_keys is not None:
        kwargs['duplicate_keys'] = duplicate_keys
    return (
        (backend['kvitems_basecoro'], (prefix,), kwargs),
        (backend['parse_basecoro'], [], {}),
        (backend['basic_parse_basecoro'], [], config)
    )


def _make_basic_parse_coro(backend):
    def basic_parse_coro(target, duplicate_keys=None, **config):
        return utils.chain(
            target,
            *_basic_parse_pipeline(backend, config)
        )
    return basic_parse_coro


def _make_parse_coro(backend):
    def parse_coro(target, duplicate_keys=None, **config):
        return utils.chain(
            target,
            *_parse_pipeline(backend, config)
        )
    return parse_coro


def _make_items_coro(backend):
    def items_coro(target, prefix, map_type=None, duplicate_keys=None, **config):
        return utils.chain(
            target,
            *_items_pipeline(backend, prefix, map_type, config, duplicate_keys)
        )
    return items_coro


def _make_kvitems_coro(backend):
    def kvitems_coro(target, prefix, map_type=None, duplicate_keys=None, **config):
        return utils.chain(
            target,
            *_kvitems_pipeline(backend, prefix, map_type, config, duplicate_keys)
        )
    return kvitems_coro


def is_awaitablefunction(func):
    """True if `func` is an awaitable function"""
    return (
        inspect.iscoroutinefunction(func) or (
          inspect.isgeneratorfunction(func) and
          (func.__code__.co_flags & inspect.CO_ITERABLE_COROUTINE)
        )
    )

def is_async_file(f):
    """True if `f` has an asynchronous `read` method"""
    return (
        hasattr(f, 'read') and
        is_awaitablefunction(f.read)
    )

def is_file(x):
    """True if x has a `read` method"""
    return hasattr(x, 'read')


def is_iterable(x):
    """True if x can be iterated over"""
    return hasattr(x, '__iter__')


def _get_source(source):
    if isinstance(source, bytes):
        return io.BytesIO(source)
    elif isinstance(source, str):
        return io.StringIO(source)
    return source


def _make_basic_parse_gen(backend):
    def basic_parse_gen(file_obj, buf_size=64*1024, duplicate_keys=None, **config):
        return utils.coros2gen(
            file_source(file_obj, buf_size=buf_size),
            *_basic_parse_pipeline(backend, config)
        )
    return basic_parse_gen


def _make_parse_gen(backend):
    def parse_gen(file_obj, buf_size=64*1024, duplicate_keys=None, **config):
        return utils.coros2gen(
            file_source(file_obj, buf_size=buf_size),
            *_parse_pipeline(backend, config)
        )
    return parse_gen


def _make_items_gen(backend):
    def items_gen(file_obj, prefix, map_type=None, buf_size=64*1024,
                  duplicate_keys=None, **config):
        return utils.coros2gen(
            file_source(file_obj, buf_size=buf_size),
            *_items_pipeline(backend, prefix, map_type, config, duplicate_keys)
        )
    return items_gen


def _make_kvitems_gen(backend):
    def kvitems_gen(file_obj, prefix, map_type=None, buf_size=64*1024,
                    duplicate_keys=None, **config):
        return utils.coros2gen(
            file_source(file_obj, buf_size=buf_size),
            *_kvitems_pipeline(backend, prefix, map_type, config, duplicate_keys)
        )
    return kvitems_gen


def _make_basic_parse(backend):
    def basic_parse(source, buf_size=64*1024, duplicate_keys=None, **config):
        source = _get_source(source)
        if is_async_file(source):
            return backend['basic_parse_async'](
                source, buf_size=buf_size, **config
            )
        elif is_file(source):
            return backend['basic_parse_gen'](
                source, buf_size=buf_size, **config
            )
        raise ValueError("Unknown source type: %r" % type(source))
    return basic_parse


def _make_parse(backend):
    def parse(source, buf_size=64*1024, duplicate_keys=None, **config):
        source = _get_source(source)
        if is_async_file(source):
            return backend['parse_async'](
                source, buf_size=buf_size, **config
            )
        elif is_file(source):
            return backend['parse_gen'](
                source, buf_size=buf_size, **config
            )
        elif is_iterable(source):
            return utils.coros2gen(source,
                (backend['parse_basecoro'], (), {})
            )
        raise ValueError("Unknown source type: %r" % type(source))
    return parse


def _make_items(backend):
    def items(source, prefix, map_type=None, buf_size=64*1024,
              duplicate_keys=None, **config):
        source = _get_source(source)
        policy = _resolve_duplicate_keys(duplicate_keys, config)
        policy_kwargs = {} if policy is None else {'duplicate_keys': policy}
        if is_async_file(source):
            return backend['items_async'](
                source, prefix, map_type=map_type, buf_size=buf_size,
                **policy_kwargs, **config
            )
        elif is_file(source):
            return backend['items_gen'](
                source, prefix, map_type=map_type, buf_size=buf_size,
                **policy_kwargs, **config
            )
        elif is_iterable(source):
            basecoro_kwargs = {'map_type': map_type}
            basecoro_kwargs.update(policy_kwargs)
            return utils.coros2gen(source,
                (backend['items_basecoro'], (prefix,), basecoro_kwargs)
            )
        raise ValueError("Unknown source type: %r" % type(source))
    return items


def _make_kvitems(backend):
    def kvitems(source, prefix, map_type=None, buf_size=64*1024,
                duplicate_keys=None, **config):
        source = _get_source(source)
        policy = _resolve_duplicate_keys(duplicate_keys, config)
        policy_kwargs = {} if policy is None else {'duplicate_keys': policy}
        if is_async_file(source):
            return backend['kvitems_async'](
                source, prefix, map_type=map_type, buf_size=buf_size,
                **policy_kwargs, **config
            )
        elif is_file(source):
            return backend['kvitems_gen'](
                source, prefix, map_type=map_type, buf_size=buf_size,
                **policy_kwargs, **config
            )
        elif is_iterable(source):
            basecoro_kwargs = {'map_type': map_type}
            basecoro_kwargs.update(policy_kwargs)
            return utils.coros2gen(source,
                (backend['kvitems_basecoro'], (prefix,), basecoro_kwargs)
            )
        raise ValueError("Unknown source type: %r" % type(source))
    return kvitems


_common_functions_warn = '''
Don't use the ijson.common.* functions; instead go directly with the ijson.* ones.
See the documentation for more information.
'''

def parse(events):
    """Like ijson.parse, but takes events generated via ijson.basic_parse instead
    of a file"""
    warnings.warn(_common_functions_warn, DeprecationWarning)
    return utils.coros2gen(events,
        (parse_basecoro, (), {})
    )


def kvitems(events, prefix, map_type=None, duplicate_keys=None):
    """Like ijson.kvitems, but takes events generated via ijson.parse instead of
    a file"""
    warnings.warn(_common_functions_warn, DeprecationWarning)
    return utils.coros2gen(events,
        (kvitems_basecoro, (prefix,), {
            'map_type': map_type,
            'duplicate_keys': duplicate_keys,
        })
    )


def items(events, prefix, map_type=None, duplicate_keys=None):
    """Like ijson.items, but takes events generated via ijson.parse instead of
    a file"""
    warnings.warn(_common_functions_warn, DeprecationWarning)
    return utils.coros2gen(events,
        (items_basecoro, (prefix,), {
            'map_type': map_type,
            'duplicate_keys': duplicate_keys,
        })
    )


class BackendCapabilities:
    '''
    Capabilities supported by a backend.
    '''

    __slots__ = {
        'c_comments': 'C-ctyle comments (non-standard in JSON)',
        'multiple_values': 'Multiple top-level values (non-standard in JSON)',
        'invalid_leading_zeros_detection': 'Detection of leading zeros in numbers, marking them as invalid',
        'incomplete_json_tokens_detection': 'Documents with incomplete JSON tokens',
        'int64': '64 bit integers supported when running with ``use_float=True``',
    }

    def __init__(self):
        self.c_comments = True
        self.multiple_values = True
        self.invalid_leading_zeros_detection = True
        self.incomplete_json_tokens_detection = True
        self.int64 = True


def enrich_backend(backend, **capabilities_overrides):
    '''
    Provides a backend with any missing coroutines/generators/async-iterables
    it might be missing by using the generic ones written in python.
    '''
    # Backends unset some of these
    capabilities = BackendCapabilities()
    for name, value in capabilities_overrides.items():
        setattr(capabilities, name, value)
    backend['capabilities'] = capabilities
    backend['backend'] = backend['__name__'].split('.')[-1]
    backend['backend_name'] = backend['backend']
    for name in ('basic_parse', 'parse', 'items', 'kvitems'):
        basecoro_name = name + '_basecoro'
        if basecoro_name not in backend:
            backend[basecoro_name] = globals()[basecoro_name]
        coro_name = name + '_coro'
        if coro_name not in backend:
            factory = globals()['_make_' + coro_name]
            backend[coro_name] = factory(backend)
        gen_name = name + '_gen'
        if gen_name not in backend:
            factory = globals()['_make_' + gen_name]
            backend[gen_name] = factory(backend)
        async_name = name + '_async'
        if async_name not in backend:
            factory = getattr(utils35, '_make_' + async_name)
            backend[async_name] = factory(backend)
        factory = globals()['_make_' + name]
        backend[name] = factory(backend)
