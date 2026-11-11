'''
Backend independent higher level interfaces, common exceptions.
'''
import decimal
import inspect
import io
import warnings

from ijson import compat, utils, utils35


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


class ParseBudgetExceeded(JSONError):
    '''
    Raised when a parse budget limit is exceeded.

    The offending dimension, the amount used (or the amount that would be
    used), and the configured limit are available as attributes.
    '''
    _LIMIT_NAMES = {
        'depth': 'max_depth',
        'events': 'max_events',
        'nodes': 'max_nodes',
        'string_bytes': 'max_string_bytes',
        'key_bytes': 'max_key_bytes',
        'input_bytes': 'max_input_bytes',
        'buffer_bytes': 'max_buffer_bytes',
    }

    def __init__(self, dimension, used, limit):
        self.dimension = dimension
        self.dimension_name = dimension
        self.used = used
        self.used_amount = used
        self.limit = limit
        self.limit_value = limit
        limit_name = self._LIMIT_NAMES.get(dimension, dimension)
        self.limit_name = limit_name
        super(ParseBudgetExceeded, self).__init__(
            'Parse budget exceeded for %s (%s): used=%s limit=%s' %
            (dimension, limit_name, used, limit)
        )


class ParseBudget:
    '''
    Optional limits and accounting for a single parse.

    All limits default to ``None`` (unlimited), so passing no budget to the
    regular ijson entry points preserves their previous behaviour.  A budget
    instance accumulates counters while parsing; create a new instance for a
    new parse if limits should start counting from zero again.

    Limits are expressed as:

    - ``max_depth``: maximum container nesting depth (a top-level container
      has depth 1)
    - ``max_events``: maximum number of ijson events produced
    - ``max_nodes``: maximum number of JSON nodes (containers and scalar
      values, but not map keys or closing events)
    - ``max_string_bytes``: maximum UTF-8 byte length of one string value
    - ``max_key_bytes``: maximum UTF-8 byte length of one map key
    - ``max_input_bytes``: maximum number of bytes read from the source
    - ``max_buffer_bytes``: maximum size of a single read buffer/chunk; this
      is also the largest read size requested from the source

    The constructor also accepts common spelling variants such as
    ``max_nesting_depth``, ``max_event_count``, ``max_node_count``,
    ``max_string_length``, ``max_key_length``, ``max_consumed_bytes`` and
    ``max_buffer_size``.
    '''

    _ALIASES = {
        'depth': 'max_depth',
        'max_nesting_depth': 'max_depth',
        'max_nesting': 'max_depth',
        'max_nesting_level': 'max_depth',
        'events': 'max_events',
        'max_event_count': 'max_events',
        'nodes': 'max_nodes',
        'max_node_count': 'max_nodes',
        'max_string_length': 'max_string_bytes',
        'max_string_size': 'max_string_bytes',
        'string_bytes': 'max_string_bytes',
        'max_key_length': 'max_key_bytes',
        'max_key_size': 'max_key_bytes',
        'key_bytes': 'max_key_bytes',
        'max_consumed_bytes': 'max_input_bytes',
        'max_read_bytes': 'max_input_bytes',
        'input_bytes': 'max_input_bytes',
        'max_buffer_size': 'max_buffer_bytes',
        'max_chunk_bytes': 'max_buffer_bytes',
        'buffer_bytes': 'max_buffer_bytes',
        'buffer_size': 'max_buffer_bytes',
    }

    def __init__(self, max_depth=None, max_events=None, max_nodes=None,
                 max_string_bytes=None, max_key_bytes=None,
                 max_input_bytes=None, max_buffer_bytes=None, **aliases):
        values = {
            'max_depth': max_depth,
            'max_events': max_events,
            'max_nodes': max_nodes,
            'max_string_bytes': max_string_bytes,
            'max_key_bytes': max_key_bytes,
            'max_input_bytes': max_input_bytes,
            'max_buffer_bytes': max_buffer_bytes,
        }
        for alias, value in aliases.items():
            try:
                canonical = self._ALIASES[alias]
            except KeyError:
                raise TypeError('Unknown ParseBudget parameter: %s' % alias)
            if values[canonical] is not None:
                raise TypeError(
                    'ParseBudget parameter %s specified more than once' %
                    canonical
                )
            values[canonical] = value
        for name, value in values.items():
            if value is not None and (isinstance(value, bool) or
                                      not isinstance(value, int) or value < 0):
                raise TypeError('%s must be a non-negative integer or None' % name)
            setattr(self, name, value)

        self.depth = 0
        self.max_depth_seen = 0
        self.events = 0
        self.nodes = 0
        self.input_bytes = 0
        self.peak_buffer_bytes = 0
        self.max_string_bytes_seen = 0
        self.max_key_bytes_seen = 0
        self.aborted = False

    def reset(self):
        '''Clear accumulated counters while keeping the configured limits.'''
        self.depth = 0
        self.max_depth_seen = 0
        self.events = 0
        self.nodes = 0
        self.input_bytes = 0
        self.peak_buffer_bytes = 0
        self.max_string_bytes_seen = 0
        self.max_key_bytes_seen = 0
        self.aborted = False

    @property
    def event_count(self):
        return self.events

    @property
    def node_count(self):
        return self.nodes

    @property
    def current_depth(self):
        return self.depth

    @property
    def nesting_depth(self):
        return self.depth

    @property
    def max_depth_reached(self):
        return self.max_depth_seen

    @property
    def peak_depth(self):
        return self.max_depth_seen

    @property
    def bytes_read(self):
        return self.input_bytes

    @property
    def consumed_bytes(self):
        return self.input_bytes

    @property
    def string_bytes(self):
        return self.max_string_bytes_seen

    @property
    def key_bytes(self):
        return self.max_key_bytes_seen

    @property
    def buffer_bytes(self):
        return self.peak_buffer_bytes

    @property
    def peak_buffer(self):
        return self.peak_buffer_bytes

    def _exceeded(self, dimension, used, limit):
        self.aborted = True
        raise ParseBudgetExceeded(dimension, used, limit)

    def _check(self, dimension, used, limit):
        if limit is not None and used > limit:
            self._exceeded(dimension, used, limit)

    def prepare_read(self, requested):
        '''Return the safe read size, raising before a budget would be crossed.'''
        limit = requested
        if self.max_buffer_bytes is not None and limit is not None:
            limit = min(limit, self.max_buffer_bytes)
        if self.max_input_bytes is not None:
            remaining = self.max_input_bytes - self.input_bytes
            if remaining <= 0:
                self._exceeded('input_bytes', self.input_bytes,
                               self.max_input_bytes)
            if limit is None:
                limit = remaining
            else:
                limit = min(limit, remaining)
        return limit

    def record_read(self, data):
        '''Account for a chunk returned by the source.'''
        size = len(data)
        if not size:
            return
        self.peak_buffer_bytes = max(self.peak_buffer_bytes, size)
        used = self.input_bytes + size
        self.input_bytes = used
        self._check('buffer_bytes', size, self.max_buffer_bytes)
        self._check('input_bytes', used, self.max_input_bytes)

    def observe(self, event, value):
        '''Account for one ijson event and enforce event/node/string limits.'''
        self.events += 1
        self._check('events', self.events, self.max_events)

        if event in ('start_map', 'start_array'):
            depth = self.depth + 1
            self._check('depth', depth, self.max_depth)
            self.depth = depth
            self.max_depth_seen = max(self.max_depth_seen, depth)
            self.nodes += 1
            self._check('nodes', self.nodes, self.max_nodes)
        elif event in ('end_map', 'end_array'):
            if self.depth:
                self.depth -= 1
        elif event == 'map_key':
            size = self._value_bytes(value)
            self.max_key_bytes_seen = max(self.max_key_bytes_seen, size)
            self._check('key_bytes', size, self.max_key_bytes)
        else:
            self.nodes += 1
            self._check('nodes', self.nodes, self.max_nodes)
            if event == 'string':
                size = self._value_bytes(value)
                self.max_string_bytes_seen = max(
                    self.max_string_bytes_seen, size
                )
                self._check('string_bytes', size, self.max_string_bytes)

    @staticmethod
    def _value_bytes(value):
        if isinstance(value, str):
            return len(value.encode('utf-8'))
        if isinstance(value, bytes):
            return len(value)
        return len(str(value))

    def lexeme_limit(self):
        '''Largest quoted lexeme the backend should accumulate, if any.'''
        limits = [limit for limit in
                  (self.max_string_bytes, self.max_key_bytes)
                  if limit is not None]
        return max(limits) if limits else None

    def check_lexeme(self, kind, used):
        '''Early check while a backend is still accumulating a quoted lexeme.'''
        if kind == 'key':
            self.max_key_bytes_seen = max(self.max_key_bytes_seen, used)
            self._check('key_bytes', used, self.max_key_bytes)
        elif kind == 'string':
            self.max_string_bytes_seen = max(
                self.max_string_bytes_seen, used
            )
            self._check('string_bytes', used, self.max_string_bytes)


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
    def __init__(self, map_type=None):
        self.value = None
        self.containers = []
        self.map_type = map_type or dict

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

    def event(self, event, value):
        if event == 'map_key':
            self.key = value
        elif event == 'start_map':
            mappable = self.map_type()
            self._add(mappable)
            self.containers.append(mappable)
        elif event == 'start_array':
            array = []
            self._add(array)
            self.containers.append(array)
        elif event == 'end_array' or event == 'end_map':
            self.containers.pop()
        else:
            self._add(value)


@utils.coroutine
def items_basecoro(target, prefix, map_type=None):
    '''
    An couroutine dispatching native Python objects constructed from the events
    under a given prefix.
    '''
    while True:
        current, event, value = (yield)
        if current == prefix:
            if event in ('start_map', 'start_array'):
                object_depth = 1
                builder = ObjectBuilder(map_type=map_type)
                while object_depth:
                    builder.event(event, value)
                    current, event, value = (yield)
                    if event in ('start_map', 'start_array'):
                        object_depth += 1
                    elif event in ('end_map', 'end_array'):
                        object_depth -= 1
                target.send(builder.value)
            else:
                target.send(value)


@utils.coroutine
def kvitems_basecoro(target, prefix, map_type=None):
    '''
    An coroutine dispatching (key, value) pairs constructed from the events
    under a given prefix. The prefix should point to JSON objects
    '''
    builder = None
    while True:
        path, event, value = (yield)
        while path == prefix and event == 'map_key':
            object_depth = 0
            key = value
            builder = ObjectBuilder(map_type=map_type)
            path, event, value = (yield)
            if event == 'start_map':
                object_depth += 1
            while (
                (event != 'map_key' or object_depth != 0) and
                (event != 'end_map' or object_depth != -1)):
                builder.event(event, value)
                path, event, value = (yield)
                if event == 'start_map':
                    object_depth += 1
                elif event == 'end_map':
                    object_depth -= 1
            target.send((key, builder.value))


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

def file_source(f, buf_size=64*1024, budget=None):
    '''A generator that yields data from a file-like object'''
    f = compat.bytes_reader(f)
    while True:
        if budget is None:
            data = f.read(buf_size)
        else:
            data = f.read(budget.prepare_read(buf_size))
            budget.record_read(data)
        yield data
        if not data:
            break


@utils.coroutine
def budget_basecoro(target, budget):
    '''Checks a ParseBudget against every event flowing through it.'''
    while True:
        item = (yield)
        if len(item) == 2:
            event, value = item
        else:
            _, event, value = item
        budget.observe(event, value)
        target.send(item)


def _with_budget(pipeline, budget):
    if budget is None:
        return pipeline
    pipeline = list(pipeline)
    pipeline.insert(len(pipeline) - 1,
                    (budget_basecoro, [], {'budget': budget}))
    return tuple(pipeline)


def _before_sink_budget(pipeline, budget):
    '''Put budget immediately in front of a single sink-side coroutine.'''
    if budget is None:
        return pipeline
    return tuple(pipeline) + ((budget_basecoro, [], {'budget': budget}),)


def _config_with_budget(backend, config, budget):
    if budget is None:
        return config
    try:
        parameters = inspect.signature(
            backend['basic_parse_basecoro']
        ).parameters
    except (TypeError, ValueError):
        return config
    if 'budget' in parameters:
        config = dict(config)
        config['budget'] = budget
    return config


def _basic_parse_pipeline(backend, config, budget=None):
    return _with_budget((
        (backend['basic_parse_basecoro'], [],
         _config_with_budget(backend, config, budget)),
    ), budget)


def _parse_pipeline(backend, config, budget=None):
    return _with_budget((
        (backend['parse_basecoro'], [], {}),
        (backend['basic_parse_basecoro'], [],
         _config_with_budget(backend, config, budget))
    ), budget)


def _items_pipeline(backend, prefix, map_type, config, budget=None):
    return _with_budget((
        (backend['items_basecoro'], (prefix,), {'map_type': map_type}),
        (backend['parse_basecoro'], [], {}),
        (backend['basic_parse_basecoro'], [],
         _config_with_budget(backend, config, budget))
    ), budget)


def _kvitems_pipeline(backend, prefix, map_type, config, budget=None):
    return _with_budget((
        (backend['kvitems_basecoro'], (prefix,), {'map_type': map_type}),
        (backend['parse_basecoro'], [], {}),
        (backend['basic_parse_basecoro'], [],
         _config_with_budget(backend, config, budget))
    ), budget)


def _make_basic_parse_coro(backend):
    def basic_parse_coro(target, budget=None, **config):
        return utils.chain(
            target,
            *_basic_parse_pipeline(backend, config, budget)
        )
    return basic_parse_coro


def _make_parse_coro(backend):
    def parse_coro(target, budget=None, **config):
        return utils.chain(
            target,
            *_parse_pipeline(backend, config, budget)
        )
    return parse_coro


def _make_items_coro(backend):
    def items_coro(target, prefix, map_type=None, budget=None, **config):
        return utils.chain(
            target,
            *_items_pipeline(backend, prefix, map_type, config, budget)
        )
    return items_coro


def _make_kvitems_coro(backend):
    def kvitems_coro(target, prefix, map_type=None, budget=None, **config):
        return utils.chain(
            target,
            *_kvitems_pipeline(backend, prefix, map_type, config, budget)
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
    def basic_parse_gen(file_obj, buf_size=64*1024, budget=None, **config):
        return utils.coros2gen(
            file_source(file_obj, buf_size=buf_size, budget=budget),
            *_basic_parse_pipeline(backend, config, budget)
        )
    return basic_parse_gen


def _make_parse_gen(backend):
    def parse_gen(file_obj, buf_size=64*1024, budget=None, **config):
        return utils.coros2gen(
            file_source(file_obj, buf_size=buf_size, budget=budget),
            *_parse_pipeline(backend, config, budget)
        )
    return parse_gen


def _make_items_gen(backend):
    def items_gen(file_obj, prefix, map_type=None, buf_size=64*1024,
                  budget=None, **config):
        return utils.coros2gen(
            file_source(file_obj, buf_size=buf_size, budget=budget),
            *_items_pipeline(backend, prefix, map_type, config, budget),
            trim_budget_events=False
        )
    return items_gen


def _make_kvitems_gen(backend):
    def kvitems_gen(file_obj, prefix, map_type=None, buf_size=64*1024,
                    budget=None, **config):
        return utils.coros2gen(
            file_source(file_obj, buf_size=buf_size, budget=budget),
            *_kvitems_pipeline(backend, prefix, map_type, config, budget),
            trim_budget_events=False
        )
    return kvitems_gen


def _make_basic_parse(backend):
    def basic_parse(source, buf_size=64*1024, budget=None, **config):
        source = _get_source(source)
        if is_async_file(source):
            return backend['basic_parse_async'](
                source, buf_size=buf_size, budget=budget, **config
            )
        elif is_file(source):
            return backend['basic_parse_gen'](
                source, buf_size=buf_size, budget=budget, **config
            )
        raise ValueError("Unknown source type: %r" % type(source))
    return basic_parse


def _make_parse(backend):
    def parse(source, buf_size=64*1024, budget=None, **config):
        source = _get_source(source)
        if is_async_file(source):
            return backend['parse_async'](
                source, buf_size=buf_size, budget=budget, **config
            )
        elif is_file(source):
            return backend['parse_gen'](
                source, buf_size=buf_size, budget=budget, **config
            )
        elif is_iterable(source):
            return utils.coros2gen(source,
                *_before_sink_budget((
                    (backend['parse_basecoro'], (), {}),
                ), budget)
            )
        raise ValueError("Unknown source type: %r" % type(source))
    return parse


def _make_items(backend):
    def items(source, prefix, map_type=None, buf_size=64*1024, budget=None,
              **config):
        source = _get_source(source)
        if is_async_file(source):
            return backend['items_async'](
                source, prefix, map_type=map_type, buf_size=buf_size,
                budget=budget, **config
            )
        elif is_file(source):
            return backend['items_gen'](
                source, prefix, map_type=map_type, buf_size=buf_size,
                budget=budget, **config
            )
        elif is_iterable(source):
            return utils.coros2gen(source,
                *_before_sink_budget((
                    (backend['items_basecoro'], (prefix,),
                     {'map_type': map_type}),
                ), budget),
                trim_budget_events=False
            )
        raise ValueError("Unknown source type: %r" % type(source))
    return items


def _make_kvitems(backend):
    def kvitems(source, prefix, map_type=None, buf_size=64*1024, budget=None,
                **config):
        source = _get_source(source)
        if is_async_file(source):
            return backend['kvitems_async'](
                source, prefix, map_type=map_type, buf_size=buf_size,
                budget=budget, **config
            )
        elif is_file(source):
            return backend['kvitems_gen'](
                source, prefix, map_type=map_type, buf_size=buf_size,
                budget=budget, **config
            )
        elif is_iterable(source):
            return utils.coros2gen(source,
                *_before_sink_budget((
                    (backend['kvitems_basecoro'], (prefix,),
                     {'map_type': map_type}),
                ), budget),
                trim_budget_events=False
            )
        raise ValueError("Unknown source type: %r" % type(source))
    return kvitems


_common_functions_warn = '''
Don't use the ijson.common.* functions; instead go directly with the ijson.* ones.
See the documentation for more information.
'''

def parse(events, budget=None):
    """Like ijson.parse, but takes events generated via ijson.basic_parse instead
    of a file"""
    warnings.warn(_common_functions_warn, DeprecationWarning)
    return utils.coros2gen(events,
        *_before_sink_budget(((parse_basecoro, (), {}),), budget)
    )


def kvitems(events, prefix, map_type=None, budget=None):
    """Like ijson.kvitems, but takes events generated via ijson.parse instead of
    a file"""
    warnings.warn(_common_functions_warn, DeprecationWarning)
    return utils.coros2gen(events,
        *_before_sink_budget(
            ((kvitems_basecoro, (prefix,), {'map_type': map_type}),),
            budget
        ),
        trim_budget_events=False
    )


def items(events, prefix, map_type=None, budget=None):
    """Like ijson.items, but takes events generated via ijson.parse instead of
    a file"""
    warnings.warn(_common_functions_warn, DeprecationWarning)
    return utils.coros2gen(events,
        *_before_sink_budget(
            ((items_basecoro, (prefix,), {'map_type': map_type}),),
            budget
        ),
        trim_budget_events=False
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
