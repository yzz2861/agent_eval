'''
Backend independent higher level interfaces, common exceptions.
'''
import decimal
import enum
import inspect
import io
import json
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
    A coroutine dispatching native Python objects constructed from the events
    under a given prefix.

    prefix may also be an iterable of prefixes, in which case objects
    discovered under any of them are dispatched in document order.  Selected
    prefixes may overlap (for example parent and parent.child); each
    selected value is built independently rather than letting an enclosing
    object hide a nested one.
    '''
    prefixes = frozenset(_normalize_prefixes(prefix))
    send = target.send
    active = []
    depth = 0
    while True:
        current, event, value = (yield)

        if event == 'start_map' or event == 'start_array':
            for end_depth, start_prefix, builder in active:
                builder.event(event, value)
            if (current in prefixes and
                    not any(start_prefix == current
                            for _, start_prefix, _ in active)):
                builder = ObjectBuilder(map_type=map_type)
                builder.event(event, value)
                active.append((depth, current, builder))
            depth += 1
        elif event == 'end_map' or event == 'end_array':
            for end_depth, start_prefix, builder in active:
                builder.event(event, value)
            depth -= 1
            completed = [
                entry for entry in active if entry[0] == depth
            ]
            if completed:
                active = [entry for entry in active if entry[0] != depth]
                for _, _, builder in completed:
                    send(builder.value)
        else:
            for end_depth, start_prefix, builder in active:
                builder.event(event, value)
            if current in prefixes and event != 'map_key':
                if not any(start_prefix == current for _, start_prefix, _ in active):
                    send(value)


@utils.coroutine
def kvitems_basecoro(target, prefix, map_type=None):
    '''
    An coroutine dispatching (key, value) pairs constructed from the events
    under a given prefix. The prefix should point to JSON objects.

    As with :func:, prefix may be an iterable of prefixes.
    '''
    prefixes = frozenset(_normalize_prefixes(prefix))
    builder = None
    while True:
        path, event, value = (yield)
        while path in prefixes and event == 'map_key':
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

def file_source(f, buf_size=64*1024):
    '''A generator that yields data from a file-like object'''
    f = compat.bytes_reader(f)
    while True:
        data = f.read(buf_size)
        yield data
        if not data:
            break


class ProbeCompletion(str, enum.Enum):
    '''Why a read-only probe stopped.

    ``NATURAL_END`` means the source was exhausted (or a complete top-level
    JSON value was read) and therefore the whole selected range was observed.
    ``BUDGET_EXHAUSTED`` means the caller's read budget was consumed while the
    source still had unobserved content.
    '''

    NATURAL_END = 'natural_end'
    BUDGET_EXHAUSTED = 'budget_exhausted'
    INCOMPLETE = 'incomplete'
    INVALID = 'invalid'
    STOPPED = 'stopped'

    # Common alternative spellings, intentionally aliases of the values above.
    EOF = 'natural_end'
    COMPLETE = 'natural_end'
    NATURAL = 'natural_end'
    EOF_REACHED = 'natural_end'
    LIMIT_REACHED = 'budget_exhausted'
    EXHAUSTED = 'budget_exhausted'
    TRUNCATED = 'budget_exhausted'
    READ_BUDGET_EXHAUSTED = 'budget_exhausted'
    LIMIT = 'budget_exhausted'

    def __str__(self):
        return self.value

    def __eq__(self, other):
        if isinstance(other, str):
            return other.lower() == self.value
        return super().__eq__(other)

    def __hash__(self):
        return hash(self.value)


class ProbeStatus(str, enum.Enum):
    '''State of one field/prefix after a probe.'''

    FOUND = 'found'
    EXCLUDED = 'excluded'
    PENDING = 'pending'
    UNCHECKED = 'unchecked'

    # Common alternative spellings, intentionally aliases of the values above.
    PRESENT = 'found'
    ABSENT = 'excluded'
    NOT_FOUND = 'excluded'
    EXCLUDED_CONFIRMED = 'excluded'
    ABSENT_CONFIRMED = 'excluded'
    UNKNOWN = 'pending'
    INCONCLUSIVE = 'pending'
    UNRESOLVED = 'pending'
    HALF_OBSERVED = 'pending'
    NOT_SELECTED = 'unchecked'
    OUT_OF_SCOPE = 'unchecked'
    NOT_CHECKED = 'unchecked'
    UNQUERIED = 'unchecked'

    def __str__(self):
        return self.value

    def __eq__(self, other):
        if isinstance(other, str):
            return other.lower() == self.value
        return super().__eq__(other)

    def __hash__(self):
        return hash(self.value)


# Friendly aliases for callers that describe the same result differently.
ProbeOutcome = ProbeStatus
ProbeState = ProbeStatus
ProbeCompletionReason = ProbeCompletion
ProbeStopReason = ProbeCompletion


class PrefixProbeResult:
    '''Outcome of probing a single prefix, including its explanation.'''

    __slots__ = (
        'prefix', 'status', 'events', 'key_events', 'completion', 'reason',
        'nested', 'crosses_chunks', 'depth', 'checked', 'selected',
    )

    def __init__(self, prefix, status, completion=None, events=None,
                 reason=None, nested=False, crosses_chunks=False,
                 checked=True, selected=True, key_events=None):
        self.prefix = prefix
        self.status = ProbeStatus(status)
        self.events = list(events or ())
        self.key_events = list(key_events or ())
        self.completion = (
            ProbeCompletion(completion) if completion is not None else None
        )
        self.reason = reason or _DEFAULT_REASONS[self.status]
        self.depth = prefix.count('.') + 1 if prefix else 0
        self.nested = bool(nested or self.depth > 1)
        self.crosses_chunks = bool(crosses_chunks)
        self.checked = bool(checked)
        self.selected = bool(selected)

    @property
    def found(self):
        return self.status is ProbeStatus.FOUND

    @property
    def key_seen(self):
        return bool(self.key_events)

    @property
    def excluded(self):
        return self.status is ProbeStatus.EXCLUDED

    @property
    def pending(self):
        return self.status is ProbeStatus.PENDING

    @property
    def unchecked(self):
        return self.status is ProbeStatus.UNCHECKED

    @property
    def complete(self):
        '''True when the field state is final (found or excluded).'''
        return self.status in (ProbeStatus.FOUND, ProbeStatus.EXCLUDED)

    @property
    def exhausted(self):
        return self.completion is ProbeCompletion.BUDGET_EXHAUSTED

    @property
    def natural_end(self):
        return self.completion is ProbeCompletion.NATURAL_END

    @property
    def values(self):
        return [event[2] for event in self.events]

    @property
    def name(self):
        return self.prefix

    @property
    def state(self):
        return self.status

    @property
    def outcome(self):
        return self.status

    @property
    def matched(self):
        return self.found

    @property
    def present(self):
        return self.found

    @property
    def value(self):
        return self.events[0][2] if self.events else None

    def explain(self):
        '''Return a short, stable explanation of this field's state.'''
        parts = ['%s: %s' % (self.prefix or '<root>', self.status.value)]
        parts.append('reason=%s' % (self.reason,))
        if self.nested:
            parts.append('nested')
        if self.crosses_chunks:
            parts.append('crosses_chunks')
        if not self.checked:
            parts.append('not_selected')
        return ', '.join(parts)

    explanation = property(explain)

    def __bool__(self):
        return self.found

    def __eq__(self, other):
        if isinstance(other, PrefixProbeResult):
            return (
                self.prefix == other.prefix and
                self.status is other.status and
                self.events == other.events
            )
        if isinstance(other, ProbeStatus):
            return self.status is other
        if isinstance(other, str):
            return self.status.value == other
        return NotImplemented

    def __hash__(self):
        return hash((self.prefix, self.status.value))

    def __getitem__(self, key):
        if isinstance(key, (int, slice)):
            return self.events[key]
        if key in ('status', 'state', 'outcome'):
            return self.status
        if key in ('found', 'present'):
            return self.found
        if key in ('complete', 'done'):
            return self.complete
        raise KeyError(key)

    def as_dict(self):
        return {
            'prefix': self.prefix,
            'status': self.status.value,
            'found': self.found,
            'complete': self.complete,
            'completion': (
                self.completion.value if self.completion is not None else None
            ),
            'reason': self.reason,
            'nested': self.nested,
            'crosses_chunks': self.crosses_chunks,
            'checked': self.checked,
            'events': list(self.events),
        }

    def __repr__(self):
        return (
            'PrefixProbeResult(prefix=%r, status=%r, completion=%r)'
            % (self.prefix, self.status.value,
               self.completion.value if self.completion is not None else None)
        )


_DEFAULT_REASONS = {
    ProbeStatus.FOUND: 'field_present',
    ProbeStatus.EXCLUDED: 'complete_range_without_field',
    ProbeStatus.PENDING: 'read_budget_exhausted',
    ProbeStatus.UNCHECKED: 'outside_selected_prefixes',
}


class ProbeResult:
    '''Result returned by :func:`probe`.

    The object behaves as a mapping from prefix to
    :class:`PrefixProbeResult`, while also exposing aggregate attributes such
    as ``found``, ``complete``, ``completion`` and ``bytes_read``.
    '''

    def __init__(self, prefixes, selected, results, completion,
                 bytes_read=0, error=None, observed_prefixes=(),
                 stopped_early=False):
        self.prefixes = dict(results)
        self.results = self.prefixes
        self.fields = self.prefixes
        self.matches = {
            prefix: result.events
            for prefix, result in self.prefixes.items()
        }
        self.selected_prefixes = tuple(selected)
        self.requested_prefixes = tuple(prefixes)
        self.completion = (
            ProbeCompletion(completion) if completion is not None else None
        )
        self.bytes_read = int(bytes_read)
        self.read_bytes = self.bytes_read
        self.consumed = self.bytes_read
        self.error = error
        self.observed_prefixes = tuple(dict.fromkeys(observed_prefixes))
        self.stopped_early = bool(stopped_early)

    @property
    def found(self):
        return any(result.found for result in self.prefixes.values())

    @property
    def found_prefixes(self):
        return tuple(
            prefix for prefix, result in self.prefixes.items() if result.found
        )

    @property
    def excluded_prefixes(self):
        return tuple(
            prefix for prefix, result in self.prefixes.items()
            if result.excluded
        )

    @property
    def pending_prefixes(self):
        return tuple(
            prefix for prefix, result in self.prefixes.items()
            if result.pending
        )

    @property
    def unknown_prefixes(self):
        return self.pending_prefixes

    @property
    def inconclusive_prefixes(self):
        return self.pending_prefixes

    @property
    def unchecked_prefixes(self):
        return tuple(
            prefix for prefix, result in self.prefixes.items()
            if result.unchecked
        )

    @property
    def not_checked_prefixes(self):
        return self.unchecked_prefixes

    @property
    def checked_prefixes(self):
        return tuple(
            prefix for prefix, result in self.prefixes.items()
            if result.checked
        )

    @property
    def complete(self):
        '''True when the probe reached a natural end of its selected range.'''
        return self.completion is ProbeCompletion.NATURAL_END

    @property
    def done(self):
        return self.complete

    @property
    def completed(self):
        return self.complete

    @property
    def natural_end(self):
        return self.complete

    @property
    def eof(self):
        return self.complete

    @property
    def exhausted(self):
        return self.completion is ProbeCompletion.BUDGET_EXHAUSTED

    @property
    def budget_exhausted(self):
        return self.exhausted

    @property
    def truncated(self):
        return self.exhausted

    @property
    def status(self):
        results = tuple(self.prefixes.values())
        if any(result.found for result in results):
            return ProbeStatus.FOUND
        if results and all(result.excluded for result in results):
            return ProbeStatus.EXCLUDED
        if any(result.pending for result in results):
            return ProbeStatus.PENDING
        if any(result.unchecked for result in results):
            return ProbeStatus.UNCHECKED
        return ProbeStatus.EXCLUDED

    @property
    def state(self):
        return self.status

    @property
    def reason(self):
        if isinstance(self.error, IncompleteJSONError):
            return 'incomplete_json'
        if self.error is not None:
            return 'invalid_json'
        return self.completion.value if self.completion is not None else None

    @property
    def stop_reason(self):
        return self.completion

    @property
    def completion_reason(self):
        return self.completion

    @property
    def explanations(self):
        return {
            prefix: result.explain()
            for prefix, result in self.prefixes.items()
        }

    def status_for(self, prefix):
        return self[prefix].status

    def has(self, prefix):
        return self[prefix].found

    contains = has

    def is_found(self, prefix):
        return self[prefix].found

    def is_excluded(self, prefix):
        return self[prefix].excluded

    def is_pending(self, prefix):
        return self[prefix].pending

    def is_unchecked(self, prefix):
        return self[prefix].unchecked

    def explain(self, prefix=None):
        if prefix is not None:
            return self[prefix].explain()
        completion = (
            self.completion.value if self.completion is not None else 'running'
        )
        return '%s (%s, %d bytes read)' % (
            self.status.value, completion, self.bytes_read
        )

    explanation = property(explain)

    def as_dict(self):
        return {
            'status': self.status.value,
            'completion': (
                self.completion.value if self.completion is not None else None
            ),
            'found': self.found,
            'complete': self.complete,
            'exhausted': self.exhausted,
            'bytes_read': self.bytes_read,
            'prefixes': {
                prefix: result.as_dict()
                for prefix, result in self.prefixes.items()
            },
        }

    def __getitem__(self, prefix):
        try:
            return self.prefixes[prefix]
        except KeyError:
            return PrefixProbeResult(
                prefix, ProbeStatus.UNCHECKED,
                reason=_DEFAULT_REASONS[ProbeStatus.UNCHECKED],
                checked=False, selected=False,
            )

    def get(self, prefix, default=None):
        if prefix in self.prefixes:
            return self.prefixes[prefix]
        return default

    def __contains__(self, prefix):
        return prefix in self.prefixes

    def __iter__(self):
        return iter(self.prefixes)

    def __len__(self):
        return len(self.prefixes)

    def __bool__(self):
        return self.found

    def __repr__(self):
        return (
            'ProbeResult(status=%r, completion=%r, prefixes=%r)'
            % (self.status.value,
               self.completion.value if self.completion is not None else None,
               self.requested_prefixes)
        )


Probe = ProbeResult
PrefixResult = PrefixProbeResult
ProbeFieldResult = PrefixProbeResult


def _basic_parse_pipeline(backend, config):
    return (
        (backend['basic_parse_basecoro'], [], config),
    )


def _parse_pipeline(backend, config):
    return (
        (backend['parse_basecoro'], [], {}),
        (backend['basic_parse_basecoro'], [], config)
    )


def _items_pipeline(backend, prefix, map_type, config):
    return (
        (backend['items_basecoro'], (prefix,), {'map_type': map_type}),
        (backend['parse_basecoro'], [], {}),
        (backend['basic_parse_basecoro'], [], config)
    )


def _kvitems_pipeline(backend, prefix, map_type, config):
    return (
        (backend['kvitems_basecoro'], (prefix,), {'map_type': map_type}),
        (backend['parse_basecoro'], [], {}),
        (backend['basic_parse_basecoro'], [], config)
    )


def _make_basic_parse_coro(backend):
    def basic_parse_coro(target, **config):
        return utils.chain(
            target,
            *_basic_parse_pipeline(backend, config)
        )
    return basic_parse_coro


def _make_parse_coro(backend):
    def parse_coro(target, **config):
        return utils.chain(
            target,
            *_parse_pipeline(backend, config)
        )
    return parse_coro


def _make_items_coro(backend):
    def items_coro(target, prefix, map_type=None, **config):
        return utils.chain(
            target,
            *_items_pipeline(backend, prefix, map_type, config)
        )
    return items_coro


def _make_kvitems_coro(backend):
    def kvitems_coro(target, prefix, map_type=None, **config):
        return utils.chain(
            target,
            *_kvitems_pipeline(backend, prefix, map_type, config)
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


def _normalize_prefixes(value):
    '''Return prefixes as a de-duplicated tuple, preserving input order.'''
    if value is None:
        return ()
    if isinstance(value, bytes):
        value = value.decode('utf-8')
    if isinstance(value, str):
        return (value,)
    prefixes = []
    for prefix in value:
        if isinstance(prefix, bytes):
            prefix = prefix.decode('utf-8')
        if not isinstance(prefix, str):
            raise TypeError('prefixes must be strings, got %r' % (prefix,))
        prefixes.append(prefix)
    return tuple(dict.fromkeys(prefixes))


def _resolve_read_limit(values):
    '''Resolve aliases for the byte budget, rejecting conflicting values.'''
    limit = None
    for value in values:
        if value is None:
            continue
        if limit is not None and value != limit:
            raise TypeError('conflicting read limits supplied')
        limit = value
    if limit is not None and limit < 0:
        raise ValueError('read limit must be non-negative')
    return limit


class _ChunkTracker:
    '''Small helper used to explain lexemes that crossed a read boundary.'''

    _MAX_RAW = 1024 * 1024

    def __init__(self):
        self.total = 0
        self.base = 0
        self.raw = bytearray()
        self.boundaries = []

    def feed(self, chunk):
        self.boundaries.append(self.total)
        self.raw.extend(chunk)
        self.total += len(chunk)
        excess = len(self.raw) - self._MAX_RAW
        if excess > 0:
            del self.raw[:excess]
            self.base += excess

    def crosses(self, value):
        if not value or not self.boundaries:
            return False
        try:
            needle = json.dumps(value, ensure_ascii=False).encode('utf-8')
        except Exception:
            return False
        start = bytes(self.raw).rfind(needle)
        if start < 0:
            try:
                needle = json.dumps(value, ensure_ascii=True).encode('ascii')
            except Exception:
                return False
            start = bytes(self.raw).rfind(needle)
            if start < 0:
                return False
        start += self.base
        end = start + len(needle)
        return any(start < boundary < end for boundary in self.boundaries)


class _ProbeState:
    '''Accumulates the information needed to state probe outcomes.'''

    def __init__(self, requested, selected):
        self.requested = tuple(requested)
        self.selected = frozenset(selected)
        self.events = {prefix: [] for prefix in self.requested}
        self.key_events = {prefix: [] for prefix in self.requested}
        self.crosses_chunks = {prefix: False for prefix in self.requested}
        self.observed = []
        self.depth = 0
        self.root_started = False
        self.root_complete = False
        self.error = None
        self.tracker = _ChunkTracker()

    def send(self, event):
        try:
            prefix, event_type, value = event
        except (TypeError, ValueError):
            return
        self.observed.append(prefix)
        if event_type == 'map_key':
            key_prefix = '.'.join(
                part for part in (prefix, value) if part
            ) if (prefix or value) else ''
            if key_prefix in self.key_events:
                self.key_events[key_prefix].append(
                    (key_prefix, 'map_key', value)
                )
                if value and value != 'item':
                    self.crosses_chunks[key_prefix] |= (
                        self.tracker.crosses(value)
                    )
        if prefix in self.events:
            self.events[prefix].append((prefix, event_type, value))
            key = value if event_type == 'map_key' else (
                prefix.rsplit('.', 1)[-1] if prefix else ''
            )
            if key and key != 'item':
                self.crosses_chunks[prefix] |= self.tracker.crosses(key)
            if event_type == 'string' and value:
                self.crosses_chunks[prefix] |= self.tracker.crosses(value)

        if event_type in ('start_map', 'start_array'):
            if self.depth == 0:
                self.root_started = True
            self.depth += 1
        elif event_type in ('end_map', 'end_array'):
            self.depth -= 1
            if self.depth == 0:
                self.root_complete = True
        elif self.depth == 0:
            # A document consisting of a single scalar value is complete too.
            self.root_started = True
            self.root_complete = True

    def final_events(self, prefix):
        return tuple(self.events.get(prefix, ()))

    def final_key_events(self, prefix):
        return tuple(self.key_events.get(prefix, ()))


class _SyncChunkReader:
    '''Reads a sync source in bounded chunks without borrowing its buffering.'''

    def __init__(self, source, buf_size, limit):
        self.source = source
        self.limit = limit
        self.buf_size = 64 * 1024 if not buf_size else buf_size
        self.bytes_read = 0
        self.bytes_fetched = 0
        self.natural_end = False
        self.at_budget = False
        self._warned = False
        self._pending = b''
        self._iterator = None
        if is_file(source):
            self.reader = compat.bytes_reader(source)
        elif is_iterable(source):
            self.reader = None
            self._iterator = iter(source)
        else:
            raise ValueError('Unknown source type: %r' % type(source))

    def _coerce(self, chunk):
        if isinstance(chunk, bytes):
            return chunk
        if isinstance(chunk, (bytearray, memoryview)):
            return bytes(chunk)
        if isinstance(chunk, str):
            if not self._warned:
                compat._warn_and_return(None)
                self._warned = True
            return chunk.encode('utf-8')
        raise TypeError('expected bytes or str chunks, got %r' % type(chunk))

    def _read(self, size):
        if self._pending:
            chunk, self._pending = self._pending, b''
            return chunk
        if self.reader is not None:
            read_bounded = getattr(self.reader, "read_bounded", None)
            chunk = (read_bounded(size) if read_bounded is not None
                     else self.reader.read(size))
        else:
            try:
                chunk = next(self._iterator)
            except StopIteration:
                chunk = b''
        return self._coerce(chunk)

    def _known_exhausted(self):
        if isinstance(self.source, io.BytesIO):
            return self.source.tell() >= len(self.source.getbuffer())
        if isinstance(self.source, io.StringIO):
            return self.source.tell() >= len(self.source.getvalue())
        return False

    def __iter__(self):
        while True:
            if self.limit is None:
                size = self.buf_size
            else:
                remaining = self.limit - self.bytes_read
                if remaining <= 0:
                    self.at_budget = True
                    if self._known_exhausted():
                        self.natural_end = True
                    break
                size = min(self.buf_size, remaining)

            chunk = self._read(size)
            self.bytes_fetched += len(chunk)
            if not chunk:
                self.natural_end = True
                break
            if self.limit is not None:
                remaining = self.limit - self.bytes_read
                if len(chunk) > remaining:
                    self._pending = chunk[remaining:]
                    chunk = chunk[:remaining]
            self.bytes_read += len(chunk)
            if chunk:
                yield chunk


class _AsyncChunkReader(_SyncChunkReader):
    '''Asynchronous counterpart of :class:`_SyncChunkReader`.'''

    def __init__(self, source, buf_size, limit):
        self.source = source
        self.limit = limit
        self.buf_size = 64 * 1024 if not buf_size else buf_size
        self.bytes_read = 0
        self.bytes_fetched = 0
        self.natural_end = False
        self.at_budget = False
        self._warned = False
        self._pending = b''
        self._read_bounded = getattr(source, 'read_bounded', None)
        if hasattr(source, '__aiter__'):
            self._iterator = source.__aiter__()
            self._is_async_iterable = True
            self.reader = None
        else:
            self._iterator = None
            self._is_async_iterable = False
            self.reader = None

    async def _read_async(self, size):
        if self._pending:
            chunk, self._pending = self._pending, b''
            return chunk
        if self._is_async_iterable:
            try:
                chunk = await anext(self._iterator)
            except StopAsyncIteration:
                chunk = b''
        else:
            if self._read_bounded is not None:
                chunk = await self._read_bounded(size)
            else:
                if self.reader is None:
                    self.reader = _awaitable_reader(
                        await utils35._get_read(self.source)
                    )
                chunk = await self.reader.read(size)
        return self._coerce(chunk)

    def __aiter__(self):
        return self

    async def __anext__(self):
        while True:
            if self.limit is None:
                size = self.buf_size
            else:
                remaining = self.limit - self.bytes_read
                if remaining <= 0:
                    self.at_budget = True
                    if self._known_exhausted():
                        self.natural_end = True
                    raise StopAsyncIteration
                size = min(self.buf_size, remaining)

            chunk = await self._read_async(size)
            self.bytes_fetched += len(chunk)
            if not chunk:
                self.natural_end = True
                raise StopAsyncIteration
            if self.limit is not None:
                remaining = self.limit - self.bytes_read
                if len(chunk) > remaining:
                    self._pending = chunk[remaining:]
                    chunk = chunk[:remaining]
            self.bytes_read += len(chunk)
            if chunk:
                return chunk


class _AwaitableReader:
    def __init__(self, read):
        self._read = read

    async def read(self, size):
        return await self._read(size)


def _awaitable_reader(read):
    return _AwaitableReader(read)


def anext(ait):
    return ait.__anext__()


def _make_probe_result(requested, selected, state, completion, reader,
                       stopped_early=False):
    results = {}
    for prefix in requested:
        if prefix not in state.selected:
            results[prefix] = PrefixProbeResult(
                prefix, ProbeStatus.UNCHECKED, completion=None,
                reason=_DEFAULT_REASONS[ProbeStatus.UNCHECKED],
                checked=False, selected=False,
            )
            continue
        events = state.final_events(prefix)
        key_events = state.final_key_events(prefix)
        crosses_chunks = state.crosses_chunks.get(prefix, False)
        if events or key_events:
            results[prefix] = PrefixProbeResult(
                prefix, ProbeStatus.FOUND, completion=completion,
                events=events, key_events=key_events,
                reason='field_present', crosses_chunks=crosses_chunks,
            )
        elif completion is ProbeCompletion.NATURAL_END:
            results[prefix] = PrefixProbeResult(
                prefix, ProbeStatus.EXCLUDED, completion=completion,
                reason='complete_range_without_field',
            )
        else:
            reason = 'read_budget_exhausted'
            if state.error is not None:
                reason = 'incomplete_json'
            results[prefix] = PrefixProbeResult(
                prefix, ProbeStatus.PENDING, completion=completion,
                reason=reason,
            )
    return ProbeResult(
        requested, selected, results, completion,
        bytes_read=reader.bytes_read, error=state.error,
        observed_prefixes=state.observed, stopped_early=stopped_early,
    )


def _probe_finish(completion, state, reader, requested, selected,
                  stopped_early=False):
    error = state.error
    if error is not None:
        if isinstance(error, IncompleteJSONError):
            completion = ProbeCompletion.INCOMPLETE
        else:
            completion = ProbeCompletion.INVALID
    return _make_probe_result(
        requested, selected, state, completion, reader,
        stopped_early=stopped_early,
    )


def _probe_sync(backend, source, prefixes, selected, limit, buf_size,
                stop_on_all_found, config):
    state = _ProbeState(prefixes, selected)
    reader = _SyncChunkReader(source, buf_size, limit)
    parser = backend['parse_coro'](state, **config)
    stopped_early = False
    finished = False
    try:
        for chunk in reader:
            state.tracker.feed(chunk)
            try:
                parser.send(chunk)
            except StopIteration:
                finished = True
                break
            except JSONError as error:
                state.error = error
                break
            if stop_on_all_found and all(
                    state.events.get(prefix) for prefix in state.selected):
                stopped_early = True
                break
        else:
            if reader.natural_end:
                try:
                    parser.send(b'')
                except StopIteration:
                    finished = True
                except JSONError as error:
                    state.error = error
    finally:
        if not finished:
            try:
                parser.close()
            except Exception:
                pass

    if state.error is not None:
        completion = (
            ProbeCompletion.INCOMPLETE
            if isinstance(state.error, IncompleteJSONError)
            else ProbeCompletion.INVALID
        )
    elif finished or reader.natural_end:
        completion = ProbeCompletion.NATURAL_END
    elif stopped_early:
        completion = ProbeCompletion.STOPPED
    elif reader.at_budget and state.root_complete:
        # The budget ended exactly on the last byte of a complete value.  No
        # unobserved part of the selected JSON range is left to search.
        completion = ProbeCompletion.NATURAL_END
    else:
        completion = ProbeCompletion.BUDGET_EXHAUSTED
    return _probe_finish(
        completion, state, reader, prefixes, selected,
        stopped_early=stopped_early,
    )


async def _probe_async(backend, source, prefixes, selected, limit, buf_size,
                       stop_on_all_found, config):
    state = _ProbeState(prefixes, selected)
    reader = _AsyncChunkReader(source, buf_size, limit)
    parser = backend['parse_coro'](state, **config)
    stopped_early = False
    finished = False
    try:
        async for chunk in reader:
            state.tracker.feed(chunk)
            try:
                parser.send(chunk)
            except StopIteration:
                finished = True
                break
            except JSONError as error:
                state.error = error
                break
            if stop_on_all_found and all(
                    state.events.get(prefix) for prefix in state.selected):
                stopped_early = True
                break
        else:
            if reader.natural_end:
                try:
                    parser.send(b'')
                except StopIteration:
                    finished = True
                except JSONError as error:
                    state.error = error
    finally:
        if not finished:
            try:
                parser.close()
            except Exception:
                pass

    if state.error is not None:
        completion = (
            ProbeCompletion.INCOMPLETE
            if isinstance(state.error, IncompleteJSONError)
            else ProbeCompletion.INVALID
        )
    elif finished or reader.natural_end:
        completion = ProbeCompletion.NATURAL_END
    elif stopped_early:
        completion = ProbeCompletion.STOPPED
    elif reader.at_budget and state.root_complete:
        completion = ProbeCompletion.NATURAL_END
    else:
        completion = ProbeCompletion.BUDGET_EXHAUSTED
    return _probe_finish(
        completion, state, reader, prefixes, selected,
        stopped_early=stopped_early,
    )


def _probe_event_source(events, prefixes, selected, stop_on_all_found):
    state = _ProbeState(prefixes, selected)
    reader = type('_EventReader', (), {'bytes_read': 0})()
    stopped_early = False
    for event in events:
        state.send(event)
        if stop_on_all_found and all(
                state.events.get(prefix) for prefix in state.selected):
            stopped_early = True
            break
    completion = (
        ProbeCompletion.STOPPED if stopped_early
        else ProbeCompletion.NATURAL_END
    )
    return _make_probe_result(
        prefixes, selected, state, completion, reader,
        stopped_early=stopped_early,
    )


def _probe_dispatch(backend, source, prefixes=None, limit=None, buf_size=64*1024,
                    stop_on_all_found=False, select=None, config=None):
    requested = _normalize_prefixes(prefixes)
    selected_value = select if select is not None else prefixes
    selected = _normalize_prefixes(selected_value)
    if select is not None:
        requested = tuple(dict.fromkeys(requested + selected))
    if not selected:
        selected = requested
    source = _get_source(source)

    if is_iterable(source) and not is_file(source):
        iterator = iter(source)
        try:
            first = next(iterator)
        except StopIteration:
            return _probe_event_source((), requested, selected,
                                       stop_on_all_found)
        if isinstance(first, (tuple, list)) and len(first) == 3:
            import itertools
            return _probe_event_source(
                itertools.chain((first,), iterator), requested, selected,
                stop_on_all_found,
            )
        import itertools
        source = itertools.chain((first,), iterator)

    if is_async_file(source) or hasattr(source, '__aiter__'):
        return _probe_async(
            backend, source, requested, selected, limit, buf_size,
            stop_on_all_found, config or {},
        )
    return _probe_sync(
        backend, source, requested, selected, limit, buf_size,
        stop_on_all_found, config or {},
    )


class _ProbeCoro:
    '''Push-style probe collecting outcomes until the caller closes it.'''

    def __init__(self, backend, target, prefixes, selected, limit, config):
        self.target = target
        self.state = _ProbeState(prefixes, selected)
        self.requested = tuple(prefixes)
        self.selected = tuple(selected)
        self.limit = limit
        self.parser = backend['parse_coro'](self.state, **config)
        self.bytes_read = 0
        self.bytes_fetched = 0
        self.finished = False
        self.closed = False
        self.result = None

    def send(self, chunk):
        if self.finished or self.closed:
            raise StopIteration
        if isinstance(chunk, str):
            chunk = chunk.encode('utf-8')
        elif isinstance(chunk, (bytearray, memoryview)):
            chunk = bytes(chunk)
        elif not isinstance(chunk, bytes):
            raise TypeError('expected bytes or str chunks, got %r' % type(chunk))
        if self.limit is not None:
            remaining = self.limit - self.bytes_read
            if remaining <= 0:
                self._finish(natural=False)
                raise StopIteration
            if len(chunk) > remaining:
                chunk = chunk[:remaining]
        if not chunk:
            self._finish(natural=True)
            return
        self.bytes_fetched += len(chunk)
        self.bytes_read += len(chunk)
        self.state.tracker.feed(chunk)
        try:
            self.parser.send(chunk)
        except StopIteration:
            self._finish(natural=True)
            raise StopIteration
        except JSONError:
            self._finish(natural=False)
            raise

    def _finish(self, natural):
        if self.finished:
            return
        self.finished = True
        if natural:
            try:
                self.parser.send(b'')
            except StopIteration:
                pass
            except JSONError as error:
                self.state.error = error
        try:
            self.parser.close()
        except Exception:
            pass
        if self.state.error is not None:
            completion = (
                ProbeCompletion.INCOMPLETE
                if isinstance(self.state.error, IncompleteJSONError)
                else ProbeCompletion.INVALID
            )
        elif natural:
            completion = ProbeCompletion.NATURAL_END
        elif self.limit is not None and self.bytes_read >= self.limit:
            completion = ProbeCompletion.BUDGET_EXHAUSTED
        else:
            completion = ProbeCompletion.STOPPED
        reader = type('_CoroReader', (), {'bytes_read': self.bytes_read})()
        result = _make_probe_result(
            self.requested, self.selected, self.state, completion, reader,
        )
        self.result = result
        send = getattr(self.target, 'send', None)
        if send is not None:
            send(result)
        else:
            self.target(result)
        return result

    def finish(self):
        return self._finish(natural=True)

    def close(self):
        if not self.closed:
            self.closed = True
            if not self.finished:
                self._finish(natural=True)
        return False


def _make_probe(backend):
    def probe(source, prefixes=None, max_bytes=None, *,
              prefix=None, fields=None, select=None, scope=None,
              read_limit=None, limit=None, budget=None, max_read=None,
              max_size=None, limit_bytes=None, byte_limit=None,
              read_budget=None, max_bytes_read=None,
              buf_size=64*1024, chunk_size=None, read_size=None,
              stop_on_all_found=False, map_type=None, **config):
        '''Probe selected JSON prefixes within an optional read budget.

        ``prefixes`` may be one prefix or an iterable of prefixes.  The
        optional ``select``/``scope`` argument limits which of the reported
        ``prefixes``/``fields`` are actually searched; the remaining ones are
        returned as ``unchecked`` rather than silently treated as absent.
        '''
        if prefixes is not None:
            prefixes = _normalize_prefixes(prefixes)
        if fields is not None:
            fields = _normalize_prefixes(fields)
        if prefixes is None:
            if prefix is not None:
                prefixes = prefix
            elif fields is not None:
                prefixes = fields
        elif fields is not None and _normalize_prefixes(prefixes) != \
                _normalize_prefixes(fields):
            # ``fields`` is an alias unless both spellings were supplied.
            raise TypeError('probe accepts either prefixes or fields, not both')
        if select is None:
            select = scope
        limit = _resolve_read_limit((
            max_bytes, read_limit, limit, budget, max_read, max_size,
            limit_bytes, byte_limit, read_budget, max_bytes_read,
        ))
        sizes = [size for size in (chunk_size, read_size) if size is not None]
        if sizes:
            if len(set(sizes)) > 1:
                raise TypeError("conflicting chunk sizes supplied")
            buf_size = sizes[0]
        return _probe_dispatch(
            backend, source, prefixes, limit, buf_size,
            stop_on_all_found, select, config,
        )
    return probe


def _make_probe_gen(backend):
    def probe_gen(file_obj, prefixes=None, max_bytes=None, **kwargs):
        return _make_probe(backend)(
            file_obj, prefixes, max_bytes=max_bytes, **kwargs
        )
    return probe_gen


def _make_probe_async(backend):
    def probe_async(file_obj, prefixes=None, max_bytes=None, **kwargs):
        return _make_probe(backend)(
            file_obj, prefixes, max_bytes=max_bytes, **kwargs
        )
    return probe_async


def _make_probe_coro(backend):
    def probe_coro(target, prefixes=None, max_bytes=None, *,
                   prefix=None, select=None, scope=None, read_limit=None,
                   limit=None, budget=None, max_read=None, max_size=None,
                   **config):
        if prefixes is None:
            prefixes = prefix
        requested = _normalize_prefixes(prefixes)
        selected = _normalize_prefixes(select if select is not None else scope)
        if not selected:
            selected = requested
        else:
            requested = tuple(dict.fromkeys(requested + selected))
        read_limit = _resolve_read_limit((
            max_bytes, read_limit, limit, budget, max_read, max_size,
        ))
        return _ProbeCoro(
            backend, target, requested, selected, read_limit, config
        )
    return probe_coro


def _make_basic_parse_gen(backend):
    def basic_parse_gen(file_obj, buf_size=64*1024, **config):
        return utils.coros2gen(
            file_source(file_obj, buf_size=buf_size),
            *_basic_parse_pipeline(backend, config)
        )
    return basic_parse_gen


def _make_parse_gen(backend):
    def parse_gen(file_obj, buf_size=64*1024, **config):
        return utils.coros2gen(
            file_source(file_obj, buf_size=buf_size),
            *_parse_pipeline(backend, config)
        )
    return parse_gen


def _make_items_gen(backend):
    def items_gen(file_obj, prefix, map_type=None, buf_size=64*1024, **config):
        return utils.coros2gen(
            file_source(file_obj, buf_size=buf_size),
            *_items_pipeline(backend, prefix, map_type, config)
        )
    return items_gen


def _make_kvitems_gen(backend):
    def kvitems_gen(file_obj, prefix, map_type=None, buf_size=64*1024, **config):
        return utils.coros2gen(
            file_source(file_obj, buf_size=buf_size),
            *_kvitems_pipeline(backend, prefix, map_type, config)
        )
    return kvitems_gen


def _make_basic_parse(backend):
    def basic_parse(source, buf_size=64*1024, **config):
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
    def parse(source, buf_size=64*1024, **config):
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
    def items(source, prefix, map_type=None, buf_size=64*1024, **config):
        source = _get_source(source)
        if is_async_file(source):
            return backend['items_async'](
                source, prefix, map_type=map_type, buf_size=buf_size, **config
            )
        elif is_file(source):
            return backend['items_gen'](
                source, prefix, map_type=map_type, buf_size=buf_size, **config
            )
        elif is_iterable(source):
            return utils.coros2gen(source,
                (backend['items_basecoro'], (prefix,), {'map_type': map_type})
            )
        raise ValueError("Unknown source type: %r" % type(source))
    return items


def _make_kvitems(backend):
    def kvitems(source, prefix, map_type=None, buf_size=64*1024, **config):
        source = _get_source(source)
        if is_async_file(source):
            return backend['kvitems_async'](
                source, prefix, map_type=map_type, buf_size=buf_size, **config
            )
        elif is_file(source):
            return backend['kvitems_gen'](
                source, prefix, map_type=map_type, buf_size=buf_size, **config
            )
        elif is_iterable(source):
            return utils.coros2gen(source,
                (backend['kvitems_basecoro'], (prefix,), {'map_type': map_type})
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


def kvitems(events, prefix, map_type=None):
    """Like ijson.kvitems, but takes events generated via ijson.parse instead of
    a file"""
    warnings.warn(_common_functions_warn, DeprecationWarning)
    return utils.coros2gen(events,
        (kvitems_basecoro, (prefix,), {'map_type': map_type})
    )


def items(events, prefix, map_type=None):
    """Like ijson.items, but takes events generated via ijson.parse instead of
    a file"""
    warnings.warn(_common_functions_warn, DeprecationWarning)
    return utils.coros2gen(events,
        (items_basecoro, (prefix,), {'map_type': map_type})
    )


def _default_probe_backend():
    from ijson import backend_name, get_backend
    return get_backend(backend_name)


def probe(source, prefixes=None, max_bytes=None, **kwargs):
    """Probe prefixes using the package default backend."""
    return getattr(_default_probe_backend(), "probe")(
        source, prefixes, max_bytes=max_bytes, **kwargs
    )


def probe_gen(file_obj, prefixes=None, max_bytes=None, **kwargs):
    return getattr(_default_probe_backend(), "probe_gen")(
        file_obj, prefixes, max_bytes=max_bytes, **kwargs
    )


def probe_async(file_obj, prefixes=None, max_bytes=None, **kwargs):
    return getattr(_default_probe_backend(), "probe_async")(
        file_obj, prefixes, max_bytes=max_bytes, **kwargs
    )


def probe_coro(target, prefixes=None, max_bytes=None, **kwargs):
    return getattr(_default_probe_backend(), "probe_coro")(
        target, prefixes, max_bytes=max_bytes, **kwargs
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
    if 'probe' not in backend:
        backend['probe'] = _make_probe(backend)
    if 'probe_gen' not in backend:
        backend['probe_gen'] = _make_probe_gen(backend)
    if 'probe_async' not in backend:
        backend['probe_async'] = _make_probe_async(backend)
    if 'probe_coro' not in backend:
        backend['probe_coro'] = _make_probe_coro(backend)
