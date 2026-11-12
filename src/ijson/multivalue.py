'''
Explicit multi-value JSON stream support.

This module is deliberately separate from the regular single-value parsing
functions.  Callers opt in to it when a source contains consecutive JSON
values (NDJSON, concatenated objects, concatenated arrays, and so on).

The scanner below only hands a value to the regular parser after the complete
value has been seen.  This is important for streaming consumers: a truncated
tail value must not leak a ``start_map``/``start_array`` event before EOF.

The public entry point is :func:`multi_value_stream`, which returns an iterator
of :class:`MultiValueBatch` objects.  Each batch contains the parsed top-level
value, its parser events, and the absolute byte cursor just after the value.
'''

import inspect
import re

from ijson import common, utils


_WS = frozenset(b' \t\r\n')
_NUMBER_CHARS = frozenset(b'0123456789+-.eE')
_NUMBER_RE = re.compile(
    rb'-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\Z'
)
_NUMBER_PREFIX_RE = re.compile(
    rb'-?(?:(?:0|[1-9][0-9]*)(?:\.[0-9]*)?(?:[eE][+-]?[0-9]*)?)?\Z'
)
_LITERALS = (b'true', b'false', b'null')


def _error(message, pos):
    exc = common.JSONError('%s at %d' % (message, pos))
    exc.pos = pos
    exc.offset = pos
    return exc


def _incomplete(message, pos, eof_pos=None):
    if eof_pos is None:
        text = '%s at %d' % (message, pos)
    else:
        text = '%s at %d (EOF at %d)' % (message, pos, eof_pos)
    exc = common.IncompleteJSONError(text)
    exc.pos = pos
    exc.offset = pos
    if eof_pos is not None:
        exc.eof_pos = eof_pos
    return exc


class _Span:
    __slots__ = ('data', 'start', 'end')

    def __init__(self, data, start, end):
        self.data = data
        self.start = start
        self.end = end


class _ValueScanner:
    '''Incrementally find complete top-level JSON values in a byte stream.'''

    _GAP = 'gap'
    _CONTAINER = 'container'
    _STRING = 'string'
    _CONTAINER_STRING = 'container-string'
    _NUMBER = 'number'
    _LITERAL = 'literal'
    _SCALAR_SEP = 'scalar-separator'

    def __init__(self, start_cursor=0):
        self._buf = bytearray()
        self._base = start_cursor
        self._i = 0
        self._state = self._GAP
        self._value_start_i = None
        self._value_start = None
        self._stack = []
        self._escape = False
        self._string_open = None
        self._literal = b''
        self._literal_start = None
        self._pending_end_i = None

    def _abs(self, index):
        return self._base + index

    def _begin_value(self, ch):
        self._value_start_i = self._i
        self._value_start = self._abs(self._i)
        if ch in b'{[':
            self._stack = [(ch, self._value_start)]
            self._state = self._CONTAINER
        elif ch == 0x22:  # '"'
            self._string_open = self._value_start
            self._escape = False
            self._state = self._STRING
        elif ch in _NUMBER_CHARS:
            self._state = self._NUMBER
        elif ch in b'tfn':
            self._literal = bytes((ch,))
            self._literal_start = self._value_start
            self._state = self._LITERAL
        else:
            raise _error('Unexpected symbol %r' % bytes((ch,)), self._value_start)
        self._i += 1

    def _reset_value(self):
        self._value_start_i = None
        self._value_start = None
        self._stack = []
        self._escape = False
        self._string_open = None
        self._literal = b''
        self._literal_start = None
        self._pending_end_i = None
        self._state = self._GAP

    def _make_span(self, end_i):
        start_i = self._value_start_i
        data = bytes(self._buf[start_i:end_i])
        span = _Span(data, self._value_start, self._abs(end_i))
        return span

    def _emit_scalar(self, end_i, eof=False):
        token = bytes(self._buf[self._value_start_i:end_i])
        if self._state == self._NUMBER:
            if not _NUMBER_RE.fullmatch(token):
                if eof and _NUMBER_PREFIX_RE.fullmatch(token) and token not in (b'-',):
                    raise _incomplete('Incomplete JSON number', self._value_start, self._abs(end_i))
                raise _error('Invalid JSON number %r' % token, self._value_start)
        elif self._state == self._LITERAL:
            if token not in _LITERALS:
                if eof and any(literal.startswith(token) for literal in _LITERALS):
                    raise _incomplete('Incomplete JSON literal', self._literal_start, self._abs(end_i))
                raise _error('Invalid JSON literal %r' % token, self._literal_start)
        span = self._make_span(end_i)
        self._i = end_i
        self._reset_value()
        return span

    def _end_scalar_token(self, end_i, next_ch, eof=False):
        if next_ch is not None and next_ch not in _WS:
            raise _error(
                'Unexpected symbol %r' % bytes((next_ch,)),
                self._abs(self._i),
            )
        return self._emit_scalar(end_i, eof=eof)

    def _complete_container(self):
        return self._make_span(self._i)

    def _scan(self, eof):
        while True:
            n = len(self._buf)
            state = self._state

            if state == self._GAP:
                while self._i < n and self._buf[self._i] in _WS:
                    self._i += 1
                if self._i >= n:
                    if eof:
                        return
                    break
                self._begin_value(self._buf[self._i])
                continue

            if self._i >= n:
                if not eof:
                    break
                if state == self._CONTAINER:
                    if self._stack:
                        opener, pos = self._stack[-1]
                        raise _incomplete(
                            'Incomplete JSON content: unclosed %r' % _matching_opener(opener),
                            pos,
                            self._abs(n),
                        )
                    raise _incomplete('Incomplete JSON content', self._value_start, self._abs(n))
                if state == self._STRING:
                    raise _incomplete('Incomplete string lexeme', self._string_open, self._abs(n))
                if state == self._CONTAINER_STRING:
                    raise _incomplete('Incomplete string lexeme', self._string_open, self._abs(n))
                if state == self._NUMBER or state == self._LITERAL:
                    yield self._emit_scalar(self._i, eof=True)
                    continue
                if state == self._SCALAR_SEP:
                    end_i = self._pending_end_i
                    yield self._emit_scalar(end_i, eof=True)
                    continue
                raise _incomplete('Incomplete JSON content', self._value_start, self._abs(n))

            ch = self._buf[self._i]

            if state == self._CONTAINER:
                if ch == 0x22:  # '"'
                    self._string_open = self._abs(self._i)
                    self._escape = False
                    self._state = self._CONTAINER_STRING
                    self._i += 1
                    continue
                if ch in b'{[':
                    self._stack.append((ch, self._abs(self._i)))
                    self._i += 1
                    continue
                if ch in b'}':
                    opener, pos = self._stack[-1]
                    if opener != b'{'[0]:
                        raise _error(
                            "Mismatched closing symbol '}' (expected %r for opener at %d)" %
                            (_matching_closer(opener), pos),
                            self._abs(self._i),
                        )
                    self._stack.pop()
                    self._i += 1
                    if not self._stack:
                        span = self._complete_container()
                        self._reset_value()
                        yield span
                    continue
                if ch in b']':
                    opener, pos = self._stack[-1]
                    if opener != b'['[0]:
                        raise _error(
                            "Mismatched closing symbol ']' (expected %r for opener at %d)" %
                            (_matching_closer(opener), pos),
                            self._abs(self._i),
                        )
                    self._stack.pop()
                    self._i += 1
                    if not self._stack:
                        span = self._complete_container()
                        self._reset_value()
                        yield span
                    continue
                self._i += 1
                continue

            if state == self._CONTAINER_STRING or state == self._STRING:
                if self._escape:
                    self._escape = False
                elif ch == 0x5c:  # '\\'
                    self._escape = True
                elif ch == 0x22:
                    self._i += 1
                    if state == self._STRING:
                        self._pending_end_i = self._i
                        self._state = self._SCALAR_SEP
                    else:
                        self._state = self._CONTAINER
                    continue
                self._i += 1
                continue

            if state == self._NUMBER:
                if ch in _NUMBER_CHARS:
                    self._i += 1
                    continue
                span = self._end_scalar_token(self._i, ch)
                yield span
                continue

            if state == self._LITERAL:
                if 0x41 <= ch <= 0x5a or 0x61 <= ch <= 0x7a:
                    self._literal += bytes((ch,))
                    self._i += 1
                    continue
                token = self._literal
                if token in _LITERALS:
                    span = self._end_scalar_token(self._i, ch)
                    yield span
                    continue
                if any(literal.startswith(token) for literal in _LITERALS):
                    raise _incomplete(
                        'Incomplete JSON literal', self._literal_start, self._abs(self._i)
                    )
                raise _error('Invalid JSON literal %r' % token, self._literal_start)

            if state == self._SCALAR_SEP:
                if ch in _WS:
                    span = self._emit_scalar(self._pending_end_i, eof=False)
                    yield span
                    continue
                raise _error(
                    'Unexpected symbol %r' % bytes((ch,)),
                    self._abs(self._i),
                )

            raise _error('Unexpected parser state %r' % state, self._abs(self._i))

    def _compact(self):
        keep = self._i
        if self._value_start_i is not None:
            keep = min(keep, self._value_start_i)
        if keep:
            del self._buf[:keep]
            self._base += keep
            self._i -= keep
            if self._value_start_i is not None:
                self._value_start_i -= keep
            if self._pending_end_i is not None:
                self._pending_end_i -= keep

    def feed(self, chunk):
        if isinstance(chunk, str):
            chunk = chunk.encode('utf-8')
        elif not isinstance(chunk, (bytes, bytearray)):
            raise TypeError('multi_value_stream expects bytes or str chunks')
        if chunk:
            self._buf.extend(chunk)
        try:
            yield from self._scan(eof=False)
        finally:
            self._compact()

    def finish(self):
        try:
            yield from self._scan(eof=True)
        finally:
            self._compact()


def _matching_closer(opener):
    return '}' if opener == b'{'[0] else ']'


def _matching_opener(opener):
    return '{' if opener == b'{'[0] else '['


def _parse_backend(backend):
    if backend is None:
        import ijson
        backend = ijson.backend
    if isinstance(backend, str):
        import ijson
        return ijson.get_backend(backend)
    return backend


def _object_from_events(events, map_type=None):
    builder = common.ObjectBuilder(map_type=map_type)
    for event, value in events:
        builder.event(event, value)
    return builder.value


def _items_from_events(events, prefix, map_type=None):
    return list(utils.coros2gen(
        iter(events),
        (common.items_basecoro, (prefix,), {'map_type': map_type}),
        (common.parse_basecoro, (), {}),
    ))


def _parse_events_from_basic(events):
    return list(utils.coros2gen(
        iter(events),
        (common.parse_basecoro, (), {}),
    ))


def _events_for_span(backend, span, use_float=False, allow_comments=False):
    kwargs = {'use_float': use_float}
    if allow_comments:
        kwargs['allow_comments'] = True
    try:
        return list(backend.basic_parse(span.data, **kwargs))
    except common.JSONError as exc:
        if not hasattr(exc, 'pos'):
            match = re.search(r' at (\d+)', str(exc))
            if match:
                pos = span.start + int(match.group(1))
                exc.pos = pos
                exc.offset = pos
                exc.args = (
                    '%s at %d%s' % (
                        str(exc)[:match.start()], pos, str(exc)[match.end():]
                    ),
                )
        raise


def _invoke_callback(callback, batch):
    try:
        signature = inspect.signature(callback)
    except (TypeError, ValueError):
        signature = None
    if signature is not None:
        try:
            signature.bind(batch)
        except TypeError:
            try:
                signature.bind(batch.value, batch.cursor)
            except TypeError:
                try:
                    signature.bind(batch.value, batch.events, batch.cursor)
                except TypeError:
                    pass
                else:
                    return callback(batch.value, batch.events, batch.cursor)
            else:
                return callback(batch.value, batch.cursor)
    return callback(batch)


class MultiValueBatch:
    '''One complete top-level JSON value and the cursor after it.'''

    __slots__ = (
        'value', 'events', 'parse_events', 'start', 'end', 'cursor', 'index',
        'data',
    )

    def __init__(self, value, events, start, end, index, data):
        self.value = value
        self.events = events
        self.parse_events = _parse_events_from_basic(events)
        self.start = start
        self.end = end
        self.cursor = end
        self.index = index
        self.data = data

    @property
    def position(self):
        return self.cursor

    @property
    def input_cursor(self):
        return self.cursor

    @property
    def offset(self):
        return self.cursor

    def __iter__(self):
        yield self.value
        yield self.cursor

    def __len__(self):
        return 2

    def __getitem__(self, key):
        if isinstance(key, str):
            return getattr(self, key)
        return (self.value, self.cursor)[key]

    def items(self, prefix='', map_type=None):
        return _items_from_events(self.events, prefix, map_type=map_type)

    def __repr__(self):
        return 'MultiValueBatch(value=%r, cursor=%r)' % (self.value, self.cursor)


class MultiValueStream:
    '''Iterator over complete values in a multi-value JSON byte stream.'''

    def __init__(self, source, buf_size=64 * 1024, *,
                 backend=None, use_float=False, allow_comments=False,
                 map_type=None, callback=None, on_batch=None, on_value=None,
                 start_cursor=0):
        self._chunks = _iter_chunks(source, buf_size=buf_size)
        self._scanner = _ValueScanner(start_cursor=start_cursor)
        self._pending = []
        self._pending_error = None
        self._source_exhausted = False
        self._backend = _parse_backend(backend)
        self._use_float = use_float
        self._allow_comments = allow_comments
        self._map_type = map_type
        self._callbacks = [
            callback for callback in (callback, on_batch, on_value)
            if callback is not None
        ]
        self.cursor = start_cursor
        self.count = 0
        self.last_batch = None

    def __iter__(self):
        return self

    @property
    def input_cursor(self):
        return self.cursor

    @property
    def offset(self):
        return self.cursor

    def tell(self):
        '''Return the byte cursor just after the last committed value.'''
        return self.cursor

    def _collect(self, spans):
        try:
            for span in spans:
                self._pending.append(span)
        except Exception as exc:
            self._pending_error = exc

    def _make_events(self, span):
        return _events_for_span(
            self._backend, span, self._use_float, self._allow_comments
        )

    def _make_batch(self, span):
        events = self._make_events(span)
        value = _object_from_events(events, self._map_type)
        batch = MultiValueBatch(
            value, events, span.start, span.end, self.count, span.data
        )
        self.count += 1
        self.cursor = batch.cursor
        self.last_batch = batch
        for callback in self._callbacks:
            _invoke_callback(callback, batch)
        return batch

    def __next__(self):
        while not self._pending:
            if self._pending_error is not None:
                exc = self._pending_error
                self._pending_error = None
                raise exc
            if self._source_exhausted:
                raise StopIteration
            try:
                chunk = next(self._chunks)
            except StopIteration:
                self._source_exhausted = True
                self._collect(self._scanner.finish())
                continue
            if chunk:
                self._collect(self._scanner.feed(chunk))
        return self._make_batch(self._pending.pop(0))


def _iter_chunks(source, buf_size=64 * 1024):
    if isinstance(source, (bytes, bytearray, str)):
        yield source
        return
    if hasattr(source, 'read'):
        while True:
            chunk = source.read(buf_size)
            if not chunk:
                return
            yield chunk
    if hasattr(source, '__aiter__'):
        raise TypeError(
            'multi_value_stream does not support async sources; '
            'use multi_value_stream_async instead'
        )
    if hasattr(source, '__iter__'):
        yield from source
        return
    raise TypeError('Unsupported source type: %r' % (type(source),))


def multi_value_stream(source, buf_size=64 * 1024, *, backend=None,
                       use_float=False, allow_comments=False, map_type=None,
                       callback=None, on_batch=None, on_value=None,
                       start_cursor=0):
    '''Return an iterator over complete values in a multi-value byte stream.

    ``source`` may be bytes, a file-like object, or an iterable of byte/str
    chunks.  Values are emitted only after they are complete; an incomplete
    final value raises ``IncompleteJSONError`` at EOF without ever exposing
    the partial value's events.

    Each yielded :class:`MultiValueBatch` has ``value``, ``events`` and
    ``cursor`` attributes.  ``cursor`` is the absolute byte offset just after
    the value, suitable for checkpointing and resuming the remaining stream.
    '''
    return MultiValueStream(
        source,
        buf_size=buf_size,
        backend=backend,
        use_float=use_float,
        allow_comments=allow_comments,
        map_type=map_type,
        callback=callback,
        on_batch=on_batch,
        on_value=on_value,
        start_cursor=start_cursor,
    )


def consume_multi_values(source, callback, *args, **kwargs):
    '''Consume a multi-value stream, invoking ``callback(batch)`` per value.

    Returns the final byte cursor after the last complete value.
    '''
    stream = MultiValueStream(source, *args, callback=callback, **kwargs)
    for _ in stream:
        pass
    return stream.cursor


async def _iter_chunks_async(source, buf_size=64 * 1024):
    if isinstance(source, (bytes, bytearray, str)):
        yield source
        return
    if hasattr(source, 'read'):
        while True:
            chunk = source.read(buf_size)
            if inspect.isawaitable(chunk):
                chunk = await chunk
            if not chunk:
                return
            yield chunk
    if hasattr(source, '__aiter__'):
        async for chunk in source:
            yield chunk
        return
    if hasattr(source, '__iter__'):
        for chunk in source:
            yield chunk
        return
    raise TypeError('Unsupported source type: %r' % (type(source),))


class AsyncMultiValueStream:
    '''Async equivalent of :class:`MultiValueStream`.'''

    def __init__(self, source, buf_size=64 * 1024, *,
                 backend=None, use_float=False, allow_comments=False,
                 map_type=None, callback=None, on_batch=None, on_value=None,
                 start_cursor=0):
        self._chunks = _iter_chunks_async(source, buf_size=buf_size)
        self._scanner = _ValueScanner(start_cursor=start_cursor)
        self._pending = []
        self._pending_error = None
        self._source_exhausted = False
        self._backend = _parse_backend(backend)
        self._use_float = use_float
        self._allow_comments = allow_comments
        self._map_type = map_type
        self._callbacks = [
            callback for callback in (callback, on_batch, on_value)
            if callback is not None
        ]
        self.cursor = start_cursor
        self.count = 0
        self.last_batch = None

    def __aiter__(self):
        return self

    @property
    def input_cursor(self):
        return self.cursor

    @property
    def offset(self):
        return self.cursor

    def tell(self):
        return self.cursor

    def _collect(self, spans):
        try:
            for span in spans:
                self._pending.append(span)
        except Exception as exc:
            self._pending_error = exc

    def _make_batch(self, span):
        events = _events_for_span(
            self._backend, span, self._use_float, self._allow_comments
        )
        value = _object_from_events(events, self._map_type)
        batch = MultiValueBatch(
            value, events, span.start, span.end, self.count, span.data
        )
        self.count += 1
        self.cursor = batch.cursor
        self.last_batch = batch
        for callback in self._callbacks:
            _invoke_callback(callback, batch)
        return batch

    async def __anext__(self):
        while not self._pending:
            if self._pending_error is not None:
                exc = self._pending_error
                self._pending_error = None
                raise exc
            if self._source_exhausted:
                raise StopAsyncIteration
            try:
                chunk = await self._chunks.__anext__()
            except StopAsyncIteration:
                self._source_exhausted = True
                self._collect(self._scanner.finish())
                continue
            if chunk:
                self._collect(self._scanner.feed(chunk))
        return self._make_batch(self._pending.pop(0))


def multi_value_stream_async(source, buf_size=64 * 1024, *, backend=None,
                             use_float=False, allow_comments=False,
                             map_type=None, callback=None, on_batch=None,
                             on_value=None, start_cursor=0):
    '''Async variant of :func:`multi_value_stream`.'''
    return AsyncMultiValueStream(
        source,
        buf_size=buf_size,
        backend=backend,
        use_float=use_float,
        allow_comments=allow_comments,
        map_type=map_type,
        callback=callback,
        on_batch=on_batch,
        on_value=on_value,
        start_cursor=start_cursor,
    )


async def consume_multi_values_async(source, callback, *args, **kwargs):
    '''Async variant of :func:`consume_multi_values`.'''
    stream = AsyncMultiValueStream(source, *args, callback=callback, **kwargs)
    async for _ in stream:
        pass
    return stream.cursor


def multi_value_items(source, prefix='', map_type=None, *args, **kwargs):
    '''Yield one batch for each item found at ``prefix`` in each top-level value.'''
    kwargs.pop('map_type', None)
    callbacks = [
        callback for callback in (
            kwargs.pop('callback', None),
            kwargs.pop('on_batch', None),
            kwargs.pop('on_value', None),
        ) if callback is not None
    ]
    stream = MultiValueStream(source, *args, map_type=map_type, **kwargs)
    for batch in stream:
        for item in batch.items(prefix, map_type=map_type):
            item_batch = MultiValueBatch(
                item, batch.events, batch.start, batch.end, batch.index, batch.data
            )
            for callback in callbacks:
                _invoke_callback(callback, item_batch)
            yield item_batch


async def multi_value_items_async(source, prefix='', map_type=None, *args, **kwargs):
    '''Async variant of :func:`multi_value_items`.'''
    kwargs.pop('map_type', None)
    callbacks = [
        callback for callback in (
            kwargs.pop('callback', None),
            kwargs.pop('on_batch', None),
            kwargs.pop('on_value', None),
        ) if callback is not None
    ]
    stream = AsyncMultiValueStream(source, *args, map_type=map_type, **kwargs)
    async for batch in stream:
        for item in batch.items(prefix, map_type=map_type):
            item_batch = MultiValueBatch(
                item, batch.events, batch.start, batch.end, batch.index, batch.data
            )
            for callback in callbacks:
                _invoke_callback(callback, item_batch)
            yield item_batch


def multi_value_parse(source, *args, **kwargs):
    '''Yield one batch per top-level value with parsed (prefixed) events available.'''
    return multi_value_stream(source, *args, **kwargs)


# Convenience aliases for callers using verb-first naming.
items_multi = multi_value_items
items_multi_async = multi_value_items_async
parse_multi = multi_value_parse
stream_values = multi_value_stream
items_stream = multi_value_items
multi_values = multi_value_stream
