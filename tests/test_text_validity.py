"""Tests for text-level validity checks shared by all backends:

- incremental UTF-8 decoding (multi-byte characters split across chunks,
  immediate failure on invalid sequences)
- \\u escape validation, including UTF-16 surrogate pairing
- BOM handling (compat/strict policies)
- rejection of unescaped control characters
- parser behavior after a failure (no further events, no further reads)
"""

import inspect
import io

import pytest

import ijson
from ijson import common, utils

from .support._async_common import _aiorun


BOM = b'\xef\xbb\xbf'
CHINESE_DOC = '{"greeting": "中文"}'.encode('utf-8')
CHINESE_EVENTS = [
    ('start_map', None),
    ('map_key', 'greeting'),
    ('string', '中文'),
    ('end_map', None),
]


def _parse_in_chunks(backend, chunks, **config):
    """Feeds chunks through basic_parse_coro; returns (events, exception)."""
    events = utils.sendable_list()
    coro = backend.basic_parse_coro(events, **config)
    try:
        for chunk in chunks:
            coro.send(chunk)
        coro.close()
    except Exception as e:
        return events, e
    return events, None


def _one_byte_chunks(data):
    return [data[i:i + 1] for i in range(len(data))]


def _available_backends():
    backends = []
    for name in ijson.ALL_BACKENDS:
        try:
            backends.append(ijson.get_backend(name))
        except ImportError:
            pass
    return backends


def _supports_bom_policy(backend):
    try:
        sig = inspect.signature(backend.basic_parse_basecoro)
    except (TypeError, ValueError):
        return False
    return 'bom_policy' in sig.parameters


# ---------------------------------------------------------------------------
# Incremental UTF-8 decoding
# ---------------------------------------------------------------------------

def test_multibyte_character_split_across_chunks(backend):
    """A multi-byte UTF-8 character split at every possible position must
    still decode into a single, correct string event."""
    for i in range(1, len(CHINESE_DOC)):
        events, exc = _parse_in_chunks(
            backend, [CHINESE_DOC[:i], CHINESE_DOC[i:]]
        )
        assert exc is None, 'split at %d raised %r' % (i, exc)
        assert events == CHINESE_EVENTS


def test_multibyte_character_one_byte_chunks(backend):
    events, exc = _parse_in_chunks(backend, _one_byte_chunks(CHINESE_DOC))
    assert exc is None
    assert events == CHINESE_EVENTS


def test_multibyte_character_no_replacement_char(adaptor):
    """No U+FFFD replacement character may appear in any produced event."""
    events = adaptor.basic_parse(CHINESE_DOC)
    assert events == CHINESE_EVENTS
    for event, value in events:
        if isinstance(value, str):
            assert '\ufffd' not in value


def test_invalid_utf8(adaptor):
    with pytest.raises(common.JSONError, match='byte offset 7'):
        adaptor.basic_parse(b'{"k": "\xff"}')


def test_invalid_utf8_offset_is_absolute(backend):
    """The reported offset must not depend on how the input was chunked."""
    doc = b'{"key": "value", "k2": "\xff"}'
    expected = 'byte offset %d' % doc.index(b'\xff')
    for i in range(1, len(doc)):
        events, exc = _parse_in_chunks(backend, [doc[:i], doc[i:]])
        assert isinstance(exc, common.JSONError)
        assert expected in str(exc), 'split at %d: %s' % (i, exc)


def test_invalid_utf8_offset_with_buffered_bytes(backend):
    """A sequence started in a previous chunk is reported at the position
    where the sequence started, not where the chunk boundary was."""
    events, exc = _parse_in_chunks(backend, [b'{"k": "\xe4', b'\xff'])
    assert isinstance(exc, common.JSONError)
    assert 'byte offset 7' in str(exc)


def test_truncated_utf8_at_eof(adaptor):
    with pytest.raises(common.IncompleteJSONError):
        adaptor.basic_parse(b'{"k": "\xe4\xb8')


def test_invalid_utf8_stops_events(backend):
    """No events may be produced after an invalid UTF-8 sequence."""
    events, exc = _parse_in_chunks(
        backend, [b'{"a": 1, "b": "', b'\xff', b'"}']
    )
    assert isinstance(exc, common.JSONError)
    assert events == [
        ('start_map', None),
        ('map_key', 'a'),
        ('number', 1),
        ('map_key', 'b'),
    ]


# ---------------------------------------------------------------------------
# \\u escapes and surrogates
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('doc', [
    br'"\ud800"',              # lone high surrogate
    br'"\ud800x"',             # high surrogate followed by a normal char
    br'"\ud800\u0041"',       # high surrogate followed by an escaped char
    br'"\ud800\ud800\udc00"',  # high surrogate followed by a valid pair
    br'"\udc00"',              # lone low surrogate
    br'"x\udc00"',             # low surrogate after a normal char
    br'{"\ud800": 1}',         # lone surrogate in a map key
    br'{"k": "v\udc00"}',      # lone low surrogate in a map value
])
def test_lone_surrogates_rejected(adaptor, doc):
    with pytest.raises(common.JSONError, match='[Ss]urrogate'):
        adaptor.basic_parse(doc)


def test_lone_high_surrogate_position(backend):
    events, exc = _parse_in_chunks(backend, [br'{"k": "\ud800"}'])
    assert isinstance(exc, common.JSONError)
    assert 'surrogate' in str(exc)
    assert 'at 7' in str(exc)
    # the string event for the invalid string must not have been produced
    assert events == [('start_map', None), ('map_key', 'k')]


def test_lone_low_surrogate_position(backend):
    events, exc = _parse_in_chunks(backend, [br'"\udc00"'])
    assert isinstance(exc, common.JSONError)
    assert 'at 1' in str(exc)
    assert events == []


@pytest.mark.parametrize('doc, expected', [
    (br'"\ud83d\ude00"', '\U0001f600'),
    (br'"\ud83d\udca9"', '\U0001f4a9'),
    (br'{"\ud83d\ude00": "\ud83d\udca9"}', None),
])
def test_valid_surrogate_pairs(adaptor, doc, expected):
    events = adaptor.basic_parse(doc)
    if expected is not None:
        assert ('string', expected) in events
    else:
        assert ('map_key', '\U0001f600') in events
        assert ('string', '\U0001f4a9') in events


def test_surrogate_error_does_not_echo_content(backend):
    events, exc = _parse_in_chunks(backend, [br'{"k": "sensitive\ud800"}'])
    assert isinstance(exc, common.JSONError)
    assert 'sensitive' not in str(exc)


# ---------------------------------------------------------------------------
# BOM handling
# ---------------------------------------------------------------------------

def test_bom_at_start_default_policy(adaptor):
    """By default (compat) a BOM at the very start of the input is skipped."""
    assert adaptor.basic_parse(BOM + b'[1, 2]') == [
        ('start_array', None),
        ('number', 1),
        ('number', 2),
        ('end_array', None),
    ]


def test_bom_at_start_strict_policy(adaptor):
    assert adaptor.basic_parse(BOM + b'[1]', bom_policy='strict') == [
        ('start_array', None),
        ('number', 1),
        ('end_array', None),
    ]


def test_bom_at_start_split_chunks(backend):
    """The BOM itself may be split across chunks."""
    for policy in ('compat', 'strict'):
        events, exc = _parse_in_chunks(
            backend, [BOM[:1], BOM[1:], b'[1]'], bom_policy=policy
        )
        assert exc is None
        assert events == [('start_array', None), ('number', 1), ('end_array', None)]


def test_bom_in_middle_compat(adaptor):
    """compat keeps the historical behavior: a generic parse error."""
    with pytest.raises(common.JSONError):
        adaptor.basic_parse(b'[1,' + BOM + b'2]')


def test_bom_in_middle_strict(adaptor):
    with pytest.raises(common.JSONError, match='found one at 3'):
        adaptor.basic_parse(b'[1,' + BOM + b'2]', bom_policy='strict')


def test_bom_at_end_compat(adaptor):
    with pytest.raises(common.JSONError):
        adaptor.basic_parse(b'[1]' + BOM)


def test_bom_at_end_strict(adaptor):
    with pytest.raises(common.JSONError, match='found one at 3'):
        adaptor.basic_parse(b'[1]' + BOM, bom_policy='strict')


def test_double_bom_at_start(adaptor):
    """Only one BOM is allowed at the start, in either policy."""
    with pytest.raises(common.JSONError):
        adaptor.basic_parse(BOM + BOM + b'[1]')
    with pytest.raises(common.JSONError, match='found one at 1'):
        adaptor.basic_parse(BOM + BOM + b'[1]', bom_policy='strict')


@pytest.mark.parametrize('policy', ['compat', 'strict'])
def test_bom_inside_string_is_data(adaptor, policy):
    """A BOM (U+FEFF) inside a string literal is content, not a BOM."""
    events = adaptor.basic_parse(b'["' + BOM + b'"]', bom_policy=policy)
    assert ('string', '\ufeff') in events
    events = adaptor.basic_parse(br'["\ufeff"]', bom_policy=policy)
    assert ('string', '\ufeff') in events


def test_invalid_bom_policy(backend):
    with pytest.raises(ValueError):
        backend.basic_parse_coro(utils.sendable_list(), bom_policy='bogus')


# ---------------------------------------------------------------------------
# Control characters
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('char', [
    b'\x00', b'\x01', b'\x08', b'\x09', b'\x0a', b'\x0d', b'\x1f'
])
def test_unescaped_control_characters_rejected(adaptor, char):
    with pytest.raises(common.JSONError, match='[Cc]ontrol character'):
        adaptor.basic_parse(b'{"k": "a' + char + b'b"}')


def test_control_character_position(backend):
    events, exc = _parse_in_chunks(backend, [b'{"k": "ab\x01"}'])
    assert isinstance(exc, common.JSONError)
    assert 'at 9' in str(exc)
    assert events == [('start_map', None), ('map_key', 'k')]


def test_control_character_error_does_not_echo_content(backend):
    events, exc = _parse_in_chunks(backend, [b'{"k": "sensitive\x01"}'])
    assert isinstance(exc, common.JSONError)
    assert 'sensitive' not in str(exc)


def test_escaped_control_characters_allowed(adaptor):
    events = adaptor.basic_parse(br'["\u0001\u001f"]')
    assert ('string', '\x01\x1f') in events


def test_del_is_not_a_control_character(adaptor):
    events = adaptor.basic_parse(b'["\x7f"]')
    assert ('string', '\x7f') in events


# ---------------------------------------------------------------------------
# Behavior after a failure
# ---------------------------------------------------------------------------

def test_feed_after_error_coro(backend):
    """Once a parsing session has failed it must not produce more events."""
    events = utils.sendable_list()
    coro = backend.basic_parse_coro(events)
    with pytest.raises(common.JSONError):
        coro.send(b'{"k": "\xff"}')
    count = len(events)
    with pytest.raises(StopIteration):
        coro.send(b'1')
    coro.close()
    assert len(events) == count


def test_feed_after_error_gen(backend):
    gen = backend.basic_parse_gen(io.BytesIO(b'{"k": "\xff"}'))
    with pytest.raises(common.JSONError):
        for _ in gen:
            pass
    with pytest.raises(StopIteration):
        next(gen)


class _BadUtf8File:
    """A file-like object serving an endless stream of invalid bytes."""

    def __init__(self):
        self.reads = 0

    def read(self, n=-1):
        self.reads += 1
        if not n or n < 0:
            return b''
        return b'\xff' * n


def test_no_unbounded_read_after_error(backend):
    """After a failure the source must not be read anymore."""
    f = _BadUtf8File()
    gen = backend.basic_parse_gen(f, buf_size=16)
    with pytest.raises(common.JSONError):
        next(gen)
    reads = f.reads
    for _ in range(5):
        with pytest.raises(StopIteration):
            next(gen)
    assert f.reads == reads


def test_no_unbounded_read_after_error_async(backend):
    class AsyncBadUtf8File:
        def __init__(self):
            self.reads = 0

        async def read(self, n=-1):
            self.reads += 1
            if not n or n < 0:
                return b''
            return b'\xff' * n

    f = AsyncBadUtf8File()
    reads_after_error = []

    async def run():
        it = backend.basic_parse_async(f, buf_size=16)
        with pytest.raises(common.JSONError):
            async for _ in it:
                pass
        reads_after_error.append(f.reads)
        with pytest.raises(StopAsyncIteration):
            await it.__anext__()

    _aiorun(run())
    assert f.reads == reads_after_error[0]


# ---------------------------------------------------------------------------
# Cross-backend consistency
# ---------------------------------------------------------------------------

def _consistency_corpus():
    return [
        (b'{"a": 1}', {}),
        (CHINESE_DOC, {}),
        (BOM + b'[1, 2]', {}),
        (BOM + b'[1, 2]', {'bom_policy': 'strict'}),
        (b'[1,' + BOM + b'2]', {'bom_policy': 'strict'}),
        (b'[1]' + BOM, {'bom_policy': 'strict'}),
        (b'{"k": "\xff"}', {}),
        (b'{"k": "\xe4\xb8', {}),
        (br'{"k": "\ud800"}', {}),
        (br'{"k": "\udc00"}', {}),
        (br'{"k": "\ud83d\ude00"}', {}),
        (b'{"k": "a\x01b"}', {}),
    ]


def test_consistent_events_and_errors_across_backends():
    """All available backends must produce the same events and the same
    error (type and position) for the same input."""
    backends = [
        backend for backend in _available_backends()
        if _supports_bom_policy(backend)
    ]
    assert backends, 'the python backend should always be available'
    results = {}
    for backend in backends:
        backend_results = []
        for doc, config in _consistency_corpus():
            events, exc = _parse_in_chunks(
                backend, _one_byte_chunks(doc), **config
            )
            backend_results.append(
                (list(events), type(exc).__name__ if exc else None,
                 str(exc) if exc else None)
            )
        results[backend.backend_name] = backend_results
    names = sorted(results)
    for name in names[1:]:
        assert results[name] == results[names[0]]
