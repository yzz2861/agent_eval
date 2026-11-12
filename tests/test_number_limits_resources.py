'''
Resource-focused checks for the number limits, using the pure-Python backend
so they run without any optional C dependency.'''

import io
import tracemalloc

import pytest

from ijson import numbers
from ijson.backends import python as backend


TEN_KB = 10 * 1024


@pytest.mark.parametrize("chunk_size", (16, 4096))
def test_100k_digit_integer_does_not_exhaust_memory(chunk_size):
    # the reported pathological input: a 100k-digit integer
    document = b'[' + b'1' * 100_000 + b']'
    tracemalloc.start()
    try:
        with pytest.raises(numbers.NumberLimitError):
            list(backend.basic_parse(io.BytesIO(document), buf_size=chunk_size))
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < TEN_KB * 1024


@pytest.mark.parametrize("token", (b'1e999999999', b'1e-999999999'))
def test_billion_magnitude_exponent_fails_cheaply(token):
    tracemalloc.start()
    try:
        with pytest.raises(numbers.NumberLimitError, match='exponent too large'):
            list(backend.basic_parse(token))
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < TEN_KB * 1024


def test_limit_failure_flushes_complete_events_only():
    events = []
    with pytest.raises(numbers.NumberLimitError):
        for event in backend.basic_parse(
                b'{"ok": 1, "bad": [2, 1234567]}',
                number_limits=numbers.NumberLimits(max_integer_digits=3)):
            events.append(event)
    # the bad number produces no event at all; everything before it is intact
    assert events[-1] == ('number', 2)
    assert not any(value == 1234567 for _, value in events)


def test_token_length_error_points_at_token_offset():
    document = b'{"a": ' + b'1' * 100_001 + b'}'
    with pytest.raises(numbers.NumberLimitError) as exc_info:
        list(backend.parse(document))
    err = exc_info.value
    assert err.path == 'a'
    assert err.offset == 6
