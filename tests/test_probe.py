import io

import pytest

import ijson
from ijson import probe, ProbeStatus
from ijson.backends import python as python_backend


JSON = b'''{
  "docs": [
    {"meta": {"key": "value"}},
    {"meta": [1, 2, 3]},
    {"other": "a plain string value"}
  ],
  "tail": "end"
}'''


class RawStream(io.RawIOBase):
    '''An unbuffered, non-seekable stream returning short reads.'''

    def __init__(self, data, chunk=5):
        self._data = data
        self._chunk = chunk
        self._pos = 0

    def readable(self):
        return True

    def read(self, n=-1):
        if self._pos >= len(self._data):
            return b''
        if n is None or n < 0 or n > self._chunk:
            n = self._chunk
        data = self._data[self._pos:self._pos + n]
        self._pos += len(data)
        return data


def test_found_and_excluded_multiple_prefixes():
    result = probe(JSON, 'docs.item.meta', 'missing')
    assert result.status_of('docs.item.meta') is ProbeStatus.FOUND
    assert result.status_of('missing') is ProbeStatus.EXCLUDED
    assert result.ended_naturally
    assert not result.budget_exhausted
    assert result.complete
    assert result.bytes_read == len(JSON)


def test_prefixes_as_single_list():
    result = probe(JSON, ['docs.item.meta', 'missing'])
    assert result.prefixes == ('docs.item.meta', 'missing')


def test_nested_object_prefix():
    result = probe(JSON, 'docs.item.meta.key')
    assert result.status_of('docs.item.meta.key') is ProbeStatus.FOUND
    assert result['docs.item.meta.key'].event == ('string', 'value')


def test_field_spanning_chunks_is_found():
    # A tiny buf_size splits keys and values across many reads; the
    # conclusion must be the same as with a large buffer.
    for buf_size in (1, 2, 3, 7, 64 * 1024):
        result = probe(JSON, 'docs.item.meta.key', 'missing', buf_size=buf_size)
        assert result.status_of('docs.item.meta.key') is ProbeStatus.FOUND
        assert result.status_of('missing') is ProbeStatus.EXCLUDED


def test_excluded_is_stable_across_buf_sizes():
    for buf_size in (1, 4, 16, 64 * 1024):
        result = probe(JSON, 'nope', buf_size=buf_size)
        assert result.status_of('nope') is ProbeStatus.EXCLUDED
        assert result.ended_naturally


def test_budget_exhaustion_stays_pending_across_buf_sizes():
    budget = JSON.index(b'meta')  # cuts before the first managed field
    for buf_size in (1, 4, 16, 64 * 1024):
        result = probe(JSON, 'docs.item.meta', 'missing',
                       max_bytes=budget, buf_size=buf_size)
        assert result.status_of('docs.item.meta') is ProbeStatus.PENDING
        assert result.status_of('missing') is ProbeStatus.PENDING
        assert result.budget_exhausted
        assert not result.ended_naturally
        assert not result.complete
        assert result.bytes_read == budget


def test_budget_equal_to_stream_length_cannot_confirm_eof():
    result = probe(JSON, 'missing', max_bytes=len(JSON))
    assert result.status_of('missing') is ProbeStatus.PENDING
    result = probe(JSON, 'missing', max_bytes=len(JSON) + 1)
    assert result.status_of('missing') is ProbeStatus.EXCLUDED


def test_found_before_budget_cut():
    budget = JSON.index(b'"key"') + 5
    result = probe(JSON, 'docs.item.meta', 'tail', max_bytes=budget)
    assert result.status_of('docs.item.meta') is ProbeStatus.FOUND
    assert result.status_of('tail') is ProbeStatus.PENDING


def test_unlimited_budget_by_default():
    result = probe(JSON, 'missing')
    assert result.budget is None
    assert result.status_of('missing') is ProbeStatus.EXCLUDED


def test_unbuffered_stream_source():
    result = probe(RawStream(JSON), 'docs.item.meta', 'missing', buf_size=64 * 1024)
    assert result.status_of('docs.item.meta') is ProbeStatus.FOUND
    assert result.status_of('missing') is ProbeStatus.EXCLUDED
    assert result.bytes_read == len(JSON)


def test_unbuffered_stream_with_budget():
    budget = 10
    result = probe(RawStream(JSON), 'missing', max_bytes=budget)
    assert result.status_of('missing') is ProbeStatus.PENDING
    assert result.bytes_read == budget


def test_iterable_source():
    chunks = [JSON[i:i + 6] for i in range(0, len(JSON), 6)]
    result = probe(iter(chunks), 'docs.item.meta', 'missing')
    assert result.status_of('docs.item.meta') is ProbeStatus.FOUND
    assert result.status_of('missing') is ProbeStatus.EXCLUDED


def test_str_source():
    result = probe(JSON.decode('utf-8'), 'docs.item.meta', 'missing')
    assert result.status_of('docs.item.meta') is ProbeStatus.FOUND
    assert result.status_of('missing') is ProbeStatus.EXCLUDED


def test_explicit_backend():
    result = probe(JSON, 'missing', backend=python_backend)
    assert result.status_of('missing') is ProbeStatus.EXCLUDED


def test_early_stop_when_all_found():
    result = probe(JSON, 'docs.item.meta', buf_size=8)
    assert result.complete
    assert not result.ended_naturally
    assert not result.budget_exhausted
    assert result.bytes_read < len(JSON)


def test_occurrences_are_counted():
    result = probe(JSON, 'docs.item.meta', 'tail')
    assert result['docs.item.meta'].occurrences == 2


def test_unchecked_prefix_outside_selection():
    result = probe(JSON, 'docs.item.meta')
    assert result.status_of('tail') is ProbeStatus.UNCHECKED
    explanation = result.explain('tail')
    assert 'not part of the probe selection' in explanation
    assert 'unchecked' in explanation


def test_explain_mentions_completion_condition():
    result = probe(JSON, 'docs.item.meta', 'missing')
    text = result.explain()
    assert 'natural end' in text
    assert 'docs.item.meta' in text
    result = probe(JSON, 'missing', max_bytes=4)
    assert 'budget' in result.explain('missing')
    assert 'pending' in result.explain('missing')


def test_requires_at_least_one_prefix():
    with pytest.raises(ValueError):
        probe(JSON)


def test_rejects_async_source():
    class AsyncFile:
        async def read(self, n=-1):
            return b''

    with pytest.raises(ValueError):
        probe(AsyncFile(), 'missing')


def test_rejects_unknown_source():
    with pytest.raises(ValueError):
        probe(42, 'missing')


def test_truncated_json_without_budget_raises():
    with pytest.raises(ijson.IncompleteJSONError):
        probe(JSON[:10], 'missing')
