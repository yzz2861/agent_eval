import asyncio
import io

import pytest

import ijson
from ijson import common


DATA = b'{"outer": {"alpha": {"beta": 1}}, "alpha": {"beta": 2}, "items": [{"id": 1}, {"id": 2}]}'


@pytest.mark.parametrize('buf_size', [1, 2, 3, 5, 7, 13, 64 * 1024])
def test_absent_prefix_is_excluded_only_after_complete_read(buf_size):
    result = ijson.probe(DATA, ['alpha.missing'], buf_size=buf_size)
    assert result.complete
    assert result.completion == 'natural_end'
    assert result.bytes_read == len(DATA)
    assert result['alpha.missing'].status == 'excluded'
    assert not result['alpha.missing'].found


@pytest.mark.parametrize('buf_size', [1, 2, 3, 5, 7, 13, 64 * 1024])
def test_partial_read_keeps_absent_prefix_pending(buf_size):
    result = ijson.probe(DATA, ['alpha.missing'], max_bytes=20, buf_size=buf_size)
    assert result.exhausted
    assert result.completion == 'budget_exhausted'
    assert result.bytes_read == 20
    assert result['alpha.missing'].status == 'pending'
    assert not result['alpha.missing'].complete


@pytest.mark.parametrize('buf_size', [1, 2, 3, 5, 7, 13, 64 * 1024])
def test_budget_equal_to_complete_range_is_a_natural_end(buf_size):
    result = ijson.probe(DATA, ['alpha.missing'], max_bytes=len(DATA),
                         buf_size=buf_size)
    assert result.natural_end
    assert result['alpha.missing'].status == 'excluded'


def test_multiple_prefixes_are_reported_separately():
    result = ijson.probe(DATA, ['alpha.beta', 'items.item.id', 'absent'])
    assert result['alpha.beta'].status == 'found'
    assert result['items.item.id'].status == 'found'
    assert result['absent'].status == 'excluded'
    assert result.completion == 'natural_end'
    assert set(result.found_prefixes) == {'alpha.beta', 'items.item.id'}
    assert result['alpha.beta'].nested


def test_selected_scope_marks_unqueried_fields_unchecked():
    result = ijson.probe(DATA, ['alpha.beta', 'items'], select=['alpha.beta'])
    assert result['alpha.beta'].status == 'found'
    assert result['items'].status == 'unchecked'
    assert result['other'].status == 'unchecked'
    assert result['items'].reason == 'outside_selected_prefixes'


def test_prefix_spanning_chunks_is_found_and_explained():
    result = ijson.probe(DATA, ['alpha.beta'], buf_size=2)
    field = result['alpha.beta']
    assert field.status == 'found'
    assert field.crosses_chunks
    assert 'crosses_chunks' in field.explanation


def test_exact_prefix_does_not_match_same_name_at_another_level():
    result = ijson.probe(DATA, ['alpha.beta'])
    assert result['alpha.beta'].status == 'found'
    assert [event[2] for event in result['alpha.beta'].events] == [2]


def test_unbuffered_chunk_iterable():
    chunks = (DATA[i:i + 3] for i in range(0, len(DATA), 3))
    result = ijson.probe(chunks, ['alpha.beta'], max_bytes=len(DATA))
    assert result.natural_end
    assert result['alpha.beta'].status == 'found'

    chunks = (DATA[i:i + 3] for i in range(0, len(DATA), 3))
    result = ijson.probe(chunks, ['alpha.missing'], max_bytes=12)
    assert result.completion == 'budget_exhausted'
    assert result['alpha.missing'].status == 'pending'


def test_probe_from_parse_events():
    events = ijson.parse(io.BytesIO(DATA))
    result = ijson.probe(events, ['alpha.beta'])
    assert result.natural_end
    assert result['alpha.beta'].status == 'found'
    assert result.bytes_read == 0


def test_alias_arguments():
    result = ijson.probe(DATA, prefix='alpha.beta', read_limit=len(DATA))
    assert result['alpha.beta'].status == 'found'
    result = ijson.probe(DATA, fields=['alpha.beta'], select=['alpha.beta'])
    assert result['alpha.beta'].found


def test_values_and_explanations():
    result = ijson.probe(DATA, ['alpha.beta'])
    assert result['alpha.beta'].values == [2]
    assert result.as_dict()['completion'] == 'natural_end'
    assert 'natural_end' in result.explanation


def test_items_accepts_multiple_prefixes():
    assert list(ijson.items(DATA, ['alpha.beta', 'outer.alpha.beta'])) == [1, 2]
    assert list(ijson.kvitems(b'{"a": {"x": 1}, "b": {"y": 2}}', ['a', 'b'])) == [('x', 1), ('y', 2)]


def test_async_probe_file_and_iterable():
    class AsyncReader:
        def __init__(self, data):
            self.data = io.BytesIO(data)

        async def read(self, n=-1):
            await asyncio.sleep(0)
            return self.data.read(n)

    async def chunks():
        for i in range(0, len(DATA), 2):
            yield DATA[i:i + 2]

    async def main():
        result = await ijson.probe(AsyncReader(DATA), ['alpha.beta'], buf_size=2)
        assert result.natural_end
        assert result['alpha.beta'].found
        assert result['alpha.beta'].crosses_chunks

        result = await ijson.probe(chunks(), ['alpha.missing'], max_bytes=12)
        assert result.completion == 'budget_exhausted'
        assert result['alpha.missing'].status == 'pending'

    asyncio.run(main())


def test_probe_coro_reports_after_close():
    results = []
    coro = ijson.probe_coro(results.append, ['alpha.beta'])
    for i in range(0, len(DATA), 4):
        coro.send(DATA[i:i + 4])
    coro.close()
    assert len(results) == 1
    assert results[0]['alpha.beta'].status == 'found'
    assert results[0].completion == 'natural_end'


def test_key_seen_before_value_is_confirmed_but_completion_remains_budgeted():
    data = b'{"secret": "a very long value"}'
    result = ijson.probe(data, ['secret'], max_bytes=len(b'{"secret"'))
    field = result['secret']
    assert field.found
    assert field.key_seen
    assert result.completion == 'budget_exhausted'


def test_from_iter_reader_is_bounded_by_probe():
    chunks = [b'{"alpha":', b' {"beta":', b' 1}}']
    reader = ijson.from_iter(iter(chunks))
    result = ijson.probe(reader, ['alpha.beta'], max_bytes=9, buf_size=2)
    assert result.completion == 'budget_exhausted'
    assert result['alpha.beta'].status == 'pending'
    assert result.bytes_read == 9
