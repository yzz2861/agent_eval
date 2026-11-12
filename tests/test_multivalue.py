import pytest

import ijson
from ijson import common


def _run(data, buf_size=64 * 1024):
    stream = ijson.multi_value_stream(data, buf_size=buf_size)
    batches = list(stream)
    return batches, stream.cursor


def test_two_objects_batches_and_callback_count():
    committed = []
    stream = ijson.multi_value_stream(
        b'{"a": 1}{"b": 2}',
        callback=lambda batch: committed.append((batch.value, batch.cursor)),
    )
    assert [({'a': 1}, 8), ({'b': 2}, 16)] == [tuple(batch) for batch in stream]
    assert [({'a': 1}, 8), ({'b': 2}, 16)] == committed
    assert 2 == stream.count
    assert 16 == stream.cursor


def test_concatenated_arrays_are_separate_values():
    batches, cursor = _run(b'[1, 2][3, 4]')
    assert [[1, 2], [3, 4]] == [batch.value for batch in batches]
    assert [6, 12] == [batch.cursor for batch in batches]
    assert 12 == cursor


def test_objects_inside_arrays_are_not_new_top_level_values():
    batches, cursor = _run(b'[{"a": 1}, {"b": 2}]{"c": 3}')
    assert [[{'a': 1}, {'b': 2}], {'c': 3}] == [batch.value for batch in batches]
    assert 2 == len(batches)
    assert 28 == cursor


@pytest.mark.parametrize('data', [
    b'{"a": 1}{"b": 2}',
    b'[1, 2][3, 4]',
    b' "a"  true  null ',
])
def test_cross_chunk_boundaries(data):
    whole, whole_cursor = _run(data)
    chunked, chunked_cursor = _run(data, buf_size=1)
    assert [(batch.value, batch.cursor) for batch in whole] == [
        (batch.value, batch.cursor) for batch in chunked
    ]
    assert whole_cursor == chunked_cursor


def test_incomplete_tail_is_reported_only_at_eof():
    committed = []
    stream = ijson.multi_value_stream(
        b'{"a": 1}{"b": ', callback=lambda batch: committed.append(batch.value)
    )
    with pytest.raises(common.IncompleteJSONError) as excinfo:
        list(stream)
    assert [{'a': 1}] == committed
    assert 8 == stream.cursor
    assert 8 == excinfo.value.pos
    assert 0x7b == stream.last_batch.data[0]


def test_incomplete_tail_events_are_only_for_complete_values():
    events = ijson.basic_parse(b'{"a": 1}{"b": ', multiple_values=True)
    collected = []
    with pytest.raises(common.IncompleteJSONError):
        for event in events:
            collected.append(event)
    assert [
        ('start_map', None),
        ('map_key', 'a'),
        ('number', 1),
        ('end_map', None),
    ] == collected


@pytest.mark.parametrize(
    'data, pos',
    (
        (b'{"a": 1}x', 8),
        (b'{"a": 1} :', 9),
        (b'{"a": 1} tru', 9),
        (b'{"a": 1} "x""y"', 12),
    ),
)
def test_invalid_concatenation_offsets(data, pos):
    stream = ijson.multi_value_stream(data)
    with pytest.raises(common.JSONError) as excinfo:
        list(stream)
    assert pos == excinfo.value.pos
    assert 1 == stream.count
    assert 8 == stream.cursor


def test_empty_input():
    batches, cursor = _run(b'')
    assert [] == batches
    assert 0 == cursor


def test_whitespace_only_input():
    batches, cursor = _run(b' \n\t\r  ')
    assert [] == batches
    assert 0 == cursor


def test_cursor_positions_include_only_complete_values():
    data = b'  {"a": 1}  [2, 3]\n'
    batches, cursor = _run(data, buf_size=3)
    assert [10, 18] == [batch.cursor for batch in batches]
    assert 18 == cursor


def test_cursor_can_be_used_to_resume_reading():
    data = b'{"a": 1}\n{"b": 2}'
    first = next(ijson.multi_value_stream(data))
    resumed = ijson.multi_value_stream(
        data[first.cursor:], start_cursor=first.cursor
    )
    remaining = list(resumed)
    assert [{'b': 2}] == [batch.value for batch in remaining]
    assert len(data) == resumed.cursor


def test_existing_items_api_can_request_stream_batches():
    batches = list(ijson.items(
        b'{"docs": [{"id": 1}, {"id": 2}]}{"docs": [{"id": 3}]}',
        'docs.item.id',
        with_cursor=True,
    ))
    assert [1, 2, 3] == [batch.value for batch in batches]
    assert [32, 32, 53] == [batch.cursor for batch in batches]


def test_scalar_concatenation_policy():
    batches, _ = _run(b'12')
    assert [12] == [batch.value for batch in batches]

    batches, cursor = _run(b'1 2')
    assert [1, 2] == [batch.value for batch in batches]
    assert 3 == cursor

    batches, cursor = _run(b'"a" "b"')
    assert ['a', 'b'] == [batch.value for batch in batches]
    assert 7 == cursor


def test_adjacent_scalars_without_separator_are_rejected():
    for data, pos in ((b'"a""b"', 3), (b'1{}', 1), (b'true{}', 4)):
        with pytest.raises(common.JSONError) as excinfo:
            list(ijson.multi_value_stream(data))
        assert pos == excinfo.value.pos


def test_unclosed_nested_structure_offset():
    stream = ijson.multi_value_stream(b'{"a": 1} {"b": [1, 2')
    with pytest.raises(common.IncompleteJSONError) as excinfo:
        list(stream)
    assert 1 == stream.count
    assert 15 == excinfo.value.pos
