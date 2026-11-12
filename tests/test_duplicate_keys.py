"""Tests for the explicit duplicate map-key policies."""

import collections

import pytest

from ijson import DuplicateKeyError


DUPLICATE_JSON = b'{"rules":{"action":"old","enabled":true,"action":"new"}}'


def test_items_first_last_and_key_order(adaptor):
    assert adaptor.items(DUPLICATE_JSON, 'rules', duplicate_keys='first') == [
        {'action': 'old', 'enabled': True}
    ]
    result = adaptor.items(DUPLICATE_JSON, 'rules', duplicate_keys='last')
    assert result == [{'action': 'new', 'enabled': True}]
    assert list(result[0]) == ['action', 'enabled']


def test_items_reject_reports_path_and_positions(adaptor):
    with pytest.raises(DuplicateKeyError) as exc:
        adaptor.items(DUPLICATE_JSON, 'rules', duplicate_keys='reject')
    error = exc.value
    assert error.key == 'action'
    assert error.path == 'rules.action'
    assert error.map_path == 'rules'
    assert error.first_position == 4
    assert error.second_position == 8
    assert 'rules.action' in str(error)


def test_nested_map_scopes_are_independent(adaptor):
    json = b'{"a":{"x":1,"x":2},"b":{"x":3,"x":4}}'
    assert adaptor.items(json, '', duplicate_keys='first') == [
        {'a': {'x': 1}, 'b': {'x': 3}}
    ]
    assert adaptor.items(json, '', duplicate_keys='last') == [
        {'a': {'x': 2}, 'b': {'x': 4}}
    ]


def test_objects_inside_arrays_do_not_share_duplicate_scopes(adaptor):
    json = b'{"items":[{"x":1,"x":2},{"x":3,"x":4}]}'
    assert adaptor.items(json, 'items.item', duplicate_keys='first') == [
        {'x': 1}, {'x': 3}
    ]
    assert adaptor.items(json, 'items.item', duplicate_keys='last') == [
        {'x': 2}, {'x': 4}
    ]


def test_duplicate_values_can_be_containers(adaptor):
    json = b'{"rules":{"action":{"old":1},"action":{"new":2}}}'
    assert adaptor.items(json, 'rules', duplicate_keys='first') == [
        {'action': {'old': 1}}
    ]
    assert adaptor.items(json, 'rules', duplicate_keys='last') == [
        {'action': {'new': 2}}
    ]
    with pytest.raises(DuplicateKeyError):
        list(adaptor.items(json, 'rules', duplicate_keys='reject'))


def test_escaped_and_empty_keys(adaptor):
    json = b'{"rules":{"a":1,"\\u0061":2,"":3,"":4}}'
    assert adaptor.items(json, 'rules', duplicate_keys='first') == [
        {'a': 1, '': 3}
    ]
    assert adaptor.items(json, 'rules', duplicate_keys='last') == [
        {'a': 2, '': 4}
    ]
    with pytest.raises(DuplicateKeyError) as exc:
        adaptor.items(json, 'rules', duplicate_keys='reject')
    assert exc.value.path == 'rules.a'


def test_visual_unicode_homographs_are_distinct(adaptor):
    json = '{"rules":{"\u00e9":1,"e\u0301":2}}'.encode('utf-8')
    assert adaptor.items(json, 'rules', duplicate_keys='reject') == [
        {'\u00e9': 1, 'e\u0301': 2}
    ]


def test_duplicate_key_across_chunks(backend):
    json = b'{"rules":{"action":"old","action":"new"}}'
    assert list(backend.items(
        json, 'rules', duplicate_keys='first', buf_size=1
    )) == [{'action': 'old'}]
    assert list(backend.items(
        json, 'rules', duplicate_keys='last', buf_size=1
    )) == [{'action': 'new'}]
    assert list(backend.kvitems(
        b'{"a":1,"b":2,"a":3}', '', duplicate_keys='last', buf_size=1
    )) == [('a', 3), ('b', 2)]


def test_kvitems_applies_policy_to_member_values(adaptor):
    json = b'{"rules":{"rule":{"action":"old","action":"new"}}}'
    assert adaptor.kvitems(json, 'rules', duplicate_keys='first') == [
        ('rule', {'action': 'old'})
    ]
    assert adaptor.kvitems(json, 'rules', duplicate_keys='last') == [
        ('rule', {'action': 'new'})
    ]
    with pytest.raises(DuplicateKeyError) as exc:
        adaptor.kvitems(json, 'rules', duplicate_keys='reject')
    assert exc.value.path == 'rules.rule.action'


def test_kvitems_rejects_duplicate_members_at_prefix(adaptor):
    json = b'{"rules":{"action":"old","action":"new"}}'
    with pytest.raises(DuplicateKeyError) as exc:
        adaptor.kvitems(json, 'rules', duplicate_keys='reject')
    assert exc.value.path == 'rules.action'
    # first/last choose the member value that is projected at the selected map.
    assert adaptor.kvitems(json, 'rules', duplicate_keys='first') == [
        ('action', 'old')
    ]
    assert adaptor.kvitems(json, 'rules', duplicate_keys='last') == [
        ('action', 'new')
    ]


def test_basic_parse_keeps_raw_events_for_every_policy(backend):
    raw = list(backend.basic_parse(
        DUPLICATE_JSON, duplicate_keys='reject'
    ))
    keys = [value for event, value in raw if event == 'map_key']
    assert keys == ['rules', 'action', 'enabled', 'action']
    assert len(raw) == 11


def test_custom_map_type_with_duplicates(adaptor):
    result = adaptor.items(
        DUPLICATE_JSON, 'rules', map_type=collections.OrderedDict,
        duplicate_keys='last'
    )[0]
    assert result['action'] == 'new'
    assert list(result) == ['action', 'enabled']


def test_invalid_policy_is_rejected(adaptor):
    with pytest.raises(ValueError):
        adaptor.items(DUPLICATE_JSON, 'rules', duplicate_keys='unknown')


def test_policy_aliases(adaptor):
    assert adaptor.items(
        DUPLICATE_JSON, 'rules', duplicate_key_policy='first'
    ) == [{'action': 'old', 'enabled': True}]
    assert adaptor.kvitems(
        b'{"rules":{"rule":{"a":1,"a":2}}}', 'rules',
        duplicate_key_strategy='last'
    ) == [('rule', {'a': 2})]


def test_basic_parse_accepts_and_ignores_policy_aliases(adaptor):
    events = adaptor.basic_parse(
        DUPLICATE_JSON, duplicate_key_policy='reject'
    )
    assert [value for event, value in events if event == 'map_key'] == [
        'rules', 'action', 'enabled', 'action'
    ]
