import pytest

import yaml


class LenientSafeLoader(yaml.SafeLoader):
    duplicate_key_policy = 'allow'


class StrictSafeLoader(yaml.SafeLoader):
    duplicate_key_policy = 'strict'


def test_top_level_duplicate_key_rejected():
    with pytest.raises(yaml.YAMLError, match="duplicate key"):
        yaml.safe_load("timeout: 30\ntimeout: 0\n")


def test_nested_duplicate_key_rejected():
    with pytest.raises(yaml.YAMLError, match="duplicate key"):
        yaml.safe_load("server:\n  host: a\n  host: b\n")


def test_deeply_nested_duplicate_key_rejected():
    source = "a:\n  b:\n    c:\n      x: 1\n      x: 2\n"
    with pytest.raises(yaml.YAMLError, match="duplicate key"):
        yaml.safe_load(source)


def test_merge_key_conflicts_with_explicit_key():
    source = """
base: &base {timeout: 30}
target:
  <<: *base
  timeout: 0
"""
    with pytest.raises(yaml.YAMLError, match="duplicate key"):
        yaml.safe_load(source)


def test_merge_sequence_same_key_first_merge_wins():
    source = """
b1: &b1 {x: 1}
b2: &b2 {x: 2}
target: {<<: [*b1, *b2]}
"""
    assert yaml.safe_load(source)['target'] == {'x': 1}


def test_explicit_merge_tag_conflicts_with_explicit_key():
    source = """
base: &base {x: 1}
target:
  !!merge << : *base
  x: 2
"""
    with pytest.raises(yaml.YAMLError, match="duplicate key"):
        yaml.safe_load(source)


def test_duplicate_key_via_alias():
    source = """
anchor: &k somekey
*k : 1
*k : 2
"""
    with pytest.raises(yaml.YAMLError, match="duplicate key"):
        yaml.safe_load(source)


def test_explicit_tag_mapping_duplicate_key():
    with pytest.raises(yaml.YAMLError, match="duplicate key"):
        yaml.safe_load("!!map {a: 1, a: 2}")


def test_same_int_key_different_text():
    with pytest.raises(yaml.YAMLError, match="duplicate key"):
        yaml.safe_load("0x10: a\n16: b\n")


def test_same_bool_key_different_text():
    with pytest.raises(yaml.YAMLError, match="duplicate key"):
        yaml.safe_load("yes: a\ntrue: b\n")


def test_same_string_key_different_quoting():
    with pytest.raises(yaml.YAMLError, match="duplicate key"):
        yaml.safe_load("foo: a\n'foo': b\n")


def test_different_types_same_text_are_not_duplicates():
    assert yaml.safe_load("1: a\n!!str 1: b\n") == {1: 'a', '1': 'b'}


def test_int_and_bool_keys_are_not_duplicates():
    assert yaml.safe_load("1: a\ntrue: b\n") == {1: 'a', True: 'b'}


def test_lenient_mode_keeps_last_value_wins():
    source = "timeout: 30\ntimeout: 0\n"
    assert yaml.load(source, Loader=LenientSafeLoader) == {'timeout': 0}
    loader = yaml.SafeLoader(source, duplicate_key_policy='allow')
    try:
        assert loader.get_single_data() == {'timeout': 0}
    finally:
        loader.dispose()


def test_strict_mode_reports_both_key_positions():
    source = "a: 1\nb: 2\na: 3\n"
    with pytest.raises(yaml.YAMLError) as excinfo:
        yaml.load(source, Loader=StrictSafeLoader)
    message = str(excinfo.value)
    assert "first occurrence at line 1, column 1" in message
    assert 'line 3, column 1' in message


def test_error_does_not_leak_full_long_key():
    key = "s3cr3t" * 2000
    source = "%s: 1\n%s: 2\n" % (key, key)
    with pytest.raises(yaml.YAMLError) as excinfo:
        yaml.safe_load(source)
    message = str(excinfo.value)
    assert key not in message
    assert len(message) < 500


def test_legal_yaml_and_return_types_unchanged():
    source = """
name: example
retries: 3
enabled: true
tags: [a, b]
nested:
  timeout: 30
"""
    data = yaml.safe_load(source)
    assert data == {
        'name': 'example',
        'retries': 3,
        'enabled': True,
        'tags': ['a', 'b'],
        'nested': {'timeout': 30},
    }


def test_merge_without_conflict_still_loads():
    source = """
base: &base {x: 1, y: 2}
target:
  <<: *base
  z: 3
"""
    assert yaml.safe_load(source) == {
        'base': {'x': 1, 'y': 2},
        'target': {'x': 1, 'y': 2, 'z': 3},
    }


def test_dump_load_roundtrip_unchanged():
    data = {'a': [1, 2, 3], 'b': {'c': 'd'}, 'e': None}
    assert yaml.safe_load(yaml.dump(data)) == data
