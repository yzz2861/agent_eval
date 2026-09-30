"""Tests for configurable mapping key collision handling."""

from collections import Counter, defaultdict
from collections.abc import Mapping
from typing import Any

import pytest
from attrs import define

from cattrs import BaseConverter, Converter, KeyCollisionError, transform_error
from cattrs.converters import KeyCollisionPolicy
from cattrs.errors import IterableValidationError
from cattrs.gen import make_mapping_structure_fn, make_mapping_unstructure_fn


class KeyConversionError(Exception):
    pass


class ValueConversionError(Exception):
    pass


@define(frozen=True)
class CollidingKey:
    value: str


@define(frozen=True)
class ValueModel:
    value: str


class DuplicateItemsMapping(Mapping):
    def __init__(self, pairs):
        self._pairs = tuple(pairs)

    def __getitem__(self, key):
        for current_key, value in self._pairs:
            if current_key == key:
                return value
        raise KeyError(key)

    def __iter__(self):
        return iter(dict(self._pairs))

    def __len__(self):
        return len({key for key, _ in self._pairs})

    def items(self):
        return list(self._pairs)


class CountingKeyHook:
    def __init__(self):
        self.calls = []

    def __call__(self, value: str, _: Any = None) -> int:
        self.calls.append(value)
        if value == "bad":
            raise KeyConversionError(value)
        return int(value)


class CountingUnstructureKeyHook:
    def __init__(self):
        self.calls = []

    def __call__(self, key: CollidingKey) -> int:
        self.calls.append(key.value)
        return int(key.value)


class CountingValueHook:
    def __init__(self):
        self.calls = []

    def __call__(self, value: ValueModel, _: Any = None) -> str:
        self.calls.append(value.value)
        raise ValueConversionError(value.value)


@pytest.fixture
def strict_converter(request):
    converter = request.param(key_collision_policy=KeyCollisionPolicy.RAISE)
    key_hook = CountingKeyHook()
    converter.register_structure_hook(int, key_hook)

    unstructure_key_hook = CountingUnstructureKeyHook()
    converter.register_unstructure_hook(CollidingKey, unstructure_key_hook)
    return converter, key_hook, unstructure_key_hook


@pytest.fixture
def structure_data():
    return {"1": "a", "01": "b"}


@pytest.fixture
def unstructure_data():
    return {CollidingKey("1"): "a", CollidingKey("01"): "b"}


@pytest.mark.parametrize("detailed_validation", [False, True])
@pytest.mark.parametrize("converter_cls", [BaseConverter, Converter], indirect=True)
def test_default_policy_keeps_last_value(
    converter_cls, detailed_validation, structure_data, unstructure_data
):
    converter = converter_cls(detailed_validation=detailed_validation)

    assert converter.structure(structure_data, dict[int, str]) == {1: "b"}

    converter.register_unstructure_hook(CollidingKey, lambda key: int(key.value))
    assert converter.unstructure(
        unstructure_data, unstructure_as=dict[CollidingKey, str]
    ) == {1: "b"}


@pytest.mark.parametrize("strict_converter", [BaseConverter, Converter], indirect=True)
@pytest.mark.parametrize("detailed_validation", [False, True])
def test_strict_structure_reports_collision(
    strict_converter, detailed_validation, structure_data
):
    converter, key_hook, _ = strict_converter
    converter.detailed_validation = detailed_validation

    with pytest.raises(Exception) as exc_info:
        converter.structure(structure_data, dict[int, Any])

    if detailed_validation:
        assert isinstance(exc_info.value, IterableValidationError)
        collision = exc_info.value.exceptions[0]
    else:
        collision = exc_info.value

    assert isinstance(collision, KeyCollisionError)
    assert collision.source_key == "1"
    assert collision.colliding_key == "01"
    assert collision.target_key == 1
    assert structure_data == {"1": "a", "01": "b"}
    assert key_hook.calls == ["1", "01"]


@pytest.mark.parametrize("strict_converter", [BaseConverter, Converter], indirect=True)
def test_strict_unstructure_reports_collision(strict_converter, unstructure_data):
    converter, _, unstructure_key_hook = strict_converter
    with pytest.raises(KeyCollisionError) as exc_info:
        converter.unstructure(unstructure_data, unstructure_as=dict[CollidingKey, str])

    collision = exc_info.value
    assert collision.source_key == CollidingKey("1")
    assert collision.colliding_key == CollidingKey("01")
    assert collision.target_key == 1
    assert unstructure_data == {CollidingKey("1"): "a", CollidingKey("01"): "b"}
    assert unstructure_key_hook.calls == ["1", "01"]


@pytest.mark.parametrize("detailed_validation", [False, True])
def test_strict_nested_structure_mapping(detailed_validation):
    converter = Converter(
        detailed_validation=detailed_validation,
        key_collision_policy=KeyCollisionPolicy.RAISE,
    )

    with pytest.raises(Exception) as exc_info:
        converter.structure({"outer": {"1": "a", "01": "b"}}, dict[str, dict[int, str]])

    collision = exc_info.value
    while not isinstance(collision, KeyCollisionError):
        collision = collision.exceptions[0]
    assert (collision.source_key, collision.colliding_key, collision.target_key) == (
        "1",
        "01",
        1,
    )


def test_strict_nested_unstructure_mapping(unstructure_data):
    converter = Converter(key_collision_policy=KeyCollisionPolicy.RAISE)
    converter.register_unstructure_hook(CollidingKey, lambda key: int(key.value))

    with pytest.raises(KeyCollisionError) as exc_info:
        converter.unstructure(
            {"outer": unstructure_data},
            unstructure_as=dict[str, dict[CollidingKey, str]],
        )

    assert exc_info.value.target_key == 1


@pytest.mark.parametrize("detailed_validation", [False, True])
def test_key_value_and_collision_failures_are_separate(detailed_validation):
    converter = Converter(
        detailed_validation=detailed_validation,
        key_collision_policy=KeyCollisionPolicy.RAISE,
    )
    key_hook = CountingKeyHook()
    converter.register_structure_hook(int, key_hook)

    def structure_value(value, _):
        raise ValueConversionError(value)

    converter.register_structure_hook(ValueModel, structure_value)

    with pytest.raises((KeyConversionError, IterableValidationError)) as exc_info:
        converter.structure({"bad": "a"}, dict[int, str])
    if isinstance(exc_info.value, IterableValidationError):
        assert isinstance(exc_info.value.exceptions[0], KeyConversionError)

    with pytest.raises((ValueConversionError, IterableValidationError)) as exc_info:
        converter.structure({"1": ValueModel("a")}, dict[int, ValueModel])
    if isinstance(exc_info.value, IterableValidationError):
        assert isinstance(exc_info.value.exceptions[0], ValueConversionError)

    with pytest.raises((KeyCollisionError, IterableValidationError)) as exc_info:
        converter.structure({"1": "a", "01": "b"}, dict[int, Any])
    if isinstance(exc_info.value, IterableValidationError):
        assert isinstance(exc_info.value.exceptions[0], KeyCollisionError)


def test_detailed_collision_is_detected_after_earlier_value_failure():
    converter = Converter(
        detailed_validation=True, key_collision_policy=KeyCollisionPolicy.RAISE
    )
    key_hook = CountingKeyHook()
    value_hook = CountingValueHook()
    converter.register_structure_hook(int, key_hook)
    converter.register_structure_hook(ValueModel, value_hook)

    with pytest.raises(IterableValidationError) as exc_info:
        converter.structure(
            {"1": ValueModel("a"), "01": ValueModel("b")}, dict[int, ValueModel]
        )

    exceptions = exc_info.value.exceptions
    assert any(isinstance(exc, ValueConversionError) for exc in exceptions)
    assert any(isinstance(exc, KeyCollisionError) for exc in exceptions)
    assert key_hook.calls == ["1", "01"]
    assert value_hook.calls == ["a"]


def test_generated_mapping_hooks_use_explicit_policy(structure_data, unstructure_data):
    converter = Converter()
    key_hook = CountingKeyHook()
    converter.register_structure_hook(int, key_hook)
    unstructure_key_hook = CountingUnstructureKeyHook()
    converter.register_unstructure_hook(CollidingKey, unstructure_key_hook)

    structure_hook = make_mapping_structure_fn(
        dict[int, str],
        converter,
        detailed_validation=False,
        key_collision_policy=KeyCollisionPolicy.RAISE,
    )
    with pytest.raises(KeyCollisionError):
        structure_hook(structure_data, dict[int, str])
    assert key_hook.calls == ["1", "01"]

    unstructure_hook = make_mapping_unstructure_fn(
        dict[CollidingKey, str],
        converter,
        key_collision_policy=KeyCollisionPolicy.RAISE,
    )
    with pytest.raises(KeyCollisionError):
        unstructure_hook(unstructure_data)
    assert unstructure_key_hook.calls == ["1", "01"]


def test_detailed_collision_has_mapping_path_and_message():
    converter = Converter(
        detailed_validation=True, key_collision_policy=KeyCollisionPolicy.RAISE
    )

    with pytest.raises(IterableValidationError) as exc_info:
        converter.structure({"1": "a", "01": "b"}, dict[int, str])

    messages = transform_error(exc_info.value)
    assert messages == ["Converted mapping keys '1' and '01' collide at 1 @ $['01']"]


@pytest.mark.parametrize("detailed_validation", [False, True])
@pytest.mark.parametrize("mapping_type", [dict, Mapping])
def test_strict_structure_abstract_mapping(mapping_type, detailed_validation):
    converter = Converter(
        detailed_validation=detailed_validation,
        key_collision_policy=KeyCollisionPolicy.RAISE,
    )

    with pytest.raises(Exception) as exc_info:
        converter.structure({"1": "a", "01": "b"}, mapping_type[int, Any])

    collision = exc_info.value
    if detailed_validation:
        collision = collision.exceptions[0]
    assert isinstance(collision, KeyCollisionError)


@pytest.mark.parametrize("detailed_validation", [False, True])
def test_strict_defaultdict_and_counter(detailed_validation):
    converter = Converter(
        detailed_validation=detailed_validation,
        key_collision_policy=KeyCollisionPolicy.RAISE,
    )

    with pytest.raises(Exception) as exc_info:
        converter.structure({"1": "1", "01": "2"}, defaultdict[int, int])
    collision = exc_info.value
    if detailed_validation:
        collision = collision.exceptions[0]
    assert isinstance(collision, KeyCollisionError)

    with pytest.raises(Exception) as exc_info:
        converter.structure({"1": 1, "01": 2}, Counter[int])
    collision = exc_info.value
    if detailed_validation:
        collision = collision.exceptions[0]
    assert isinstance(collision, KeyCollisionError)


@pytest.mark.parametrize("converter_cls", [BaseConverter, Converter], indirect=True)
def test_strict_bare_mapping_reports_duplicate_source_key(converter_cls):
    converter = converter_cls(key_collision_policy=KeyCollisionPolicy.RAISE)
    mapping = DuplicateItemsMapping((("same", "a"), ("same", "b")))

    with pytest.raises(KeyCollisionError) as exc_info:
        converter.structure(mapping, dict)

    assert exc_info.value.source_key == "same"
    assert exc_info.value.colliding_key == "same"
    assert exc_info.value.target_key == "same"


def test_copy_preserves_and_overrides_key_collision_policy():
    converter = Converter(key_collision_policy=KeyCollisionPolicy.RAISE)
    assert converter.copy().key_collision_policy is KeyCollisionPolicy.RAISE
    assert (
        converter.copy(
            key_collision_policy=KeyCollisionPolicy.LAST_WINS
        ).key_collision_policy
        is KeyCollisionPolicy.LAST_WINS
    )
