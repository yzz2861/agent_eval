from collections import Counter

import pytest

from cattrs import (
    BaseConverter,
    Converter,
    KeyCollisionStrategy,
    MappingKeyCollisionError,
)
from cattrs.errors import IterableValidationError
from cattrs.v import transform_error

converter_classes = pytest.mark.parametrize("converter_cls", [BaseConverter, Converter])


class StructureKey:
    def __init__(self, value: str) -> None:
        self.value = value

    def __repr__(self) -> str:
        return f"StructureKey({self.value!r})"


class UnstructureKey:
    def __init__(self, value: str) -> None:
        self.value = value

    def __repr__(self) -> str:
        return f"UnstructureKey({self.value!r})"


@converter_classes
@pytest.mark.parametrize("detailed_validation", [True, False])
def test_structure_last_wins_is_default(
    converter_cls: type, detailed_validation: bool
) -> None:
    converter = converter_cls(detailed_validation=detailed_validation)

    assert converter.structure({"1": "a", "01": "b"}, dict[int, str]) == {1: "b"}


@converter_classes
@pytest.mark.parametrize("detailed_validation", [True, False])
def test_structure_strict_reports_collision(
    converter_cls: type, detailed_validation: bool
) -> None:
    converter = converter_cls(
        detailed_validation=detailed_validation,
        key_collision_strategy=KeyCollisionStrategy.RAISE,
    )
    payload = {"1": "a", "01": "b"}

    with pytest.raises(
        IterableValidationError if detailed_validation else MappingKeyCollisionError
    ) as exc_info:
        converter.structure(payload, dict[int, str])

    collision = exc_info.value.exceptions[0] if detailed_validation else exc_info.value
    assert isinstance(collision, MappingKeyCollisionError)
    assert collision.target_key == 1
    assert collision.existing_source_key == "1"
    assert collision.conflicting_source_key == "01"
    assert collision.source_keys == ("1", "01")
    assert payload == {"1": "a", "01": "b"}


@converter_classes
@pytest.mark.parametrize("detailed_validation", [True, False])
def test_structure_strict_separates_key_value_and_collision_errors(
    converter_cls: type, detailed_validation: bool
) -> None:
    converter = converter_cls(
        detailed_validation=detailed_validation,
        key_collision_strategy=KeyCollisionStrategy.RAISE,
    )
    payload = {"1": 1, "01": 2, "bad-key": 3, "2": "bad-value"}

    if not detailed_validation:
        with pytest.raises(MappingKeyCollisionError):
            converter.structure(payload, dict[int, int])
        return

    with pytest.raises(IterableValidationError) as exc_info:
        converter.structure(payload, dict[int, int])

    collision_errors = [
        exc
        for exc in exc_info.value.exceptions
        if isinstance(exc, MappingKeyCollisionError)
    ]
    value_errors = [
        exc
        for exc in exc_info.value.exceptions
        if hasattr(exc, "__notes__")
        and exc.__notes__[0].startswith("Structuring mapping value")
    ]
    key_errors = [
        exc
        for exc in exc_info.value.exceptions
        if hasattr(exc, "__notes__")
        and exc.__notes__[0].startswith("Structuring mapping key")
    ]
    assert len(collision_errors) == 1
    assert collision_errors[0].source_keys == ("1", "01")
    assert len(value_errors) == 1
    assert value_errors[0].__notes__[0].index == "2"
    assert len(key_errors) == 1
    assert key_errors[0].__notes__[0].index == "bad-key"


@converter_classes
@pytest.mark.parametrize("detailed_validation", [True, False])
def test_structure_strict_uses_custom_key_hook_once(
    converter_cls: type, detailed_validation: bool
) -> None:
    converter = converter_cls(
        detailed_validation=detailed_validation,
        key_collision_strategy=KeyCollisionStrategy.RAISE,
    )
    calls = []
    converter.register_structure_hook(
        StructureKey, lambda value, _: calls.append(value) or int(value.value)
    )
    payload = {StructureKey("1"): 1, StructureKey("01"): 2}
    snapshot = [(key, key.value, value) for key, value in payload.items()]
    with pytest.raises(
        IterableValidationError if detailed_validation else MappingKeyCollisionError
    ):
        converter.structure(payload, dict[StructureKey, int])

    assert [call.value for call in calls] == ["1", "01"]
    assert [(key, key.value, value) for key, value in payload.items()] == snapshot


@converter_classes
def test_structure_strict_covers_nested_mappings(converter_cls: type) -> None:
    converter = converter_cls(key_collision_strategy=KeyCollisionStrategy.RAISE)
    payload = {"outer": {"1": "a", "01": "b"}}

    with pytest.raises(
        IterableValidationError
        if converter.detailed_validation
        else MappingKeyCollisionError
    ):
        converter.structure(payload, dict[str, dict[int, str]])

    assert payload == {"outer": {"1": "a", "01": "b"}}


@converter_classes
@pytest.mark.parametrize("detailed_validation", [True, False])
def test_unstructure_last_wins_is_default(
    converter_cls: type, detailed_validation: bool
) -> None:
    converter = converter_cls(detailed_validation=detailed_validation)
    converter.register_unstructure_hook(UnstructureKey, lambda key: int(key.value))

    payload = {UnstructureKey("1"): "a", UnstructureKey("01"): "b"}
    assert converter.unstructure(payload, unstructure_as=dict[UnstructureKey, str]) == {
        1: "b"
    }


@converter_classes
@pytest.mark.parametrize("detailed_validation", [True, False])
def test_unstructure_strict_reports_collision(
    converter_cls: type, detailed_validation: bool
) -> None:
    converter = converter_cls(
        detailed_validation=detailed_validation,
        key_collision_strategy=KeyCollisionStrategy.RAISE,
    )
    converter.register_unstructure_hook(UnstructureKey, lambda key: int(key.value))
    payload = {UnstructureKey("1"): "a", UnstructureKey("01"): "b"}
    snapshot = [(key, key.value, value) for key, value in payload.items()]

    with pytest.raises(MappingKeyCollisionError) as exc_info:
        converter.unstructure(payload, unstructure_as=dict[UnstructureKey, str])

    assert exc_info.value.target_key == 1
    assert tuple(exc_info.value.source_keys) == tuple(payload)
    assert [(key, key.value, value) for key, value in payload.items()] == snapshot


@converter_classes
def test_unstructure_strict_uses_custom_key_hook_once(converter_cls: type) -> None:
    converter = converter_cls(key_collision_strategy=KeyCollisionStrategy.RAISE)
    calls: list[UnstructureKey] = []

    def unstructure_key(key: UnstructureKey) -> int:
        calls.append(key)
        return int(key.value)

    converter.register_unstructure_hook(UnstructureKey, unstructure_key)
    payload = {UnstructureKey("1"): "a", UnstructureKey("01"): "b"}

    with pytest.raises(MappingKeyCollisionError):
        converter.unstructure(payload, unstructure_as=dict[UnstructureKey, str])

    assert [call.value for call in calls] == ["1", "01"]


@converter_classes
def test_unstructure_strict_covers_nested_mappings(converter_cls: type) -> None:
    converter = converter_cls(key_collision_strategy=KeyCollisionStrategy.RAISE)
    converter.register_unstructure_hook(UnstructureKey, lambda key: int(key.value))
    payload = {"outer": {UnstructureKey("1"): "a", UnstructureKey("01"): "b"}}

    with pytest.raises(MappingKeyCollisionError):
        converter.unstructure(
            payload, unstructure_as=dict[str, dict[UnstructureKey, str]]
        )


def test_copy_preserves_and_overrides_strategy() -> None:
    converter = Converter(key_collision_strategy=KeyCollisionStrategy.RAISE)
    assert converter.copy().key_collision_strategy is KeyCollisionStrategy.RAISE
    copy = converter.copy(key_collision_strategy="last-wins")
    assert copy.key_collision_strategy is KeyCollisionStrategy.LAST_WINS


def test_strict_alias_raises_collision() -> None:
    assert KeyCollisionStrategy("strict") is KeyCollisionStrategy.RAISE
    assert KeyCollisionStrategy.STRICT == KeyCollisionStrategy.RAISE
    assert KeyCollisionStrategy("legacy") is KeyCollisionStrategy.LAST_WINS
    assert KeyCollisionStrategy.LEGACY == KeyCollisionStrategy.LAST_WINS


@pytest.mark.parametrize("detailed_validation", [True, False])
def test_generated_counter_structure_uses_converter_strategy(
    detailed_validation: bool,
) -> None:
    converter = Converter(
        detailed_validation=detailed_validation,
        key_collision_strategy=KeyCollisionStrategy.RAISE,
    )

    with pytest.raises(
        IterableValidationError if detailed_validation else MappingKeyCollisionError
    ):
        converter.structure({"1": 1, "01": 2}, Counter[int])


def test_generated_unstructure_custom_key_handler_runs_once() -> None:
    converter = Converter(key_collision_strategy=KeyCollisionStrategy.RAISE)
    calls = []

    def key_handler(key: str) -> int:
        calls.append(key)
        return int(key.lstrip("0") or "0")

    hook = converter.gen_unstructure_mapping(dict[str, str], key_handler=key_handler)

    with pytest.raises(MappingKeyCollisionError):
        hook({"1": "a", "01": "b"})

    assert calls == ["1", "01"]


@pytest.mark.parametrize("converter_cls", [BaseConverter, Converter])
def test_unhashable_converted_key_is_a_key_error(
    converter_cls: type,
) -> None:
    converter = converter_cls(key_collision_strategy=KeyCollisionStrategy.RAISE)
    converter.register_structure_hook(int, lambda value, _: [int(value)])

    with pytest.raises(IterableValidationError) as exc_info:
        converter.structure({"1": "a"}, dict[int, str])

    assert not isinstance(exc_info.value.exceptions[0], MappingKeyCollisionError)
    assert exc_info.value.exceptions[0].__notes__[0].index == "1"


def test_transform_error_describes_key_collision() -> None:
    converter = Converter(key_collision_strategy=KeyCollisionStrategy.RAISE)

    with pytest.raises(IterableValidationError) as exc_info:
        converter.structure({"1": "a", "01": "b"}, dict[int, str])

    assert transform_error(exc_info.value) == [
        "mapping key collision: source keys '1' and '01' both convert to 1 @ $"
    ]
