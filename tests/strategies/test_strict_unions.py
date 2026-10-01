from typing import Generic, Literal, Optional, TypeVar, Union

import pytest
from attrs import define

from cattrs import (
    AmbiguousUnionError,
    BaseConverter,
    Converter,
    UnionValidationError,
    UnstructureStrategy,
    transform_error,
)
from cattrs.strategies import configure_strict_union, configure_tagged_union


@define
class IntegerBox:
    value: int


@define
class StringBox:
    value: str


@define
class OtherIntegerBox:
    value: int


@define
class LiteralA:
    kind: Literal["a"] = "a"
    value: int = 1


@define
class LiteralB:
    kind: Literal["b"] = "b"
    value: str = "x"


T = TypeVar("T")


@define
class GenericBox(Generic[T]):
    inner: T


@define
class Wrapper:
    box: Union[IntegerBox, StringBox]


@pytest.mark.parametrize("converter_cls", [BaseConverter, Converter])
def test_strict_union_requires_unique_success(converter_cls):
    converter = converter_cls()
    union = Union[IntegerBox, StringBox]
    configure_strict_union(union, converter)

    assert converter.structure({"value": 1}, union) == IntegerBox(1)
    assert converter.structure({"value": "x"}, union) == StringBox("x")


def test_strict_union_reports_all_failures_with_type_and_path():
    converter = Converter()
    union = Union[IntegerBox, StringBox]
    configure_strict_union(union, converter)

    with pytest.raises(UnionValidationError) as exc_info:
        converter.structure({}, union)

    assert exc_info.value.types == (IntegerBox, StringBox)
    assert transform_error(exc_info.value) == [
        "required field missing @ $.value as IntegerBox",
        "required field missing @ $.value as StringBox",
    ]


@pytest.mark.parametrize("converter_cls", [BaseConverter, Converter])
def test_strict_union_reports_ambiguity(converter_cls):
    converter = converter_cls()
    union = Union[IntegerBox, OtherIntegerBox]
    configure_strict_union(union, converter)

    with pytest.raises(AmbiguousUnionError) as exc_info:
        converter.structure({"value": 1}, union)

    assert exc_info.value.types == (IntegerBox, OtherIntegerBox)
    assert transform_error(exc_info.value) == [
        "ambiguous union; successful candidates: IntegerBox, OtherIntegerBox @ $"
    ]


@pytest.mark.parametrize("converter_cls", [BaseConverter, Converter])
def test_strict_union_supports_optional(converter_cls):
    converter = converter_cls()
    union = Optional[Union[IntegerBox, StringBox]]
    configure_strict_union(union, converter)

    assert converter.structure(None, union) is None
    assert converter.structure({"value": 1}, union) == IntegerBox(1)


def test_strict_union_supports_tuple_structure():
    converter = BaseConverter(unstruct_strat=UnstructureStrategy.AS_TUPLE)
    union = Union[IntegerBox, StringBox]
    configure_strict_union(union, converter)

    assert converter.structure((1,), union) == IntegerBox(1)
    assert converter.structure(("x",), union) == StringBox("x")


@pytest.mark.parametrize("converter_cls", [BaseConverter, Converter])
def test_strict_union_keeps_literal_disambiguation(converter_cls):
    converter = converter_cls()
    union = Union[LiteralA, LiteralB]
    configure_strict_union(union, converter)

    assert converter.structure({"kind": "a", "value": 1}, union) == LiteralA()
    assert converter.structure({"kind": "b", "value": "x"}, union) == LiteralB("b", "x")

    with pytest.raises(KeyError):
        converter.structure({"value": 1}, union)


def test_strict_union_applies_to_nested_generic_unions():
    converter = Converter()
    union = Union[GenericBox[IntegerBox], GenericBox[StringBox]]
    configure_strict_union(union, converter)

    assert converter.structure({"inner": {"value": 1}}, union) == GenericBox(
        IntegerBox(1)
    )

    with pytest.raises(UnionValidationError):
        converter.structure({"inner": {"value": True}}, union)


def test_strict_union_applies_to_attrs_fields():
    converter = Converter()
    union = Union[IntegerBox, StringBox]
    configure_strict_union(union, converter)

    assert converter.structure({"box": {"value": 1}}, Wrapper) == Wrapper(IntegerBox(1))


def test_strict_union_does_not_override_explicit_nested_union_hook():
    converter = Converter()
    nested = Union[IntegerBox, StringBox]
    converter.register_structure_hook(nested, lambda value, _: StringBox("custom"))
    configure_strict_union(Union[Wrapper, IntegerBox], converter)

    assert converter.structure(
        {"box": {"value": 1}}, Union[Wrapper, IntegerBox]
    ) == Wrapper(StringBox("custom"))


def test_strict_union_calls_each_candidate_hook_once_and_reuses_success():
    converter = Converter()
    calls = {IntegerBox: 0, StringBox: 0}
    result = IntegerBox(1)
    union = Union[IntegerBox, StringBox]

    def integer_hook(value, cl):
        calls[IntegerBox] += 1
        return result

    def string_hook(value, cl):
        calls[StringBox] += 1
        raise ValueError("no")

    converter.register_structure_hook(IntegerBox, integer_hook)
    converter.register_structure_hook(StringBox, string_hook)
    configure_strict_union(union, converter)

    assert converter.structure({"value": 1}, union) is result
    assert converter.structure({"value": 1}, union) is result
    assert calls[IntegerBox] == 2
    assert calls[StringBox] == 0


def test_strict_nested_union_reuses_candidate_hook_results():
    converter = Converter()
    calls = []

    @define
    class X:
        value: int

    @define
    class Y:
        value: int

    def make_hook(candidate):
        def hook(value, cl):
            calls.append(candidate)
            return candidate(value["value"])

        return hook

    converter.register_structure_hook(X, make_hook(X))
    converter.register_structure_hook(Y, make_hook(Y))
    nested = Union[X, Y]
    configure_strict_union(Union[nested, nested], converter)

    with pytest.raises(AmbiguousUnionError):
        converter.structure({"value": 1}, Union[nested, nested])

    assert calls == [X, Y]


def test_tagged_union_takes_precedence_over_strict_union():
    converter = Converter()
    union = Union[LiteralA, LiteralB]
    configure_strict_union(union, converter)
    configure_tagged_union(union, converter)

    result = converter.structure(
        {"kind": "b", "value": "x", "_type": "LiteralB"}, union
    )
    assert result == LiteralB("b", "x")
