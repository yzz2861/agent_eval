"""Tests for the strict union strategy."""

from typing import Generic, Literal, Optional, TypeVar, Union

import pytest
from attrs import define

from cattrs import BaseConverter, Converter, transform_error
from cattrs.errors import UnionAmbiguityError, UnionValidationError, UnionValidationNote
from cattrs.strategies import configure_strict_union


@define
class A:
    a: int


@define
class B:
    a: int


@define
class C:
    c: str


@define
class L1:
    kind: Literal["l1"]
    x: int


@define
class L2:
    kind: Literal["l2"]
    x: int


T = TypeVar("T")


@define
class G(Generic[T]):
    g: T


def test_single_match(converter: BaseConverter):
    """Exactly one successful branch is returned."""
    union = Union[A, C]
    configure_strict_union(union, converter)

    assert converter.structure({"a": 1}, union) == A(1)
    assert converter.structure({"c": "x"}, union) == C("x")


def test_ambiguity(converter: BaseConverter):
    """More than one successful branch raises UnionAmbiguityError."""
    union = Union[A, B]
    configure_strict_union(union, converter)

    with pytest.raises(UnionAmbiguityError) as exc_info:
        converter.structure({"a": 1}, union)

    assert exc_info.value.cl == union
    assert exc_info.value.matches == (A, B)
    assert "A" in str(exc_info.value)
    assert "B" in str(exc_info.value)


def test_no_match(converter: BaseConverter):
    """No successful branch raises UnionValidationError with branch errors."""
    union = Union[A, C]
    configure_strict_union(union, converter)

    with pytest.raises(UnionValidationError) as exc_info:
        converter.structure({"b": 1}, union)

    exc = exc_info.value
    assert exc.cl == union
    assert len(exc.exceptions) == 2

    # Each branch error is annotated with the branch type.
    with_notes, without = exc.group_exceptions()
    assert not without
    assert {note.type for _, note in with_notes} == {A, C}
    assert all(isinstance(note, UnionValidationNote) for _, note in with_notes)

    # Errors are described by type and field path.
    errors = transform_error(exc)
    if isinstance(converter, Converter) and converter.detailed_validation:
        assert errors == [
            "required field missing @ $[A].a",
            "required field missing @ $[C].c",
        ]
    else:
        assert len(errors) == 2
        assert errors[0].endswith("@ $[A]")
        assert errors[1].endswith("@ $[C]")


def test_none(converter: BaseConverter):
    """None is supported as a union member."""
    union = Union[A, C, None]
    configure_strict_union(union, converter)

    assert converter.structure(None, union) is None
    assert converter.structure({"a": 1}, union) == A(1)

    with pytest.raises(UnionValidationError):
        converter.structure({"b": 1}, union)


def test_none_not_in_union(converter: BaseConverter):
    """None fails all branches if NoneType is not a member."""
    union = Union[A, C]
    configure_strict_union(union, converter)

    with pytest.raises(UnionValidationError):
        converter.structure(None, union)


def test_literals_take_priority(converter: BaseConverter):
    """Literal discriminator fields are used directly when available."""
    union = Union[L1, L2]
    configure_strict_union(union, converter)

    assert converter.structure({"kind": "l1", "x": 1}, union) == L1("l1", 1)
    assert converter.structure({"kind": "l2", "x": 2}, union) == L2("l2", 2)

    # An unknown discriminator value falls back to strict evaluation.
    with pytest.raises(UnionValidationError):
        converter.structure({"kind": "l3", "x": 3}, union)


def test_literals_disabled(converter: BaseConverter):
    """Literal disambiguation can be turned off."""
    union = Union[L1, L2]
    configure_strict_union(union, converter, use_literals=False)

    assert converter.structure({"kind": "l1", "x": 1}, union) == L1("l1", 1)


def test_hook_called_once_per_call(converter: BaseConverter):
    """Each candidate hook runs at most once per structuring call."""
    calls = 0
    orig_hook = converter.get_structure_hook(A)

    def counting_hook(obj, t):
        nonlocal calls
        calls += 1
        return orig_hook(obj, t)

    converter.register_structure_hook(A, counting_hook)

    union = Union[A, C]
    configure_strict_union(union, converter)

    assert converter.structure({"a": 1}, union) == A(1)
    assert calls == 1


def test_successful_result_reused(converter: BaseConverter):
    """The object structured during evaluation is returned directly."""
    sentinel = object()

    converter.register_structure_hook(A, lambda obj, t: sentinel)

    union = Union[A, C]
    configure_strict_union(union, converter)

    assert converter.structure({"a": 1}, union) is sentinel


def test_generics(converter: BaseConverter):
    """Generic classes are supported as members."""
    union = Union[G[int], C]
    configure_strict_union(union, converter)

    assert converter.structure({"g": "1"}, union) == G(1)
    assert converter.structure({"c": "x"}, union) == C("x")


def test_nested_union(converter: BaseConverter):
    """Members which are themselves configured unions are supported."""
    inner = Union[L1, L2]
    configure_strict_union(inner, converter)

    @define
    class D:
        d: int

    outer = Union[D, inner]
    configure_strict_union(outer, converter)

    assert converter.structure({"kind": "l2", "x": 1}, outer) == L2("l2", 1)
    assert converter.structure({"d": 1}, outer) == D(1)


def test_optional_nested(converter: BaseConverter):
    """Optional members work."""
    union = Union[A, Optional[C]]
    configure_strict_union(union, converter)

    assert converter.structure(None, union) is None
    assert converter.structure({"c": "x"}, union) == C("x")


def test_not_a_union(converter: BaseConverter):
    """Configuring a non-union raises."""
    with pytest.raises(ValueError):
        configure_strict_union(A, converter)


def test_unstructure_unaffected(converter: BaseConverter):
    """Unstructuring is not changed by the strategy."""
    union = Union[A, C]
    configure_strict_union(union, converter)

    assert converter.unstructure(A(1), unstructure_as=union) == {"a": 1}
