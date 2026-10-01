from __future__ import annotations

import pytest

from cattrs import BaseConverter
from cattrs.errors import UnionAmbiguityError, UnionValidationError
from cattrs.strategies import configure_strict_union

from .test_strict_union import L1, L2, A, B, C


def test_type_alias(converter: BaseConverter):
    """Type aliases of unions also work."""
    type AOrC = A | C

    configure_strict_union(AOrC, converter)

    assert converter.structure({"a": 1}, AOrC) == A(1)
    assert converter.structure({"c": "x"}, AOrC) == C("x")

    with pytest.raises(UnionValidationError):
        converter.structure({"b": 1}, AOrC)


def test_nested_type_alias(converter: BaseConverter):
    """Unions containing aliased (nested) unions also work."""
    type Inner = L1 | L2
    type Outer = A | Inner

    configure_strict_union(Inner, converter)
    configure_strict_union(Outer, converter)

    assert converter.structure({"kind": "l2", "x": 1}, Outer) == L2("l2", 1)
    assert converter.structure({"a": 1}, Outer) == A(1)

    with pytest.raises(UnionValidationError):
        converter.structure({"b": 1}, Outer)


def test_ambiguous_alias(converter: BaseConverter):
    """Ambiguity is reported through aliases as well."""
    type AOrB = A | B

    configure_strict_union(AOrB, converter)

    with pytest.raises(UnionAmbiguityError):
        converter.structure({"a": 1}, AOrB)
