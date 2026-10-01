from attrs import define

from cattrs import Converter
from cattrs.strategies import configure_strict_union


@define
class A:
    value: int


@define
class B:
    value: str


type StrictUnion = A | B | None


def test_strict_union_type_alias():
    converter = Converter()
    configure_strict_union(StrictUnion, converter)

    assert converter.structure({"value": 1}, StrictUnion) == A(1)
    assert converter.structure(None, StrictUnion) is None
