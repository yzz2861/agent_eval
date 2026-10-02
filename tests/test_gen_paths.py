"""Tests for the `path` override, mapping flat attributes to nested locations."""

from copy import deepcopy
from typing import Annotated, Generic, Optional, TypeVar

import pytest
from attrs import define, field

from cattrs import BaseConverter, Converter
from cattrs.errors import ClassValidationError, ForbiddenExtraKeysError
from cattrs.gen import make_dict_structure_fn, make_dict_unstructure_fn, override

T = TypeVar("T")


@define
class Profile:
    name: str
    city: str
    zip_code: str = "00000"
    nick: Optional[str] = None


PATH_OVERRIDES = {
    "city": override(path=("profile", "address", "city")),
    "zip_code": override(path=("profile", "address", "zip")),
    "nick": override(path=("profile", "nick")),
}


def test_structure_path(converter: BaseConverter) -> None:
    """Fields are read from nested locations."""
    fn = make_dict_structure_fn(Profile, converter, **PATH_OVERRIDES)

    data = {
        "name": "Ana",
        "profile": {"address": {"city": "Berlin", "zip": "10115"}, "nick": "annie"},
    }
    assert fn(data, Profile) == Profile("Ana", "Berlin", "10115", "annie")


def test_unstructure_path(converter: BaseConverter) -> None:
    """Fields are written to nested locations, sharing intermediate dicts."""
    fn = make_dict_unstructure_fn(Profile, converter, **PATH_OVERRIDES)

    assert fn(Profile("Ana", "Berlin", "10115", "annie")) == {
        "name": "Ana",
        "profile": {"address": {"city": "Berlin", "zip": "10115"}, "nick": "annie"},
    }


def test_path_roundtrip(genconverter: Converter) -> None:
    """Nested paths survive a round trip."""
    s_fn = make_dict_structure_fn(Profile, genconverter, **PATH_OVERRIDES)
    u_fn = make_dict_unstructure_fn(Profile, genconverter, **PATH_OVERRIDES)

    inst = Profile("Ana", "Berlin", "10115", "annie")
    assert s_fn(u_fn(inst), Profile) == inst


def test_path_dotted_keys_not_split(converter: BaseConverter) -> None:
    """String segments are used as-is; dots in real keys are not special."""

    @define
    class C:
        a: int
        b: int

    overrides = {
        "a": override(path=("weird.key", "a")),
        "b": override(path="another.key"),
    }
    s_fn = make_dict_structure_fn(C, converter, **overrides)
    u_fn = make_dict_unstructure_fn(C, converter, **overrides)

    data = {"weird.key": {"a": 1}, "another.key": 2}
    assert s_fn(data, C) == C(1, 2)
    assert u_fn(C(1, 2)) == data


def test_path_array_indices(converter: BaseConverter) -> None:
    """Integer segments index into sequences."""

    @define
    class C:
        first: str
        third: str

    overrides = {
        "first": override(path=("items", 0, "name")),
        "third": override(path=("items", 2, "name")),
    }
    s_fn = make_dict_structure_fn(C, converter, **overrides)
    u_fn = make_dict_unstructure_fn(C, converter, **overrides)

    data = {"items": [{"name": "a"}, {"name": "b"}, {"name": "c"}]}
    assert s_fn(data, C) == C("a", "c")
    assert u_fn(C("a", "c")) == {"items": [{"name": "a"}, None, {"name": "c"}]}


def test_path_missing_uses_default(converter: BaseConverter) -> None:
    """Absent keys, including absent intermediates, fall back to defaults."""

    @define
    class C:
        a: int = 1
        b: str = "x"

    overrides = {"a": override(path=("cfg", "a")), "b": override(path=("cfg", "b"))}
    fn = make_dict_structure_fn(C, converter, **overrides)

    assert fn({}, C) == C()
    assert fn({"cfg": {}}, C) == C()
    assert fn({"cfg": {"a": 2}}, C) == C(2)


def test_path_missing_required(converter: BaseConverter) -> None:
    """A missing required nested field is an error."""
    fn = make_dict_structure_fn(Profile, converter, **PATH_OVERRIDES)

    with pytest.raises(
        ClassValidationError if converter.detailed_validation else KeyError
    ):
        fn({"name": "Ana", "profile": {}}, Profile)


def test_path_explicit_null(converter: BaseConverter) -> None:
    """Explicit nulls are structured, not treated as missing."""

    @define
    class C:
        n: int
        o: Optional[int] = 5

    overrides = {"n": override(path=("wrap", "n")), "o": override(path=("wrap", "o"))}
    fn = make_dict_structure_fn(C, converter, **overrides)

    assert fn({"wrap": {"n": 1, "o": None}}, C) == C(1, None)
    with pytest.raises(
        ClassValidationError if converter.detailed_validation else TypeError
    ):
        fn({"wrap": {"n": None}}, C)


def test_path_intermediate_null(converter: BaseConverter) -> None:
    """A null intermediate is an error, not a miss."""
    fn = make_dict_structure_fn(Profile, converter, **PATH_OVERRIDES)

    with pytest.raises(
        ClassValidationError if converter.detailed_validation else TypeError
    ):
        fn({"name": "Ana", "profile": None}, Profile)


def test_path_detailed_error_notes() -> None:
    """Detailed validation errors point at the offending attribute."""
    converter = Converter(detailed_validation=True)

    @define
    class C:
        age: int

    fn = make_dict_structure_fn(C, converter, age=override(path=("profile", "age")))

    with pytest.raises(ClassValidationError) as exc_info:
        fn({"profile": {"age": None}}, C)

    notes = exc_info.value.exceptions[0].__notes__
    assert any("attribute age" in note for note in notes)


def test_path_conflicts_at_generation(converter: BaseConverter) -> None:
    """Overlapping paths are rejected when the hook is generated."""

    @define
    class C:
        a: int
        b: int
        c: int

    # Same path twice.
    with pytest.raises(ValueError, match="same path"):
        make_dict_structure_fn(
            C, converter, a=override(path=("x", "y")), b=override(path=("x", "y"))
        )
    with pytest.raises(ValueError, match="same path"):
        make_dict_unstructure_fn(
            C, converter, a=override(path=("x", "y")), b=override(path=("x", "y"))
        )

    # A path being a prefix of another.
    with pytest.raises(ValueError, match="prefix"):
        make_dict_structure_fn(
            C, converter, a=override(path=("x",)), b=override(path=("x", "y"))
        )
    with pytest.raises(ValueError, match="prefix"):
        make_dict_unstructure_fn(
            C, converter, a=override(path=("x",)), b=override(path=("x", "y"))
        )

    # A renamed field colliding with a path.
    with pytest.raises(ValueError, match="prefix"):
        make_dict_unstructure_fn(
            C, converter, a=override(rename="x"), b=override(path=("x", "y"))
        )

    # Sibling paths and disjoint paths are fine.
    make_dict_structure_fn(
        C,
        converter,
        a=override(path=("x", "a")),
        b=override(path=("x", "b")),
        c=override(path=("y", "c")),
    )


def test_path_rename_mutually_exclusive() -> None:
    """`rename` and `path` cannot be combined."""
    with pytest.raises(ValueError):
        override(rename="x", path=("y",))


@pytest.mark.parametrize(
    "bad_path", [(), (0, "a"), ("a", -1), ("a", 1.5), ("a", True), ("a", None), 1]
)
def test_invalid_paths(bad_path) -> None:
    """Malformed paths are rejected eagerly."""
    with pytest.raises(ValueError):
        override(path=bad_path)


def test_path_shared_prefix_independence(converter: BaseConverter) -> None:
    """Results of separate unstructures do not share nested containers."""
    fn = make_dict_unstructure_fn(Profile, converter, **PATH_OVERRIDES)

    first = fn(Profile("Ana", "Berlin"))
    second = fn(Profile("Bob", "Paris"))
    first["profile"]["address"]["city"] = "MUTATED"
    assert second["profile"]["address"]["city"] == "Paris"


def test_path_structure_input_not_mutated(converter: BaseConverter) -> None:
    """The input mapping is not modified during structuring."""
    fn = make_dict_structure_fn(Profile, converter, **PATH_OVERRIDES)

    data = {
        "name": "Ana",
        "profile": {"address": {"city": "Berlin", "zip": "10115"}, "nick": "annie"},
    }
    snapshot = deepcopy(data)
    fn(data, Profile)
    assert data == snapshot


def test_path_omit_if_default(converter: BaseConverter) -> None:
    """Omitted defaults do not leave empty parent dicts behind."""
    fn = make_dict_unstructure_fn(
        Profile,
        converter,
        city=override(path=("profile", "address", "city")),
        zip_code=override(path=("profile", "address", "zip"), omit_if_default=True),
        nick=override(path=("profile", "nick"), omit_if_default=True),
    )

    assert fn(Profile("Ana", "Berlin")) == {
        "name": "Ana",
        "profile": {"address": {"city": "Berlin"}},
    }


def test_path_forbid_extra_keys(genconverter: Converter) -> None:
    """The first path segment is an allowed key for extra-key checks."""
    fn = make_dict_structure_fn(
        Profile, genconverter, _cattrs_forbid_extra_keys=True, **PATH_OVERRIDES
    )

    data = {
        "name": "Ana",
        "profile": {"address": {"city": "Berlin", "zip": "10115"}, "nick": "annie"},
    }
    assert fn(data, Profile) == Profile("Ana", "Berlin", "10115", "annie")

    # In detailed validation mode the error is wrapped in a ClassValidationError.
    with pytest.raises((ForbiddenExtraKeysError, ClassValidationError)):
        fn({**data, "junk": 1}, Profile)


def test_path_annotated_override(genconverter: Converter) -> None:
    """Paths work through `Annotated` metadata."""

    @define
    class C:
        a: int
        city: Annotated[str, override(path=("profile", "city"))]

    s_fn = make_dict_structure_fn(C, genconverter)
    u_fn = make_dict_unstructure_fn(C, genconverter)

    assert s_fn({"a": 1, "profile": {"city": "Berlin"}}, C) == C(1, "Berlin")
    assert u_fn(C(1, "Berlin")) == {"a": 1, "profile": {"city": "Berlin"}}


def test_path_generic(converter: BaseConverter) -> None:
    """Paths work on generic classes with resolved type variables."""

    @define
    class Box(Generic[T]):
        content: T
        tag: str

    s_fn = make_dict_structure_fn(
        Box[int], converter, content=override(path=("payload", "content"))
    )
    u_fn = make_dict_unstructure_fn(
        Box[int], converter, content=override(path=("payload", "content"))
    )

    assert s_fn({"payload": {"content": "1"}, "tag": "t"}, Box[int]) == Box(1, "t")
    assert u_fn(Box(1, "t")) == {"payload": {"content": 1}, "tag": "t"}


def test_path_nested_generic_fields(converter: BaseConverter) -> None:
    """Fields with nested generic types structure correctly under paths."""

    @define
    class C:
        items: list[int]

    fn = make_dict_structure_fn(C, converter, items=override(path=("data", "items")))

    assert fn({"data": {"items": ["1", "2"]}}, C) == C([1, 2])


def test_path_init_false(converter: BaseConverter) -> None:
    """Paths work for `init=False` fields."""

    @define
    class C:
        a: int
        b: int = field(init=False, default=5)

    fn = make_dict_structure_fn(
        C, converter, b=override(path=("x", "b")), _cattrs_include_init_false=True
    )

    res = fn({"a": 1, "x": {"b": 2}}, C)
    assert (res.a, res.b) == (1, 2)
    res = fn({"a": 1}, C)
    assert (res.a, res.b) == (1, 5)


def test_path_kw_only(converter: BaseConverter) -> None:
    """Paths work for keyword-only fields."""

    @define
    class C:
        a: int
        b: int = field(kw_only=True)

    s_fn = make_dict_structure_fn(C, converter, b=override(path=("x", "b")))
    u_fn = make_dict_unstructure_fn(C, converter, b=override(path=("x", "b")))

    assert s_fn({"a": 1, "x": {"b": 2}}, C) == C(1, b=2)
    assert u_fn(C(1, b=2)) == {"a": 1, "x": {"b": 2}}


def test_path_attached_to_overrides(converter: BaseConverter) -> None:
    """The generated hooks expose the path overrides."""
    s_fn = make_dict_structure_fn(Profile, converter, **PATH_OVERRIDES)
    u_fn = make_dict_unstructure_fn(Profile, converter, **PATH_OVERRIDES)

    assert s_fn.overrides["city"].path == ("profile", "address", "city")
    assert u_fn.overrides["city"].path == ("profile", "address", "city")
