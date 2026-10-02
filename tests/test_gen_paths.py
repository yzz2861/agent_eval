"""Tests for the `path` override of generated dict functions."""

from typing import Generic, List, Optional, TypeVar

import pytest
from attrs import define, field, frozen
from typing_extensions import Annotated, TypedDict

from cattrs import Converter
from cattrs.errors import ClassValidationError, ForbiddenExtraKeysError
from cattrs.gen import make_dict_structure_fn, make_dict_unstructure_fn, override
from cattrs.gen.typeddicts import make_dict_structure_fn as make_td_structure_fn
from cattrs.gen.typeddicts import make_dict_unstructure_fn as make_td_unstructure_fn

T = TypeVar("T")


@define
class Profile:
    name: str
    city: str
    zip_code: int = 0


PATHS = {
    "city": override(path=("profile", "address", "city")),
    "zip_code": override(path=("profile", "address", "zip")),
}


@pytest.fixture(params=[True, False], ids=["detailed", "non-detailed"])
def converter(request) -> Converter:
    return Converter(detailed_validation=request.param)


def test_structure_from_nested_path(converter: Converter):
    fn = make_dict_structure_fn(Profile, converter, **PATHS)

    res = fn({"name": "n", "profile": {"address": {"city": "Paris", "zip": 75000}}})

    assert res == Profile("n", "Paris", 75000)


def test_unstructure_to_nested_path(converter: Converter):
    fn = make_dict_unstructure_fn(Profile, converter, **PATHS)

    assert fn(Profile("n", "Paris", 75000)) == {
        "name": "n",
        "profile": {"address": {"city": "Paris", "zip": 75000}},
    }


def test_roundtrip(converter: Converter):
    payload = {"name": "n", "profile": {"address": {"city": "Paris", "zip": 1}}}
    st = make_dict_structure_fn(Profile, converter, **PATHS)
    un = make_dict_unstructure_fn(Profile, converter, **PATHS)

    assert un(st(payload)) == payload


def test_dotted_keys_are_single_segments(converter: Converter):
    """Keys containing dots must not be split."""

    @define
    class C:
        v: int

    st = make_dict_structure_fn(C, converter, v=override(path=("a.b", "c.d")))
    un = make_dict_unstructure_fn(C, converter, v=override(path=("a.b", "c.d")))

    assert st({"a.b": {"c.d": 5}}) == C(5)
    assert un(C(5)) == {"a.b": {"c.d": 5}}


def test_integer_indices(converter: Converter):
    @define
    class C:
        first: str
        third: str

    overrides = {
        "first": override(path=("items", 0)),
        "third": override(path=("items", 2)),
    }
    st = make_dict_structure_fn(C, converter, **overrides)
    un = make_dict_unstructure_fn(C, converter, **overrides)

    assert st({"items": ["a", None, "c"]}) == C("a", "c")
    assert un(C("a", "c")) == {"items": ["a", None, "c"]}


def test_missing_uses_default(converter: Converter):
    @define
    class C:
        a: int = 1

    fn = make_dict_structure_fn(C, converter, a=override(path=("p", "a")))

    assert fn({}) == C(1)
    assert fn({"p": {}}) == C(1)


def test_missing_required(converter: Converter):
    @define
    class C:
        a: int

    fn = make_dict_structure_fn(C, converter, a=override(path=("p", "a")))

    if converter.detailed_validation:
        with pytest.raises(ClassValidationError) as exc_info:
            fn({})
        assert isinstance(exc_info.value.exceptions[0], KeyError)
    else:
        with pytest.raises(KeyError):
            fn({})


def test_explicit_null_leaf(converter: Converter):
    """An explicit null is not the same as missing; it goes to the hook."""

    @define
    class C:
        a: Optional[int] = 1

    fn = make_dict_structure_fn(C, converter, a=override(path=("p", "a")))

    assert fn({"p": {"a": None}}) == C(None)


def test_explicit_null_leaf_invalid(converter: Converter):
    @define
    class C:
        a: int = 1

    fn = make_dict_structure_fn(C, converter, a=override(path=("p", "a")))

    if converter.detailed_validation:
        with pytest.raises(ClassValidationError):
            fn({"p": {"a": None}})
    else:
        with pytest.raises(TypeError):
            fn({"p": {"a": None}})


def test_explicit_null_intermediate(converter: Converter):
    """A null intermediate is an error, not a missing value."""

    @define
    class C:
        a: int = 1

    fn = make_dict_structure_fn(C, converter, a=override(path=("p", "a")))

    if converter.detailed_validation:
        with pytest.raises(ClassValidationError) as exc_info:
            fn({"p": None})
        assert isinstance(exc_info.value.exceptions[0], TypeError)
    else:
        with pytest.raises(TypeError):
            fn({"p": None})


def test_input_not_mutated(converter: Converter):
    fn = make_dict_structure_fn(Profile, converter, **PATHS)
    payload = {"name": "n", "profile": {"address": {"city": "Paris", "zip": 1}}}
    snapshot = {"name": "n", "profile": {"address": {"city": "Paris", "zip": 1}}}

    fn(payload)

    assert payload == snapshot


def test_unstructure_results_not_shared(converter: Converter):
    """Shared path prefixes must be rebuilt fresh on every call."""
    fn = make_dict_unstructure_fn(Profile, converter, **PATHS)

    first = fn(Profile("n", "a", 1))
    second = fn(Profile("n", "b", 2))
    first["profile"]["address"]["city"] = "mutated"

    assert second["profile"]["address"]["city"] == "b"
    assert fn(Profile("n", "c", 3))["profile"]["address"]["city"] == "c"


def test_omit_if_default(converter: Converter):
    @define
    class C:
        a: int = 1
        b: int = 2

    fn = make_dict_unstructure_fn(
        C,
        converter,
        _cattrs_omit_if_default=True,
        a=override(path=("p", "a")),
        b=override(path=("p", "b")),
    )

    assert fn(C(1, 5)) == {"p": {"b": 5}}
    # No container is created when everything is omitted.
    assert fn(C()) == {}


def test_forbid_extra_keys(converter: Converter):
    @define
    class C:
        a: int

    fn = make_dict_structure_fn(
        C, converter, _cattrs_forbid_extra_keys=True, a=override(path=("p", "a"))
    )

    assert fn({"p": {"a": 1}}) == C(1)
    with pytest.raises((ForbiddenExtraKeysError, ClassValidationError)):
        fn({"p": {"a": 1}, "extra": 2})


def test_annotated_override(converter: Converter):
    @define
    class C:
        a: Annotated[int, override(path=("p", "a"))]

    st = make_dict_structure_fn(C, converter)
    un = make_dict_unstructure_fn(C, converter)

    assert st({"p": {"a": 7}}) == C(7)
    assert un(C(7)) == {"p": {"a": 7}}


def test_include_init_false(converter: Converter):
    @define
    class C:
        a: int
        b: int = field(init=False, default=5)

    st = make_dict_structure_fn(
        C, converter, _cattrs_include_init_false=True, b=override(path=("p", "b"))
    )

    assert st({"a": 1, "p": {"b": 9}}).b == 9
    assert st({"a": 1}).b == 5

    un = make_dict_unstructure_fn(
        C, converter, _cattrs_include_init_false=True, b=override(path=("p", "b"))
    )

    inst = C(1)
    inst.b = 9
    assert un(inst) == {"a": 1, "p": {"b": 9}}


def test_generics(converter: Converter):
    @define
    class Inner(Generic[T]):
        val: T

    @define
    class Outer(Generic[T]):
        inner: Inner[T]
        tag: str = "t"

    st = make_dict_structure_fn(
        Outer[int], converter, inner=override(path=("payload", "inner"))
    )
    un = make_dict_unstructure_fn(
        Outer[int], converter, inner=override(path=("payload", "inner"))
    )

    res = st({"payload": {"inner": {"val": "3"}}, "tag": "z"})
    assert res == Outer(Inner(3), "z")
    assert isinstance(res.inner.val, int)
    assert un(res) == {"tag": "z", "payload": {"inner": {"val": 3}}}


def test_nested_generic_list(converter: Converter):
    @define
    class C(Generic[T]):
        vals: List[T]

    st = make_dict_structure_fn(C[int], converter, vals=override(path=("p", "vals")))

    res = st({"p": {"vals": ["1", "2"]}})
    assert res.vals == [1, 2]


def test_detailed_validation_notes_contain_path():
    @define
    class C:
        a: int

    fn = make_dict_structure_fn(C, Converter(), a=override(path=("p", "deep", "a")))

    with pytest.raises(ClassValidationError) as exc_info:
        fn({"p": {"deep": {"a": "not-an-int"}}})

    notes = exc_info.value.exceptions[0].__notes__
    assert any("path: p.deep.a" in note for note in notes)


@pytest.mark.parametrize(
    "fn_factory", [make_dict_structure_fn, make_dict_unstructure_fn]
)
def test_conflicting_identical_paths(fn_factory):
    @define
    class C:
        a: int = 0
        b: int = 0

    with pytest.raises(ValueError, match=r"[Cc]onflicting paths"):
        fn_factory(
            C, Converter(), a=override(path=("x", "y")), b=override(path=("x", "y"))
        )


@pytest.mark.parametrize(
    "fn_factory", [make_dict_structure_fn, make_dict_unstructure_fn]
)
def test_conflicting_prefix_paths(fn_factory):
    @define
    class C:
        a: int = 0
        b: int = 0

    with pytest.raises(ValueError, match=r"[Cc]onflicting paths"):
        fn_factory(C, Converter(), a=override(path=("x",)), b=override(path=("x", "y")))


@pytest.mark.parametrize(
    "fn_factory", [make_dict_structure_fn, make_dict_unstructure_fn]
)
def test_conflicting_container_types(fn_factory):
    @define
    class C:
        a: int = 0
        b: int = 0

    with pytest.raises(ValueError, match="container types"):
        fn_factory(
            C, Converter(), a=override(path=("x", 0)), b=override(path=("x", "y"))
        )


@pytest.mark.parametrize(
    "fn_factory", [make_dict_structure_fn, make_dict_unstructure_fn]
)
def test_conflicting_path_and_plain_field(fn_factory):
    """A plain field colliding with a path prefix is also a conflict."""

    @define
    class C:
        a: int = 0
        b: int = 0

    with pytest.raises(ValueError, match=r"[Cc]onflicting paths"):
        fn_factory(C, Converter(), a=override(path=("b", "y")))


@pytest.mark.parametrize(
    "fn_factory", [make_dict_structure_fn, make_dict_unstructure_fn]
)
def test_rename_and_path_are_mutually_exclusive(fn_factory):
    @define
    class C:
        a: int = 0

    with pytest.raises(ValueError, match="mutually exclusive"):
        fn_factory(C, Converter(), a=override(rename="z", path=("x", "y")))


@pytest.mark.parametrize(
    "bad_path",
    [(), ("x", -1), ("x", 1.5), (0, "x"), ("x", True), ("x", None)],
    ids=["empty", "negative", "float", "int-first", "bool", "none"],
)
@pytest.mark.parametrize(
    "fn_factory", [make_dict_structure_fn, make_dict_unstructure_fn]
)
def test_invalid_paths(fn_factory, bad_path):
    @define
    class C:
        a: int = 0

    with pytest.raises(ValueError, match="path"):
        fn_factory(C, Converter(), a=override(path=bad_path))


def test_sibling_paths_do_not_conflict():
    @define
    class C:
        a: int = 0
        b: int = 0
        c: int = 0

    # Same dict prefix, different keys; same list prefix, different indices.
    make_dict_structure_fn(
        C,
        Converter(),
        a=override(path=("x", "y")),
        b=override(path=("x", "z")),
        c=override(path=("l", 0)),
    )


def test_typeddicts_not_supported():
    class TD(TypedDict):
        a: int

    with pytest.raises(NotImplementedError):
        make_td_structure_fn(TD, Converter(), a=override(path=("p", "a")))
    with pytest.raises(NotImplementedError):
        make_td_unstructure_fn(TD, Converter(), a=override(path=("p", "a")))


def test_frozen_class_roundtrip():
    @frozen
    class C:
        a: int
        b: str = "x"

    converter = Converter()
    overrides = {"a": override(path=("p", "a")), "b": override(path=("p", "b"))}
    st = make_dict_structure_fn(C, converter, **overrides)
    un = make_dict_unstructure_fn(C, converter, **overrides)

    payload = {"p": {"a": 1, "b": "y"}}
    assert un(st(payload)) == payload
