"""Tests for the trust boundary between (untrusted) definitions and generated code.

The compiler and the structure metaclass generate Python source code from definitions.
These tests prove, using harmless side-effect markers, that crafted names and constant
expressions from definitions are never executed as code, that only an explicit subset of
constant expressions is accepted (rejected before any code is generated or executed), and
that the compiler and the interpreter produce identical results for legal structures -
including structures with Unicode names and nested anonymous structures.
"""

from __future__ import annotations

import io
import unicodedata
from typing import TYPE_CHECKING

import pytest

from dissect.cstruct import cstruct
from dissect.cstruct.compiler import is_safe_identifier
from dissect.cstruct.exception import ExpressionParserError, ParserError, UnknownIdentifierError
from dissect.cstruct.expression import Expression
from tests.util import verify_compiled

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

# Harmless side-effect marker: if any crafted name or expression were executed as Python
# code that somehow reached this module's globals, it would show up here.
SIDE_EFFECTS: list[str] = []

PAYLOAD = "SIDE_EFFECTS.append('pwned')"


@pytest.fixture(autouse=True)
def _reset_side_effects() -> Iterator[None]:
    SIDE_EFFECTS.clear()
    yield
    assert SIDE_EFFECTS == []


def load_and_check(cs: cstruct, cdef: str, compiled: bool) -> None:
    cs.load(cdef, compiled=compiled)
    assert SIDE_EFFECTS == []


def test_safe_identifier() -> None:
    assert is_safe_identifier("field")
    assert is_safe_identifier("_field1")
    assert is_safe_identifier("名前")
    assert is_safe_identifier(unicodedata.normalize("NFC", "e\u0301"))

    assert not is_safe_identifier("")
    assert not is_safe_identifier("class")
    assert not is_safe_identifier("a.b")
    assert not is_safe_identifier("1abc")
    assert not is_safe_identifier("a b")
    assert not is_safe_identifier("a'b")
    # Not NFC-normalized: the Python parser normalizes source identifiers to NFC (PEP 3131),
    # so this name must go through the _getattr/_setattr path to stay consistent
    assert not is_safe_identifier("e\u0301")


@pytest.mark.parametrize(
    "name",
    [
        # Python keywords
        "class",
        "for",
        "import",
        "def",
        "return",
        "global",
        # Dotted names
        "a.b",
        "os.system",
        # Dunder names
        "__class__",
        "__init__",
        "__dict__",
        # Names colliding with generated locals and symbols
        "_value0",
        "_type0",
        "values",
        "sizes",
        "cls",
        "stream",
        "obj",
        "context",
        "endian",
        "buf",
        "_count",
        # Unicode (NFC and NFD)
        "名前",
        "\u00e9",
        "e\u0301",
    ],
)
def test_crafted_field_names(cs: cstruct, compiled: bool, name: str) -> None:
    """Crafted field names are data, not code: reading and writing works and is consistent."""
    cdef = f"""
    struct test {{
        uint32 {name};
        uint32 other;
    }};
    """
    load_and_check(cs, cdef, compiled)
    assert verify_compiled(cs.test, compiled)

    if name in ("__class__", "__dict__"):
        # These names can't be set as attributes on an instance; both modes reject equally
        with pytest.raises(TypeError):
            cs.test(io.BytesIO(b"\x01\x00\x00\x00\x02\x00\x00\x00"))
        return

    obj = cs.test(io.BytesIO(b"\x01\x00\x00\x00\x02\x00\x00\x00"))
    assert SIDE_EFFECTS == []

    # The original name is preserved in the result
    assert obj.__values__[name] == 1
    assert obj.__values__["other"] == 2
    assert getattr(obj, name) == 1

    # Writing uses the original name as well
    assert obj.dumps() == b"\x01\x00\x00\x00\x02\x00\x00\x00"
    assert SIDE_EFFECTS == []


def test_crafted_field_names_consistent(compiled: bool) -> None:
    """Compiler and interpreter agree on structures with crafted field names."""
    names = ["class", "a.b", "名前", "e\u0301", "_value0", "values"]
    cdef = "struct test {\n" + "\n".join(f"    uint32 {name};" for name in names) + "\n};"

    cs = cstruct()
    load_and_check(cs, cdef, compiled)

    data = bytes(range(1, 4 * len(names) + 1))
    obj = cs.test(io.BytesIO(data))
    assert obj.dumps() == data
    assert list(obj.__values__) == names


def test_crafted_type_and_const_names(cs: cstruct, compiled: bool) -> None:
    """Crafted type and constant names are registered under their original name, never executed."""
    cdef = """
    #define SIDE_EFFECTS.append 1
    #define 定数 0x2a
    #define SIDE_EFFECTS 7

    struct os.system {
        uint32 a;
    };

    struct test {
        os.system a;
        uint32 b[定数];
    };
    """
    load_and_check(cs, cdef, compiled)

    # Payload-like define values are inert constants
    assert cs.consts["SIDE_EFFECTS.append"] == 1
    assert cs.consts["定数"] == 0x2A
    assert cs.consts["SIDE_EFFECTS"] == 7

    obj = cs.test(io.BytesIO(b"\x01\x00\x00\x00" + b"\x00" * 0x2A * 4))
    assert obj.a.a == 1
    assert len(obj.b) == 0x2A
    assert SIDE_EFFECTS == []


def test_define_payload_is_inert(cs: cstruct, compiled: bool) -> None:
    """A define value that looks like Python code is stored as a string, never evaluated."""
    load_and_check(cs, '#define X __import__("os").system("echo pwned")', compiled)
    assert cs.consts["X"] == '__import__("os").system("echo pwned")'

    load_and_check(cs, f"#define Y {PAYLOAD}", compiled)
    assert cs.consts["Y"] == PAYLOAD
    assert SIDE_EFFECTS == []


@pytest.mark.parametrize(
    "expression",
    [
        PAYLOAD,
        "SIDE_EFFECTS.append(1)",
        "__import__('os')",
        "a b",
        "1 +",
        "(1",
        "1)",
        "()",
        "1 2",
        "nosuchfunc(1)",
    ],
)
def test_expression_subset_rejected_at_load(cs: cstruct, compiled: bool, expression: str) -> None:
    """Expressions outside the subset are rejected at load, before any code is generated or executed."""
    with pytest.raises(ParserError):
        cs.load(f"struct test {{ uint8 a[{expression}]; }};", compiled=compiled)
    assert SIDE_EFFECTS == []


def test_expression_subset_rejected_in_enum(cs: cstruct, compiled: bool) -> None:
    with pytest.raises(ParserError):
        cs.load(f"enum E {{ A = {PAYLOAD} }};", compiled=compiled)
    assert SIDE_EFFECTS == []


@pytest.mark.parametrize(
    "expression",
    [
        "1 + 2 * 3",
        "(1 | 2) & 3",
        "1 << 4",
        "8 >> 1",
        "-1 + 2",
        "~1 + 4",
        "10 % 3",
        "10 / 3",
        "sizeof(uint32)",
        "CONST",
        "CONST * 2",
    ],
)
def test_expression_subset_accepted(cs: cstruct, compiled: bool, expression: str) -> None:
    """The explicit subset of constant expressions keeps working."""
    cs.load(
        f"""
    #define CONST 4
    struct test {{
        uint8 a[{expression}];
    }};
    """,
        compiled=compiled,
    )
    assert verify_compiled(cs.test, compiled)

    expected = Expression(expression).evaluate(cs)
    obj = cs.test(io.BytesIO(bytes(range(expected))))
    assert list(obj.a) == list(range(expected))
    assert SIDE_EFFECTS == []


def test_expression_validate_does_not_resolve() -> None:
    """Validation checks syntax only: it neither resolves identifiers nor generates code."""
    Expression("SIDE_EFFECTS.append + 1").validate()  # unknown identifier, but syntactically valid
    with pytest.raises(ExpressionParserError):
        Expression("1 +").validate()
    with pytest.raises(ExpressionParserError):
        Expression("a b").validate()
    assert SIDE_EFFECTS == []


def test_dynamic_array_expression(cs: cstruct, compiled: bool) -> None:
    """Array sizes referring to earlier fields are evaluated at read time, in both modes."""
    load_and_check(
        cs,
        """
    struct test {
        uint8 n;
        uint8 a[n * 2 + 1];
    };
    """,
        compiled,
    )
    assert verify_compiled(cs.test, compiled)

    obj = cs.test(io.BytesIO(b"\x02" + bytes(range(5))))
    assert obj.n == 2
    assert list(obj.a) == [0, 1, 2, 3, 4]
    assert SIDE_EFFECTS == []


def test_unknown_identifier_error_keeps_name(cs: cstruct, compiled: bool) -> None:
    """Errors for dynamic expressions report the original identifier."""
    load_and_check(cs, "struct test { uint8 a[名前]; };", compiled)
    with pytest.raises(UnknownIdentifierError, match="名前"):
        cs.test(io.BytesIO(b"\x00"))
    assert SIDE_EFFECTS == []


def test_parser_error_keeps_original_name(cs: cstruct, compiled: bool) -> None:
    """Parse errors point at the original source, including Unicode names."""
    with pytest.raises(ParserError) as excinfo:
        cs.load("struct test { uint8 a[名前 +]; };", compiled=compiled)
    assert "名前" in str(excinfo.value)
    assert SIDE_EFFECTS == []


def test_unicode_names(cs: cstruct, compiled: bool) -> None:
    """Legal Unicode names are fully supported, not blanket-disabled."""
    cdef = """
    #define 定数 2

    enum 色 : uint8 {
        赤 = 1,
        緑 = 2,
    };

    struct 構造体 {
        uint32 名前;
        色 色;
        uint16 値[定数];
    };
    """
    load_and_check(cs, cdef, compiled)
    assert verify_compiled(cs.構造体, compiled)

    data = b"\x2a\x00\x00\x00\x02\x01\x00\x02\x00"
    obj = cs.構造体(io.BytesIO(data))
    assert obj.名前 == 42
    assert obj.色 == cs.色.緑
    assert list(obj.値) == [1, 2]
    assert obj.__values__["名前"] == 42
    assert obj.dumps() == data
    assert SIDE_EFFECTS == []


def test_unicode_names_nfd_consistent(compiled: bool) -> None:
    """Non-NFC-normalized Unicode names behave identically in compiled and interpreted mode."""
    name = "e\u0301"  # 'e' + combining acute, not NFC-normalized
    assert not is_safe_identifier(name)

    cs = cstruct()
    load_and_check(cs, f"struct test {{ uint32 {name}; uint32 other; }};", compiled)

    obj = cs.test(io.BytesIO(b"\x01\x00\x00\x00\x02\x00\x00\x00"))
    assert getattr(obj, name) == 1
    assert obj.__values__[name] == 1
    assert obj.dumps() == b"\x01\x00\x00\x00\x02\x00\x00\x00"


def test_nested_anonymous_structures(cs: cstruct, compiled: bool) -> None:
    """Nested anonymous structures and unions keep working in both modes."""
    cdef = """
    struct test {
        uint32 a;
        struct {
            uint16 b;
            struct {
                uint8 c;
                uint8 d;
            };
        };
        union {
            uint32 e;
            uint8 f[4];
        };
        uint32 g;
    };
    """
    load_and_check(cs, cdef, compiled)
    assert verify_compiled(cs.test, compiled)

    data = bytes(range(1, 17))
    obj = cs.test(io.BytesIO(data))
    assert (obj.a, obj.b, obj.c, obj.d, obj.e, obj.g) == (0x04030201, 0x0605, 7, 8, 0x0C0B0A09, 0x100F0E0D)
    assert list(obj.f) == [9, 10, 11, 12]
    assert obj.dumps() == data
    assert SIDE_EFFECTS == []


def test_nested_anonymous_structure_names_preserved(cs: cstruct, compiled: bool) -> None:
    """Fields of nested anonymous structures are folded under their original names."""
    load_and_check(
        cs,
        """
    struct test {
        struct {
            uint32 名前;
        };
        uint32 other;
    };
    """,
        compiled,
    )

    obj = cs.test(io.BytesIO(b"\x01\x00\x00\x00\x02\x00\x00\x00"))
    assert obj.名前 == 1
    assert obj.other == 2
    assert list(obj.__values__) == ["名前", "other"]


def test_full_entry_points(tmp_path: Path, compiled: bool) -> None:
    """The trust boundary holds for every way of loading definitions and reading data."""
    cdef = f"""
    #define X {PAYLOAD}
    struct test {{
        uint32 class;
        uint32 名前;
    }};
    """

    # Constructor entry point (always compiles)
    cs = cstruct(cdef)
    assert verify_compiled(cs.test, True)
    if not compiled:
        cs = cstruct()
        cs.load(cdef, compiled=False)
        assert verify_compiled(cs.test, False)

    # loadfile entry point
    path = tmp_path / "testdef.txt"
    path.write_text(cdef)
    cs2 = cstruct()
    cs2.loadfile(path, compiled=compiled)

    for instance in (cs, cs2):
        assert instance.consts["X"] == PAYLOAD

        # Bytes, stream and file-like entry points
        for source in (
            io.BytesIO(b"\x01\x00\x00\x00\x02\x00\x00\x00"),
            b"\x01\x00\x00\x00\x02\x00\x00\x00",
        ):
            obj = instance.test(source)
            assert obj.__values__ == {"class": 1, "名前": 2}
            assert obj.dumps() == b"\x01\x00\x00\x00\x02\x00\x00\x00"

    assert SIDE_EFFECTS == []
