#!/usr/bin/env python3
"""Static range audit for a small C expression.

This example uses pycparser's AST to answer a narrow question:

    Given a caller-supplied target ABI (the width of ``int`` and the type of
    the log field), does every value of this C expression provably stay in
    the business interval [min, max]?

It is deliberately *not* a compiler and it never compiles or runs firmware.
The evaluator models the parts of C integer semantics that commonly change
the answer between boards:

* integer promotions (``unsigned short`` may promote to ``int`` or
  ``unsigned int`` depending on the width of ``int``);
* the usual arithmetic conversions;
* unsigned modular arithmetic and signed-overflow undefined behaviour;
* explicit integer casts, including truncation;
* assignment/final conversion to the log field type;
* ``?:`` with a finite, constant condition branch;
* unknown types or identifiers, which are reported as needing confirmation
  instead of being guessed.

The output includes a per-target trace suitable for a code review.  A small
hand-checkable example is built in; run this file with no arguments.

Example command::

    python examples/expr_range_audit.py \\
        --expr '(health - baseline) * 10' \\
        --var 'health=uint16_t@0..1000' \\
        --var 'baseline=uint16_t@800..800' \\
        --target 'board-16=int32_t@16' \\
        --target 'board-32=int32_t@32' \\
        --bounds=-8000..2000

The interesting threshold in that example is not the final value range: it is
whether ``int`` can represent every ``uint16_t`` value.  With a 16-bit
``int`` it cannot, so ``uint16_t`` promotes to 16-bit ``unsigned int`` and
``health - baseline`` wraps.  With a 32-bit ``int`` it promotes to signed
``int`` and the expression is safe.  See the built-in demo output.
"""

from __future__ import annotations

import argparse
import itertools
import json
import re
import sys
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

# This is not required if pycparser is installed in site-packages.
sys.path.extend([".", ".."])

from pycparser import c_ast, c_generator, c_parser


# ---------------------------------------------------------------------------
# Types


@dataclass(frozen=True)
class IntType:
    """A concrete C integer type in one target ABI."""

    name: str
    bits: int
    signed: bool
    rank: int

    @property
    def minimum(self) -> int:
        return -(1 << (self.bits - 1)) if self.signed else 0

    @property
    def maximum(self) -> int:
        return (1 << (self.bits - 1)) - 1 if self.signed else (1 << self.bits) - 1


@dataclass(frozen=True)
class UnknownType:
    """A type the target ABI model cannot resolve."""

    name: str


CType = IntType | UnknownType


_QUALIFIERS = frozenset({"const", "volatile", "restrict", "_Atomic"})
_NON_INTEGER_WORDS = frozenset(
    {"void", "float", "double", "_Complex", "struct", "union", "enum"}
)
_TYPE_WORDS = frozenset(
    {"char", "short", "int", "long", "signed", "unsigned", "_Bool", "bool"}
)


def canonical_type_name(text: str) -> str:
    """Return a normalized spelling for the integer type names we model."""

    text = text.strip()
    if not text:
        return text

    tokens = re.findall(r"[A-Za-z_]\w*", text)
    if not tokens:
        return text

    tokens = [token for token in tokens if token not in _QUALIFIERS]
    if not tokens:
        return text

    if any(token in _NON_INTEGER_WORDS for token in tokens):
        return " ".join(tokens)

    if len(tokens) == 1 and tokens[0] not in _TYPE_WORDS:
        # A typedef or an explicitly overridden type name.
        return tokens[0]

    if "bool" in tokens:
        return "_Bool"
    if "_Bool" in tokens:
        return "_Bool"

    if "char" in tokens:
        if "unsigned" in tokens:
            return "unsigned char"
        if "signed" in tokens:
            return "signed char"
        return "char"

    if "short" in tokens:
        return "unsigned short" if "unsigned" in tokens else "short"

    long_count = tokens.count("long")
    if long_count >= 2:
        base = "long long"
    elif long_count == 1:
        base = "long"
    else:
        base = "int"

    return f"unsigned {base}" if "unsigned" in tokens else base


class TypeModel:
    """Integer types and conversions for one target ``int`` width."""

    def __init__(
        self,
        int_width: int,
        *,
        char_signed: bool = True,
        char_bits: int = 8,
        type_widths: Mapping[str, tuple[int, bool]] | None = None,
        typedefs: Mapping[str, str] | None = None,
    ) -> None:
        if int_width < 8:
            raise ValueError("integer width must be at least 8 bits")
        if char_bits < 1:
            raise ValueError("char width must be at least 1 bit")

        self.int_width = int_width
        self.char_bits = char_bits
        self.short_width = min(16, int_width)
        self.long_width = max(32, int_width)
        self.long_long_width = max(64, self.long_width)
        self.typedefs = {
            canonical_type_name(name): target
            for name, target in (typedefs or {}).items()
        }
        self.extra_widths = dict(type_widths or {})
        self.types: dict[str, IntType] = {}

        self._add("_Bool", 1, False, 0)
        self._add("bool", 1, False, 0)
        self._add("char", char_bits, char_signed, 1)
        self._add("signed char", char_bits, True, 1)
        self._add("unsigned char", char_bits, False, 1)
        self._add("short", self.short_width, True, 2)
        self._add("short int", self.short_width, True, 2)
        self._add("signed short", self.short_width, True, 2)
        self._add("signed short int", self.short_width, True, 2)
        self._add("unsigned short", self.short_width, False, 2)
        self._add("unsigned short int", self.short_width, False, 2)
        self._add("int", int_width, True, 3)
        self._add("signed", int_width, True, 3)
        self._add("signed int", int_width, True, 3)
        self._add("unsigned", int_width, False, 3)
        self._add("unsigned int", int_width, False, 3)
        self._add("long", self.long_width, True, 4)
        self._add("long int", self.long_width, True, 4)
        self._add("signed long", self.long_width, True, 4)
        self._add("signed long int", self.long_width, True, 4)
        self._add("unsigned long", self.long_width, False, 4)
        self._add("unsigned long int", self.long_width, False, 4)
        self._add("long long", self.long_long_width, True, 5)
        self._add("long long int", self.long_long_width, True, 5)
        self._add("signed long long", self.long_long_width, True, 5)
        self._add("signed long long int", self.long_long_width, True, 5)
        self._add("unsigned long long", self.long_long_width, False, 5)
        self._add("unsigned long long int", self.long_long_width, False, 5)
        self._add("intmax_t", self.long_long_width, True, 5)
        self._add("uintmax_t", self.long_long_width, False, 5)

        for name, (bits, signed) in self.extra_widths.items():
            if bits < 1:
                raise ValueError(f"width for {name!r} must be positive")
            canonical = canonical_type_name(name)
            self.types[canonical] = IntType(
                canonical, bits, signed, self._rank_for_width(bits)
            )

    def _add(self, name: str, bits: int, signed: bool, rank: int) -> None:
        self.types[name] = IntType(name, bits, signed, rank)

    def _rank_for_width(self, bits: int) -> int:
        if bits <= self.char_bits:
            return 1
        if bits <= self.short_width:
            return 2
        if bits <= self.int_width:
            return 3
        if bits <= self.long_width:
            return 4
        return 5

    def _fixed_width_type(self, name: str) -> IntType | None:
        match = re.fullmatch(r"(u?)int(8|16|32|64)_t", name)
        if not match:
            return None
        bits = int(match.group(2))
        signed = match.group(1) != "u"
        return IntType(name, bits, signed, self._rank_for_width(bits))

    def resolve_string(self, text: str, seen: frozenset[str] = frozenset()) -> CType:
        canonical = canonical_type_name(text)
        if canonical in self.typedefs and canonical not in seen:
            return self.resolve_string(
                self.typedefs[canonical], seen | {canonical}
            )
        if canonical in self.types:
            return self.types[canonical]

        fixed = self._fixed_width_type(canonical)
        if fixed is not None:
            return fixed

        if canonical in self.extra_widths:
            bits, signed = self.extra_widths[canonical]
            return IntType(canonical, bits, signed, self._rank_for_width(bits))

        return UnknownType(canonical or text.strip())

    def resolve_type_node(self, node: c_ast.Node) -> CType:
        while isinstance(node, c_ast.TypeDecl):
            node = node.type

        if isinstance(node, c_ast.IdentifierType):
            return self.resolve_string(" ".join(node.names))

        if isinstance(node, c_ast.Enum):
            return UnknownType("enum")
        if isinstance(node, (c_ast.Struct, c_ast.Union)):
            return UnknownType(node.name or node.__class__.__name__.lower())
        if isinstance(node, (c_ast.PtrDecl, c_ast.ArrayDecl, c_ast.FuncDecl)):
            return UnknownType("non-integer type")
        if isinstance(node, c_ast.Typename):
            return self.resolve_type_node(node.type)

        return UnknownType(node.__class__.__name__)

    def promote(self, ctype: CType) -> CType:
        if isinstance(ctype, UnknownType):
            return ctype
        if ctype.rank >= 3:
            return ctype

        int_type = self.types["int"]
        if ctype.signed or ctype.bits < self.int_width:
            return int_type
        return self.types["unsigned int"]

    def unsigned_like(self, ctype: IntType) -> IntType:
        if not ctype.signed:
            return ctype

        if ctype.rank == 1:
            name = "unsigned char"
        elif ctype.rank == 2:
            name = "unsigned short"
        elif ctype.rank == 3:
            name = "unsigned int"
        elif ctype.rank == 4:
            name = "unsigned long"
        else:
            name = "unsigned long long"

        return IntType(name, ctype.bits, False, ctype.rank)

    def usual_arithmetic(self, left: CType, right: CType) -> CType:
        if isinstance(left, UnknownType):
            return left
        if isinstance(right, UnknownType):
            return right
        if left == right:
            return left

        if left.signed == right.signed:
            if left.rank != right.rank:
                return left if left.rank > right.rank else right
            return left if left.bits >= right.bits else right

        if left.signed:
            signed, unsigned = left, right
        else:
            signed, unsigned = right, left

        if unsigned.rank > signed.rank:
            return unsigned
        if unsigned.rank == signed.rank:
            return unsigned if unsigned.bits >= signed.bits else signed
        if signed.bits > unsigned.bits:
            return signed
        return self.unsigned_like(signed)


# ---------------------------------------------------------------------------
# Ranges and issues

Interval = tuple[int, int]


@dataclass(frozen=True)
class Issue:
    kind: str
    detail: str


@dataclass(frozen=True)
class Value:
    ctype: CType
    intervals: tuple[Interval, ...] | None
    issues: frozenset[Issue] = frozenset()


def _normalize_ranges(intervals: Iterable[Interval]) -> tuple[Interval, ...]:
    ordered = sorted((lo, hi) for lo, hi in intervals if lo <= hi)
    merged: list[Interval] = []
    for lo, hi in ordered:
        if not merged or lo > merged[-1][1] + 1:
            merged.append((lo, hi))
        else:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
    return tuple(merged)


def _union_ranges(*sets: Iterable[Interval]) -> tuple[Interval, ...]:
    return _normalize_ranges(itertools.chain.from_iterable(sets))


def _mod_image(lo: int, hi: int, bits: int) -> tuple[Interval, ...]:
    """Image of every integer in [lo, hi] modulo 2**bits."""

    modulus = 1 << bits
    if hi - lo >= modulus - 1:
        return ((0, modulus - 1),)

    start = lo % modulus
    end = start + (hi - lo)
    if end < modulus:
        return ((start, end),)
    return ((start, modulus - 1), (0, end - modulus))


def _trunc_div(numerator: int, denominator: int) -> int:
    """C integer division: truncate toward zero."""

    quotient = abs(numerator) // abs(denominator)
    return quotient if (numerator >= 0) == (denominator >= 0) else -quotient


def _trunc_mod(numerator: int, denominator: int) -> int:
    return numerator - _trunc_div(numerator, denominator) * denominator


def _range_text(intervals: tuple[Interval, ...] | None) -> str:
    if intervals is None:
        return "unknown"
    if not intervals:
        return "empty"
    parts = []
    for lo, hi in intervals:
        parts.append(str(lo) if lo == hi else f"{lo}..{hi}")
    return " | ".join(parts)


def _type_text(ctype: CType) -> str:
    if isinstance(ctype, UnknownType):
        return f"unknown type '{ctype.name}'"
    signedness = "signed" if ctype.signed else "unsigned"
    return f"{ctype.name} ({ctype.bits}-bit {signedness})"


# ---------------------------------------------------------------------------
# Expression evaluation


@dataclass(frozen=True)
class VariableSpec:
    name: str
    c_type: str
    minimum: int | None = None
    maximum: int | None = None


_INT_LITERAL_RE = re.compile(
    r"(?P<number>0[xX][0-9a-fA-F]+|0[bB][01]+|0[0-7]*|[1-9][0-9]*)"
    r"(?P<suffix>[uUlL]*)"
)


class Evaluator:
    """Evaluate one expression for one target ABI."""

    def __init__(
        self,
        model: TypeModel,
        variables: Sequence[VariableSpec],
        *,
        trace: bool = True,
    ) -> None:
        self.model = model
        self.trace_enabled = trace
        self.trace_lines: list[str] = []
        self._generator = c_generator.CGenerator()
        self.variables: dict[str, tuple[VariableSpec, CType]] = {}
        for spec in variables:
            self.variables[spec.name] = (spec, model.resolve_string(spec.c_type))

    # -- public entry points -------------------------------------------------

    def evaluate(self, node: c_ast.Node) -> Value:
        method = getattr(self, f"eval_{node.__class__.__name__}", None)
        if method is None:
            return self._unknown(
                node,
                "unsupported",
                f"unsupported C construct: {node.__class__.__name__}",
            )
        return method(node)

    def convert_final(self, value: Value, field_type: CType) -> Value:
        if isinstance(field_type, UnknownType):
            issue = Issue(
                "unknown_type",
                f"log field type '{field_type.name}' is not in the target ABI model",
            )
            return Value(field_type, None, value.issues | {issue})

        converted = self._convert(value, field_type, kind="field")
        self._record_line(
            "final field conversion",
            converted,
            f"assignment to {_type_text(field_type)}",
        )
        return converted

    # -- trace helpers -------------------------------------------------------

    def _expr_text(self, node: c_ast.Node) -> str:
        try:
            text = self._generator.visit(node)
        except Exception:
            text = node.__class__.__name__
        text = " ".join(text.split())
        if len(text) > 96:
            text = text[:93] + "..."
        return text

    def _record(self, node: c_ast.Node, value: Value, note: str = "") -> Value:
        if not self.trace_enabled:
            return value
        self._record_line(self._expr_text(node), value, note)
        return value

    def _record_line(self, text: str, value: Value, note: str = "") -> None:
        if not self.trace_enabled:
            return
        line = (
            f"{text}: {_type_text(value.ctype)} = "
            f"{_range_text(value.intervals)}"
        )
        if note:
            line += f"; {note}"
        elif value.issues:
            kinds = ", ".join(sorted({issue.kind for issue in value.issues}))
            line += f"; issues: {kinds}"
        self.trace_lines.append(line)

    def _unknown(
        self, node: c_ast.Node, kind: str, detail: str, ctype: CType | None = None
    ) -> Value:
        issue = Issue(kind, detail)
        value = Value(
            ctype or UnknownType(node.__class__.__name__), None, frozenset({issue})
        )
        return self._record(node, value)

    # -- leaves --------------------------------------------------------------

    def eval_ID(self, node: c_ast.ID) -> Value:
        entry = self.variables.get(node.name)
        if entry is None:
            return self._unknown(
                node,
                "unknown_identifier",
                f"identifier '{node.name}' has no declared type; "
                f"declare it with --var {node.name}=TYPE",
            )

        spec, base_type = entry
        if isinstance(base_type, UnknownType):
            issue = Issue(
                "unknown_type",
                f"variable '{node.name}' has unknown type '{base_type.name}'; "
                "confirm it with --type-width or --typedef",
            )
            value = Value(base_type, None, frozenset({issue}))
            return self._record(node, value)

        minimum = spec.minimum if spec.minimum is not None else base_type.minimum
        maximum = spec.maximum if spec.maximum is not None else base_type.maximum
        issues: set[Issue] = set()
        if minimum > maximum:
            issues.add(
                Issue(
                    "assumption_conflict",
                    f"assumed range for '{node.name}' is empty "
                    f"({minimum}..{maximum})",
                )
            )
            intervals = None
        else:
            clamped_lo = max(minimum, base_type.minimum)
            clamped_hi = min(maximum, base_type.maximum)
            if clamped_lo != minimum or clamped_hi != maximum:
                issues.add(
                    Issue(
                        "assumption_outside_type",
                        f"assumed range for '{node.name}' "
                        f"({minimum}..{maximum}) is partly outside "
                        f"{_type_text(base_type)}",
                    )
                )
            intervals = (
                ((clamped_lo, clamped_hi),) if clamped_lo <= clamped_hi else None
            )

        promoted_type = self.model.promote(base_type)
        note = ""
        if promoted_type != base_type:
            if base_type.signed:
                note = "integer promotion to int"
            elif base_type.bits < self.model.int_width:
                note = "integer promotion to signed int; int represents all values"
            else:
                note = (
                    "integer promotion to unsigned int; "
                    f"{self.model.int_width}-bit int cannot represent all "
                    f"{base_type.name} values"
                )

        value = Value(promoted_type, intervals, frozenset(issues))
        return self._record(node, value, note)

    def eval_Constant(self, node: c_ast.Constant) -> Value:
        text = node.value.strip()
        if text.startswith("'") or text.startswith("L'"):
            return self._eval_char_constant(node, text)

        match = _INT_LITERAL_RE.fullmatch(text)
        if not match:
            return self._unknown(
                node,
                "unsupported",
                f"only integer constants are modeled, got {text!r}",
            )

        number_text = match.group("number")
        suffix = match.group("suffix").lower()
        if number_text.lower().startswith("0x"):
            base = 16
        elif number_text.lower().startswith("0b"):
            base = 2
        elif len(number_text) > 1 and number_text.startswith("0"):
            base = 8
        else:
            base = 10

        try:
            number = int(number_text, base)
        except ValueError:
            return self._unknown(
                node, "unsupported", f"invalid integer constant {text!r}"
            )

        unsigned = "u" in suffix
        long_count = suffix.count("l")
        candidates = self._literal_candidates(base, unsigned, long_count)
        for name in candidates:
            ctype = self.model.resolve_string(name)
            if isinstance(ctype, UnknownType):
                continue
            if ctype.minimum <= number <= ctype.maximum:
                return Value(ctype, ((number, number),))

        issue = Issue(
            "literal_too_large",
            f"integer constant {text!r} does not fit any modeled C integer type",
        )
        return Value(UnknownType("integer constant"), None, frozenset({issue}))

    def _literal_candidates(
        self, base: int, unsigned: bool, long_count: int
    ) -> list[str]:
        if long_count == 0:
            signed = ["int", "long", "long long"]
        elif long_count == 1:
            signed = ["long", "long long"]
        else:
            signed = ["long long"]

        if unsigned:
            return [f"unsigned {name}" for name in signed]

        if base == 10:
            return signed

        # Hexadecimal and octal literals consider unsigned types at each rank.
        candidates: list[str] = []
        for name in signed:
            candidates.append(name)
            candidates.append(f"unsigned {name}")
        return candidates

    def _eval_char_constant(self, node: c_ast.Constant, text: str) -> Value:
        if text.startswith("L'"):
            return self._unknown(
                node,
                "unknown_type",
                "wide character constant depends on wchar_t width; confirm it",
            )

        body = text[1:-1]
        simple_escapes = {
            "\\0": 0,
            "\\a": 7,
            "\\b": 8,
            "\\t": 9,
            "\\n": 10,
            "\\v": 11,
            "\\f": 12,
            "\\r": 13,
            "\\\\": 92,
            "\\'": 39,
            '\\"': 34,
        }
        if body in simple_escapes:
            value = simple_escapes[body]
        elif body.startswith("\\x"):
            try:
                value = int(body[2:], 16)
            except ValueError:
                return self._unknown(
                    node, "unsupported", f"invalid character constant {text!r}"
                )
        elif re.fullmatch(r"\\[0-7]{1,3}", body):
            value = int(body[1:], 8)
        elif len(body) == 1:
            value = ord(body)
        else:
            return self._unknown(
                node,
                "unsupported",
                "multi-character constants are implementation-defined",
            )

        int_type = self.model.types["int"]
        return Value(int_type, ((value, value),))

    # -- operations ----------------------------------------------------------

    def eval_UnaryOp(self, node: c_ast.UnaryOp) -> Value:
        if node.op in ("sizeof", "alignof", "_Alignof"):
            return self._eval_sizeof_like(node)

        operand = self.evaluate(node.expr)
        promoted = self._promote_value(operand)

        if node.op == "!":
            state = self._truth_state(promoted)
            if state is True:
                value = self._int_value(0)
            elif state is False:
                value = self._int_value(1)
            else:
                value = Value(self.model.types["int"], ((0, 1),), promoted.issues)
            return self._record(node, value)

        if node.op == "+":
            return self._record(node, promoted, "integer promotion")

        if promoted.intervals is None:
            return self._record(
                node,
                Value(promoted.ctype, None, promoted.issues),
                f"unary {node.op}",
            )

        if node.op == "-":
            intervals = tuple((-hi, -lo) for lo, hi in promoted.intervals)
            value = self._fit_to_type(
                promoted.ctype,
                intervals,
                unsigned_issue="unsigned_wrap",
                signed_issue="signed_overflow",
            )
            value = Value(
                value.ctype, value.intervals, promoted.issues | value.issues
            )
            return self._record(node, value, "unary minus")

        if node.op == "~":
            if not isinstance(promoted.ctype, IntType):
                return self._record(node, promoted, "bitwise complement")
            if promoted.ctype.signed:
                issue = Issue(
                    "implementation_defined",
                    "bitwise complement of a signed value depends on the "
                    "signed representation",
                )
                value = Value(
                    promoted.ctype, None, promoted.issues | {issue}
                )
                return self._record(node, value, "signed bitwise complement")

            maximum = promoted.ctype.maximum
            intervals = tuple(
                (maximum - hi, maximum - lo) for lo, hi in promoted.intervals
            )
            value = Value(promoted.ctype, _normalize_ranges(intervals), promoted.issues)
            return self._record(node, value, "bitwise complement")

        return self._unknown(
            node, "unsupported", f"unary operator {node.op!r} is not modeled"
        )

    def _eval_sizeof_like(self, node: c_ast.UnaryOp) -> Value:
        size_type = self.model.resolve_string("size_t")
        if isinstance(size_type, UnknownType):
            issue = Issue(
                "unknown_type",
                "sizeof/alignof result type size_t is ABI-dependent; confirm it "
                "with --type-width size_t=BITS[:s|u]",
            )
            value = Value(size_type, None, frozenset({issue}))
            return self._record(node, value, "unknown size_t")

        if node.op != "sizeof":
            issue = Issue(
                "unsupported",
                f"{node.op} depends on ABI alignment rules that are not modeled",
            )
            value = Value(size_type, None, frozenset({issue}))
            return self._record(node, value, "alignment is not modeled")

        if isinstance(node.expr, c_ast.Typename):
            subject_type = self.model.resolve_type_node(node.expr)
        elif isinstance(node.expr, c_ast.ID):
            entry = self.variables.get(node.expr.name)
            subject_type = (
                entry[1]
                if entry is not None
                else UnknownType(f"unknown identifier {node.expr.name!r}")
            )
        elif isinstance(node.expr, c_ast.Cast):
            subject_type = self.model.resolve_type_node(node.expr.to_type)
        else:
            trace_length = len(self.trace_lines)
            subject = self.evaluate(node.expr)
            del self.trace_lines[trace_length:]
            subject_type = subject.ctype

        if not isinstance(subject_type, IntType):
            issue = Issue(
                "unknown_type",
                f"sizeof operand has unknown or non-integer type "
                f"{_type_text(subject_type)}",
            )
            value = Value(size_type, None, frozenset({issue}))
            return self._record(node, value, "unknown sizeof operand type")

        if subject_type.bits % self.model.char_bits != 0:
            issue = Issue(
                "unknown_type",
                f"sizeof({_type_text(subject_type)}) is not a whole number of "
                f"{self.model.char_bits}-bit chars",
            )
            value = Value(size_type, None, frozenset({issue}))
            return self._record(node, value, "non-integral byte size")

        size = subject_type.bits // self.model.char_bits
        value = Value(size_type, ((size, size),))
        return self._record(
            node, value, f"sizeof({_type_text(subject_type)}) = {size} bytes"
        )

    def eval_BinaryOp(self, node: c_ast.BinaryOp) -> Value:
        if node.op == ",":
            left = self.evaluate(node.left)
            right = self.evaluate(node.right)
            return self._record(
                node,
                Value(right.ctype, right.intervals, left.issues | right.issues),
                "comma operator",
            )

        if node.op in ("&&", "||"):
            return self._eval_logical(node)

        left = self.evaluate(node.left)
        right = self.evaluate(node.right)
        left = self._promote_value(left)
        right = self._promote_value(right)

        if node.op in ("<<", ">>"):
            return self._eval_shift(node, left, right)

        common = self.model.usual_arithmetic(left.ctype, right.ctype)
        if isinstance(common, UnknownType):
            return self._record(
                node,
                Value(common, None, left.issues | right.issues),
                "usual arithmetic conversions",
            )

        left = self._convert(left, common, kind="arithmetic")
        right = self._convert(right, common, kind="arithmetic")
        issues = left.issues | right.issues

        if node.op in ("<", ">", "<=", ">=", "==", "!="):
            intervals = self._compare(node.op, left.intervals, right.intervals)
            value = Value(self.model.types["int"], intervals, issues)
            return self._record(node, value, "comparison result is int")

        if left.intervals is None or right.intervals is None:
            return self._record(
                node,
                Value(common, None, issues),
                f"binary {node.op}; operand range unknown",
            )

        if node.op in ("+", "-", "*"):
            intervals, new_issues = self._arithmetic(
                node.op, left.intervals, right.intervals
            )
        elif node.op in ("/", "%"):
            intervals, new_issues = self._division(
                node.op, left.intervals, right.intervals
            )
        elif node.op in ("&", "|", "^"):
            intervals, new_issues = self._bitwise(
                node.op, left.intervals, right.intervals, common
            )
        else:
            return self._unknown(
                node, "unsupported", f"binary operator {node.op!r} is not modeled"
            )

        fitted = self._fit_to_type(
            common,
            intervals,
            unsigned_issue="unsigned_wrap",
            signed_issue="signed_overflow",
        )
        issues = issues | fitted.issues | frozenset(new_issues)
        note = ""
        if any(issue.kind == "unsigned_wrap" for issue in issues):
            note = (
                "unsigned arithmetic wraps modulo "
                f"2^{common.bits}; value is not the mathematical result"
            )
        elif any(issue.kind == "signed_overflow" for issue in issues):
            note = "signed overflow is undefined behaviour"
        return self._record(node, Value(common, fitted.intervals, issues), note)

    def _eval_logical(self, node: c_ast.BinaryOp) -> Value:
        left = self.evaluate(node.left)
        left_state = self._truth_state(left)

        if node.op == "&&" and left_state is False:
            return self._record(
                node, self._int_value(0), "short-circuit: left operand is false"
            )
        if node.op == "||" and left_state is True:
            return self._record(
                node, self._int_value(1), "short-circuit: left operand is true"
            )

        right = self.evaluate(node.right)
        right_state = self._truth_state(right)
        issues = left.issues | right.issues

        if node.op == "&&":
            if left_state is True:
                result: bool | None = right_state
            elif right_state is False:
                result = False
            else:
                result = None
        else:
            if left_state is False:
                result = right_state
            elif right_state is True:
                result = True
            else:
                result = None

        if result is True:
            value = self._int_value(1)
        elif result is False:
            value = self._int_value(0)
        else:
            value = Value(self.model.types["int"], ((0, 1),), issues)
        value = Value(value.ctype, value.intervals, issues)
        return self._record(node, value, "logical result is int 0 or 1")

    def _eval_shift(
        self, node: c_ast.BinaryOp, left: Value, right: Value
    ) -> Value:
        result_type = left.ctype
        if not isinstance(result_type, IntType):
            return self._record(
                node, Value(result_type, None, left.issues | right.issues)
            )
        if left.intervals is None or right.intervals is None:
            return self._record(
                node,
                Value(result_type, None, left.issues | right.issues),
                "shift with unknown operand range",
            )

        counts = range(
            right.intervals[0][0], right.intervals[-1][1] + 1
        )
        if (
            right.intervals[0][0] < 0
            or right.intervals[-1][1] >= result_type.bits
        ):
            issue = Issue(
                "shift_ub",
                f"shift count {_range_text(right.intervals)} is not valid for "
                f"a {result_type.bits}-bit left operand",
            )
            return self._record(
                node,
                Value(result_type, None, left.issues | right.issues | {issue}),
                "shift count out of range",
            )

        issues = set(left.issues | right.issues)
        ranges: list[Interval] = []
        for count in counts:
            if node.op == "<<":
                if result_type.signed and any(
                    lo < 0 for lo, _ in left.intervals
                ):
                    issues.add(
                        Issue(
                            "signed_overflow",
                            "left shift of a negative signed value is undefined",
                        )
                    )
                    return self._record(
                        node,
                        Value(result_type, None, frozenset(issues)),
                        "undefined signed left shift",
                    )
                factor = 1 << count
                shifted = [
                    (lo * factor, hi * factor) for lo, hi in left.intervals
                ]
                fitted = self._fit_to_type(
                    result_type,
                    shifted,
                    unsigned_issue="unsigned_wrap",
                    signed_issue="signed_overflow",
                )
                issues |= set(fitted.issues)
                if fitted.intervals is None:
                    return self._record(
                        node,
                        Value(result_type, None, frozenset(issues)),
                        "shift overflow",
                    )
                ranges.extend(fitted.intervals)
            else:
                if result_type.signed and any(
                    lo < 0 for lo, _ in left.intervals
                ):
                    issue = Issue(
                        "implementation_defined",
                        "right shift of a negative signed value is "
                        "implementation-defined",
                    )
                    return self._record(
                        node,
                        Value(
                            result_type,
                            None,
                            frozenset(issues | {issue}),
                        ),
                        "implementation-defined right shift",
                    )
                divisor = 1 << count
                ranges.extend(
                    (lo // divisor, hi // divisor) for lo, hi in left.intervals
                )

        value = Value(result_type, _normalize_ranges(ranges), frozenset(issues))
        return self._record(node, value, f"shift by {_range_text(right.intervals)}")

    def eval_Cast(self, node: c_ast.Cast) -> Value:
        target = self.model.resolve_type_node(node.to_type)
        operand = self.evaluate(node.expr)
        if isinstance(target, UnknownType):
            issue = Issue(
                "unknown_type",
                f"cast target '{target.name}' is not in the target ABI model",
            )
            value = Value(target, None, operand.issues | {issue})
            return self._record(node, value, "unknown cast target")

        converted = self._convert(operand, target, kind="cast")
        note = f"explicit cast to {_type_text(target)}"
        if any(
            issue.kind in ("cast_truncation", "cast_signed_out_of_range")
            for issue in converted.issues
        ):
            note += "; value changes on conversion"
        return self._record(node, converted, note)

    def eval_TernaryOp(self, node: c_ast.TernaryOp) -> Value:
        condition = self.evaluate(node.cond)
        state = self._truth_state(condition)

        if state is True:
            return self._eval_constant_ternary(
                node, node.iftrue, node.iffalse, condition
            )
        if state is False:
            return self._eval_constant_ternary(
                node, node.iffalse, node.iftrue, condition
            )

        iftrue = self.evaluate(node.iftrue)
        iffalse = self.evaluate(node.iffalse)
        common = self.model.usual_arithmetic(iftrue.ctype, iffalse.ctype)
        issues = condition.issues | iftrue.issues | iffalse.issues
        if isinstance(common, UnknownType):
            return self._record(
                node,
                Value(common, None, issues),
                "ternary with unknown branch type",
            )

        true_value = self._convert(iftrue, common, kind="arithmetic")
        false_value = self._convert(iffalse, common, kind="arithmetic")
        issues = issues | true_value.issues | false_value.issues
        if true_value.intervals is None or false_value.intervals is None:
            return self._record(
                node,
                Value(common, None, issues),
                "ternary with unknown branch range",
            )

        intervals = _union_ranges(true_value.intervals, false_value.intervals)
        return self._record(
            node,
            Value(common, intervals, issues),
            "union of two finite ternary branches",
        )

    def _eval_constant_ternary(
        self,
        node: c_ast.TernaryOp,
        selected_node: c_ast.Node,
        other_node: c_ast.Node,
        condition: Value,
    ) -> Value:
        selected = self.evaluate(selected_node)

        # C gives ?: the usual-arithmetic-conversion type of both branches
        # even when the condition is a compile-time constant.  Only the
        # selected branch is evaluated, so discard the unselected branch's
        # range/issue trace.
        trace_length = len(self.trace_lines)
        other = self.evaluate(other_node)
        del self.trace_lines[trace_length:]

        common = self.model.usual_arithmetic(selected.ctype, other.ctype)
        issues = condition.issues | selected.issues
        if isinstance(common, UnknownType):
            return self._record(
                node,
                Value(common, None, issues),
                "constant condition, but the other branch type is unknown",
            )

        converted = self._convert(selected, common, kind="arithmetic")
        issues = issues | converted.issues
        return self._record(
            node,
            Value(common, converted.intervals, issues),
            "constant condition selects one finite branch; result uses the "
            "common branch type",
        )

    # -- unsupported constructs ---------------------------------------------

    def eval_FuncCall(self, node: c_ast.FuncCall) -> Value:
        return self._unknown(
            node,
            "unknown_value",
            "function-call results are not modeled; confirm the callee contract",
        )

    def eval_ArrayRef(self, node: c_ast.ArrayRef) -> Value:
        return self._unknown(
            node, "unknown_value", "array element values are not modeled"
        )

    def eval_StructRef(self, node: c_ast.StructRef) -> Value:
        return self._unknown(
            node, "unknown_value", "struct/union member values are not modeled"
        )

    def eval_ExprList(self, node: c_ast.ExprList) -> Value:
        value: Value | None = None
        for expression in node.exprs:
            value = self.evaluate(expression)
        return value or self._unknown(
            node, "unsupported", "empty expression list"
        )

    # -- conversion and arithmetic helpers ----------------------------------

    def _int_value(self, number: int) -> Value:
        return Value(self.model.types["int"], ((number, number),))

    def _promote_value(self, value: Value) -> Value:
        if isinstance(value.ctype, UnknownType):
            return value
        promoted = self.model.promote(value.ctype)
        if promoted == value.ctype:
            return value
        return Value(promoted, value.intervals, value.issues)

    def _truth_state(self, value: Value) -> bool | None:
        if value.intervals is None or not value.intervals:
            return None
        definitely_false = all(lo == 0 and hi == 0 for lo, hi in value.intervals)
        definitely_true = all(lo > 0 or hi < 0 for lo, hi in value.intervals)
        if definitely_false:
            return False
        if definitely_true:
            return True
        return None

    def _convert(self, value: Value, target: IntType, *, kind: str) -> Value:
        if value.intervals is None:
            return Value(target, None, value.issues)

        if target.name == "_Bool":
            ranges: list[Interval] = []
            for lo, hi in value.intervals:
                if lo == 0 and hi == 0:
                    ranges.append((0, 0))
                elif lo > 0 or hi < 0:
                    ranges.append((1, 1))
                else:
                    ranges.append((0, 1))
            return Value(target, _normalize_ranges(ranges), value.issues)

        unsigned_issue = {
            "arithmetic": "unsigned_wrap",
            "cast": "cast_truncation",
            "field": "field_conversion",
        }[kind]
        signed_issue = {
            "arithmetic": "signed_overflow",
            "cast": "cast_signed_out_of_range",
            "field": "field_signed_out_of_range",
        }[kind]
        fitted = self._fit_to_type(
            target,
            value.intervals,
            unsigned_issue=unsigned_issue,
            signed_issue=signed_issue,
        )
        return Value(
            fitted.ctype,
            fitted.intervals,
            value.issues | fitted.issues,
        )

    def _fit_to_type(
        self,
        ctype: CType,
        intervals: Iterable[Interval],
        *,
        unsigned_issue: str,
        signed_issue: str,
    ) -> Value:
        if isinstance(ctype, UnknownType):
            return Value(ctype, None, frozenset())

        ranges = _normalize_ranges(intervals)
        if not ranges:
            return Value(ctype, None)
        if ctype.name == "_Bool":
            converted: list[Interval] = []
            for lo, hi in ranges:
                if lo == 0 and hi == 0:
                    converted.append((0, 0))
                elif lo > 0 or hi < 0:
                    converted.append((1, 1))
                else:
                    converted.append((0, 1))
            return Value(ctype, _normalize_ranges(converted))

        if ctype.signed:
            if all(lo >= ctype.minimum and hi <= ctype.maximum for lo, hi in ranges):
                return Value(ctype, ranges)
            issue = Issue(
                signed_issue,
                f"value range {_range_text(ranges)} does not fit "
                f"{_type_text(ctype)}; signed overflow/conversion is not "
                "a reliable evidence source",
            )
            return Value(ctype, None, frozenset({issue}))

        converted_ranges: list[Interval] = []
        wrapped = False
        for lo, hi in ranges:
            if lo < ctype.minimum or hi > ctype.maximum:
                wrapped = True
            converted_ranges.extend(_mod_image(lo, hi, ctype.bits))

        issues: frozenset[Issue] = frozenset()
        if wrapped:
            issues = frozenset(
                {
                    Issue(
                        unsigned_issue,
                        f"value range {_range_text(ranges)} is reduced modulo "
                        f"2^{ctype.bits}; the stored value differs from the "
                        "mathematical value",
                    )
                }
            )
        return Value(ctype, _normalize_ranges(converted_ranges), issues)

    def _arithmetic(
        self, op: str, left: tuple[Interval, ...], right: tuple[Interval, ...]
    ) -> tuple[list[Interval], list[Issue]]:
        result: list[Interval] = []
        for left_lo, left_hi in left:
            for right_lo, right_hi in right:
                if op == "+":
                    result.append((left_lo + right_lo, left_hi + right_hi))
                elif op == "-":
                    result.append((left_lo - right_hi, left_hi - right_lo))
                else:
                    corners = (
                        left_lo * right_lo,
                        left_lo * right_hi,
                        left_hi * right_lo,
                        left_hi * right_hi,
                    )
                    result.append((min(corners), max(corners)))
        return result, []

    def _division(
        self, op: str, left: tuple[Interval, ...], right: tuple[Interval, ...]
    ) -> tuple[list[Interval], list[Issue]]:
        result: list[Interval] = []
        issues: list[Issue] = []
        for numerator_lo, numerator_hi in left:
            for divisor_lo, divisor_hi in right:
                parts: list[tuple[int, int]] = []
                if divisor_lo < 0:
                    parts.append((divisor_lo, min(divisor_hi, -1)))
                if divisor_hi > 0:
                    parts.append((max(divisor_lo, 1), divisor_hi))
                if divisor_lo <= 0 <= divisor_hi:
                    issues.append(
                        Issue(
                            "zero_division",
                            f"divisor range {divisor_lo}..{divisor_hi} includes "
                            "zero; division by zero is undefined behaviour",
                        )
                    )

                if not parts:
                    continue

                for part_lo, part_hi in parts:
                    if op == "/":
                        corners = (
                            _trunc_div(numerator_lo, part_lo),
                            _trunc_div(numerator_lo, part_hi),
                            _trunc_div(numerator_hi, part_lo),
                            _trunc_div(numerator_hi, part_hi),
                        )
                        result.append((min(corners), max(corners)))
                    else:
                        if numerator_lo == numerator_hi and part_lo == part_hi:
                            remainder = _trunc_mod(numerator_lo, part_lo)
                            result.append((remainder, remainder))
                            continue
                        max_divisor = max(abs(part_lo), abs(part_hi))
                        max_numerator = max(abs(numerator_lo), abs(numerator_hi))
                        magnitude = min(max_divisor - 1, max_numerator)
                        if numerator_lo >= 0:
                            result.append((0, magnitude))
                        elif numerator_hi <= 0:
                            result.append((-magnitude, 0))
                        else:
                            result.append((-magnitude, magnitude))

        return result, issues

    def _bitwise(
        self,
        op: str,
        left: tuple[Interval, ...],
        right: tuple[Interval, ...],
        ctype: IntType,
    ) -> tuple[list[Interval], list[Issue]]:
        issues: list[Issue] = []
        if ctype.signed and (
            any(lo < 0 for lo, _ in left) or any(lo < 0 for lo, _ in right)
        ):
            issues.append(
                Issue(
                    "implementation_defined",
                    "bitwise operation on negative signed values depends on the "
                    "signed representation",
                )
            )

        result: list[Interval] = []
        for left_lo, left_hi in left:
            for right_lo, right_hi in right:
                if left_lo == left_hi and right_lo == right_hi:
                    if op == "&":
                        number = left_lo & right_lo
                    elif op == "|":
                        number = left_lo | right_lo
                    else:
                        number = left_lo ^ right_lo
                    result.append((number, number))
                    continue

                # Sound supersets for the non-negative domain.  A single
                # interval cannot represent arbitrary bit patterns exactly.
                max_left = max(0, left_hi)
                max_right = max(0, right_hi)
                if op == "&":
                    result.append((0, min(max_left, max_right)))
                else:
                    top = max(max_left, max_right)
                    width = top.bit_length()
                    upper = (1 << width) - 1 if width else 0
                    result.append((0, upper))

        if (left[0][0] if left else 0) < 0 or (right[0][0] if right else 0) < 0:
            result.append((ctype.minimum, ctype.maximum))
        return result, issues

    def _compare(
        self,
        op: str,
        left: tuple[Interval, ...] | None,
        right: tuple[Interval, ...] | None,
    ) -> tuple[Interval, ...]:
        if left is None or right is None or not left or not right:
            return ((0, 1),)

        if op == "==":
            if all(
                hi < right_lo or right_hi < lo
                for lo, hi in left
                for right_lo, right_hi in right
            ):
                return ((0, 0),)
            if (
                len(left) == 1
                and len(right) == 1
                and left == right
                and left[0][0] == left[0][1]
            ):
                return ((1, 1),)
            return ((0, 1),)
        if op == "!=":
            equal = self._compare("==", left, right)
            if equal == ((0, 0),):
                return ((1, 1),)
            if equal == ((1, 1),):
                return ((0, 0),)
            return ((0, 1),)

        if op == "<":
            if all(left_hi < right_lo for _, left_hi in left for right_lo, _ in right):
                return ((1, 1),)
            if all(left_lo >= right_hi for left_lo, _ in left for _, right_hi in right):
                return ((0, 0),)
            return ((0, 1),)
        if op == "<=":
            if all(left_hi <= right_lo for _, left_hi in left for right_lo, _ in right):
                return ((1, 1),)
            if all(left_lo > right_hi for left_lo, _ in left for _, right_hi in right):
                return ((0, 0),)
            return ((0, 1),)
        if op == ">":
            return self._compare("<", right, left)
        if op == ">=":
            return self._compare("<=", right, left)
        return ((0, 1),)


# ---------------------------------------------------------------------------
# Request/report API


@dataclass(frozen=True)
class Target:
    name: str
    field_type: str
    int_width: int


@dataclass(frozen=True)
class AuditRequest:
    expression: str
    variables: tuple[VariableSpec, ...]
    targets: tuple[Target, ...]
    business_min: int
    business_max: int
    max_witness_cases: int = 100_000
    char_signed: bool = True
    char_bits: int = 8
    type_widths: Mapping[str, tuple[int, bool]] | None = None
    typedefs: Mapping[str, str] | None = None


@dataclass(frozen=True)
class TargetResult:
    target: Target
    field_type: CType
    value: Value
    verdict: str
    sufficient: bool
    bounds_proven: bool
    semantics_clean: bool
    witness: Mapping[str, int] | None
    witness_value: int | None
    trace: tuple[str, ...]
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class AuditReport:
    request: AuditRequest
    results: tuple[TargetResult, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "expression": self.request.expression,
            "business_bounds": [
                self.request.business_min,
                self.request.business_max,
            ],
            "variables": [
                {
                    "name": spec.name,
                    "declared_type": spec.c_type,
                    "assumed_min": spec.minimum,
                    "assumed_max": spec.maximum,
                }
                for spec in self.request.variables
            ],
            "targets": [
                {
                    "name": result.target.name,
                    "int_width": result.target.int_width,
                    "field_type": result.target.field_type,
                    "resolved_field_type": (
                        result.field_type.name
                        if isinstance(result.field_type, IntType)
                        else f"unknown:{result.field_type.name}"
                    ),
                    "verdict": result.verdict,
                    "sufficient": result.sufficient,
                    "bounds_proven": result.bounds_proven,
                    "semantics_clean": result.semantics_clean,
                    "range": (
                        [list(interval) for interval in result.value.intervals]
                        if result.value.intervals is not None
                        else None
                    ),
                    "witness": dict(result.witness) if result.witness else None,
                    "witness_value": result.witness_value,
                    "issues": sorted(
                        {issue.kind for issue in result.value.issues}
                    ),
                    "evidence": list(result.trace),
                    "reasons": list(result.reasons),
                }
                for result in self.results
            ],
        }


class AuditError(ValueError):
    pass


_COMMON_TYPE_NAMES = frozenset(
    {
        "int8_t",
        "int16_t",
        "int32_t",
        "int64_t",
        "uint8_t",
        "uint16_t",
        "uint32_t",
        "uint64_t",
        "intmax_t",
        "uintmax_t",
        "size_t",
        "ptrdiff_t",
        "intptr_t",
        "uintptr_t",
        "wchar_t",
        "bool",
    }
)
_TYPE_SPECIFIER_WORDS = frozenset(
    {
        "void",
        "char",
        "short",
        "int",
        "long",
        "signed",
        "unsigned",
        "_Bool",
        "bool",
        "float",
        "double",
        "const",
        "volatile",
        "restrict",
        "_Atomic",
    }
)


def _type_names_for_parser(request: AuditRequest) -> set[str]:
    names = set(_COMMON_TYPE_NAMES)
    names.update(request.typedefs or {})
    names.update(request.type_widths or {})

    for spec in request.variables:
        for token in re.findall(r"[A-Za-z_]\w*", spec.c_type):
            if token not in _TYPE_SPECIFIER_WORDS:
                names.add(token)

    for target in request.targets:
        for token in re.findall(r"[A-Za-z_]\w*", target.field_type):
            if token not in _TYPE_SPECIFIER_WORDS:
                names.add(token)

    # It is conventional for type names to end in _t; predeclaring those also
    # lets casts in the expression parse without a preprocessor.  Do not
    # predeclare a name that the caller has declared as a variable: typedef
    # names and ordinary identifiers share a namespace in C.
    variable_names = {spec.name for spec in request.variables}
    names.update(
        name
        for name in re.findall(r"\b[A-Za-z_]\w*_t\b", request.expression)
        if name not in variable_names
    )
    names.difference_update(variable_names)
    return names


def parse_expression(expression: str, type_names: Iterable[str]) -> c_ast.Node:
    expression = expression.strip()
    while expression.endswith(";"):
        expression = expression[:-1].rstrip()
    if not expression:
        raise AuditError("expression is empty")

    prelude = [
        f"typedef int {name};"
        for name in sorted(set(type_names))
        if name not in _TYPE_SPECIFIER_WORDS
        and re.fullmatch(r"[A-Za-z_]\w*", name) is not None
        and name not in {"__audit_expr", "__audit_value"}
    ]
    source = (
        "\n".join(prelude)
        + "\nvoid __audit_expr(void) { (void)("
        + expression
        + "); }\n"
    )
    try:
        ast = c_parser.CParser().parse(source, filename="<expression>")
    except Exception as exc:
        raise AuditError(
            f"could not parse C expression {expression!r}: {exc}\n"
            "Hint: unknown typedefs used in casts need --typedef NAME=TYPE."
        ) from exc

    function = ast.ext[-1]
    if not isinstance(function, c_ast.FuncDef):
        raise AuditError("internal parse error: expression wrapper is missing")
    if not function.body.block_items:
        raise AuditError("expression wrapper is empty")

    statement = function.body.block_items[-1]
    # Older pycparser versions wrap expression statements in ExprStatement.
    # The version in this tree stores the expression node directly.
    expression_statement = getattr(c_ast, "ExprStatement", None)
    if expression_statement is not None and isinstance(
        statement, expression_statement
    ):
        expression_node = statement.expr
    else:
        expression_node = statement

    if isinstance(expression_node, c_ast.Cast) and _is_void_cast(
        expression_node
    ):
        expression_node = expression_node.expr
    return expression_node


def _is_void_cast(node: c_ast.Cast) -> bool:
    target = node.to_type
    if isinstance(target, c_ast.Typename):
        target = target.type
    while isinstance(target, c_ast.TypeDecl):
        target = target.type
    return isinstance(target, c_ast.IdentifierType) and target.names == ["void"]


def _used_identifiers(node: c_ast.Node) -> set[str]:
    names: set[str] = set()
    stack = [node]
    while stack:
        current = stack.pop()
        if isinstance(current, c_ast.ID):
            names.add(current.name)
        for child in current.children():
            if isinstance(child, tuple):
                child = child[1]
            stack.append(child)
    return names


def _witness_search(
    ast: c_ast.Node,
    request: AuditRequest,
    target: Target,
    model: TypeModel,
) -> tuple[Mapping[str, int], int] | None:
    domains: list[tuple[str, str, int, int]] = []
    total = 1
    used = _used_identifiers(ast)
    for spec in request.variables:
        if spec.name not in used:
            continue
        ctype = model.resolve_string(spec.c_type)
        if isinstance(ctype, UnknownType):
            return None
        minimum = spec.minimum if spec.minimum is not None else ctype.minimum
        maximum = spec.maximum if spec.maximum is not None else ctype.maximum
        minimum = max(minimum, ctype.minimum)
        maximum = min(maximum, ctype.maximum)
        if minimum > maximum:
            return None
        size = maximum - minimum + 1
        if size > request.max_witness_cases:
            return None
        total *= size
        if total > request.max_witness_cases:
            return None
        domains.append((spec.name, spec.c_type, minimum, maximum))

    if not domains:
        return None

    field_type = model.resolve_string(target.field_type)
    if isinstance(field_type, UnknownType):
        return None

    for values in itertools.product(
        *(range(minimum, maximum + 1) for _, _, minimum, maximum in domains)
    ):
        concrete_specs = [
            VariableSpec(name, c_type, value, value)
            for (name, c_type, _, _), value in zip(domains, values)
        ]
        evaluator = Evaluator(model, concrete_specs, trace=False)
        value = evaluator.evaluate(ast)
        final = evaluator.convert_final(value, field_type)

        blocking = {
            "unknown_type",
            "unknown_identifier",
            "unknown_value",
            "unsupported",
            "signed_overflow",
            "signed_conversion",
            "field_signed_out_of_range",
            "cast_signed_out_of_range",
            "implementation_defined",
            "zero_division",
            "shift_ub",
            "assumption_conflict",
            "assumption_outside_type",
        }
        if any(issue.kind in blocking for issue in final.issues):
            continue
        if final.intervals is None:
            continue
        if len(final.intervals) != 1:
            continue
        lo, hi = final.intervals[0]
        if lo != hi:
            continue
        if lo < request.business_min or lo > request.business_max:
            return (
                {
                    name: value
                    for (name, _, _, _), value in zip(domains, values)
                },
                lo,
            )
    return None


_NEEDS_CONFIRMATION_KINDS = frozenset(
    {
        "unknown_type",
        "unknown_identifier",
        "unknown_value",
        "unsupported",
        "literal_too_large",
        "assumption_conflict",
        "assumption_outside_type",
    }
)
_BLOCKING_KINDS = frozenset(
    {
        "signed_overflow",
        "signed_conversion",
        "cast_signed_out_of_range",
        "field_signed_out_of_range",
        "implementation_defined",
        "zero_division",
        "shift_ub",
    }
)
_SEMANTIC_KINDS = frozenset({"unsigned_wrap", "cast_truncation", "field_conversion"})


def _make_result(
    request: AuditRequest,
    target: Target,
    field_type: CType,
    value: Value,
    trace: tuple[str, ...],
    witness: tuple[Mapping[str, int], int] | None,
) -> TargetResult:
    witness_assignments = witness[0] if witness is not None else None
    witness_value = witness[1] if witness is not None else None
    kinds = {issue.kind for issue in value.issues}
    bounds = (request.business_min, request.business_max)

    definitely_outside = False
    ranges_within = False
    if value.intervals is not None:
        definitely_outside = bool(value.intervals) and all(
            hi < bounds[0] or lo > bounds[1] for lo, hi in value.intervals
        )
        ranges_within = bool(value.intervals) and all(
            lo >= bounds[0] and hi <= bounds[1] for lo, hi in value.intervals
        )

    if kinds & _NEEDS_CONFIRMATION_KINDS:
        verdict = "NEEDS_CONFIRMATION"
    elif witness_assignments is not None:
        verdict = "VIOLATED"
    elif kinds & _BLOCKING_KINDS:
        verdict = "INSUFFICIENT"
    elif value.intervals is None:
        verdict = "INSUFFICIENT"
    elif definitely_outside:
        verdict = "VIOLATED"
    elif not ranges_within:
        verdict = "INSUFFICIENT"
    elif kinds & _SEMANTIC_KINDS:
        verdict = "PROVEN_BOUNDS_ONLY"
    else:
        verdict = "PROVEN"

    bounds_proven = (
        value.intervals is not None
        and ranges_within
        and not (kinds & (_NEEDS_CONFIRMATION_KINDS | _BLOCKING_KINDS))
    )
    semantics_clean = bounds_proven and not (kinds & _SEMANTIC_KINDS)
    sufficient = verdict == "PROVEN"

    reasons: list[str] = []
    for issue in sorted(value.issues, key=lambda item: (item.kind, item.detail)):
        reasons.append(issue.detail)
    if witness_assignments is not None:
        assignments = ", ".join(
            f"{name}={number}" for name, number in witness_assignments.items()
        )
        reasons.append(
            f"witness {assignments} produces {witness_value}, outside "
            f"[{request.business_min}, {request.business_max}]"
        )
    if definitely_outside:
        reasons.append(
            f"final range {_range_text(value.intervals)} is entirely outside "
            f"business bounds [{request.business_min}, {request.business_max}]"
        )
    elif value.intervals is not None and ranges_within:
        reasons.append(
            f"final range {_range_text(value.intervals)} is within business "
            f"bounds [{request.business_min}, {request.business_max}]"
        )
    elif (
        witness_assignments is None
        and bool(value.intervals)
        and not definitely_outside
    ):
        reasons.append(
            f"final range {_range_text(value.intervals)} is not fully inside "
            f"business bounds [{request.business_min}, {request.business_max}]; "
            "no finite witness was found within the supplied assumptions"
        )
    if verdict == "PROVEN":
        reasons.append(
            "no wrap, truncation, undefined behaviour, or unknown type "
            "affects this target"
        )
    elif verdict == "PROVEN_BOUNDS_ONLY":
        reasons.append(
            "bounds are proven for the modeled C semantics, but a wrap or "
            "truncation means the logged count is not the mathematical value"
        )

    return TargetResult(
        target=target,
        field_type=field_type,
        value=value,
        verdict=verdict,
        sufficient=sufficient,
        bounds_proven=bounds_proven,
        semantics_clean=semantics_clean,
        witness=witness_assignments,
        witness_value=witness_value,
        trace=trace,
        reasons=tuple(reasons),
    )


def audit_single(
    expression: str,
    *,
    int_width: int,
    field_type: str,
    bounds: tuple[int, int],
    variables: Sequence[VariableSpec] = (),
    **request_options: object,
) -> TargetResult:
    """Convenience API for the one-expression/one-target case."""

    request = AuditRequest(
        expression=expression,
        variables=tuple(variables),
        targets=(Target("target", field_type, int_width),),
        business_min=bounds[0],
        business_max=bounds[1],
        **request_options,
    )
    return audit(request).results[0]


def audit(request: AuditRequest) -> AuditReport:
    if request.business_min > request.business_max:
        raise AuditError("business minimum must not exceed business maximum")
    if not request.targets:
        raise AuditError("at least one target is required")

    variable_names: set[str] = set()
    for spec in request.variables:
        if spec.name in variable_names:
            raise AuditError(f"duplicate variable declaration: {spec.name}")
        variable_names.add(spec.name)

    ast = parse_expression(request.expression, _type_names_for_parser(request))
    models: dict[int, TypeModel] = {}
    results: list[TargetResult] = []

    for target in request.targets:
        model = models.get(target.int_width)
        if model is None:
            model = TypeModel(
                target.int_width,
                char_signed=request.char_signed,
                char_bits=request.char_bits,
                type_widths=request.type_widths,
                typedefs=request.typedefs,
            )
            models[target.int_width] = model

        field_type = model.resolve_string(target.field_type)
        evaluator = Evaluator(model, request.variables, trace=True)
        value = evaluator.evaluate(ast)
        value = evaluator.convert_final(value, field_type)
        witness = _witness_search(ast, request, target, model)
        results.append(
            _make_result(
                request,
                target,
                field_type,
                value,
                tuple(evaluator.trace_lines),
                witness,
            )
        )

    return AuditReport(request=request, results=tuple(results))


# ---------------------------------------------------------------------------
# Command line


def _parse_range(text: str, option: str) -> tuple[int, int]:
    match = re.fullmatch(r"\s*(-?\d+)\s*\.\.\s*(-?\d+)\s*", text)
    if not match:
        raise argparse.ArgumentTypeError(
            f"{option} expects MIN..MAX, got {text!r}"
        )
    minimum, maximum = int(match.group(1)), int(match.group(2))
    if minimum > maximum:
        raise argparse.ArgumentTypeError(
            f"{option} minimum {minimum} exceeds maximum {maximum}"
        )
    return minimum, maximum


def _parse_var(text: str) -> VariableSpec:
    if "=" not in text:
        raise argparse.ArgumentTypeError(
            f"--var expects NAME=TYPE[@MIN..MAX], got {text!r}"
        )
    name, rest = text.split("=", 1)
    name = name.strip()
    if not re.fullmatch(r"[A-Za-z_]\w*", name):
        raise argparse.ArgumentTypeError(f"invalid variable name {name!r}")

    minimum: int | None = None
    maximum: int | None = None
    if "@" in rest:
        c_type, range_text = rest.rsplit("@", 1)
        minimum, maximum = _parse_range(range_text, "--var")
    else:
        c_type = rest
    c_type = c_type.strip()
    if not c_type:
        raise argparse.ArgumentTypeError(f"missing type for variable {name!r}")
    return VariableSpec(name, c_type, minimum, maximum)


def _parse_target(text: str, default_int_width: int) -> Target:
    if "=" not in text:
        raise argparse.ArgumentTypeError(
            f"--target expects NAME=FIELD_TYPE@INT_WIDTH, got {text!r}"
        )
    name, rest = text.split("=", 1)
    name = name.strip()
    if not name:
        raise argparse.ArgumentTypeError("target name must not be empty")

    int_width = default_int_width
    if "@" in rest:
        field_type, width_text = rest.rsplit("@", 1)
        try:
            int_width = int(width_text)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(
                f"invalid int width in {text!r}"
            ) from exc
    else:
        field_type = rest
    field_type = field_type.strip()
    if not field_type:
        raise argparse.ArgumentTypeError(f"missing field type for {name!r}")
    if int_width < 8:
        raise argparse.ArgumentTypeError("target int width must be at least 8")
    return Target(name, field_type, int_width)


def _parse_assumption(text: str) -> tuple[str, tuple[int, int]]:
    if "=" not in text:
        raise argparse.ArgumentTypeError(
            f"--assume expects NAME=MIN..MAX, got {text!r}"
        )
    name, range_text = text.split("=", 1)
    name = name.strip()
    if not re.fullmatch(r"[A-Za-z_]\w*", name):
        raise argparse.ArgumentTypeError(f"invalid variable name {name!r}")
    return name, _parse_range(range_text, "--assume")


def _parse_type_width(text: str) -> tuple[str, tuple[int, bool]]:
    if "=" not in text:
        raise argparse.ArgumentTypeError(
            f"--type-width expects NAME=BITS[:s|u], got {text!r}"
        )
    name, rest = text.split("=", 1)
    name = name.strip()
    signed = True
    if ":" in rest:
        bits_text, sign_text = rest.rsplit(":", 1)
        if sign_text == "u":
            signed = False
        elif sign_text != "s":
            raise argparse.ArgumentTypeError(
                f"type sign must be 's' or 'u' in {text!r}"
            )
    else:
        bits_text = rest
    try:
        bits = int(bits_text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid width in {text!r}") from exc
    return name, (bits, signed)


def _parse_typedef(text: str) -> tuple[str, str]:
    if "=" not in text:
        raise argparse.ArgumentTypeError(
            f"--typedef expects NAME=TYPE, got {text!r}"
        )
    name, target = text.split("=", 1)
    name = name.strip()
    if not re.fullmatch(r"[A-Za-z_]\w*", name):
        raise argparse.ArgumentTypeError(f"invalid typedef name {name!r}")
    return name, target.strip()


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Static C expression range audit for a caller-supplied target ABI. "
            "Does not compile or run firmware."
        )
    )
    parser.add_argument("expression", nargs="?", help="C expression to audit")
    parser.add_argument(
        "--expr",
        dest="expr_option",
        metavar="EXPR",
        help="C expression to audit (alternative to the positional argument)",
    )
    parser.add_argument(
        "--var",
        action="append",
        default=[],
        type=_parse_var,
        metavar="NAME=TYPE[@MIN..MAX]",
        help="declare an expression variable and optional assumed values",
    )
    parser.add_argument(
        "--assume",
        action="append",
        default=[],
        type=_parse_assumption,
        metavar="NAME=MIN..MAX",
        help="assumed value range for a variable",
    )
    parser.add_argument(
        "--target",
        action="append",
        default=[],
        metavar="NAME=FIELD_TYPE@INT_WIDTH",
        help="target board; repeat for each maintained board",
    )
    parser.add_argument(
        "--int-width",
        type=int,
        default=32,
        help="default C int width for targets that omit @WIDTH (default: 32)",
    )
    parser.add_argument(
        "--field-type",
        default="int",
        help="log field type when --target is omitted (default: int)",
    )
    parser.add_argument(
        "--bounds",
        type=lambda text: _parse_range(text, "--bounds"),
        metavar="MIN..MAX",
        help="business invariant for the stored field value",
    )
    parser.add_argument(
        "--type-width",
        action="append",
        default=[],
        type=_parse_type_width,
        metavar="NAME=BITS[:s|u]",
        help="model an otherwise unknown ABI type (for example size_t=16:u)",
    )
    parser.add_argument(
        "--typedef",
        action="append",
        default=[],
        type=_parse_typedef,
        metavar="NAME=TYPE",
        help="tell the analyzer that NAME is a typedef for TYPE",
    )
    parser.add_argument(
        "--unsigned-char",
        action="store_true",
        help="model plain char as unsigned (default: signed)",
    )
    parser.add_argument(
        "--char-bits",
        type=int,
        default=8,
        help="width of char in bits (default: 8)",
    )
    parser.add_argument(
        "--max-witness-cases",
        type=int,
        default=100_000,
        help="limit for concrete witness search (default: 100000)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit a machine-readable JSON report",
    )
    return parser


def _print_report(report: AuditReport) -> None:
    request = report.request
    print("static C expression range audit (pycparser; no firmware build/run)")
    print(f"expression: {request.expression}")
    print(
        f"business invariant: {request.business_min} <= stored value <= "
        f"{request.business_max}"
    )
    print("variables:")
    for spec in request.variables:
        if spec.minimum is None and spec.maximum is None:
            assumption = "full declared type range"
        else:
            assumption = f"assumed {spec.minimum}..{spec.maximum}"
        print(f"  {spec.name}: {spec.c_type} ({assumption})")
    print()

    for result in report.results:
        print(
            f"[{result.target.name}] int width {result.target.int_width}, "
            f"log field {result.target.field_type}"
        )
        print(f"  verdict: {result.verdict}")
        print(
            "  sufficient evidence: "
            + ("yes" if result.sufficient else "no")
            + f" (bounds={result.bounds_proven}, "
            + f"semantics={result.semantics_clean})"
        )
        print(f"  final range: {_range_text(result.value.intervals)}")
        if result.witness:
            print(
                "  witness: "
                + ", ".join(
                    f"{name}={number}" for name, number in result.witness.items()
                )
                + f" -> {result.witness_value}"
            )
        print("  evidence:")
        for line in result.trace:
            print(f"    - {line}")
        for reason in result.reasons:
            print(f"    - {reason}")
        print()

    print("summary:")
    for result in report.results:
        if result.sufficient:
            marker = "sufficient"
        elif result.bounds_proven:
            marker = "bounds proven; count semantics not proven"
        else:
            marker = "not sufficient"
        print(f"  {result.target.name}: {result.verdict} ({marker})")


def demo_request() -> AuditRequest:
    """The hand-checkable 16-bit versus 32-bit board example."""

    return AuditRequest(
        expression="(health - baseline) * 10",
        variables=(
            VariableSpec("health", "uint16_t", 0, 1000),
            VariableSpec("baseline", "uint16_t", 800, 800),
        ),
        targets=(
            Target("board-16", "int32_t", 16),
            Target("board-32", "int32_t", 32),
        ),
        business_min=-8000,
        business_max=2000,
    )


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments:
        report = audit(demo_request())
        _print_report(report)
        print("hand check:")
        print(
            "  threshold: uint16_t promotes to signed int only when int_width "
            ">= 17 (in practice 32); a 16-bit int_width is below it."
        )
        print(
            "  board-16: (0 - 800) mod 65536 = 64736; 64736 * 10 mod 65536 "
            "= 57536, outside [-8000, 2000]."
        )
        print(
            "  board-32: (0 - 800) * 10 = -8000, inside [-8000, 2000]."
        )
        return 0

    parser = _build_arg_parser()
    args = parser.parse_args(arguments)

    if args.expression and args.expr_option:
        parser.error("use either the positional expression or --expr, not both")
    expression = args.expr_option or args.expression
    if not expression:
        parser.error("an expression is required (positional or --expr)")
    if args.bounds is None:
        parser.error("--bounds MIN..MAX is required")
    if args.char_bits < 1:
        parser.error("--char-bits must be positive")
    if args.max_witness_cases < 0:
        parser.error("--max-witness-cases must not be negative")

    assumptions = dict(args.assume)
    variables: list[VariableSpec] = []
    for spec in args.var:
        if spec.name in assumptions:
            assumed_min, assumed_max = assumptions.pop(spec.name)
            spec = VariableSpec(
                spec.name,
                spec.c_type,
                assumed_min,
                assumed_max,
            )
        variables.append(spec)
    if assumptions:
        parser.error(
            "--assume names without --var: " + ", ".join(sorted(assumptions))
        )

    type_widths = dict(args.type_width)
    typedefs = dict(args.typedef)

    if args.target:
        targets = tuple(
            _parse_target(text, args.int_width) for text in args.target
        )
    else:
        targets = (Target("default", args.field_type, args.int_width),)

    request = AuditRequest(
        expression=expression,
        variables=tuple(variables),
        targets=targets,
        business_min=args.bounds[0],
        business_max=args.bounds[1],
        max_witness_cases=args.max_witness_cases,
        char_signed=not args.unsigned_char,
        char_bits=args.char_bits,
        type_widths=type_widths,
        typedefs=typedefs,
    )
    try:
        report = audit(request)
    except (AuditError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=False))
    else:
        _print_report(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
