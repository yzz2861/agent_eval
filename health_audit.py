#!/usr/bin/env python3
"""Static integer-range review for small C expressions using pycparser."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, replace
from typing import Any, Optional

from pycparser import CParser, c_ast
from pycparser.c_generator import CGenerator
from pycparser.c_parser import ParseError


UNKNOWN_TYPE_NAME = "unknown-type"


@dataclass(frozen=True)
class Issue:
    code: str
    message: str
    node: Optional[str] = None
    severity: str = "blocker"

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
            "node": self.node,
        }


@dataclass(frozen=True)
class TypeInfo:
    name: str
    bits: Optional[int]
    signed: Optional[bool]
    rank: int = 4
    unknown: bool = False
    floating: bool = False

    @property
    def minimum(self) -> Optional[int]:
        if self.bits is None or self.signed is None:
            return None
        return -(1 << (self.bits - 1)) if self.signed else 0

    @property
    def maximum(self) -> Optional[int]:
        if self.bits is None:
            return None
        if self.signed is None:
            return None
        return (1 << (self.bits - 1)) - 1 if self.signed else (1 << self.bits) - 1

    def contains(self, value: int) -> bool:
        lo, hi = self.minimum, self.maximum
        return lo is not None and hi is not None and lo <= value <= hi


UNKNOWN_TYPE = TypeInfo(UNKNOWN_TYPE_NAME, None, None, 99, unknown=True)


@dataclass(frozen=True)
class RangeSet:
    intervals: tuple[tuple[int, int], ...] = ()

    @staticmethod
    def create(pairs: Any) -> "RangeSet":
        normalized: list[list[int]] = []
        for pair in pairs:
            lo, hi = int(pair[0]), int(pair[1])
            if lo > hi:
                continue
            normalized.append([lo, hi])
        normalized.sort()
        merged: list[list[int]] = []
        for lo, hi in normalized:
            if not merged or lo > merged[-1][1] + 1:
                merged.append([lo, hi])
            else:
                merged[-1][1] = max(merged[-1][1], hi)
        return RangeSet(tuple((lo, hi) for lo, hi in merged))

    @staticmethod
    def point(value: int) -> "RangeSet":
        return RangeSet(((value, value),))

    @staticmethod
    def full(type_info: TypeInfo) -> "RangeSet":
        lo, hi = type_info.minimum, type_info.maximum
        if lo is None or hi is None:
            return RangeSet(())
        return RangeSet(((lo, hi),))

    @property
    def empty(self) -> bool:
        return not self.intervals

    @property
    def lo(self) -> int:
        return self.intervals[0][0]

    @property
    def hi(self) -> int:
        return self.intervals[-1][1]

    def union(self, other: "RangeSet") -> "RangeSet":
        return RangeSet.create(self.intervals + other.intervals)

    def intersection(self, other: "RangeSet") -> "RangeSet":
        pairs: list[tuple[int, int]] = []
        for left_lo, left_hi in self.intervals:
            for right_lo, right_hi in other.intervals:
                lo = max(left_lo, right_lo)
                hi = min(left_hi, right_hi)
                if lo <= hi:
                    pairs.append((lo, hi))
        return RangeSet.create(pairs)

    def contains_zero(self) -> bool:
        return not self.intersection(RangeSet.point(0)).empty

    def all_zero(self) -> bool:
        return self.intervals == ((0, 0),)

    def all_nonzero(self) -> bool:
        return not any(lo <= 0 <= hi for lo, hi in self.intervals)


@dataclass(frozen=True)
class Value:
    ranges: Optional[RangeSet]
    type: TypeInfo
    issues: tuple[Issue, ...] = ()


@dataclass(frozen=True)
class Target:
    name: str = "target"
    char_bits: int = 8
    short_bits: int = 16
    int_bits: int = 32
    long_bits: int = 32
    long_long_bits: int = 64
    pointer_bits: int = 32
    char_signed: bool = True
    size_t_bits: Optional[int] = None
    signed_cast: str = "implementation_defined"
    max_branch_envs: int = 8

    @classmethod
    def from_dict(cls, data: Optional[dict[str, Any]]) -> "Target":
        data = dict(data or {})
        known = {field for field in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{key: value for key, value in data.items() if key in known})


def source_text(node: c_ast.Node) -> str:
    try:
        return CGenerator().visit(node)
    except Exception:
        return type(node).__name__


def modulo_cast(ranges: RangeSet, bits: int) -> RangeSet:
    modulus = 1 << bits
    result: list[tuple[int, int]] = []
    for lo, hi in ranges.intervals:
        width = hi - lo
        if width >= modulus - 1:
            return RangeSet(((0, modulus - 1),))
        start = lo % modulus
        end = start + width
        if end < modulus:
            result.append((start, end))
        else:
            result.append((start, modulus - 1))
            result.append((0, end - modulus))
    return RangeSet.create(result)


def twos_complement_to_signed(ranges: RangeSet, bits: int) -> RangeSet:
    half = 1 << (bits - 1)
    modulus = 1 << bits
    result: list[tuple[int, int]] = []
    for lo, hi in ranges.intervals:
        if hi < half:
            result.append((lo, hi))
        elif lo >= half:
            result.append((lo - modulus, hi - modulus))
        else:
            result.append((lo, half - 1))
            result.append((-half, hi - modulus))
    return RangeSet.create(result)


class TypeLibrary:
    """Target-dependent C integer type table."""

    def __init__(self, target: Target):
        self.target = target
        self.bool = TypeInfo("_Bool", 1, False, 0)
        self.char = TypeInfo("char", target.char_bits, target.char_signed, 1)
        self.schar = TypeInfo("signed char", target.char_bits, True, 1)
        self.uchar = TypeInfo("unsigned char", target.char_bits, False, 1)
        self.short = TypeInfo("short", target.short_bits, True, 2)
        self.ushort = TypeInfo("unsigned short", target.short_bits, False, 2)
        self.int = TypeInfo("int", target.int_bits, True, 3)
        self.uint = TypeInfo("unsigned int", target.int_bits, False, 3)
        self.long = TypeInfo("long", target.long_bits, True, 4)
        self.ulong = TypeInfo("unsigned long", target.long_bits, False, 4)
        self.llong = TypeInfo("long long", target.long_long_bits, True, 5)
        self.ullong = TypeInfo("unsigned long long", target.long_long_bits, False, 5)
        size_bits = target.size_t_bits or target.int_bits
        self.size_t = TypeInfo("size_t", size_bits, False, 3)

        self.aliases: dict[str, TypeInfo] = {}
        for type_info, names in {
            self.bool: ("_bool", "bool"),
            self.char: ("char",),
            self.schar: ("signed char",),
            self.uchar: ("unsigned char",),
            self.short: ("short", "short int", "signed short", "signed short int"),
            self.ushort: ("unsigned short", "unsigned short int"),
            self.int: ("int", "signed", "signed int"),
            self.uint: ("unsigned", "unsigned int"),
            self.long: ("long", "long int", "signed long", "signed long int"),
            self.ulong: (
                "unsigned long",
                "unsigned long int",
                "long unsigned int",
            ),
            self.llong: (
                "long long",
                "long long int",
                "signed long long",
                "signed long long int",
            ),
            self.ullong: (
                "unsigned long long",
                "unsigned long long int",
                "long long unsigned int",
            ),
            self.size_t: ("size_t",),
            TypeInfo("float", 32, True, 4, floating=True): ("float",),
            TypeInfo("double", 64, True, 5, floating=True): ("double",),
            TypeInfo("long double", 128, True, 6, floating=True): ("long double",),
        }.items():
            for alias in names:
                self.aliases[alias] = type_info

        for width in (8, 16, 32, 64):
            rank = {8: 1, 16: 2, 32: 3, 64: 5}[width]
            self.aliases[f"int{width}_t"] = TypeInfo(
                f"int{width}_t", width, True, rank
            )
            self.aliases[f"uint{width}_t"] = TypeInfo(
                f"uint{width}_t", width, False, rank
            )
            self.aliases[f"int_least{width}_t"] = self.aliases[f"int{width}_t"]
            self.aliases[f"uint_least{width}_t"] = self.aliases[f"uint{width}_t"]

        pointer = TypeInfo("uintptr_t", target.pointer_bits, False, 4)
        self.aliases["uintptr_t"] = pointer
        self.aliases["intptr_t"] = TypeInfo(
            "intptr_t", target.pointer_bits, True, 4
        )
        self.aliases["ptrdiff_t"] = self.aliases["intptr_t"]

    def named(self, name: str) -> TypeInfo:
        key = re.sub(r"\s+", " ", name.strip().lower().replace("_", " ")).strip()
        key = key.replace("unsigned int", "unsigned int")
        if key in self.aliases:
            return self.aliases[key]
        compact = re.sub(r"\s+", " ", name.strip().lower())
        if compact in self.aliases:
            return self.aliases[compact]
        return replace(UNKNOWN_TYPE, name=name)

    def unsigned_counterpart(self, type_info: TypeInfo) -> TypeInfo:
        if type_info.bits == self.int.bits and type_info.rank == self.int.rank:
            return self.uint
        if type_info.bits == self.long.bits and type_info.rank == self.long.rank:
            return self.ulong
        if type_info.bits == self.llong.bits and type_info.rank == self.llong.rank:
            return self.ullong
        if type_info.bits == self.short.bits and type_info.rank == self.short.rank:
            return self.ushort
        name = "unsigned " + type_info.name.removeprefix("signed ")
        return replace(type_info, name=name, signed=False)

    def promote(self, type_info: TypeInfo) -> TypeInfo:
        if type_info.unknown or type_info.floating or type_info.bits is None:
            return type_info
        if (type_info.rank, type_info.bits) >= (self.int.rank, self.int.bits):
            return type_info
        if type_info.signed:
            if (
                type_info.minimum is not None
                and type_info.maximum is not None
                and type_info.minimum >= self.int.minimum  # type: ignore[operator]
                and type_info.maximum <= self.int.maximum  # type: ignore[operator]
            ):
                return self.int
        elif type_info.maximum is not None and type_info.maximum <= self.int.maximum:  # type: ignore[operator]
            return self.int
        return self.uint

    def usual_arithmetic(self, left: TypeInfo, right: TypeInfo) -> TypeInfo:
        if left.unknown or right.unknown:
            return UNKNOWN_TYPE
        if left.floating or right.floating:
            return left if left.floating else right
        left = self.promote(left)
        right = self.promote(right)
        if left.signed == right.signed:
            return left if (left.rank, left.bits or 0) >= (
                right.rank,
                right.bits or 0,
            ) else right

        unsigned = left if left.signed is False else right
        signed = right if left.signed is False else left
        if unsigned.rank >= signed.rank:
            return unsigned
        if (
            signed.bits is not None
            and unsigned.bits is not None
            and signed.bits > unsigned.bits
        ):
            return signed
        return self.unsigned_counterpart(signed)


def type_from_spec(
    spec: Any, types: TypeLibrary, custom_types: Optional[dict[str, Any]] = None
) -> TypeInfo:
    if isinstance(spec, TypeInfo):
        return spec
    if isinstance(spec, dict):
        if spec.get("unknown"):
            return replace(UNKNOWN_TYPE, name=str(spec.get("name", "unknown-type")))
        if "bits" not in spec:
            return replace(UNKNOWN_TYPE, name=str(spec.get("name", "unknown-type")))
        bits = int(spec["bits"])
        signed = bool(spec.get("signed", True))
        rank = 1 if bits <= 8 else 2 if bits <= 16 else 3 if bits <= 32 else 5
        return TypeInfo(
            name=str(spec.get("name", f"int{bits}_t")),
            bits=bits,
            signed=signed,
            rank=int(spec.get("rank", rank)),
        )
    if isinstance(spec, str):
        if custom_types and spec in custom_types:
            return type_from_spec(custom_types[spec], types, custom_types)
        return types.named(spec)
    return UNKNOWN_TYPE


def char_constant_value(raw: str) -> Optional[int]:
    text = raw
    if text.startswith("L"):
        text = text[1:]
    if len(text) < 2 or text[0] != "'" or text[-1] != "'":
        return None
    body = text[1:-1]
    escapes = {"n": 10, "t": 9, "r": 13, "0": 0, "\\": 92, "'": 39, '"': 34}
    if not body:
        return None
    if body[0] != "\\":
        return ord(body)
    rest = body[1:]
    if rest in escapes:
        return escapes[rest]
    if rest.startswith("x"):
        return int(rest[1:], 16)
    if re.fullmatch(r"[0-7]{1,3}", rest):
        return int(rest, 8)
    return ord(rest[-1])


def constant_value(node: c_ast.Constant) -> Optional[int]:
    if node.type == "char":
        return char_constant_value(node.value)
    core = re.sub(r"[uUlL]+$", "", node.value)
    try:
        if core.lower().startswith("0x"):
            return int(core, 16)
        if core.lower().startswith("0b"):
            return int(core, 2)
        if len(core) > 1 and core.startswith("0"):
            return int(core, 8)
        return int(core, 10)
    except ValueError:
        return None


def build_audit_source(expression: str, typedef_names: list[str]) -> str:
    lines = [
        "typedef signed char int8_t;",
        "typedef unsigned char uint8_t;",
        "typedef signed short int16_t;",
        "typedef unsigned short uint16_t;",
        "typedef signed int int32_t;",
        "typedef unsigned int uint32_t;",
        "typedef signed long long int64_t;",
        "typedef unsigned long long uint64_t;",
    ]
    for name in sorted(set(typedef_names)):
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            lines.append(f"typedef long {name};")
    clean_expression = expression.strip().rstrip(";")
    lines.append(f"void __health_audit__(void) {{ return ({clean_expression}); }}")
    return "\n".join(lines)


def parse_expression(
    expression: str, typedef_names: Optional[list[str]] = None
) -> tuple[Optional[c_ast.Node], Optional[Issue]]:
    source = build_audit_source(expression, typedef_names or [])
    try:
        tree = CParser().parse(source, filename="<health-expression>")
    except ParseError as error:
        return None, Issue(
            "parse_error",
            f"pycparser could not parse expression or an unknown cast type: {error}",
            severity="confirmation",
        )
    for node in tree:
        if isinstance(node, c_ast.FuncDef) and node.decl.name == "__health_audit__":
            body = node.body.block_items or []
            if body and isinstance(body[0], c_ast.Return):
                return body[0].expr, None
    return None, Issue("parse_error", "audit wrapper did not contain a return expression")


def arithmetic_ranges(
    op: str, left: RangeSet, right: RangeSet
) -> tuple[Optional[RangeSet], Optional[str]]:
    pairs: list[tuple[int, int]] = []

    def add_pair(lo: int, hi: int) -> None:
        pairs.append((lo, hi))

    for a_lo, a_hi in left.intervals:
        for b_lo, b_hi in right.intervals:
            if op == "+":
                add_pair(a_lo + b_lo, a_hi + b_hi)
            elif op == "-":
                add_pair(a_lo - b_hi, a_hi - b_lo)
            elif op == "*":
                corners = (
                    a_lo * b_lo,
                    a_lo * b_hi,
                    a_hi * b_lo,
                    a_hi * b_hi,
                )
                add_pair(min(corners), max(corners))
            elif op in ("/", "%"):
                divisor_pairs = []
                if b_lo < 0:
                    divisor_pairs.append((b_lo, min(b_hi, -1)))
                if b_hi > 0:
                    divisor_pairs.append((max(b_lo, 1), b_hi))
                nonzero = RangeSet.create(divisor_pairs)
                if nonzero.empty:
                    return None, "division_by_zero"
                for n_lo, n_hi in nonzero.intervals:
                    values = (
                        c_div(a_lo, n_lo),
                        c_div(a_lo, n_hi),
                        c_div(a_hi, n_lo),
                        c_div(a_hi, n_hi),
                    )
                    if op == "/":
                        add_pair(min(values), max(values))
                    else:
                        remainder_bound = max(abs(n_lo), abs(n_hi)) - 1
                        if a_lo >= 0:
                            add_pair(0, min(a_hi, remainder_bound))
                        elif a_hi <= 0:
                            add_pair(-remainder_bound, 0)
                        else:
                            add_pair(-remainder_bound, remainder_bound)
            else:
                return None, "unsupported_operator"
    return RangeSet.create(pairs), None


def c_div(left: int, right: int) -> int:
    quotient = abs(left) // abs(right)
    return -quotient if (left < 0) != (right < 0) else quotient


def c_rem(left: int, right: int) -> int:
    quotient = c_div(left, right)
    return left - quotient * right


class Auditor:
    """Evaluate a small integer expression under one target ABI."""

    def __init__(
        self,
        target: Target,
        fields: Optional[dict[str, Any]] = None,
        custom_types: Optional[dict[str, Any]] = None,
    ):
        self.target = target
        self.types = TypeLibrary(target)
        self.fields = fields or {}
        self.custom_types = custom_types or {}

    def field_type(self, name: str) -> TypeInfo:
        spec = self.fields.get(name)
        if spec is None and "." in name:
            spec = self.fields.get(name.split(".")[-1])
        if spec is None:
            return replace(UNKNOWN_TYPE, name=name)
        return type_from_spec(spec, self.types, self.custom_types)

    def lvalue_name(self, node: Optional[c_ast.Node]) -> Optional[str]:
        if isinstance(node, c_ast.ID):
            return node.name
        if isinstance(node, c_ast.StructRef):
            base = self.lvalue_name(node.name)
            leaf = node.field.name if isinstance(node.field, c_ast.ID) else source_text(node.field)
            return f"{base}.{leaf}" if base else str(leaf)
        if isinstance(node, c_ast.ArrayRef):
            return self.lvalue_name(node.name)
        return None

    def lvalue_type(self, node: c_ast.Node) -> TypeInfo:
        name = self.lvalue_name(node)
        if name is None:
            return UNKNOWN_TYPE
        if isinstance(node, c_ast.ArrayRef):
            element_spec = self.fields.get(name + "[]")
            if element_spec is None:
                base_spec = self.fields.get(name)
                if isinstance(base_spec, dict):
                    element_spec = base_spec.get("element_type")
                elif isinstance(base_spec, str) and base_spec.endswith("[]"):
                    element_spec = base_spec[:-2]
            if element_spec is not None:
                return type_from_spec(element_spec, self.types, self.custom_types)
            return replace(UNKNOWN_TYPE, name=name + "[]")
        return self.field_type(name)

    @staticmethod
    def make_issue(
        code: str,
        message: str,
        node: Optional[c_ast.Node] = None,
        severity: str = "blocker",
    ) -> Issue:
        return Issue(code, message, source_text(node) if node is not None else None, severity)

    @staticmethod
    def unknown_value(type_info: TypeInfo, issue: Issue) -> Value:
        return Value(None, type_info, (issue,))

    @staticmethod
    def merge(values: list[Value], result_type: Optional[TypeInfo] = None) -> Value:
        issues: list[Issue] = []
        ranges: Optional[RangeSet] = RangeSet(())
        chosen_type = result_type or UNKNOWN_TYPE
        for value in values:
            issues.extend(value.issues)
            if result_type is None:
                chosen_type = value.type
            if ranges is None or value.ranges is None:
                ranges = None
            else:
                ranges = ranges.union(value.ranges)
        unique_issues = tuple(sorted(set(issues), key=lambda item: (item.code, item.message)))
        return Value(ranges, chosen_type, unique_issues)

    def convert_value(
        self,
        value: Value,
        target_type: TypeInfo,
        node: Optional[c_ast.Node] = None,
    ) -> Value:
        issues = list(value.issues)
        if target_type.unknown:
            issues.append(self.make_issue(
                "unknown_type",
                f"target type {target_type.name!r} was not supplied; confirm its width and signedness",
                node,
                "confirmation",
            ))
            return Value(None, target_type, tuple(set(issues)))
        if value.type.floating or target_type.floating:
            issues.append(self.make_issue(
                "floating_point_unsupported",
                "floating-point range semantics are outside the integer audit configuration",
                node,
                "confirmation",
            ))
            return Value(None, target_type, tuple(set(issues)))
        if value.ranges is None or value.type.unknown:
            return Value(None, target_type, tuple(set(issues)))
        if target_type.name == "_Bool":
            if value.ranges.all_zero():
                bool_range = RangeSet.point(0)
            elif value.ranges.all_nonzero():
                bool_range = RangeSet.point(1)
            else:
                bool_range = RangeSet.create([(0, 1)])
            return Value(bool_range, target_type, tuple(set(issues)))
        if target_type.bits is None or target_type.signed is None:
            return Value(None, target_type, tuple(set(issues)))
        if (value.type.bits, value.type.signed) == (target_type.bits, target_type.signed):
            return Value(value.ranges, target_type, tuple(set(issues)))
        if value.ranges.lo >= target_type.minimum and value.ranges.hi <= target_type.maximum:  # type: ignore[operator]
            return Value(value.ranges, target_type, tuple(set(issues)))

        unsigned_ranges = modulo_cast(value.ranges, target_type.bits)
        if target_type.signed is False:
            return Value(unsigned_ranges, target_type, tuple(set(issues)))

        signed_ranges = twos_complement_to_signed(unsigned_ranges, target_type.bits)
        if self.target.signed_cast == "twos_complement_guaranteed":
            return Value(signed_ranges, target_type, tuple(set(issues)))
        if self.target.signed_cast == "twos_complement_assumed":
            issues.append(self.make_issue(
                "signed_cast_assumed",
                "out-of-range signed conversion modeled as two's complement; confirm compiler ABI guarantee",
                node,
                "warning",
            ))
            return Value(signed_ranges, target_type, tuple(set(issues)))
        issues.append(self.make_issue(
            "implementation_defined_cast",
            "out-of-range conversion to signed type is implementation-defined; confirm target compiler behavior",
            node,
            "confirmation",
        ))
        return Value(signed_ranges, target_type, tuple(set(issues)))

    NEGATED_COMPARISON = {
        "<": ">=",
        "<=": ">",
        ">": "<=",
        ">=": "<",
        "==": "!=",
        "!=": "==",
    }
    REVERSED_COMPARISON = {
        "<": ">",
        "<=": ">=",
        ">": "<",
        ">=": "<=",
        "==": "==",
        "!=": "!=",
    }

    def comparison_bound(
        self, node: c_ast.Node
    ) -> Optional[tuple[str, str, int]]:
        if not isinstance(node, c_ast.BinaryOp) or node.op not in self.NEGATED_COMPARISON:
            return None
        value = constant_value(node.right)
        name_node = node.left
        op = node.op
        if value is None and isinstance(node.left, c_ast.Constant):
            value = constant_value(node.left)
            name_node = node.right
            op = self.REVERSED_COMPARISON[node.op]
        if value is None:
            return None
        name = self.lvalue_name(name_node)
        if name is None:
            return None
        return name, op, value

    def condition_range(
        self, name: str, op: str, bound: int, truth: bool
    ) -> Optional[RangeSet]:
        if not truth:
            op = self.NEGATED_COMPARISON[op]
        type_info = self.field_type(name)
        lo, hi = type_info.minimum, type_info.maximum
        if lo is None or hi is None:
            return None
        if op == "<":
            hi = min(hi, bound - 1)
        elif op == "<=":
            hi = min(hi, bound)
        elif op == ">":
            lo = max(lo, bound + 1)
        elif op == ">=":
            lo = max(lo, bound)
        elif op == "==":
            lo, hi = max(lo, bound), min(hi, bound)
            return RangeSet.full(type_info).intersection(RangeSet.create([(lo, hi)]))
        elif op == "!=":
            return RangeSet.full(type_info).intersection(
                RangeSet.create([(type_info.minimum, bound - 1), (bound + 1, type_info.maximum)])  # type: ignore[arg-type]
            )
        return RangeSet.full(type_info).intersection(RangeSet.create([(lo, hi)]))

    def constrain_envs(
        self, env: dict[str, RangeSet], node: c_ast.Node, truth: bool
    ) -> list[dict[str, RangeSet]]:
        return self._constrain_envs([dict(env)], node, truth)

    def _constrain_envs(
        self,
        envs: list[dict[str, RangeSet]],
        node: c_ast.Node,
        truth: bool,
    ) -> list[dict[str, RangeSet]]:
        if isinstance(node, c_ast.BinaryOp) and node.op == "&&":
            if truth:
                envs = self._constrain_envs(envs, node.left, True)
                return self._constrain_envs(envs, node.right, True)
            left_false = self._constrain_envs(envs, node.left, False)
            left_true_right_false = self._constrain_envs(
                self._constrain_envs(envs, node.left, True), node.right, False
            )
            return self._cap_envs(left_false + left_true_right_false)

        if isinstance(node, c_ast.BinaryOp) and node.op == "||":
            if truth:
                left_true = self._constrain_envs(envs, node.left, True)
                left_false_right_true = self._constrain_envs(
                    self._constrain_envs(envs, node.left, False), node.right, True
                )
                return self._cap_envs(left_true + left_false_right_true)
            envs = self._constrain_envs(envs, node.left, False)
            return self._constrain_envs(envs, node.right, False)

        if isinstance(node, c_ast.UnaryOp) and node.op == "!":
            return self._constrain_envs(envs, node.expr, not truth)

        bound = self.comparison_bound(node)
        if bound is None:
            return envs
        name, op, value = bound
        constrained = self.condition_range(name, op, value, truth)
        if constrained is None:
            return envs
        result: list[dict[str, RangeSet]] = []
        for env in envs:
            next_env = dict(env)
            current = next_env.get(name, RangeSet.full(self.field_type(name)))
            next_env[name] = current.intersection(constrained)
            result.append(next_env)
        return result

    def _cap_envs(self, envs: list[dict[str, RangeSet]]) -> list[dict[str, RangeSet]]:
        if len(envs) <= self.target.max_branch_envs:
            return envs
        return [{}]

    def type_for_constant(self, node: c_ast.Constant, value: int) -> TypeInfo:
        raw = node.value or ""
        lower = raw.lower()
        long_count = len(re.findall(r"l", lower))
        unsigned_suffix = "u" in lower
        if node.type == "char":
            return self.types.int
        if long_count >= 2:
            candidates = [self.types.llong, self.types.ullong]
        elif long_count == 1:
            candidates = [self.types.long, self.types.llong]
            if unsigned_suffix:
                candidates = [self.types.ulong, self.types.ullong]
        elif unsigned_suffix:
            candidates = [self.types.uint, self.types.ulong, self.types.ullong]
        elif "x" in lower or (len(raw) > 1 and raw.lstrip("ULul")[0] == "0"):
            candidates = [
                self.types.int,
                self.types.uint,
                self.types.long,
                self.types.ulong,
                self.types.llong,
                self.types.ullong,
            ]
        else:
            candidates = [self.types.int, self.types.long, self.types.llong]
        for candidate in candidates:
            if candidate.contains(value):
                return candidate
        return self.types.ullong

    def typename(self, node: c_ast.Node) -> TypeInfo:
        try:
            text = CGenerator().visit(node)
        except Exception:
            text = source_text(node)
        return type_from_spec(text, self.types, self.custom_types)

    def eval(self, node: Optional[c_ast.Node], env: dict[str, RangeSet]) -> Value:
        if node is None:
            issue = self.make_issue("missing_node", "expression contained an empty node")
            return Value(None, UNKNOWN_TYPE, (issue,))
        if isinstance(node, c_ast.Constant):
            return self.eval_constant(node)
        if isinstance(node, (c_ast.ID, c_ast.StructRef)):
            return self.eval_named(node, env)
        if isinstance(node, c_ast.ArrayRef):
            return self.eval_array_ref(node, env)
        if isinstance(node, c_ast.UnaryOp):
            return self.eval_unary(node, env)
        if isinstance(node, c_ast.BinaryOp):
            return self.eval_binary(node, env)
        if isinstance(node, c_ast.TernaryOp):
            return self.eval_ternary(node, env)
        if isinstance(node, c_ast.Cast):
            value = self.eval(node.expr, env)
            target_type = self.typename(node.to_type)
            return self.convert_value(value, target_type, node)
        if isinstance(node, c_ast.Assignment):
            return self.eval_assignment(node, env)
        if isinstance(node, c_ast.ExprList):
            return self.eval_expr_list(node, env)
        if isinstance(node, c_ast.FuncCall):
            for argument in node.args.exprs if isinstance(node.args, c_ast.ExprList) else []:
                self.eval(argument, env)
            issue = self.make_issue(
                "function_call_not_modeled",
                "called function body is outside the supplied expression; provide its result range or remove the call",
                node,
                "confirmation",
            )
            return Value(None, UNKNOWN_TYPE, (issue,))
        issue = self.make_issue(
            "construct_not_modeled",
            f"{type(node).__name__} is not covered by the integer range model",
            node,
            "confirmation",
        )
        return Value(None, UNKNOWN_TYPE, (issue,))

    def eval_constant(self, node: c_ast.Constant) -> Value:
        value = constant_value(node)
        if value is None:
            issue = self.make_issue(
                "constant_not_parsed",
                f"could not interpret C constant {node.value!r}",
                node,
                "confirmation",
            )
            return Value(None, UNKNOWN_TYPE, (issue,))
        type_info = self.type_for_constant(node, value)
        return Value(RangeSet.point(value), type_info)

    def eval_named(self, node: c_ast.Node, env: dict[str, RangeSet]) -> Value:
        name = self.lvalue_name(node) or source_text(node)
        type_info = self.field_type(name)
        if type_info.unknown:
            issue = self.make_issue(
                "unknown_type",
                f"field {name!r} has no caller-supplied integer type; confirm width and signedness",
                node,
                "confirmation",
            )
            return Value(None, type_info, (issue,))
        ranges = RangeSet.full(type_info)
        constraint = env.get(name)
        if constraint is not None:
            ranges = ranges.intersection(constraint)
        return Value(ranges, type_info)

    def eval_array_ref(self, node: c_ast.ArrayRef, env: dict[str, RangeSet]) -> Value:
        index_value = self.eval(node.subscript, env)
        type_info = self.lvalue_type(node)
        if type_info.unknown:
            issue = self.make_issue(
                "unknown_array_type",
                "array element type was not supplied; use field name \"base[]\" or an element_type descriptor",
                node,
                "confirmation",
            )
            return Value(None, type_info, index_value.issues + (issue,))
        ranges = RangeSet.full(type_info)
        return Value(ranges, type_info, index_value.issues)

    @staticmethod
    def truth_possible(value: Value) -> tuple[bool, bool]:
        if value.ranges is None:
            return True, True
        if value.ranges.empty:
            return False, False
        zero_possible = value.ranges.contains_zero()
        nonzero_possible = not value.ranges.all_zero()
        return zero_possible, nonzero_possible

    def checked_integer_result(
        self,
        raw: Optional[RangeSet],
        result_type: TypeInfo,
        issues: list[Issue],
        node: c_ast.Node,
    ) -> Value:
        if raw is None or result_type.bits is None or result_type.signed is None:
            return Value(None, result_type, tuple(set(issues)))
        if result_type.signed:
            lo, hi = result_type.minimum, result_type.maximum
            if lo is not None and hi is not None and raw.lo >= lo and raw.hi <= hi:
                return Value(raw, result_type, tuple(set(issues)))
            issues.append(self.make_issue(
                "signed_overflow_possible",
                f"signed result envelope [{raw.lo}, {raw.hi}] exceeds "
                f"{result_type.name} range [{result_type.minimum}, {result_type.maximum}]; "
                "C signed overflow is undefined behavior",
                node,
                "blocker",
            ))
            return Value(raw, result_type, tuple(set(issues)))
        wrapped = modulo_cast(raw, result_type.bits)
        return Value(wrapped, result_type, tuple(set(issues)))

    def eval_unary(self, node: c_ast.UnaryOp, env: dict[str, RangeSet]) -> Value:
        op = node.op
        if op == "sizeof":
            operand_type = self.typename(node.expr) if isinstance(node.expr, c_ast.Typename) else self.eval(node.expr, env).type
            if operand_type.bits is None:
                issue = self.make_issue("sizeof_unknown_type", "cannot derive sizeof without target type width", node, "confirmation")
                return Value(None, self.types.size_t, (issue,))
            char_bits = max(1, self.target.char_bits)
            size = max(1, (operand_type.bits + char_bits - 1) // char_bits)
            return Value(RangeSet.point(size), self.types.size_t)
        if op in ("&", "*"):
            issue = self.make_issue("pointer_not_modeled", "pointer addresses and dereferences are outside the integer value model", node, "confirmation")
            return Value(None, UNKNOWN_TYPE, (issue,))
        if op in ("++", "--", "p++", "p--"):
            issue = self.make_issue("increment_not_modeled", "increment/decrement side effects need an explicit assignment model", node, "confirmation")
            return Value(None, UNKNOWN_TYPE, (issue,))

        value = self.eval(node.expr, env)
        promoted_type = self.types.promote(value.type)
        value = self.convert_value(value, promoted_type, node.expr)
        issues = list(value.issues)
        if value.ranges is None:
            return Value(None, promoted_type, tuple(set(issues)))

        if op == "+":
            return Value(value.ranges, promoted_type, tuple(set(issues)))
        if op == "-":
            raw = RangeSet.create([(-value.ranges.hi, -value.ranges.lo)])
            return self.checked_integer_result(raw, promoted_type, issues, node)
        if op == "~":
            raw = RangeSet.create([(-value.ranges.hi - 1, -value.ranges.lo - 1)])
            if promoted_type.signed and self.target.signed_cast == "implementation_defined":
                issues.append(self.make_issue(
                    "signed_bitwise_representation",
                    "bitwise complement on a signed target is interpreted as two's complement; confirm ABI",
                    node,
                    "confirmation",
                ))
            return self.checked_integer_result(raw, promoted_type, issues, node)
        if op == "!":
            zero_possible, nonzero_possible = self.truth_possible(value)
            if nonzero_possible and not zero_possible:
                bool_range = RangeSet.point(0)
            elif zero_possible and not nonzero_possible:
                bool_range = RangeSet.point(1)
            else:
                bool_range = RangeSet.create([(0, 1)])
            return Value(bool_range, self.types.int, tuple(set(issues)))

        issue = self.make_issue("unary_operator_not_modeled", f"unary operator {op!r} is not covered", node, "confirmation")
        return Value(None, UNKNOWN_TYPE, tuple(set(issues) + [issue]))

    def without_zero(self, ranges: RangeSet) -> RangeSet:
        pairs: list[tuple[int, int]] = []
        for lo, hi in ranges.intervals:
            if lo <= 0 <= hi:
                if lo < 0:
                    pairs.append((lo, -1))
                if hi > 0:
                    pairs.append((1, hi))
            else:
                pairs.append((lo, hi))
        return RangeSet.create(pairs)

    def compute_binary(
        self,
        op: str,
        left: Value,
        right: Value,
        node: c_ast.Node,
    ) -> Value:
        issues: list[Issue] = list(left.issues) + list(right.issues)
        if left.ranges is None or right.ranges is None:
            result_type = self.types.usual_arithmetic(left.type, right.type)
            return Value(None, result_type, tuple(set(issues)))

        if op in ("<<", ">>"):
            result_type = self.types.promote(left.type)
            operand = self.convert_value(left, result_type, node.left if isinstance(node, c_ast.BinaryOp) else node)
            issues.extend(operand.issues)
            count = right.ranges
            if count.lo < 0 or count.hi >= (result_type.bits or 0):
                issues.append(self.make_issue(
                    "invalid_shift",
                    f"shift count envelope [{count.lo}, {count.hi}] is outside [0, {result_type.bits - 1}]",
                    node,
                    "blocker",
                ))
                return Value(None, result_type, tuple(set(issues)))
            if op == "<<":
                if result_type.signed and operand.ranges.lo < 0:
                    issues.append(self.make_issue("negative_shift_left", "left shift of a negative signed value is not modeled", node, "confirmation"))
                    return Value(None, result_type, tuple(set(issues)))
                raw = RangeSet.create([(operand.ranges.lo << count.lo, operand.ranges.hi << count.hi)])
            else:
                if result_type.signed and operand.ranges.lo < 0:
                    issues.append(self.make_issue("signed_right_shift", "right shift of a negative signed value is implementation-defined", node, "confirmation"))
                    return Value(RangeSet.full(result_type), result_type, tuple(set(issues)))
                raw = RangeSet.create([(operand.ranges.lo >> count.hi, operand.ranges.hi >> count.lo)])
            return self.checked_integer_result(raw, result_type, issues, node)

        promoted_left = self.types.promote(left.type)
        promoted_right = self.types.promote(right.type)
        result_type = self.types.usual_arithmetic(promoted_left, promoted_right)
        left_value = self.convert_value(left, result_type, node)
        right_value = self.convert_value(right, result_type, node)
        issues.extend(left_value.issues)
        issues.extend(right_value.issues)
        if left_value.ranges is None or right_value.ranges is None:
            return Value(None, result_type, tuple(set(issues)))

        if op in ("&", "|", "^"):
            if result_type.signed and (left_value.ranges.lo < 0 or right_value.ranges.lo < 0):
                issues.append(self.make_issue(
                    "signed_bitwise_operation",
                    "signed bitwise range semantics depend on target representation; confirm ABI",
                    node,
                    "confirmation",
                ))
                return Value(RangeSet.full(result_type), result_type, tuple(set(issues)))
            if op == "&":
                raw = RangeSet.create([(0, min(left_value.ranges.hi, right_value.ranges.hi))])
            else:
                highest = max(left_value.ranges.hi, right_value.ranges.hi)
                mask = (1 << max(1, highest.bit_length())) - 1
                raw = RangeSet.create([(0, mask)])
            return Value(raw, result_type, tuple(set(issues)))

        divisor = right_value.ranges
        if op in ("/", "%") and divisor.contains_zero():
            issues.append(self.make_issue(
                "division_by_zero_possible",
                "divisor envelope contains zero; the expression has a possible runtime divide-by-zero/UB path",
                node,
                "blocker",
            ))
            divisor = self.without_zero(divisor)
            if divisor.empty:
                return Value(None, result_type, tuple(set(issues)))

        raw, arithmetic_error = arithmetic_ranges(
            op,
            left_value.ranges,
            divisor if op in ("/", "%") else right_value.ranges,
        )
        if arithmetic_error == "unsupported_operator":
            issues.append(self.make_issue("operator_not_modeled", f"binary operator {op!r} is not covered", node, "confirmation"))
            return Value(None, result_type, tuple(set(issues)))
        return self.checked_integer_result(raw, result_type, issues, node)

    def comparison_range(
        self, op: str, left: RangeSet, right: RangeSet
    ) -> RangeSet:
        true_possible = False
        false_possible = False
        for a_lo, a_hi in left.intervals:
            for b_lo, b_hi in right.intervals:
                overlap = max(a_lo, b_lo) <= min(a_hi, b_hi)
                if op == "<":
                    true_possible |= a_lo < b_hi
                    false_possible |= a_hi >= b_lo
                elif op == "<=":
                    true_possible |= a_lo <= b_hi
                    false_possible |= a_hi > b_lo
                elif op == ">":
                    true_possible |= a_hi > b_lo
                    false_possible |= a_lo <= b_hi
                elif op == ">=":
                    true_possible |= a_hi >= b_lo
                    false_possible |= a_lo < b_hi
                elif op == "==":
                    true_possible |= overlap
                    singleton_pair = a_lo == a_hi == b_lo == b_hi
                    false_possible |= not singleton_pair
                elif op == "!=":
                    true_possible |= not (a_lo == a_hi == b_lo == b_hi)
                    false_possible |= overlap
        if true_possible and false_possible:
            return RangeSet.create([(0, 1)])
        if true_possible:
            return RangeSet.point(1)
        return RangeSet.point(0)

    def eval_binary(self, node: c_ast.BinaryOp, env: dict[str, RangeSet]) -> Value:
        if node.op in ("&&", "||"):
            return self.eval_logical(node, env)

        left = self.eval(node.left, env)
        right = self.eval(node.right, env)
        issues = list(left.issues) + list(right.issues)
        if node.op in self.NEGATED_COMPARISON:
            result_type = self.types.usual_arithmetic(left.type, right.type)
            left_value = self.convert_value(left, result_type, node)
            right_value = self.convert_value(right, result_type, node)
            issues.extend(left_value.issues)
            issues.extend(right_value.issues)
            if left_value.ranges is None or right_value.ranges is None:
                return Value(None, self.types.int, tuple(set(issues)))
            result_range = self.comparison_range(node.op, left_value.ranges, right_value.ranges)
            return Value(result_range, self.types.int, tuple(set(issues)))

        return self.compute_binary(node.op, left, right, node)

    def eval_logical(self, node: c_ast.BinaryOp, env: dict[str, RangeSet]) -> Value:
        left = self.eval(node.left, env)
        zero_possible, nonzero_possible = self.truth_possible(left)
        issues = list(left.issues)

        if node.op == "&&":
            if zero_possible and not nonzero_possible:
                return Value(RangeSet.point(0), self.types.int, tuple(set(issues)))
            branch_envs = self.constrain_envs(env, node.left, True)
            right = self.merge([self.eval(node.right, branch_env) for branch_env in branch_envs], self.types.int)
            issues.extend(right.issues)
            right_zero, right_nonzero = self.truth_possible(right)
            can_be_one = nonzero_possible and right_nonzero
            can_be_zero = zero_possible or right_zero
        else:
            if nonzero_possible and not zero_possible:
                return Value(RangeSet.point(1), self.types.int, tuple(set(issues)))
            branch_envs = self.constrain_envs(env, node.left, False)
            right = self.merge([self.eval(node.right, branch_env) for branch_env in branch_envs], self.types.int)
            issues.extend(right.issues)
            right_zero, right_nonzero = self.truth_possible(right)
            can_be_one = nonzero_possible or right_nonzero
            can_be_zero = zero_possible and right_zero

        if can_be_one and can_be_zero:
            result_range = RangeSet.create([(0, 1)])
        elif can_be_one:
            result_range = RangeSet.point(1)
        else:
            result_range = RangeSet.point(0)
        return Value(result_range, self.types.int, tuple(set(issues)))

    def eval_ternary(self, node: c_ast.TernaryOp, env: dict[str, RangeSet]) -> Value:
        condition = self.eval(node.cond, env)
        zero_possible, nonzero_possible = self.truth_possible(condition)
        values: list[Value] = []

        if nonzero_possible:
            then_envs = self.constrain_envs(env, node.cond, True)
            values.extend(self.eval(node.iftrue, branch_env) for branch_env in then_envs)
        if zero_possible and node.iffalse is not None:
            else_envs = self.constrain_envs(env, node.cond, False)
            values.extend(self.eval(node.iffalse, branch_env) for branch_env in else_envs)

        if not values:
            issue = self.make_issue("unreachable_branch_model_error", "ternary produced no feasible branch", node)
            return Value(None, UNKNOWN_TYPE, condition.issues + (issue,))

        result_type = values[0].type
        if len(values) >= 2:
            result_type = self.types.usual_arithmetic(values[0].type, values[1].type)
        converted = [self.convert_value(value, result_type, node) for value in values]
        result = self.merge(converted, result_type)
        issues = list(result.issues) + list(condition.issues)
        return replace(result, issues=tuple(sorted(set(issues), key=lambda item: (item.code, item.message))))

    def eval_assignment(self, node: c_ast.Assignment, env: dict[str, RangeSet]) -> Value:
        target_type = self.lvalue_type(node.lvalue)
        if node.op == "=":
            raw_value = self.eval(node.rvalue, env)
            value = self.convert_value(raw_value, target_type, node)
        else:
            current = self.eval(node.lvalue, env)
            raw_value = self.eval(node.rvalue, env)
            op = node.op[:-1] if node.op.endswith("=") else node.op
            combined = self.compute_binary(op, current, raw_value, node)
            value = self.convert_value(combined, target_type, node)

        name = self.lvalue_name(node.lvalue)
        if name is not None and value.ranges is not None and not target_type.unknown:
            env[name] = value.ranges
        return value

    def eval_expr_list(self, node: c_ast.ExprList, env: dict[str, RangeSet]) -> Value:
        result: Optional[Value] = None
        for expression in node.exprs:
            result = self.eval(expression, env)
        if result is None:
            issue = self.make_issue("empty_expression_list", "comma expression list was empty", node)
            return Value(None, UNKNOWN_TYPE, (issue,))
        return result


C_TYPE_KEYWORDS = {
    "const", "volatile", "register", "restrict", "static", "extern",
    "auto", "signed", "unsigned", "char", "short", "int", "long",
    "float", "double", "void", "_Bool", "bool",
}


def typedef_names_from_config(
    fields: dict[str, Any],
    custom_types: dict[str, Any],
    explicit: Optional[list[str]] = None,
) -> list[str]:
    names = set(explicit or [])
    probe_types = TypeLibrary(Target(name="probe"))
    for type_name in custom_types:
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", type_name):
            names.add(type_name)
    for spec in fields.values():
        candidates: list[str] = []
        if isinstance(spec, str):
            candidates = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", spec)
        elif isinstance(spec, dict) and isinstance(spec.get("name"), str):
            candidates = [spec["name"]]
        for token in candidates:
            if token in C_TYPE_KEYWORDS:
                continue
            if token in probe_types.aliases:
                continue
            if token.startswith("int") and token.endswith("_t"):
                continue
            names.add(token)
    return sorted(names)


def range_to_dict(ranges: Optional[RangeSet]) -> Optional[dict[str, Any]]:
    if ranges is None:
        return None
    return {
        "min": ranges.lo if not ranges.empty else None,
        "max": ranges.hi if not ranges.empty else None,
        "segments": [list(pair) for pair in ranges.intervals],
    }


def audit_expression_for_target(
    expression: str,
    target_data: dict[str, Any],
    fields: dict[str, Any],
    business: dict[str, Any],
    custom_types: Optional[dict[str, Any]] = None,
    typedef_names: Optional[list[str]] = None,
) -> dict[str, Any]:
    target = Target.from_dict(target_data)
    custom_types = custom_types or {}
    all_typedefs = typedef_names_from_config(fields, custom_types, typedef_names)
    ast_expression, parse_issue = parse_expression(expression, all_typedefs)

    issues: list[Issue] = []
    value: Optional[Value] = None
    if parse_issue is not None:
        issues.append(parse_issue)
        result_type = UNKNOWN_TYPE
    else:
        auditor = Auditor(target, fields, custom_types)
        value = auditor.eval(ast_expression, {})
        issues.extend(value.issues)
        result_type = value.type
        if value.ranges is not None and value.ranges.empty:
            issues.append(Issue(
                "empty_result_range",
                "analysis found no feasible result values; branch constraints need review",
                severity="blocker",
            ))

    unique_issues = tuple(sorted(set(issues), key=lambda item: (item.severity, item.code, item.message)))
    confirmation = [item for item in unique_issues if item.severity == "confirmation"]
    blockers = [item for item in unique_issues if item.severity == "blocker"]
    warnings = [item for item in unique_issues if item.severity == "warning"]

    business_min = business.get("min")
    business_max = business.get("max")
    computed = range_to_dict(value.ranges if value is not None else None)
    outside: list[str] = []
    if computed is not None and computed["min"] is not None:
        if business_min is not None and computed["min"] < int(business_min):
            outside.append("min")
        if business_max is not None and computed["max"] > int(business_max):
            outside.append("max")

    if confirmation:
        status = "needs_confirmation"
    elif blockers or value is None or value.ranges is None:
        status = "insufficient_evidence"
    elif outside:
        status = "insufficient_evidence"
    else:
        status = "sufficient_evidence"

    reason: str
    if status == "sufficient_evidence":
        reason = "sound range envelope is inside caller-supplied business bounds"
    elif confirmation:
        reason = "unknown type/ABI or unsupported syntax must be confirmed before proof"
    elif blockers:
        reason = "possible undefined/runtime behavior blocks a business-invariant proof"
    elif outside:
        reason = "computed envelope exceeds business " + "/".join(outside) + " bound"
    else:
        reason = "expression result could not be modeled"

    return {
        "target": target.name,
        "status": status,
        "reason": reason,
        "result_type": result_type.name,
        "target_widths": {
            "char_bits": target.char_bits,
            "short_bits": target.short_bits,
            "int_bits": target.int_bits,
            "long_bits": target.long_bits,
            "long_long_bits": target.long_long_bits,
        },
        "computed_range": computed,
        "business_bounds": {
            "min": int(business_min) if business_min is not None else None,
            "max": int(business_max) if business_max is not None else None,
        },
        "outside_bounds": outside,
        "issues": [item.to_dict() for item in unique_issues],
        "blocker_count": len(blockers),
        "confirmation_count": len(confirmation),
        "warning_count": len(warnings),
    }


def audit_config(config: dict[str, Any]) -> dict[str, Any]:
    expression = config.get("expression")
    if not expression and config.get("expression_file"):
        expression = open(config["expression_file"], "r", encoding="utf-8").read()
    if not expression:
        raise ValueError("config requires 'expression' or 'expression_file'")

    fields = config.get("fields", {})
    business = config.get("business", {})
    custom_types = config.get("types", {})
    typedef_names = config.get("typedef_names", [])
    targets = config.get("targets")
    if targets is None:
        targets = [config.get("target", {"name": "target"})]
    if isinstance(targets, dict):
        targets = [targets]

    reports = [
        audit_expression_for_target(
            expression,
            target,
            fields,
            business,
            custom_types,
            typedef_names,
        )
        for target in targets
    ]
    return {
        "expression": expression.strip(),
        "business_bounds": business,
        "reports": reports,
    }


def format_text_report(report: dict[str, Any]) -> str:
    lines = [f"C expression: {report['expression']}", f"Business bounds: {report['business_bounds']}", ""]
    for item in report["reports"]:
        lines.append(f"== {item['target']} (int={item['target_widths']['int_bits']}-bit) ==")
        lines.append(f"decision: {item['status']}")
        lines.append(f"reason: {item['reason']}")
        lines.append(f"result type: {item['result_type']}")
        lines.append(f"computed range: {item['computed_range']}")
        for issue in item["issues"]:
            location = f" [{issue['node']}]" if issue.get("node") else ""
            lines.append(f"- {issue['severity']}: {issue['code']}{location}: {issue['message']}")
        lines.append("")
    return "\n".join(lines).rstrip()


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", help="JSON config containing expression, fields, targets and bounds")
    parser.add_argument("--expr", help="C integer expression to audit")
    parser.add_argument("--fields-json", default="{}", help="JSON object mapping names/dotted fields to C types")
    parser.add_argument("--targets-json", help="JSON array of target width objects")
    parser.add_argument("--business-min", type=int)
    parser.add_argument("--business-max", type=int)
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        if args.config:
            with open(args.config, "r", encoding="utf-8") as handle:
                config = json.load(handle)
        else:
            if not args.expr:
                raise ValueError("either --config or --expr is required")
            config = {
                "expression": args.expr,
                "fields": json.loads(args.fields_json),
                "business": {"min": args.business_min, "max": args.business_max},
            }
            if args.targets_json:
                config["targets"] = json.loads(args.targets_json)
        report = audit_config(config)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"health_audit: {error}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(format_text_report(report))
    return 0 if all(item["status"] == "sufficient_evidence" for item in report["reports"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
