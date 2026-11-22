#-------------------------------------------------------------------------------
# elftools: dwarf/cfi_compare.py
#
# Read-only comparison of DWARF call-frame information from two ELF files.
#
# This code is in the public domain.
#-------------------------------------------------------------------------------
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Literal, Mapping, Sequence, cast

from ..common.exceptions import DWARFError, ELFError
from ..elf.elffile import ELFFile
from .callframe import (
    CFARule,
    DecodedCallFrameTable,
    FDE,
    Line,
    RegisterRule,
)


FrameSection = Literal['auto', '.eh_frame', '.debug_frame']


class FrameCompareError(DWARFError):
    """ Raised when two CFI sources cannot be compared as requested.
    """


class ComparisonStatus(str, Enum):
    """ Result of comparing one contiguous instruction interval.
    """
    SAME = 'same'
    DIFFERENT = 'different'
    INCOMPARABLE = 'incomparable'
    LEFT_ONLY = 'left_only'
    RIGHT_ONLY = 'right_only'


@dataclass(frozen=True, init=False)
class AddressMap:
    """ Maps addresses in the right-hand file into the left-hand address space.

        The mapping is intentionally explicit: callers must say which file is
        the artifact (left) and which one is the external debug file (right),
        and supply the load/link bias between them. A positive offset means

            left_address = right_address + offset

        `bias` is accepted as an alias for `offset`.
    """
    offset: int

    def __init__(self, offset: int = 0, *, bias: int | None = None) -> None:
        if bias is not None:
            if offset not in (0, bias):
                raise ValueError('offset and bias disagree')
            offset = bias
        object.__setattr__(self, 'offset', int(offset))

    def map_address(self, address: int) -> int:
        return int(address) + self.offset

    # Short alias for callers that use mapping terminology.
    map = map_address

    def map_range(self, start: int, end: int) -> tuple[int, int]:
        if end < start:
            raise FrameCompareError(
                f'invalid address range: 0x{start:x}..0x{end:x}')
        return self.map_address(start), self.map_address(end)

    def to_dict(self) -> dict[str, int | str]:
        return {
            'direction': 'right_to_left',
            'offset': self.offset,
            'offset_hex': _hex(self.offset),
        }


@dataclass(frozen=True)
class FrameFile:
    """ One side of a CFI file pair.

        `section` may be '.eh_frame', '.debug_frame', or 'auto'. For a pair,
        the left side prefers .eh_frame (the artifact) and the right side
        prefers .debug_frame (the external debug file).
    """
    path: str | os.PathLike[str]
    section: str = 'auto'

    def __post_init__(self) -> None:
        object.__setattr__(self, 'path', os.fspath(self.path))
        if self.section not in ('auto', '.eh_frame', '.debug_frame'):
            raise ValueError(
                f"unknown frame section {self.section!r}; use 'auto', "
                "'.eh_frame', or '.debug_frame'")


@dataclass(frozen=True)
class FramePair:
    """ An auditable pair of CFI sources and the right-to-left address map. """
    left: FrameFile
    right: FrameFile
    right_to_left: AddressMap = field(default_factory=AddressMap)


@dataclass(frozen=True)
class RuleSource:
    """ Provenance for a register/CFA rule.

        `line_index` is the index in the decoded FDE table. `pc` is the raw
        (unmapped) table PC, so an external-debug result can still be traced
        back to its original file and FDE.
    """
    side: str = 'unknown'
    path: str = '<synthetic>'
    section: str = '<synthetic>'
    fde_index: int | None = None
    fde_offset: int | None = None
    cie_offset: int | None = None
    line_index: int | None = None
    pc: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            'side': self.side,
            'path': self.path,
            'section': self.section,
            'fde_index': self.fde_index,
            'fde_offset': self.fde_offset,
            'fde_offset_hex': _hex_optional(self.fde_offset),
            'cie_offset': self.cie_offset,
            'cie_offset_hex': _hex_optional(self.cie_offset),
            'line_index': self.line_index,
            'pc': self.pc,
            'pc_hex': _hex_optional(self.pc),
        }


@dataclass(frozen=True)
class NormalizedCFARule:
    rule_type: str
    register: int | None = None
    offset: int | None = None
    expression: bytes | None = None
    comparable: bool = True
    description: str = ''


@dataclass(frozen=True)
class NormalizedRegisterRule:
    register: int
    rule_type: str
    offset: int | None = None
    source_register: int | None = None
    expression: bytes | None = None
    comparable: bool = True
    description: str = ''


@dataclass(frozen=True)
class RuleState:
    """ A normalized snapshot of every rule that matters at one PC. """
    cfa: NormalizedCFARule
    registers: tuple[NormalizedRegisterRule, ...] = ()

    def register(self, number: int) -> NormalizedRegisterRule:
        for rule in self.registers:
            if rule.register == number:
                return rule
        return _implicit_undefined_register(number)


@dataclass(frozen=True)
class FrameSegment:
    """ Rules that are in effect over the half-open range [start, end). """
    start: int
    end: int
    rules: RuleState
    source: RuleSource

    def __post_init__(self) -> None:
        if self.end <= self.start:
            raise ValueError(
                f'empty frame segment: 0x{self.start:x}..0x{self.end:x}')


@dataclass(frozen=True)
class RuleDifference:
    field: str
    left: str
    right: str
    register: int | None = None
    left_source: RuleSource | None = None
    right_source: RuleSource | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            'field': self.field,
            'register': self.register,
            'left': self.left,
            'right': self.right,
            'left_source': _source_to_dict(self.left_source),
            'right_source': _source_to_dict(self.right_source),
        }


@dataclass(frozen=True)
class IncomparableRule:
    """ A complex or otherwise unsupported rule, retained with its source.

        Expression bytes are deliberately not interpreted. They are kept so a
        later tool can inspect the original expression without this comparator
        claiming that two expressions are equivalent.
    """
    side: str
    field: str
    rule_type: str
    source: RuleSource
    expression: bytes | None = None
    description: str = ''

    def to_dict(self) -> dict[str, Any]:
        return {
            'side': self.side,
            'field': self.field,
            'rule_type': self.rule_type,
            'expression': self.expression.hex() if self.expression else None,
            'expression_bytes': (
                list(self.expression) if self.expression else None),
            'description': self.description,
            'source': self.source.to_dict(),
        }


@dataclass(frozen=True)
class IntervalComparison:
    """ A half-open instruction interval with one comparison verdict. """
    start: int
    end: int
    status: ComparisonStatus
    left_sources: tuple[RuleSource, ...] = ()
    right_sources: tuple[RuleSource, ...] = ()
    differences: tuple[RuleDifference, ...] = ()
    incomparable_rules: tuple[IncomparableRule, ...] = ()

    @property
    def left_source(self) -> RuleSource | None:
        return self.left_sources[0] if self.left_sources else None

    @property
    def right_source(self) -> RuleSource | None:
        return self.right_sources[0] if self.right_sources else None

    @property
    def expressions(self) -> tuple[IncomparableRule, ...]:
        return tuple(
            rule for rule in self.incomparable_rules
            if rule.expression is not None)

    def to_dict(self) -> dict[str, Any]:
        return {
            'start': self.start,
            'end': self.end,
            'start_hex': _hex(self.start),
            'end_hex': _hex(self.end),
            'status': self.status.value,
            'left_sources': [
                source.to_dict() for source in self.left_sources],
            'right_sources': [
                source.to_dict() for source in self.right_sources],
            'differences': [
                difference.to_dict() for difference in self.differences],
            'incomparable_rules': [
                rule.to_dict() for rule in self.incomparable_rules],
        }


@dataclass(frozen=True)
class FrameFileInfo:
    """ Identity and section facts for one auditable input file. """
    path: str
    section: str
    section_address: int
    section_size: int
    file_size: int
    sha256: str
    elf_class: int
    little_endian: bool
    machine: str

    def to_dict(self) -> dict[str, Any]:
        return {
            'path': self.path,
            'section': self.section,
            'section_address': self.section_address,
            'section_address_hex': _hex(self.section_address),
            'section_size': self.section_size,
            'file_size': self.file_size,
            'sha256': self.sha256,
            'elf_class': self.elf_class,
            'little_endian': self.little_endian,
            'machine': self.machine,
        }


@dataclass(frozen=True)
class MatchedFDE:
    """ A same-start FDE pairing, useful for auditing the comparison. """
    start: int
    left_source: RuleSource
    right_source: RuleSource
    left_range: tuple[int, int]
    right_range: tuple[int, int]
    right_raw_range: tuple[int, int]

    def to_dict(self) -> dict[str, Any]:
        return {
            'start': self.start,
            'start_hex': _hex(self.start),
            'left_source': self.left_source.to_dict(),
            'right_source': self.right_source.to_dict(),
            'left_range': [_hex(self.left_range[0]), _hex(self.left_range[1])],
            'right_range': [
                _hex(self.right_range[0]), _hex(self.right_range[1])],
            'right_raw_range': [
                _hex(self.right_raw_range[0]),
                _hex(self.right_raw_range[1])],
        }


@dataclass(frozen=True)
class FrameComparison:
    pair: FramePair
    left_file: FrameFileInfo
    right_file: FrameFileInfo
    matched_fdes: tuple[MatchedFDE, ...]
    intervals: tuple[IntervalComparison, ...]
    warnings: tuple[str, ...] = ()

    @property
    def same_intervals(self) -> tuple[IntervalComparison, ...]:
        return self._with_status(ComparisonStatus.SAME)

    @property
    def different_intervals(self) -> tuple[IntervalComparison, ...]:
        return self._with_status(ComparisonStatus.DIFFERENT)

    @property
    def incomparable_intervals(self) -> tuple[IntervalComparison, ...]:
        return self._with_status(ComparisonStatus.INCOMPARABLE)

    @property
    def unmatched_intervals(self) -> tuple[IntervalComparison, ...]:
        return tuple(
            interval for interval in self.intervals
            if interval.status in (
                ComparisonStatus.LEFT_ONLY,
                ComparisonStatus.RIGHT_ONLY))

    @property
    def is_clean(self) -> bool:
        return bool(self.intervals) and all(
            interval.status is ComparisonStatus.SAME
            for interval in self.intervals)

    def _with_status(
        self,
        status: ComparisonStatus,
    ) -> tuple[IntervalComparison, ...]:
        return tuple(
            interval for interval in self.intervals
            if interval.status is status)

    def summary(self) -> dict[str, int]:
        summary = {status.value: 0 for status in ComparisonStatus}
        for interval in self.intervals:
            summary[interval.status.value] += 1
        return summary

    def to_dict(self) -> dict[str, Any]:
        return {
            'schema': 'pyelftools.cfi-compare/v1',
            'read_only': True,
            'pair': {
                'left': self.left_file.to_dict(),
                'right': self.right_file.to_dict(),
                'address_mapping': self.pair.right_to_left.to_dict(),
            },
            'matched_fdes': [
                fde.to_dict() for fde in self.matched_fdes],
            'intervals': [
                interval.to_dict() for interval in self.intervals],
            'warnings': list(self.warnings),
            'summary': self.summary(),
        }


@dataclass(frozen=True)
class _LoadedFDE:
    index: int
    offset: int
    cie_offset: int | None
    raw_start: int
    raw_end: int
    decoded: DecodedCallFrameTable
    source: RuleSource


def _hex(value: int) -> str:
    return f'-0x{-value:x}' if value < 0 else f'0x{value:x}'


def _hex_optional(value: int | None) -> str | None:
    return _hex(value) if value is not None else None


def _source_to_dict(source: RuleSource | None) -> dict[str, Any] | None:
    return source.to_dict() if source is not None else None


def _expression_bytes(expression: Any) -> bytes | None:
    if expression is None:
        return None
    if isinstance(expression, (bytes, bytearray, memoryview)):
        return bytes(expression)
    try:
        return bytes(int(byte) for byte in expression)
    except (TypeError, ValueError):
        return repr(expression).encode('utf-8', 'replace')


def _int_argument(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _normalize_cfa(rule: CFARule | None) -> NormalizedCFARule:
    if rule is None:
        return NormalizedCFARule(
            rule_type='UNSET', offset=0, description='cfa=<unset>')

    if rule.expr is not None:
        expression = _expression_bytes(rule.expr)
        return NormalizedCFARule(
            rule_type='EXPRESSION',
            expression=expression,
            comparable=False,
            description='cfa=expression'
                        + (f'({len(expression)} bytes)' if expression else ''))

    if rule.reg is not None and rule.offset is not None:
        register = _int_argument(rule.reg)
        offset = _int_argument(rule.offset)
        if register is not None and offset is not None:
            return NormalizedCFARule(
                rule_type='REGISTER_OFFSET',
                register=register,
                offset=offset,
                description=f'cfa=r{register}{offset:+d}')

    if rule.reg is None and rule.offset in (None, 0):
        return NormalizedCFARule(
            rule_type='UNSET', offset=0, description='cfa=<unset>')

    return NormalizedCFARule(
        rule_type='UNKNOWN',
        comparable=False,
        description=f'cfa={rule!r}')


def _normalize_register(
    number: int,
    rule: RegisterRule,
) -> NormalizedRegisterRule:
    rule_type = rule.type

    if rule_type == RegisterRule.UNDEFINED:
        return NormalizedRegisterRule(
            number, rule_type, description='undefined')

    if rule_type == RegisterRule.SAME_VALUE:
        return NormalizedRegisterRule(
            number, rule_type, description='same_value')

    if rule_type in (RegisterRule.OFFSET, RegisterRule.VAL_OFFSET):
        offset = _int_argument(rule.arg)
        if offset is not None:
            if rule_type == RegisterRule.OFFSET:
                description = f'cfa{offset:+d}'
            else:
                description = f'value(cfa{offset:+d})'
            return NormalizedRegisterRule(
                number,
                rule_type,
                offset=offset,
                description=description)

    if rule_type == RegisterRule.REGISTER:
        source_register = _int_argument(rule.arg)
        if source_register is not None:
            return NormalizedRegisterRule(
                number,
                rule_type,
                source_register=source_register,
                description=f'r{source_register}')

    if rule_type in (
        RegisterRule.EXPRESSION,
        RegisterRule.VAL_EXPRESSION,
    ):
        expression = _expression_bytes(rule.arg)
        return NormalizedRegisterRule(
            number,
            rule_type,
            expression=expression,
            comparable=False,
            description=rule_type
                        + (f'({len(expression)} bytes)' if expression else ''))

    return NormalizedRegisterRule(
        number,
        rule_type,
        comparable=False,
        description=f'{rule_type}({rule.arg!r})')


def normalize_rule_line(line: Mapping[Any, Any]) -> RuleState:
    """ Convert one pyelftools decoded-table line into comparable rules. """
    cfa = _normalize_cfa(cast(CFARule | None, line.get('cfa')))
    registers = []
    for key, value in line.items():
        if key == 'cfa' or not isinstance(key, int):
            continue
        if isinstance(value, RegisterRule):
            registers.append(_normalize_register(key, value))
    registers.sort(key=lambda rule: rule.register)
    return RuleState(cfa=cfa, registers=tuple(registers))


def _implicit_undefined_register(number: int) -> NormalizedRegisterRule:
    return NormalizedRegisterRule(
        number, RegisterRule.UNDEFINED, description='undefined (implicit)')


def segments_from_decoded_table(
    table: DecodedCallFrameTable | Sequence[Line],
    start: int,
    end: int,
    source: RuleSource | None = None,
) -> tuple[FrameSegment, ...]:
    """ Build rule segments from a decoded pyelftools FDE table.

        Each decoded row is effective from its PC until the next row's PC,
        or until `end` for the final row. Rows outside [start, end) are
        clipped. The returned source objects retain the FDE/section offsets
        and the original table line index.
    """
    if end <= start:
        return ()

    rows = table.table if isinstance(table, DecodedCallFrameTable) else list(table)
    if not rows:
        return ()

    base_source = source or RuleSource()
    segments: list[FrameSegment] = []
    previous_pc: int | None = None

    for index, row in enumerate(rows):
        pc = int(row['pc'])
        if previous_pc is not None and pc < previous_pc:
            raise FrameCompareError(
                'decoded FDE table is not sorted by PC: '
                f'{_hex(pc)} follows {_hex(previous_pc)}')
        previous_pc = pc

        next_pc = int(rows[index + 1]['pc']) if index + 1 < len(rows) else end
        segment_start = max(start, pc)
        segment_end = min(end, next_pc)
        if segment_start >= segment_end:
            continue

        row_source = replace(base_source, line_index=index, pc=pc)
        segments.append(FrameSegment(
            start=segment_start,
            end=segment_end,
            rules=normalize_rule_line(row),
            source=row_source))

    return tuple(segments)


def segments_from_fde(
    fde: FDE,
    *,
    side: str,
    path: str,
    section: str,
    fde_index: int | None = None,
) -> tuple[FrameSegment, ...]:
    """ Build rule segments directly from a parsed pyelftools FDE. """
    start = int(fde['initial_location'])
    end = start + int(fde['address_range'])
    cie_offset = fde.cie.offset if fde.cie is not None else None
    source = RuleSource(
        side=side,
        path=path,
        section=section,
        fde_index=fde_index,
        fde_offset=fde.offset,
        cie_offset=cie_offset)
    return segments_from_decoded_table(
        fde.get_decoded(), start, end, source)


def _cfa_semantics(rule: NormalizedCFARule) -> tuple[Any, ...]:
    return (rule.rule_type, rule.register, rule.offset, rule.expression)


def _register_semantics(
    rule: NormalizedRegisterRule,
) -> tuple[Any, ...]:
    return (
        rule.rule_type,
        rule.offset,
        rule.source_register,
        rule.expression,
    )


def _incomparable(
    side: str,
    field_name: str,
    rule_type: str,
    source: RuleSource,
    expression: bytes | None,
    description: str,
) -> IncomparableRule:
    return IncomparableRule(
        side=side,
        field=field_name,
        rule_type=rule_type,
        source=source,
        expression=expression,
        description=description)


def _compare_rule_states(
    left: RuleState,
    right: RuleState,
    left_source: RuleSource,
    right_source: RuleSource,
) -> tuple[
        ComparisonStatus,
        tuple[RuleDifference, ...],
        tuple[IncomparableRule, ...]]:
    differences: list[RuleDifference] = []
    incomparable: list[IncomparableRule] = []

    if not left.cfa.comparable or not right.cfa.comparable:
        if not left.cfa.comparable:
            incomparable.append(_incomparable(
                'left', 'cfa', left.cfa.rule_type, left_source,
                left.cfa.expression, left.cfa.description))
        if not right.cfa.comparable:
            incomparable.append(_incomparable(
                'right', 'cfa', right.cfa.rule_type, right_source,
                right.cfa.expression, right.cfa.description))
    elif _cfa_semantics(left.cfa) != _cfa_semantics(right.cfa):
        differences.append(RuleDifference(
            field='cfa',
            left=left.cfa.description,
            right=right.cfa.description,
            left_source=left_source,
            right_source=right_source))

    left_registers = {rule.register: rule for rule in left.registers}
    right_registers = {rule.register: rule for rule in right.registers}
    for number in sorted(set(left_registers) | set(right_registers)):
        left_rule = left_registers.get(number) or _implicit_undefined_register(
            number)
        right_rule = (
            right_registers.get(number)
            or _implicit_undefined_register(number))
        field_name = f'r{number}'

        if not left_rule.comparable or not right_rule.comparable:
            if not left_rule.comparable:
                incomparable.append(_incomparable(
                    'left', field_name, left_rule.rule_type, left_source,
                    left_rule.expression, left_rule.description))
            if not right_rule.comparable:
                incomparable.append(_incomparable(
                    'right', field_name, right_rule.rule_type, right_source,
                    right_rule.expression, right_rule.description))
        elif _register_semantics(left_rule) != _register_semantics(right_rule):
            differences.append(RuleDifference(
                field=field_name,
                register=number,
                left=left_rule.description,
                right=right_rule.description,
                left_source=left_source,
                right_source=right_source))

    if differences:
        status = ComparisonStatus.DIFFERENT
    elif incomparable:
        status = ComparisonStatus.INCOMPARABLE
    else:
        status = ComparisonStatus.SAME

    return status, tuple(differences), tuple(incomparable)


def _validate_segments(
    segments: Sequence[FrameSegment],
    label: str,
) -> tuple[FrameSegment, ...]:
    ordered = tuple(sorted(segments, key=lambda segment: segment.start))
    previous: FrameSegment | None = None
    for segment in ordered:
        if previous is not None and segment.start < previous.end:
            raise FrameCompareError(
                f'{label} rule segments overlap: '
                f'0x{previous.start:x}..0x{previous.end:x} and '
                f'0x{segment.start:x}..0x{segment.end:x}')
        previous = segment
    return ordered


def _difference_signature(
    differences: Sequence[RuleDifference],
) -> tuple[tuple[Any, ...], ...]:
    return tuple(
        (difference.field, difference.left, difference.right)
        for difference in differences)


def _incomparable_signature(
    rules: Sequence[IncomparableRule],
) -> tuple[tuple[Any, ...], ...]:
    return tuple(
        (rule.side, rule.field, rule.rule_type, rule.expression,
         rule.description)
        for rule in rules)


def _append_unique(
    current: tuple[Any, ...],
    additions: Sequence[Any],
) -> tuple[Any, ...]:
    seen = set(current)
    result = list(current)
    for item in additions:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return tuple(result)


def _merge_atomic_intervals(
    intervals: Sequence[IntervalComparison],
) -> tuple[IntervalComparison, ...]:
    merged: list[IntervalComparison] = []
    for interval in intervals:
        if merged:
            previous = merged[-1]
            same_verdict = (
                previous.end == interval.start
                and previous.status is interval.status
                and _difference_signature(previous.differences)
                    == _difference_signature(interval.differences)
                and _incomparable_signature(previous.incomparable_rules)
                    == _incomparable_signature(interval.incomparable_rules))
            if same_verdict:
                merged[-1] = IntervalComparison(
                    start=previous.start,
                    end=interval.end,
                    status=interval.status,
                    left_sources=_append_unique(
                        previous.left_sources, interval.left_sources),
                    right_sources=_append_unique(
                        previous.right_sources, interval.right_sources),
                    differences=_append_unique(
                        previous.differences, interval.differences),
                    incomparable_rules=_append_unique(
                        previous.incomparable_rules,
                        interval.incomparable_rules))
                continue
        merged.append(interval)
    return tuple(merged)


def compare_rule_segments(
    left_segments: Sequence[FrameSegment],
    right_segments: Sequence[FrameSegment],
) -> tuple[IntervalComparison, ...]:
    """ Compare two already address-mapped rule tables.

        The result is a minimal list of contiguous half-open intervals with
        one of the ComparisonStatus verdicts. A gap on one side becomes
        LEFT_ONLY/RIGHT_ONLY rather than a false difference.
    """
    left = _validate_segments(left_segments, 'left')
    right = _validate_segments(right_segments, 'right')

    points = sorted({
        segment.start for segment in left + right
    } | {
        segment.end for segment in left + right
    })
    if len(points) < 2:
        return ()

    atomic: list[IntervalComparison] = []
    left_index = 0
    right_index = 0

    for start, end in zip(points, points[1:]):
        if start >= end:
            continue

        while left_index < len(left) and left[left_index].end <= start:
            left_index += 1
        while right_index < len(right) and right[right_index].end <= start:
            right_index += 1

        left_segment = (
            left[left_index]
            if left_index < len(left)
            and left[left_index].start <= start < left[left_index].end
            else None)
        right_segment = (
            right[right_index]
            if right_index < len(right)
            and right[right_index].start <= start < right[right_index].end
            else None)

        if left_segment is None and right_segment is None:
            continue

        if left_segment is not None and right_segment is not None:
            status, differences, incomparable = _compare_rule_states(
                left_segment.rules,
                right_segment.rules,
                left_segment.source,
                right_segment.source)
            atomic.append(IntervalComparison(
                start=start,
                end=end,
                status=status,
                left_sources=(left_segment.source,),
                right_sources=(right_segment.source,),
                differences=differences,
                incomparable_rules=incomparable))
        elif left_segment is not None:
            atomic.append(IntervalComparison(
                start=start,
                end=end,
                status=ComparisonStatus.LEFT_ONLY,
                left_sources=(left_segment.source,)))
        else:
            assert right_segment is not None
            atomic.append(IntervalComparison(
                start=start,
                end=end,
                status=ComparisonStatus.RIGHT_ONLY,
                right_sources=(right_segment.source,)))

    return _merge_atomic_intervals(atomic)


def compare_decoded_tables(
    left: DecodedCallFrameTable | Sequence[Line],
    right: DecodedCallFrameTable | Sequence[Line],
    *,
    start: int,
    end: int,
    left_start: int | None = None,
    left_end: int | None = None,
    right_start: int | None = None,
    right_end: int | None = None,
    left_source: RuleSource | None = None,
    right_source: RuleSource | None = None,
) -> tuple[IntervalComparison, ...]:
    """ Compare short, already-decoded tables (useful for focused tests).

        By default both tables cover [start, end). Callers may override each
        side's range to model one file's FDE ending earlier than the other's.
    """
    left_start = start if left_start is None else left_start
    right_start = start if right_start is None else right_start
    left_end = end if left_end is None else left_end
    right_end = end if right_end is None else right_end

    left_segments = segments_from_decoded_table(
        left,
        left_start,
        left_end,
        left_source or RuleSource(side='left', path='<left table>'))
    right_segments = segments_from_decoded_table(
        right,
        right_start,
        right_end,
        right_source or RuleSource(side='right', path='<right table>'))
    return compare_rule_segments(left_segments, right_segments)


def _coerce_address_map(value: AddressMap | int) -> AddressMap:
    if isinstance(value, AddressMap):
        return value
    if isinstance(value, int):
        return AddressMap(value)
    raise TypeError('right_to_left must be an AddressMap or an integer offset')


def _as_frame_file(
    value: FrameFile | str | os.PathLike[str],
    section: str,
) -> FrameFile:
    if isinstance(value, FrameFile):
        return value
    return FrameFile(value, section)


def _file_sha256(path: str) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with open(path, 'rb') as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
    return digest.hexdigest(), size


def _choose_section(
    requested: str,
    side: str,
    has_eh_frame: bool,
    has_debug_frame: bool,
) -> str:
    if requested == '.eh_frame':
        if not has_eh_frame:
            raise FrameCompareError(
                f'{side} file has no .eh_frame section')
        return requested
    if requested == '.debug_frame':
        if not has_debug_frame:
            raise FrameCompareError(
                f'{side} file has no .debug_frame section')
        return requested

    preferences = (
        ('.eh_frame', '.debug_frame')
        if side == 'left'
        else ('.debug_frame', '.eh_frame'))
    for candidate in preferences:
        if candidate == '.eh_frame' and has_eh_frame:
            return candidate
        if candidate == '.debug_frame' and has_debug_frame:
            return candidate
    raise FrameCompareError(
        f'{side} file has neither .eh_frame nor .debug_frame')


def _load_frame_file(
    source: FrameFile,
    side: str,
) -> tuple[FrameFileInfo, tuple[_LoadedFDE, ...]]:
    path = os.path.abspath(os.fspath(source.path))
    try:
        sha256, file_size = _file_sha256(path)
        with open(path, 'rb') as stream:
            elf = ELFFile(stream)
            dwarf = elf.get_dwarf_info(follow_links=False)
            section = _choose_section(
                source.section,
                side,
                dwarf.has_EH_CFI(),
                dwarf.has_CFI())

            if section == '.eh_frame':
                descriptor = dwarf.eh_frame_sec
                entries = dwarf.EH_CFI_entries()
            else:
                descriptor = dwarf.debug_frame_sec
                entries = dwarf.CFI_entries()
            assert descriptor is not None

            loaded: list[_LoadedFDE] = []
            fde_index = 0
            for entry in entries:
                if not isinstance(entry, FDE):
                    continue
                start = int(entry['initial_location'])
                end = start + int(entry['address_range'])
                if end <= start:
                    continue
                cie_offset = (
                    entry.cie.offset if entry.cie is not None else None)
                loaded.append(_LoadedFDE(
                    index=fde_index,
                    offset=entry.offset,
                    cie_offset=cie_offset,
                    raw_start=start,
                    raw_end=end,
                    decoded=entry.get_decoded(),
                    source=RuleSource(
                        side=side,
                        path=path,
                        section=section,
                        fde_index=fde_index,
                        fde_offset=entry.offset,
                        cie_offset=cie_offset)))
                fde_index += 1

            info = FrameFileInfo(
                path=path,
                section=section,
                section_address=int(descriptor.address),
                section_size=int(descriptor.size),
                file_size=file_size,
                sha256=sha256,
                elf_class=elf.elfclass,
                little_endian=elf.little_endian,
                machine=elf.get_machine_arch())

    except FrameCompareError:
        raise
    except (ELFError, DWARFError, OSError) as error:
        raise FrameCompareError(
            f'cannot read {side} CFI from {path}: {error}') from error

    return info, tuple(loaded)


def _index_by_start(
    fdes: Sequence[_LoadedFDE],
    address_map: AddressMap,
    side: str,
) -> dict[int, tuple[_LoadedFDE, int, int]]:
    indexed: dict[int, tuple[_LoadedFDE, int, int]] = {}
    for fde in fdes:
        start, end = address_map.map_range(fde.raw_start, fde.raw_end)
        if start in indexed:
            other = indexed[start][0]
            raise FrameCompareError(
                f'{side} has more than one FDE starting at {_hex(start)} '
                f'(offsets {_hex(other.offset)} and {_hex(fde.offset)}); '
                'the pairing is ambiguous')
        indexed[start] = (fde, start, end)
    return indexed


def _map_segments(
    segments: Sequence[FrameSegment],
    address_map: AddressMap,
) -> tuple[FrameSegment, ...]:
    return tuple(
        replace(
            segment,
            start=address_map.map_address(segment.start),
            end=address_map.map_address(segment.end))
        for segment in segments)


def _one_sided_intervals(
    segments: Sequence[FrameSegment],
    status: ComparisonStatus,
) -> tuple[IntervalComparison, ...]:
    if status is ComparisonStatus.LEFT_ONLY:
        intervals = (
            IntervalComparison(
                start=segment.start,
                end=segment.end,
                status=status,
                left_sources=(segment.source,))
            for segment in segments)
    else:
        intervals = (
            IntervalComparison(
                start=segment.start,
                end=segment.end,
                status=status,
                right_sources=(segment.source,))
            for segment in segments)
    return _merge_atomic_intervals(tuple(intervals))


def compare_frame_files(
    pair: FramePair | FrameFile | str | os.PathLike[str],
    right: FrameFile | str | os.PathLike[str] | None = None,
    *,
    left_section: str = 'auto',
    right_section: str = 'auto',
    right_to_left: AddressMap | int = 0,
) -> FrameComparison:
    """ Compare CFI from an explicit file pair.

        The preferred form is `compare_frame_files(FramePair(...))`. For
        convenience, `compare_frame_files(left_path, right_path,
        right_to_left=offset)` is also accepted.

        The function only opens inputs for reading. It pairs FDEs whose
        mapped initial locations are equal, then compares the register and
        CFA rules over each interval. Complex DWARF expressions are never
        declared equal: such intervals are INCOMPARABLE and retain the raw
        expression bytes plus FDE/line provenance.
    """
    if isinstance(pair, FramePair):
        if right is not None:
            raise TypeError(
                'do not pass a second file when a FramePair is supplied')
        if _coerce_address_map(right_to_left).offset != 0:
            raise TypeError(
                'set the address map on FramePair.right_to_left')
        frame_pair = pair
    else:
        if right is None:
            raise TypeError('right file is required when left is not a pair')
        frame_pair = FramePair(
            left=_as_frame_file(pair, left_section),
            right=_as_frame_file(right, right_section),
            right_to_left=_coerce_address_map(right_to_left))

    left_info, left_fdes = _load_frame_file(frame_pair.left, 'left')
    right_info, right_fdes = _load_frame_file(frame_pair.right, 'right')

    identity = AddressMap()
    left_by_start = _index_by_start(left_fdes, identity, 'left')
    right_by_start = _index_by_start(
        right_fdes, frame_pair.right_to_left, 'right')

    intervals: list[IntervalComparison] = []
    matched: list[MatchedFDE] = []
    warnings: list[str] = []

    for start in sorted(set(left_by_start) | set(right_by_start)):
        left_entry = left_by_start.get(start)
        right_entry = right_by_start.get(start)

        if left_entry is not None and right_entry is not None:
            left_fde, left_start, left_end = left_entry
            right_fde, right_start, right_end = right_entry
            left_segments = segments_from_decoded_table(
                left_fde.decoded,
                left_start,
                left_end,
                left_fde.source)
            right_segments = _map_segments(
                segments_from_decoded_table(
                    right_fde.decoded,
                    right_fde.raw_start,
                    right_fde.raw_end,
                    right_fde.source),
                frame_pair.right_to_left)
            intervals.extend(
                compare_rule_segments(left_segments, right_segments))
            matched.append(MatchedFDE(
                start=start,
                left_source=left_fde.source,
                right_source=right_fde.source,
                left_range=(left_start, left_end),
                right_range=(right_start, right_end),
                right_raw_range=(
                    right_fde.raw_start, right_fde.raw_end)))

        elif left_entry is not None:
            left_fde, left_start, left_end = left_entry
            left_segments = segments_from_decoded_table(
                left_fde.decoded,
                left_start,
                left_end,
                left_fde.source)
            intervals.extend(_one_sided_intervals(
                left_segments, ComparisonStatus.LEFT_ONLY))
            warnings.append(
                f'left FDE at {_hex(start)} has no same-start right FDE')

        else:
            assert right_entry is not None
            right_fde, right_start, right_end = right_entry
            right_segments = _map_segments(
                segments_from_decoded_table(
                    right_fde.decoded,
                    right_fde.raw_start,
                    right_fde.raw_end,
                    right_fde.source),
                frame_pair.right_to_left)
            intervals.extend(_one_sided_intervals(
                right_segments, ComparisonStatus.RIGHT_ONLY))
            warnings.append(
                f'right FDE at {_hex(start)} has no same-start left FDE')

    intervals.sort(key=lambda interval: (interval.start, interval.end))

    return FrameComparison(
        pair=frame_pair,
        left_file=left_info,
        right_file=right_info,
        matched_fdes=tuple(matched),
        intervals=tuple(intervals),
        warnings=tuple(warnings))


__all__ = [
    'AddressMap',
    'ComparisonStatus',
    'FrameCompareError',
    'FrameComparison',
    'FrameFile',
    'FrameFileInfo',
    'FramePair',
    'FrameSegment',
    'IncomparableRule',
    'IntervalComparison',
    'MatchedFDE',
    'NormalizedCFARule',
    'NormalizedRegisterRule',
    'RuleDifference',
    'RuleSource',
    'RuleState',
    'compare_decoded_tables',
    'compare_frame_files',
    'compare_rule_segments',
    'normalize_rule_line',
    'segments_from_decoded_table',
    'segments_from_fde',
]
