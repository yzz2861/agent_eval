#-------------------------------------------------------------------------------
# elftools: dwarf/dwarf_expr.py
#
# Decoding DWARF expressions
#
# Eli Bendersky (eliben@gmail.com)
# This code is in the public domain
#-------------------------------------------------------------------------------
from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
from typing import IO, TYPE_CHECKING, Any, NamedTuple

from ..common.exceptions import DWARFError
from ..common.utils import struct_parse

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Mapping

    from ..construct.core import Construct
    from .structs import DWARFStructs


# DWARF expression opcodes. name -> opcode mapping
DW_OP_name2opcode: Mapping[str, int] = dict(
    DW_OP_addr=0x03,
    DW_OP_deref=0x06,
    DW_OP_const1u=0x08,
    DW_OP_const1s=0x09,
    DW_OP_const2u=0x0a,
    DW_OP_const2s=0x0b,
    DW_OP_const4u=0x0c,
    DW_OP_const4s=0x0d,
    DW_OP_const8u=0x0e,
    DW_OP_const8s=0x0f,
    DW_OP_constu=0x10,
    DW_OP_consts=0x11,
    DW_OP_dup=0x12,
    DW_OP_drop=0x13,
    DW_OP_over=0x14,
    DW_OP_pick=0x15,
    DW_OP_swap=0x16,
    DW_OP_rot=0x17,
    DW_OP_xderef=0x18,
    DW_OP_abs=0x19,
    DW_OP_and=0x1a,
    DW_OP_div=0x1b,
    DW_OP_minus=0x1c,
    DW_OP_mod=0x1d,
    DW_OP_mul=0x1e,
    DW_OP_neg=0x1f,
    DW_OP_not=0x20,
    DW_OP_or=0x21,
    DW_OP_plus=0x22,
    DW_OP_plus_uconst=0x23,
    DW_OP_shl=0x24,
    DW_OP_shr=0x25,
    DW_OP_shra=0x26,
    DW_OP_xor=0x27,
    DW_OP_bra=0x28,
    DW_OP_eq=0x29,
    DW_OP_ge=0x2a,
    DW_OP_gt=0x2b,
    DW_OP_le=0x2c,
    DW_OP_lt=0x2d,
    DW_OP_ne=0x2e,
    DW_OP_skip=0x2f,
    DW_OP_regx=0x90,
    DW_OP_fbreg=0x91,
    DW_OP_bregx=0x92,
    DW_OP_piece=0x93,
    DW_OP_deref_size=0x94,
    DW_OP_xderef_size=0x95,
    DW_OP_nop=0x96,
    DW_OP_push_object_address=0x97,
    DW_OP_call2=0x98,
    DW_OP_call4=0x99,
    DW_OP_call_ref=0x9a,
    DW_OP_form_tls_address=0x9b,
    DW_OP_call_frame_cfa=0x9c,
    DW_OP_bit_piece=0x9d,
    DW_OP_implicit_value=0x9e,
    DW_OP_stack_value=0x9f,
    DW_OP_implicit_pointer=0xa0,
    DW_OP_addrx=0xa1,
    DW_OP_constx=0xa2,
    DW_OP_entry_value=0xa3,
    DW_OP_const_type=0xa4,
    DW_OP_regval_type=0xa5,
    DW_OP_deref_type=0xa6,
    DW_OP_xderef_type=0xa7,
    DW_OP_convert=0xa8,
    DW_OP_reinterpret=0xa9,
    DW_OP_lo_user=0xe0,
    DW_OP_GNU_push_tls_address=0xe0,
    DW_OP_WASM_location=0xed,
    DW_OP_GNU_uninit=0xf0,
    DW_OP_GNU_implicit_pointer=0xf2,
    DW_OP_GNU_entry_value=0xf3,
    DW_OP_GNU_const_type=0xf4,
    DW_OP_GNU_regval_type=0xf5,
    DW_OP_GNU_deref_type=0xf6,
    DW_OP_GNU_convert=0xf7,
    DW_OP_GNU_parameter_ref=0xfa,
    DW_OP_GNU_addr_index=0xfb,
    DW_OP_GNU_const_index=0xfc,
    DW_OP_GNU_variable_value=0xfd,
    DW_OP_hi_user=0xff,
    **{f"DW_OP_lit{val}": 0x30 + val for val in range(32)},
    **{f"DW_OP_reg{val}": 0x50 + val for val in range(32)},
    **{f"DW_OP_breg{val}": 0x70 + val for val in range(32)},
)

# opcode -> name mapping
DW_OP_opcode2name: Mapping[int, str] = {v: k for k, v in DW_OP_name2opcode.items()}


# Sentinel for "no explicit budget argument was passed to parse_expr".
_BUDGET_UNSET: Any = object()


@dataclass(frozen=True)
class ExprBudget:
    """Configurable resource limits for parsing a DWARF expression.

    Every limit is optional; a ``None`` value (the default for all fields)
    disables the corresponding check. A parser without a budget therefore
    behaves exactly like the historical byte-sequential parser. When a budget
    is active, limits apply to the whole expression tree, including nested
    ``DW_OP_entry_value`` / ``DW_OP_GNU_entry_value`` sub-expressions.

    max_opcodes: maximum number of opcodes decoded across the expression and
        any nested expressions. It also bounds the number of abstract
        execution steps, so a control-flow loop cannot run unbounded.
    max_stack_depth: maximum number of entries the virtual stack may hold on
        any reachable control-flow path. The depth is tracked as a plain
        integer; the virtual stack itself is never materialized.
    max_branch_offset: maximum absolute signed displacement accepted for
        DW_OP_bra / DW_OP_skip. Independently of this value, a jump must
        always land on an opcode boundary inside the current expression.
    max_entry_value_depth: maximum nesting depth of entry_value expressions.
    max_implicit_value_length: maximum length, in bytes, of an implicit value
        or typed value block. The declared length is checked before the block
        is read or allocated.
    """

    max_opcodes: int | None = None
    max_stack_depth: int | None = None
    max_branch_offset: int | None = None
    max_entry_value_depth: int | None = None
    max_implicit_value_length: int | None = None

    def __post_init__(self) -> None:
        for field_name in (
            'max_opcodes',
            'max_stack_depth',
            'max_branch_offset',
            'max_entry_value_depth',
            'max_implicit_value_length',
        ):
            value = getattr(self, field_name)
            if value is not None and value < 0:
                raise ValueError(f'{field_name} must be non-negative, got {value}')

    @property
    def enabled(self) -> bool:
        return any(
            getattr(self, field_name) is not None
            for field_name in (
                'max_opcodes',
                'max_stack_depth',
                'max_branch_offset',
                'max_entry_value_depth',
                'max_implicit_value_length',
            )
        )

    @classmethod
    def default(cls) -> ExprBudget:
        """A conservative, ready-to-use budget for parsing untrusted input."""
        return cls(
            max_opcodes=10_000,
            max_stack_depth=1024,
            max_branch_offset=None,
            max_entry_value_depth=64,
            max_implicit_value_length=1 << 20,
        )


class DWARFExprLimitError(DWARFError):
    """Raised when an expression exceeds a configured :class:`ExprBudget`.

    Attributes:
        dimension: name of the exhausted budget dimension.
        limit: the configured limit that was exceeded (may be ``None`` for
            bounds that do not map to a numeric budget, such as an
            out-of-range branch target).
        offset: byte offset of the offending opcode within the expression
            blob.
        opcode: numeric opcode being processed; 0 when the failure is caused
            by a length-prefixed argument rather than an opcode itself.
    """

    def __init__(
        self,
        dimension: str,
        limit: int | None,
        offset: int,
        opcode: int = 0,
    ) -> None:
        self.dimension = dimension
        self.limit = limit
        self.offset = offset
        self.opcode = opcode
        if opcode:
            op_name = DW_OP_opcode2name.get(opcode, f'OP:0x{opcode:x}')
            message = (
                f'DWARF expression exceeded {dimension} limit {limit} at '
                f'offset {offset} (opcode {op_name}, 0x{opcode:02x})')
        else:
            message = (
                f'DWARF expression exceeded {dimension} limit {limit} at '
                f'offset {offset}')
        super().__init__(message)


# Each parsed DWARF expression is returned as this type with its numeric opcode,
# op name (as a string) and a list of arguments.
class DWARFExprOp(NamedTuple):
    op: int
    op_name: str
    args: list[Any]
    offset: int


class DWARFExprParser:
    """DWARF expression parser.

    When initialized, requires structs to cache a dispatch table. After that,
    parse_expr can be called repeatedly. A parser created without a budget is
    stateless and reproduces the historical parser byte for byte; a parser
    created with an :class:`ExprBudget` enforces the configured resource
    limits while parsing.
    """

    def __init__(
        self,
        structs: DWARFStructs,
        budget: ExprBudget | None = None,
    ) -> None:
        self._dispatch_table = _init_dispatch_table(structs)
        self._budget = budget

    def parse_expr(
        self,
        expr: bytes | Iterable[int],
        budget: ExprBudget | object = _BUDGET_UNSET,
    ) -> list[DWARFExprOp]:
        """ Parses expr (bytes or a list of integers) into a list of DWARFExprOp.

        The list can potentially be nested.

        ``budget`` optionally overrides the parser's budget for this call.
        When no budget is in effect the parser keeps its historical behavior,
        including the way unknown opcodes are represented. With a budget, the
        parser tracks the virtual stack, validates jump targets and nested
        entry_value depth and raises :class:`DWARFExprLimitError` with the
        offending expression offset, opcode and exhausted dimension instead
        of exhausting memory or recursion.
        """
        if budget is _BUDGET_UNSET:
            budget = self._budget
        state = _ParseState(budget)  # type: ignore[arg-type]
        return self._parse_expr(bytes(expr), state)

    def _parse_expr(
        self,
        expr: bytes,
        state: _ParseState,
        entry_value_depth: int = 0,
    ) -> list[DWARFExprOp]:
        budget = state.budget
        stream = BytesIO(bytes(expr))
        parsed: list[DWARFExprOp] = []
        expr_length = len(expr)
        branch_offsets: list[int] = []
        linear_depth = 0

        while True:
            # Get the next opcode from the stream. If nothing is left in the
            # stream, we're done.
            offset = stream.tell()
            byte = stream.read(1)
            if not byte:
                break

            # Decode the opcode and its name.
            op = ord(byte)
            op_name = DW_OP_opcode2name.get(op, f'OP:0x{op:x}')

            if budget is not None:
                # Total decoded opcodes across the whole expression tree, so
                # nested entry_value expressions cannot bypass the budget.
                state.total_opcodes += 1
                if (budget.max_opcodes is not None
                        and state.total_opcodes > budget.max_opcodes):
                    raise DWARFExprLimitError(
                        'opcodes', budget.max_opcodes, offset, op)

                arg_parser = self._dispatch_table.get(op)
                if arg_parser is None:
                    # The argument layout of an unknown opcode cannot be
                    # decoded, so represent it opaquely and stop rather than
                    # desynchronizing the stream.
                    parsed.append(DWARFExprOp(
                        op=op, op_name=op_name, args=[], offset=offset))
                    break
            else:
                # Historical behavior: a missing dispatch entry raises
                # KeyError exactly as before.
                arg_parser = self._dispatch_table[op]

            # Use dispatch table to parse args.
            context = _ParseContext(
                stream=stream,
                state=state,
                budget=budget,
                parser=self,
                opcode_offset=offset,
                opcode=op,
                entry_value_depth=entry_value_depth,
            )
            args = arg_parser(stream, context)

            parsed.append(DWARFExprOp(op=op, op_name=op_name, args=args, offset=offset))
            if budget is not None and op in (
                    DW_OP_name2opcode['DW_OP_bra'],
                    DW_OP_name2opcode['DW_OP_skip']):
                branch_offsets.append(offset)

            if budget is not None and not branch_offsets:
                # Fast path for straight-line code: track the stack depth as
                # we decode so a pathological dup/pick chain fails without
                # buffering the whole expression first. Branchy expressions
                # are validated precisely by _validate_control_flow.
                linear_depth += _STACK_EFFECT.get(op, 0)
                if (budget.max_stack_depth is not None
                        and linear_depth > budget.max_stack_depth):
                    raise DWARFExprLimitError(
                        'stack_depth',
                        budget.max_stack_depth,
                        offset,
                        op)
                if linear_depth < 0:
                    raise DWARFError(
                        f'DWARF expression underflows the virtual stack at '
                        f'offset {offset} (opcode {op_name})')

        if budget is not None:
            _validate_control_flow(parsed, expr_length, budget)

        return parsed


class _ParseState:
    """Shared, mutable resource counters across a whole expression tree."""

    def __init__(self, budget: ExprBudget | None) -> None:
        self.budget = budget
        self.total_opcodes = 0


class _ParseContext:
    """Everything an argument parser needs beyond the raw byte stream."""

    def __init__(
        self,
        stream: IO[bytes],
        state: _ParseState,
        budget: ExprBudget | None,
        parser: DWARFExprParser,
        opcode_offset: int,
        opcode: int,
        entry_value_depth: int,
    ) -> None:
        self.stream = stream
        self.state = state
        self.budget = budget
        self.parser = parser
        self.opcode_offset = opcode_offset
        self.opcode = opcode
        self.entry_value_depth = entry_value_depth


# Net effect of an opcode on the number of virtual stack entries. Entries
# only need to cover opcodes with a non-zero effect; everything else
# (including piece/bit_piece and all unknown opcodes) is treated as neutral.
_STACK_EFFECT: dict[int, int] = {}
for _push_op in (
    'DW_OP_addr', 'DW_OP_addrx', 'DW_OP_const1u', 'DW_OP_const1s',
    'DW_OP_const2u', 'DW_OP_const2s', 'DW_OP_const4u', 'DW_OP_const4s',
    'DW_OP_const8u', 'DW_OP_const8s', 'DW_OP_constu', 'DW_OP_consts',
    'DW_OP_dup', 'DW_OP_over', 'DW_OP_pick', 'DW_OP_deref',
    'DW_OP_xderef', 'DW_OP_abs',
    'DW_OP_neg', 'DW_OP_not', 'DW_OP_plus_uconst', 'DW_OP_deref_size',
    'DW_OP_xderef_size', 'DW_OP_push_object_address',
    'DW_OP_form_tls_address', 'DW_OP_call_frame_cfa', 'DW_OP_regx',
    'DW_OP_bregx', 'DW_OP_fbreg', 'DW_OP_constx', 'DW_OP_entry_value',
    'DW_OP_deref_type', 'DW_OP_xderef_type', 'DW_OP_const_type',
    'DW_OP_regval_type', 'DW_OP_GNU_push_tls_address',
    'DW_OP_GNU_entry_value', 'DW_OP_GNU_deref_type',
    'DW_OP_GNU_const_type', 'DW_OP_GNU_regval_type',
    'DW_OP_GNU_addr_index', 'DW_OP_GNU_const_index',
    'DW_OP_GNU_variable_value', 'DW_OP_WASM_location',
):
    _STACK_EFFECT[DW_OP_name2opcode[_push_op]] = 1
for _n in range(32):
    _STACK_EFFECT[DW_OP_name2opcode[f'DW_OP_lit{_n}']] = 1
    _STACK_EFFECT[DW_OP_name2opcode[f'DW_OP_reg{_n}']] = 1
    _STACK_EFFECT[DW_OP_name2opcode[f'DW_OP_breg{_n}']] = 1
for _pop2_op in (
    'DW_OP_and', 'DW_OP_div', 'DW_OP_minus', 'DW_OP_mod', 'DW_OP_mul',
    'DW_OP_or', 'DW_OP_plus', 'DW_OP_shl', 'DW_OP_shr', 'DW_OP_shra',
    'DW_OP_xor', 'DW_OP_eq', 'DW_OP_ge', 'DW_OP_gt', 'DW_OP_le', 'DW_OP_lt',
    'DW_OP_ne',
):
    _STACK_EFFECT[DW_OP_name2opcode[_pop2_op]] = -2
for _pop1_op in ('DW_OP_drop', 'DW_OP_swap', 'DW_OP_rot'):
    # swap/rot are stack-preserving; they only need entries to exist, so
    # represent them as consuming one entry for underflow purposes.
    effect = 0 if _pop1_op in ('DW_OP_swap', 'DW_OP_rot') else -1
    _STACK_EFFECT[DW_OP_name2opcode[_pop1_op]] = effect


def _validate_control_flow(
    parsed: list[DWARFExprOp],
    expr_length: int,
    budget: ExprBudget,
) -> None:
    """Validate jump targets and bound the virtual stack over all paths.

    The virtual stack is modeled with a single integer depth rather than a
    materialized list, so an expression pushing hundreds of thousands of
    entries costs constant memory. An abstract walk over the expression's
    control-flow graph reaches every path reachable through DW_OP_bra /
    DW_OP_skip; the number of abstract steps is bounded by the opcode budget,
    which guarantees termination even in the presence of loops.
    """
    boundary_offsets = {expr_op.offset for expr_op in parsed}
    index_at_offset = {
        expr_op.offset: index for index, expr_op in enumerate(parsed)}

    # First pass: every jump must land on an opcode boundary inside this
    # expression and honor the optional displacement budget.
    for expr_op in parsed:
        if expr_op.op not in (
                DW_OP_name2opcode['DW_OP_bra'],
                DW_OP_name2opcode['DW_OP_skip']):
            continue
        displacement = int(expr_op.args[0])
        if (budget.max_branch_offset is not None
                and abs(displacement) > budget.max_branch_offset):
            raise DWARFExprLimitError(
                'branch_offset',
                budget.max_branch_offset,
                expr_op.offset,
                expr_op.op)
        target = expr_op.offset + 2 + displacement
        if not 0 <= target < expr_length or target not in boundary_offsets:
            raise DWARFExprLimitError(
                'branch_target', None, expr_op.offset, expr_op.op)

    max_depth = budget.max_stack_depth
    # Each opcode is visited at most once per distinct incoming depth; both
    # are bounded, and the opcode budget caps the number of abstract steps.
    # With no depth limit the state space is bounded by the opcode count,
    # which still guarantees termination for any loop.
    if budget.max_opcodes is not None:
        step_budget = budget.max_opcodes
    elif max_depth is not None:
        step_budget = len(parsed) * (max_depth + 1)
    else:
        # No numeric cap was configured; the walk still terminates because a
        # single depth can only be seen once per opcode. Use a generous guard.
        step_budget = len(parsed) * (len(parsed) + 1)
    steps = 0
    seen: set[tuple[int, int]] = set()
    work: list[tuple[int, int]] = [(0, 0)]

    while work:
        index, depth = work.pop()
        state_key = (index, depth)
        if state_key in seen:
            continue
        seen.add(state_key)
        steps += 1
        if steps > step_budget:
            offending = parsed[index] if index < len(parsed) else parsed[-1]
            raise DWARFExprLimitError(
                'steps', step_budget, offending.offset, offending.op)

        expr_op = parsed[index]
        effect = _STACK_EFFECT.get(expr_op.op, 0)
        depth += effect
        if depth < 0:
            raise DWARFError(
                f'DWARF expression underflows the virtual stack at offset '
                f'{expr_op.offset} (opcode {expr_op.op_name})')
        if max_depth is not None and depth > max_depth:
            raise DWARFExprLimitError(
                'stack_depth', max_depth, expr_op.offset, expr_op.op)

        if expr_op.op in (
                DW_OP_name2opcode['DW_OP_bra'],
                DW_OP_name2opcode['DW_OP_skip']):
            displacement = int(expr_op.args[0])
            target = expr_op.offset + 2 + displacement
            target_index = index_at_offset[target]
            work.append((target_index, depth))
            if expr_op.op == DW_OP_name2opcode['DW_OP_skip']:
                continue
        if index + 1 < len(parsed):
            work.append((index + 1, depth))


def _init_dispatch_table(
    structs: DWARFStructs,
) -> dict[int, Callable[[IO[bytes], _ParseContext], list[Any]]]:
    """Creates a dispatch table for parsing args of an op.

    Returns a dict mapping opcode to a function. The function accepts a stream
    and parse context and returns a list of parsed arguments for the opcode
    from the stream; the stream is advanced by the function as needed.
    """
    table: dict[int, Callable[[IO[bytes], _ParseContext], list[Any]]] = {}
    def add(
        opcode_name: str,
        func: Callable[[IO[bytes], _ParseContext], list[Any]],
    ) -> None:
        table[DW_OP_name2opcode[opcode_name]] = func

    def parse_noargs() -> Callable[[IO[bytes], _ParseContext], list[None]]:
        return lambda stream, context: []

    def parse_op_addr() -> Callable[[IO[bytes], _ParseContext], list[int]]:
        return lambda stream, context: [
            struct_parse(structs.the_Dwarf_target_addr, stream)]

    def parse_arg_struct(
        arg_struct: Construct,
    ) -> Callable[[IO[bytes], _ParseContext], list[Any]]:
        return lambda stream, context: [struct_parse(arg_struct, stream)]

    def parse_arg_struct2(
        arg1_struct: Construct,
        arg2_struct: Construct,
    ) -> Callable[[IO[bytes], _ParseContext], list[Any]]:
        return lambda stream, context: [struct_parse(arg1_struct, stream),
                                        struct_parse(arg2_struct, stream)]

    # ULEB128, then an expression of that length
    def parse_nestedexpr() -> (
        Callable[[IO[bytes], _ParseContext], list[list[DWARFExprOp]]]):

        def parse(
            stream: IO[bytes], context: _ParseContext
        ) -> list[list[DWARFExprOp]]:
            size: int = struct_parse(structs.the_Dwarf_uleb128, stream)
            nested_expr_blob = stream.read(size)
            nested_depth = context.entry_value_depth + 1
            budget = context.budget
            if (budget is not None
                    and budget.max_entry_value_depth is not None
                    and nested_depth > budget.max_entry_value_depth):
                raise DWARFExprLimitError(
                    'entry_value_depth',
                    budget.max_entry_value_depth,
                    context.opcode_offset,
                    context.opcode)
            return [context.parser._parse_expr(
                nested_expr_blob,
                context.state,
                entry_value_depth=nested_depth)]
        return parse

    # ULEB128, then a blob of that size
    def parse_blob() -> Callable[[IO[bytes], _ParseContext], list[list[int]]]:
        def parse(stream: IO[bytes], context: _ParseContext) -> list[list[int]]:
            size = struct_parse(structs.the_Dwarf_uleb128, stream)
            budget = context.budget
            if (budget is not None
                    and budget.max_implicit_value_length is not None
                    and size > budget.max_implicit_value_length):
                # Fail before the block is read or materialized.
                raise DWARFExprLimitError(
                    'implicit_value_length',
                    budget.max_implicit_value_length,
                    context.opcode_offset)
            return [list(stream.read(size))]
        return parse

    # ULEB128 with datatype DIE offset, then byte, then a blob of that size
    def parse_typedblob() -> (
        Callable[[IO[bytes], _ParseContext], list[int | list[int]]]):
        def parse(
            stream: IO[bytes], context: _ParseContext
        ) -> list[int | list[int]]:
            type_offset = struct_parse(structs.the_Dwarf_uleb128, stream)
            size = struct_parse(structs.the_Dwarf_uint8, stream)
            budget = context.budget
            if (budget is not None
                    and budget.max_implicit_value_length is not None
                    and size > budget.max_implicit_value_length):
                raise DWARFExprLimitError(
                    'implicit_value_length',
                    budget.max_implicit_value_length,
                    context.opcode_offset)
            return [type_offset, list(stream.read(size))]
        return parse

    # https://yurydelendik.github.io/webassembly-dwarf/
    # Byte, then variant: 0, 1, 2 => uleb128, 3 => uint32
    def parse_wasmloc() -> Callable[[IO[bytes], _ParseContext], list[int]]:

        def parse(stream: IO[bytes], context: _ParseContext) -> list[int]:
            op: int = struct_parse(structs.the_Dwarf_uint8, stream)
            if 0 <= op <= 2:
                return [op, struct_parse(structs.the_Dwarf_uleb128, stream)]
            elif op == 3:
                return [op, struct_parse(structs.the_Dwarf_uint32, stream)]
            else:
                raise DWARFError(
                    f"Unknown operation code in DW_OP_WASM_location: {int(op)}")
        return parse

    add('DW_OP_addr', parse_op_addr())
    add('DW_OP_addrx', parse_arg_struct(structs.the_Dwarf_uleb128))
    add('DW_OP_const1u', parse_arg_struct(structs.the_Dwarf_uint8))
    add('DW_OP_const1s', parse_arg_struct(structs.Dwarf_int8('')))
    add('DW_OP_const2u', parse_arg_struct(structs.the_Dwarf_uint16))
    add('DW_OP_const2s', parse_arg_struct(structs.Dwarf_int16('')))
    add('DW_OP_const4u', parse_arg_struct(structs.the_Dwarf_uint32))
    add('DW_OP_const4s', parse_arg_struct(structs.Dwarf_int32('')))
    add('DW_OP_const8u', parse_arg_struct(structs.Dwarf_uint64('')))
    add('DW_OP_const8s', parse_arg_struct(structs.Dwarf_int64('')))
    add('DW_OP_constu', parse_arg_struct(structs.the_Dwarf_uleb128))
    add('DW_OP_consts', parse_arg_struct(structs.the_Dwarf_sleb128))
    add('DW_OP_pick', parse_arg_struct(structs.the_Dwarf_uint8))
    add('DW_OP_plus_uconst', parse_arg_struct(structs.the_Dwarf_uleb128))
    add('DW_OP_bra', parse_arg_struct(structs.Dwarf_int16('')))
    add('DW_OP_skip', parse_arg_struct(structs.Dwarf_int16('')))

    for opname in [ 'DW_OP_deref', 'DW_OP_dup', 'DW_OP_drop', 'DW_OP_over',
                    'DW_OP_swap', 'DW_OP_swap', 'DW_OP_rot', 'DW_OP_xderef',
                    'DW_OP_abs', 'DW_OP_and', 'DW_OP_div', 'DW_OP_minus',
                    'DW_OP_mod', 'DW_OP_mul', 'DW_OP_neg', 'DW_OP_not',
                    'DW_OP_or', 'DW_OP_plus', 'DW_OP_shl', 'DW_OP_shr',
                    'DW_OP_shra', 'DW_OP_xor', 'DW_OP_eq', 'DW_OP_ge',
                    'DW_OP_gt', 'DW_OP_le', 'DW_OP_lt', 'DW_OP_ne', 'DW_OP_nop',
                    'DW_OP_push_object_address', 'DW_OP_form_tls_address',
                    'DW_OP_call_frame_cfa', 'DW_OP_stack_value',
                    'DW_OP_GNU_push_tls_address', 'DW_OP_GNU_uninit']:
        add(opname, parse_noargs())

    for n in range(32):
        add(f'DW_OP_lit{n}', parse_noargs())
        add(f'DW_OP_reg{n}', parse_noargs())
        add(f'DW_OP_breg{n}', parse_arg_struct(structs.the_Dwarf_sleb128))

    for opname in [ 'DW_OP_regx', 'DW_OP_piece', 'DW_OP_convert', 'DW_OP_GNU_convert',
                    'DW_OP_GNU_addr_index', 'DW_OP_GNU_const_index', 'DW_OP_GNU_variable_value']:
        add(opname, parse_arg_struct(structs.the_Dwarf_uleb128))

    add('DW_OP_fbreg', parse_arg_struct(structs.the_Dwarf_sleb128))
    add('DW_OP_bregx', parse_arg_struct2(structs.the_Dwarf_uleb128,
                                         structs.the_Dwarf_sleb128))
    add('DW_OP_bit_piece', parse_arg_struct2(structs.the_Dwarf_uleb128,
                                             structs.the_Dwarf_uleb128))
    add('DW_OP_deref_size', parse_arg_struct(structs.Dwarf_int8('')))
    add('DW_OP_xderef_size', parse_arg_struct(structs.Dwarf_int8('')))
    add('DW_OP_call2', parse_arg_struct(structs.the_Dwarf_uint16))
    add('DW_OP_call4', parse_arg_struct(structs.the_Dwarf_uint32))
    add('DW_OP_call_ref', parse_arg_struct(structs.the_Dwarf_offset))
    add('DW_OP_implicit_value', parse_blob())
    add('DW_OP_entry_value', parse_nestedexpr())
    add('DW_OP_const_type', parse_typedblob())
    add('DW_OP_regval_type', parse_arg_struct2(structs.the_Dwarf_uleb128,
                                                   structs.the_Dwarf_uleb128))
    add('DW_OP_deref_type', parse_arg_struct2(structs.the_Dwarf_uint8,
                                              structs.the_Dwarf_uleb128))
    add('DW_OP_implicit_pointer', parse_arg_struct2(structs.the_Dwarf_offset,
                                                        structs.the_Dwarf_sleb128))
    add('DW_OP_GNU_entry_value', parse_nestedexpr())
    add('DW_OP_GNU_const_type', parse_typedblob())
    add('DW_OP_GNU_regval_type', parse_arg_struct2(structs.the_Dwarf_uleb128,
                                                   structs.the_Dwarf_uleb128))
    add('DW_OP_GNU_deref_type', parse_arg_struct2(structs.the_Dwarf_uint8,
                                                   structs.the_Dwarf_uleb128))
    add('DW_OP_GNU_implicit_pointer', parse_arg_struct2(structs.the_Dwarf_offset,
                                                        structs.the_Dwarf_sleb128))
    add('DW_OP_GNU_parameter_ref', parse_arg_struct(structs.the_Dwarf_offset))
    add('DW_OP_WASM_location', parse_wasmloc())

    return table
