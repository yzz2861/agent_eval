#-------------------------------------------------------------------------------
# elftools tests
#
# Eli Bendersky (eliben@gmail.com)
# This code is in the public domain
#-------------------------------------------------------------------------------
import unittest

from elftools.dwarf.descriptions import (
    ExprDumper,
    describe_DWARF_expr,
    describe_reg_name,
    set_global_machine_arch,
)
from elftools.common.exceptions import DWARFError
from elftools.dwarf.dwarf_expr import (
    DWARFExprOp,
    DWARFExprLimitError,
    DWARFExprParser,
    ExprBudget,
)
from elftools.dwarf.structs import DWARFStructs


class TestExprDumper(unittest.TestCase):
    structs32 = DWARFStructs(
            little_endian=True,
            dwarf_format=32,
            address_size=4)

    def setUp(self):
        self.visitor = ExprDumper(self.structs32)
        set_global_machine_arch('x64')

    def test_basic_single(self):
        self.assertEqual(self.visitor.dump_expr([0x1b]),
            'DW_OP_div')

        self.assertEqual(self.visitor.dump_expr([0x74, 0x82, 0x01]),
            'DW_OP_breg4 (rsi): 130')

        self.assertEqual(self.visitor.dump_expr([0x91, 0x82, 0x01]),
            'DW_OP_fbreg: 130')

        self.assertEqual(self.visitor.dump_expr([0x51]),
            'DW_OP_reg1 (rdx)')

        self.assertEqual(self.visitor.dump_expr([0x90, 16]),
            'DW_OP_regx: 16 (rip)')

        self.assertEqual(self.visitor.dump_expr([0x9d, 0x8f, 0x0A, 0x90, 0x01]),
            # Explaining the arguments is what the latest readelf does
            'DW_OP_bit_piece: size: 1295 offset: 144')

        self.assertEqual(self.visitor.dump_expr([0x0e, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00]),
            'DW_OP_const8u: 71777214294589695')

    def test_basic_sequence(self):
        self.assertEqual(self.visitor.dump_expr([0x03, 0x01, 0x02, 0, 0, 0x06, 0x06]),
            'DW_OP_addr: 201; DW_OP_deref; DW_OP_deref')

        self.assertEqual(self.visitor.dump_expr([0x15, 0xFF, 0x0b, 0xf1, 0xff]),
            'DW_OP_pick: 255; DW_OP_const2s: -15')

        self.assertEqual(self.visitor.dump_expr([0x1d, 0x1e, 0x1d, 0x1e, 0x1d, 0x1e]),
            'DW_OP_mod; DW_OP_mul; DW_OP_mod; DW_OP_mul; DW_OP_mod; DW_OP_mul')

        # 0xe0 maps to both DW_OP_GNU_push_tls_address and DW_OP_lo_user, so
        # check for both to prevent non-determinism.
        self.assertIn(self.visitor.dump_expr([0x08, 0x0f, 0xe0]),
                      ('DW_OP_const1u: 15; DW_OP_GNU_push_tls_address',
                       'DW_OP_const1u: 15; DW_OP_lo_user'))

    def test_riscv_registers(self):
        set_global_machine_arch('RISC-V')
        self.addCleanup(set_global_machine_arch, 'x64')
        self.assertEqual(
            self.visitor.dump_expr([0x5a, 0x72, 8, 0x90, 42, 0x90, 96]),
            'DW_OP_reg10 (a0); DW_OP_breg2 (sp): 8; '
            'DW_OP_regx: 42 (fa0); DW_OP_regx: 96 (v0)')

        # Reserved and unmapped numbers retain the usual numeric fallback.
        for regnum in (-1, 64, 95, 128, 8192):
            with self.subTest(regnum=regnum):
                self.assertEqual(describe_reg_name(regnum), f'r{regnum}')
                self.assertIsNone(describe_reg_name(regnum, 'RISC-V', default=False))


class TestParseExpr(unittest.TestCase):
    structs32 = DWARFStructs(
            little_endian=True,
            dwarf_format=32,
            address_size=4)

    def setUp(self):
        set_global_machine_arch('x64')

    def test_single(self):
        p = DWARFExprParser(self.structs32)
        lst = p.parse_expr(b'\x1b')
        self.assertEqual(lst, [DWARFExprOp(op=0x1B, op_name='DW_OP_div', args=[], offset=0)])

        lst = p.parse_expr(b'\x90\x10')
        self.assertEqual(lst, [DWARFExprOp(op=0x90, op_name='DW_OP_regx', args=[16], offset=0)])

        lst = p.parse_expr(b'\xe0')
        self.assertEqual(len(lst), 1)
        # 0xe0 maps to both DW_OP_GNU_push_tls_address and DW_OP_lo_user, so
        # check for both to prevent non-determinism.
        self.assertIn(lst[0], [
            DWARFExprOp(op=0xe0, op_name='DW_OP_GNU_push_tls_address', args=[], offset=0),
            DWARFExprOp(op=0xe0, op_name='DW_OP_lo_user', args=[], offset=0)])

        # Real life example:
        # push_object_address
        # deref
        # dup
        # bra 4
        # lit0
        # skip 3
        # lit4
        # minus
        # deref
        lst = p.parse_expr(b'\x97\x06\x12\x28\x04\x00\x30\x2F\x03\x00\x34\x1C\x06')
        self.assertEqual(len(lst), 9)
        self.assertEqual(lst, [
            DWARFExprOp(op=0x97, op_name='DW_OP_push_object_address', args=[], offset=0),
            DWARFExprOp(op=0x6,  op_name='DW_OP_deref', args=[], offset=1),
            DWARFExprOp(op=0x12, op_name='DW_OP_dup', args=[], offset=2),
            DWARFExprOp(op=0x28, op_name='DW_OP_bra', args=[4], offset=3),
            DWARFExprOp(op=0x30, op_name='DW_OP_lit0', args=[], offset=6),
            DWARFExprOp(op=0x2f, op_name='DW_OP_skip', args=[3], offset=7),
            DWARFExprOp(op=0x34, op_name='DW_OP_lit4', args=[], offset=10),
            DWARFExprOp(op=0x1c, op_name='DW_OP_minus', args=[], offset=11),
            DWARFExprOp(op=0x6,  op_name='DW_OP_deref', args=[], offset=12)])

        # This expression blob came from the test binary in issue 508,
        # DT_TAG_variable at 0x2a48C, DW_AT_location
        lst = p.parse_expr(b'\x5f\xf0')
        self.assertEqual(len(lst), 2)
        self.assertEqual(lst, [
            DWARFExprOp(op=0x5f, op_name='DW_OP_reg15', args=[], offset=0),
            DWARFExprOp(op=0xf0,  op_name='DW_OP_GNU_uninit', args=[], offset=1)])


def _uleb128(value):
    out = []
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _nested_entry_value(depth):
    # DW_OP_entry_value <uleb size> <sub-expr>, wrapped `depth` times around
    # a single DW_OP_lit0.
    blob = b'\x30'
    for _ in range(depth):
        blob = b'\xa3' + _uleb128(len(blob)) + blob
    return blob


class TestExprBudget(unittest.TestCase):
    structs32 = DWARFStructs(
            little_endian=True,
            dwarf_format=32,
            address_size=4)

    def setUp(self):
        set_global_machine_arch('x64')

    def test_budget_disabled_by_default(self):
        parser = DWARFExprParser(self.structs32)
        self.assertIsNone(parser._budget)
        # A very deep dup chain still parses linearly in legacy mode and the
        # virtual stack is never materialized.
        blob = b'\x30' + b'\x12' * 50000
        parsed = parser.parse_expr(blob)
        self.assertEqual(len(parsed), 50001)

    def test_deep_stack_is_rejected(self):
        # DW_OP_lit0 followed by many DW_OP_dup.
        blob = b'\x30' + b'\x12' * 50000
        parser = DWARFExprParser(
            self.structs32,
            ExprBudget(max_stack_depth=128, max_opcodes=10**9))
        with self.assertRaises(DWARFExprLimitError) as caught:
            parser.parse_expr(blob)
        err = caught.exception
        self.assertEqual(err.dimension, 'stack_depth')
        self.assertEqual(err.limit, 128)
        self.assertEqual(err.opcode, 0x12)
        # Offset points at the dup that crosses the limit.
        self.assertEqual(err.offset, 128)
        self.assertIn('stack_depth', str(err))

    def test_deep_stack_does_not_allocate_the_stack(self):
        # Parsing must stay cheap regardless of the claimed stack height.
        blob = b'\x30' + b'\x12' * 200000
        parser = DWARFExprParser(
            self.structs32,
            ExprBudget(max_stack_depth=64, max_opcodes=10**9))
        with self.assertRaises(DWARFExprLimitError):
            parser.parse_expr(blob)

    def test_pick_chain_within_budget_parses(self):
        # DW_OP_lit0 + DW_OP_pick 0 repeated; pick is stack-neutral here.
        blob = b'\x30' + b'\x15\x00' * 100
        parser = DWARFExprParser(
            self.structs32,
            ExprBudget(max_stack_depth=128, max_opcodes=1000))
        parsed = parser.parse_expr(blob)
        self.assertEqual(len(parsed), 101)

    def test_opcode_budget_covers_nested_expressions(self):
        # Five entry_value wrappers around many lit0 ops: the shared counter
        # must count opcodes across the whole expression tree.
        inner = b'\x30' * 40
        blob = b'\xa3' + _uleb128(len(inner)) + inner
        parser = DWARFExprParser(
            self.structs32, ExprBudget(max_opcodes=20))
        with self.assertRaises(DWARFExprLimitError) as caught:
            parser.parse_expr(blob)
        self.assertEqual(caught.exception.dimension, 'opcodes')

    def test_growing_loop_hits_step_limit(self):
        # lit0; lit0; DW_OP_skip -3 -> jumps back to the second lit0,
        # growing the abstract stack on every iteration.
        grow = b'\x30\x30\x2f\xfd\xff'
        parser = DWARFExprParser(
            self.structs32,
            ExprBudget(max_opcodes=100, max_stack_depth=1000))
        with self.assertRaises(DWARFExprLimitError) as caught:
            parser.parse_expr(grow)
        self.assertEqual(caught.exception.dimension, 'steps')
        self.assertEqual(caught.exception.opcode, 0x2f)
        self.assertEqual(caught.exception.offset, 2)

    def test_constant_depth_loop_is_allowed(self):
        # nop; DW_OP_skip -2 loops forever at runtime but never grows the
        # stack, and the abstract walk terminates on its own.
        const_loop = b'\x96\x2f\xfe\xff'
        parser = DWARFExprParser(
            self.structs32, ExprBudget(max_opcodes=50))
        parsed = parser.parse_expr(const_loop)
        self.assertEqual([op.op_name for op in parsed],
                         ['DW_OP_nop', 'DW_OP_skip'])

    def test_negative_jump_within_expression(self):
        # nop; DW_OP_bra -2 lands back on the bra opcode boundary.
        blob = b'\x96\x28\xfe\xff'
        parser = DWARFExprParser(
            self.structs32, ExprBudget(max_opcodes=50))
        parsed = parser.parse_expr(blob)
        self.assertEqual(parsed[1].op_name, 'DW_OP_bra')

    def test_out_of_bounds_jump_target(self):
        # nop; DW_OP_bra +20 points past the end of the expression.
        blob = b'\x96\x28\x14\x00'
        parser = DWARFExprParser(self.structs32, ExprBudget())
        with self.assertRaises(DWARFExprLimitError) as caught:
            parser.parse_expr(blob)
        self.assertEqual(caught.exception.dimension, 'branch_target')
        self.assertEqual(caught.exception.offset, 1)
        self.assertEqual(caught.exception.opcode, 0x28)

    def test_branch_offset_displacement_budget(self):
        blob = b'\x96\x28\x14\x00'
        parser = DWARFExprParser(
            self.structs32, ExprBudget(max_branch_offset=1))
        with self.assertRaises(DWARFExprLimitError) as caught:
            parser.parse_expr(blob)
        self.assertEqual(caught.exception.dimension, 'branch_offset')
        self.assertEqual(caught.exception.limit, 1)

    def test_misaligned_jump_target(self):
        # DW_OP_skip targeting the argument byte of another skip, which is
        # not an opcode boundary.
        blob = b'\x2f\x00\x00\x2f\x00\x00'
        parser = DWARFExprParser(self.structs32, ExprBudget())
        with self.assertRaises(DWARFExprLimitError) as caught:
            parser.parse_expr(
                blob[:3] + b'\x2f\x02\x00')
        self.assertEqual(caught.exception.dimension, 'branch_target')

    def test_nested_entry_value_depth(self):
        budget = ExprBudget(max_entry_value_depth=64)
        parser = DWARFExprParser(self.structs32, budget)
        shallow = parser.parse_expr(_nested_entry_value(5))
        self.assertEqual(shallow[0].op_name, 'DW_OP_entry_value')
        with self.assertRaises(DWARFExprLimitError) as caught:
            parser.parse_expr(_nested_entry_value(65))
        self.assertEqual(caught.exception.dimension, 'entry_value_depth')
        self.assertEqual(caught.exception.limit, 64)
        self.assertEqual(caught.exception.opcode, 0xa3)

    def test_oversized_implicit_value_checked_before_read(self):
        # DW_OP_implicit_value declaring 10 million bytes without providing
        # them: the length must be rejected before any block allocation.
        blob = b'\x9e' + _uleb128(10_000_000)
        parser = DWARFExprParser(
            self.structs32,
            ExprBudget(max_implicit_value_length=1024))
        with self.assertRaises(DWARFExprLimitError) as caught:
            parser.parse_expr(blob)
        err = caught.exception
        self.assertEqual(err.dimension, 'implicit_value_length')
        self.assertEqual(err.limit, 1024)
        self.assertEqual(err.offset, 0)

    def test_legal_implicit_value(self):
        blob = b'\x9e' + _uleb128(3) + b'\x01\x02\x03'
        parser = DWARFExprParser(
            self.structs32,
            ExprBudget(max_implicit_value_length=1024))
        parsed = parser.parse_expr(blob)
        self.assertEqual(parsed[0].args, [[1, 2, 3]])

    def test_legal_long_expression(self):
        blob = b'\x96' * 200
        parser = DWARFExprParser(
            self.structs32,
            ExprBudget(max_opcodes=300, max_stack_depth=8))
        self.assertEqual(len(parser.parse_expr(blob)), 200)

    def test_unknown_opcode_opaque_with_budget(self):
        # 0x01 is not a defined expression opcode. With a budget it is
        # represented opaquely and parsing stops cleanly instead of raising.
        parser = DWARFExprParser(self.structs32, ExprBudget())
        parsed = parser.parse_expr(b'\x96\x01')
        self.assertEqual(parsed[0],
                         DWARFExprOp(0x96, 'DW_OP_nop', [], 0))
        self.assertEqual(parsed[1].op, 0x01)
        self.assertEqual(parsed[1].op_name, 'OP:0x1')

    def test_unknown_opcode_legacy_keyerror(self):
        parser = DWARFExprParser(self.structs32)
        with self.assertRaises(KeyError):
            parser.parse_expr(b'\x01')

    def test_constant_results_unchanged(self):
        legacy = DWARFExprParser(self.structs32)
        budgeted = DWARFExprParser(self.structs32, ExprBudget.default())
        for blob in (
                b'\x08\xfe',                      # const1u
                b'\x09\xfe',                      # const1s (signed)
                b'\x10\x80\x01',                  # constu (uleb)
                b'\x11\x80\x01',                  # consts (sleb)
                b'\x0e\xff\x00\xff\x00\xff\x00\xff\x00',  # const8u
                b'\x03' + (0xdeadbeef).to_bytes(4, 'little'),
                b'\x91\x82\x01',                  # fbreg signed
        ):
            self.assertEqual(
                legacy.parse_expr(blob),
                budgeted.parse_expr(blob),
                blob)

    def test_default_budget_factory(self):
        budget = ExprBudget.default()
        self.assertTrue(budget.enabled)
        self.assertIsNotNone(budget.max_stack_depth)
        self.assertIsNone(budget.max_branch_offset)

    def test_legacy_implicit_value_truncated_blob_preserved(self):
        # Without a budget the parser reads whatever bytes remain, matching
        # the historical behavior even when the declared length is larger.
        parser = DWARFExprParser(self.structs32)
        parsed = parser.parse_expr(b'\x9e\x05abc')
        self.assertEqual(parsed[0].args, [[ord('a'), ord('b'), ord('c')]])

    def test_invalid_budget_rejected(self):
        with self.assertRaises(ValueError):
            ExprBudget(max_stack_depth=-1)

    def test_per_call_budget_override(self):
        parser = DWARFExprParser(self.structs32)
        blob = b'\x30' + b'\x12' * 100
        # No constructor budget: legacy parse succeeds.
        self.assertEqual(len(parser.parse_expr(blob)), 101)
        # A per-call budget enforces limits without mutating the parser.
        with self.assertRaises(DWARFExprLimitError):
            parser.parse_expr(
                blob, budget=ExprBudget(max_stack_depth=8))
        self.assertIsNone(parser._budget)
        self.assertEqual(len(parser.parse_expr(blob)), 101)

    def test_stack_underflow_reported(self):
        # DW_OP_minus with an empty stack.
        parser = DWARFExprParser(self.structs32, ExprBudget())
        with self.assertRaises(DWARFError):
            parser.parse_expr(b'\x1c')

    def test_dumper_and_describe_path_propagate_budget(self):
        blob = b'\x30' + b'\x12' * 100
        dumper = ExprDumper(self.structs32, ExprBudget(max_stack_depth=4))
        with self.assertRaises(DWARFExprLimitError):
            dumper.dump_expr(blob)
        with self.assertRaises(DWARFExprLimitError):
            describe_DWARF_expr(
                blob, self.structs32,
                budget=ExprBudget(max_stack_depth=4))
        # Without a budget the description path keeps working.
        text = describe_DWARF_expr(blob, self.structs32)
        self.assertIn('DW_OP_dup', text)


if __name__ == '__main__':
    unittest.main()
