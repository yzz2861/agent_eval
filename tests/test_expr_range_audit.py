import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "examples"))

import expr_range_audit as era


def run_audit(expression, variables, targets, bounds, **kwargs):
    request = era.AuditRequest(
        expression=expression,
        variables=tuple(variables),
        targets=tuple(targets),
        business_min=bounds[0],
        business_max=bounds[1],
        **kwargs,
    )
    return era.audit(request)


class ExpressionRangeAuditTests(unittest.TestCase):
    def test_builtin_example_shows_promotion_threshold(self):
        report = run_audit(
            "(health - baseline) * 10",
            (
                era.VariableSpec("health", "uint16_t", 0, 1000),
                era.VariableSpec("baseline", "uint16_t", 800, 800),
            ),
            (
                era.Target("board-16", "int32_t", 16),
                era.Target("board-32", "int32_t", 32),
            ),
            (-8000, 2000),
        )

        board16, board32 = report.results
        self.assertEqual(board16.verdict, "VIOLATED")
        self.assertFalse(board16.sufficient)
        self.assertEqual(board16.witness, {"health": 0, "baseline": 800})
        self.assertEqual(board16.witness_value, 57536)

        self.assertEqual(board32.verdict, "PROVEN")
        self.assertTrue(board32.sufficient)
        self.assertEqual(board32.value.intervals, ((-8000, 2000),))

    def test_unsigned_char_promotes_to_signed_int(self):
        report = run_audit(
            "x + 1",
            (era.VariableSpec("x", "unsigned char", 0, 255),),
            (era.Target("t", "int", 16),),
            (0, 256),
        )
        result = report.results[0]
        self.assertEqual(result.verdict, "PROVEN")
        self.assertEqual(result.value.intervals, ((1, 256),))

    def test_unsigned_short_wrap_is_bounds_only(self):
        report = run_audit(
            "x + 1",
            (era.VariableSpec("x", "uint16_t", 65535, 65535),),
            (era.Target("t", "int32_t", 16),),
            (-100000, 100000),
        )
        result = report.results[0]
        self.assertEqual(result.verdict, "PROVEN_BOUNDS_ONLY")
        self.assertTrue(result.bounds_proven)
        self.assertFalse(result.semantics_clean)
        self.assertIn("unsigned_wrap", {issue.kind for issue in result.value.issues})

    def test_explicit_cast_truncation_is_bounds_only(self):
        report = run_audit(
            "(uint16_t)(x * 300)",
            (era.VariableSpec("x", "uint16_t", 0, 255),),
            (era.Target("t", "uint32_t", 32),),
            (0, 65535),
        )
        result = report.results[0]
        self.assertEqual(result.verdict, "PROVEN_BOUNDS_ONLY")
        self.assertIn("cast_truncation", {issue.kind for issue in result.value.issues})

    def test_constant_ternary_selects_one_finite_branch(self):
        report = run_audit(
            "mode == 2 ? 7 : 99",
            (era.VariableSpec("mode", "int", 2, 2),),
            (era.Target("t", "int", 32),),
            (0, 10),
        )
        result = report.results[0]
        self.assertEqual(result.verdict, "PROVEN")
        self.assertEqual(result.value.intervals, ((7, 7),))

    def test_nonconstant_ternary_union_can_be_refuted(self):
        report = run_audit(
            "mode == 2 ? 7 : 99",
            (era.VariableSpec("mode", "int", 0, 2),),
            (era.Target("t", "int", 32),),
            (0, 10),
        )
        result = report.results[0]
        self.assertEqual(result.verdict, "VIOLATED")
        self.assertEqual(result.witness_value, 99)

    def test_unknown_type_needs_confirmation(self):
        report = run_audit(
            "x + 1",
            (era.VariableSpec("x", "my_count_t", 0, 10),),
            (era.Target("t", "int", 32),),
            (0, 100),
        )
        result = report.results[0]
        self.assertEqual(result.verdict, "NEEDS_CONFIRMATION")
        self.assertFalse(result.sufficient)
        self.assertIn("unknown_type", {issue.kind for issue in result.value.issues})

    def test_unknown_identifier_needs_confirmation(self):
        report = run_audit(
            "missing + 1",
            (),
            (era.Target("t", "int", 32),),
            (0, 100),
        )
        result = report.results[0]
        self.assertEqual(result.verdict, "NEEDS_CONFIRMATION")
        self.assertIn(
            "unknown_identifier", {issue.kind for issue in result.value.issues}
        )

    def test_division_by_zero_is_insufficient(self):
        report = run_audit(
            "x / y",
            (
                era.VariableSpec("x", "int", 0, 10),
                era.VariableSpec("y", "int", 0, 0),
            ),
            (era.Target("t", "int", 32),),
            (0, 10),
        )
        result = report.results[0]
        self.assertEqual(result.verdict, "INSUFFICIENT")
        self.assertIn("zero_division", {issue.kind for issue in result.value.issues})

    def test_signed_overflow_is_not_evidence(self):
        report = run_audit(
            "2147483647 + 1",
            (),
            (era.Target("t", "int", 32),),
            (-2147483648, 2147483647),
        )
        result = report.results[0]
        self.assertEqual(result.verdict, "INSUFFICIENT")
        self.assertIn("signed_overflow", {issue.kind for issue in result.value.issues})

    def test_unsigned_field_conversion_is_bounds_only(self):
        report = run_audit(
            "-1",
            (),
            (era.Target("t", "uint16_t", 32),),
            (0, 65535),
        )
        result = report.results[0]
        self.assertEqual(result.verdict, "PROVEN_BOUNDS_ONLY")
        self.assertEqual(result.value.intervals, ((65535, 65535),))
        self.assertIn("field_conversion", {issue.kind for issue in result.value.issues})

    def test_report_is_json_serializable(self):
        report = run_audit(
            "x + 1",
            (era.VariableSpec("x", "uint16_t", 0, 10),),
            (era.Target("t", "int", 32),),
            (0, 100),
        )
        encoded = report.to_dict()
        self.assertEqual(encoded["expression"], "x + 1")
        self.assertEqual(encoded["targets"][0]["verdict"], "PROVEN")

    def test_narrow_unsigned_type_converts_to_wider_signed_type(self):
        report = run_audit(
            "x + y",
            (
                era.VariableSpec("x", "int64_t", -1, -1),
                era.VariableSpec("y", "uint32_t", 1, 1),
            ),
            (era.Target("t", "int64_t", 64),),
            (-100, 100),
        )
        result = report.results[0]
        self.assertEqual(result.verdict, "PROVEN")
        self.assertEqual(result.value.intervals, ((0, 0),))

    def test_sizeof_uses_confirmed_size_t(self):
        report = run_audit(
            "sizeof(int)",
            (),
            (era.Target("t", "size_t", 16),),
            (0, 10),
            type_widths={"size_t": (16, False)},
        )
        result = report.results[0]
        self.assertEqual(result.verdict, "PROVEN")
        self.assertEqual(result.value.intervals, ((2, 2),))

    def test_typedef_resolves_variable_and_cast(self):
        report = run_audit(
            "(my_count_t)(x + 1)",
            (era.VariableSpec("x", "my_count_t", 0, 10),),
            (era.Target("t", "int", 32),),
            (0, 100),
            typedefs={"my_count_t": "uint16_t"},
        )
        result = report.results[0]
        self.assertEqual(result.verdict, "PROVEN")
        self.assertEqual(result.value.intervals, ((1, 11),))

    def test_cli_demo_succeeds_and_summarizes_targets(self):
        import contextlib
        import io

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            return_code = era.main([])
        self.assertEqual(return_code, 0)
        text = output.getvalue()
        self.assertIn("board-16: VIOLATED", text)
        self.assertIn("board-32: PROVEN", text)
        self.assertIn("threshold:", text)


if __name__ == "__main__":
    unittest.main()
