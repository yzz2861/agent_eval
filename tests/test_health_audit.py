import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from health_audit import audit_expression_for_target, audit_config


def audit(expr, int_bits, fields=None, business=None):
    return audit_expression_for_target(
        expr,
        {"name": f"int{int_bits}", "int_bits": int_bits},
        fields or {"samples": "int16_t"},
        business or {"min": 0, "max": 32768},
    )


def test_hand_calculated_threshold_distinguishes_targets():
    board16 = audit(
        "(uint16_t)((samples >= 0 && samples <= 16384) ? samples * 2 : 32766)",
        16,
    )
    board32 = audit(
        "(uint16_t)((samples >= 0 && samples <= 16384) ? samples * 2 : 32766)",
        32,
    )

    assert board32["status"] == "sufficient_evidence"
    assert board32["computed_range"] == {
        "min": 0,
        "max": 32768,
        "segments": [[0, 32768]],
    }
    assert board16["status"] == "insufficient_evidence"
    assert any(issue["code"] == "signed_overflow_possible" for issue in board16["issues"])


def test_threshold_one_lower_is_safe_on_16_bit_target():
    report = audit(
        "(uint16_t)((samples >= 0 && samples < 16384) ? samples * 2 : 32766)",
        16,
        business={"min": 0, "max": 32766},
    )

    assert report["status"] == "sufficient_evidence"
    assert report["computed_range"]["max"] == 32766


def test_integer_promotion_changes_unsigned_result_type():
    fields = {"events": "uint16_t"}
    board16 = audit("events + 1", 16, fields, {"min": 0, "max": 65535})
    board32 = audit("events + 1", 32, fields, {"min": 1, "max": 65536})

    assert board16["result_type"] == "unsigned int"
    assert board16["computed_range"] == {
        "min": 0,
        "max": 65535,
        "segments": [[0, 65535]],
    }
    assert board32["result_type"] == "int"
    assert board32["computed_range"]["min"] == 1
    assert board32["computed_range"]["max"] == 65536


def test_explicit_unsigned_cast_truncates_to_field_width():
    report = audit(
        "(uint8_t)raw",
        32,
        {"raw": "uint16_t"},
        {"min": 0, "max": 255},
    )

    assert report["status"] == "sufficient_evidence"
    assert report["result_type"] == "uint8_t"
    assert report["computed_range"]["segments"] == [[0, 255]]


def test_unknown_field_type_is_pending_confirmation():
    report = audit("vendor_state + 1", 32, {}, {"min": 0, "max": 10})

    assert report["status"] == "needs_confirmation"
    assert any(issue["code"] == "unknown_type" for issue in report["issues"])


def test_constant_branch_eliminates_unknown_other_branch():
    report = audit("1 ? 7 : unresolved_field", 32, {}, {"min": 0, "max": 7})

    assert report["status"] == "sufficient_evidence"
    assert report["computed_range"]["segments"] == [[7, 7]]


def test_example_config_reports_one_sufficient_board():
    report = audit_config({
        "expression": "(uint16_t)((samples >= 0 && samples <= 16384) ? samples * 2 : 32766)",
        "fields": {"samples": "int16_t"},
        "business": {"min": 0, "max": 32768},
        "targets": [
            {"name": "board16", "int_bits": 16},
            {"name": "board32", "int_bits": 32},
        ],
    })

    statuses = {item["target"]: item["status"] for item in report["reports"]}
    assert statuses == {
        "board16": "insufficient_evidence",
        "board32": "sufficient_evidence",
    }
