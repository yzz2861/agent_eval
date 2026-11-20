import io
import json
import os

from cpe.migration import (
    DECISION_APPROVED_DEVICE,
    DECISION_APPROVED_INHERITANCE,
    DECISION_APPROVED_PRODUCT,
    DECISION_PENDING,
    REASON_CPE_MATCH_WITHOUT_DEVICE_APPROVAL,
    REASON_DEVICE_APPROVAL_CPE_MISMATCH,
    REASON_INHERITANCE_EVIDENCE_MISSING,
    build_preview,
    main,
)


HERE = os.path.dirname(__file__)
EXAMPLE = os.path.join(
    HERE, "..", "..", "examples", "migration_preview", "input.json")


def _load_example():
    with io.open(EXAMPLE, "r", encoding="utf-8") as input_file:
        return json.load(input_file)


def test_example_splits_device_and_product_approvals():
    preview = build_preview(_load_example())
    document = preview.to_dict()

    assert document["summary"]["devices"] == 7
    assert document["summary"]["approved"] == 5
    assert document["summary"]["pending_review"] == 2

    assert preview.asset_result("EDGE-N-01")["decision"] == (
        DECISION_APPROVED_DEVICE)
    assert preview.asset_result("AP-N-01")["decision"] == (
        DECISION_APPROVED_PRODUCT)
    assert preview.asset_result("AP-S-01")["decision"] == (
        DECISION_APPROVED_PRODUCT)


def test_same_model_device_without_asset_approval_stays_pending():
    preview = build_preview(_load_example())
    result = preview.asset_result("EDGE-N-02")

    assert result["inventory"] == "north"
    assert result["decision"] == DECISION_PENDING
    assert result["reason_code"] == (
        REASON_CPE_MATCH_WITHOUT_DEVICE_APPROVAL)
    assert result["cpe_matches"][0]["rule_id"] == "LEGACY-EDGE-GROUP"
    assert result["cpe_matches"][0]["authorized"] is False
    assert result["approved_by"] is None


def test_evidenced_inheritance_carries_device_approval():
    preview = build_preview(_load_example())
    result = preview.asset_result("EDGE-S-02")

    assert result["decision"] == DECISION_APPROVED_INHERITANCE
    assert result["approved_by"] == "LEGACY-EDGE-GROUP"
    assert result["evidence"] == ["handover:HTO-2026-041"]
    assert result["inheritance"] == [{
        "parent_asset_id": "EDGE-S-01",
        "evidence": ["handover:HTO-2026-041"],
    }]


def test_missing_inheritance_evidence_returns_device_to_review():
    preview = build_preview(_load_example())
    result = preview.asset_result("EDGE-S-03")

    assert result["decision"] == DECISION_PENDING
    assert result["reason_code"] == REASON_INHERITANCE_EVIDENCE_MISSING
    assert result["inheritance"] == [{
        "parent_asset_id": "EDGE-S-01",
        "evidence": [],
    }]


def test_device_id_with_mismatched_cpe_is_not_approved():
    document = {
        "rules": [{
            "id": "old-device",
            "basis": "device",
            "cpes": [
                "cpe:2.3:h:acme:edge_gateway:2.4.1:*:*:*:*:*:*:*"
            ],
            "device_ids": ["EDGE-01"],
        }],
        "inheritances": [],
        "inventories": [{
            "name": "after",
            "devices": [{
                "asset_id": "EDGE-01",
                "cpe": "cpe:2.3:h:acme:edge_gateway:2.5.0:*:*:*:*:*:*:*",
            }],
        }],
    }

    result = build_preview(document).asset_result("EDGE-01")

    assert result["decision"] == DECISION_PENDING
    assert result["reason_code"] == REASON_DEVICE_APPROVAL_CPE_MISMATCH


def test_cli_can_focus_the_unapproved_same_model_device(capsys):
    assert main([EXAMPLE, "--device", "EDGE-N-02"]) == 0
    output = capsys.readouterr().out

    assert "<-- FOCUS" in output
    assert "关注设备: north/EDGE-N-02" in output
    assert "CPE 命中:" in output
    assert "关注设备: north/EDGE-S-02" not in output
