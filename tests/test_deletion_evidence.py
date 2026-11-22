import hashlib
import io
import os

import pytest
import sys

from Registry.DeletionEvidence import analyze_deletion

sys.path.insert(0, os.path.dirname(__file__))


SAMPLES = os.path.join(os.path.dirname(__file__), "reg_samples", "deletion")
BEFORE = os.path.join(SAMPLES, "software_before.hive")
RELEASED = os.path.join(SAMPLES, "software_after_released.hive")
REALLOCATED = os.path.join(SAMPLES, "software_after_reallocated.hive")
REALLOCATED_LOG = os.path.join(
    SAMPLES, "software_after_reallocated.SOFTWARE.LOG1")
NOT_COLLECTED_BEFORE = os.path.join(
    SAMPLES, "software_before_not_collected.hive")
NOT_COLLECTED_AFTER = os.path.join(
    SAMPLES, "software_after_not_collected.hive")
WRONG_HIVE = os.path.join(SAMPLES, "software_after_wrong_hive.hive")
KEY = r"SOFTWARE\Contoso\Agent"
VALUE = "Policy"


def test_released_old_value_cell():
    report = analyze_deletion(BEFORE, RELEASED, KEY, VALUE)

    assert report["verdict"] == "RELEASED"
    assert report["reason_code"] == "OLD_VK_CELL_IS_FREE"
    assert report["query"]["value_path"] == r"SOFTWARE\Contoso\Agent!Policy"
    assert report["before"]["target"]["value"]["vk_cell"][
        "cell_offset_relative_to_first_hbin"] == 0x150
    assert report["after"]["old_vk_slot"]["state"] == "free"
    assert report["after"]["old_vk_slot"]["same_payload_as_before"] is True
    assert report["after"]["old_data_slot"]["state"] == "free"
    assert report["transaction_batches"]["alignment"] == "NOT_PROVIDED"


def test_reallocated_old_value_cell_with_aligned_batch():
    report = analyze_deletion(
        BEFORE, REALLOCATED, KEY, VALUE, [REALLOCATED_LOG])

    assert report["verdict"] == "REALLOCATED"
    assert report["reason_code"] == "OLD_VK_CELL_START_REUSED"
    assert report["materials"]["status"] == "MATCH"

    old_vk_slot = report["after"]["old_vk_slot"]
    assert old_vk_slot["relation"] == "exact"
    assert old_vk_slot["state"] == "allocated"
    assert old_vk_slot["allocated_vk"]["name"] == "Rotation"
    assert old_vk_slot["same_bytes_as_before"] is False

    assert report["after"]["old_data_slot"]["state"] == "free"
    assert report["transaction_batches"]["alignment"] == "ALIGNED"
    assert report["transaction_batches"]["coverage"]["old_vk_cell"] is True
    assert report["transaction_batches"]["coverage"][
        "dirty_page_matches_after_vk_cell"] is True

    batch = report["transaction_batches"]["slot_state_by_batch"][0]
    assert batch["sequence"] == 8
    assert batch["vk_cell"][0]["state"] == "allocated"
    assert batch["vk_cell"][0]["value_name"] == "Rotation"
    assert batch["data_cell"][0]["state"] == "free"


def test_target_absent_from_both_snapshots_is_not_collected():
    report = analyze_deletion(
        NOT_COLLECTED_BEFORE, NOT_COLLECTED_AFTER, KEY, VALUE)

    assert report["verdict"] == "NOT_COLLECTED"
    assert report["reason_code"] == "TARGET_NOT_IN_EITHER_SNAPSHOT"
    assert report["before"]["target"]["key_present"] is True
    assert report["before"]["target"]["value_present"] is False
    assert report["after"]["target"]["value_present"] is False
    assert report["before"]["old_vk_slot"] is None
    missing = {item["code"] for item in report["missing_evidence"]}
    assert "EARLIER_ACQUISITION_WITH_TARGET" in missing
    assert "PHYSICAL_IDENTITY_OF_TARGET" in missing


def test_foreign_hive_material_is_undetermined():
    report = analyze_deletion(
        BEFORE, WRONG_HIVE, KEY, VALUE, [REALLOCATED_LOG])

    assert report["verdict"] == "UNDETERMINED"
    assert report["reason_code"] == "MATERIAL_MISMATCH"
    assert report["materials"]["status"] == "MISMATCH"
    assert any(
        reason.startswith("HIVE_NAME_MISMATCH")
        for reason in report["materials"]["reasons"])


def test_log_outside_sequence_window_is_undetermined():
    import make_synthetic_hives

    after = open(REALLOCATED, "rb").read()
    future_log = make_synthetic_hives._build_log(after, sequence=99)
    report = analyze_deletion(
        BEFORE, REALLOCATED, KEY, VALUE, [io.BytesIO(future_log)])

    assert report["verdict"] == "UNDETERMINED"
    assert report["reason_code"] == "TRANSACTION_BATCH_MISMATCH"
    assert report["transaction_batches"]["alignment"] == "MISMATCH"
    assert any(
        "outside snapshot window" in reason
        for reason in report["transaction_batches"]["alignment_reasons"])


def test_same_snapshot_still_present():
    report = analyze_deletion(BEFORE, BEFORE, KEY, VALUE)

    assert report["verdict"] == "PRESENT"
    assert report["materials"]["same_image"] is True
    assert report["after"]["target"]["value"]["value_preview"] == "Enabled"


def test_analysis_does_not_modify_inputs():
    def fingerprint(path):
        with open(path, "rb") as handle:
            data = handle.read()
        stat = os.stat(path)
        return hashlib.sha256(data).hexdigest(), stat.st_size, stat.st_mtime_ns

    before = fingerprint(BEFORE)
    after = fingerprint(REALLOCATED)
    log = fingerprint(REALLOCATED_LOG)

    analyze_deletion(BEFORE, REALLOCATED, KEY, VALUE, [REALLOCATED_LOG])

    assert fingerprint(BEFORE) == before
    assert fingerprint(REALLOCATED) == after
    assert fingerprint(REALLOCATED_LOG) == log

def test_old_slot_beyond_captured_hbins_is_undetermined():
    import make_synthetic_hives
    import struct

    hive = bytearray(open(RELEASED, "rb").read())
    struct.pack_into("<I", hive, 0x28, 0)
    make_synthetic_hives._update_checksum(hive)

    report = analyze_deletion(BEFORE, io.BytesIO(bytes(hive)), KEY, VALUE)

    assert report["verdict"] == "UNDETERMINED"
    assert report["reason_code"] == "OLD_VK_SLOT_NOT_COMPARABLE"
    assert report["after"]["old_vk_slot"]["state"] == "beyond_captured_hbins"

def test_cli_output_cannot_overwrite_evidence():
    from Registry.DeletionEvidence import main

    with pytest.raises(SystemExit) as excinfo:
        main([
            "--before", BEFORE,
            "--after", REALLOCATED,
            "--key", KEY,
            "--value", VALUE,
            "--output", BEFORE,
        ])

    assert excinfo.value.code == 2

