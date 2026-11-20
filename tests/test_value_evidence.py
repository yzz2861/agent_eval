#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import subprocess
import sys

import pytest

import Registry
from Registry import Registry as RegistryModule


SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "reg_samples", "policy_evidence")
BASELINE = os.path.join(SAMPLE_DIR, "baseline.hive")
REPRESENTATION = os.path.join(SAMPLE_DIR, "representation_change.hive")
VALUE_CHANGE = os.path.join(SAMPLE_DIR, "value_change.hive")


@pytest.fixture
def baseline():
    return RegistryModule.Registry(BASELINE).root()


def test_legacy_value_api_is_unchanged(baseline):
    value = baseline.value("AuditLevel")
    assert value.value() == 1
    assert value.raw_data() == b"\x01\x00\x00\x00"
    assert value.value_type() == RegistryModule.RegDWord


def test_evidence_keeps_storage_type_and_decoded_value(baseline):
    evidence = baseline.value("AuditLevel").evidence()
    assert evidence.raw_data == b"\x01\x00\x00\x00"
    assert evidence.raw_hex == "01000000"
    assert evidence.type_marker == RegistryModule.RegDWord
    assert evidence.type_name == "RegDWord"
    assert evidence.decoded == 1
    assert evidence.complete is True
    assert evidence.readable is True


def test_explicit_big_endian_is_distinguished(baseline):
    evidence = baseline.value("RestrictAnonymous").evidence()
    assert evidence.type_marker == RegistryModule.RegBigEndian
    assert evidence.type_name == "RegBigEndian"
    assert evidence.byte_order == "big"
    assert evidence.encoding == RegistryModule.EVIDENCE_BIG_ENDIAN
    assert evidence.kind == RegistryModule.EVIDENCE_BIG_ENDIAN
    assert evidence.is_big_endian is True
    assert evidence.decoded == 1


def test_usual_little_endian_is_distinguished(baseline):
    evidence = baseline.value("LmCompatibilityLevel").evidence()
    assert evidence.type_marker == RegistryModule.RegDWord
    assert evidence.byte_order == "little"
    assert evidence.encoding == RegistryModule.EVIDENCE_LITTLE_ENDIAN
    assert evidence.kind == RegistryModule.EVIDENCE_LITTLE_ENDIAN
    assert evidence.is_little_endian is True
    assert evidence.decoded == 3


def test_readable_but_declared_incomplete(baseline):
    evidence = baseline.value("IncompletePolicy").evidence()
    assert evidence.complete is False
    assert evidence.is_incomplete is True
    assert evidence.readable is True
    assert evidence.decoded == 5
    assert evidence.declared_length == 2
    assert evidence.expected_length == 4
    assert evidence.kind == RegistryModule.EVIDENCE_INCOMPLETE
    assert "declared length 2" in evidence.notes[0]


def test_same_raw_hex_does_not_mean_same_evidence(baseline):
    before = baseline.value("AuditLevel").evidence()
    after = RegistryModule.Registry(REPRESENTATION).root().value("AuditLevel").evidence()

    assert before.display_key == after.display_key == "01000000"
    assert before.raw_data == after.raw_data
    assert before.comparison_key != after.comparison_key

    comparison = before.compare(after)
    assert comparison.status == RegistryModule.EVIDENCE_REPRESENTATION_CHANGED
    assert comparison.representation_changed is True
    assert comparison.value_changed is False
    assert comparison.same_raw_data is True
    assert comparison.same_type_marker is False


def test_true_policy_value_change_is_distinguished(baseline):
    before = baseline.value("LmCompatibilityLevel").evidence()
    after = RegistryModule.Registry(VALUE_CHANGE).root().value(
        "LmCompatibilityLevel"
    ).evidence()

    comparison = before.compare(after)
    assert comparison.status == RegistryModule.EVIDENCE_VALUE_CHANGED
    assert comparison.value_changed is True
    assert comparison.representation_changed is False
    assert comparison.same_raw_data is False
    assert comparison.same_decoded_value is False


def test_evidence_is_mapping_and_json_friendly(baseline):
    evidence = baseline.value("AuditLevel").evidence()
    assert evidence["raw_data"] == evidence.raw_data
    assert evidence["type"] == RegistryModule.RegDWord
    assert evidence["decoded_value"] == 1
    safe = evidence.to_dict()
    assert safe["raw_data"] == "01000000"


def test_external_comparator_names_both_outcomes():
    command = [
        sys.executable,
        os.path.join(os.path.dirname(__file__), "..", "samples",
                     "compare_policy_evidence.py"),
    ]

    representation = subprocess.check_output(
        command + [BASELINE, REPRESENTATION], universal_newlines=True
    )
    assert "[representation_changed] Policies\\AuditLevel" in representation
    assert "evidence representation change" in representation
    assert "0 true policy value change(s)" in representation

    value_change = subprocess.check_output(
        command + [BASELINE, VALUE_CHANGE], universal_newlines=True
    )
    assert "[value_changed] Policies\\LmCompatibilityLevel" in value_change
    assert "true policy value change" in value_change
    assert "1 true policy value change(s)" in value_change


def test_readable_but_missing_inline_marker():
    from io import BytesIO
    import struct

    data = bytearray(open(BASELINE, "rb").read())
    offset = RegistryModule.Registry(BASELINE).root().value(
        "AuditLevel"
    )._vkrecord.offset()
    struct.pack_into("<I", data, offset + 4, 4)

    value = RegistryModule.Registry(BytesIO(bytes(data))).root().value(
        "AuditLevel"
    )
    evidence = value.evidence()
    assert value.value() == 1
    assert evidence.complete is False
    assert evidence.kind == RegistryModule.EVIDENCE_INCOMPLETE
    assert "0x80000000" in " ".join(evidence.notes)
