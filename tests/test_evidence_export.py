import hashlib
import io
import os
import struct
import tempfile
import unittest

from Registry import Registry
from Registry.SyntheticHive import SyntheticHive
from Registry.EvidenceExport import (
    export_evidence,
    export_evidence_json,
    EMPTY_RECORD,
    RANGE_ONLY,
    RAW_CARRY,
    RESTORED,
)

NUL2 = bytes([0, 0])


def build_and_open(builder):
    data = builder.build()
    handle = io.BytesIO(data)
    return Registry.Registry(handle), data


def evidence_for(builder):
    _hive, data = build_and_open(builder)
    return export_evidence(io.BytesIO(data))


def index_entries(report):
    return dict((entry["value_name"], entry) for entry in report["values"])


class StringEvidenceTests(unittest.TestCase):
    def test_empty_record_vs_terminator_only_are_distinct(self):
        builder = SyntheticHive("RootKey", "EVIDENCE_STRINGS")
        builder.add_value("genuinely_empty", Registry.RegSZ, b"")
        builder.add_value("terminator_only", Registry.RegSZ, NUL2)
        report = evidence_for(builder)
        entries = index_entries(report)

        empty = entries["genuinely_empty"]
        terminated = entries["terminator_only"]

        # The reader collapses both to the same displayed string ...
        hive, _data = build_and_open(builder)
        displayed = dict((v.name(), v.value()) for v in hive.root().values())
        self.assertEqual(displayed["genuinely_empty"], displayed["terminator_only"])
        self.assertEqual(displayed["genuinely_empty"], u"")

        # ... yet the evidence keeps different declared lengths and verdicts.
        self.assertEqual(empty["raw"]["declared_length"], 0)
        self.assertEqual(empty["parsed_view"]["restoration"], EMPTY_RECORD)
        self.assertIn("zero_length_record", empty["parsed_view"]["anomalies"])

        self.assertEqual(terminated["raw"]["declared_length"], 2)
        self.assertEqual(terminated["parsed_view"]["restoration"], RESTORED)
        self.assertTrue(terminated["parsed_view"]["round_trip_verified"])
        self.assertEqual(terminated["parsed_view"]["anomalies"], [])

    def test_well_formed_string_is_restored_with_matching_hash(self):
        builder = SyntheticHive("RootKey", "EVIDENCE_STRINGS")
        raw = u"evidence text".encode("utf-16-le") + NUL2
        builder.add_value("good", Registry.RegSZ, raw)
        entry = index_entries(evidence_for(builder))["good"]
        self.assertEqual(entry["parsed_view"]["restoration"], RESTORED)
        self.assertEqual(entry["parsed_view"]["value"], u"evidence text")
        self.assertEqual(entry["raw"]["hex"], raw.hex())
        self.assertEqual(entry["raw"]["sha256"],
                         hashlib.sha256(raw).hexdigest())
        self.assertEqual(entry["raw"]["observed_length"], len(raw))

    def test_missing_terminator_is_range_only(self):
        builder = SyntheticHive("RootKey", "EVIDENCE_STRINGS")
        raw = u"dangling".encode("utf-16-le")
        builder.add_value("no_terminator", Registry.RegSZ, raw)
        entry = index_entries(evidence_for(builder))["no_terminator"]
        self.assertEqual(entry["parsed_view"]["restoration"], RANGE_ONLY)
        self.assertIn("missing_terminator", entry["parsed_view"]["anomalies"])
        self.assertFalse(entry["parsed_view"]["round_trip_verified"])
        # The observed range is still fully reported for independent review.
        self.assertEqual(entry["raw"]["hex"], raw.hex())
        self.assertEqual(entry["reader_view"]["value"], u"dangling")

    def test_odd_byte_length_is_range_only(self):
        builder = SyntheticHive("RootKey", "EVIDENCE_STRINGS")
        builder.add_value("odd", Registry.RegSZ, b"abc", declared_length=3)
        entry = index_entries(evidence_for(builder))["odd"]
        self.assertEqual(entry["raw"]["declared_length"], 3)
        self.assertEqual(entry["parsed_view"]["restoration"], RANGE_ONLY)
        self.assertIn("odd_byte_length", entry["parsed_view"]["anomalies"])


class SameDisplayDifferentTypeTests(unittest.TestCase):
    def test_same_display_string_and_number_trace_to_distinct_types(self):
        builder = SyntheticHive("RootKey", "EVIDENCE_TYPES")
        string_raw = u"42".encode("utf-16-le") + NUL2
        dword_raw = struct.pack("<I", 42)
        binary_raw = struct.pack("<I", 42)
        builder.add_value("as_string", Registry.RegSZ, string_raw)
        builder.add_value("as_dword", Registry.RegDWord, dword_raw)
        builder.add_value("as_binary", Registry.RegBin, binary_raw)

        hive, _data = build_and_open(builder)
        values = dict((v.name(), v.value()) for v in hive.root().values())
        # All three present the same logical payload to a downstream consumer.
        self.assertEqual(values["as_string"], u"42")
        self.assertEqual(values["as_dword"], 42)
        self.assertEqual(values["as_binary"], binary_raw)

        entries = index_entries(evidence_for(builder))
        self.assertEqual(entries["as_string"]["declared_type"]["code"], Registry.RegSZ)
        self.assertEqual(entries["as_dword"]["declared_type"]["code"], Registry.RegDWord)
        self.assertEqual(entries["as_binary"]["declared_type"]["code"], Registry.RegBin)

        self.assertEqual(entries["as_string"]["raw"]["declared_length"], 6)
        self.assertEqual(entries["as_dword"]["raw"]["declared_length"], 4)
        self.assertEqual(entries["as_binary"]["raw"]["declared_length"], 4)
        # The dword and binary share bytes but never share a type conclusion.
        self.assertEqual(entries["as_dword"]["raw"]["hex"],
                         entries["as_binary"]["raw"]["hex"])
        self.assertNotEqual(entries["as_dword"]["declared_type"]["name"],
                            entries["as_binary"]["declared_type"]["name"])
        self.assertEqual(entries["as_dword"]["parsed_view"]["restoration"], RESTORED)
        self.assertEqual(entries["as_binary"]["parsed_view"]["restoration"], RAW_CARRY)

    def test_dword_with_wrong_declared_length_is_range_only(self):
        builder = SyntheticHive("RootKey", "EVIDENCE_TYPES")
        builder.add_value("short_dword", Registry.RegDWord,
                          struct.pack("<I", 7), declared_length=2)
        entry = index_entries(evidence_for(builder))["short_dword"]
        self.assertEqual(entry["raw"]["declared_length"], 2)
        self.assertEqual(entry["parsed_view"]["restoration"], RANGE_ONLY)
        self.assertTrue(
            any("expected_4" in note for note in entry["parsed_view"]["anomalies"]))
        # The reader still repairs a number; the evidence flags the disagreement.
        self.assertEqual(entry["reader_view"]["value"], 7)


class MultiStringAndBinaryTests(unittest.TestCase):
    def test_multi_sz_round_trip_and_missing_terminator(self):
        builder = SyntheticHive("RootKey", "EVIDENCE_MULTI")
        good = SyntheticHive.multi_sz([u"alpha", u"beta"])
        builder.add_value("good_multi", Registry.RegMultiSZ, good)
        no_term = u"alpha\x00beta".encode("utf-16-le")
        builder.add_value("no_term_multi", Registry.RegMultiSZ, no_term)
        entries = index_entries(evidence_for(builder))
        self.assertEqual(entries["good_multi"]["parsed_view"]["restoration"], RESTORED)
        self.assertEqual(entries["good_multi"]["parsed_view"]["value"],
                         [u"alpha", u"beta"])
        self.assertEqual(entries["no_term_multi"]["parsed_view"]["restoration"],
                         RANGE_ONLY)
        self.assertIn("missing_terminator",
                      entries["no_term_multi"]["parsed_view"]["anomalies"])

    def test_empty_binary_and_none_are_empty_records(self):
        builder = SyntheticHive("RootKey", "EVIDENCE_BIN")
        builder.add_value("empty_bin", Registry.RegBin, b"")
        builder.add_value("empty_none", Registry.RegNone, b"")
        entries = index_entries(evidence_for(builder))
        for name in ("empty_bin", "empty_none"):
            self.assertEqual(entries[name]["raw"]["declared_length"], 0)
            self.assertEqual(entries[name]["parsed_view"]["restoration"],
                             EMPTY_RECORD)

    def test_qword_restoration(self):
        builder = SyntheticHive("RootKey", "EVIDENCE_NUM")
        raw = struct.pack("<Q", 0x0102030405060708)
        builder.add_value("q", Registry.RegQWord, raw)
        entry = index_entries(evidence_for(builder))["q"]
        self.assertEqual(entry["parsed_view"]["restoration"], RESTORED)
        self.assertEqual(entry["parsed_view"]["value"], 0x0102030405060708)
        self.assertEqual(entry["raw"]["hex"], raw.hex())


class StructureAndSerializationTests(unittest.TestCase):
    def test_subkey_path_is_recorded(self):
        builder = SyntheticHive("RootKey", "EVIDENCE_PATHS")
        builder.add_key_value("Nested", "v", Registry.RegDWord, struct.pack("<I", 1))
        report = evidence_for(builder)
        nested = [e for e in report["values"] if e["value_name"] == "v"][0]
        self.assertTrue(nested["key_path"].endswith(u"Nested"))
        self.assertEqual(nested["declared_type"]["code"], Registry.RegDWord)

    def test_json_document_is_valid_and_self_describing(self):
        builder = SyntheticHive("RootKey", "EVIDENCE_JSON")
        builder.add_value("s", Registry.RegSZ,
                          u"x".encode("utf-16-le") + NUL2)
        _hive, data = build_and_open(builder)
        text = export_evidence_json(io.BytesIO(data))
        import json
        document = json.loads(text)
        self.assertEqual(document["schema_version"], 1)
        self.assertEqual(document["source"]["sha256"],
                         hashlib.sha256(data).hexdigest())
        self.assertEqual(document["value_count"], len(document["values"]))

    def test_export_does_not_modify_the_hive(self):
        builder = SyntheticHive("RootKey", "EVIDENCE_READONLY")
        builder.add_value("s", Registry.RegSZ,
                          u"keep".encode("utf-16-le") + NUL2)
        data = builder.build()
        fd, path = tempfile.mkstemp(prefix="evidence_", suffix=".hive")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
            with open(path, "rb") as handle:
                before = handle.read()
            export_evidence(path)
            with open(path, "rb") as handle:
                after = handle.read()
            self.assertEqual(before, after)
        finally:
            os.remove(path)


if __name__ == "__main__":
    unittest.main()
