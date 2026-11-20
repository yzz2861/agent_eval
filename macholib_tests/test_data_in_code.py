import hashlib
import json
import os
import tempfile

from macholib import MachO, mach_o
from macholib.data_in_code import build_evidence_manifest
from macholib_tests.samples.dual_slice_data_in_code import (
    build_dual_slice_sample,
)

try:
    import unittest
except ImportError:
    import unittest2 as unittest


class TestDataInCodeEvidence(unittest.TestCase):
    def write_sample(self, image):
        handle, path = tempfile.mkstemp(suffix=".macho")
        with os.fdopen(handle, "wb") as output:
            output.write(image)
        self.addCleanup(os.unlink, path)
        return path

    def manifest(self, path):
        return build_evidence_manifest(path)

    @staticmethod
    def covers(region, relative_offset):
        return (
            region["slice_file_offset"]
            <= relative_offset
            < region["slice_file_offset"] + region["length"]
        )

    def test_data_in_code_entry_has_on_disk_layout(self):
        self.assertEqual(mach_o.data_in_code_entry._size_, 8)
        self.assertEqual(
            mach_o.DATA_IN_CODE_KINDS[mach_o.DICE_KIND_JUMP_TABLE32],
            "DICE_KIND_JUMP_TABLE32",
        )

    def test_two_slices_get_independent_interpretations(self):
        path = self.write_sample(build_dual_slice_sample())
        manifest = self.manifest(path)

        self.assertEqual(manifest["slice_count"], 2)
        self.assertTrue(manifest["read_only"])
        self.assertEqual(manifest["slices"][0]["file_offset"], 0x1000)
        self.assertEqual(manifest["slices"][1]["file_offset"], 0x2000)
        self.assertEqual(manifest["slices"][0]["endian"], ">")
        self.assertEqual(manifest["slices"][1]["endian"], "<")

        recorded_slice = manifest["slices"][0]
        candidate_slice = manifest["slices"][1]
        self.assertTrue(recorded_slice["data_in_code"]["present"])
        self.assertFalse(candidate_slice["data_in_code"]["present"])

        relative_offset = 0x104
        self.assertTrue(
            any(
                self.covers(region, relative_offset)
                for region in recorded_slice["data_regions"]
            )
        )
        self.assertTrue(
            any(
                self.covers(candidate, relative_offset)
                for candidate in candidate_slice["instruction_candidates"]
            )
        )
        self.assertFalse(
            any(
                self.covers(region, relative_offset)
                for region in candidate_slice["data_regions"]
            )
        )

    def test_records_have_file_offsets_and_virtual_addresses(self):
        path = self.write_sample(build_dual_slice_sample())
        manifest = self.manifest(path)
        slice_data = manifest["slices"][0]
        record = slice_data["records"][0]

        self.assertEqual(record["offset"], 0x100)
        self.assertEqual(record["length"], 0x10)
        self.assertEqual(record["kind"], mach_o.DICE_KIND_JUMP_TABLE32)
        self.assertEqual(record["slice_file_offset"], 0x100)
        self.assertEqual(record["file_offset"], 0x1000 + 0x100)
        self.assertEqual(record["virtual_address"], 0x100000100)
        self.assertLess(record["record_file_offset"], 0x1000 + record["file_offset"])
        self.assertEqual(
            record["record_file_offset"],
            slice_data["data_in_code"]["commands"][0]["table_file_offset"],
        )

        for region in slice_data["data_regions"]:
            self.assertIn("file_offset", region)
            self.assertIn("virtual_address", region)
            self.assertIsNotNone(region["file_offset"])
            self.assertIsNotNone(region["virtual_address"])

    def test_conflicts_trace_back_to_raw_records(self):
        path = self.write_sample(build_dual_slice_sample())
        manifest = self.manifest(path)
        conflicts = manifest["slices"][0]["conflicts"]

        overlap = [
            item
            for item in conflicts
            if item["category"] == "overlapping_data_in_code_records"
        ]
        self.assertEqual(len(overlap), 1)
        self.assertEqual(
            overlap[0]["record_ids"],
            [
                "slice:0/data-in-code:1/entry:0",
                "slice:0/data-in-code:1/entry:1",
            ],
        )
        self.assertEqual(len(overlap[0]["records"]), 2)
        for source in overlap[0]["records"]:
            self.assertIsInstance(source["record_file_offset"], int)
            self.assertIn("offset", source)
            self.assertIn("length", source)
            self.assertIn("kind", source)

        symbol_conflict = [
            item
            for item in conflicts
            if item["category"] == "symbol_inside_data_region"
        ]
        self.assertTrue(symbol_conflict)
        self.assertEqual(
            symbol_conflict[0]["symbol_id"],
            "slice:0/symtab:2/symbol:1",
        )
        self.assertEqual(
            symbol_conflict[0]["record_ids"],
            ["slice:0/data-in-code:1/entry:0"],
        )

    def test_unknown_kind_is_not_data_or_confirmed_instruction(self):
        image = build_dual_slice_sample(slice0_entries=((0x100, 0x10, 0x7777),))
        path = self.write_sample(image)
        slice_data = self.manifest(path)["slices"][0]

        self.assertEqual(slice_data["data_regions"], [])
        self.assertEqual(len(slice_data["unresolved"]), 1)
        unresolved = slice_data["unresolved"][0]
        self.assertEqual(unresolved["status"], "unresolved")
        self.assertFalse(unresolved["known_kind"])
        self.assertEqual(
            unresolved["record"]["kind_name"],
            None,
        )
        self.assertTrue(
            all(
                not self.covers(candidate, 0x104)
                for candidate in slice_data["instruction_candidates"]
            )
        )
        self.assertTrue(
            all(
                candidate["confirmed_instruction"] is False
                for candidate in slice_data["instruction_candidates"]
            )
        )

    def test_missing_table_leaves_only_instruction_candidates(self):
        path = self.write_sample(build_dual_slice_sample())
        slice_data = self.manifest(path)["slices"][1]

        self.assertTrue(slice_data["data_in_code"]["missing"])
        self.assertEqual(slice_data["data_regions"], [])
        self.assertTrue(slice_data["instruction_candidates"])
        for candidate in slice_data["instruction_candidates"]:
            self.assertEqual(candidate["status"], "instruction_candidate")
            self.assertFalse(candidate["confirmed_instruction"])
            self.assertIn("data_in_code_table_missing", candidate["evidence"])

    def test_little_endian_slice_parses_records(self):
        image = build_dual_slice_sample(
            slice0_entries=((0x100, 0x10, mach_o.DICE_KIND_JUMP_TABLE32),),
            slice1_entries=((0x100, 0x08, mach_o.DICE_KIND_DATA),),
        )
        path = self.write_sample(image)
        manifest = self.manifest(path)

        slice0_record = manifest["slices"][0]["records"][0]
        slice1_record = manifest["slices"][1]["records"][0]
        self.assertEqual(slice0_record["offset"], 0x100)
        self.assertEqual(slice1_record["offset"], 0x100)
        self.assertEqual(slice0_record["kind"], mach_o.DICE_KIND_JUMP_TABLE32)
        self.assertEqual(slice1_record["kind"], mach_o.DICE_KIND_DATA)
        self.assertEqual(slice1_record["file_offset"], 0x2000 + 0x100)

    def test_existing_enumeration_and_json_remain_available(self):
        path = self.write_sample(build_dual_slice_sample())
        macho = MachO.MachO(path)
        self.assertEqual(len(macho.headers[0].commands), 3)
        for load_command, _command, _data in macho.headers[0].commands:
            self.assertIsInstance(load_command.cmd, int)

        manifest = macho.build_data_in_code_manifest()
        self.assertEqual(len(manifest.slices), 2)
        json.dumps(manifest)

        header_manifest = macho.headers[0].build_data_in_code_manifest()
        self.assertEqual(len(header_manifest["slices"]), 1)
        self.assertEqual(header_manifest["slices"][0]["slice_index"], 0)

    def test_manifest_build_is_read_only(self):
        path = self.write_sample(build_dual_slice_sample())
        before = hashlib.sha256(open(path, "rb").read()).hexdigest()
        self.manifest(path)
        after = hashlib.sha256(open(path, "rb").read()).hexdigest()
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
