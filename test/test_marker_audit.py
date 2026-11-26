import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

import marker_audit  # noqa: E402
from examples.marker_attribution import build_demo  # noqa: E402


class MarkerAuditTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        temp_path = Path(cls.temp.name)
        cls.program_a = temp_path / "program_a.elf"
        cls.program_b = temp_path / "program_b.elf"
        build_demo.inject_note_section(
            build_demo.PROGRAM_A_SOURCE, cls.program_a, build_demo.A_NOTES
        )
        build_demo.inject_note_section(
            build_demo.PROGRAM_B_SOURCE, cls.program_b, build_demo.B_NOTES
        )
        cls.manifest = build_demo.build_manifest()
        cls.report = marker_audit.audit_paths(
            [cls.program_a, cls.program_b],
            cls.manifest,
            include_symbols=False,
        )

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_report_classifies_all_expected_occurrences(self):
        summary = self.report["summary"]
        self.assertEqual(summary["occurrence_count"], 12)
        self.assertEqual(summary["approved_occurrence_count"], 6)
        self.assertEqual(summary["duplicate_name_group_count"], 2)
        self.assertEqual(summary["unmapped_occurrence_count"], 2)
        self.assertEqual(summary["undeclared_occurrence_count"], 2)

    def test_approved_coordinates_map_to_file_offsets(self):
        approved_ids = set(self.report["categories"]["approved_before_release"])
        approved = [
            item
            for item in self.report["occurrences"]
            if item["occurrence_id"] in approved_ids
        ]
        self.assertEqual(
            {item["marker"] for item in approved},
            {"boot.attested", "heartbeat", "trace.flush", "release.gate"},
        )
        boot = next(
            item
            for item in approved
            if item["marker"] == "boot.attested" and item["artifact"] == "program_a.elf"
        )
        self.assertTrue(boot["mapping"]["file_mapped"])
        self.assertEqual(boot["mapping"]["section"], ".text")
        self.assertEqual(boot["mapping"]["file_offset"], 0x420)

    def test_duplicate_names_keep_distinct_providers_and_locations(self):
        groups = {
            group["marker"]: group
            for group in self.report["categories"]["same_name_different_locations"]
        }
        self.assertEqual(set(groups), {"heartbeat", "trace.flush"})
        self.assertEqual(
            groups["heartbeat"]["providers"],
            ["acme.observability", "beta.driver"],
        )
        self.assertEqual(groups["heartbeat"]["location_count"], 2)
        self.assertTrue(groups["heartbeat"]["within_artifact_duplicate"])
        self.assertEqual(groups["trace.flush"]["location_count"], 2)

    def test_unmapped_includes_absent_and_nobits_addresses(self):
        unmapped = {
            item["marker"]: item["mapping"]["reason"]
            for item in self.report["categories"]["addresses_without_file_mapping"]
        }
        self.assertEqual(unmapped["telemetry.dma"], "address_outside_all_mappings")
        self.assertEqual(unmapped["runtime.watermark"], "zero_fill_only")

    def test_undeclared_markers_remain_separate(self):
        undeclared = {
            item["marker"] for item in self.report["categories"]["undeclared_markers"]
        }
        self.assertEqual(undeclared, {"shadow.event", "debug.probe"})

    def test_comparison_distinguishes_unambiguous_approvals(self):
        comparison = self.report["comparison"]
        self.assertEqual(
            comparison["approved_markers"],
            ["boot.attested", "heartbeat", "release.gate", "trace.flush"],
        )
        self.assertEqual(
            comparison["unambiguous_approved_markers"],
            ["boot.attested", "release.gate"],
        )

    def test_obs1_binary_descriptor(self):
        payload = (
            marker_audit.struct.pack("<4sBBBBQ", b"OBS1", 1, 4, 4, 0, 0x1234)
            + b"bootacme"
        )
        parsed = marker_audit.parse_obs1_descriptor(payload)
        self.assertEqual(parsed["name"], "boot")
        self.assertEqual(parsed["provider"], "acme")
        self.assertEqual(parsed["address"], 0x1234)

    def test_json_manifest_file_roundtrip(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            manifest_path = Path(temp_dir) / "manifest.json"
            manifest_path.write_text(json.dumps(self.manifest), encoding="utf-8")
            loaded = marker_audit.load_manifest(manifest_path)
            self.assertEqual(len(loaded["records"]), len(self.manifest["markers"]))


if __name__ == "__main__":
    unittest.main()
