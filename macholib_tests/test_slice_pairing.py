import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest

from macholib import slice_pairing
from macholib.MachO import MachO
from macholib.mach_o import (
    CPU_TYPE_NAMES,
    LC_UUID,
    mach_header,
    mach_header_64,
)
from macholib.ptypes import sizeof
from macholib_tests.slice_pairing_samples import (
    CPU_TYPE_ARM64,
    CPU_TYPE_POWERPC,
    CPU_TYPE_X86_64,
    SUBTYPE_ARM64_ALL,
    SUBTYPE_POWERPC_ALL,
    SUBTYPE_X86_64_ALL,
    UUID_ARM64,
    UUID_REPLACEMENT,
    UUID_X86_64,
    build_release_materials,
    lc_uuid,
    lc_unknown,
    pack_fat_macho,
    pack_thin_macho,
)

if sys.version_info[:2] <= (2, 6):
    import unittest2 as unittest


def _uuid_text(raw_uuid):
    return slice_pairing._uuid_details(raw_uuid)["uuid"]


def _finding_paths(finding):
    paths = []
    if finding.get("path"):
        paths.append(finding["path"])
    for related in finding.get("related") or []:
        if isinstance(related, dict) and related.get("path"):
            paths.append(related["path"])
    return paths


def _group_paths(groups):
    return [
        member["path"]
        for group in groups
        for member in group.get("members", [])
    ]


class SlicePairingTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="macholib-slice-pairing-")
        self.addCleanup(shutil.rmtree, self.root)

    def _materialize(self, **kwargs):
        return build_release_materials(self.root, **kwargs)

    def _audit(self, materials, **kwargs):
        return slice_pairing.build_pairing_report(
            universal=materials["universal"],
            archive=materials["archive"],
            debug=materials["debug"],
            **kwargs
        )

    def test_complete_materials_have_two_unique_correspondences(self):
        materials = self._materialize()
        report = self._audit(materials)

        self.assertEqual(report["summary"]["unique_count"], 2)
        self.assertEqual(report["summary"]["duplicate_count"], 0)
        self.assertEqual(report["summary"]["incomplete_count"], 0)
        self.assertEqual(report["summary"]["unmatched_count"], 0)
        self.assertEqual(report["summary"]["problem_count"], 0)
        self.assertTrue(report["summary"]["all_complete"])

        identities = set()
        for group in report["unique"]:
            self.assertEqual(group["counts"]["universal"], 1)
            self.assertEqual(group["counts"]["archive"], 1)
            self.assertEqual(group["counts"]["debug"], 1)
            self.assertEqual(len(group["members"]), 3)
            identities.add(
                (
                    group["identity"]["uuid"],
                    group["identity"]["cputype"],
                    group["identity"]["cpusubtype"],
                )
            )
        self.assertEqual(
            identities,
            {
                (_uuid_text(UUID_ARM64), CPU_TYPE_ARM64, SUBTYPE_ARM64_ALL),
                (_uuid_text(UUID_X86_64), CPU_TYPE_X86_64, SUBTYPE_X86_64_ALL),
            },
        )

    def test_command_provenance_keeps_file_and_offsets(self):
        path = os.path.join(self.root, "archive", "offset.bin")
        command_bytes = [
            lc_unknown(),
            lc_uuid(UUID_ARM64),
        ]
        data = pack_thin_macho(commands=command_bytes)
        os.makedirs(os.path.dirname(path))
        with open(path, "wb") as fp:
            fp.write(data)

        records = slice_pairing.read_slices(path, "archive")
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record["status"], "ok")
        self.assertEqual(record["uuid"], _uuid_text(UUID_ARM64))
        self.assertEqual(record["command_count"], 2)

        header_size = sizeof(mach_header_64)
        first, second = record["commands"]
        self.assertEqual(first["command_index"], 0)
        self.assertEqual(first["cmd"], 0x707A11ED)
        self.assertEqual(first["cmdsize"], 12)
        self.assertEqual(first["slice_offset"], header_size)
        self.assertEqual(first["file_offset"], header_size)
        self.assertEqual(second["command_index"], 1)
        self.assertEqual(second["cmd"], LC_UUID)
        self.assertEqual(second["slice_offset"], header_size + 12)
        self.assertEqual(second["file_offset"], header_size + 12)
        self.assertEqual(second["uuid"], _uuid_text(UUID_ARM64))
        self.assertEqual(second["uuid_slice_offset"], header_size + 20)
        self.assertEqual(second["uuid_file_offset"], header_size + 20)

        report = slice_pairing.build_pairing_report(materials={"archive": path})
        self.assertEqual(len(report["commands"]), 2)
        for command in report["commands"]:
            self.assertEqual(command["path"], path)
            self.assertEqual(command["kind"], "archive")
            self.assertEqual(command["slice_index"], 0)
        self.assertEqual(report["uuid_commands"][0]["path"], path)

    def test_fat_slice_command_offsets_are_absolute(self):
        materials = self._materialize()
        records = slice_pairing.read_slices(materials["universal"], "universal")
        self.assertEqual(len(records), 2)
        for record in records:
            self.assertEqual(record["container"], "fat")
            self.assertGreater(record["file_offset"], 0)
            uuid_command = record["commands"][0]
            self.assertEqual(uuid_command["cmd"], LC_UUID)
            self.assertEqual(
                uuid_command["file_offset"],
                record["file_offset"] + sizeof(mach_header_64),
            )
            self.assertEqual(
                uuid_command["uuid_file_offset"],
                uuid_command["file_offset"] + 8,
            )

    def test_swapped_uuid_points_at_the_archive(self):
        materials = self._materialize(swap="uuid")
        bad_archive = materials["archive"][0]
        report = self._audit(materials)

        mismatches = [
            finding
            for finding in report["problems"]
            if finding["code"] == "identity_mismatch"
        ]
        self.assertEqual(len(mismatches), 1)
        mismatch = mismatches[0]
        self.assertEqual(mismatch["path"], bad_archive)
        self.assertEqual(mismatch["kind"], "archive")
        self.assertEqual(mismatch["expected_uuid"], _uuid_text(UUID_ARM64))
        self.assertEqual(
            mismatch["actual_uuid"], _uuid_text(UUID_REPLACEMENT)
        )
        self.assertIn(
            materials["universal"],
            [related["path"] for related in mismatch["related"]],
        )

        self.assertIn(bad_archive, _group_paths(report["unmatched"]))
        self.assertIn(bad_archive, _finding_paths(mismatch))
        self.assertFalse(report["summary"]["all_complete"])

    def test_expected_kinds_turns_a_missing_archive_into_coverage_gap(self):
        materials = self._materialize(swap="uuid")
        report = self._audit(
            materials,
            expected_kinds=("universal", "archive", "debug"),
        )
        missing_groups = [
            group
            for group in report["unmatched"]
            if group["missing_required_kinds"]
        ]
        self.assertTrue(missing_groups)
        self.assertTrue(
            any(
                "archive" in group["missing_required_kinds"]
                for group in missing_groups
            )
        )
        self.assertIn(materials["archive"][0], _group_paths(report["unmatched"]))

    def test_truncated_uuid_is_incomplete_not_unmatched(self):
        materials = self._materialize(swap="truncate")
        bad_archive = materials["archive"][0]
        report = self._audit(materials)

        incomplete_paths = [entry["path"] for entry in report["incomplete"]]
        self.assertIn(bad_archive, incomplete_paths)
        entry = [e for e in report["incomplete"] if e["path"] == bad_archive][0]
        self.assertEqual(entry["status"], "incomplete")
        self.assertIsNone(entry["uuid"])
        codes = {issue["code"] for issue in entry["issues"]}
        self.assertIn("truncated_uuid", codes)
        uuid_command = entry["commands"][0]
        self.assertEqual(uuid_command["uuid"], None)
        self.assertEqual(
            uuid_command["uuid_slice_offset"], sizeof(mach_header_64) + 8
        )
        self.assertEqual(
            uuid_command["uuid_file_offset"], sizeof(mach_header_64) + 8
        )

        counterpart = [
            finding
            for finding in report["problems"]
            if finding["code"] == "incomplete_counterpart"
            and finding["path"] == bad_archive
        ]
        self.assertEqual(len(counterpart), 1)
        self.assertIn(bad_archive, _finding_paths(counterpart[0]))
        self.assertNotIn(
            bad_archive,
            [
                member["path"]
                for group in report["unique"]
                for member in group["members"]
            ],
        )

    def test_missing_uuid_is_reported_without_guessing(self):
        materials = self._materialize(swap="no_uuid")
        bad_archive = materials["archive"][0]
        report = self._audit(materials)
        entry = [e for e in report["incomplete"] if e["path"] == bad_archive][0]
        self.assertEqual(entry["status"], "unidentified")
        self.assertIn(
            "missing_lc_uuid", {issue["code"] for issue in entry["issues"]}
        )
        self.assertIsNone(entry["uuid"])

    def test_duplicate_archive_identity_is_not_consumed_by_input_order(self):
        materials = self._materialize(duplicate_archives=True)
        report_a = self._audit(materials)
        report_b = slice_pairing.build_pairing_report(
            universal=materials["universal"],
            archive=list(reversed(materials["archive"])),
            debug=list(reversed(materials["debug"])),
        )
        self.assertEqual(report_a, report_b)

        duplicate_groups = [
            group
            for group in report_a["duplicates"]
            if group.get("reason") == "duplicate_material_kind"
        ]
        self.assertEqual(len(duplicate_groups), 1)
        duplicate = duplicate_groups[0]
        self.assertIn("archive", duplicate["duplicate_kinds"])
        self.assertEqual(
            {
                member["path"]
                for member in duplicate["members"]
                if member["kind"] == "archive"
            },
            {materials["archive"][0], materials["archive"][2]},
        )
        self.assertFalse(
            any(
                finding["code"] == "identity_mismatch"
                for finding in report_a["problems"]
            )
        )

    def test_input_order_does_not_change_the_report(self):
        materials = self._materialize()
        report_a = self._audit(materials)
        report_b = slice_pairing.build_pairing_report(
            universal=materials["universal"],
            archive=list(reversed(materials["archive"])),
            debug=list(reversed(materials["debug"])),
        )
        self.assertEqual(report_a, report_b)

    def test_directory_inputs_match_explicit_files(self):
        materials = self._materialize()
        explicit = self._audit(materials)
        from_directories = slice_pairing.build_pairing_report(
            universal=materials["universal"],
            archive=os.path.dirname(materials["archive"][0]),
            debug=os.path.dirname(materials["debug"][0]),
        )
        self.assertEqual(explicit, from_directories)

    def test_multiple_uuid_commands_do_not_use_the_first_one(self):
        path = os.path.join(self.root, "archive", "two-uuids.bin")
        data = pack_thin_macho(
            commands=[
                lc_uuid(UUID_ARM64),
                lc_uuid(UUID_REPLACEMENT),
            ]
        )
        os.makedirs(os.path.dirname(path))
        with open(path, "wb") as fp:
            fp.write(data)

        record = slice_pairing.read_slices(path, "archive")[0]
        self.assertEqual(record["status"], "ambiguous")
        self.assertIsNone(record["uuid"])
        self.assertEqual(
            record["uuid_candidates"],
            [_uuid_text(UUID_ARM64), _uuid_text(UUID_REPLACEMENT)],
        )
        self.assertEqual(
            [command["uuid"] for command in record["commands"]],
            [_uuid_text(UUID_ARM64), _uuid_text(UUID_REPLACEMENT)],
        )

        report = slice_pairing.build_pairing_report(materials={"archive": path})
        self.assertEqual(
            [entry["reason"] for entry in report["duplicates"]],
            ["multiple_lc_uuid_commands"],
        )
        self.assertEqual(
            [finding["code"] for finding in report["problems"]],
            ["ambiguous_uuid_commands"],
        )

    def test_fat_arch_cpu_mismatch_is_incomplete(self):
        materials = self._materialize(swap="fat_arch_cpu")
        report = self._audit(materials)
        universal_incomplete = [
            entry
            for entry in report["incomplete"]
            if entry["path"] == materials["universal"]
        ]
        self.assertEqual(len(universal_incomplete), 1)
        codes = {
            issue["code"] for issue in universal_incomplete[0]["issues"]
        }
        self.assertIn("fat_arch_cpu_mismatch", codes)
        self.assertFalse(report["summary"]["all_complete"])

    def test_big_endian_32_bit_header(self):
        path = os.path.join(self.root, "archive", "ppc.bin")
        data = pack_thin_macho(
            UUID_ARM64,
            CPU_TYPE_POWERPC,
            SUBTYPE_POWERPC_ALL,
            endian=">",
            bits=32,
        )
        os.makedirs(os.path.dirname(path))
        with open(path, "wb") as fp:
            fp.write(data)

        record = slice_pairing.read_slices(path, "archive")[0]
        self.assertEqual(record["status"], "ok")
        self.assertEqual(record["bits"], 32)
        self.assertEqual(record["endian"], ">")
        self.assertEqual(record["cputype"], CPU_TYPE_POWERPC)
        self.assertEqual(record["cpusubtype"], SUBTYPE_POWERPC_ALL)
        self.assertEqual(record["uuid"], _uuid_text(UUID_ARM64))
        self.assertEqual(
            record["commands"][0]["slice_offset"], sizeof(mach_header)
        )
        self.assertEqual(
            record["cputype_name"],
            CPU_TYPE_NAMES.get(CPU_TYPE_POWERPC, str(CPU_TYPE_POWERPC)),
        )

    def test_fat_magic_64_container(self):
        materials = self._materialize(fat64=True)
        report = self._audit(materials)
        self.assertEqual(report["summary"]["unique_count"], 2)
        self.assertTrue(report["summary"]["all_complete"])
        universal_slices = [
            record
            for record in report["slices"]
            if record["kind"] == "universal"
        ]
        self.assertEqual(len(universal_slices), 2)
        self.assertTrue(all(record["status"] == "ok" for record in universal_slices))

    def test_swapped_fat_magic_is_still_understood(self):
        arm64 = pack_thin_macho(UUID_ARM64, CPU_TYPE_ARM64, SUBTYPE_ARM64_ALL)
        x86_64 = pack_thin_macho(
            UUID_X86_64, CPU_TYPE_X86_64, SUBTYPE_X86_64_ALL
        )
        data = pack_fat_macho(
            [
                {
                    "cputype": CPU_TYPE_ARM64,
                    "cpusubtype": SUBTYPE_ARM64_ALL,
                    "blob": arm64,
                },
                {
                    "cputype": CPU_TYPE_X86_64,
                    "cpusubtype": SUBTYPE_X86_64_ALL,
                    "blob": x86_64,
                },
            ],
            endian="<",
        )
        path = os.path.join(self.root, "universal-cigam.bin")
        with open(path, "wb") as fp:
            fp.write(data)

        records = slice_pairing.read_slices(path, "universal")
        self.assertEqual(len(records), 2)
        self.assertEqual(
            [record["uuid"] for record in records],
            [_uuid_text(UUID_ARM64), _uuid_text(UUID_X86_64)],
        )

    def test_audit_is_read_only(self):
        materials = self._materialize()
        paths = [materials["universal"]]
        paths.extend(materials["archive"])
        paths.extend(materials["debug"])

        def digest(path):
            with open(path, "rb") as fp:
                return hashlib.sha256(fp.read()).hexdigest()

        before = {path: digest(path) for path in paths}
        self._audit(materials)
        after = {path: digest(path) for path in paths}
        self.assertEqual(before, after)

    def test_report_is_json_serializable(self):
        materials = self._materialize(swap="uuid")
        report = self._audit(materials)
        encoded = json.dumps(report)
        decoded = json.loads(encoded)
        self.assertEqual(decoded["summary"], dict(report["summary"]))

    def test_aliases_and_command_omission(self):
        materials = self._materialize()
        audit = slice_pairing.audit_slices(
            universal=materials["universal"],
            archive=materials["archive"],
            debug=materials["debug"],
        )
        paired = slice_pairing.pair_slices(
            universal=materials["universal"],
            archive=materials["archive"],
            debug=materials["debug"],
        )
        self.assertEqual(audit, paired)

        compact = self._audit(materials, include_commands=False)
        self.assertEqual(compact["commands"], [])
        self.assertEqual(compact["uuid_commands"], [])
        self.assertNotIn("commands", compact["slices"][0])

    def test_cpu_only_swap_still_points_at_the_archive(self):
        materials = self._materialize(swap="cpu")
        bad_archive = materials["archive"][0]
        report = self._audit(materials)
        problem_paths = _group_paths(report["unmatched"] + report["duplicates"])
        self.assertIn(bad_archive, problem_paths)
        self.assertTrue(
            any(
                bad_archive in _finding_paths(finding)
                for finding in report["problems"]
            )
        )
        self.assertFalse(report["summary"]["all_complete"])

    def test_same_uuid_with_two_cpus_is_a_duplicate_identity(self):
        materials = self._materialize(swap="uuid_conflict")
        bad_archive = materials["archive"][1]
        report = self._audit(materials)

        conflicts = [
            finding
            for finding in report["problems"]
            if finding["code"] == "uuid_cpu_conflict"
        ]
        self.assertEqual(len(conflicts), 1)
        self.assertIn(bad_archive, conflicts[0]["paths"])
        self.assertGreaterEqual(report["summary"]["duplicate_count"], 1)
        self.assertNotIn(bad_archive, _group_paths(report["unique"]))
        self.assertFalse(report["summary"]["all_complete"])

    def test_majority_uuid_points_at_a_bad_universal_slice(self):
        materials = self._materialize(swap="universal_uuid")
        report = self._audit(materials)
        mismatches = [
            finding
            for finding in report["problems"]
            if finding["code"] == "identity_mismatch"
        ]
        self.assertEqual(len(mismatches), 1)
        mismatch = mismatches[0]
        self.assertEqual(mismatch["path"], materials["universal"])
        self.assertEqual(mismatch["slice_index"], 0)
        self.assertEqual(mismatch["expected_uuid"], _uuid_text(UUID_ARM64))
        self.assertEqual(
            mismatch["actual_uuid"], _uuid_text(UUID_REPLACEMENT)
        )

    def test_macho_header_uuid_helpers_do_not_pick_a_first_command(self):
        single_path = os.path.join(self.root, "archive", "single.bin")
        double_path = os.path.join(self.root, "archive", "double.bin")
        os.makedirs(os.path.dirname(single_path))
        with open(single_path, "wb") as fp:
            fp.write(pack_thin_macho(UUID_ARM64))
        with open(double_path, "wb") as fp:
            fp.write(
                pack_thin_macho(
                    commands=[
                        lc_uuid(UUID_ARM64),
                        lc_uuid(UUID_REPLACEMENT),
                    ]
                )
            )

        single = MachO(single_path)
        self.assertEqual(len(single.headers[0].getUUIDCommands()), 1)
        self.assertEqual(single.headers[0].getUUID(), UUID_ARM64)

        double = MachO(double_path)
        self.assertEqual(len(double.headers[0].getUUIDCommands()), 2)
        self.assertIsNone(double.headers[0].getUUIDCommand())
        self.assertIsNone(double.headers[0].getUUID())


if __name__ == "__main__":
    unittest.main()
