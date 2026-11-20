import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from elftools.elf.address_attribution import (
    UNVERIFIED,
    VERIFIED,
    DebugFile,
    LoadMapping,
    attribute_addresses,
    request_from_config,
)
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import NoteSection


TEST_DIR = os.path.join("test", "testfiles_for_unittests")
MAIN = os.path.join(TEST_DIR, "debuglink")
DEBUG = os.path.join(TEST_DIR, "debuglink.debug")


def _build_id_note(path):
    with open(path, "rb") as stream:
        elf = ELFFile(stream)
        for section in elf.iter_sections():
            if not isinstance(section, NoteSection):
                continue
            for note in section.iter_notes():
                if note.get("n_type") == "NT_GNU_BUILD_ID":
                    return elf, note
    raise AssertionError(f"no build-ID note in {path}")


def _copy_with_build_id(path, destination, mode):
    elf, note = _build_id_note(path)
    with open(path, "rb") as stream:
        data = bytearray(stream.read())

    header_size = elf.structs.Elf_Nhdr.sizeof()
    name_size = ((int(note["n_namesz"]) + 3) // 4) * 4
    description_offset = int(note["n_offset"]) + header_size + name_size
    description_size = int(note["n_descsz"])

    if mode == "mismatch":
        data[description_offset : description_offset + description_size] = (
            b"\xaa" * description_size
        )
    elif mode == "missing":
        # Leave the section and note in place, but make the note unrecognized.
        data[int(note["n_offset"]) + 8 : int(note["n_offset"]) + 12] = (0).to_bytes(
            4, "little"
        )
    else:
        raise AssertionError(mode)

    os.makedirs(os.path.dirname(destination), exist_ok=True)
    with open(destination, "wb") as output:
        output.write(data)


def _rename_debug_info_section(path, destination):
    with open(path, "rb") as stream:
        elf = ELFFile(stream)
        names = elf.get_section_by_name(".shstrtab")
        assert names is not None
        offset = names["sh_offset"]
        size = names["sh_size"]

    with open(path, "rb") as stream:
        data = bytearray(stream.read())
    table = bytes(data[offset : offset + size])
    if b".debug_info\x00" not in table:
        raise AssertionError("no .debug_info section name")
    replacement = b".debugXinfo\x00"
    if len(replacement) != len(b".debug_info\x00"):
        raise AssertionError("replacement name has a different length")
    data[offset : offset + size] = table.replace(b".debug_info\x00", replacement)
    with open(destination, "wb") as output:
        output.write(data)


class AddressAttributionTest(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.temp = self._temp.name

    def _verified_request(self, debug_files=None, mappings=None, addresses=None):
        return attribute_addresses(
            MAIN,
            [DEBUG] if debug_files is None else debug_files,
            [LoadMapping.from_bias("reported", 0x10000)]
            if mappings is None
            else mappings,
            [0x11149] if addresses is None else addresses,
        ).to_dict()

    def test_verified_address_returns_line_and_source(self):
        report = self._verified_request()
        address = report["addresses"][0]

        self.assertEqual(address["status"], "resolved")
        self.assertEqual(len(address["candidates"]), 1)
        candidate = address["candidates"][0]
        self.assertEqual(candidate["file"], "debuglink.c")
        self.assertEqual(candidate["line"], 3)
        self.assertEqual(candidate["trust"], VERIFIED)
        self.assertTrue(candidate["accepted"])
        self.assertEqual(candidate["mapping"], "reported")
        self.assertEqual(candidate["link_address"], "0x1149")
        self.assertEqual(candidate["source"]["artifact_id"], "debug-0")
        self.assertEqual(candidate["source"]["line_section"], ".debug_line")
        self.assertEqual(candidate["source"]["sequence_index"], 0)
        self.assertIn(
            "build_id", report["debug_files"][0]["identity"]["strong_matches"]
        )
        self.assertEqual(report["conflicts"], [])

    def test_main_elf_dwarf_is_a_source_when_present(self):
        report = attribute_addresses(
            DEBUG,
            [],
            [LoadMapping.from_bias("identity", 0)],
            [0x1149],
        ).to_dict()
        address = report["addresses"][0]

        self.assertEqual(address["status"], "resolved")
        candidate = address["candidates"][0]
        self.assertEqual(candidate["line"], 3)
        self.assertEqual(candidate["source"]["artifact_id"], "main")
        self.assertEqual(candidate["source"]["artifact_role"], "main")

    def test_same_named_wrong_package_is_a_conflict_record(self):
        good = os.path.join(self.temp, "good", "debuglink.debug")
        bad = os.path.join(self.temp, "bad", "debuglink.debug")
        os.makedirs(os.path.dirname(good))
        shutil.copyfile(DEBUG, good)
        _copy_with_build_id(DEBUG, bad, "mismatch")

        report = self._verified_request(
            debug_files=[DebugFile(bad, id="pkg-bad"), DebugFile(good, id="pkg-good")]
        )
        address = report["addresses"][0]

        self.assertEqual(address["status"], "resolved")
        self.assertEqual(
            [(c["line"], c["source"]["artifact_id"]) for c in address["candidates"]],
            [(3, "pkg-good")],
        )
        self.assertEqual(
            [
                (c["line"], c["source"]["artifact_id"])
                for c in address["rejected_candidates"]
            ],
            [(3, "pkg-bad")],
        )
        self.assertEqual(address["conflicts"], ["identity-pkg-bad"])

        self.assertEqual(report["summary"]["conflict_records"], 1)
        conflict = report["conflicts"][0]
        self.assertEqual(conflict["kind"], "identity_conflict")
        self.assertEqual(conflict["severity"], "error")
        self.assertEqual(conflict["artifact_path"], os.path.abspath(bad))
        self.assertEqual(conflict["same_basename_as"], ["pkg-good"])
        self.assertEqual(
            conflict["same_basename_artifacts"],
            [{"id": "pkg-good", "path": os.path.abspath(good)}],
        )
        materials = {
            item["material"] for item in conflict["identity"]["contradictions"]
        }
        self.assertEqual(materials, {"build_id", "gnu_debuglink_crc32"})
        self.assertGreater(conflict["line_table"]["rows"], 0)
        self.assertTrue(conflict["plausible_for_requested_addresses"])
        self.assertEqual(conflict["requested_address_coverage"][0]["line"], 3)
        self.assertEqual(
            conflict["requested_address_coverage"][0]["link_address"], "0x1149"
        )

    def test_missing_identity_is_unverified_not_a_contradiction(self):
        orphan = os.path.join(self.temp, "orphan.debug")
        _copy_with_build_id(DEBUG, orphan, "missing")

        report = self._verified_request(debug_files=[orphan])
        address = report["addresses"][0]

        self.assertEqual(address["status"], "provisional")
        self.assertEqual(len(address["candidates"]), 1)
        self.assertEqual(address["candidates"][0]["trust"], UNVERIFIED)
        self.assertFalse(address["candidates"][0]["accepted"])
        self.assertEqual(address["rejected_candidates"], [])

        conflict = report["conflicts"][0]
        self.assertEqual(conflict["kind"], "identity_unverified")
        self.assertEqual(conflict["severity"], "warning")
        self.assertEqual(conflict["identity"]["contradictions"], [])
        self.assertTrue(
            any(
                item["material"] == "build_id"
                for item in conflict["identity"]["missing"]
            )
        )

    def test_line_only_debug_file_is_usable(self):
        line_only = os.path.join(self.temp, "lineonly.debug")
        _rename_debug_info_section(DEBUG, line_only)

        report = self._verified_request(debug_files=[line_only])
        address = report["addresses"][0]
        debug = report["debug_files"][0]

        self.assertFalse(debug["has_debug_info"])
        self.assertTrue(debug["has_debug_line"])
        self.assertEqual(debug["line_table"]["standalone_units"], 1)
        self.assertEqual(address["status"], "resolved")
        candidate = address["candidates"][0]
        self.assertEqual(candidate["line"], 3)
        self.assertTrue(candidate["source"]["standalone_line_unit"])

    def test_multiple_mappings_are_reported_separately(self):
        mappings = [
            LoadMapping.from_bias("reported", 0x10000),
            LoadMapping.from_regions(
                "alternate",
                [
                    (0x11100, 0x11200, 0x110F),
                ],
            ),
        ]
        report = self._verified_request(mappings=mappings)
        address = report["addresses"][0]

        self.assertEqual(address["status"], "ambiguous")
        self.assertEqual(
            [(c["mapping"], c["line"]) for c in address["candidates"]],
            [("reported", 3), ("alternate", 4)],
        )
        self.assertEqual(len(report["mappings"]), 2)
        self.assertEqual(
            report["ambiguities"][0]["kind"], "multiple_verified_attributions"
        )

    def test_line_table_gap_is_an_evidence_gap(self):
        report = self._verified_request(addresses=[0x111C0])
        address = report["addresses"][0]

        self.assertEqual(address["status"], "unresolved")
        self.assertEqual(address["candidates"], [])
        self.assertEqual(address["rejected_candidates"], [])
        self.assertEqual(report["conflicts"], [])
        self.assertIn("no line-table row", address["reason"])

    def test_config_resolves_paths_relative_to_config_file(self):
        good = os.path.join(self.temp, "pkg", "debuglink.debug")
        os.makedirs(os.path.dirname(good))
        shutil.copyfile(DEBUG, good)
        main = os.path.join(self.temp, "pkg", "firmware.elf")
        shutil.copyfile(MAIN, main)

        request = request_from_config(
            {
                "main_elf": "pkg/firmware.elf",
                "debug_files": [
                    {"path": "pkg/debuglink.debug", "id": "package"},
                ],
                "mappings": [
                    {"name": "reported", "bias": "0x10000"},
                ],
                "addresses": ["0x11149"],
            },
            base_dir=self.temp,
        )

        self.assertEqual(request.main_elf, os.path.abspath(main))
        self.assertEqual(request.debug_files[0].id, "package")
        report = attribute_addresses(request).to_dict()
        self.assertEqual(report["addresses"][0]["candidates"][0]["line"], 3)

    def test_cli_writes_full_report_and_conflict_file(self):
        bad = os.path.join(self.temp, "bad", "debuglink.debug")
        _copy_with_build_id(DEBUG, bad, "mismatch")
        config_path = os.path.join(self.temp, "request.json")
        report_path = os.path.join(self.temp, "report.json")
        conflicts_path = os.path.join(self.temp, "conflicts.json")

        with open(config_path, "w", encoding="utf-8") as output:
            json.dump(
                {
                    "main_elf": os.path.abspath(MAIN),
                    "debug_files": [
                        {"path": bad, "id": "wrong-package"},
                    ],
                    "mappings": [
                        {"name": "reported", "bias": "0x10000"},
                    ],
                    "addresses": ["0x11149"],
                },
                output,
            )

        script = os.path.join(
            os.path.dirname(__file__), "..", "scripts", "attribute_address.py"
        )
        result = subprocess.run(
            [
                sys.executable,
                script,
                "--config",
                config_path,
                "--output",
                report_path,
                "--conflicts-out",
                conflicts_path,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

        with open(report_path, encoding="utf-8") as stream:
            report = json.load(stream)
        with open(conflicts_path, encoding="utf-8") as stream:
            conflicts = json.load(stream)
        self.assertEqual(report["addresses"][0]["status"], "unresolved")
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0]["kind"], "identity_conflict")
        self.assertEqual(conflicts[0]["artifact_id"], "wrong-package")


if __name__ == "__main__":
    unittest.main()
