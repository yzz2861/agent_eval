import hashlib
import os
import struct
import sys
import tempfile

from macholib import mach_o
from macholib.MachO import MachO
from macholib.forensics import (
    COORDINATE_FILE,
    COORDINATE_SLICE,
    EVIDENCE_ARCHITECTURE,
    EVIDENCE_COORDINATE,
    EVIDENCE_SLICE_INDEX,
    STATUS_AMBIGUOUS,
    STATUS_ARCHITECTURE_MISMATCH,
    STATUS_COORDINATE_MISSING,
    STATUS_INVALID_DECLARATION,
    STATUS_OUT_OF_BOUNDS,
    STATUS_OWNERSHIP_MISMATCH,
    STATUS_SEGMENT_LENGTH_MISMATCH,
    STATUS_UNVERIFIED,
    STATUS_VERIFIED,
    AmbiguousOffsetError,
    convert_offset,
    format_report,
    verify_excerpt,
    verify_excerpts,
    verify_ledger,
)

if sys.version_info[:2] <= (2, 6):
    import unittest2 as unittest
else:
    import unittest


ARM64 = 0x0100000C
X86_64 = 0x01000007
ARM64_SUBTYPE = 0
X86_64_SUBTYPE = 3

HEADER_SIZE_64 = 32
SEGMENT_COMMAND_64_SIZE = 64
SECTION_64_SIZE = 80
LOAD_COMMAND_SIZE = 8
CMDSIZE = SEGMENT_COMMAND_64_SIZE + SECTION_64_SIZE + LOAD_COMMAND_SIZE
BODY_OFFSET = HEADER_SIZE_64 + CMDSIZE
BODY_SIZE = 0x400

PAYLOAD = b"FORENSIC-EXCERPT"
OTHER_BYTES = b"X86-ONLY-BYTES!!"
SLICE_A = 0x200
SLICE_B = 0x300
FIRST_SLICE_BASE = 0x1000
SLICE_STRIDE = 0x1000


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def build_slice(cputype, cpusubtype, fill, writes):
    body = bytearray([fill]) * BODY_SIZE
    for relative_offset, data in writes.items():
        position = relative_offset - BODY_OFFSET
        assert position >= 0
        assert position + len(data) <= BODY_SIZE
        body[position : position + len(data)] = data

    header = struct.pack(
        ">IIIIIIII",
        mach_o.MH_MAGIC_64,
        cputype,
        cpusubtype,
        2,
        1,
        CMDSIZE,
        0,
        0,
    )
    load_command = struct.pack(">II", mach_o.LC_SEGMENT_64, CMDSIZE)
    segment = struct.pack(
        ">16sQQQQiiII",
        b"__TEXT",
        0x100000000,
        0x1000,
        BODY_OFFSET,
        BODY_SIZE,
        7,
        5,
        1,
        0,
    )
    section = struct.pack(
        ">16s16sQQIIIIIIII",
        b"__text",
        b"__TEXT",
        0x100000000 + BODY_OFFSET,
        BODY_SIZE,
        BODY_OFFSET,
        4,
        0,
        0,
        0,
        0,
        0,
        0,
    )
    return header + load_command + segment + section + bytes(body)


def build_fat(architectures):
    """Build a fat Mach-O from ``(cputype, cpusubtype, slice_bytes)`` tuples."""
    count = len(architectures)
    file_size = FIRST_SLICE_BASE + SLICE_STRIDE * (count - 1) + len(
        architectures[-1][2]
    )
    output = bytearray(file_size)
    output[0:8] = struct.pack(">II", mach_o.FAT_MAGIC, count)
    position = 8
    for index, (cputype, cpusubtype, data) in enumerate(architectures):
        base = FIRST_SLICE_BASE + SLICE_STRIDE * index
        output[position : position + 20] = struct.pack(
            ">iiIII", cputype, cpusubtype, base, len(data), 12
        )
        output[base : base + len(data)] = data
        position += 20
    return bytes(output)


class FatMachoFixture(object):
    def __init__(self, architectures):
        self.data = build_fat(architectures)
        handle = tempfile.NamedTemporaryFile(delete=False)
        handle.write(self.data)
        handle.close()
        self.path = handle.name

    def close(self):
        if os.path.exists(self.path):
            os.unlink(self.path)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


def standard_fixture():
    """Two slices; both carry PAYLOAD at 0x200, only ARM64 carries it at 0x300."""
    arm = build_slice(
        ARM64,
        ARM64_SUBTYPE,
        0x41,
        {SLICE_A: PAYLOAD, SLICE_B: PAYLOAD},
    )
    x86 = build_slice(
        X86_64,
        X86_64_SUBTYPE,
        0x58,
        {SLICE_A: PAYLOAD, SLICE_B: OTHER_BYTES},
    )
    return FatMachoFixture(
        [
            (ARM64, ARM64_SUBTYPE, arm),
            (X86_64, X86_64_SUBTYPE, x86),
        ]
    )


def declaration(**overrides):
    value = {
        "id": "excerpt",
        "coordinate_system": COORDINATE_SLICE,
        "offset": SLICE_A,
        "length": len(PAYLOAD),
        "digest": sha256(PAYLOAD),
    }
    value.update(overrides)
    return value


class TestExcerptVerification(unittest.TestCase):
    def test_slice_coordinate_selects_declared_architecture(self):
        with standard_fixture() as fixture:
            result = verify_excerpt(
                fixture.path, declaration(id="arm-a", arch="arm64")
            )
        self.assertEqual(result.status, STATUS_VERIFIED)
        self.assertTrue(result.ok)
        self.assertEqual(result.slice_index, 0)
        self.assertEqual(result.resolved_arch, "ARM64")
        self.assertEqual(result.coordinate_system, COORDINATE_SLICE)
        self.assertEqual(result.segment_lengths, {"__TEXT": len(PAYLOAD)})
        self.assertEqual(
            result.converted["absolute_offset"], FIRST_SLICE_BASE + SLICE_A
        )
        self.assertEqual(result.converted["coordinate_system"], COORDINATE_FILE)
        self.assertTrue(result.converted["parts"][0]["slice_offset"] == SLICE_A)

    def test_same_digest_in_two_slices_is_ambiguous_without_architecture(self):
        with standard_fixture() as fixture:
            result = verify_excerpt(fixture.path, declaration())
        self.assertEqual(result.status, STATUS_AMBIGUOUS)
        self.assertFalse(result.ok)
        self.assertIn(EVIDENCE_ARCHITECTURE, result.missing_evidence)
        self.assertIn(EVIDENCE_SLICE_INDEX, result.missing_evidence)
        self.assertEqual(result.ownership, None)
        self.assertEqual(len(result.candidates), 2)
        self.assertTrue(all(c["digest_match"] for c in result.candidates))

    def test_old_file_coordinate_is_rebuilt_into_slice_coordinate(self):
        old_offset = FIRST_SLICE_BASE + SLICE_A
        with standard_fixture() as fixture:
            result = verify_excerpt(
                fixture.path,
                declaration(
                    id="legacy",
                    coordinate_system=COORDINATE_FILE,
                    offset=old_offset,
                ),
            )
        self.assertEqual(result.status, STATUS_VERIFIED)
        self.assertTrue(result.ok)
        self.assertEqual(result.slice_index, 0)
        self.assertEqual(result.converted["coordinate_system"], COORDINATE_SLICE)
        self.assertEqual(result.converted["offset"], SLICE_A)
        self.assertEqual(result.converted["absolute_offset"], old_offset)
        self.assertTrue(result.converted["reconstructed"])

    def test_wrong_coordinate_system_does_not_silently_pass(self):
        old_offset = FIRST_SLICE_BASE + SLICE_A
        with standard_fixture() as fixture:
            result = verify_excerpt(
                fixture.path,
                declaration(
                    id="wrong-coordinate",
                    coordinate_system=COORDINATE_SLICE,
                    offset=old_offset,
                    arch="arm64",
                ),
            )
        self.assertEqual(result.status, STATUS_OUT_OF_BOUNDS)
        self.assertFalse(result.ok)

    def test_digest_match_does_not_override_declared_architecture(self):
        # PAYLOAD really is at 0x300 in the ARM64 slice, but the declaration
        # claims the x86_64 slice, whose bytes at 0x300 differ.  The digest
        # matches *a* slice, yet the ownership check must fail.
        with standard_fixture() as fixture:
            result = verify_excerpt(
                fixture.path,
                declaration(id="misowned", offset=SLICE_B, arch="x86_64"),
            )
        self.assertEqual(result.status, STATUS_OWNERSHIP_MISMATCH)
        self.assertFalse(result.ok)
        self.assertEqual(result.slice_index, 1)
        self.assertEqual(result.resolved_arch, "x86_64")
        self.assertNotEqual(result.actual_digest, result.declared_digest)
        self.assertTrue(
            any("matches slice" in problem for problem in result.problems)
        )

    def test_same_bytes_at_two_positions_keep_distinct_coordinates(self):
        with standard_fixture() as fixture:
            first = verify_excerpt(
                fixture.path, declaration(id="at-a", offset=SLICE_A, arch="arm64")
            )
            second = verify_excerpt(
                fixture.path, declaration(id="at-b", offset=SLICE_B, arch="arm64")
            )
        self.assertTrue(first.ok)
        self.assertTrue(second.ok)
        self.assertEqual(first.declared_digest, second.declared_digest)
        self.assertEqual(first.converted["offset"], SLICE_A)
        self.assertEqual(second.converted["offset"], SLICE_B)

    def test_multi_part_declaration_reports_per_segment_lengths(self):
        expected = PAYLOAD + PAYLOAD
        with standard_fixture() as fixture:
            result = verify_excerpt(
                fixture.path,
                {
                    "id": "two-parts",
                    "coordinate_system": COORDINATE_SLICE,
                    "parts": [
                        {"offset": SLICE_A, "length": len(PAYLOAD)},
                        {"offset": SLICE_B, "length": len(PAYLOAD)},
                    ],
                    "length": len(expected),
                    "digest": sha256(expected),
                    "arch": "arm64",
                },
            )
        self.assertTrue(result.ok)
        self.assertEqual(result.declared_length, len(expected))
        self.assertEqual(result.segment_lengths, {"__TEXT": len(expected)})
        self.assertEqual(len(result.parts), 2)
        self.assertEqual(result.parts[0]["slice_offset"], SLICE_A)
        self.assertEqual(result.parts[1]["slice_offset"], SLICE_B)
        self.assertEqual(
            result.parts[0]["segment_lengths"], {"__TEXT": len(PAYLOAD)}
        )

    def test_parts_may_use_different_coordinate_systems(self):
        expected = PAYLOAD + PAYLOAD
        with standard_fixture() as fixture:
            result = verify_excerpt(
                fixture.path,
                {
                    "id": "mixed-parts",
                    "parts": [
                        {
                            "coordinate_system": COORDINATE_FILE,
                            "offset": FIRST_SLICE_BASE + SLICE_A,
                            "length": len(PAYLOAD),
                        },
                        {
                            "coordinate_system": COORDINATE_SLICE,
                            "offset": SLICE_B,
                            "length": len(PAYLOAD),
                        },
                    ],
                    "digest": sha256(expected),
                    "arch": "arm64",
                },
            )
        self.assertTrue(result.ok)
        self.assertEqual(result.coordinate_system, "mixed")
        self.assertEqual(result.converted["coordinate_system"], "mixed")
        self.assertEqual(result.parts[0]["slice_offset"], SLICE_A)
        self.assertEqual(result.parts[1]["slice_offset"], SLICE_B)

    def test_declared_segment_lengths_are_checked(self):
        with standard_fixture() as fixture:
            result = verify_excerpt(
                fixture.path,
                declaration(
                    arch="arm64", segment_lengths={"__TEXT": len(PAYLOAD) - 1}
                ),
            )
        self.assertEqual(result.status, STATUS_SEGMENT_LENGTH_MISMATCH)
        self.assertFalse(result.ok)
        self.assertTrue(
            any("per-segment lengths" in problem for problem in result.problems)
        )

    def test_missing_coordinate_system_is_not_guessed(self):
        with standard_fixture() as fixture:
            value = declaration(arch="arm64")
            del value["coordinate_system"]
            result = verify_excerpt(fixture.path, value)
        self.assertEqual(result.status, STATUS_COORDINATE_MISSING)
        self.assertFalse(result.ok)
        self.assertIn(EVIDENCE_COORDINATE, result.missing_evidence)

    def test_duplicate_architecture_needs_slice_index(self):
        first = build_slice(
            ARM64, ARM64_SUBTYPE, 0x41, {SLICE_A: PAYLOAD}
        )
        second = build_slice(
            ARM64, ARM64_SUBTYPE, 0x42, {SLICE_A: PAYLOAD}
        )
        with FatMachoFixture(
            [
                (ARM64, ARM64_SUBTYPE, first),
                (ARM64, ARM64_SUBTYPE, second),
            ]
        ) as fixture:
            ambiguous = verify_excerpt(
                fixture.path, declaration(arch="arm64")
            )
            selected = verify_excerpt(
                fixture.path, declaration(arch="arm64", slice_index=1)
            )
        self.assertEqual(ambiguous.status, STATUS_AMBIGUOUS)
        self.assertIn(EVIDENCE_SLICE_INDEX, ambiguous.missing_evidence)
        self.assertTrue(selected.ok)
        self.assertEqual(selected.slice_index, 1)
        self.assertEqual(
            selected.converted["absolute_offset"],
            FIRST_SLICE_BASE + SLICE_STRIDE + SLICE_A,
        )

    def test_thin_macho_has_a_single_zero_based_slice(self):
        thin = build_slice(
            ARM64, ARM64_SUBTYPE, 0x41, {SLICE_A: PAYLOAD}
        )
        handle = tempfile.NamedTemporaryFile(delete=False)
        handle.write(thin)
        handle.close()
        try:
            result = verify_excerpt(handle.name, declaration())
        finally:
            os.unlink(handle.name)
        self.assertTrue(result.ok)
        self.assertEqual(result.slice_index, 0)
        self.assertEqual(result.slice.offset, 0)
        self.assertEqual(result.converted["absolute_offset"], SLICE_A)

    def test_object_declarations_and_alternate_digest_forms(self):
        class Declaration(object):
            id = "object"
            coordinate_system = "slice"
            offset = SLICE_A
            length = len(PAYLOAD)
            arch = "arm64"
            digest = {"algorithm": "sha256", "value": sha256(PAYLOAD).upper()}

        with standard_fixture() as fixture:
            result = verify_excerpt(fixture.path, Declaration())
        self.assertTrue(result.ok)
        self.assertEqual(result.id, "object")

    def test_prefixed_digest_and_default_coordinate_system(self):
        value = declaration(id="prefixed", arch="arm64")
        del value["coordinate_system"]
        value["digest"] = "sha256:" + value["digest"]
        with standard_fixture() as fixture:
            result = verify_excerpt(
                fixture.path,
                value,
                default_coordinate_system=COORDINATE_SLICE,
            )
        self.assertTrue(result.ok)
        self.assertEqual(result.digest_algorithm, "sha256")

    def test_legacy_flag_selects_file_coordinates(self):
        value = declaration(
            id="legacy-flag", offset=FIRST_SLICE_BASE + SLICE_A
        )
        del value["coordinate_system"]
        value["legacy"] = True
        with standard_fixture() as fixture:
            result = verify_excerpt(fixture.path, value)
        self.assertTrue(result.ok)
        self.assertEqual(result.coordinate_system, COORDINATE_FILE)
        self.assertEqual(result.converted["offset"], SLICE_A)
        self.assertTrue(result.converted["reconstructed"])

    def test_unknown_architecture_with_matching_bytes_is_ownership_mismatch(self):
        with standard_fixture() as fixture:
            result = verify_excerpt(
                fixture.path, declaration(id="unknown-arch", arch="mips")
            )
        self.assertEqual(result.status, STATUS_OWNERSHIP_MISMATCH)
        self.assertFalse(result.ok)

    def test_unknown_architecture_without_matching_bytes(self):
        with standard_fixture() as fixture:
            result = verify_excerpt(
                fixture.path,
                declaration(
                    id="unknown-arch",
                    arch="mips",
                    offset=0x3F0,
                    digest=sha256(b"not-present....."),
                ),
            )
        self.assertEqual(result.status, STATUS_ARCHITECTURE_MISMATCH)
        self.assertIn(EVIDENCE_ARCHITECTURE, result.missing_evidence)

    def test_base_offset_selects_the_owning_slice(self):
        with standard_fixture() as fixture:
            result = verify_excerpt(
                fixture.path,
                declaration(id="base", base_offset=FIRST_SLICE_BASE),
            )
        self.assertTrue(result.ok)
        self.assertEqual(result.slice_index, 0)

    def test_out_of_bounds_and_missing_digest(self):
        with standard_fixture() as fixture:
            outside = verify_excerpt(
                fixture.path,
                declaration(id="outside", offset=0x5000, arch="arm64"),
            )
            no_digest = declaration(id="no-digest", arch="arm64")
            del no_digest["digest"]
            unverified = verify_excerpt(fixture.path, no_digest)
        self.assertEqual(outside.status, STATUS_OUT_OF_BOUNDS)
        self.assertEqual(unverified.status, STATUS_UNVERIFIED)
        self.assertIn("digest", unverified.missing_evidence)

    def test_conflicting_lengths_are_invalid(self):
        with standard_fixture() as fixture:
            result = verify_excerpt(
                fixture.path,
                {
                    "id": "bad-length",
                    "coordinate_system": COORDINATE_SLICE,
                    "parts": [{"offset": SLICE_A, "length": len(PAYLOAD)}],
                    "length": 99,
                    "digest": sha256(PAYLOAD),
                    "arch": "arm64",
                },
            )
        self.assertEqual(result.status, STATUS_INVALID_DECLARATION)
        self.assertFalse(result.ok)


class TestOffsetConversion(unittest.TestCase):
    def test_file_offset_reconstructs_slice_offset(self):
        with standard_fixture() as fixture:
            converted = convert_offset(
                fixture.path,
                FIRST_SLICE_BASE + SLICE_A,
                COORDINATE_FILE,
                length=len(PAYLOAD),
            )
        self.assertEqual(converted["coordinate_system"], COORDINATE_SLICE)
        self.assertEqual(converted["offset"], SLICE_A)
        self.assertEqual(converted["slice_index"], 0)
        self.assertTrue(converted["reconstructed"])

    def test_slice_offset_needs_architecture_when_slices_overlap(self):
        with standard_fixture() as fixture:
            with self.assertRaises(AmbiguousOffsetError) as context:
                convert_offset(
                    fixture.path,
                    SLICE_A,
                    COORDINATE_SLICE,
                    length=len(PAYLOAD),
                )
        self.assertIn(
            EVIDENCE_ARCHITECTURE, context.exception.missing_evidence
        )

    def test_slice_offset_with_architecture_returns_file_offset(self):
        with standard_fixture() as fixture:
            converted = convert_offset(
                fixture.path,
                SLICE_A,
                COORDINATE_SLICE,
                arch="arm64",
                length=len(PAYLOAD),
            )
        self.assertEqual(converted["coordinate_system"], COORDINATE_FILE)
        self.assertEqual(
            converted["absolute_offset"], FIRST_SLICE_BASE + SLICE_A
        )


class TestLedgerAndMachOIntegration(unittest.TestCase):
    def test_ledger_reports_every_entry(self):
        entries = [
            declaration(id="good", arch="arm64"),
            declaration(id="bad", arch="x86_64", offset=SLICE_B),
        ]
        with standard_fixture() as fixture:
            ledger = verify_excerpts(fixture.path, entries)
        self.assertFalse(ledger.ok)
        self.assertEqual(len(ledger), 2)
        self.assertTrue(ledger[0].ok)
        self.assertFalse(ledger[1].ok)
        payload = ledger.to_dict()
        self.assertEqual(payload["entries"][0]["status"], STATUS_VERIFIED)
        self.assertEqual(
            payload["entries"][1]["status"], STATUS_OWNERSHIP_MISMATCH
        )

    def test_ledger_flags_duplicate_digests_with_distinct_coordinates(self):
        entries = [
            declaration(id="copy-a", offset=SLICE_A, arch="arm64"),
            declaration(id="copy-b", offset=SLICE_B, arch="arm64"),
        ]
        with standard_fixture() as fixture:
            ledger = verify_excerpts(fixture.path, entries)
        self.assertTrue(ledger.ok)
        self.assertEqual(ledger[0].declared_digest, ledger[1].declared_digest)
        self.assertNotEqual(
            ledger[0].converted["offset"], ledger[1].converted["offset"]
        )
        key = "sha256:" + sha256(PAYLOAD)
        self.assertEqual(ledger.duplicate_digests, {key: ["copy-a", "copy-b"]})
        self.assertIn(key, ledger.to_dict()["duplicate_digests"])

    def test_macho_and_header_entry_points(self):
        with standard_fixture() as fixture:
            macho = MachO(fixture.path)
            from_file = macho.verify_excerpt(
                declaration(id="from-macho", arch="arm64")
            )
            from_arm_header = macho.headers[0].verify_excerpt(
                declaration(id="from-arm-header")
            )
            from_x86_header = macho.headers[1].verify_excerpt(
                declaration(id="from-x86-header")
            )
            wrong_header = macho.headers[1].verify_excerpt(
                declaration(id="wrong-header", offset=SLICE_B)
            )
        self.assertTrue(from_file.ok)
        self.assertTrue(from_arm_header.ok)
        self.assertEqual(from_arm_header.slice_index, 0)
        self.assertTrue(from_x86_header.ok)
        self.assertEqual(from_x86_header.slice_index, 1)
        self.assertEqual(wrong_header.status, STATUS_OWNERSHIP_MISMATCH)

    def test_format_report_states_coordinates_arch_and_segments(self):
        with standard_fixture() as fixture:
            result = verify_excerpt(
                fixture.path, declaration(id="report", arch="arm64")
            )
        report = format_report(result)
        self.assertIn("coordinate system: slice", report)
        self.assertIn("owning slice: #0 ARM64", report)
        self.assertIn("segment lengths: __TEXT=16", report)
        self.assertIn("converted file offset", report)

    def test_multi_file_ledger_uses_each_declaration_path(self):
        with standard_fixture() as first, standard_fixture() as second:
            entries = [
                dict(declaration(id="first-ok", arch="arm64"), path=first.path),
                dict(
                    declaration(id="second-bad", arch="x86_64", offset=SLICE_B),
                    path=second.path,
                ),
            ]
            ledger = verify_ledger(entries)
        self.assertEqual(len(ledger), 2)
        self.assertTrue(ledger[0].ok)
        self.assertEqual(ledger[1].status, STATUS_OWNERSHIP_MISMATCH)

    def test_multi_file_ledger_default_source(self):
        with standard_fixture() as fixture:
            ledger = verify_ledger(
                [declaration(id="default-source", arch="arm64")],
                source=fixture.path,
            )
        self.assertTrue(ledger.ok)


if __name__ == "__main__":
    unittest.main()
