
"""Tests for the read-only pairwise slice comparator.

The fixtures are synthetic fat Mach-O blobs built purely in Python (see
:mod:`macholib_tests.sample_macho`); they exercise slice reordering, absent
and duplicate architectures, explained layout shifts from a dylib reference
rewrite, an unexplained data edit located to byte ranges and signature
coverage changes.
"""

import unittest

from macholib import slice_diff as sd
from macholib_tests import sample_macho as sm


OLD_PATH = "/usr/lib/libdependency.dylib"
NEW_PATH = "@executable_path/../Frameworks/libdependency.dylib"
DATA_PAYLOAD = bytes((index * 7) & 0xFF for index in range(64))
SIGNATURE_PAYLOAD = b"\xFA\xCE" * 16


def _slice(cputype, path, data=DATA_PAYLOAD, signature=SIGNATURE_PAYLOAD):
    return sm.build_slice(cputype, path, data, signature)


class SliceDiffTest(unittest.TestCase):
    def setUp(self):
        x86_before, self.x86_meta = _slice(sm.CPU_X86_64, OLD_PATH)
        arm_before, self.arm_meta = _slice(sm.CPU_ARM64, OLD_PATH)
        self.before = sm.build_fat(
            [
                (sm.CPU_X86_64, x86_before),
                (sm.CPU_ARM64, arm_before),
            ]
        )

        x86_after, self.x86_after_meta = _slice(
            sm.CPU_X86_64, NEW_PATH
        )
        arm_after, _ = _slice(sm.CPU_ARM64, NEW_PATH)
        # Reverse order to prove slice matching ignores fat ordering.
        self.after = sm.build_fat(
            [
                (sm.CPU_ARM64, arm_after),
                (sm.CPU_X86_64, x86_after),
            ]
        )

    def test_parser_reads_both_architectures(self):
        views = sd.parse_bytes("before", self.before)
        self.assertEqual(len(views), 2)
        self.assertEqual(
            [view.arch_key[0] for view in views],
            [sm.CPU_X86_64, sm.CPU_ARM64],
        )
        for view in views:
            self.assertEqual(len(view.commands), 4)
            self.assertTrue(view.signature.present)

    def test_rewrite_is_fully_explained(self):
        report = sd.compare_blobs(
            "before", self.before, "after", self.after
        )
        self.assertFalse(report.has_unexplained_changes)
        explained = report.findings_by_category(
            sd.EXPLAINED_LOAD_COMMAND
        )
        self.assertEqual(len(explained), 2)
        for finding in explained:
            self.assertEqual(finding.detail, "reference_rewrite")
            self.assertIsNotNone(finding.before_index)


    def test_unexplained_data_edit_is_located_to_byte_ranges(self):
        edited = bytearray(DATA_PAYLOAD)
        edited[10:13] = b"\xDE\xAD\xBE"
        x86_after, after_meta = _slice(
            sm.CPU_X86_64, NEW_PATH, data=bytes(edited)
        )
        arm_after, _ = _slice(sm.CPU_ARM64, NEW_PATH)
        after = sm.build_fat(
            [
                (sm.CPU_ARM64, arm_after),
                (sm.CPU_X86_64, x86_after),
            ]
        )
        report = sd.compare_blobs(
            "before", self.before, "after", after
        )
        content = report.findings_by_category(
            sd.UNEXPLAINED_CONTENT
        )
        self.assertEqual(len(content), 1)
        finding = content[0]
        self.assertEqual(finding.detail, "segment_content")
        self.assertEqual(finding.arch_label, "x86_64/0")
        delta = after_meta["data_offset"] - self.x86_meta["data_offset"]
        self.assertEqual(
            finding.before_range.slice_offset,
            self.x86_meta["data_offset"] + 10,
        )
        self.assertEqual(finding.before_range.length, 3)
        self.assertEqual(
            finding.after_range.slice_offset,
            after_meta["data_offset"] + 10,
        )
        self.assertEqual(
            finding.after_range.slice_offset
            - finding.before_range.slice_offset,
            delta,
        )
        # Whole-file fat coordinates are available on both sides.
        x86_comparison = next(
            comparison
            for comparison in report.slice_comparisons
            if comparison.arch_key[0] == sm.CPU_X86_64
        )
        self.assertEqual(
            finding.before_range.file_offset,
            x86_comparison.before.fat_offset
            + finding.before_range.slice_offset,
        )
        self.assertEqual(
            finding.after_range.file_offset,
            x86_comparison.after.fat_offset
            + finding.after_range.slice_offset,
        )


    def test_absent_architecture_is_missing_evidence(self):
        x86_after, _ = _slice(sm.CPU_X86_64, NEW_PATH)
        after = sm.build_fat([(sm.CPU_X86_64, x86_after)])
        report = sd.compare_blobs(
            "before", self.before, "after", after
        )
        missing = report.findings_by_category(sd.MISSING_EVIDENCE)
        self.assertTrue(missing)
        absent = [
            finding
            for finding in missing
            if finding.detail == "slice_absent"
        ]
        self.assertEqual(len(absent), 1)
        self.assertIn("ARM64", absent[0].arch_label)
        self.assertIsNotNone(absent[0].before_range)
        self.assertIsNone(absent[0].after_range)

    def test_duplicate_architectures_pair_by_ordinal(self):
        x86_first, _ = _slice(sm.CPU_X86_64, OLD_PATH)
        x86_second, _ = _slice(
            sm.CPU_X86_64,
            OLD_PATH,
            data=bytes((index + 1) & 0xFF for index in range(64)),
        )
        before = sm.build_fat(
            [
                (sm.CPU_X86_64, x86_first),
                (sm.CPU_X86_64, x86_second),
            ]
        )
        after_first, _ = _slice(sm.CPU_X86_64, NEW_PATH)
        after_second, _ = _slice(
            sm.CPU_X86_64,
            NEW_PATH,
            data=bytes((index + 1) & 0xFF for index in range(64)),
        )
        # Keep the same ordinal order; the point is that two identical
        # architecture keys are paired one-to-one rather than collapsed.
        after = sm.build_fat(
            [
                (sm.CPU_X86_64, after_first),
                (sm.CPU_X86_64, after_second),
            ]
        )
        report = sd.compare_blobs(
            "before", before, "after", after
        )
        x86_comparisons = [
            comparison
            for comparison in report.slice_comparisons
            if comparison.arch_key[0] == sm.CPU_X86_64
        ]
        self.assertEqual(len(x86_comparisons), 2)
        # Each duplicate keeps its own payload through ordinal pairing.
        self.assertFalse(report.has_unexplained_changes)
        absent = report.findings_by_category(sd.MISSING_EVIDENCE)
        self.assertEqual(
            [f.detail for f in absent if f.detail == "slice_absent"],
            [],
        )

    def test_signature_change_is_separate_from_content(self):
        new_signature = b"\xBE\xEF" * 16
        x86_after, _ = _slice(
            sm.CPU_X86_64,
            NEW_PATH,
            signature=new_signature,
        )
        arm_after, _ = _slice(sm.CPU_ARM64, NEW_PATH)
        after = sm.build_fat(
            [
                (sm.CPU_ARM64, arm_after),
                (sm.CPU_X86_64, x86_after),
            ]
        )
        report = sd.compare_blobs(
            "before", self.before, "after", after
        )
        signature_findings = report.findings_by_category(
            sd.SIGNATURE_CHANGE
        )
        self.assertTrue(signature_findings)
        self.assertEqual(
            signature_findings[0].detail, "signature_bytes"
        )
        # The edited signature must not also appear as content drift.
        content = report.findings_by_category(
            sd.UNEXPLAINED_CONTENT
        )
        self.assertEqual(content, [])
        # The finding points at both signature regions.
        self.assertIsNotNone(signature_findings[0].before_range)
        self.assertIsNotNone(signature_findings[0].after_range)


    def test_signature_coverage_change_is_reported(self):
        grown_signature = SIGNATURE_PAYLOAD + b"\x00" * 16
        x86_after, after_meta = _slice(
            sm.CPU_X86_64,
            NEW_PATH,
            signature=grown_signature,
        )
        arm_after, _ = _slice(sm.CPU_ARM64, NEW_PATH)
        after = sm.build_fat(
            [
                (sm.CPU_ARM64, arm_after),
                (sm.CPU_X86_64, x86_after),
            ]
        )
        report = sd.compare_blobs(
            "before", self.before, "after", after
        )
        coverage = [
            finding
            for finding in report.findings_by_category(
                sd.SIGNATURE_CHANGE
            )
            if finding.detail == "signature_coverage"
        ]
        self.assertEqual(len(coverage), 1)
        self.assertEqual(
            coverage[0].before_range.length,
            len(SIGNATURE_PAYLOAD),
        )
        self.assertEqual(
            coverage[0].after_range.length,
            len(grown_signature),
        )

    def test_unexplained_layout_becomes_missing_evidence(self):
        # Place the payload one extra alignment step beyond where the
        # rewritten commands and normal alignment would put it.  The slice
        # stays structurally valid, but the extra displacement cannot follow
        # from the reference rewrite.
        x86_before, before_meta = _slice(
            sm.CPU_X86_64, OLD_PATH
        )
        x86_after_natural, natural_meta = _slice(
            sm.CPU_X86_64, NEW_PATH
        )
        forced_offset = natural_meta["natural_data_offset"] + 16
        x86_after, _ = sm.build_slice(
            sm.CPU_X86_64,
            NEW_PATH,
            DATA_PAYLOAD,
            SIGNATURE_PAYLOAD,
            data_offset=forced_offset,
        )
        before = sm.build_fat([(sm.CPU_X86_64, x86_before)])
        after = sm.build_fat([(sm.CPU_X86_64, x86_after)])
        report = sd.compare_blobs(
            "before", before, "after", after
        )
        layout = [
            finding
            for finding in report.findings_by_category(
                sd.MISSING_EVIDENCE
            )
            if finding.detail == "unexplained_layout"
        ]
        self.assertTrue(layout)

    def test_render_report_and_main(self):
        import os
        import tempfile

        report = sd.compare_blobs(
            "before", self.before, "after", self.after
        )
        rendered = sd.render_report(report)
        self.assertIn("architecture", rendered)
        self.assertIn("LC_LOAD_DYLIB", rendered)
        self.assertIn("file[", rendered)

        tmpdir = tempfile.mkdtemp()
        before_path = os.path.join(tmpdir, "before.fat")
        after_path = os.path.join(tmpdir, "after.fat")
        for path, blob in (
            (before_path, self.before),
            (after_path, self.after),
        ):
            with open(path, "wb") as handle:
                handle.write(blob)
        # A fully explained rewrite exits zero.
        self.assertEqual(sd.main([before_path, after_path]), 0)

        edited = bytearray(DATA_PAYLOAD)
        edited[5] = 0xEE
        x86_dirty, _ = _slice(
            sm.CPU_X86_64, NEW_PATH, data=bytes(edited)
        )
        arm_clean, _ = _slice(sm.CPU_ARM64, NEW_PATH)
        dirty = sm.build_fat(
            [
                (sm.CPU_ARM64, arm_clean),
                (sm.CPU_X86_64, x86_dirty),
            ]
        )
        dirty_path = os.path.join(tmpdir, "dirty.fat")
        with open(dirty_path, "wb") as handle:
            handle.write(dirty)
        self.assertEqual(sd.main([before_path, dirty_path]), 1)

    def test_diff_ranges_helper(self):
        self.assertEqual(
            sd.diff_ranges(b"abcdef", b"abXdeY"),
            [(2, 3), (5, 6)],
        )
        with self.assertRaises(ValueError):
            sd.diff_ranges(b"abc", b"ab")


if __name__ == "__main__":
    unittest.main()
