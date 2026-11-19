"""Tests for the explicit loading-strategy views in peloadview.

The fixtures are hand-crafted PE images smaller than 64KB. No binary is
executed and no operating-system loader is invoked; pefile is used only as an
independent cross-check of the bytes its two documented accessors yield.
"""

import sys
import unittest
from pathlib import Path

import pefile

sys.path.insert(0, str(Path(__file__).resolve().parent))

import pebuild

import peloadview


class LoadingViewTest(unittest.TestCase):
    def assertByte(self, resolution, status, value):
        self.assertEqual(resolution.status, status)
        self.assertEqual(resolution.value, value)

    def test_all_images_are_under_64kb(self):
        for build in (
            pebuild.build_overlapping_sections,
            pebuild.build_truncated_section,
            pebuild.build_shared_and_bss,
            pebuild.build_illegal_alignment,
            pebuild.build_export_overlap,
            pebuild.build_pe32_plus,
        ):
            self.assertLess(len(build()), 0x10000)

    def test_same_rva_multiple_sources(self):
        image = peloadview.LoadImage(pebuild.build_overlapping_sections())

        overlaps = image.section_rva_overlaps()
        self.assertEqual(len(overlaps), 1)
        start, end, sections = overlaps[0]
        self.assertEqual((start, end), (0x1000, 0x1100))
        self.assertEqual([section.name for section in sections],
                         [b".text", b".ovl"])

        for rva in range(0x1000, 0x1100):
            file_res = image.file_backed.resolve(rva)
            self.assertEqual(file_res.status, peloadview.RVAStatus.AMBIGUOUS)
            self.assertIsNone(file_res.value)
            candidate_bytes = {source.byte_value for source in file_res.sources}
            self.assertEqual(candidate_bytes, {0xAA, 0xBB})
            for source in file_res.sources:
                self.assertEqual(source.kind, "section_raw")
                expected_offset = (
                    rva - source.section.virtual_address
                    + source.section.pointer_to_raw_data
                )
                self.assertEqual(source.file_offset, expected_offset)
                self.assertEqual(
                    source.byte_value, image.data[source.file_offset]
                )

            mem_res = image.memory_mapped.resolve(rva)
            self.assertEqual(mem_res.status, peloadview.RVAStatus.RESOLVED)
            self.assertEqual(mem_res.value, 0xBB)
            self.assertEqual(mem_res.sources[0].section.name, b".ovl")

        self.assertEqual(
            len(image.memory_mapped.overlaps()), 0x100
        )


    def test_file_tail_truncation(self):
        image = peloadview.LoadImage(pebuild.build_truncated_section())

        for rva in range(0x1000, 0x1080):
            self.assertByte(
                image.file_backed.resolve(rva),
                peloadview.RVAStatus.RESOLVED,
                0xCC,
            )
            self.assertByte(
                image.memory_mapped.resolve(rva),
                peloadview.RVAStatus.RESOLVED,
                0xCC,
            )

        for rva in range(0x1080, 0x1200):
            file_res = image.file_backed.resolve(rva)
            self.assertEqual(file_res.status, peloadview.RVAStatus.TRUNCATED)
            self.assertIsNone(file_res.value)
            self.assertEqual(file_res.sources[0].kind, "truncated")

        for rva in range(0x1080, 0x1200):
            mem_res = image.memory_mapped.resolve(rva)
            if rva < 0x1200:
                self.assertEqual(
                    mem_res.status, peloadview.RVAStatus.ZERO_FILL
                )
                self.assertEqual(mem_res.value, 0)
                self.assertEqual(mem_res.sources[0].kind, "zero_fill")

    def test_legal_shared_section_and_bss(self):
        image = peloadview.LoadImage(pebuild.build_shared_and_bss())

        shared = image.shared_ranges()
        self.assertEqual(len(shared), 1)
        start, end, section = shared[0]
        self.assertEqual((start, end), (0x2000, 0x2080))
        self.assertEqual(section.name, b".shared")

        for rva in range(0x2000, 0x2080):
            self.assertByte(
                image.file_backed.resolve(rva),
                peloadview.RVAStatus.RESOLVED,
                0x42,
            )
            self.assertByte(
                image.memory_mapped.resolve(rva),
                peloadview.RVAStatus.RESOLVED,
                0x42,
            )

        for rva in range(0x3000, 0x3100):
            file_res = image.file_backed.resolve(rva)
            self.assertEqual(file_res.status, peloadview.RVAStatus.ZERO_FILL)
            self.assertEqual(file_res.value, 0)
            mem_res = image.memory_mapped.resolve(rva)
            self.assertEqual(mem_res.status, peloadview.RVAStatus.ZERO_FILL)
            self.assertEqual(mem_res.value, 0)

        executable = image.executable_ranges()
        self.assertEqual(
            [(start, end) for start, end, _ in executable],
            [(0x1000, 0x1100)],
        )

    def test_unsupported_alignment_reports_unknown(self):
        image = peloadview.LoadImage(pebuild.build_illegal_alignment())
        self.assertFalse(image.alignment.supported)
        self.assertTrue(
            any("FileAlignment" in reason for reason in image.alignment.reasons)
        )
        for rva in (0x1000, 0x1001, 0x10FF):
            self.assertEqual(
                image.file_backed.resolve(rva).status,
                peloadview.RVAStatus.UNKNOWN,
            )
            self.assertEqual(
                image.memory_mapped.resolve(rva).status,
                peloadview.RVAStatus.UNKNOWN,
            )
        status, output = image.file_backed.read(0x1000, 4)
        self.assertEqual(status, peloadview.RVAStatus.UNKNOWN)
        self.assertIsNone(output)


    def test_entry_point_conflict(self):
        image = peloadview.LoadImage(pebuild.build_overlapping_sections())
        report = peloadview.report_entry_point(image)
        self.assertTrue(report["present"])
        self.assertEqual(report["rva"], 0x1000)
        self.assertFalse(report["agree"])
        self.assertEqual(
            report["file_backed"].status, peloadview.RVAStatus.AMBIGUOUS
        )
        self.assertEqual(report["memory_mapped"].value, 0xBB)

        clean = peloadview.LoadImage(pebuild.build_shared_and_bss())
        clean_report = peloadview.report_entry_point(clean)
        self.assertTrue(clean_report["agree"])
        self.assertEqual(clean_report["file_backed"].value, 0x90)
        self.assertEqual(clean_report["memory_mapped"].value, 0x90)

    def test_export_target_conflict(self):
        image = peloadview.LoadImage(pebuild.build_export_overlap())
        report = peloadview.report_exports(image)
        self.assertEqual(len(report), 1)
        target = report[0]
        self.assertEqual(target["target_rva"], 0x1000)
        self.assertFalse(target["forwarded"])
        resolution = target["resolution"]
        self.assertEqual(
            resolution["file_backed"].status,
            peloadview.RVAStatus.AMBIGUOUS,
        )
        self.assertEqual(resolution["memory_mapped"].value, 0xBB)
        self.assertFalse(resolution["agree"])

    def test_executable_region_conflicts(self):
        image = peloadview.LoadImage(pebuild.build_overlapping_sections())
        findings = peloadview.report_executable_regions(image)
        self.assertTrue(findings)
        kinds = {finding["kind"] for finding in findings}
        self.assertIn(peloadview.RVAStatus.AMBIGUOUS, kinds)
        total = sum(
            finding["rva_end"] - finding["rva_start"]
            for finding in findings
        )
        self.assertEqual(total, 0x100)

    def test_provenance_is_recomputable(self):
        image = peloadview.LoadImage(pebuild.build_overlapping_sections())
        resolution = image.file_backed.resolve(0x1050)
        for source in resolution.sources:
            self.assertEqual(
                source.byte_value, image.data[source.file_offset]
            )
        mem = image.memory_mapped.resolve(0x1050)
        source = mem.sources[0]
        self.assertEqual(
            source.byte_value, image.data[source.file_offset]
        )
        self.assertEqual(
            image.memory_mapped.image[0x1050],
            image.data[source.file_offset],
        )

    def test_matches_pefile_documented_accessors(self):
        cases = [
            (pebuild.build_overlapping_sections(), 0x1000),
            (pebuild.build_shared_and_bss(), 0x2000),
            (pebuild.build_shared_and_bss(), 0x1000),
        ]
        for raw, rva in cases:
            image = peloadview.LoadImage(raw)
            pe = pefile.PE(data=raw, fast_load=True)
            pefile_flat = pe.get_data(rva, 1)
            pefile_mapped = pe.get_memory_mapped_image()[rva : rva + 1]

            file_res = image.file_backed.resolve(rva)
            if file_res.status == peloadview.RVAStatus.AMBIGUOUS:
                self.assertEqual(
                    pefile_flat,
                    bytes([file_res.sources[0].byte_value]),
                )
            else:
                self.assertEqual(pefile_flat, bytes([file_res.value]))

            mem_res = image.memory_mapped.resolve(rva)
            self.assertEqual(pefile_mapped, bytes([mem_res.value]))
            pe.close()

    def test_pe32_plus_header_layout(self):
        image = peloadview.LoadImage(pebuild.build_pe32_plus())
        self.assertTrue(image.pe.is_64)
        self.assertEqual(image.pe.image_base, 0x140000000)
        self.assertEqual(image.pe.file_alignment, 0x200)
        self.assertEqual(image.pe.section_alignment, 0x1000)
        self.assertEqual(image.pe.size_of_image, 0x2000)
        self.assertEqual(image.pe.size_of_headers, 0x200)
        self.assertTrue(image.alignment.supported)
        self.assertByte(
            image.memory_mapped.resolve(0x1000),
            peloadview.RVAStatus.RESOLVED,
            0xF4,
        )
        self.assertByte(
            image.file_backed.resolve(0x1000),
            peloadview.RVAStatus.RESOLVED,
            0xF4,
        )

    def test_full_report_structure(self):
        image = peloadview.LoadImage(pebuild.build_export_overlap())
        report = peloadview.build_report(image)
        self.assertTrue(report["alignment_supported"])
        self.assertEqual(len(report["section_rva_overlaps"]), 1)
        self.assertTrue(report["entry_point"]["present"])
        self.assertEqual(len(report["exports"]), 1)
        self.assertEqual(len(report["memory_overwritten_rvas"]), 0x100)


if __name__ == "__main__":
    unittest.main()
