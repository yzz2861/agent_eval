import os
import unittest

from universal_guard import parse_artifact
from universal_guard.synthesize import build_slice

from .fixtures import (
    CPU_ARM64,
    CPU_X86_64,
    PLATFORM_MACOS,
    build_artifact,
)


class TestParsing(unittest.TestCase):
    def test_fat_artifact_has_two_indexed_slices(self):
        artifact = parse_artifact(build_artifact())
        self.assertTrue(artifact.is_fat)
        self.assertEqual(len(artifact.slices), 2)
        self.assertEqual([slc.index for slc in artifact.slices], [0, 1])
        cputypes = [slc.cpu_type for slc in artifact.slices]
        self.assertEqual(cputypes, [CPU_X86_64, CPU_ARM64])

    def test_platform_and_minimum_os_are_decoded(self):
        artifact = parse_artifact(build_artifact())
        x86, arm = artifact.slices
        self.assertEqual(x86.platform.platform, PLATFORM_MACOS)
        self.assertEqual(str(x86.platform.min_os), "10.13.0")
        self.assertEqual(str(arm.platform.min_os), "11.0.0")
        self.assertEqual(x86.platform.source_command, "LC_BUILD_VERSION")

    def test_slice_digests_are_stable(self):
        first = parse_artifact(build_artifact())
        second = parse_artifact(build_artifact())
        for index in range(2):
            self.assertEqual(
                first.slices[index].digests["sha256"],
                second.slices[index].digests["sha256"],
            )
            self.assertEqual(
                len(first.slices[index].digests["sha256"]), 64
            )

    def test_thin_macho_is_single_slice(self):
        image = build_slice(
            cpu_type=CPU_X86_64,
            cpu_subtype=3,
            platform=PLATFORM_MACOS,
            min_os=(10, 13, 0),
        )
        artifact = parse_artifact(image)
        self.assertFalse(artifact.is_fat)
        self.assertEqual(len(artifact.slices), 1)

    def test_rejects_non_macho_bytes(self):
        with self.assertRaises(ValueError):
            parse_artifact(b"not a mach-o file at all")

    @unittest.skipUnless(
        os.path.exists("/bin/ls"), "system Mach-O not available"
    )
    def test_parses_real_system_universal_binary(self):
        artifact = parse_artifact("/bin/ls")
        self.assertTrue(artifact.is_fat)
        self.assertGreaterEqual(len(artifact.slices), 2)
        for slc in artifact.slices:
            self.assertTrue(slc.code_signature.present)
            self.assertTrue(slc.code_signature.has_code_directory)
            self.assertEqual(slc.code_signature.cdhash_algorithm, "sha256")
            self.assertEqual(len(slc.code_signature.cdhash), 64)


if __name__ == "__main__":
    unittest.main()
