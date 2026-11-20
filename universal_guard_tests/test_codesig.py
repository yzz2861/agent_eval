import unittest

from universal_guard import parse_artifact
from universal_guard.synthesize import CS_ADHOC, CS_KILL, CS_RUNTIME

from .fixtures import build_artifact


class TestCodeSignature(unittest.TestCase):
    def setUp(self):
        self.artifact = parse_artifact(build_artifact())

    def test_code_directory_hash_and_algorithm(self):
        for slc in self.artifact.slices:
            signature = slc.code_signature
            self.assertTrue(signature.present)
            self.assertTrue(signature.has_code_directory)
            self.assertEqual(signature.cdhash_algorithm, "sha256")
            self.assertEqual(len(signature.cdhash), 64)

    def test_flags_are_decoded_by_name(self):
        x86 = self.artifact.slices[0].code_signature
        self.assertIn("CS_RUNTIME", x86.flag_names)
        self.assertIn("CS_KILL", x86.flag_names)
        self.assertIn("CS_ADHOC", x86.flag_names)
        self.assertTrue(x86.adhoc)

    def test_second_slice_has_weaker_protection(self):
        arm = self.artifact.slices[1].code_signature
        self.assertEqual(arm.flag_names, ("CS_ADHOC",))
        self.assertNotIn("CS_RUNTIME", arm.flag_names)

    def test_team_id_is_extracted_when_present(self):
        self.assertEqual(
            self.artifact.slices[0].code_signature.team_id, "GUARD"
        )
        self.assertIsNone(self.artifact.slices[1].code_signature.team_id)

    def test_identifier_is_read_from_string_area(self):
        for slc in self.artifact.slices:
            self.assertEqual(
                slc.code_signature.identifier,
                "com.universal-guard.synthetic",
            )

    def test_missing_signature_is_reported_not_raised(self):
        from universal_guard.synthesize import build_slice
        from universal_guard import parse_artifact as parse
        from .fixtures import CPU_X86_64, PLATFORM_MACOS

        image = build_slice(
            cpu_type=CPU_X86_64,
            cpu_subtype=3,
            platform=PLATFORM_MACOS,
            min_os=(10, 13, 0),
            include_signature=False,
        )
        signature = parse(image).slices[0].code_signature
        self.assertFalse(signature.present)
        self.assertFalse(signature.has_code_directory)


if __name__ == "__main__":
    unittest.main()
