import unittest

from universal_guard import (
    OSVersion,
    Terminal,
    select_slice,
    subtype_compatible,
)

from .fixtures import (
    CPU_ARM64,
    CPU_X86_64,
    PLATFORM_IOS,
    PLATFORM_MACOS,
    parsed_artifact,
)


class TestSubtypeCompatibility(unittest.TestCase):
    def test_generic_subtype_runs_everywhere(self):
        self.assertTrue(subtype_compatible(0, 0))
        self.assertTrue(subtype_compatible(0, 2))

    def test_specialised_slice_needs_specialised_terminal(self):
        self.assertFalse(subtype_compatible(2, 0))
        self.assertTrue(subtype_compatible(2, 2))

    def test_capability_bits_are_masked(self):
        # 0x80000003 carries a capability flag but is still subtype 3.
        self.assertTrue(subtype_compatible(0x80000003, 3))


class TestSliceSelection(unittest.TestCase):
    def setUp(self):
        self.artifact = parsed_artifact()

    def test_intel_terminal_selects_x86_slice(self):
        terminal = Terminal(
            "intel", CPU_X86_64, 3, PLATFORM_MACOS, OSVersion(10, 15)
        )
        slc, reasons = select_slice(self.artifact, terminal)
        self.assertEqual(slc.index, 0)
        self.assertEqual(reasons, [])

    def test_arm_terminal_selects_arm_slice(self):
        terminal = Terminal(
            "apple", CPU_ARM64, 0, PLATFORM_MACOS, OSVersion(12, 0)
        )
        slc, _reasons = select_slice(self.artifact, terminal)
        self.assertEqual(slc.index, 1)

    def test_os_below_minimum_has_no_selectable_slice(self):
        terminal = Terminal(
            "old-intel", CPU_X86_64, 3, PLATFORM_MACOS, OSVersion(10, 12)
        )
        slc, reasons = select_slice(self.artifact, terminal)
        self.assertIsNone(slc)
        codes = [reason.code for reason in reasons]
        self.assertIn("no_selectable_slice", codes)
        self.assertIn("os_version_below_minimum", codes)

    def test_platform_mismatch_excludes_slice(self):
        terminal = Terminal(
            "iphone", CPU_ARM64, 0, PLATFORM_IOS, OSVersion(15, 0)
        )
        slc, reasons = select_slice(self.artifact, terminal)
        self.assertIsNone(slc)
        self.assertIn(
            "platform_mismatch", [reason.code for reason in reasons]
        )

    def test_wrong_cpu_type_is_rejected(self):
        terminal = Terminal(
            "alien", 999, 0, PLATFORM_MACOS, OSVersion(12, 0)
        )
        slc, reasons = select_slice(self.artifact, terminal)
        self.assertIsNone(slc)
        self.assertIn(
            "cpu_type_mismatch", [reason.code for reason in reasons]
        )


if __name__ == "__main__":
    unittest.main()
