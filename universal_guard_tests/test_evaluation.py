import unittest

from universal_guard import (
    OSVersion,
    ProtectionPolicy,
    Terminal,
    TerminalStatus,
    evaluate,
)

from .fixtures import (
    CPU_ARM64,
    CPU_X86_64,
    PLATFORM_IOS,
    PLATFORM_MACOS,
    build_artifact,
    evidence_for,
    parsed_artifact,
)


def make_terminals():
    return [
        Terminal("intel-catalina", CPU_X86_64, 3, PLATFORM_MACOS,
                 OSVersion(10, 15)),
        Terminal("intel-mojave", CPU_X86_64, 3, PLATFORM_MACOS,
                 OSVersion(10, 14)),
        Terminal("apple-bigsur", CPU_ARM64, 0, PLATFORM_MACOS,
                 OSVersion(11, 0)),
        Terminal("apple-monterey", CPU_ARM64, 0, PLATFORM_MACOS,
                 OSVersion(12, 0)),
        Terminal("iphone", CPU_ARM64, 0, PLATFORM_IOS,
                 OSVersion(15, 0)),
    ]


class TestEvaluation(unittest.TestCase):
    def setUp(self):
        self.artifact = parsed_artifact()
        self.terminals = make_terminals()

    def _report(self, overrides=None, policy=None):
        return evaluate(
            build_artifact(),
            self.terminals,
            evidence_for(self.artifact, overrides),
            policy=policy or ProtectionPolicy(),
        )

    def test_all_covered_when_every_slice_verified(self):
        report = self._report()
        statuses = {
            item.terminal_id: item.status for item in report.terminals
        }
        self.assertEqual(
            statuses["intel-catalina"], TerminalStatus.COVERED
        )
        self.assertEqual(
            statuses["apple-monterey"], TerminalStatus.COVERED
        )

    def test_unsupported_platform_is_missing_evidence(self):
        report = self._report()
        iphone = next(
            item for item in report.terminals
            if item.terminal_id == "iphone"
        )
        self.assertEqual(iphone.status, TerminalStatus.MISSING_EVIDENCE)
        self.assertIn(
            "no_selectable_slice",
            [reason.code for reason in iphone.reasons],
        )

    def test_inconsistent_slices_split_terminal_verdicts(self):
        # arm64 slice fails backend verification; x86_64 stays valid.
        report = self._report(overrides={1: False})
        by_id = {
            item.terminal_id: item for item in report.terminals
        }
        self.assertEqual(
            by_id["intel-catalina"].status, TerminalStatus.COVERED
        )
        self.assertEqual(
            by_id["apple-bigsur"].status,
            TerminalStatus.MISSING_EVIDENCE,
        )
        self.assertIn(
            "signature_verification_failed",
            [reason.code for reason in by_id["apple-bigsur"].reasons],
        )
        self.assertEqual(
            report.slices[0].status.value, "covered"
        )
        self.assertEqual(
            report.slices[1].status.value, "missing_evidence"
        )

    def test_missing_evidence_when_no_verification_supplied(self):
        report = evaluate(
            build_artifact(), self.terminals, [],
            policy=ProtectionPolicy(),
        )
        self.assertTrue(
            all(
                item.status == TerminalStatus.MISSING_EVIDENCE
                for item in report.terminals
                if item.slice_index is not None
            )
        )

    def test_required_protection_attribute_drives_at_risk(self):
        policy = ProtectionPolicy(
            required_attributes={"hardened_runtime": True}
        )
        report = self._report(policy=policy)
        by_id = {
            item.terminal_id: item for item in report.terminals
        }
        # x86_64 slice has CS_RUNTIME, arm64 does not.
        self.assertEqual(
            by_id["intel-catalina"].status, TerminalStatus.COVERED
        )
        self.assertEqual(
            by_id["apple-bigsur"].status, TerminalStatus.AT_RISK
        )
        self.assertIn(
            "protection_attribute_missing",
            [
                reason.code
                for reason in by_id["apple-bigsur"].reasons
            ],
        )

    def test_deployment_scope_can_exclude_a_terminal(self):
        scopes = {
            0: {"max_os": OSVersion(10, 14)},
        }
        report = evaluate(
            build_artifact(),
            self.terminals,
            evidence_for(self.artifact),
            policy=ProtectionPolicy(),
            deployment_scopes=scopes,
        )
        by_id = {
            item.terminal_id: item for item in report.terminals
        }
        self.assertEqual(
            by_id["intel-mojave"].status, TerminalStatus.COVERED
        )
        self.assertEqual(
            by_id["intel-catalina"].status,
            TerminalStatus.MISSING_EVIDENCE,
        )
        self.assertIn(
            "deployment_scope_excluded",
            [
                reason.code
                for reason in by_id["intel-catalina"].reasons
            ],
        )

    def test_report_groups_terminals_by_status(self):
        report = self._report(overrides={1: False})
        covered_ids = {item.terminal_id for item in report.covered}
        missing_ids = {
            item.terminal_id for item in report.missing_evidence
        }
        self.assertIn("intel-catalina", covered_ids)
        self.assertIn("apple-bigsur", missing_ids)
        self.assertIn("iphone", missing_ids)


if __name__ == "__main__":
    unittest.main()
