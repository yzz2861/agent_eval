import unittest

from universal_guard import (
    OSVersion,
    ProtectionPolicy,
    Terminal,
    TerminalStatus,
    diff_reports,
    evaluate,
    explain_change,
    parse_artifact,
    rewrite_minimum_os,
)

from .fixtures import (
    CPU_ARM64,
    CPU_X86_64,
    PLATFORM_IOS,
    PLATFORM_MACOS,
    build_artifact,
    evidence_for,
)


def make_terminals():
    return [
        Terminal("intel-catalina", CPU_X86_64, 3, PLATFORM_MACOS,
                 OSVersion(10, 15)),
        Terminal("intel-mojave", CPU_X86_64, 3, PLATFORM_MACOS,
                 OSVersion(10, 14)),
        Terminal("apple-bigsur", CPU_ARM64, 0, PLATFORM_MACOS,
                 OSVersion(11, 0)),
        Terminal("iphone", CPU_ARM64, 0, PLATFORM_IOS,
                 OSVersion(15, 0)),
    ]


class TestMinimumOsRewrite(unittest.TestCase):
    def setUp(self):
        self.data = build_artifact()
        self.terminals = make_terminals()

    def test_rewrite_changes_only_target_slice(self):
        rewritten = rewrite_minimum_os(
            self.data, (10, 15, 0),
            cpu_type=CPU_X86_64, cpu_subtype=3,
        )
        artifact = parse_artifact(rewritten)
        self.assertEqual(
            str(artifact.slices[0].platform.min_os), "10.15.0"
        )
        self.assertEqual(
            str(artifact.slices[1].platform.min_os), "11.0.0"
        )

    def test_raised_minimum_os_moves_terminal_to_missing_evidence(self):
        before = parse_artifact(self.data)
        report_before = evaluate(
            self.data, self.terminals,
            evidence_for(before), policy=ProtectionPolicy(),
        )
        rewritten = rewrite_minimum_os(
            self.data, (10, 15, 0),
            cpu_type=CPU_X86_64, cpu_subtype=3,
        )
        after = parse_artifact(rewritten)
        report_after = evaluate(
            rewritten, self.terminals,
            evidence_for(after), policy=ProtectionPolicy(),
        )

        changes = diff_reports(report_before, report_after)
        changed_ids = [change.terminal_id for change in changes]
        self.assertEqual(changed_ids, ["intel-mojave"])

        mojave_after = next(
            item for item in report_after.terminals
            if item.terminal_id == "intel-mojave"
        )
        self.assertEqual(
            mojave_after.status, TerminalStatus.MISSING_EVIDENCE
        )
        self.assertIn(
            "os_version_below_minimum",
            [reason.code for reason in mojave_after.reasons],
        )

    def test_explain_change_names_affected_terminal(self):
        before = parse_artifact(self.data)
        report_before = evaluate(
            self.data, self.terminals,
            evidence_for(before), policy=ProtectionPolicy(),
        )
        rewritten = rewrite_minimum_os(
            self.data, (10, 15, 0),
            cpu_type=CPU_X86_64, cpu_subtype=3,
        )
        after = parse_artifact(rewritten)
        report_after = evaluate(
            rewritten, self.terminals,
            evidence_for(after), policy=ProtectionPolicy(),
        )
        explanation = explain_change(report_before, report_after)
        self.assertEqual(len(explanation), 1)
        self.assertIn("intel-mojave", explanation[0])
        self.assertIn("covered", explanation[0])
        self.assertIn("missing_evidence", explanation[0])

    def test_rewrite_invalidates_stale_evidence(self):
        before = parse_artifact(self.data)
        stale_evidence = evidence_for(before)
        rewritten = rewrite_minimum_os(
            self.data, (10, 15, 0),
            cpu_type=CPU_X86_64, cpu_subtype=3,
        )
        report = evaluate(
            rewritten, self.terminals, stale_evidence,
            policy=ProtectionPolicy(),
        )
        self.assertTrue(
            any(
                reason.code == "evidence_digest_mismatch"
                for reason in report.unmatched_evidence
            )
        )

    def test_unknown_architecture_raises(self):
        with self.assertRaises(ValueError):
            rewrite_minimum_os(
                self.data, (10, 15, 0),
                cpu_type=999, cpu_subtype=0,
            )


if __name__ == "__main__":
    unittest.main()
