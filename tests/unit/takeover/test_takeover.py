# SPDX-License-Identifier: Apache-2.0
import testtools

from bandit.takeover import paths
from bandit.takeover.models import Finding, fingerprint, severity_rank
from bandit.takeover.ownership import OwnershipPolicy, UNOWNED
from bandit.takeover.ledger import Handoff, HandoffLedger
from bandit.takeover.coverage import CoverageTracker, CoverageStatus
from bandit.takeover.engine import AdjudicationEngine, Disposition
from bandit.takeover.loader import load_policy
from bandit.takeover import reports


def result(
    filename,
    test_id,
    test_name,
    text,
    severity="LOW",
    confidence="HIGH",
    cwe=259,
    line=1,
):
    return {
        "filename": filename,
        "line_number": line,
        "line_range": [line],
        "test_id": test_id,
        "test_name": test_name,
        "issue_text": text,
        "issue_severity": severity,
        "issue_confidence": confidence,
        "issue_cwe": {"id": cwe},
    }


class PathsTests(testtools.TestCase):
    def test_normalize_handles_separators_and_absolute(self):
        self.assertEqual(
            "svc/portal/auth.py",
            paths.normalize_path("./svc\\portal/auth.py"),
        )
        self.assertEqual(
            "repo/svc/portal/auth.py",
            paths.normalize_path("/repo/svc/portal/auth.py"),
        )
        self.assertEqual(
            "svc/portal/auth.py",
            paths.normalize_path("/svc/portal/auth.py"),
        )

    def test_is_within_boundary(self):
        self.assertTrue(paths.is_within("svc/portal", "svc/portal/a.py"))
        self.assertTrue(paths.is_within("svc/portal", "svc/portal"))
        self.assertFalse(paths.is_within("svc/portal", "svc/portal-ish/x.py"))

    def test_path_map_rewrite_longest_prefix_first(self):
        path_map = paths.PathMap(
            [("monolith", "svc"), ("monolith/portal", "svc/portal")]
        )
        self.assertEqual(
            "svc/portal/auth.py",
            path_map.rewrite("monolith/portal/auth.py"),
        )
        self.assertEqual(
            "svc/billing/x.py",
            path_map.rewrite("monolith/billing/x.py"),
        )


class ModelTests(testtools.TestCase):
    def test_fingerprint_ignores_severity_and_line(self):
        low = result("a.py", "B105", "t", "text", severity="LOW", line=2)
        high = result("a.py", "B105", "t", "text", severity="HIGH", line=99)
        self.assertEqual(fingerprint(low), fingerprint(high))

    def test_fingerprint_distinguishes_identity(self):
        first = result("a.py", "B105", "t", "one")
        second = result("a.py", "B106", "t", "two")
        self.assertNotEqual(fingerprint(first), fingerprint(second))

    def test_severity_rank(self):
        self.assertLess(severity_rank("LOW"), severity_rank("HIGH"))


class OwnershipAndLedgerTests(testtools.TestCase):
    def setUp(self):
        super().setUp()
        self.policy = OwnershipPolicy.from_dict(
            {
                "ownership": [
                    {"directory": "svc/portal", "team": "portal-team"},
                    {"directory": "svc", "team": "platform-team"},
                ]
            }
        )
        self.handoff = Handoff(
            "H1",
            "monolith/portal",
            "svc/portal",
            "platform-team",
            "portal-team",
            "2026-11-17",
        )

    def test_longest_prefix_owner_wins(self):
        self.assertEqual(
            "portal-team", self.policy.resolve("svc/portal/auth.py")
        )
        self.assertEqual(
            "platform-team", self.policy.resolve("svc/billing/x.py")
        )
        self.assertEqual(UNOWNED, self.policy.resolve("docs/x.rst"))

    def test_handoff_translates_paths_and_scopes_coverage(self):
        self.assertTrue(self.handoff.covers("svc/portal/auth.py"))
        self.assertFalse(self.handoff.covers("svc/billing/x.py"))
        self.assertEqual(
            "monolith/portal/auth.py",
            self.handoff.moved_from("svc/portal/auth.py"),
        )

    def test_ledger_picks_most_specific_record(self):
        broad = Handoff("H0", "monolith", "svc", "a", "b", "2026-11-01")
        ledger = HandoffLedger([broad, self.handoff])
        self.assertEqual(
            "H1", ledger.find("svc/portal/auth.py").record_id
        )
        self.assertEqual("H0", ledger.find("svc/billing/x.py").record_id)


class CoverageTests(testtools.TestCase):
    def test_directory_states(self):
        tracker = CoverageTracker(["svc/portal", "svc/billing", "tools/admin"])
        coverages = tracker.evaluate(
            scanned_files=["svc/portal/a.py", "svc/billing/ok.py"],
            errors=[
                {
                    "filename": "svc/billing/broken.py",
                    "reason": "syntax error",
                }
            ],
        )
        statuses = {c.directory: c.status for c in coverages}
        self.assertEqual(CoverageStatus.SCANNED, statuses["svc/portal"])
        self.assertEqual(CoverageStatus.PARTIAL, statuses["svc/billing"])
        self.assertEqual(
            CoverageStatus.NOT_SCANNED, statuses["tools/admin"]
        )
        unknown = [c for c in coverages if c.risk_unknown]
        self.assertEqual(2, len(unknown))

    def test_fully_failed_directory_is_unknown_risk(self):
        tracker = CoverageTracker(["svc/billing"])
        coverages = tracker.evaluate(
            scanned_files=[],
            errors=[{"filename": "svc/billing/x.py", "reason": "boom"}],
        )
        self.assertEqual(CoverageStatus.FAILED, coverages[0].status)
        self.assertTrue(coverages[0].risk_unknown)


def build_engine():
    policy = OwnershipPolicy.from_dict(
        {
            "ownership": [
                {"directory": "svc/portal", "team": "portal-team"},
                {"directory": "svc/billing", "team": "billing-team"},
                {"directory": "tools/admin", "team": "sre-team"},
                {"directory": "svc", "team": "platform-team"},
            ]
        }
    )
    ledger = HandoffLedger(
        [
            Handoff(
                "HO-1",
                "monolith/portal",
                "svc/portal",
                "platform-team",
                "portal-team",
                "2026-11-17",
            )
        ]
    )
    return AdjudicationEngine(policy, ledger)


class EngineTests(testtools.TestCase):
    def test_legacy_debt_carries_across_accepted_handoff(self):
        engine = build_engine()
        legacy = {
            "results": [
                result(
                    "monolith/portal/auth.py",
                    "B105",
                    "hardcoded_password_string",
                    "hardcoded pwd",
                    severity="LOW",
                )
            ]
        }
        current = {
            "results": [
                result(
                    "svc/portal/auth.py",
                    "B105",
                    "hardcoded_password_string",
                    "hardcoded pwd",
                    severity="LOW",
                    line=14,
                )
            ],
            "errors": [],
        }
        report = engine.adjudicate(current, legacy, ["svc/portal"])
        adjudication = report.adjudications[0]
        self.assertEqual(Disposition.LEGACY_DEBT, adjudication.disposition)
        self.assertFalse(adjudication.blocks)
        self.assertEqual("portal-team", adjudication.owner)
        self.assertEqual("HO-1", adjudication.handoff.record_id)
        self.assertEqual(
            "monolith/portal/auth.py", adjudication.legacy_filename
        )

    def test_escalation_blocks_even_under_handoff(self):
        engine = build_engine()
        legacy = {
            "results": [
                result(
                    "monolith/portal/views.py",
                    "B608",
                    "xss",
                    "mark safe",
                    severity="MEDIUM",
                    confidence="MEDIUM",
                    cwe=80,
                )
            ]
        }
        current = {
            "results": [
                result(
                    "svc/portal/views.py",
                    "B608",
                    "xss",
                    "mark safe",
                    severity="HIGH",
                    confidence="HIGH",
                    cwe=80,
                )
            ],
            "errors": [],
        }
        report = engine.adjudicate(current, legacy, ["svc/portal"])
        adjudication = report.adjudications[0]
        self.assertEqual(Disposition.ESCALATED, adjudication.disposition)
        self.assertTrue(adjudication.blocks)
        self.assertIn(
            "severity escalated MEDIUM -> HIGH", adjudication.reasons
        )

    def test_cross_boundary_without_handoff_is_new_debt(self):
        engine = build_engine()
        legacy = {
            "results": [
                result(
                    "tools/admin/runner.py",
                    "B602",
                    "shell",
                    "shell true",
                    severity="HIGH",
                    cwe=78,
                )
            ]
        }
        current = {
            "results": [
                result(
                    "svc/billing/runner.py",
                    "B602",
                    "shell",
                    "shell true",
                    severity="HIGH",
                    cwe=78,
                )
            ],
            "errors": [],
        }
        report = engine.adjudicate(current, legacy, ["svc/billing"])
        adjudication = report.adjudications[0]
        self.assertEqual(
            Disposition.CROSS_BOUNDARY_UNACCEPTED, adjudication.disposition
        )
        self.assertTrue(adjudication.blocks)
        self.assertIsNone(adjudication.handoff)

    def test_new_finding_blocks(self):
        engine = build_engine()
        current = {
            "results": [
                result("svc/portal/api.py", "B321", "xml", "xml parse")
            ],
            "errors": [],
        }
        report = engine.adjudicate(current, {}, ["svc/portal"])
        self.assertEqual(
            Disposition.NEW_FINDING, report.adjudications[0].disposition
        )
        self.assertTrue(report.gate_failed)

    def test_resolved_legacy_is_reported(self):
        engine = build_engine()
        legacy = {
            "results": [
                result("svc/portal/old.py", "B110", "te", "pass")
            ]
        }
        current = {"results": [], "errors": []}
        report = engine.adjudicate(current, legacy, ["svc/portal"])
        self.assertEqual(1, len(report.resolved_legacy))

    def test_gate_fails_on_unknown_risk_even_without_blocking_finding(self):
        engine = build_engine()
        current = {"results": [], "errors": []}
        report = engine.adjudicate(current, {}, ["tools/admin"])
        self.assertTrue(report.gate_failed)
        self.assertEqual(
            "not_scanned",
            report.unknown_risk_directories()[0].status.value,
        )

    def test_gate_passes_for_clean_full_scan(self):
        engine = build_engine()
        current = {
            "results": [],
            "errors": [],
            "metrics": {"svc/portal/clean.py": {"loc": 1}},
        }
        report = engine.adjudicate(current, {}, ["svc/portal"])
        self.assertFalse(report.gate_failed)


class ReportTests(testtools.TestCase):
    def test_legacy_report_keeps_bandit_shape(self):
        scan = {
            "results": [result("a.py", "B105", "t", "x")],
            "errors": [{"filename": "b.py", "reason": "boom"}],
            "metrics": {"_totals": {"loc": 1}},
        }
        rendered = reports.render_legacy_report(scan)
        import json

        data = json.loads(rendered)
        self.assertEqual(
            {"errors", "results", "metrics", "generated_at"},
            set(data),
        )
        self.assertEqual(1, len(data["results"]))

    def test_approval_detail_lists_owner_and_unknown_directories(self):
        engine = build_engine()
        current = {
            "results": [
                result("svc/portal/api.py", "B321", "xml", "xml parse")
            ],
            "errors": [],
        }
        report = engine.adjudicate(current, {}, ["svc/portal", "tools/admin"])
        text = reports.render_approval_detail(report)
        self.assertIn("Owner: portal-team", text)
        self.assertIn("New finding - fix now", text)
        self.assertIn("tools/admin [not_scanned]", text)
        self.assertIn("Gate decision: FAIL", text)


class PolicyLoaderTests(testtools.TestCase):
    def test_load_example_policy_bundle(self):
        bundle = load_policy("examples/takeover/ownership-policy.yaml")
        self.assertEqual(
            "portal-team",
            bundle.ownership_policy.resolve("svc/portal/auth.py"),
        )
        self.assertEqual(1, len(bundle.handoff_ledger))
        self.assertIn("svc/portal", bundle.scan_manifest)
