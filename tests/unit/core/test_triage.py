# SPDX-License-Identifier: Apache-2.0
import datetime
import unittest

from bandit.core import issue
from bandit.core import triage


class FakeClock:
    def __init__(self, value):
        self.value = value

    def __call__(self):
        return self.value

    def advance(self, **kwargs):
        self.value += datetime.timedelta(**kwargs)


def make_issue(
    severity="MEDIUM",
    confidence="HIGH",
    test_id="B999",
    test_name="bandit_plugin",
    fname="code.py",
    lineno=1,
    col_offset=0,
    text="Test issue",
):
    result = issue.Issue(
        severity,
        cwe=issue.Cwe.MULTIPLE_BINDS,
        confidence=confidence,
        text=text,
        test_id=test_id,
    )
    result.fname = fname
    result.test = test_name
    result.lineno = lineno
    result.col_offset = col_offset
    result.end_col_offset = col_offset + 1
    return result


class TriageAllocatorTests(unittest.TestCase):
    def setUp(self):
        self.start = datetime.datetime(
            2026, 11, 28, 9, 0, tzinfo=datetime.timezone.utc
        )
        self.clock = FakeClock(self.start)

    def test_high_severity_stays_visible_when_quota_is_exhausted(self):
        allocator = triage.TriageAllocator(
            {"on-call": 0},
            non_deferrable=("HIGH",),
            clock=self.clock,
        )
        issues = [
            make_issue("HIGH", fname="a.py", lineno=1, test_id="B602"),
            make_issue("HIGH", fname="b.py", lineno=2, test_id="B605"),
            make_issue("MEDIUM", fname="c.py", lineno=3, test_id="B101"),
            make_issue("LOW", fname="d.py", lineno=4, test_id="B110"),
        ]

        result = allocator.allocate(issues, responsibilities="on-call")

        self.assertEqual(2, len(result.actionable))
        self.assertTrue(
            all(item.severity == "HIGH" for item in result.actionable)
        )
        self.assertTrue(all(item.over_quota for item in result.actionable))
        self.assertEqual(2, len(result.deferred))
        self.assertFalse(
            any(item.severity == "HIGH" for item in result.deferred)
        )

    def test_quota_accumulates_across_calls_and_reset_releases_queue(self):
        allocator = triage.TriageAllocator(
            {"team": 2}, non_deferrable=(), clock=self.clock
        )
        first = allocator.allocate(
            [make_issue("MEDIUM", fname="a.py", lineno=1)],
            responsibilities="team",
        )
        self.assertEqual(1, len(first.actionable))
        self.assertEqual(1, allocator.used_for("team"))

        second = allocator.allocate(
            [
                make_issue("MEDIUM", fname="b.py", lineno=1),
                make_issue("MEDIUM", fname="c.py", lineno=1),
            ],
            responsibilities="team",
        )
        self.assertEqual(1, len(second.actionable))
        self.assertEqual(1, len(second.deferred))
        self.assertEqual(2, allocator.used_for("team"))
        self.assertEqual(0, allocator.remaining_for("team"))

        released = allocator.reset_quota(now=self.clock())
        self.assertEqual(1, len(released))
        self.assertEqual(0, allocator.used_for("team"))
        self.assertEqual(0, len(allocator.pending))

        third = allocator.allocate(released, now=self.clock())
        self.assertEqual(1, len(third.actionable))
        self.assertEqual(1, allocator.used_for("team"))

    def test_duplicate_alerts_in_same_responsibility_use_one_slot(self):
        allocator = triage.TriageAllocator(
            {"team": 1}, non_deferrable=(), clock=self.clock
        )
        duplicate = make_issue("MEDIUM", fname="a.py", lineno=10)
        result = allocator.allocate(
            [duplicate, duplicate, duplicate], responsibilities="team"
        )

        self.assertEqual(1, len(result.actionable))
        self.assertEqual(0, len(result.deferred))
        self.assertEqual(2, result.duplicate_count)
        self.assertEqual(1, len(result.duplicates))
        self.assertEqual(2, result.duplicates[0].occurrences)
        self.assertEqual(2, result.actionable[0].duplicate_count)
        self.assertEqual(3, result.actionable[0].alert_count)
        self.assertEqual(1, allocator.used_for("team"))

    def test_multiple_plugins_at_same_location_merge_without_downgrade(self):
        allocator = triage.TriageAllocator(
            {"team": 1}, non_deferrable=("HIGH",), clock=self.clock
        )
        medium = make_issue(
            "MEDIUM",
            test_id="B101",
            test_name="assert_used",
            fname="a.py",
            lineno=7,
            col_offset=4,
        )
        high = make_issue(
            "HIGH",
            test_id="B602",
            test_name="subprocess_popen_with_shell_equals_true",
            fname="a.py",
            lineno=7,
            col_offset=10,
        )

        result = allocator.allocate([medium, high], responsibilities="team")

        self.assertEqual(1, len(result.actionable))
        finding = result.actionable[0]
        self.assertEqual("HIGH", finding.severity)
        self.assertEqual(("B101", "B602"), finding.test_ids)
        self.assertEqual(1, allocator.used_for("team"))
        self.assertEqual([], list(result.deferred))

    def test_same_location_under_different_responsibilities_is_kept(self):
        allocator = triage.TriageAllocator(
            {"team-a": 1, "team-b": 1},
            non_deferrable=(),
            clock=self.clock,
        )
        issue_a = make_issue("MEDIUM", fname="a.py", lineno=1, test_id="B1")
        issue_b = make_issue("MEDIUM", fname="a.py", lineno=1, test_id="B2")
        responsibilities = {
            issue_a: "team-a",
            issue_b: "team-b",
        }

        result = allocator.allocate([issue_a, issue_b], responsibilities)

        self.assertEqual(2, len(result.actionable))
        self.assertEqual(
            {"team-a", "team-b"},
            {item.responsibility for item in result.actionable},
        )

    def test_issues_without_line_numbers_are_not_collapsed(self):
        first = issue.Issue("MEDIUM", text="one", test_id="B1")
        second = issue.Issue("HIGH", text="two", test_id="B2")

        result = triage.allocate(
            [first, second],
            responsibilities="team",
            quotas={"team": 2},
            clock=self.clock,
        )

        self.assertEqual(2, len(result.actionable))
        self.assertEqual(
            {"B1", "B2"},
            {
                test_id
                for item in result.actionable
                for test_id in item.test_ids
            },
        )

    def test_deferred_queue_explains_when_it_can_resume(self):
        allocator = triage.TriageAllocator(
            {"team": 0}, non_deferrable=(), clock=self.clock
        )
        result = allocator.allocate(
            [make_issue("MEDIUM", fname="a.py", lineno=1)],
            responsibilities="team",
        )
        entry = result.deferred[0]

        self.assertEqual(allocator.next_reset_at, entry.resume_at)
        self.assertEqual("quota_exhausted", entry.reason)
        self.assertEqual("quota_reset", entry.resume_reason)
        self.assertFalse(entry.is_resumable(now=self.clock()))
        self.assertTrue(entry.is_resumable(now=entry.resume_at))
        serialized = entry.as_dict(with_code=False)
        self.assertEqual("quota_exhausted", serialized["defer_reason"])
        self.assertEqual(
            triage._isoformat(entry.resume_at), serialized["resume_at"]
        )
        self.assertEqual(1, len(result.deferral_queue))

    def test_period_rollover_restores_quota_automatically(self):
        allocator = triage.TriageAllocator(
            {"team": 1}, non_deferrable=(), clock=self.clock
        )
        allocator.allocate(
            [make_issue("MEDIUM", fname="a.py", lineno=1)],
            responsibilities="team",
        )
        self.assertEqual(0, allocator.remaining_for("team"))

        self.clock.advance(days=2)
        result = allocator.allocate(
            [make_issue("MEDIUM", fname="b.py", lineno=1)],
            responsibilities="team",
        )

        self.assertEqual(1, len(result.actionable))
        self.assertEqual(1, allocator.used_for("team"))

    def test_reset_can_target_one_responsibility(self):
        allocator = triage.TriageAllocator(
            {"a": 0, "b": 0}, non_deferrable=(), clock=self.clock
        )
        issue_a = make_issue("MEDIUM", fname="a.py", lineno=1)
        issue_b = make_issue("MEDIUM", fname="b.py", lineno=1)
        allocator.allocate([issue_a], responsibilities="a")
        allocator.allocate([issue_b], responsibilities="b")

        released = allocator.reset_quota("a", now=self.clock())

        self.assertEqual([issue_a], list(released[0].issues))
        self.assertEqual("b", allocator.pending[0].responsibility)
        self.assertEqual(0, allocator.used_for("a"))

    def test_weighted_costs_keep_mandatory_items_visible(self):
        allocator = triage.TriageAllocator(
            {"team": 2},
            non_deferrable=("HIGH",),
            severity_costs={"HIGH": 2, "MEDIUM": 1},
            clock=self.clock,
        )
        result = allocator.allocate(
            [
                make_issue("HIGH", fname="a.py", lineno=1),
                make_issue("MEDIUM", fname="b.py", lineno=1),
            ],
            responsibilities="team",
        )

        self.assertEqual(1, len(result.actionable))
        self.assertIn("HIGH", [item.severity for item in result.actionable])
        self.assertEqual(1, len(result.deferred))
        self.assertEqual(2, allocator.used_for("team"))

    def test_lower_non_deferrable_threshold_also_protects_high(self):
        allocator = triage.TriageAllocator(
            {"team": 0},
            non_deferrable=("MEDIUM",),
            clock=self.clock,
        )
        result = allocator.allocate(
            [
                make_issue("HIGH", fname="a.py", lineno=1),
                make_issue("MEDIUM", fname="b.py", lineno=1),
                make_issue("LOW", fname="c.py", lineno=1),
            ],
            responsibilities="team",
        )

        self.assertEqual(
            {"HIGH", "MEDIUM"}, {item.severity for item in result.actionable}
        )
        self.assertEqual(["LOW"], [item.severity for item in result.deferred])

    def test_downgraded_rule_keeps_original_high_severity_visible(self):
        downgraded = make_issue("LOW", fname="a.py", lineno=1, test_id="B602")
        downgraded.original_severity = "HIGH"
        allocator = triage.TriageAllocator(
            {"team": 0}, non_deferrable=("HIGH",), clock=self.clock
        )

        result = allocator.allocate([downgraded], responsibilities="team")

        self.assertEqual(1, len(result.actionable))
        self.assertEqual("HIGH", result.actionable[0].severity)
        self.assertEqual(0, len(result.deferred))
        item = result.as_dict(with_code=False)["results"][0]
        self.assertEqual("HIGH", item["issue_severity"])
        self.assertEqual("LOW", item["reported_severity"])
        self.assertTrue(item["severity_downgraded"])

    def test_existing_report_keys_are_preserved(self):
        allocator = triage.TriageAllocator(
            {"team": 1}, non_deferrable=(), clock=self.clock
        )
        result = allocator.allocate(
            [make_issue("MEDIUM", fname="a.py", lineno=5)],
            responsibilities="team",
        )
        report = result.as_dict(with_code=False)
        item = report["results"][0]

        for key in (
            "filename",
            "test_name",
            "test_id",
            "issue_severity",
            "issue_confidence",
            "issue_text",
            "line_number",
        ):
            self.assertIn(key, item)
        self.assertEqual("team", item["responsibility"])
        self.assertEqual(["B999"], item["test_ids"])
        self.assertEqual(
            len(result.actionable) + len(result.deferred),
            len(report["results"]),
        )
        self.assertIn("deferral_queue", report)
        self.assertIn("next_reset_at", report)

    def test_responsibility_can_be_mapping_callable_or_issue_attribute(self):
        issue_a = make_issue("MEDIUM", fname="a.py", lineno=1)
        issue_b = make_issue("MEDIUM", fname="b.py", lineno=1)
        issue_c = make_issue("MEDIUM", fname="c.py", lineno=1)
        issue_c.responsibility = "team-c"

        mapped = triage.allocate(
            [issue_a],
            responsibilities={("a.py", 1): "team-a"},
            quotas={"team-a": 1},
            clock=self.clock,
        )
        self.assertEqual("team-a", mapped.actionable[0].responsibility)

        called = triage.allocate(
            [issue_b],
            responsibilities=lambda item: "team-" + item.fname[0],
            quotas={"team-b": 1},
            clock=self.clock,
        )
        self.assertEqual("team-b", called.actionable[0].responsibility)

        attributed = triage.allocate(
            [issue_c], quotas={"team-c": 1}, clock=self.clock
        )
        self.assertEqual("team-c", attributed.actionable[0].responsibility)

    def test_invalid_configuration_is_rejected(self):
        with self.assertRaises(ValueError):
            triage.TriageAllocator({"team": -1})
        with self.assertRaises(ValueError):
            triage.TriageAllocator({"team": 1}, non_deferrable=("CRITICAL",))
        with self.assertRaises(TypeError):
            triage.TriageAllocator({"team": 1}, severity_costs=3)

    def test_manager_helper_reuses_existing_issue_list(self):
        class Manager:
            def __init__(self, issues):
                self.issues = issues

            def get_issue_list(self, sev_level, conf_level):
                return self.issues

        result = triage.triage_manager(
            Manager([make_issue("HIGH", fname="a.py", lineno=1)]),
            responsibilities="team",
            quotas={"team": 0},
            clock=self.clock,
        )

        self.assertEqual(1, len(result.actionable))
        self.assertEqual("HIGH", result.actionable[0].severity)


if __name__ == "__main__":
    unittest.main()
