"""Tests for offline signing-policy review."""

import json
import tempfile
import unittest
from pathlib import Path

from securesystemslib.policy_review.cli import main
from securesystemslib.policy_review.metrics import (
    minimum_blocking_domains,
    minimum_satisfying_domains,
)
from securesystemslib.policy_review.models import PolicyReviewError
from securesystemslib.policy_review.policy import parse_policy
from securesystemslib.policy_review.report import report_to_dict, report_to_markdown
from securesystemslib.policy_review.review import review
from securesystemslib.policy_review.roster import parse_roster


def _threshold_policy(keyids, threshold, policy_id="p", rule_id="r"):
    return parse_policy(
        {
            "policy_id": policy_id,
            "rules": [
                {"rule_id": rule_id, "type": "threshold", "keyids": keyids,
                    "threshold": threshold}
            ],
        }
    )


def _roster(mapping, roster_id="r", candidates=None):
    candidates = candidates or {}
    all_keyids = list(mapping) + [k for k in candidates if k not in mapping]
    keys = []
    for keyid in all_keyids:
        owners = [{"domain": d, "status": "confirmed"} for d in mapping.get(keyid, [])]
        owners += [
            {"domain": d, "status": "candidate"} for d in candidates.get(keyid, [])
        ]
        keys.append({"keyid": keyid, "owners": owners})
    return parse_roster({"roster_id": roster_id, "frozen_at": "2026-11-22",
        "keys": keys})

class TestPolicyParsing(unittest.TestCase):
    def test_threshold_expands_to_all_combinations(self):
        policy = _threshold_policy(["a", "b", "c"], 2)
        self.assertEqual(len(policy.rules), 3)
        self.assertEqual(len(policy.rule_index), 3)
        self.assertEqual(policy.keyids, frozenset({"a", "b", "c"}))

    def test_slots_expand_alternates_and_dedupe_combos(self):
        policy = parse_policy(
            {
                "policy_id": "p",
                "rules": [
                    {"rule_id": "s", "type": "slots", "slots": [["a", "b"], "c"]},
                    {"rule_id": "c", "type": "combination", "keyids": ["a", "c"]},
                ],
            }
        )
        # slots yield {a,c} and {b,c}; combination duplicates {a,c}.
        self.assertEqual(len(policy.rules), 3)
        self.assertEqual(len(policy.rule_index), 2)
        merged = next(iter(v for k,
            v in policy.rule_index.items() if k == frozenset({"a", "c"})))
        self.assertEqual(merged, ("s", "c"))

    def test_slot_rejects_key_reuse_across_slots(self):
        with self.assertRaises(PolicyReviewError):
            parse_policy(
                {
                "policy_id": "p",
                "rules": [{"type": "slots", "slots": [["a"], "a"]}],
                }
            )

    def test_threshold_bounds_validated(self):
        with self.assertRaises(PolicyReviewError):
            _threshold_policy(["a", "b"], 3)
        with self.assertRaises(PolicyReviewError):
            _threshold_policy(["a", "b"], 0)

    def test_unknown_rule_type_rejected(self):
        with self.assertRaises(PolicyReviewError):
            parse_policy({"policy_id": "p", "rules": [{"type": "mystery"}]})

class TestRosterParsing(unittest.TestCase):
    def test_candidate_kept_separate_from_confirmed(self):
        roster = parse_roster(
            {
                "roster_id": "r",
                "keys": [
                {
                    "keyid": "a",
                    "owners": [
                    {"domain": "X", "status": "confirmed"},
                    {"domain": "Y", "status": "candidate"},
                    {"domain": "X", "status": "candidate"},
                    ],
                }
                ],
            }
        )
        ownership = roster.ownership["a"]
        self.assertEqual(ownership.confirmed, frozenset({"X"}))
        self.assertEqual(ownership.candidates, frozenset({"Y"}))
        self.assertFalse(ownership.unresolved)

    def test_key_with_only_candidates_is_unresolved(self):
        roster = parse_roster(
            {
                "roster_id": "r",
                "keys": [{"keyid": "a", "owners": [{"domain": "Y",
                    "status": "candidate"}]}],
            }
        )
        self.assertTrue(roster.ownership["a"].unresolved)

    def test_duplicate_key_rejected(self):
        with self.assertRaises(PolicyReviewError):
            parse_roster(
                {
                "roster_id": "r",
                "keys": [
                {"keyid": "a", "owners": [{"domain": "X"}]},
                {"keyid": "a", "owners": [{"domain": "Y"}]},
                ],
                }
            )

class TestMetrics(unittest.TestCase):
    def _key_domains(self, mapping):
        return {k: frozenset(v) for k, v in mapping.items()}

    def test_balanced_three_of_six(self):
        policy = _threshold_policy([f"k{i}" for i in range(1, 7)], 3)
        key_domains = self._key_domains(
            {
                "k1": ["A"], "k2": ["A"],
                "k3": ["B"], "k4": ["B"],
                "k5": ["C"], "k6": ["C"],
            }
        )
        satisfying = minimum_satisfying_domains(policy, key_domains)
        blocking = minimum_blocking_domains(policy, key_domains)
        self.assertEqual(satisfying.value, 2)
        self.assertEqual(blocking.value, 2)
        self.assertTrue(satisfying.exhaustive and blocking.exhaustive)

    def test_shared_owner_collapses_both_metrics_to_one(self):
        policy = _threshold_policy([f"k{i}" for i in range(1, 7)], 3)
        key_domains = self._key_domains(
            {
                "k1": ["A"], "k2": ["A"], "k3": ["A"], "k4": ["A"],
                "k5": ["B"], "k6": ["C"],
            }
        )
        satisfying = minimum_satisfying_domains(policy, key_domains)
        blocking = minimum_blocking_domains(policy, key_domains)
        self.assertEqual(satisfying.value, 1)
        self.assertEqual(satisfying.witness.domains, frozenset({"A"}))
        self.assertEqual(blocking.value, 1)
        self.assertEqual(blocking.witness.domains, frozenset({"A"}))

    def test_blocking_needs_two_when_no_domain_holds_majority(self):
        # 2-of-2 with keys on different domains: one absence never blocks.
        policy = _threshold_policy(["x", "y"], 2)
        key_domains = self._key_domains({"x": ["A"], "y": ["B"]})
        self.assertEqual(minimum_satisfying_domains(policy, key_domains).value, 2)
        self.assertEqual(minimum_blocking_domains(policy, key_domains).value, 1)

    def test_witness_lists_supplying_domains_per_key(self):
        policy = _threshold_policy(["x", "y"], 2)
        key_domains = self._key_domains({"x": ["A", "B"], "y": ["B"]})
        metric = minimum_satisfying_domains(policy, key_domains)
        self.assertEqual(metric.value, 1)
        self.assertEqual(metric.witness.key_to_domains["x"], ("B",))
        self.assertEqual(metric.witness.key_to_domains["y"], ("B",))

class TestReview(unittest.TestCase):
    def test_missing_roster_entry_raises(self):
        policy = _threshold_policy(["a", "b"], 2)
        roster = _roster({"a": ["X"]})
        with self.assertRaises(PolicyReviewError):
            review(policy, roster)

    def test_extra_roster_entry_raises(self):
        policy = _threshold_policy(["a"], 1)
        roster = _roster({"a": ["X"], "b": ["Y"]})
        with self.assertRaises(PolicyReviewError):
            review(policy, roster)

    def test_shared_owner_finding_is_deduped_and_explicit(self):
        policy = _threshold_policy(["a", "b", "c"], 3)
        roster = _roster({"a": ["A"], "b": ["A"], "c": ["A"]})
        report = review(policy, roster)
        shared = [f for f in report.findings if f.startswith("shared-owner")]
        self.assertEqual(len(shared), 1)
        self.assertIn("domain "+repr("A"), shared[0])

    def test_candidate_range_reports_distinct_extremes(self):
        policy = parse_policy(
            {
                "policy_id": "p",
                "rules": [
                {"rule_id": "east", "type": "combination", "keyids": ["a", "b"]},
                {"rule_id": "west", "type": "combination", "keyids": ["a", "c"]},
                ],
            }
        )
        roster = _roster(
            {"a": ["A"]},
            candidates={"b": ["A", "B"], "c": ["A", "C"]},
        )
        report = review(policy, roster)
        rng = report.candidate_range
        self.assertIsNotNone(rng)
        self.assertTrue(rng.exhaustive)
        self.assertEqual((rng.satisfying_min, rng.satisfying_max), (1, 2))
        self.assertNotEqual(
            rng.best_resolution.assignment, rng.worst_resolution.assignment
        )
        self.assertIn("b", report.unassigned_keyids)

    def test_confirmed_view_flags_unassigned_placeholder(self):
        policy = _threshold_policy(["a", "b"], 2)
        roster = _roster({"a": ["A"]}, candidates={"b": ["B", "C"]})
        report = review(policy, roster)
        self.assertTrue(report.warnings)
        markdown = report_to_markdown(report)
        self.assertIn("UNASSIGNED-PENDING-CONFIRMATION", markdown)

class TestReportAndCli(unittest.TestCase):
    def setUp(self):
        self.policy = _threshold_policy(["a", "b", "c"], 3)
        self.roster = _roster({"a": ["A"], "b": ["A"], "c": ["B"]})

    def test_json_report_is_serializable(self):
        report = review(self.policy, self.roster)
        encoded = json.dumps(report_to_dict(report))
        decoded = json.loads(encoded)
        satisfying = decoded["confirmed_view"]["minimum_satisfying_domains"]
        self.assertEqual(satisfying["value"], 2)
        self.assertIn("witness", decoded["confirmed_view"]["minimum_blocking_domains"])

    def test_markdown_contains_hand_check_table(self):
        report = review(self.policy, self.roster)
        markdown = report_to_markdown(report)
        self.assertIn("| Rule | Key id | Supplied by witness domain(s) |", markdown)
        self.assertIn("Minimum domains", markdown)

    def test_cli_writes_json_file_and_returns_zero(self):
        report = review(self.policy, self.roster)
        with tempfile.TemporaryDirectory() as tmp:
            policy_path = Path(tmp) / "policy.json"
            roster_path = Path(tmp) / "roster.json"
            output_path = Path(tmp) / "report.json"
            policy_path.write_text(json.dumps({"policy_id": "p", "rules": [
                {"rule_id": "r", "type": "threshold", "keyids": ["a", "b", "c"],
                    "threshold": 3}
            ]}))
            roster_path.write_text(json.dumps({"roster_id": "r", "keys": [
                {"keyid": "a", "owners": [{"domain": "A"}]},
                {"keyid": "b", "owners": [{"domain": "A"}]},
                {"keyid": "c", "owners": [{"domain": "B"}]},
            ]}))
            code = main([str(policy_path), str(roster_path), "--format", "json",
                "--output", str(output_path)])
            self.assertEqual(code, 0)
            decoded = json.loads(output_path.read_text())
            self.assertEqual(decoded["policy_id"], "p")

    def test_cli_returns_error_code_on_bad_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy_path = Path(tmp) / "policy.json"
            roster_path = Path(tmp) / "roster.json"
            policy_path.write_text(json.dumps({"policy_id": "p", "rules": []}))
            roster_path.write_text(json.dumps({"roster_id": "r", "keys": []}))
            code = main([str(policy_path), str(roster_path)])
            self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
