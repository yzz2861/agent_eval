import json
import unittest
from pathlib import Path

from regression.engine import build_pairs, evaluate_pairs, run_regression
from regression.loader import (
    load_gate,
    load_rules,
    load_samples,
    load_scan,
    load_scopes,
)
from regression.model import PairVerdict
from regression.report import render_coverage_report, render_gate_report

ROOT = Path(__file__).resolve().parents[1]
FROZEN = ROOT / "fixtures" / "frozen"
SCANS = ROOT / "fixtures" / "scans"


def _load_all():
    rules = load_rules(FROZEN / "rule_catalogue.json")
    samples = load_samples(FROZEN / "samples.json", FROZEN)
    scopes = load_scopes(FROZEN / "applicability.json")
    default_floor, groups = load_gate(FROZEN / "gate.json")
    old_scan = load_scan(SCANS / "old_bandit.json", "old")
    new_scan = load_scan(SCANS / "new_bandit.json", "new")
    return rules, samples, scopes, default_floor, groups, old_scan, new_scan


class LoaderTest(unittest.TestCase):
    def test_duplicate_findings_collapsed(self):
        old_scan = load_scan(SCANS / "old_bandit.json", "old")
        self.assertEqual(old_scan.raw_hit_count, 12)
        self.assertEqual(len(old_scan.unique_hits), 11)
        self.assertEqual(old_scan.duplicate_hits_removed, 1)
        new_scan = load_scan(SCANS / "new_bandit.json", "new")
        self.assertEqual(new_scan.raw_hit_count, 15)
        self.assertEqual(len(new_scan.unique_hits), 14)
        self.assertEqual(new_scan.duplicate_hits_removed, 1)

    def test_disabled_rules_loaded(self):
        new_scan = load_scan(SCANS / "new_bandit.json", "new")
        self.assertEqual(new_scan.disabled_rules, {"B108"})

    def test_freeze_integrity_detects_drift(self):
        samples = load_samples(FROZEN / "samples.json", FROZEN)
        self.assertEqual(len(samples), 14)
        tampered = [
            {
                "sample_id": "X1",
                "path": "src/company/s01_os_system.py",
                "family": "command_injection",
                "adjudication": "confirmed",
                "rule_id": "B602",
                "severity": "HIGH",
                "sha256": "0" * 64,
            }
        ]
        tmp = ROOT / "output" / "_tampered_manifest.json"
        tmp.parent.mkdir(exist_ok=True)
        tmp.write_text(json.dumps({"samples": tampered}))
        with self.assertRaises(ValueError):
            load_samples(tmp, FROZEN)
        tmp.unlink()


class EngineTest(unittest.TestCase):
    def setUp(self):
        (
            self.rules,
            self.samples,
            self.scopes,
            self.floor,
            self.groups,
            self.old_scan,
            self.new_scan,
        ) = _load_all()
        self.pairs = build_pairs(self.samples, self.rules, self.scopes)

    def test_duplicate_sample_never_inflates_denominator(self):
        sample_ids = {pair.sample_id for pair in self.pairs}
        self.assertNotIn("S14", sample_ids)
        self.assertEqual(len(sample_ids), 13)

    def test_out_of_scope_cell_excluded(self):
        verdicts = evaluate_pairs(self.pairs, self.new_scan)
        oos = [p for p in verdicts if not p.in_scope]
        self.assertEqual(len(oos), 1)
        self.assertEqual(oos[0].rule_id, "B301")
        self.assertEqual(oos[0].verdict, PairVerdict.OUT_OF_SCOPE)

    def test_three_failure_states_are_separated(self):
        verdicts = evaluate_pairs(self.pairs, self.new_scan)
        by_key = {(p.sample_id, p.rule_id): p.verdict for p in verdicts}
        self.assertEqual(by_key[("S01", "B602")], PairVerdict.SCAN_MISSING)
        self.assertEqual(by_key[("S12", "B108")], PairVerdict.RULE_DISABLED)
        self.assertEqual(by_key[("S11", "B324")], PairVerdict.CORRECTLY_SILENT)
        self.assertEqual(by_key[("S04", "B324")], PairVerdict.HIT)

    def test_same_location_multiple_hits_count_once(self):
        verdicts = evaluate_pairs(self.pairs, self.new_scan)
        b324_s05 = [
            p for p in verdicts
            if p.sample_id == "S05" and p.rule_id == "B324"
        ]
        self.assertEqual(len(b324_s05), 1)
        self.assertEqual(b324_s05[0].verdict, PairVerdict.HIT)

    def test_old_and_new_scan_diverge_per_rule(self):
        old_verdicts = {
            (p.sample_id, p.rule_id): p.verdict
            for p in evaluate_pairs(self.pairs, self.old_scan)
        }
        new_verdicts = {
            (p.sample_id, p.rule_id): p.verdict
            for p in evaluate_pairs(self.pairs, self.new_scan)
        }
        self.assertEqual(
            old_verdicts[("S01", "B602")], PairVerdict.HIT
        )
        self.assertEqual(
            new_verdicts[("S01", "B602")], PairVerdict.SCAN_MISSING
        )
        self.assertEqual(
            old_verdicts[("S12", "B108")], PairVerdict.SCAN_MISSING
        )
        self.assertEqual(
            new_verdicts[("S12", "B108")], PairVerdict.RULE_DISABLED
        )
        self.assertEqual(
            new_verdicts[("S03", "B602")], PairVerdict.HIT
        )

    def test_recall_uses_only_expected_cells(self):
        result = run_regression(
            "test-freeze", self.samples, self.rules, self.scopes,
            self.old_scan, self.new_scan, self.floor, self.groups,
        )
        self.assertLessEqual(result.overall.recall, 1.0)
        self.assertEqual(result.overall.expected_pairs, 10)
        self.assertEqual(result.overall.true_hits, 8)
        self.assertEqual(result.overall.scan_missing, 1)
        self.assertEqual(result.overall.rule_disabled, 2)
        self.assertEqual(result.overall.correctly_silent, 7)


class GateTest(unittest.TestCase):
    def test_block_on_lost_critical_finding(self):
        rules, samples, scopes, floor, groups, old, new = _load_all()
        result = run_regression(
            "test-freeze", samples, rules, scopes, old, new, floor, groups
        )
        self.assertTrue(result.blocked)
        ci = next(g for g in result.groups if g.family == "command_injection")
        self.assertTrue(ci.blocked)
        joined = " ".join(ci.reasons)
        self.assertIn("B602", joined)
        self.assertIn("s01_os_system.py", joined)
        self.assertLess(ci.bucket.recall, ci.min_recall)
        passing = sorted(
            g.family for g in result.groups
            if g.family in ("tls_validation", "weak_crypto")
        )
        self.assertEqual(passing, ["tls_validation", "weak_crypto"])

    def test_reports_render_and_mention_block_evidence(self):
        rules, samples, scopes, floor, groups, old, new = _load_all()
        result = run_regression(
            "test-freeze", samples, rules, scopes, old, new, floor, groups
        )
        coverage = render_coverage_report(result)
        gate = render_gate_report(result)
        self.assertIn("重复样本 1 条未计入分母", coverage)
        self.assertIn("阻断（BLOCK）", gate)
        self.assertIn("confirmed HIGH finding lost", gate)


if __name__ == "__main__":
    unittest.main()
