"""End-to-end campaign tests: determinism, artifacts and time budget."""

import base64
import json
import os
import tempfile
import time
import unittest

from oletools.rtf_fuzz import Campaign, CampaignConfig, run_campaign


class CampaignTest(unittest.TestCase):
    def test_campaign_is_deterministic_for_a_seed(self):
        first = run_campaign(seed=1234, valid_steps=20, invalid_steps=20,
                             reduce_findings=False).summary()
        second = run_campaign(seed=1234, valid_steps=20, invalid_steps=20,
                              reduce_findings=False).summary()
        self.assertEqual(
            [r["chain"] for r in first["records"]],
            [r["chain"] for r in second["records"]])
        self.assertEqual(
            [f["signature"] for f in first["findings"]],
            [f["signature"] for f in second["findings"]])

    def test_valid_pool_never_reports_false_positives(self):
        summary = run_campaign(seed=99, valid_steps=40, invalid_steps=20).summary()
        self.assertTrue(all(f["entry"]["pool"] != "valid"
                            for f in summary["findings"]))

    def test_budget_records_seed_chain_and_minimal_sample(self):
        with tempfile.TemporaryDirectory() as output_dir:
            campaign = run_campaign(seed=7, valid_steps=15, invalid_steps=15,
                                    output_dir=output_dir)
            summary = campaign.summary()
            summary_path = os.path.join(output_dir,
                                        "campaign_summary.json")
            self.assertTrue(os.path.isfile(summary_path))
            on_disk = json.load(open(summary_path))
            self.assertEqual(on_disk["config"]["seed"], 7)
            self.assertIn("seeds", on_disk)
            self.assertIn("budget", on_disk)
            for finding in summary["findings"]:
                self.assertTrue(finding["entry"]["chain"])
                if "reduction" in finding:
                    decoded = base64.b64decode(
                        finding["reduction"]["minimal_b64"])
                    self.assertTrue(decoded)
                    rtf_path = os.path.join(
                        output_dir, finding["id"] + ".rtf")
                    self.assertTrue(os.path.isfile(rtf_path))

    def test_reduced_findings_keep_their_signature(self):
        summary = run_campaign(seed=5, valid_steps=10, invalid_steps=30).summary()
        for finding in summary["findings"]:
            if "reduction" in finding:
                self.assertTrue(finding["reduction"]["signature_kept"])

    def test_fixed_campaign_finishes_well_under_thirty_seconds(self):
        start = time.time()
        run_campaign(seed=20261119, valid_steps=50, invalid_steps=50)
        self.assertLess(time.time() - start, 30.0)

    def test_budget_is_dual_and_always_recorded(self):
        summary = run_campaign(seed=1, valid_steps=12, invalid_steps=12,
                               max_bytes=4096).summary()
        budget = summary["budget"]
        self.assertIn("max_steps", budget)
        self.assertIn("max_bytes", budget)
        self.assertIn("steps_used", budget)
        self.assertIn("bytes_used", budget)
        self.assertTrue(budget["stop_reason"] in (
            "max_steps_reached", "max_bytes_reached", None))


if __name__ == "__main__":
    unittest.main()
