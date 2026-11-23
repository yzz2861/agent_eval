#
# SPDX-License-Identifier: Apache-2.0
import json
import os
import tempfile

import testtools

from bandit.cli import attribution as attribution_cli
from bandit.core import attribution


class AttributionTests(testtools.TestCase):
    report = "tests/fixtures/attribution/bandit-report.json"
    phase1 = "tests/fixtures/attribution/phase-1-legacy-manifest.json"
    phase2 = "tests/fixtures/attribution/phase-2-handover-manifest.json"

    def _attribute(self, manifest):
        return attribution.attribute(self.report, manifest)

    def test_phase_1_legacy_and_shared_code_counted_once(self):
        result = self._attribute(self.phase1)
        burden = {row["owner"]: row for row in result.risk_burden}

        self.assertEqual({"team-legacy", "team-platform"}, set(burden))
        platform = burden["team-platform"]
        self.assertEqual(1, platform["finding_count"])
        self.assertEqual(
            ["product-new-2.0.0", "product-old-1.0.0"],
            platform["artifacts"],
        )
        self.assertEqual(1, platform["shared_finding_count"])
        reasons = {row["reason"] for row in result.double_counting}
        self.assertIn("shared_component", reasons)
        self.assertIn("shared_source_finding", reasons)

    def test_legacy_attribution_remains_reportable(self):
        result = self._attribute(self.phase1)
        legacy = {
            (row["filename"], row["owner"])
            for row in result.legacy_attribution
        }

        self.assertIn(("legacy/plugin/crypto.py", "team-legacy"), legacy)
        self.assertIn(
            ("/build/product-new/src/shared/runtime.py", "team-legacy"),
            legacy,
        )
        shared = [
            row
            for row in result.legacy_attribution
            if row["component"] == "shared-runtime"
        ]
        self.assertTrue(shared)
        self.assertEqual("team-platform", shared[0]["current_owner"])
        self.assertEqual("team-platform", shared[0]["superseded_by"])

    def test_near_filename_is_only_a_review_candidate(self):
        result = self._attribute(self.phase1)
        candidate = next(
            row
            for row in result.review_candidates
            if row["filename"] == "legacy/plugin/crypto_utils.py"
        )
        source = next(
            row
            for row in result.attributions
            if row["filename"] == "legacy/plugin/crypto_utils.py"
        )

        self.assertFalse(candidate["counted"])
        self.assertEqual("needs_review", candidate["status"])
        self.assertEqual("legacy-crypto", candidate["component"])
        self.assertIn(
            candidate["reason"],
            {"same_basename_different_path", "similar_filename"},
        )
        self.assertFalse(source["counted"])
        self.assertEqual("needs_review", source["status"])
        self.assertEqual([], source["components"])
        self.assertEqual([], source["artifacts"])

    def test_proven_handover_moves_current_burden(self):
        result = self._attribute(self.phase2)
        self.assertEqual(
            ["team-core"], [row["owner"] for row in result.risk_burden]
        )
        shared = result.risk_burden[0]
        self.assertEqual(1, shared["finding_count"])
        self.assertEqual(
            ["product-new-2.0.0", "product-old-1.0.0"],
            shared["artifacts"],
        )

        attributed = [
            row
            for row in result.attributions
            if row["component"] == "shared-runtime"
            and row["status"] == "attributed"
        ]
        self.assertTrue(attributed)
        self.assertEqual("team-core", attributed[0]["owner"])
        self.assertEqual("handover", attributed[0]["owner_source"])
        self.assertEqual("team-legacy", attributed[0]["legacy_owner"])

    def test_stopped_old_product_keeps_legacy_without_new_burden(self):
        result = self._attribute(self.phase2)
        crypto = next(
            row
            for row in result.attributions
            if row["filename"] == "legacy/plugin/crypto.py"
        )
        legacy = [
            row
            for row in result.legacy_attribution
            if row["filename"] == "legacy/plugin/crypto.py"
        ]

        self.assertEqual("retired", crypto["status"])
        self.assertFalse(crypto["counted"])
        self.assertEqual("artifact_stopped_before_as_of", crypto["reason"])
        self.assertTrue(legacy)
        self.assertEqual("team-legacy", legacy[0]["owner"])
        self.assertEqual("legacy-only-0.9.0", legacy[0]["artifact"])
        self.assertNotIn(
            "legacy-crypto",
            [
                component
                for row in result.risk_burden
                for component in row["components"]
            ],
        )

    def test_unproven_handover_is_ignored_and_warned(self):
        result = self._attribute(self.phase2)
        crypto = next(
            row
            for row in result.attributions
            if row["filename"] == "legacy/plugin/crypto.py"
        )

        self.assertEqual("team-legacy", crypto["owner"])
        self.assertNotIn(
            "unproven_handover",
            {row["reason"] for row in result.double_counting},
        )
        self.assertTrue(
            any(
                "unproven handover" in warning
                for warning in result.evidence["warnings"]
            )
        )

    def test_duplicate_report_entry_counted_once(self):
        with open(self.report, encoding="utf-8") as report_file:
            report = json.load(report_file)
        report["results"].append(dict(report["results"][0]))

        result = attribution.attribute(report, self.phase1)

        self.assertEqual(4, result.summary["finding_count"])
        self.assertIn(
            "duplicate_report_entry",
            {row["reason"] for row in result.double_counting},
        )

    def test_evidence_digest_is_reproducible(self):
        first = self._attribute(self.phase2).as_dict()
        second = self._attribute(self.phase2).as_dict()

        self.assertEqual(first, second)
        self.assertEqual(
            first["evidence"]["evidence_digest"],
            second["evidence"]["evidence_digest"],
        )
        self.assertRegex(
            first["evidence"]["evidence_digest"], r"^sha256:[0-9a-f]{64}$"
        )

    def test_old_product_before_stop_ship_still_receives_ticket(self):
        manifest = {
            "as_of": "2026-11-01T00:00:00Z",
            "artifacts": [
                {
                    "id": "old-product-0.9.0",
                    "stop_ship_at": "2026-12-31T00:00:00Z",
                    "components": ["old"],
                }
            ],
            "components": [
                {
                    "id": "old",
                    "paths": ["src/old/ticket.py"],
                    "maintainer": "team-old",
                    "revision": "git:old",
                }
            ],
        }
        report = {
            "results": [
                {
                    "filename": "src/old/ticket.py",
                    "test_id": "B101",
                    "test_name": "assert_used",
                    "line_number": 1,
                    "issue_severity": "LOW",
                    "issue_confidence": "HIGH",
                    "issue_text": "assert",
                }
            ]
        }

        result = attribution.attribute(report, manifest)

        self.assertEqual(
            ["team-old"], [row["owner"] for row in result.risk_burden]
        )
        self.assertEqual(1, result.risk_burden[0]["finding_count"])
        self.assertEqual("attributed", result.attributions[0]["status"])

    def test_future_handover_is_not_applied(self):
        manifest = {
            "as_of": "2026-11-01T00:00:00Z",
            "artifacts": [
                {
                    "id": "new-product-1.0.0",
                    "components": ["shared"],
                }
            ],
            "components": [
                {
                    "id": "shared",
                    "paths": ["src/shared/runtime.py"],
                    "maintainer": "team-before",
                    "revision": "git:shared",
                }
            ],
            "handovers": [
                {
                    "component": "shared",
                    "to": "team-after",
                    "effective_at": "2027-01-01T00:00:00Z",
                    "proof": {"ticket": "OPS-1"},
                }
            ],
        }
        report = {
            "results": [
                {
                    "filename": "src/shared/runtime.py",
                    "test_id": "B101",
                    "test_name": "assert_used",
                    "line_number": 1,
                    "issue_severity": "LOW",
                    "issue_confidence": "HIGH",
                    "issue_text": "assert",
                }
            ]
        }

        result = attribution.attribute(report, manifest)

        self.assertEqual("team-before", result.risk_burden[0]["owner"])
        self.assertEqual("component", result.attributions[0]["owner_source"])

    def test_consumer_can_submit_relations_and_handovers_directly(self):
        report = {
            "results": [
                {
                    "filename": "src/shared/runtime.py",
                    "test_id": "B101",
                    "test_name": "assert_used",
                    "line_number": 1,
                    "issue_severity": "HIGH",
                    "issue_confidence": "HIGH",
                    "issue_text": "assert",
                }
            ]
        }

        result = attribution.attribute(
            report,
            as_of="2026-11-20T00:00:00Z",
            artifacts=[
                {
                    "id": "artifact-a",
                    "components": ["shared"],
                    "digest": "sha256:a",
                }
            ],
            components=[
                {
                    "id": "shared",
                    "paths": ["src/shared/runtime.py"],
                    "owner": "team-old",
                    "revision": "git:abc",
                }
            ],
            relations={"artifact-a": ["shared"]},
            handovers=[
                {
                    "component": "shared",
                    "to": "team-new",
                    "effective_at": "2026-01-01",
                    "proof": "ticket-1",
                }
            ],
            legacy_attribution=[
                {"filename": "src/shared/runtime.py", "owner": "team-old"}
            ],
        )

        self.assertEqual("team-new", result.risk_burden[0]["owner"])
        self.assertEqual("team-old", result.legacy_attribution[0]["owner"])

    def test_cli_writes_attribution_report(self):
        descriptor, output_path = tempfile.mkstemp(suffix=".json")
        os.close(descriptor)
        self.addCleanup(os.unlink, output_path)

        code = attribution_cli.main(
            [
                self.report,
                "--manifest",
                self.phase2,
                "--as-of",
                "2027-02-01T00:00:00Z",
                "--output",
                output_path,
            ]
        )

        self.assertEqual(0, code)
        with open(output_path, encoding="utf-8") as output_file:
            data = json.load(output_file)
        self.assertEqual(attribution.SCHEMA_VERSION, data["schema_version"])
        self.assertEqual("team-core", data["risk_burden"][0]["owner"])
        self.assertTrue(data["legacy_attribution"])
        self.assertNotIn(
            "unproven_handover",
            {row["reason"] for row in data["double_counting"]},
        )

    def test_cli_fail_on_double_count(self):
        code = attribution_cli.main(
            [
                self.report,
                "--manifest",
                self.phase2,
                "--as-of",
                "2027-02-01T00:00:00Z",
                "--fail-on-double-count",
            ]
        )

        self.assertEqual(1, code)
