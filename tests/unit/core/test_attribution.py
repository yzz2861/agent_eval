#
# SPDX-License-Identifier: Apache-2.0
import contextlib
import copy
import io
import json
import os

import testtools

from bandit.core import attribution
from bandit.cli import attribution as attribution_cli


FIXTURE_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__), "..", "..", "fixtures", "attribution"
    )
)


def _fixture(name):
    path = os.path.join(FIXTURE_DIR, name)
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _report():
    return _fixture("bandit_report.json")


def _manifest(phase):
    return attribution.load_manifest(
        os.path.join(FIXTURE_DIR, "release_manifest.phase%d.json" % phase)
    )


def _result(phase):
    return attribution.attribute_report(_report(), _manifest(phase))


def _finding(result, filename):
    for item in result["findings"]:
        if item["filename"] == filename:
            return item
    raise AssertionError("finding not found: %s" % filename)


class AttributionAcceptanceTests(testtools.TestCase):
    def test_phase1_shared_artifacts_count_once(self):
        result = _result(1)
        self.assertEqual(5, result["summary"]["findings"])
        self.assertEqual(3, result["summary"]["attributed"])
        self.assertEqual(18, result["summary"]["risk_points"])
        self.assertEqual(["team-legacy"], sorted(result["risk_by_owner"]))
        self.assertEqual(
            18, result["risk_by_owner"]["team-legacy"]["risk_points"]
        )
        self.assertEqual(3, result["summary"]["double_count_detected"])
        for event in result["double_count"]["events"]:
            self.assertEqual("shared_component", event["reason"])
            self.assertEqual(
                ["portal-new@2.0.0", "portal-old@1.8.0"],
                event["artifact_ids"],
            )
        impact = result["artifact_impact"]["portal-old@1.8.0"]
        self.assertEqual("maintenance", impact["status"])
        self.assertTrue(impact["accepts_work_orders"])

    def test_phase1_legacy_attribution_is_still_reportable(self):
        result = _result(1)
        bucket = result["legacy_risk_by_owner"]["team-legacy"]
        self.assertEqual(18, bucket["risk_points"])
        self.assertEqual(3, bucket["finding_count"])
        legacy_artifacts = {
            entry["artifact_id"] for entry in result["legacy_attribution"]
        }
        self.assertIn("portal-old@1.8.0", legacy_artifacts)
        self.assertIn("portal-new@2.0.0", legacy_artifacts)
        console = _finding(result, "src/console/main.py")
        self.assertEqual("legacy_only", console["attribution_status"])
        self.assertEqual(1, len(console["legacy_attribution"]))
        self.assertFalse(
            console["legacy_attribution"][0]["counts_toward_risk"]
        )
        self.assertEqual(0, console["risk_points"])

    def test_phase2_handover_moves_current_but_not_legacy(self):
        result = _result(2)
        self.assertEqual(["team-platform"], sorted(result["risk_by_owner"]))
        self.assertEqual(
            18, result["risk_by_owner"]["team-platform"]["risk_points"]
        )
        self.assertEqual(
            ["team-legacy"], sorted(result["legacy_risk_by_owner"])
        )
        self.assertEqual(
            18,
            result["legacy_risk_by_owner"]["team-legacy"]["risk_points"],
        )
        loader = _finding(result, "src/shared/loader.py")
        allocation = loader["allocation"][0]
        self.assertEqual("team-platform", allocation["owner"])
        self.assertEqual("handover", allocation["owner_source"])
        self.assertEqual(
            "CHG-4242", allocation["owner_handover"]["proof"]["id"]
        )
        self.assertEqual(2, result["manifest"]["handovers_accepted"])
        rejected = result["manifest"]["handovers_rejected"]
        self.assertEqual(1, len(rejected))
        self.assertEqual("missing_proof", rejected[0]["reason"])
        self.assertTrue(
            result["artifact_impact"]["portal-old@1.8.0"][
                "accepts_work_orders"
            ]
        )

    def test_filename_similarity_is_only_an_investigation_lead(self):
        result = _result(1)
        finding = _finding(result, "src/web-util/views.py")
        self.assertEqual("needs_investigation", finding["attribution_status"])
        self.assertEqual([], finding["allocation"])
        self.assertEqual(0, finding["risk_points"])
        self.assertEqual(1, len(result["investigation_queue"]))
        lead = result["investigation_queue"][0]
        self.assertEqual("web-next-ui", lead["candidate_component_id"])
        self.assertEqual("basename_collision", lead["kind"])
        self.assertNotIn("team-next", result["risk_by_owner"])

    def test_output_is_deterministic_and_recomputable(self):
        first = _result(2)
        second = _result(2)
        self.assertEqual(attribution.dumps(first), attribution.dumps(second))
        self.assertEqual(
            first["manifest"]["sha256"], second["manifest"]["sha256"]
        )
        self.assertEqual(
            first["reproducibility"]["findings_sha256"],
            second["reproducibility"]["findings_sha256"],
        )

    def test_views_keep_legacy_and_current_separate(self):
        current = _result(2)
        current_view = attribution.attribute_report(
            _report(), _manifest(2), view="current"
        )
        self.assertIn("risk_by_owner", current_view)
        self.assertNotIn("legacy_risk_by_owner", current_view)
        self.assertEqual(
            current["risk_by_owner"], current_view["risk_by_owner"]
        )
        legacy_view = attribution.attribute_report(
            _report(), _manifest(2), view="legacy"
        )
        self.assertNotIn("risk_by_owner", legacy_view)
        self.assertIn("legacy_risk_by_owner", legacy_view)
        self.assertEqual(
            current["legacy_risk_by_owner"],
            legacy_view["legacy_risk_by_owner"],
        )


class AttributionUnitTests(testtools.TestCase):
    def _base_manifest(self):
        return {
            "schema_version": 1,
            "manifest_id": "unit",
            "as_of": "2026-11-20",
            "components": [
                {
                    "component_id": "core",
                    "owner": "team-old",
                    "paths": ["src/core"],
                }
            ],
            "artifacts": [
                {
                    "artifact_id": "app@1.0",
                    "owner": "team-old",
                    "status": "active",
                }
            ],
            "relations": [
                {
                    "artifact_id": "app@1.0",
                    "component_id": "core",
                    "evidence": {"id": "build-1"},
                }
            ],
        }

    def _report_for(self, filename):
        return {
            "results": [
                {
                    "filename": filename,
                    "line_number": 1,
                    "test_id": "B101",
                    "test_name": "assert_used",
                    "issue_severity": "LOW",
                    "issue_confidence": "HIGH",
                    "issue_text": "assert",
                }
            ]
        }

    def test_relation_must_reference_known_artifact(self):
        data = self._base_manifest()
        data["relations"][0]["artifact_id"] = "missing"
        self.assertRaises(
            attribution.ManifestError, attribution.load_manifest, data
        )

    def test_unproven_handover_does_not_move_owner(self):
        data = self._base_manifest()
        data["handovers"] = [
            {
                "component_id": "core",
                "from_owner": "team-old",
                "to_owner": "team-new",
                "effective": "2026-11-01",
                "proof": {},
            }
        ]
        result = attribution.attribute_report(
            self._report_for("src/core/x.py"), data
        )
        self.assertEqual(["team-old"], sorted(result["risk_by_owner"]))
        self.assertEqual(
            "missing_proof",
            result["manifest"]["handovers_rejected"][0]["reason"],
        )

    def test_handover_not_yet_effective_is_rejected(self):
        data = self._base_manifest()
        data["handovers"] = [
            {
                "component_id": "core",
                "from_owner": "team-old",
                "to_owner": "team-new",
                "effective": "2026-12-01",
                "proof": {"id": "CHG-1"},
            }
        ]
        result = attribution.attribute_report(
            self._report_for("src/core/x.py"), data
        )
        self.assertEqual(["team-old"], sorted(result["risk_by_owner"]))
        self.assertEqual(
            "handover_not_yet_effective",
            result["manifest"]["handovers_rejected"][0]["reason"],
        )

    def test_eol_date_excludes_risk_but_keeps_legacy(self):
        data = self._base_manifest()
        data["artifacts"][0]["eol_date"] = "2026-01-01"
        data["artifacts"][0]["legacy_owner"] = "team-old"
        result = attribution.attribute_report(
            self._report_for("src/core/x.py"), data
        )
        self.assertEqual({}, result["risk_by_owner"])
        finding = result["findings"][0]
        self.assertEqual("legacy_only", finding["attribution_status"])
        affected = finding["allocation"][0]["affected_artifacts"][0]
        self.assertFalse(affected["counts_toward_risk"])
        self.assertEqual("eol_date_reached", affected["status_reason"])

    def test_ambiguous_exact_match_is_not_attributed(self):
        data = self._base_manifest()
        data["components"].append(
            {
                "component_id": "core-copy",
                "owner": "team-copy",
                "paths": ["src/core"],
            }
        )
        result = attribution.attribute_report(
            self._report_for("src/core/x.py"), data
        )
        finding = result["findings"][0]
        self.assertEqual("needs_investigation", finding["attribution_status"])
        self.assertEqual(
            "ambiguous_exact_component_match", finding["reason"]
        )
        self.assertEqual(0, finding["risk_points"])

    def test_component_without_relation_is_not_counted(self):
        data = self._base_manifest()
        data["relations"] = []
        result = attribution.attribute_report(
            self._report_for("src/core/x.py"), data
        )
        finding = result["findings"][0]
        self.assertEqual(
            "component_has_no_release_relation", finding["reason"]
        )
        self.assertEqual(0, finding["risk_points"])

    def test_duplicate_findings_are_collapsed(self):
        report = self._report_for("src/core/x.py")
        report["results"].append(copy.deepcopy(report["results"][0]))
        result = attribution.attribute_report(
            report, self._base_manifest()
        )
        self.assertEqual(1, len(result["findings"]))
        self.assertEqual(
            1, result["summary"]["duplicate_findings_removed"]
        )

    def test_artifact_scoped_handover_beats_stale_component_owner(self):
        data = self._base_manifest()
        data["handovers"] = [
            {
                "component_id": "core",
                "artifact_id": "app@1.0",
                "from_owner": "team-old",
                "to_owner": "team-new",
                "effective": "2026-11-01",
                "proof": {"id": "CHG-2"},
            }
        ]
        result = attribution.attribute_report(
            self._report_for("src/core/x.py"), data
        )
        self.assertEqual(["team-new"], sorted(result["risk_by_owner"]))
        allocation = result["findings"][0]["allocation"][0]
        self.assertEqual("artifact.handover", allocation["owner_source"])
        self.assertIn("team-old", result["legacy_risk_by_owner"])
        self.assertEqual(
            "handover.from_owner",
            result["findings"][0]["legacy_attribution"][0]["source"],
        )


    def test_as_of_selects_before_and_after_handover_phase(self):
        data = self._base_manifest()
        data["handovers"] = [
            {
                "component_id": "core",
                "from_owner": "team-old",
                "to_owner": "team-new",
                "effective": "2026-11-01",
                "proof": {"id": "CHG-3"},
            }
        ]
        before = copy.deepcopy(data)
        before["as_of"] = "2026-10-15"
        after = copy.deepcopy(data)
        after["as_of"] = "2026-11-20"
        before_result = attribution.attribute_report(
            self._report_for("src/core/x.py"), before
        )
        after_result = attribution.attribute_report(
            self._report_for("src/core/x.py"), after
        )
        self.assertEqual(
            ["team-old"], sorted(before_result["risk_by_owner"])
        )
        self.assertEqual(
            ["team-new"], sorted(after_result["risk_by_owner"])
        )
        self.assertEqual(
            "handover_not_yet_effective",
            before_result["manifest"]["handovers_rejected"][0]["reason"],
        )


class AttributionCliTests(testtools.TestCase):
    def _invoke(self, argv):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = attribution_cli.main(argv)
        return code, stdout.getvalue()

    def test_cli_json_output(self):
        code, output = self._invoke(
            [
                "--manifest",
                os.path.join(FIXTURE_DIR, "release_manifest.phase2.json"),
                "--report",
                os.path.join(FIXTURE_DIR, "bandit_report.json"),
            ]
        )
        self.assertEqual(0, code)
        result = json.loads(output)
        self.assertEqual(["team-platform"], sorted(result["risk_by_owner"]))
        self.assertEqual(
            3, result["summary"]["double_count_detected"]
        )

    def test_cli_text_legacy_view(self):
        code, output = self._invoke(
            [
                "--manifest",
                os.path.join(FIXTURE_DIR, "release_manifest.phase2.json"),
                "--report",
                os.path.join(FIXTURE_DIR, "bandit_report.json"),
                "--view",
                "legacy",
                "--format",
                "text",
            ]
        )
        self.assertEqual(0, code)
        self.assertIn("Legacy risk by owner", output)
        self.assertIn("team-legacy", output)

    def test_cli_fail_on_unattributed(self):
        code, _ = self._invoke(
            [
                "--manifest",
                os.path.join(FIXTURE_DIR, "release_manifest.phase1.json"),
                "--report",
                os.path.join(FIXTURE_DIR, "bandit_report.json"),
                "--fail-on-unattributed",
            ]
        )
        self.assertEqual(1, code)
