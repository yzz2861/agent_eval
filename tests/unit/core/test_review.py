#
# SPDX-License-Identifier: Apache-2.0
import copy
import os

import fixtures
import testtools

from bandit.core import config as b_config
from bandit.core import manager as b_manager
from bandit.core import review
from bandit.core import test_set as b_test_set

APP_SOURCE = (
    'import subprocess\n'
    '\n'
    'password = "hunter2"\n'
    '\n'
    'def run(cmd):\n'
    '    return subprocess.check_output(cmd, shell=True)\n'
)

SHELL_CONFIG = (
    'shell_injection:\n'
    '  subprocess: ["subprocess.Popen"]\n'
    '  shell: ["os.system"]\n'
    '  no_shell: []\n'
)


class ReviewTests(testtools.TestCase):
    def setUp(self):
        super().setUp()
        self.tempdir = self.useFixture(fixtures.TempDir()).path
        self.src_dir = os.path.join(self.tempdir, "src")
        os.makedirs(self.src_dir)
        self.app_path = os.path.join(self.src_dir, "app.py")
        with open(self.app_path, "w", encoding="utf-8") as handle:
            handle.write(APP_SOURCE)
        self.conf = b_config.BanditConfig()

    def _scan(self, review_mode=True, config_file=None):
        conf = b_config.BanditConfig(config_file=config_file)
        mgr = b_manager.BanditManager(conf, "file", review=review_mode)
        mgr.discover_files([self.app_path], True)
        mgr.run_tests()
        return mgr

    def _report(self, mgr):
        return {
            "results": [
                finding.as_dict(with_code=False)
                for finding in mgr.get_issue_list()
            ]
        }

    def test_review_mode_attaches_materials(self):
        mgr = self._scan()
        self.assertGreater(len(mgr.results), 0)
        for finding in mgr.results:
            self.assertIsNotNone(finding.review)
            file_material = finding.review["file_material"]
            rule_material = finding.review["rule_material"]
            self.assertEqual(
                file_material["content_digest"],
                review.content_digest(APP_SOURCE),
            )
            self.assertEqual(file_material["logical_path"], "app.py")
            self.assertIsNotNone(rule_material)
            self.assertEqual(rule_material["test_id"], finding.test_id)
            self.assertIsNotNone(rule_material["plugin_source_digest"])

    def test_disabled_review_mode_has_no_attestation(self):
        mgr = self._scan(review_mode=False)
        self.assertGreater(len(mgr.results), 0)
        self.assertTrue(
            all(finding.review is None for finding in mgr.results)
        )
        self.assertIsNone(mgr.review_summary())

    def test_material_survives_directory_move(self):
        mgr = self._scan()
        moved_root = os.path.join(self.tempdir, "relocated")
        os.rename(self.src_dir, moved_root)
        moved_app = os.path.join(moved_root, "app.py")
        testset = b_test_set.BanditTestSet(config=self.conf)
        outcome = review.verify_report(
            self._report(mgr), [moved_root], testset=testset
        )
        self.assertTrue(os.path.isfile(moved_app))
        self.assertEqual(
            outcome["counts"][review.REPRODUCIBLE], len(mgr.results)
        )
        self.assertEqual(outcome["counts"][review.NOT_REPRODUCIBLE], 0)

    def test_changed_input_fails_at_file_layer(self):
        mgr = self._scan()
        with open(self.app_path, "w", encoding="utf-8") as handle:
            handle.write(APP_SOURCE.replace("hunter2", "different-secret"))
        testset = b_test_set.BanditTestSet(config=self.conf)
        outcome = review.verify_report(
            self._report(mgr), [self.tempdir], testset=testset
        )
        self.assertEqual(
            outcome["counts"][review.NOT_REPRODUCIBLE], len(mgr.results)
        )
        self.assertEqual(
            outcome["counts"][review.LAYER_FILE], len(mgr.results)
        )
        self.assertTrue(
            all(
                result["layer"] == review.LAYER_FILE
                for result in outcome["results"]
            )
        )

    def test_missing_file_fails_at_file_layer(self):
        mgr = self._scan()
        os.remove(self.app_path)
        testset = b_test_set.BanditTestSet(config=self.conf)
        outcome = review.verify_report(
            self._report(mgr), [self.tempdir], testset=testset
        )
        self.assertTrue(
            all(
                result["layer"] == review.LAYER_FILE
                for result in outcome["results"]
            )
        )

    def test_changed_config_fails_at_rule_layer(self):
        mgr = self._scan()
        recorded = next(
            finding.review["rule_material"]
            for finding in mgr.results
            if finding.test_id == "B602"
        )
        default_material = review.build_rule_material(
            "B602", "subprocess_popen_with_shell_equals_true", None
        )
        # A controllable config change only moves the config fingerprint,
        # not the plugin declaration digest.
        changed_material = review.build_rule_material(
            "B602",
            "subprocess_popen_with_shell_equals_true",
            {
                "subprocess": ["subprocess.Popen"],
                "shell": ["os.system"],
                "no_shell": [],
            },
        )
        self.assertEqual(
            default_material["plugin_source_digest"],
            changed_material["plugin_source_digest"],
        )
        self.assertNotEqual(
            default_material["config_digest"],
            changed_material["config_digest"],
        )
        self.assertNotEqual(
            recorded["config_digest"],
            changed_material["config_digest"],
        )

    def test_missing_plugin_declaration_is_not_reproducible(self):
        mgr = self._scan()
        entry = copy.deepcopy(self._report(mgr)["results"][0])
        entry["review"]["rule_material"]["test_id"] = "B999"
        testset = b_test_set.BanditTestSet(config=self.conf)
        outcome = review.verify_result(
            entry, [self.src_dir], testset=testset
        )
        self.assertEqual(outcome["status"], review.NOT_REPRODUCIBLE)
        self.assertEqual(outcome["layer"], review.LAYER_RULE)
        self.assertIn("plugin declaration", outcome["reason"])

    def test_missing_review_material_is_not_reproducible(self):
        mgr = self._scan()
        report = self._report(mgr)
        report["results"][0].pop("review")
        testset = b_test_set.BanditTestSet(config=self.conf)
        outcome = review.verify_report(
            report, [self.tempdir], testset=testset
        )
        self.assertEqual(
            outcome["results"][0]["status"], review.NOT_REPRODUCIBLE
        )

    def test_workspace_change_withholds_findings(self):
        mgr = self._scan()
        self.assertGreater(len(mgr.results), 0)
        recorder = mgr.review_recorder
        recorder.snapshot(self.app_path)
        with open(self.app_path, "a", encoding="utf-8") as handle:
            handle.write("# changed while scanning" + chr(10))
        stale, reason = recorder.is_stale(self.app_path)
        self.assertTrue(stale)
        self.assertEqual(reason, review.REASON_FILE_CHANGED)
        mgr._finalize_review_file(self.app_path)
        self.assertEqual(mgr.results, [])
        summary = mgr.review_summary()
        self.assertGreater(summary["withheld_count"], 0)
        self.assertTrue(
            all(
                entry["reason"] == review.REASON_FILE_CHANGED
                for entry in summary["withheld"]
            )
        )

    def test_canonical_config_is_order_independent(self):
        first = review.config_digest({"a": {1, 2, 3}, "b": {"x": 1}})
        second = review.config_digest({"b": {"x": 1}, "a": {3, 2, 1}})
        self.assertNotEqual(first, review.config_digest(None))
        self.assertEqual(first, second)
        self.assertNotEqual(
            review.config_digest([1, 2, 3]),
            review.config_digest([3, 2, 1]),
        )

