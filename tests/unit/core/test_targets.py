#
# SPDX-License-Identifier: Apache-2.0
import os
import sys
from unittest import mock

import fixtures
import testtools

from bandit.core import config as b_config
from bandit.core import manager as b_manager
from bandit.core import metrics as b_metrics
from bandit.core import node_visitor as b_node_visitor
from bandit.core import targets as b_targets
from bandit.core import test_set as b_test_set


HOST = (sys.version_info[0], sys.version_info[1])
HOST_LABEL = f"{HOST[0]}.{HOST[1]}"
NEWER = (HOST[0], HOST[1] + 1)
NEWER_LABEL = f"{NEWER[0]}.{NEWER[1]}"

LEGACY_SRC = b"""import subprocess

subprocess.call("/bin/ls", shell=True)  # nosec
"""

HOST_ONLY_SRC = b"""import subprocess


def run_command(cmd):
    match cmd:
        case ["run", target]:
            subprocess.call(target, shell=True)  # nosec: B602
        case _:
            subprocess.call(cmd, shell=True)
"""

PLAIN_SRC = b"""import subprocess

subprocess.call("/bin/ls", shell=True)
"""


class ParseTargetVersionsTests(testtools.TestCase):
    def test_parses_comma_string_and_dedupes(self):
        self.assertEqual(
            b_targets.parse_target_versions("3.8, 3.9,3.8"),
            [(3, 8), (3, 9)],
        )

    def test_accepts_tuples_and_a_bare_version_tuple(self):
        self.assertEqual(
            b_targets.parse_target_versions([(3, 10), "3.11"]),
            [(3, 10), (3, 11)],
        )
        self.assertEqual(
            b_targets.parse_target_versions((3, 12)), [(3, 12)]
        )

    def test_none_returns_empty_list(self):
        self.assertEqual(b_targets.parse_target_versions(None), [])

    def test_rejects_malformed_spec(self):
        for bad in ("3", "3.10.1", "python3.10", "-3.10"):
            self.assertRaises(
                ValueError, b_targets.parse_target_versions, bad
            )


class HostSupportTests(testtools.TestCase):
    def test_older_and_equal_targets_are_supported(self):
        self.assertTrue(b_targets.host_supports_target((3, 8)))
        self.assertTrue(b_targets.host_supports_target(HOST))

    def test_newer_target_is_not_supported(self):
        self.assertFalse(b_targets.host_supports_target(NEWER))

    def test_python2_target_is_not_supported(self):
        self.assertFalse(b_targets.host_supports_target((2, 7)))


class ScanFileTests(testtools.TestCase):
    def setUp(self):
        super().setUp()
        self.config = b_config.BanditConfig()
        self.testset = b_test_set.BanditTestSet(self.config)
        self.metrics = b_metrics.Metrics()

    def _scan(self, data, versions):
        return b_targets.scan_file(
            "sample.py",
            data,
            b_targets.parse_target_versions(versions),
            self.testset,
            self.metrics,
        )

    def test_newer_target_is_uncovered_with_no_findings(self):
        report = self._scan(LEGACY_SRC, [NEWER_LABEL])
        target = report["targets"][0]
        self.assertEqual(target["python_version"], NEWER_LABEL)
        self.assertEqual(target["status"], b_targets.UNCOVERED)
        self.assertFalse(target["covered"])
        self.assertIsNone(target["finding_count"])
        self.assertIsNotNone(target["reason"])
        self.assertEqual(report["findings"], [])

    def test_python2_target_is_uncovered_not_a_crash(self):
        report = self._scan(LEGACY_SRC, ["2.7"])
        self.assertEqual(
            report["targets"][0]["status"], b_targets.UNCOVERED
        )

    def test_older_target_rejects_later_syntax_the_parser_clamps(self):
        # Some hosts accept f-strings even with feature_version=(3, 5);
        # the target must still be reported as rejected, not checked.
        report = self._scan(b"x = f'{y}'\n", ["3.5"])
        self.assertEqual(
            report["targets"][0]["status"], b_targets.REJECTED
        )
        self.assertIn("3.6", report["targets"][0]["reason"])

    def test_host_only_syntax_is_rejected_on_old_target(self):
        report = self._scan(HOST_ONLY_SRC, ["3.8", HOST_LABEL])
        statuses = {t["python_version"]: t for t in report["targets"]}
        self.assertEqual(statuses["3.8"]["status"], b_targets.REJECTED)
        self.assertIsNone(statuses["3.8"]["finding_count"])
        self.assertIn("3.8", report["explanation"])
        self.assertEqual(
            statuses[HOST_LABEL]["status"], b_targets.CHECKED
        )

    def test_legacy_file_is_checked_on_every_supported_target(self):
        report = self._scan(LEGACY_SRC, ["3.8", HOST_LABEL, NEWER_LABEL])
        statuses = {
            t["python_version"]: t["status"] for t in report["targets"]
        }
        self.assertEqual(statuses["3.8"], b_targets.CHECKED)
        self.assertEqual(statuses[HOST_LABEL], b_targets.CHECKED)
        self.assertEqual(statuses[NEWER_LABEL], b_targets.UNCOVERED)

    def test_findings_are_merged_across_targets_with_versions(self):
        report = self._scan(PLAIN_SRC, ["3.8", HOST_LABEL])
        by_id = {f["test_id"]: f for f in report["findings"]}
        self.assertIn("B602", by_id)
        self.assertEqual(
            by_id["B602"]["python_versions"], ["3.8", HOST_LABEL]
        )
        self.assertEqual(
            by_id["B602"]["applicable_versions"],
            ["3.8", HOST_LABEL],
        )
        self.assertEqual(by_id["B602"]["rule_id"], "B602")
        self.assertFalse(by_id["B602"]["suppressed"])

    def test_blanket_nosec_is_preserved_per_target(self):
        report = self._scan(LEGACY_SRC, ["3.8", HOST_LABEL])
        b602 = next(f for f in report["findings"] if f["test_id"] == "B602")
        self.assertTrue(b602["suppressed"])
        self.assertTrue(b602["blanket_nosec"])
        self.assertEqual(b602["suppression"], "blanket")
        self.assertEqual(
            b602["suppressed_versions"], ["3.8", HOST_LABEL]
        )
        # Suppressed findings are still emitted, never silently dropped.
        for target in report["targets"]:
            self.assertEqual(target["suppressed_count"], 1)

    def test_specific_nosec_keeps_rule_id_and_leaves_others_visible(self):
        data = (
            b"import subprocess\n"
            b"subprocess.call('/bin/ls', shell=True)  # nosec: B602\n"
        )
        report = self._scan(data, [HOST_LABEL])
        by_id = {f["test_id"]: f for f in report["findings"]}
        self.assertEqual(by_id["B602"]["suppressed_test_ids"], ["B602"])
        self.assertTrue(by_id["B602"]["suppressed"])
        self.assertFalse(by_id["B602"]["blanket_nosec"])
        self.assertEqual(by_id["B602"]["suppression"], "explicit")
        # B404 fires on the import line, which has no nosec comment.
        self.assertFalse(by_id["B404"]["suppressed"])

    def test_explicit_nosec_does_not_hide_other_rules_on_same_line(self):
        data = (
            b"import subprocess  # nosec: B602\n"
            b"subprocess.call('/bin/ls', shell=True)  # nosec: B602\n"
        )
        report = self._scan(data, [HOST_LABEL])
        by_id = {f["test_id"]: f for f in report["findings"]}
        self.assertFalse(by_id["B404"]["suppressed"])
        self.assertTrue(by_id["B602"]["suppressed"])

    def test_ignore_nosec_disables_suppression(self):
        report = b_targets.scan_file(
            "sample.py",
            LEGACY_SRC,
            b_targets.parse_target_versions([HOST_LABEL]),
            self.testset,
            self.metrics,
            ignore_nosec=True,
        )
        b602 = next(f for f in report["findings"] if f["test_id"] == "B602")
        self.assertFalse(b602["suppressed"])
        self.assertEqual(report["targets"][0]["suppressed_count"], 0)

    def test_internal_error_is_inconclusive_not_checked(self):
        with mock.patch.object(
            b_node_visitor.BanditNodeVisitor,
            "process",
            side_effect=RuntimeError("boom"),
        ):
            report = self._scan(LEGACY_SRC, [HOST_LABEL])
        target = report["targets"][0]
        self.assertEqual(target["status"], b_targets.INCONCLUSIVE)
        self.assertFalse(target["conclusive"])
        self.assertIsNone(target["finding_count"])
        self.assertIn("boom", target["reason"])


class TempDirectoryIntegrationTests(testtools.TestCase):
    def setUp(self):
        super().setUp()
        self.config = b_config.BanditConfig()
        self.manager = b_manager.BanditManager(self.config, "file")
        self.tmpdir = self.useFixture(fixtures.TempDir()).path

    def _write(self, name, content):
        path = os.path.join(self.tmpdir, name)
        with open(path, "wb") as handle:
            handle.write(content)
        return path

    def test_both_syntaxes_in_one_temp_directory(self):
        self._write("legacy_syntax.py", LEGACY_SRC)
        self._write("host_only_syntax.py", HOST_ONLY_SRC)
        self.manager.discover_files([self.tmpdir], recursive=True)
        report = self.manager.run_multi_target_tests(
            ["3.8", HOST_LABEL, NEWER_LABEL]
        )

        files = {
            os.path.basename(item["file"]): item
            for item in report["files"]
        }
        legacy = files["legacy_syntax.py"]
        host_only = files["host_only_syntax.py"]

        legacy_status = {
            t["python_version"]: t["status"] for t in legacy["targets"]
        }
        self.assertEqual(legacy_status["3.8"], b_targets.CHECKED)
        self.assertEqual(legacy_status[HOST_LABEL], b_targets.CHECKED)
        self.assertEqual(
            legacy_status[NEWER_LABEL], b_targets.UNCOVERED
        )

        host_status = {
            t["python_version"]: t for t in host_only["targets"]
        }
        self.assertEqual(host_status["3.8"]["status"], b_targets.REJECTED)
        self.assertEqual(
            host_status[HOST_LABEL]["status"], b_targets.CHECKED
        )

        legacy_b602 = next(
            f for f in legacy["findings"] if f["test_id"] == "B602"
        )
        self.assertEqual(
            legacy_b602["python_versions"], ["3.8", HOST_LABEL]
        )
        host_b602 = next(
            f
            for f in host_only["findings"]
            if f["test_id"] == "B602" and f["suppressed"]
        )
        # A real rule only appears on the host side because the older
        # grammar rejects the file before any rule can run.
        self.assertEqual(host_b602["python_versions"], [HOST_LABEL])
        self.assertTrue(host_b602["suppressed"])
        self.assertIn("only appear", host_only["explanation"])

    def test_unreadable_file_is_inconclusive(self):
        missing = os.path.join(self.tmpdir, "missing.py")
        self.manager.discover_files([missing])
        report = self.manager.run_multi_target_tests([HOST_LABEL])
        target = report["files"][0]["targets"][0]
        self.assertEqual(target["status"], b_targets.INCONCLUSIVE)
        self.assertIn("No such file", target["reason"])


class MultiTargetManagerTests(testtools.TestCase):
    def setUp(self):
        super().setUp()
        self.config = b_config.BanditConfig()
        self.manager = b_manager.BanditManager(self.config, "file")
        self.tmpdir = self.useFixture(fixtures.TempDir()).path

    def _write(self, name, content):
        path = os.path.join(self.tmpdir, name)
        with open(path, "wb") as handle:
            handle.write(content)
        return path

    def test_report_keeps_legacy_state_untouched(self):
        path = self._write("legacy.py", b"x = 1\n")
        self.manager.discover_files([path])
        report = self.manager.run_multi_target_tests(
            ["3.8", HOST_LABEL]
        )
        self.assertEqual(report["targets"], ["3.8", HOST_LABEL])
        self.assertEqual(report["host_python_version"], HOST_LABEL)
        self.assertIn("status_legend", report)
        self.assertEqual(self.manager.results, [])
        self.assertEqual(self.manager.scores, [])
        self.assertEqual(self.manager.metrics.data["_totals"]["loc"], 0)

    def test_scan_target_versions_alias(self):
        path = self._write("legacy.py", b"x = 1\n")
        self.manager.discover_files([path])
        report = self.manager.scan_target_versions([HOST_LABEL])
        self.assertEqual(report["targets"], [HOST_LABEL])

    def test_newer_target_is_reported_uncovered(self):
        path = self._write("legacy.py", b"x = 1\n")
        self.manager.discover_files([path])
        report = self.manager.run_multi_target_tests([NEWER_LABEL])
        target = report["files"][0]["targets"][0]
        self.assertEqual(target["status"], b_targets.UNCOVERED)

    def test_empty_target_list_is_an_error(self):
        path = self._write("legacy.py", b"x = 1\n")
        self.manager.discover_files([path])
        self.assertRaises(
            b_targets.TargetVersionError,
            self.manager.run_multi_target_tests,
            None,
        )


class ScanFilesTests(testtools.TestCase):
    def setUp(self):
        super().setUp()
        self.config = b_config.BanditConfig()
        self.testset = b_test_set.BanditTestSet(self.config)

    def test_backend_can_scan_in_memory_and_on_disk_files(self):
        tmpdir = self.useFixture(fixtures.TempDir()).path
        path = os.path.join(tmpdir, "legacy.py")
        with open(path, "wb") as handle:
            handle.write(LEGACY_SRC)

        report = b_targets.scan_files(
            [("memory.py", LEGACY_SRC), path],
            ["3.8", HOST_LABEL],
            self.testset,
        )
        self.assertEqual(report["targets"], ["3.8", HOST_LABEL])
        self.assertEqual(report["summary"]["files"], 2)
        self.assertEqual(report["summary"]["findings"], 4)
