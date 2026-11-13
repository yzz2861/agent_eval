#
# Copyright 2015 Hewlett-Packard Development Company, L.P.
#
# SPDX-License-Identifier: Apache-2.0
import os
from unittest import mock

import fixtures
import testtools

from bandit.core import config
from bandit.core import constants
from bandit.core import issue
from bandit.core import manager
from bandit.core import nosec as b_nosec


class ManagerTests(testtools.TestCase):
    def _get_issue_instance(
        self,
        sev=constants.MEDIUM,
        cwe=issue.Cwe.MULTIPLE_BINDS,
        conf=constants.MEDIUM,
    ):
        new_issue = issue.Issue(sev, cwe, conf, "Test issue")
        new_issue.fname = "code.py"
        new_issue.test = "bandit_plugin"
        new_issue.lineno = 1
        return new_issue

    def setUp(self):
        super().setUp()
        self.profile = {}
        self.profile["include"] = {
            "any_other_function_with_shell_equals_true",
            "assert_used",
        }

        self.config = config.BanditConfig()
        self.manager = manager.BanditManager(
            config=self.config, agg_type="file", debug=False, verbose=False
        )

    def test_create_manager(self):
        # make sure we can create a manager
        self.assertEqual(False, self.manager.debug)
        self.assertEqual(False, self.manager.verbose)
        self.assertEqual("file", self.manager.agg_type)

    def test_create_manager_with_profile(self):
        # make sure we can create a manager
        m = manager.BanditManager(
            config=self.config,
            agg_type="file",
            debug=False,
            verbose=False,
            profile=self.profile,
        )

        self.assertEqual(False, m.debug)
        self.assertEqual(False, m.verbose)
        self.assertEqual("file", m.agg_type)

    def test_matches_globlist(self):
        self.assertTrue(manager._matches_glob_list("test", ["*tes*"]))
        self.assertFalse(manager._matches_glob_list("test", ["*fes*"]))

    def test_is_file_included(self):
        a = manager._is_file_included(
            path="a.py",
            included_globs=["*.py"],
            excluded_path_strings=[],
            enforce_glob=True,
        )

        b = manager._is_file_included(
            path="a.dd",
            included_globs=["*.py"],
            excluded_path_strings=[],
            enforce_glob=False,
        )

        c = manager._is_file_included(
            path="a.py",
            included_globs=["*.py"],
            excluded_path_strings=["a.py"],
            enforce_glob=True,
        )

        d = manager._is_file_included(
            path="a.dd",
            included_globs=["*.py"],
            excluded_path_strings=[],
            enforce_glob=True,
        )

        e = manager._is_file_included(
            path="x_a.py",
            included_globs=["*.py"],
            excluded_path_strings=["x_*.py"],
            enforce_glob=True,
        )

        f = manager._is_file_included(
            path="x.py",
            included_globs=["*.py"],
            excluded_path_strings=["x_*.py"],
            enforce_glob=True,
        )
        self.assertTrue(a)
        self.assertTrue(b)
        self.assertFalse(c)
        self.assertFalse(d)
        self.assertFalse(e)
        self.assertTrue(f)

    @mock.patch("os.walk")
    def test_get_files_from_dir(self, os_walk):
        os_walk.return_value = [
            ("/", ("a"), ()),
            ("/a", (), ("a.py", "b.py", "c.ww")),
        ]

        inc, exc = manager._get_files_from_dir(
            files_dir="", included_globs=["*.py"], excluded_path_strings=None
        )

        self.assertEqual({"/a/c.ww"}, exc)
        self.assertEqual({"/a/a.py", "/a/b.py"}, inc)

    def test_populate_baseline_success(self):
        # Test populate_baseline with valid JSON
        baseline_data = """{
            "results": [
                {
                    "code": "test code",
                    "filename": "example_file.py",
                    "issue_severity": "low",
                    "issue_cwe": {
                        "id": 605,
                        "link": "%s"
                    },
                    "issue_confidence": "low",
                    "issue_text": "test issue",
                    "test_name": "some_test",
                    "test_id": "x",
                    "line_number": "n",
                    "line_range": "n-m"
                }
            ]
        }
        """ % (
            "https://cwe.mitre.org/data/definitions/605.html"
        )
        issue_dictionary = {
            "code": "test code",
            "filename": "example_file.py",
            "issue_severity": "low",
            "issue_cwe": issue.Cwe(issue.Cwe.MULTIPLE_BINDS).as_dict(),
            "issue_confidence": "low",
            "issue_text": "test issue",
            "test_name": "some_test",
            "test_id": "x",
            "line_number": "n",
            "line_range": "n-m",
        }
        baseline_items = [issue.issue_from_dict(issue_dictionary)]
        self.manager.populate_baseline(baseline_data)
        self.assertEqual(baseline_items, self.manager.baseline)

    @mock.patch("logging.Logger.warning")
    def test_populate_baseline_invalid_json(self, mock_logger_warning):
        # Test populate_baseline with invalid JSON content
        baseline_data = """{"data": "bad"}"""
        self.manager.populate_baseline(baseline_data)
        # Default value for manager.baseline is []
        self.assertEqual([], self.manager.baseline)
        self.assertTrue(mock_logger_warning.called)

    def test_results_count(self):
        levels = [constants.LOW, constants.MEDIUM, constants.HIGH]
        self.manager.results = [
            issue.Issue(
                severity=level, cwe=issue.Cwe.MULTIPLE_BINDS, confidence=level
            )
            for level in levels
        ]

        r = [
            self.manager.results_count(sev_filter=level, conf_filter=level)
            for level in levels
        ]

        self.assertEqual([3, 2, 1], r)

    def test_output_results_invalid_format(self):
        # Test that output_results succeeds given an invalid format
        temp_directory = self.useFixture(fixtures.TempDir()).path
        lines = 5
        sev_level = constants.LOW
        conf_level = constants.LOW
        output_filename = os.path.join(temp_directory, "_temp_output")
        output_format = "invalid"
        with open(output_filename, "w") as tmp_file:
            self.manager.output_results(
                lines, sev_level, conf_level, tmp_file, output_format
            )
        self.assertTrue(os.path.isfile(output_filename))

    def test_output_results_valid_format(self):
        # Test that output_results succeeds given a valid format
        temp_directory = self.useFixture(fixtures.TempDir()).path
        lines = 5
        sev_level = constants.LOW
        conf_level = constants.LOW
        output_filename = os.path.join(temp_directory, "_temp_output.txt")
        output_format = "txt"
        with open(output_filename, "w") as tmp_file:
            self.manager.output_results(
                lines, sev_level, conf_level, tmp_file, output_format
            )
        self.assertTrue(os.path.isfile(output_filename))

    @mock.patch("os.path.isdir")
    def test_discover_files_recurse_skip(self, isdir):
        isdir.return_value = True
        self.manager.discover_files(["thing"], False)
        self.assertEqual([], self.manager.files_list)
        self.assertEqual([], self.manager.excluded_files)

    @mock.patch("os.path.isdir")
    def test_discover_files_recurse_files(self, isdir):
        isdir.return_value = True
        with mock.patch.object(manager, "_get_files_from_dir") as m:
            m.return_value = ({"files"}, {"excluded"})
            self.manager.discover_files(["thing"], True)
            self.assertEqual(["files"], self.manager.files_list)
            self.assertEqual(["excluded"], self.manager.excluded_files)

    @mock.patch("os.path.isdir")
    def test_discover_files_exclude(self, isdir):
        isdir.return_value = False
        with mock.patch.object(manager, "_is_file_included") as m:
            m.return_value = False
            self.manager.discover_files(["thing"], True)
            self.assertEqual([], self.manager.files_list)
            self.assertEqual(["thing"], self.manager.excluded_files)

    @mock.patch("os.path.isdir")
    def test_discover_files_exclude_dir(self, isdir):
        isdir.return_value = False

        # Test exclude dir using wildcard
        self.manager.discover_files(["./x/y.py"], True, "./x/*")
        self.assertEqual([], self.manager.files_list)
        self.assertEqual(["./x/y.py"], self.manager.excluded_files)

        # Test exclude dir without wildcard
        isdir.side_effect = [True, False]
        self.manager.discover_files(["./x/y.py"], True, "./x/")
        self.assertEqual([], self.manager.files_list)
        self.assertEqual(["./x/y.py"], self.manager.excluded_files)

        # Test exclude dir without wildcard or trailing slash
        isdir.side_effect = [True, False]
        self.manager.discover_files(["./x/y.py"], True, "./x")
        self.assertEqual([], self.manager.files_list)
        self.assertEqual(["./x/y.py"], self.manager.excluded_files)

        # Test exclude dir without prefix or suffix
        isdir.side_effect = [False, False]
        self.manager.discover_files(["./x/y/z.py"], True, "y")
        self.assertEqual([], self.manager.files_list)
        self.assertEqual(["./x/y/z.py"], self.manager.excluded_files)

    @mock.patch("os.path.isdir")
    def test_discover_files_exclude_cmdline(self, isdir):
        isdir.return_value = False
        with mock.patch.object(manager, "_is_file_included") as m:
            self.manager.discover_files(
                ["a", "b", "c"], True, excluded_paths="a,b"
            )
            m.assert_called_with(
                "c", ["*.py", "*.pyw"], ["a", "b"], enforce_glob=False
            )

    @mock.patch("os.path.isdir")
    def test_discover_files_exclude_glob(self, isdir):
        isdir.return_value = False
        self.manager.discover_files(
            ["a.py", "test_a.py", "test.py"], True, excluded_paths="test_*.py"
        )
        self.assertEqual(["./a.py", "./test.py"], self.manager.files_list)
        self.assertEqual(["test_a.py"], self.manager.excluded_files)

    @mock.patch("os.path.isdir")
    def test_discover_files_include(self, isdir):
        isdir.return_value = False
        with mock.patch.object(manager, "_is_file_included") as m:
            m.return_value = True
            self.manager.discover_files(["thing"], True)
            self.assertEqual(["./thing"], self.manager.files_list)
            self.assertEqual([], self.manager.excluded_files)

    def test_run_tests_keyboardinterrupt(self):
        # Test that bandit manager exits when there is a keyboard interrupt
        temp_directory = self.useFixture(fixtures.TempDir()).path
        some_file = os.path.join(temp_directory, "some_code_file.py")
        with open(some_file, "w") as fd:
            fd.write("some_code = x + 1")
        self.manager.files_list = [some_file]
        with mock.patch(
            "bandit.core.metrics.Metrics.count_issues"
        ) as mock_count_issues:
            mock_count_issues.side_effect = KeyboardInterrupt
            # assert a SystemExit with code 2
            self.assertRaisesRegex(SystemExit, "2", self.manager.run_tests)

    def test_run_tests_ioerror(self):
        # Test that a file name is skipped and added to the manager.skipped
        # list when there is an IOError attempting to open/read the file
        temp_directory = self.useFixture(fixtures.TempDir()).path
        no_such_file = os.path.join(temp_directory, "no_such_file.py")
        self.manager.files_list = [no_such_file]
        self.manager.run_tests()
        # since the file name and the IOError.strerror text are added to
        # manager.skipped, we convert skipped to str to find just the file name
        # since IOError is not constant
        self.assertIn(no_such_file, str(self.manager.skipped))

    def test_compare_baseline(self):
        issue_a = self._get_issue_instance()
        issue_a.fname = "file1.py"

        issue_b = self._get_issue_instance()
        issue_b.fname = "file2.py"

        issue_c = self._get_issue_instance(sev=constants.HIGH)
        issue_c.fname = "file1.py"

        # issue c is in results, not in baseline
        self.assertEqual(
            [issue_c],
            manager._compare_baseline_results(
                [issue_a, issue_b], [issue_a, issue_b, issue_c]
            ),
        )

        # baseline and results are the same
        self.assertEqual(
            [],
            manager._compare_baseline_results(
                [issue_a, issue_b, issue_c], [issue_a, issue_b, issue_c]
            ),
        )

        # results are better than baseline
        self.assertEqual(
            [],
            manager._compare_baseline_results(
                [issue_a, issue_b, issue_c], [issue_a, issue_b]
            ),
        )

    def test_find_candidate_matches(self):
        issue_a = self._get_issue_instance()
        issue_b = self._get_issue_instance()

        issue_c = self._get_issue_instance()
        issue_c.fname = "file1.py"

        # issue a and b are the same, both should be returned as candidates
        self.assertEqual(
            {issue_a: [issue_a, issue_b]},
            manager._find_candidate_matches([issue_a], [issue_a, issue_b]),
        )

        # issue a and c are different, only a should be returned
        self.assertEqual(
            {issue_a: [issue_a]},
            manager._find_candidate_matches([issue_a], [issue_a, issue_c]),
        )

        # c doesn't match a, empty list should be returned
        self.assertEqual(
            {issue_a: []},
            manager._find_candidate_matches([issue_a], [issue_c]),
        )

        # a and b match, a and b should both return a and b candidates
        self.assertEqual(
            {issue_a: [issue_a, issue_b], issue_b: [issue_a, issue_b]},
            manager._find_candidate_matches(
                [issue_a, issue_b], [issue_a, issue_b, issue_c]
            ),
        )

    def _scan_source(self, source, fname="sample.py"):
        temp_directory = self.useFixture(fixtures.TempDir()).path
        path = os.path.join(temp_directory, fname)
        with open(path, "w") as fd:
            fd.write(source)
        mgr = manager.BanditManager(config=self.config, agg_type="file")
        mgr.discover_files([path], True)
        mgr.run_tests()
        return mgr, path

    def _issue_ids(self, mgr, path):
        return [
            (item.lineno, item.test_id)
            for item in mgr.get_issue_list()
            if item.fname == path
        ]

    def test_nosec_specific_id_leaves_other_plugins_reported(self):
        source = (
            "import subprocess\n"
            "subprocess.Popen('ls', shell=True)  # nosec B602\n"
            "subprocess.Popen('/bin/b', shell=True)\n"
        )
        mgr, path = self._scan_source(source)
        reported = self._issue_ids(mgr, path)
        self.assertNotIn((2, "B602"), reported)
        self.assertIn((2, "B607"), reported)
        self.assertIn((3, "B602"), reported)
        suppressed = [
            (item.lineno, item.test_id, item.nosec_comment)
            for item in mgr.suppressed
        ]
        self.assertIn((2, "B602", "# nosec B602"), suppressed)

    def test_nosec_colon_form_with_alias_and_case(self):
        source = (
            "import subprocess\n"
            "subprocess.Popen('/bin/a', shell=True)  "
            "# NOSEC: B602, SUBPROCESS_POPEN_WITH_SHELL_EQUALS_TRUE\n"
        )
        mgr, path = self._scan_source(source)
        reported = self._issue_ids(mgr, path)
        self.assertNotIn((2, "B602"), reported)
        record = next(iter(mgr.nosec_records[path].values()))
        self.assertEqual(
            ["B602", "subprocess_popen_with_shell_equals_true"],
            record.selectors,
        )

    def test_nosec_covers_multiline_statement(self):
        source = (
            "import subprocess\n"
            "subprocess.Popen(  # nosec B602\n"
            "    '/bin/a',\n"
            "    shell=True,\n"
            ")\n"
        )
        mgr, path = self._scan_source(source)
        self.assertNotIn((2, "B602"), self._issue_ids(mgr, path))
        record = mgr.nosec_records[path][2]
        self.assertEqual([2, 3, 4, 5], record.line_range)

    def test_nosec_comment_on_last_line_covers_full_statement(self):
        source = (
            "import subprocess\n"
            "subprocess.Popen(\n"
            "    '/bin/a',\n"
            "    shell=True)  # nosec B602\n"
        )
        mgr, path = self._scan_source(source)
        self.assertNotIn((2, "B602"), self._issue_ids(mgr, path))
        record = mgr.nosec_records[path][4]
        self.assertEqual([2, 3, 4], record.line_range)

    def test_standalone_nosec_attaches_to_next_statement(self):
        source = (
            "import subprocess\n"
            "# nosec B602\n"
            "subprocess.Popen('/bin/a', shell=True)\n"
            "subprocess.Popen('/bin/b', shell=True)\n"
        )
        mgr, path = self._scan_source(source)
        reported = self._issue_ids(mgr, path)
        self.assertNotIn((3, "B602"), reported)
        self.assertIn((4, "B602"), reported)

    def test_inline_selector_overrides_previous_line_blanket(self):
        source = (
            "import subprocess\n"
            "# nosec\n"
            "subprocess.Popen('ls', shell=True)  # nosec B602\n"
        )
        mgr, path = self._scan_source(source)
        reported = self._issue_ids(mgr, path)
        # B602 is explicitly suppressed; B607 must still be reported even
        # though the previous line carried a blanket directive.
        self.assertNotIn((3, "B602"), reported)
        self.assertIn((3, "B607"), reported)
        line_records = mgr.nosec_records[path]
        self.assertTrue(line_records[2].blanket)
        self.assertEqual(["B602"], line_records[3].selectors)

    def test_invalid_nosec_does_not_suppress_anything(self):
        source = (
            "import subprocess\n"
            "subprocess.Popen('/bin/a', shell=True)  # nosec B999\n"
        )
        mgr, path = self._scan_source(source)
        self.assertIn((2, "B602"), self._issue_ids(mgr, path))
        record = mgr.nosec_records[path][2]
        self.assertIsInstance(record, b_nosec.NosecRecord)
        self.assertFalse(record.valid)
        self.assertEqual([], mgr.suppressed)

    def test_nosec_does_not_leak_across_function_scope(self):
        source = (
            "import subprocess\n"
            "def f():\n"
            "    subprocess.Popen('a', shell=True)  # nosec B602\n"
            "\n"
            "subprocess.Popen('b', shell=True)\n"
        )
        mgr, path = self._scan_source(source, fname="scope.py")
        reported = self._issue_ids(mgr, path)
        # The directive lives inside the function and must not reach the
        # module-level statement on line 5.
        self.assertNotIn((3, "B602"), reported)
        self.assertIn((5, "B602"), reported)

    def test_nosec_records_are_isolated_per_file(self):
        first = (
            "import subprocess\n"
            "subprocess.Popen('/bin/a', shell=True)  # nosec B602\n"
        )
        second = (
            "import subprocess\n"
            "subprocess.Popen('/bin/b', shell=True)\n"
        )
        temp_directory = self.useFixture(fixtures.TempDir()).path
        first_path = os.path.join(temp_directory, "first.py")
        second_path = os.path.join(temp_directory, "second.py")
        with open(first_path, "w") as fd:
            fd.write(first)
        with open(second_path, "w") as fd:
            fd.write(second)
        mgr = manager.BanditManager(config=self.config, agg_type="file")
        mgr.discover_files([first_path, second_path], True)
        mgr.run_tests()
        self.assertEqual([2], list(mgr.nosec_records[first_path]))
        self.assertEqual({}, mgr.nosec_records[second_path])
        self.assertIn((2, "B602"), self._issue_ids(mgr, second_path))

    def test_nosec_does_not_change_baseline_issue_equality(self):
        issue_a = self._get_issue_instance()
        issue_b = self._get_issue_instance()
        issue_a.nosec_comment = "# nosec B602"
        issue_a.nosec_test_id = "B602"
        self.assertEqual(issue_a, issue_b)

    def test_suppressed_issue_serializes_like_a_normal_issue(self):
        suppressed = self._get_issue_instance()
        suppressed.nosec_comment = "# nosec B602"
        suppressed.nosec_test_id = "B602"
        normal = self._get_issue_instance()
        self.assertEqual(
            suppressed.as_dict(with_code=False),
            normal.as_dict(with_code=False),
        )
        round_trip = issue.issue_from_dict(normal.as_dict())
        self.assertEqual(round_trip, suppressed)

    def test_blanket_nosec_remains_compatible(self):
        source = (
            "import subprocess\n"
            "subprocess.Popen('/bin/a', shell=True)  # nosec\n"
        )
        mgr, path = self._scan_source(source)
        self.assertEqual(
            [(1, "B404")], self._issue_ids(mgr, path)
        )
        record = mgr.nosec_records[path][2]
        self.assertTrue(record.blanket)
        self.assertTrue(record.valid)

    def test_suppressed_audit_keeps_id_and_raw_comment(self):
        source = (
            "import subprocess\n"
            "subprocess.Popen('/bin/a', shell=True)  # nosec: b602\n"
        )
        mgr, path = self._scan_source(source)
        self.assertEqual(1, len(mgr.suppressed))
        suppressed = mgr.suppressed[0]
        self.assertEqual("B602", suppressed.nosec_test_id)
        self.assertEqual("# nosec: b602", suppressed.nosec_comment)
        record = mgr.nosec_records[path][2]
        self.assertEqual("# nosec: b602", record.comment)
        self.assertEqual({"B602"}, record.test_ids)
