#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import unittest

import dlint


class TestBadToctouUse(dlint.test.base.BaseTest):

    def lint(self, source):
        python_node = self.get_ast_node(source)
        linter = dlint.linters.BadToctouUseLinter()
        linter.visit(python_node)
        return linter

    def assert_toctou_pair(self, linter, check_line, use_line,
                           expected_conditions=None):
        matching = [
            finding for finding in linter.toctou_findings
            if finding.check_node.lineno == check_line
            and finding.use_node.lineno == use_line
        ]
        assert matching, (
            "expected check/use pair lines {} -> {}, got {}".format(
                check_line,
                use_line,
                [
                    (f.check_node.lineno, f.use_node.lineno)
                    for f in linter.toctou_findings
                ],
            )
        )
        if expected_conditions is not None:
            conditions = set()
            for finding in matching:
                conditions.update(finding.invalidations)
            missing = set(expected_conditions) - conditions
            assert not missing, (
                "missing conditions {}; got {}".format(
                    missing, conditions
                )
            )

    def assert_no_findings(self, linter):
        assert linter.get_results() == []


    def test_path_check_then_builtin_open_is_flagged(self):
        linter = self.lint(
            """
            import os

            def vulnerable(path):
                if os.path.exists(path):
                    with open(path) as handle:
                        return handle.read()
            """
        )

        assert len(linter.get_results()) == 1
        self.assert_toctou_pair(linter, 5, 6)
        result = linter.get_results()[0]
        assert result.lineno == 6
        assert result.message.startswith(
            "DUO139 TOCTOU race condition: filesystem check at line 5 "
            "is followed by use at line 6"
        )

    def test_sequential_stat_then_unlink_is_flagged(self):
        linter = self.lint(
            """
            import os

            def vulnerable(path):
                os.stat(path)
                os.unlink(path)
            """
        )

        assert len(linter.get_results()) == 1
        self.assert_toctou_pair(linter, 5, 6)

    def test_access_check_then_rename_is_flagged(self):
        linter = self.lint(
            """
            import os

            def vulnerable(path, target):
                if os.access(path, os.R_OK):
                    os.rename(path, target)
            """
        )

        assert len(linter.get_results()) == 1
        self.assert_toctou_pair(
            linter, 5, 6,
            expected_conditions=[
                dlint.linters.bad_toctou_use.INVALIDATION_BRANCH,
            ],
        )

    def test_branch_path_is_reachable_use(self):
        linter = self.lint(
            """
            import os

            def vulnerable(path, enabled):
                if os.path.exists(path):
                    if enabled:
                        os.unlink(path)
            """
        )

        assert len(linter.get_results()) == 1
        self.assert_toctou_pair(
            linter, 5, 7,
            expected_conditions=[
                dlint.linters.bad_toctou_use.INVALIDATION_BRANCH,
            ],
        )


    def test_exception_handler_use_is_flagged_with_exception_condition(self):
        linter = self.lint(
            """
            import os

            def vulnerable(path, target):
                if os.path.exists(path):
                    try:
                        os.rename(path, target)
                    except OSError:
                        os.unlink(path)
            """
        )

        assert len(linter.get_results()) == 2
        self.assert_toctou_pair(linter, 5, 7)
        self.assert_toctou_pair(linter, 5, 9)
        self.assert_toctou_pair(
            linter, 5, 9,
            expected_conditions=[
                dlint.linters.bad_toctou_use.INVALIDATION_EXCEPTION,
            ],
        )

    def test_loop_back_edge_invalidates_check(self):
        linter = self.lint(
            """
            import os

            def vulnerable(paths):
                for path in paths:
                    if os.path.exists(path):
                        with open(path) as handle:
                            handle.read()
            """
        )

        assert len(linter.get_results()) == 1
        self.assert_toctou_pair(
            linter, 6, 7,
            expected_conditions=[
                dlint.linters.bad_toctou_use.INVALIDATION_LOOP,
                dlint.linters.bad_toctou_use.INVALIDATION_BRANCH,
            ],
        )

    def test_path_rebind_invalidates_check(self):
        linter = self.lint(
            """
            import os

            def vulnerable(path, other):
                if os.path.exists(path):
                    path = other
                    os.unlink(path)
            """
        )

        results = linter.get_results()
        assert len(results) == 1
        self.assert_toctou_pair(
            linter, 5, 7,
            expected_conditions=[
                dlint.linters.bad_toctou_use.INVALIDATION_REBIND,
            ],
        )


    def test_exclusive_create_is_not_flagged(self):
        linter = self.lint(
            """
            import os

            def safe(path):
                if not os.path.exists(path):
                    descriptor = os.open(
                        path,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    )
                return descriptor
            """
        )

        self.assert_no_findings(linter)

    def test_no_follow_open_is_not_flagged(self):
        linter = self.lint(
            """
            import os

            def safe(path):
                if os.path.exists(path):
                    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                return descriptor
            """
        )

        self.assert_no_findings(linter)

    def test_no_follow_keyword_is_not_flagged(self):
        linter = self.lint(
            """
            import os

            def safe(path):
                descriptor = os.open(path, os.O_RDONLY, no_follow=True)
                return descriptor
            """
        )

        self.assert_no_findings(linter)

    def test_fdopen_transfer_keeps_descriptor_semantics(self):
        linter = self.lint(
            """
            import os

            def safe(path):
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                with os.fdopen(descriptor) as handle:
                    return handle.read()
            """
        )

        self.assert_no_findings(linter)

    def test_descriptor_functions_are_not_flagged(self):
        linter = self.lint(
            """
            import os

            def safe(path):
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                os.fstat(descriptor)
                os.fchmod(descriptor, 0o600)
                os.fsync(descriptor)
                os.close(descriptor)
            """
        )

        self.assert_no_findings(linter)


    def test_anchored_dir_fd_with_no_follow_is_not_flagged(self):
        linter = self.lint(
            """
            import os

            def safe(base, name):
                if os.path.exists(name):
                    directory = os.open(
                        base,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    )
                    descriptor = os.open(
                        name,
                        os.O_RDONLY | os.O_NOFOLLOW,
                        dir_fd=directory,
                    )
                return descriptor
            """
        )

        self.assert_no_findings(linter)

    def test_unknown_dir_fd_without_no_follow_is_flagged(self):
        linter = self.lint(
            """
            import os

            def vulnerable(directory, name):
                if os.path.exists(name):
                    descriptor = os.open(
                        name,
                        os.O_RDONLY,
                        dir_fd=directory,
                    )
                return descriptor
            """
        )

        assert len(linter.get_results()) == 1
        self.assert_toctou_pair(linter, 5, 6)

    def test_same_descriptor_vs_same_path_are_distinguished(self):
        linter = self.lint(
            """
            import os

            def mixed(path):
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                os.fstat(descriptor)
                os.unlink(path)
            """
        )

        self.assert_no_findings(linter)

    def test_pathlib_check_then_open_is_flagged(self):
        linter = self.lint(
            """
            def vulnerable(candidate):
                if candidate.exists():
                    return candidate.open()
            """
        )

        assert len(linter.get_results()) == 1
        self.assert_toctou_pair(linter, 3, 4)

    def test_unknown_wrapper_is_uncertain_not_suppressed(self):
        linter = self.lint(
            """
            import os

            def vulnerable(path):
                if os.path.exists(path):
                    data = helper.load(path)
                    with open(path) as handle:
                        handle.read()
                    return data
            """
        )

        assert len(linter.get_results()) == 1
        self.assert_toctou_pair(
            linter, 5, 7,
            expected_conditions=[
                dlint.linters.bad_toctou_use.INVALIDATION_UNKNOWN_WRAPPER,
            ],
        )
        message = linter.get_results()[0].message
        assert "unknown wrapper" in message


    def test_from_import_bare_names_are_flagged(self):
        linter = self.lint(
            """
            from os import unlink
            from os.path import exists

            def vulnerable(path):
                if exists(path):
                    unlink(path)
            """
        )

        assert len(linter.get_results()) == 1
        self.assert_toctou_pair(linter, 6, 7)

    def test_aliased_module_is_flagged(self):
        linter = self.lint(
            """
            import os as operating_system

            def vulnerable(path):
                if operating_system.path.exists(path):
                    operating_system.unlink(path)
            """
        )

        assert len(linter.get_results()) == 1
        self.assert_toctou_pair(linter, 5, 6)

    def test_local_function_shadow_is_not_flagged(self):
        linter = self.lint(
            """
            def exists(path):
                return True

            def vulnerable(path):
                if exists(path):
                    remove(path)
            """
        )

        self.assert_no_findings(linter)

    def test_checks_do_not_leak_across_functions(self):
        linter = self.lint(
            """
            import os

            def first(path):
                os.path.exists(path)

            def second(path):
                os.unlink(path)
            """
        )

        self.assert_no_findings(linter)

    def test_use_does_not_self_label_its_own_mutation(self):
        linter = self.lint(
            """
            import os

            def vulnerable(path, target):
                if os.path.exists(path):
                    os.rename(path, target)
                    os.unlink(path)
            """
        )

        assert len(linter.get_results()) == 2
        rename_finding = next(
            finding for finding in linter.toctou_findings
            if finding.use_node.lineno == 6
        )
        assert (
            dlint.linters.bad_toctou_use.INVALIDATION_MUTATION
            not in rename_finding.invalidations
        )
        unlink_finding = next(
            finding for finding in linter.toctou_findings
            if finding.use_node.lineno == 7
        )
        self.assert_toctou_pair(
            linter, 5, 7,
            expected_conditions=[
                dlint.linters.bad_toctou_use.INVALIDATION_MUTATION,
            ],
        )
        assert unlink_finding.invalidations

    def test_loop_and_exception_conditions_are_both_reachable(self):
        linter = self.lint(
            """
            import os

            def vulnerable(paths):
                while True:
                    for path in paths:
                        if os.path.exists(path):
                            try:
                                os.unlink(path)
                            except OSError:
                                continue
            """
        )

        assert len(linter.get_results()) == 1
        self.assert_toctou_pair(
            linter, 7, 9,
            expected_conditions=[
                dlint.linters.bad_toctou_use.INVALIDATION_LOOP,
            ],
        )

    def test_use_without_check_is_not_flagged(self):
        linter = self.lint(
            """
            import os

            def safe(path, target):
                os.rename(path, target)
                os.unlink(path)
            """
        )

        self.assert_no_findings(linter)

    def test_results_are_flake8_tuples(self):
        linter = self.lint(
            """
            import os

            def vulnerable(path):
                if os.path.exists(path):
                    os.unlink(path)
            """
        )

        result = linter.get_results()[0]
        assert isinstance(result, dlint.linters.base.Flake8Result)
        assert result.col_offset >= 0
        assert result.message.startswith("DUO139")


if __name__ == "__main__":
    unittest.main()
