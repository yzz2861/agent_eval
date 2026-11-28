#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import unittest

import dlint


class TestBadTemporaryResourceUse(dlint.test.base.BaseTest):

    def _results(self, source, **kwargs):
        linter = dlint.linters.BadTemporaryResourceUseLinter(**kwargs)
        linter.visit(self.get_ast_node(source))
        return linter, linter.get_results()

    def test_early_return_before_shared_cleanup(self):
        source = """
            def acquire_temp():
                ...

            def security_check(resource):
                ...

            def handle(flag):
                resource = acquire_temp()
                if flag:
                    return resource
                    security_check(resource)
                security_check(resource)
                return resource
        """

        linter, result = self._results(source)
        expected = [
            dlint.linters.base.Flake8Result(
                lineno=11,
                col_offset=8,
                message=dlint.linters.BadTemporaryResourceUseLinter._error_tmpl,
            ),
        ]

        assert result == expected

        handle = [
            evidence for evidence in linter.get_evidence()
            if evidence.name == 'handle'
        ][0]
        assert handle.problems[0].lineno == 11
        assert handle.problems[0].status == dlint.flow.UNCHECKED
        assert 'return@11' in handle.problems[0].path_text

    def test_checked_return_is_normal(self):
        source = """
            def acquire_temp():
                ...

            def security_check(resource):
                ...

            def handle():
                resource = acquire_temp()
                security_check(resource)
                return resource
        """

        linter, result = self._results(source)
        assert result == []
        handle = [
            evidence for evidence in linter.get_evidence()
            if evidence.name == 'handle'
        ][0]
        assert handle.normal_returns

    def test_finally_cleanup_is_recognised_exception_cleanup(self):
        source = """
            def acquire_temp():
                ...

            def security_check(resource):
                ...

            def handle():
                resource = acquire_temp()
                try:
                    risky()
                finally:
                    security_check(resource)
        """

        linter, result = self._results(source)
        assert result == []
        handle = [
            evidence for evidence in linter.get_evidence()
            if evidence.name == 'handle'
        ][0]
        assert any(exit.cleanup == 'finally' for exit in handle.exits)

    def test_branch_skipping_shared_finally_reports_at_return(self):
        source = """
            def acquire_temp():
                ...

            def cleanup(resource):
                ...

            def handle(flag):
                resource = acquire_temp()
                if flag:
                    return resource
                try:
                    return resource
                finally:
                    cleanup(resource)
        """

        linter, result = self._results(source)
        expected = [
            dlint.linters.base.Flake8Result(
                lineno=11,
                col_offset=8,
                message=dlint.linters.BadTemporaryResourceUseLinter._error_tmpl,
            ),
        ]
        assert result == expected
        handle = [
            evidence for evidence in linter.get_evidence()
            if evidence.name == 'handle'
        ][0]
        assert handle.problems[0].lineno == 11
        assert any(exit.cleanup == 'finally' for exit in handle.exits)

    def test_exception_only_cleanup_has_no_leak(self):
        source = """
            def acquire_temp():
                ...

            def cleanup(resource):
                ...

            def handle():
                resource = acquire_temp()
                try:
                    risky()
                except Exception:
                    cleanup(resource)
                    raise
                cleanup(resource)
                return resource
        """

        linter, result = self._results(source)
        assert result == []
        handle = [
            evidence for evidence in linter.get_evidence()
            if evidence.name == 'handle'
        ][0]
        assert handle.exception_cleanups

    def test_unknown_contract_is_distinct_from_a_confirmed_miss(self):
        source = """
            def acquire_temp():
                ...

            def handle():
                resource = acquire_temp()
                external_release(resource)
                return resource
        """

        linter, result = self._results(source)
        expected = [
            dlint.linters.base.Flake8Result(
                lineno=8,
                col_offset=4,
                message=dlint.linters.BadTemporaryResourceUseLinter._unknown_error_tmpl,
            ),
        ]
        assert result == expected
        handle = [
            evidence for evidence in linter.get_evidence()
            if evidence.name == 'handle'
        ][0]
        assert handle.problems[0].status == dlint.flow.CONTRACT_UNKNOWN

    def test_same_file_convention_declares_a_placeholder_check(self):
        source = """
            SECURITY_CHECKS = ('release_temp',)

            def acquire_temp():
                ...

            def release_temp(resource):
                ...

            def handle():
                resource = acquire_temp()
                release_temp(resource)
                return resource
        """

        result = self._results(
            source,
            checks=('security_check',),
        )[1]
        assert result == []

    def test_alias_does_not_transfer_responsibility(self):
        source = """
            def acquire_temp():
                ...

            def security_check(resource):
                ...

            def handle():
                resource = acquire_temp()
                alias = resource
                security_check(alias)
                return resource
        """

        result = self._results(source)[1]
        assert result == []

    def test_configured_factory_and_bool_contract(self):
        source = """
            def handle():
                resource = project_acquire()
                if project_check(resource):
                    return resource
                return resource
        """

        linter, result = self._results(
            source,
            factories=('project_acquire',),
            checks=('project_check',),
            contracts={'project_check': 'bool'},
        )
        assert len(result) == 1
        assert result[0].lineno == 6
        assert result[0].message == dlint.linters.BadTemporaryResourceUseLinter._error_tmpl

    def test_existing_tempfile_alert_is_preserved(self):
        source = """
            import tempfile

            tempfile.mktemp()
        """

        linter = dlint.linters.BadTempfileUseLinter()
        linter.visit(self.get_ast_node(source))
        expected = [
            dlint.linters.base.Flake8Result(
                lineno=4,
                col_offset=0,
                message=dlint.linters.BadTempfileUseLinter._error_tmpl,
            ),
        ]
        assert linter.get_results() == expected

    def test_branch_diagnostic_can_preserve_original_alert_number(self):
        source = """
            import tempfile

            def handle(flag):
                path = tempfile.mktemp()
                if flag:
                    return path
                cleanup(path)
                return path
        """

        result = self._results(source)[1]
        assert len(result) == 1
        assert result[0].message.startswith('DUO121 ')

    def test_standalone_evidence_classifies_exit_kinds(self):
        source = """
            def acquire_temp():
                ...

            def cleanup(resource):
                ...

            def handle(flag):
                resource = acquire_temp()
                if flag:
                    return resource
                try:
                    risky()
                except Exception:
                    cleanup(resource)
                    raise
                external_release(resource)
                return resource
        """

        evidence = dlint.flow.collect_evidence(source)[0]
        statuses = set(exit.status for exit in evidence.exits)
        assert dlint.flow.UNCHECKED in statuses
        assert dlint.flow.EXCEPTION_CLEANUP in statuses
        assert dlint.flow.CONTRACT_UNKNOWN in statuses
        assert evidence.to_dict()['resources']

    def test_placeholders_are_never_executed(self):
        source = """
            def acquire_temp():
                raise AssertionError('must not execute')

            def security_check(resource):
                raise AssertionError('must not execute')

            def handle(flag):
                resource = acquire_temp()
                if flag:
                    return resource
                security_check(resource)
                return resource
        """

        linter, result = self._results(source)
        assert len(result) == 1
        assert result[0].lineno == 11


if __name__ == '__main__':
    unittest.main()
