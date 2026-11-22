#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import unittest

import dlint


MUTUALLY_EXCLUSIVE = """
ticket = approvals.issue_approval()
if use_primary:
    approvals.consume_approval(ticket)
else:
    approvals.consume_approval(ticket)
"""

CONSUME_THEN_RAISE = """
ticket = approvals.issue_approval()
try:
    approvals.consume_approval(ticket)
    raise ReleaseError("retry")
except ReleaseError:
    approvals.consume_approval(ticket)
"""

READ_ONLY_BORROW = """
ticket = approvals.issue_approval()
borrowed = approvals.peek_approval(ticket)
approvals.peek_approval(ticket)
approvals.consume_approval(borrowed)
"""


class TestApprovalReuse(dlint.test.base.BaseTest):

    def _lint(self, source, **kwargs):
        node = self.get_ast_node(source)
        linter = dlint.linters.ApprovalReuseLinter(**kwargs)
        linter.visit(node)
        return linter.get_results()

    def test_mutually_exclusive_branches_pass(self):
        results = self._lint(MUTUALLY_EXCLUSIVE)
        assert results == []

    def test_consume_then_raise_reports_both_calls(self):
        results = self._lint(CONSUME_THEN_RAISE)
        assert [result.lineno for result in results] == [4, 7]
        assert all(
            result.message.startswith(
                dlint.linters.ApprovalReuseLinter._error_tmpl)
            for result in results
        )

    def test_read_only_borrow_passes(self):
        results = self._lint(READ_ONLY_BORROW)
        assert results == []

    def test_alias_container_and_helper(self):
        source = """
            def do_release(approval):
                approvals.consume_approval(approval)

            ticket = approvals.issue_approval()
            alias = ticket
            bucket = [alias]
            held = bucket[0]
            do_release(held)
            approvals.consume_approval(ticket)
        """
        results = self._lint(source)
        assert [result.lineno for result in results] == [3, 10]

    def test_external_return_has_unknown_status(self):
        source = """
            ticket = load_ticket_from_store()
            approvals.consume_approval(ticket)
        """
        results = self._lint(source)
        assert [result.lineno for result in results] == [3]
        assert results[0].message.startswith(
            dlint.linters.ApprovalReuseLinter._unknown_tmpl)

    def test_retry_loop_reports_repeated_consumption(self):
        source = """
            ticket = approvals.issue_approval()
            for attempt in range(2):
                approvals.consume_approval(ticket)
        """
        results = self._lint(source)
        assert [result.lineno for result in results] == [4]

    def test_configurable_apis(self):
        source = """
            ticket = approvals.mint()
            approvals.peek(ticket)
            approvals.spend(ticket)
            approvals.spend(ticket)
        """
        results = self._lint(
            source,
            issuance_apis=["mint"],
            borrow_apis=["peek"],
            consumption_apis=["spend"],
        )
        assert [result.lineno for result in results] == [4, 5]


if __name__ == "__main__":
    unittest.main()
