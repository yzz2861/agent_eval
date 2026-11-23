#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import unittest

import dlint
from dlint.audit import _applicability


class TestLinterApplicability(unittest.TestCase):

    def test_generic_linter_applies_everywhere(self):
        assert _applicability.linter_applies(
            dlint.linters.BadEvalUseLinter, (2, 7)
        )
        assert _applicability.linter_applies(
            dlint.linters.BadEvalUseLinter, (3, 8)
        )

    def test_duo101_python2_only(self):
        linter = dlint.linters.YieldReturnStatementLinter

        assert _applicability.linter_applies(linter, (2, 7))
        assert not _applicability.linter_applies(
            linter, (3, 8), source='x = 1'
        )

    def test_duo108_python2_only(self):
        linter = dlint.linters.BadInputUseLinter

        assert _applicability.linter_applies(linter, (2, 7))
        assert not _applicability.linter_applies(
            linter, (3, 8), source='input()'
        )

    def test_duo105_exec_call_still_applies_on_python3(self):
        linter = dlint.linters.BadExecUseLinter

        assert _applicability.linter_applies(
            linter, (3, 8), source="exec('x')"
        )

    def test_duo105_exec_statement_does_not_apply_on_python3(self):
        linter = dlint.linters.BadExecUseLinter

        assert not _applicability.linter_applies(
            linter, (3, 8), source="exec 'x'"
        )

    def test_duo105_applies_on_python2_without_source(self):
        linter = dlint.linters.BadExecUseLinter

        assert _applicability.linter_applies(linter, (2, 7))

    def test_linter_for_code_roundtrip(self):
        linter = _applicability.linter_for_code('DUO104')

        assert linter is dlint.linters.BadEvalUseLinter
        assert _applicability.linter_for_code('DUO999') is None

    def test_linter_for_code_respects_custom_registry(self):
        custom = (dlint.linters.BadEvalUseLinter,)

        assert _applicability.linter_for_code('DUO104', custom) is not None
        assert _applicability.linter_for_code('DUO105', custom) is None


if __name__ == '__main__':
    unittest.main()
