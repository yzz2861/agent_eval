#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import unittest

import dlint
from dlint.audit import (
    ReportItem,
    RuleConfig,
    ScopeAuditor,
    parse_report,
)
from dlint.audit.core import (
    ELIGIBLE_STATUSES,
    SKIP_STATUSES,
    STATUS_CLEAN,
    STATUS_FINDING,
    STATUS_RULE_DISABLED,
    STATUS_RULE_INAPPLICABLE,
    STATUS_SYNTAX_UNSUPPORTED,
    STATUS_UNEVALUABLE,
)


class TestFragmentAudit(unittest.TestCase):

    def test_syntax_unsupported_short_circuits(self):
        auditor = ScopeAuditor((3, 8))

        verdict = auditor.audit_fragment("print 'legacy'\n", 'DUO105')

        assert not verdict.syntax_supported
        assert verdict.outcomes == ()
        assert verdict.findings == ()
        assert verdict.unsupported_features[0]['name'] == 'print_statement'

    def test_rule_disabled_is_separate_from_clean(self):
        auditor = ScopeAuditor(
            (3, 8), RuleConfig(ignore=('DUO104',))
        )

        verdict = auditor.audit_fragment('x = 1\n', 'DUO104')

        assert verdict.syntax_supported
        assert len(verdict.outcomes) == 1
        assert verdict.outcomes[0].status == STATUS_RULE_DISABLED

    def test_rule_inapplicable_is_separate_from_clean(self):
        auditor = ScopeAuditor((3, 8))

        verdict = auditor.audit_fragment('input()\n', 'DUO108')

        assert verdict.outcomes[0].status == STATUS_RULE_INAPPLICABLE

    def test_clean_is_a_real_no_warning_result(self):
        auditor = ScopeAuditor((3, 8))

        verdict = auditor.audit_fragment('x = 1\n', 'DUO104')

        assert verdict.outcomes[0].status == STATUS_CLEAN
        assert verdict.findings == ()

    def test_finding_carries_linter_result(self):
        auditor = ScopeAuditor((3, 8))

        verdict = auditor.audit_fragment("eval('1')\n", 'DUO104')

        assert verdict.outcomes[0].status == STATUS_FINDING
        assert len(verdict.findings) == 1
        assert verdict.findings[0].code == 'DUO104'
        assert verdict.findings[0].lineno == 1

    def test_exec_call_fires_on_python3(self):
        auditor = ScopeAuditor((3, 8))

        verdict = auditor.audit_fragment("exec('x')\n", 'DUO105')

        assert verdict.outcomes[0].status == STATUS_FINDING

    def test_python2_syntax_is_unevaluable_from_python3_runtime(self):
        auditor = ScopeAuditor((2, 7))

        verdict = auditor.audit_fragment("print 'legacy'\n", 'DUO104')

        assert verdict.syntax_supported
        assert verdict.outcomes[0].status == STATUS_UNEVALUABLE
        assert STATUS_UNEVALUABLE in SKIP_STATUSES
        assert STATUS_UNEVALUABLE not in ELIGIBLE_STATUSES

    def test_unknown_code_raises(self):
        auditor = ScopeAuditor((3, 8))

        with self.assertRaises(ValueError):
            auditor.audit_fragment('x = 1\n', 'DUO999')

    def test_full_audit_separates_all_three_skip_buckets(self):
        auditor = ScopeAuditor(
            (3, 8), RuleConfig(ignore=('DUO103',))
        )

        result = auditor.audit_source(
            "import pickle\npickle.loads(x)\neval('1')\ninput()\n",
            filename='example.py',
        )

        summary = result.summary

        assert summary.rule_disabled >= 1
        assert summary.rule_inapplicable >= 1
        assert summary.eligible_clean >= 1
        assert summary.eligible_with_finding >= 1
        assert summary.findings >= 1

        statuses = [outcome.status for outcome in result.verdict.outcomes]
        assert STATUS_CLEAN in statuses
        assert STATUS_FINDING in statuses
        assert STATUS_RULE_DISABLED in statuses
        assert STATUS_RULE_INAPPLICABLE in statuses

    def test_syntax_unsupported_source_summary(self):
        auditor = ScopeAuditor((3, 8))

        result = auditor.audit_source("print 'legacy'\n")

        assert not result.summary.syntax_supported
        assert result.summary.eligible == 0
        assert result.verdict.unsupported_features[0]['name'] == \
            'print_statement'


class TestReportSignOff(unittest.TestCase):

    def _build_report(self):
        return parse_report(
            "app/legacy.py:4:0: DUO105 use of \"exec\" is insecure\n"
            "app/eval.py:2:0: DUO104 use of \"eval\" is insecure\n"
            "app/input.py:3:0: DUO108 use of \"input\" is insecure\n"
        )

    def _build_sources(self):
        return {
            'app/legacy.py': "exec 'legacy call'\n",
            'app/eval.py': "eval('1')\n",
            'app/input.py': "input()\n",
        }

    def test_parse_report_items(self):
        items = self._build_report()

        assert len(items) == 3
        assert isinstance(items[0], ReportItem)
        assert items[0].code == 'DUO105'
        assert items[0].lineno == 4
        assert items[1].filename == 'app/eval.py'

    def test_each_group_gets_its_own_signable_set(self):
        report = self._build_report()
        sources = self._build_sources()

        py38 = ScopeAuditor((3, 8))
        py27 = ScopeAuditor((2, 7))

        py38_signable = py38.signable_report_items(report, sources)
        py27_signable = py27.signable_report_items(report, sources)

        # The Python 3 group can only sign the eval finding; the other
        # two are environment skips and stay out of its result set.
        assert [item.code for item in py38_signable] == ['DUO104']

        # The Python 2 group can additionally sign DUO108 because that
        # rule is live there, while the exec-statement finding remains
        # unevaluable from the Python 3 audit runtime.
        assert [item.code for item in py27_signable] == [
            'DUO104', 'DUO108'
        ]

    def test_skipped_item_is_not_forced_into_shared_result(self):
        report = self._build_report()
        sources = self._build_sources()
        py38 = ScopeAuditor((3, 8))

        outcomes = {
            outcome.code: outcome
            for outcome in py38.report_item_outcomes(report, sources)
        }

        assert outcomes['DUO105'].status == STATUS_SYNTAX_UNSUPPORTED
        assert outcomes['DUO108'].status == STATUS_RULE_INAPPLICABLE
        assert outcomes['DUO104'].status == STATUS_FINDING

        signable = py38.signable_report_items(report, sources)
        assert all(item.code != 'DUO105' for item in signable)
        assert all(item.code != 'DUO108' for item in signable)

    def test_disabled_rule_item_is_not_signable(self):
        report = parse_report(
            "app/eval.py:2:0: DUO104 use of \"eval\" is insecure\n"
        )
        sources = {'app/eval.py': "eval('1')\n"}
        auditor = ScopeAuditor(
            (3, 8), RuleConfig(ignore=('DUO104',))
        )

        outcomes = auditor.report_item_outcomes(report, sources)

        assert outcomes[0].status == STATUS_RULE_DISABLED
        assert auditor.signable_report_items(report, sources) == ()

    def test_python2_group_marks_unparseable_item_unevaluable(self):
        report = parse_report(
            "app/legacy.py:4:0: DUO105 use of \"exec\" is insecure\n"
        )
        sources = {'app/legacy.py': "exec 'legacy call'\n"}
        auditor = ScopeAuditor((2, 7))

        outcome = auditor.evaluate_report_item(report[0], sources['app/legacy.py'])

        assert outcome.status == STATUS_UNEVALUABLE
        assert auditor.signable_report_items(report, sources) == ()

    def test_unknown_report_code_is_treated_as_disabled(self):
        auditor = ScopeAuditor((3, 8))
        item = ReportItem(
            filename='app/eval.py',
            lineno=2,
            col_offset=0,
            code='DUO999',
            message='unknown',
            raw='app/eval.py:2:0: DUO999 unknown',
        )

        outcome = auditor.evaluate_report_item(item, "eval('1')\n")

        assert outcome.status == STATUS_RULE_DISABLED

    def test_unparseable_report_line_raises(self):
        with self.assertRaises(ValueError):
            parse_report('not a flake8 report line\n')


if __name__ == '__main__':
    unittest.main()
