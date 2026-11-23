#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import ast
import collections
import re
import textwrap

from .. import linters
from .. import multi
from . import _applicability
from . import _selection
from . import _syntax

# A fragment cannot be parsed by the target interpreter at all, so no rule
# has a chance to run against it.
STATUS_SYNTAX_UNSUPPORTED = 'syntax_unsupported'

# The fragment parses, but the maintenance group's flake8 configuration does
# not select this rule code.
STATUS_RULE_DISABLED = 'rule_disabled'

# The rule exists, but its implementation is inert on the target Python
# version, e.g. it only visits statement nodes that no longer exist.
STATUS_RULE_INAPPLICABLE = 'rule_inapplicable'

# The target interpreter supports the syntax and the rule is enabled, but
# the interpreter running this audit cannot build an AST for the fragment
# (e.g. auditing Python 2 syntax from a Python 3 process). The rule is
# eligible in the target environment, yet cannot be evaluated here; this is
# distinct from a genuine clean result so it never inflates sign-offs.
STATUS_UNEVALUABLE = 'unevaluable'

# Both syntax and rule selection are satisfied and the rule produced no
# results. This is a genuine "no warning" outcome.
STATUS_CLEAN = 'clean'

# Both syntax and rule selection are satisfied and the rule fired.
STATUS_FINDING = 'finding'

SKIP_STATUSES = (
    STATUS_SYNTAX_UNSUPPORTED,
    STATUS_RULE_DISABLED,
    STATUS_RULE_INAPPLICABLE,
    STATUS_UNEVALUABLE,
)

ELIGIBLE_STATUSES = (
    STATUS_CLEAN,
    STATUS_FINDING,
)

Finding = collections.namedtuple(
    'Finding',
    ['code', 'lineno', 'col_offset', 'message']
)

ScopeOutcome = collections.namedtuple(
    'ScopeOutcome',
    ['scope', 'code', 'linter', 'status', 'reason', 'detail', 'findings']
)

ReportItem = collections.namedtuple(
    'ReportItem',
    ['filename', 'lineno', 'col_offset', 'code', 'message', 'raw']
)

FragmentVerdict = collections.namedtuple(
    'FragmentVerdict',
    [
        'scope',
        'source',
        'syntax_supported',
        'unsupported_features',
        'outcomes',
        'findings',
    ]
)

ScopeSummary = collections.namedtuple(
    'ScopeSummary',
    [
        'scope',
        'syntax_supported',
        'unsupported_features',
        'linters_total',
        'rule_disabled',
        'rule_inapplicable',
        'unevaluable',
        'eligible',
        'eligible_clean',
        'eligible_with_finding',
        'findings',
    ]
)

AuditResult = collections.namedtuple(
    'AuditResult',
    ['scope', 'filename', 'verdict', 'summary']
)

_REPORT_LINE_RE = re.compile(
    r'^(?P<filename>[^:]+):(?P<lineno>\d+):(?P<col>\d+):\s*'
    r'(?P<code>DUO\d+)\s*(?P<message>.*)$'
)


def parse_report_line(line):
    """Parse a single flake8 text-format report line into a ReportItem."""
    match = _REPORT_LINE_RE.match(line.strip())

    if match is None:
        raise ValueError('unparseable report line: {}'.format(line))

    return ReportItem(
        filename=match.group('filename'),
        lineno=int(match.group('lineno')),
        col_offset=int(match.group('col')),
        code=match.group('code'),
        message=match.group('message'),
        raw=line
    )


def parse_report(report_text):
    """Parse flake8 text-format report output into ReportItem instances."""
    items = []

    for line in report_text.splitlines():
        stripped = line.strip()

        if not stripped:
            continue

        items.append(parse_report_line(stripped))

    return tuple(items)


def _dedent(source):
    return textwrap.dedent(source).lstrip('\n')


class ScopeAuditor(object):
    """Audit Dlint report eligibility for one target Python environment.

    Each maintenance group constructs an auditor for its own interpreter
    version and rule configuration. Skipped fragments stay local to that
    scope and are never forced into a shared result.
    """

    def __init__(self, python_version, rule_config=None, linter_classes=None):
        self.scope = _syntax.normalize_version(python_version)
        self.rule_config = rule_config if rule_config is not None else _selection.RuleConfig()
        self.linter_classes = (
            tuple(linter_classes) if linter_classes is not None else linters.ALL
        )

    def _linter_is_enabled(self, linter_class):
        return _selection.code_is_selected(
            linter_class._code,
            self.rule_config
        )

    def _linter_applies(self, linter_class, source=None):
        return _applicability.linter_applies(
            linter_class, self.scope, source
        )

    def unsupported_features(self, source):
        """Return syntax features the target interpreter cannot parse."""
        return _syntax.unsupported_features(source, self.scope)

    def syntax_supported(self, source):
        """Return whether the target interpreter can parse this source."""
        return _syntax.is_supported(source, self.scope)[0]

    def _run_linters(self, tree, eligible_classes):
        linter_instances = [linter_class() for linter_class in eligible_classes]
        multi_visitor = multi.MultiNodeVisitor(linter_instances)
        multi_visitor.visit(tree)

        findings_by_code = collections.defaultdict(list)

        for linter_instance in linter_instances:
            code = type(linter_instance)._code

            for result in linter_instance.get_results():
                findings_by_code[code].append(
                    Finding(
                        code=code,
                        lineno=result.lineno,
                        col_offset=result.col_offset,
                        message=result.message
                    )
                )

        return findings_by_code

    def _unevaluable_verdict(self, normalized_source, code, error):
        """Build a verdict for syntax the target supports but the
        running interpreter cannot parse.
        """
        if code is not None:
            target_classes = [
                linter_class
                for linter_class in self.linter_classes
                if linter_class._code == code
            ]
        else:
            target_classes = list(self.linter_classes)

        outcomes = []
        for linter_class in target_classes:
            if not self._linter_is_enabled(linter_class):
                status = STATUS_RULE_DISABLED
                reason = 'rule code {} is not selected in this scope'.format(
                    linter_class._code
                )
            elif not self._linter_applies(linter_class, normalized_source):
                status = STATUS_RULE_INAPPLICABLE
                reason = 'rule code {} is inert on Python {}'.format(
                    linter_class._code, self.scope
                )
            else:
                status = STATUS_UNEVALUABLE
                reason = (
                    'target Python {} supports this syntax, but the audit '
                    'interpreter cannot parse it: {}'.format(
                        self.scope, error.msg
                    )
                )

            outcomes.append(
                ScopeOutcome(
                    scope=self.scope,
                    code=linter_class._code,
                    linter=linter_class,
                    status=status,
                    reason=reason,
                    detail=error,
                    findings=tuple()
                )
            )

        return FragmentVerdict(
            scope=self.scope,
            source=normalized_source,
            syntax_supported=True,
            unsupported_features=tuple(),
            outcomes=tuple(outcomes),
            findings=tuple()
        )

    def audit_fragment(self, source, code=None):
        """Audit one source fragment, optionally restricted to one rule.

        When ``code`` is provided the verdict contains a single outcome for
        that rule. Otherwise every known linter contributes an outcome and
        the three skip reasons are reported separately from clean findings.
        """
        normalized_source = _dedent(source)
        unsupported = self.unsupported_features(normalized_source)

        if unsupported:
            return FragmentVerdict(
                scope=self.scope,
                source=normalized_source,
                syntax_supported=False,
                unsupported_features=tuple(unsupported),
                outcomes=tuple(),
                findings=tuple()
            )

        try:
            tree = ast.parse(normalized_source)
        except SyntaxError as error:
            return self._unevaluable_verdict(
                normalized_source, code, error
            )

        if code is not None:
            target_classes = [
                linter_class
                for linter_class in self.linter_classes
                if linter_class._code == code
            ]

            if not target_classes:
                raise ValueError('unknown linter code: {}'.format(code))
        else:
            target_classes = list(self.linter_classes)

        eligible_classes = [
            linter_class
            for linter_class in target_classes
            if self._linter_is_enabled(linter_class)
            and self._linter_applies(linter_class, normalized_source)
        ]

        findings_by_code = self._run_linters(tree, eligible_classes)

        outcomes = []

        for linter_class in target_classes:
            linter_code = linter_class._code

            if not self._linter_is_enabled(linter_class):
                status = STATUS_RULE_DISABLED
                reason = 'rule code {} is not selected in this scope'.format(linter_code)
                linter_findings = []
            elif not self._linter_applies(linter_class, normalized_source):
                status = STATUS_RULE_INAPPLICABLE
                reason = 'rule code {} is inert on Python {}'.format(
                    linter_code,
                    self.scope
                )
                linter_findings = []
            elif findings_by_code.get(linter_code):
                status = STATUS_FINDING
                reason = 'rule code {} produced warnings'.format(linter_code)
                linter_findings = findings_by_code[linter_code]
            else:
                status = STATUS_CLEAN
                reason = 'rule code {} produced no warnings'.format(linter_code)
                linter_findings = []

            outcomes.append(
                ScopeOutcome(
                    scope=self.scope,
                    code=linter_code,
                    linter=linter_class,
                    status=status,
                    reason=reason,
                    detail=None,
                    findings=tuple(linter_findings)
                )
            )

        all_findings = tuple(
            finding
            for code_findings in findings_by_code.values()
            for finding in code_findings
        )

        return FragmentVerdict(
            scope=self.scope,
            source=normalized_source,
            syntax_supported=True,
            unsupported_features=tuple(),
            outcomes=tuple(outcomes),
            findings=all_findings
        )

    def audit_source(self, source, filename=None):
        """Audit a full source file and return verdict plus a summary."""
        verdict = self.audit_fragment(source)

        if not verdict.syntax_supported:
            summary = ScopeSummary(
                scope=self.scope,
                syntax_supported=False,
                unsupported_features=verdict.unsupported_features,
                linters_total=len(self.linter_classes),
                rule_disabled=0,
                rule_inapplicable=0,
                unevaluable=0,
                eligible=0,
                eligible_clean=0,
                eligible_with_finding=0,
                findings=0
            )

            return AuditResult(
                scope=self.scope,
                filename=filename,
                verdict=verdict,
                summary=summary
            )

        statuses = [outcome.status for outcome in verdict.outcomes]

        summary = ScopeSummary(
            scope=self.scope,
            syntax_supported=True,
            unsupported_features=tuple(),
            linters_total=len(statuses),
            rule_disabled=statuses.count(STATUS_RULE_DISABLED),
            rule_inapplicable=statuses.count(STATUS_RULE_INAPPLICABLE),
            unevaluable=statuses.count(STATUS_UNEVALUABLE),
            eligible=sum(status in ELIGIBLE_STATUSES for status in statuses),
            eligible_clean=statuses.count(STATUS_CLEAN),
            eligible_with_finding=statuses.count(STATUS_FINDING),
            findings=len(verdict.findings)
        )

        return AuditResult(
            scope=self.scope,
            filename=filename,
            verdict=verdict,
            summary=summary
        )

    def evaluate_report_item(self, report_item, source):
        """Decide whether one report item is signable in this scope.

        Report items whose fragment this environment skips come back with a
        skip status rather than being folded into the eligible result set.
        """
        linter_class = _applicability.linter_for_code(
            report_item.code,
            self.linter_classes
        )

        if linter_class is None:
            return ScopeOutcome(
                scope=self.scope,
                code=report_item.code,
                linter=None,
                status=STATUS_RULE_DISABLED,
                reason='rule code {} is unknown to this Dlint install'.format(
                    report_item.code
                ),
                detail=report_item,
                findings=tuple()
            )

        normalized_source = _dedent(source)
        unsupported = self.unsupported_features(normalized_source)

        if unsupported:
            return ScopeOutcome(
                scope=self.scope,
                code=report_item.code,
                linter=linter_class,
                status=STATUS_SYNTAX_UNSUPPORTED,
                reason='target interpreter cannot parse this source fragment',
                detail=report_item,
                findings=tuple(unsupported)
            )

        if not self._linter_is_enabled(linter_class):
            return ScopeOutcome(
                scope=self.scope,
                code=report_item.code,
                linter=linter_class,
                status=STATUS_RULE_DISABLED,
                reason='rule code {} is not selected in this scope'.format(
                    report_item.code
                ),
                detail=report_item,
                findings=tuple()
            )

        if not self._linter_applies(linter_class, normalized_source):
            return ScopeOutcome(
                scope=self.scope,
                code=report_item.code,
                linter=linter_class,
                status=STATUS_RULE_INAPPLICABLE,
                reason='rule code {} is inert on Python {}'.format(
                    report_item.code,
                    self.scope
                ),
                detail=report_item,
                findings=tuple()
            )

        try:
            ast.parse(normalized_source)
        except SyntaxError as error:
            return ScopeOutcome(
                scope=self.scope,
                code=report_item.code,
                linter=linter_class,
                status=STATUS_UNEVALUABLE,
                reason=(
                    'target Python {} supports this syntax, but the audit '
                    'interpreter cannot parse it: {}'.format(
                        self.scope, error.msg
                    )
                ),
                detail=report_item,
                findings=tuple()
            )

        return ScopeOutcome(
            scope=self.scope,
            code=report_item.code,
            linter=linter_class,
            status=STATUS_FINDING,
            reason='rule code {} is eligible and the finding is signable'.format(
                report_item.code
            ),
            detail=report_item,
            findings=(report_item,)
        )

    def signable_report_items(self, report_items, sources):
        """Return only the report items this maintenance group may sign.

        ``sources`` maps each report filename to its source text. Items
        skipped by this target environment are omitted instead of being
        forced into the shared result.
        """
        signable = []

        for report_item in report_items:
            source = sources[report_item.filename]
            outcome = self.evaluate_report_item(report_item, source)

            if outcome.status in ELIGIBLE_STATUSES:
                signable.append(report_item)

        return tuple(signable)

    def report_item_outcomes(self, report_items, sources):
        """Return per-item outcomes so skip reasons remain auditable."""
        return tuple(
            self.evaluate_report_item(
                report_item,
                sources[report_item.filename]
            )
            for report_item in report_items
        )
