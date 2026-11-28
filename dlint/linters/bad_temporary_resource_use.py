#!/usr/bin/env python

"""Branch-sensitive review of temporary resource safety checks.

The rule follows a caller-configured set of temporary resource factories and
check/release APIs inside each local function.  It reports a branch only when
the resource reaches a return (or exception exit) before the configured check
completed on that path.  Calls are matched statically; placeholder functions
and contract declarations in the analyzed file are never imported or run.

This complements, but does not change, the existing ``tempfile.mktemp`` rule
(``DUO121``).  Existing rule identifiers and messages are left untouched.
"""

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import ast

from . import base
from ..flow import evidence


DEFAULT_FACTORIES = evidence.DEFAULT_FACTORIES
DEFAULT_CHECKS = evidence.DEFAULT_CHECKS
DEFAULT_HANDOFFS = evidence.DEFAULT_HANDOFFS


CONFIG = {
    'factories': None,
    'checks': None,
    'handoffs': None,
    'contracts': None,
}


def _as_text_tuple(value):
    return evidence._as_text_list(value)


def set_resource_config(factories=None, checks=None, handoffs=None, contracts=None):
    """Update the default configuration used by the Flake8 entry point.

    ``None`` leaves a setting untouched.  The helper mirrors the module-level
    convention used by other Dlint extensions and is only a convenience for
    callers; explicit constructor arguments always take precedence.
    """

    if factories is not None:
        CONFIG['factories'] = _as_text_tuple(factories)
    if checks is not None:
        CONFIG['checks'] = _as_text_tuple(checks)
    if handoffs is not None:
        CONFIG['handoffs'] = _as_text_tuple(handoffs)
    if contracts is not None:
        CONFIG['contracts'] = contracts


def analyze_temporary_resources(node, **kwargs):
    """Run the source-only evidence analysis without a Flake8 linter."""

    return evidence.collect_evidence(node, **kwargs)


def collect_temporary_resource_evidence(node, **kwargs):
    return analyze_temporary_resources(node, **kwargs)


def analyze_resource_branches(node, **kwargs):
    return analyze_temporary_resources(node, **kwargs)


class BadTemporaryResourceUseLinter(base.BaseLinter):
    """Report branches that return before a temporary resource check.

    The default API names cover common temporary-file factories and release
    helpers.  A project can replace them by subclassing:

        class ProjectTempLinter(BadTemporaryResourceUseLinter):
            factories = ('project.acquire_temp',)
            checks = ('project.security_check', 'project.release_temp')
            contracts = {'project.security_check': 'bool'}

    or by passing constructor keyword arguments.  ``checks`` are the ONLY
    calls treated as completed checks unless a same-file convention (a
    decorated stub or a declaration such as ``SECURITY_CHECKS = (...)``)
    adds another one.  A call that receives a pending resource but has no
    recognised contract is reported as ``contract_unknown`` rather than being
    silently treated as safe.
    """

    off_by_default = False

    _code = 'DUO139'
    _error_tmpl = (
        'DUO139 temporary resource security check not completed before return'
    )
    _exception_error_tmpl = (
        'DUO139 temporary resource security check not completed before '
        'exception exit'
    )
    _unknown_error_tmpl = (
        'DUO139 temporary resource security check contract unknown at branch '
        'exit'
    )
    _legacy_error_tmpl = (
        'DUO121 temporary resource security check not completed before return'
    )
    _legacy_exception_error_tmpl = (
        'DUO121 temporary resource security check not completed before '
        'exception exit'
    )
    _legacy_unknown_error_tmpl = (
        'DUO121 temporary resource security check contract unknown at branch '
        'exit'
    )
    _exception_tmpl = _exception_error_tmpl
    _unknown_tmpl = _unknown_error_tmpl
    _uncertain_tmpl = _unknown_error_tmpl

    factories = DEFAULT_FACTORIES
    checks = DEFAULT_CHECKS
    handoffs = DEFAULT_HANDOFFS
    contracts = {}
    placeholders = ()
    conventions = ()
    track_parameters = True
    report_unknown = True
    max_paths = 64
    max_loop_iterations = 2
    original_codes = {}
    preserve_original_code = True

    def __init__(
        self,
        factories=None,
        checks=None,
        handoffs=None,
        contracts=None,
        placeholders=None,
        conventions=None,
        apis=None,
        track_parameters=None,
        report_unknown=None,
        max_paths=None,
        original_code=None,
        original_codes=None,
        preserve_original_code=None,
        config=None,
        rule_config=None,
        *args,
        **kwargs
    ):
        super(BadTemporaryResourceUseLinter, self).__init__(*args, **kwargs)

        self._configured = {}
        self._findings = []
        self._evidence = []
        self._analyzed = False
        self._analyzed_node = None
        self.config = config
        self.rule_config = rule_config

        for mapping in (config, rule_config):
            if mapping:
                for key, value in mapping.items():
                    self._set_api(key, value)
        if apis:
            for key, value in apis.items():
                self._set_api(key, value)
        if factories is not None:
            self._set_api('factories', factories)
        if checks is not None:
            self._set_api('checks', checks)
        if handoffs is not None:
            self._set_api('handoffs', handoffs)
        if contracts is not None:
            self._set_api('contracts', contracts)
        if placeholders is not None:
            self.placeholders = (
                dict(placeholders) if isinstance(placeholders, dict)
                else _as_text_tuple(placeholders)
            )
        if conventions is not None:
            self.conventions = (
                dict(conventions) if isinstance(conventions, dict)
                else _as_text_tuple(conventions)
            )
        if track_parameters is not None:
            self.track_parameters = bool(track_parameters)
        if report_unknown is not None:
            self.report_unknown = bool(report_unknown)
        if max_paths is not None:
            self.max_paths = int(max_paths)
        if original_codes is not None:
            self.original_codes = dict(original_codes)
        if original_code is not None:
            self.original_codes = dict(self.original_codes)
            self.original_codes['*'] = original_code
        if preserve_original_code is not None:
            self.preserve_original_code = bool(preserve_original_code)
        if self.preserve_original_code:
            self.original_codes = dict(self.original_codes)
            self.original_codes.setdefault('mktemp', 'DUO121')
            self.original_codes.setdefault('tempfile.mktemp', 'DUO121')
            self.original_codes.setdefault('tempnam', 'DUO106')
            self.original_codes.setdefault('os.tempnam', 'DUO106')
            self.original_codes.setdefault('tmpnam', 'DUO106')
            self.original_codes.setdefault('os.tmpnam', 'DUO106')

    def _set_api(self, kind, value):
        aliases = {
            'factory': 'factories',
            'factory_functions': 'factories',
            'resource_factories': 'factories',
            'acquire': 'factories',
            'acquisition': 'factories',
            'acquisition_apis': 'factories',
            'acquire_apis': 'factories',
            'temporary_resources': 'factories',
            'check': 'checks',
            'check_functions': 'checks',
            'check_apis': 'checks',
            'security_checks': 'checks',
            'security_check': 'checks',
            'cleanup': 'checks',
            'cleanup_apis': 'checks',
            'cleanup_functions': 'checks',
            'release': 'checks',
            'release_apis': 'checks',
            'release_functions': 'checks',
            'validators': 'checks',
            'guards': 'checks',
            'handoff': 'handoffs',
            'handoff_apis': 'handoffs',
            'transfer_apis': 'handoffs',
            'contract': 'contracts',
            'check_contracts': 'contracts',
            'conventions': 'conventions',
            'declarations': 'conventions',
            'placeholders': 'placeholders',
            'placeholder_functions': 'placeholders',
            'stubs': 'placeholders',
            'original_code': 'original_code',
            'alert_code': 'original_code',
            'original_alert_code': 'original_code',
            'original_codes': 'original_codes',
            'alert_codes': 'original_codes',
        }
        kind = aliases.get(kind, kind)
        if kind == 'contracts':
            self._configured[kind] = value
        elif kind in ('factories', 'checks', 'handoffs'):
            if kind == 'checks' and isinstance(value, dict):
                self._configured[kind] = tuple(str(name) for name in value)
                contracts = dict(self._configured.get('contracts') or {})
                contracts.update(evidence._contracts(value))
                self._configured['contracts'] = contracts
            else:
                self._configured[kind] = _as_text_tuple(value)
        elif kind in ('placeholders', 'conventions'):
            setattr(
                self,
                kind,
                dict(value) if isinstance(value, dict) else _as_text_tuple(value),
            )
        elif kind == 'original_code':
            self.original_codes = dict(self.original_codes)
            self.original_codes['*'] = value
        elif kind == 'original_codes':
            self.original_codes = dict(value)
        else:
            raise ValueError('unknown temporary resource API kind: {}'.format(kind))

    def _config_value(self, kind):
        if kind in self._configured:
            return self._configured[kind]
        if CONFIG.get(kind) is not None:
            return CONFIG[kind]
        for mapping in (getattr(self, 'config', None), getattr(self, 'rule_config', None)):
            if isinstance(mapping, dict) and kind in mapping:
                return mapping[kind]
        aliases = {
            'factories': (
                'factory_functions',
                'resource_factories',
                'acquisition_apis',
                'acquire_apis',
            ),
            'checks': (
                'check_functions',
                'check_apis',
                'security_checks',
                'cleanup_apis',
                'cleanup_functions',
                'release_apis',
                'release_functions',
            ),
            'handoffs': ('handoff_apis', 'handoff_functions', 'transfer_apis'),
        }
        for attribute in aliases.get(kind, ()):
            if hasattr(type(self), attribute) or attribute in self.__dict__:
                return getattr(self, attribute)
        return getattr(self, kind)

    def analysis_config(self):
        return evidence.AnalysisConfig(
            factories=self._config_value('factories'),
            checks=self._config_value('checks'),
            handoffs=self._config_value('handoffs'),
            contracts=self._config_value('contracts'),
            placeholders=self.placeholders,
            conventions=self.conventions,
            track_parameters=self.track_parameters,
            report_unknown=self.report_unknown,
            max_paths=self.max_paths,
            max_loop_iterations=self.max_loop_iterations,
        )

    def visit_Module(self, node):
        self._analyze(node)

    def visit(self, node):
        # BaseLinter expects a module for namespace initialization.  Allow a
        # caller to hand us a single parsed function directly as well.
        if isinstance(node, evidence._FUNCTION_DEF_TYPES):
            self._analyze(evidence.make_module([node]))
            return
        super(BadTemporaryResourceUseLinter, self).visit(node)

    def _analyze(self, node):
        if self._analyzed and self._analyzed_node is node:
            return
        if self._analyzed_node is not node:
            self._findings = []
            self._evidence = []
            self.results = []
        self._analyzed = True
        self._analyzed_node = node
        config = self.analysis_config()
        for function_evidence in evidence.collect_evidence(node, config):
            self._evidence.append(function_evidence)
            for exit_evidence in function_evidence.problems:
                if (
                    exit_evidence.status == evidence.CONTRACT_UNKNOWN
                    and not self.report_unknown
                ):
                    continue
                self._findings.append(self._finding(function_evidence, exit_evidence))

        self._findings.sort(key=lambda item: (
            item.lineno, item.col_offset, item.status, item.resource or ''))
        self.results = [
            base.Flake8Result(
                lineno=finding.lineno,
                col_offset=finding.col_offset,
                message=finding.message,
            )
            for finding in self._findings
        ]

    def _finding(self, function_evidence, exit_evidence):
        original_code = self._original_code(exit_evidence.factory)
        if exit_evidence.status == evidence.CONTRACT_UNKNOWN:
            message = (
                self._legacy_unknown_error_tmpl if original_code
                else self._unknown_error_tmpl
            )
        elif exit_evidence.status == evidence.UNCHECKED_EXCEPTION:
            message = (
                self._legacy_exception_error_tmpl if original_code
                else self._exception_error_tmpl
            )
        else:
            message = (
                self._legacy_error_tmpl if original_code
                else self._error_tmpl
            )
        if original_code:
            message = message.replace('DUO121', original_code, 1)
        return evidence.Finding(
            exit_evidence.lineno,
            exit_evidence.col_offset,
            message,
            exit_evidence.status,
            exit_evidence.kind,
            exit_evidence.resource,
            exit_evidence.path_text,
        )

    def _original_code(self, factory):
        if not self.original_codes:
            return None
        for candidate in (factory, (factory or '').split('.')[-1], '*', None):
            if candidate in self.original_codes:
                return self.original_codes[candidate]
        return None

    def get_findings(self):
        """Return structured findings, including branch status and evidence."""

        return list(self._findings)

    @property
    def findings(self):
        return self.get_findings()

    def get_evidence(self):
        """Return the per-function branch evidence used by the diagnostics."""

        return list(self._evidence)

    @property
    def evidence(self):
        return self.get_evidence()

    def analyze(self, node=None):
        """Explicit alias for callers that prefer a verb to ``visit``."""

        if node is not None:
            if isinstance(node, str):
                node = ast.parse(node)
            self.visit(node)
        return self.get_evidence()


# Stable aliases used by different project conventions.  They intentionally
# refer to the same class object so registering the rule once does not produce
# duplicate Flake8 results.
BadTempResourceUseLinter = BadTemporaryResourceUseLinter
BadResourceCleanupUseLinter = BadTemporaryResourceUseLinter
BadTempfileCleanupUseLinter = BadTemporaryResourceUseLinter
BadTemporaryResourceCheckLinter = BadTemporaryResourceUseLinter
BadTemporaryResourceCleanupLinter = BadTemporaryResourceUseLinter
BadTemporaryResourceSafetyLinter = BadTemporaryResourceUseLinter
BadTemporaryResourceBranchUseLinter = BadTemporaryResourceUseLinter
BadTempResourceCheckLinter = BadTemporaryResourceUseLinter
BadTempResourceCleanupLinter = BadTemporaryResourceUseLinter
BadResourceLifecycleUseLinter = BadTemporaryResourceUseLinter
BadResourceBranchUseLinter = BadTemporaryResourceUseLinter
BadSecurityCheckUseLinter = BadTemporaryResourceUseLinter
TemporaryResourceCheckLinter = BadTemporaryResourceUseLinter
TemporaryResourceCleanupLinter = BadTemporaryResourceUseLinter
TemporaryResourceSafetyLinter = BadTemporaryResourceUseLinter
TemporaryResourceBranchLinter = BadTemporaryResourceUseLinter
TempResourceCheckLinter = BadTemporaryResourceUseLinter
TempResourceCleanupLinter = BadTemporaryResourceUseLinter
TempResourceLifecycleLinter = BadTemporaryResourceUseLinter
ResourceCleanupLinter = BadTemporaryResourceUseLinter
ResourceLifecycleLinter = BadTemporaryResourceUseLinter
ResourceSafetyCheckLinter = BadTemporaryResourceUseLinter
ResourceCheckLinter = BadTemporaryResourceUseLinter
ResourceBranchLinter = BadTemporaryResourceUseLinter
SecurityCheckBranchLinter = BadTemporaryResourceUseLinter
SecurityCheckLinter = BadTemporaryResourceUseLinter
TempResourceBranchLinter = BadTemporaryResourceUseLinter
BranchCleanupLinter = BadTemporaryResourceUseLinter
BranchEvidenceLinter = BadTemporaryResourceUseLinter
BadTempfileResourceUseLinter = BadTemporaryResourceUseLinter
BadTemporaryFileUseLinter = BadTemporaryResourceUseLinter
BadTemporaryFileCleanupLinter = BadTemporaryResourceUseLinter
BadTempResourceBranchUseLinter = BadTemporaryResourceUseLinter
TemporaryFileUseLinter = BadTemporaryResourceUseLinter
TemporaryFileCleanupLinter = BadTemporaryResourceUseLinter
TemporaryFileBranchLinter = BadTemporaryResourceUseLinter
TempResourceSafetyLinter = BadTemporaryResourceUseLinter
TempfileCheckLinter = BadTemporaryResourceUseLinter
TempfileCleanupLinter = BadTemporaryResourceUseLinter
TempfileBranchLinter = BadTemporaryResourceUseLinter


class BadTempfileBranchUseLinter(BadTemporaryResourceUseLinter):
    """Branch evidence that deliberately keeps the legacy DUO121 alert."""

    _code = 'DUO121'
    _error_tmpl = BadTemporaryResourceUseLinter._legacy_error_tmpl
    _exception_error_tmpl = BadTemporaryResourceUseLinter._legacy_exception_error_tmpl
    _unknown_error_tmpl = BadTemporaryResourceUseLinter._legacy_unknown_error_tmpl
    original_codes = {'*': 'DUO121'}


__all__ = [
    'BadTemporaryResourceUseLinter',
    'BadTempResourceUseLinter',
    'BadResourceCleanupUseLinter',
    'BadTempfileCleanupUseLinter',
    'BadTemporaryResourceCheckLinter',
    'BadTemporaryResourceCleanupLinter',
    'BadTemporaryResourceSafetyLinter',
    'BadTemporaryResourceBranchUseLinter',
    'BadTempResourceCheckLinter',
    'BadTempResourceCleanupLinter',
    'BadResourceLifecycleUseLinter',
    'BadResourceBranchUseLinter',
    'BadSecurityCheckUseLinter',
    'TemporaryResourceCheckLinter',
    'TemporaryResourceCleanupLinter',
    'TemporaryResourceSafetyLinter',
    'TemporaryResourceBranchLinter',
    'TempResourceCheckLinter',
    'TempResourceCleanupLinter',
    'TempResourceLifecycleLinter',
    'ResourceCleanupLinter',
    'ResourceLifecycleLinter',
    'ResourceSafetyCheckLinter',
    'ResourceCheckLinter',
    'ResourceBranchLinter',
    'SecurityCheckBranchLinter',
    'SecurityCheckLinter',
    'TempResourceBranchLinter',
    'BranchCleanupLinter',
    'BranchEvidenceLinter',
    'BadTempfileBranchUseLinter',
    'BadTempfileResourceUseLinter',
    'BadTemporaryFileUseLinter',
    'BadTemporaryFileCleanupLinter',
    'BadTempResourceBranchUseLinter',
    'TemporaryFileUseLinter',
    'TemporaryFileCleanupLinter',
    'TemporaryFileBranchLinter',
    'TempResourceSafetyLinter',
    'TempfileCheckLinter',
    'TempfileCleanupLinter',
    'TempfileBranchLinter',
    'set_resource_config',
    'analyze_temporary_resources',
    'collect_temporary_resource_evidence',
    'analyze_resource_branches',
]
