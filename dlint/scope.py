#!/usr/bin/env python

"""Audit which parts of a Dlint report apply to a target Python version.

The important distinction made by this module is between:

* ``syntax_unsupported`` - the target interpreter cannot parse the source.
* ``rule_not_enabled`` - the source could be parsed, but the rule was not
  selected for this run.
* ``rule_not_applicable`` - the rule is selected but its documented Python
  version range excludes the target, so it was skipped by the environment.
* ``no_findings`` - the rule was enabled, applicable, actually ran, and
  produced no warning.
* ``missing_source`` - a report item could not be tied to a supplied source.
* ``eligible`` - a report item is reproducible/applicable for the target
  version and can be signed off by that maintenance group.

The audit is deliberately per-version.  It never intersects the eligible
report items of two versions unless the caller explicitly asks for the
intersection with :meth:`ScopeAudit.common_eligible`.
"""

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import ast
import collections
import io
import json
import os
import re
import sys
import textwrap
import tokenize
import warnings


try:
    _STRING_TYPES = (basestring,)  # noqa: F821
except NameError:
    _STRING_TYPES = (str, bytes)


ELIGIBLE = 'eligible'
SYNTAX_UNSUPPORTED = 'syntax_unsupported'
RULE_NOT_ENABLED = 'rule_not_enabled'
RULE_NOT_APPLICABLE = 'rule_not_applicable'
NO_FINDINGS = 'no_findings'
MISSING_SOURCE = 'missing_source'

# Kept as aliases because integrations have historically used slightly
# different names for the same status.
STATUS_ELIGIBLE = ELIGIBLE
STATUS_SYNTAX_UNSUPPORTED = SYNTAX_UNSUPPORTED
STATUS_RULE_NOT_ENABLED = RULE_NOT_ENABLED
STATUS_RULE_NOT_APPLICABLE = RULE_NOT_APPLICABLE
STATUS_NO_FINDINGS = NO_FINDINGS
STATUS_MISSING_SOURCE = MISSING_SOURCE

STATUSES = (
    ELIGIBLE,
    SYNTAX_UNSUPPORTED,
    RULE_NOT_ENABLED,
    RULE_NOT_APPLICABLE,
    NO_FINDINGS,
)
SKIPPED_STATUSES = (
    SYNTAX_UNSUPPORTED,
    RULE_NOT_ENABLED,
    RULE_NOT_APPLICABLE,
    MISSING_SOURCE,
)
ALL_STATUSES = STATUSES + (MISSING_SOURCE,)

class AuditStatus(object):
    ELIGIBLE = ELIGIBLE
    SYNTAX_UNSUPPORTED = SYNTAX_UNSUPPORTED
    RULE_NOT_ENABLED = RULE_NOT_ENABLED
    RULE_NOT_APPLICABLE = RULE_NOT_APPLICABLE
    NO_FINDINGS = NO_FINDINGS
    MISSING_SOURCE = MISSING_SOURCE


Status = AuditStatus
ScopeStatus = AuditStatus

STATUS_ALIASES = {
    'eligible': ELIGIBLE,
    'signable': ELIGIBLE,
    'sign_off': ELIGIBLE,
    'qualified': ELIGIBLE,
    'accepted': ELIGIBLE,
    'syntax': SYNTAX_UNSUPPORTED,
    'syntax_error': SYNTAX_UNSUPPORTED,
    'syntax_unsupported': SYNTAX_UNSUPPORTED,
    'syntax_not_supported': SYNTAX_UNSUPPORTED,
    'not_supported': SYNTAX_UNSUPPORTED,
    'unsupported_syntax': SYNTAX_UNSUPPORTED,
    'rule_disabled': RULE_NOT_ENABLED,
    'rule_not_enabled': RULE_NOT_ENABLED,
    'not_enabled': RULE_NOT_ENABLED,
    'rule_off': RULE_NOT_ENABLED,
    'disabled': RULE_NOT_ENABLED,
    'not_applicable': RULE_NOT_APPLICABLE,
    'rule_not_applicable': RULE_NOT_APPLICABLE,
    'inapplicable': RULE_NOT_APPLICABLE,
    'rule_inapplicable': RULE_NOT_APPLICABLE,
    'version_not_applicable': RULE_NOT_APPLICABLE,
    'version_skipped': RULE_NOT_APPLICABLE,
    'clean': NO_FINDINGS,
    'no_finding': NO_FINDINGS,
    'no_findings': NO_FINDINGS,
    'nothing_found': NO_FINDINGS,
    'missing_source': MISSING_SOURCE,
}

SUPPORTED_PYTHON_VERSIONS = (
    '2.7', '3.5', '3.6', '3.7', '3.8', '3.9', '3.10', '3.11', '3.12',
)

# Rules whose applicability is explicitly bounded in the Dlint documentation.
# The upper bound is exclusive.
RULE_VERSION_RANGES = {
    'DUO101': (None, (3, 3)),
    'DUO108': (None, (3, 0)),
}

_DUO_CODE_RE = re.compile(r'\b(DUO[\s_-]*\d{3})\b', re.IGNORECASE)
_VERSION_RE = re.compile(
    r'^\s*(?:c?python|py|cp)?[\s_-]*(\d+)'
    r'(?:[._-](\d+))?(?:[._-]\d+)?\s*$',
    re.IGNORECASE,
)
_COMPACT_VERSION_RE = re.compile(
    r'^\s*(?:python|py|cpython|cp|python3)?[\s_-]*([23])(\d)\s*$',
    re.IGNORECASE,
)
_SOURCE_RE = re.compile(
    r'^(?P<filename>.+?):(?P<lineno>\d+)'
    r'(?::(?P<col_offset>\d+))?:\s*(?P<rest>.*)$'
)


def normalize_status(status):
    """Return the canonical status string for ``status``."""
    if status is None:
        return None
    key = str(status).strip().lower().replace('-', '_')
    return STATUS_ALIASES.get(key, key)


def _validate_version_major(major, minor):
    if not (2 <= major <= 4) or minor < 0 or minor > 99:
        raise ValueError(
            'unrecognized Python version: {}.{}'.format(major, minor)
        )
    return (major, minor)


def normalize_version(version):
    """Normalize a version to a ``(major, minor)`` tuple.

    Accepted forms include ``2.7``, ``"3.8"``, ``"py38"``, ``"python 3.8"``,
    ``38`` and ``(3, 8)``.
    """
    if isinstance(version, PythonVersion):
        return version.as_tuple()

    if isinstance(version, (tuple, list)):
        if not version:
            raise ValueError('empty version')
        major = int(version[0])
        minor = int(version[1]) if len(version) > 1 else 0
        return (major, minor)

    if isinstance(version, int):
        value = str(version)
        if len(value) == 1:
            return (int(value), 0)
        return (int(value[0]), int(value[1:]))

    if isinstance(version, bytes):
        version = version.decode('ascii')

    text = str(version)
    compact_match = _COMPACT_VERSION_RE.match(text)
    if compact_match:
        return (int(compact_match.group(1)), int(compact_match.group(2)))

    match = _VERSION_RE.match(text)
    if not match:
        raise ValueError('unrecognized Python version: {!r}'.format(version))

    major = int(match.group(1))
    minor = int(match.group(2) or 0)
    return (major, minor)


def parse_version(version):
    """Alias for :func:`normalize_version`."""
    return normalize_version(version)


def supported_versions():
    return SUPPORTED_PYTHON_VERSIONS


def version_string(version):
    """Return a display string for a normalized version."""
    major, minor = normalize_version(version)
    return '{}.{}'.format(major, minor)


class PythonVersion(object):
    """Small immutable version wrapper used by callers that prefer objects."""

    __slots__ = ('major', 'minor')

    def __init__(self, version=None, minor=None):
        if minor is not None:
            version = (version, minor)
        self.major, self.minor = normalize_version(version)

    @classmethod
    def parse(cls, value):
        return cls(value)

    from_string = parse

    def as_tuple(self):
        return (self.major, self.minor)

    @property
    def tuple(self):
        return self.as_tuple()

    def to_dict(self):
        return {
            'version': self.version,
            'major': self.major,
            'minor': self.minor,
        }

    @property
    def version(self):
        return version_string(self.as_tuple())

    def __str__(self):
        return self.version

    def __repr__(self):
        return 'PythonVersion({!r})'.format(self.version)

    def __eq__(self, other):
        try:
            return self.as_tuple() == normalize_version(other)
        except (TypeError, ValueError):
            return False

    def __ne__(self, other):
        return not self == other

    def __lt__(self, other):
        return self.as_tuple() < normalize_version(other)

    def __le__(self, other):
        return self.as_tuple() <= normalize_version(other)

    def __gt__(self, other):
        return self.as_tuple() > normalize_version(other)

    def __ge__(self, other):
        return self.as_tuple() >= normalize_version(other)

    def __hash__(self):
        return hash(self.as_tuple())


class SyntaxResult(object):
    """Result of parsing one source fragment for one target version."""

    def __init__(
            self,
            version,
            supported,
            tree=None,
            error=None,
            message=None,
            lineno=None,
            offset=None,
            text=None,
            reason=None,
            filename=None):
        self.filename = filename
        self.version = version_string(version)
        self.version_tuple = normalize_version(version)
        self.target_version = self.version
        self.python_version = self.version_tuple
        self.supported = bool(supported)
        self.tree = tree
        self.error = error
        self.message = message
        self.lineno = lineno
        self.offset = offset
        self.text = text
        self.reason = reason

    @property
    def syntax_supported(self):
        return self.supported

    @property
    def syntax_error(self):
        if self.supported:
            return None
        return {
            'type': type(self.error).__name__ if self.error else 'SyntaxError',
            'message': self.message,
            'lineno': self.lineno,
            'offset': self.offset,
            'text': self.text,
        }

    def to_dict(self):
        return {
            'filename': self.filename,
            'version': self.version,
            'supported': self.supported,
            'syntax_supported': self.supported,
            'syntax_error': self.syntax_error,
            'reason': self.reason,
        }

    def __bool__(self):
        return self.supported

    __nonzero__ = __bool__

    def __eq__(self, other):
        if isinstance(other, bool):
            return self.supported == other
        if isinstance(other, SyntaxResult):
            return (
                self.version_tuple == other.version_tuple
                and self.supported == other.supported
                and self.message == other.message
            )
        return NotImplemented

    def __ne__(self, other):
        result = self == other
        if result is NotImplemented:
            return result
        return not result

    def __getitem__(self, key):
        return self.to_dict()[key]

    def get(self, key, default=None):
        return self.to_dict().get(key, default)


class ReportItem(object):
    """Normalized representation of one item in a Dlint/flake8 report."""

    __slots__ = (
        'filename',
        'lineno',
        'col_offset',
        'code',
        'message',
        'scope',
        'source',
        'raw',
    )

    def __init__(
            self,
            filename=None,
            lineno=None,
            col_offset=None,
            code=None,
            message=None,
            scope=None,
            source=None,
            raw=None):
        if filename is not None and not isinstance(filename, _STRING_TYPES):
            filename = str(filename)
        if scope is not None and not isinstance(scope, (str, bytes, int)):
            scope = str(scope)
        if filename is not None and not isinstance(filename, _STRING_TYPES):
            filename = str(filename)
        self.filename = filename
        self.lineno = _optional_int(lineno)
        self.col_offset = _optional_int(col_offset)
        self.code = normalize_rule_code(code)
        self.message = _to_text(message) if message is not None else None
        if self.code is None and self.message is not None:
            match = _DUO_CODE_RE.search(str(self.message))
            if match is not None:
                self.code = normalize_rule_code(match.group(1))
        if self.code is None and message is not None:
            match = _DUO_CODE_RE.search(str(message))
            if match is not None:
                self.code = normalize_rule_code(match.group(1))
        self.scope = scope
        self.source = source
        self.raw = raw

    @property
    def location(self):
        return (self.lineno, self.col_offset)

    @property
    def key(self):
        return (
            self.scope if self.scope is not None else self.filename,
            self.code,
            self.lineno,
            self.col_offset,
        )

    def __getitem__(self, key):
        return self.to_dict()[key]

    def get(self, key, default=None):
        return self.to_dict().get(key, default)

    def __eq__(self, other):
        if isinstance(other, ReportItem):
            return self.to_dict() == other.to_dict()
        if self.raw is not None:
            return self.raw == other
        return NotImplemented

    def __ne__(self, other):
        result = self == other
        if result is NotImplemented:
            return result
        return not result

    def to_dict(self):
        return {
            'filename': self.filename,
            'scope': self.scope,
            'lineno': self.lineno,
            'col_offset': self.col_offset,
            'code': self.code,
            'message': self.message,
        }


class ReportItems(list):
    """List of report items that can also be queried per version."""

    def __init__(self, items=(), audit=None):
        list.__init__(self, items)
        self.audit = audit

    def __call__(self, version=None, status=None):
        if self.audit is None:
            return list(self)
        return self.audit._report_items_for(version=version, status=status)


class SourceScope(object):
    """A source fragment/file that is audited independently."""

    __slots__ = ('scope', 'source', 'filename', 'metadata')

    def __init__(self, scope, source, filename=None, metadata=None):
        if scope is not None and not isinstance(scope, (str, bytes, int, float)):
            scope = str(scope)
        self.scope = scope
        self.source = (
            _maybe_read_source(source) if source is not None else None
        )
        self.filename = filename or scope
        if self.filename is not None and not isinstance(
                self.filename, _STRING_TYPES):
            self.filename = str(self.filename)
        self.metadata = metadata or {}

    @property
    def text(self):
        return self.source

    @property
    def code(self):
        return self.source

    def __str__(self):
        return self.source if self.source is not None else ''

    def to_dict(self):
        return {
            'scope': self.scope,
            'filename': self.filename,
            'metadata': self.metadata,
        }

    def __getitem__(self, key):
        if key in ('source', 'text', 'code'):
            return self.source
        return self.to_dict()[key]

    def get(self, key, default=None):
        if key == 'source':
            return self.source
        return self.to_dict().get(key, default)

    def __eq__(self, other):
        if isinstance(other, _STRING_TYPES):
            return self.source == _to_text(other)
        if isinstance(other, SourceScope):
            return (
                self.scope == other.scope
                and self.filename == other.filename
                and self.source == other.source
            )
        return NotImplemented

    def __ne__(self, other):
        result = self == other
        if result is NotImplemented:
            return result
        return not result


class AuditEntry(object):
    """One per-version status entry."""

    __slots__ = (
        'version',
        'scope',
        'filename',
        'code',
        'status',
        'reason',
        'lineno',
        'col_offset',
        'message',
        'item',
        'syntax_error',
        'applicable',
        'enabled',
        'reproduced',
    )

    def __init__(
            self,
            version,
            scope,
            status,
            code=None,
            reason=None,
            filename=None,
            lineno=None,
            col_offset=None,
            message=None,
            item=None,
            syntax_error=None,
            applicable=True,
            enabled=True,
            reproduced=None):
        self.version = version_string(version)
        self.scope = scope
        self.filename = filename or scope
        self.code = code
        self.status = normalize_status(status)
        self.reason = reason
        self.lineno = lineno
        self.col_offset = col_offset
        self.message = message
        self.item = item
        self.syntax_error = syntax_error
        self.applicable = applicable
        self.enabled = enabled
        self.reproduced = reproduced

    @property
    def eligible(self):
        return self.status == ELIGIBLE

    @property
    def signable(self):
        return self.eligible

    @property
    def skipped(self):
        return self.status in SKIPPED_STATUSES

    @property
    def checkable(self):
        return (
            self.status in (ELIGIBLE, NO_FINDINGS)
            and self.enabled
            and self.applicable
        )

    @property
    def report_item(self):
        return self.item

    @property
    def finding(self):
        return self.item

    @property
    def raw_item(self):
        if self.item is None:
            return None
        return self.item.raw

    @property
    def location(self):
        return (self.lineno, self.col_offset)

    @property
    def classification(self):
        return self.status

    @property
    def category(self):
        return self.status

    @property
    def kind(self):
        return self.status

    @property
    def key(self):
        return (self.scope, self.code, self.lineno, self.col_offset)

    def __getitem__(self, key):
        return self.to_dict()[key]

    def get(self, key, default=None):
        return self.to_dict().get(key, default)

    def to_dict(self):
        result = {
            'version': self.version,
            'scope': self.scope,
            'filename': self.filename,
            'code': self.code,
            'status': self.status,
            'classification': self.status,
            'category': self.status,
            'reason': self.reason,
            'lineno': self.lineno,
            'col_offset': self.col_offset,
            'message': self.message,
            'eligible': self.eligible,
            'signable': self.signable,
            'skipped': self.skipped,
            'checkable': self.checkable,
            'applicable': self.applicable,
            'enabled': self.enabled,
        }
        if self.syntax_error is not None:
            result['syntax_error'] = self.syntax_error
        if self.reproduced is not None:
            result['reproduced'] = self.reproduced
        return result


class RuleResult(object):
    """Status of one rule within one source scope."""

    def __init__(self, code, enabled, applicable, status, reason=None):
        self.code = code
        self.enabled = enabled
        self.applicable = applicable
        self.status = normalize_status(status)
        self.reason = reason
        self.report_items = []
        self.eligible_items = []

    @property
    def checkable(self):
        return (
            self.enabled
            and self.applicable
            and self.status != SYNTAX_UNSUPPORTED
            and self.status != RULE_NOT_ENABLED
        )

    @property
    def eligible(self):
        return self.status == ELIGIBLE

    @property
    def signable(self):
        return self.eligible

    @property
    def skipped(self):
        return self.status in SKIPPED_STATUSES

    def __getitem__(self, key):
        return self.to_dict()[key]

    def get(self, key, default=None):
        return self.to_dict().get(key, default)

    def to_dict(self):
        return {
            'code': self.code,
            'enabled': self.enabled,
            'applicable': self.applicable,
            'checkable': self.checkable,
            'eligible': self.eligible,
            'signable': self.signable,
            'skipped': self.skipped,
            'status': self.status,
            'reason': self.reason,
            'report_item_count': len(self.report_items),
            'eligible_item_count': len(self.eligible_items),
            'report_items': [
                item.to_dict() for item in self.report_items
            ],
            'eligible_items': [
                item.to_dict() for item in self.eligible_items
            ],
        }


class RuleCodes(list):
    """A list of rule codes that also supports lookup by code."""

    def __init__(self, codes=(), results=None):
        list.__init__(self, codes)
        self._results = results or collections.OrderedDict()

    def __getitem__(self, key):
        if isinstance(key, int):
            return list.__getitem__(self, key)
        return self._results[key]

    def keys(self):
        return list(self)

    def values(self):
        return [self._results[code] for code in self]

    def items(self):
        return [(code, self._results[code]) for code in self]

    def get(self, code, default=None):
        return self._results.get(code, default)


class ScopeResult(object):
    """Parsing and rule status for one source scope in one version."""

    def __init__(self, scope, source_result):
        self.scope = scope
        self.syntax = source_result
        self.rules = collections.OrderedDict()
        self.report_items = []
        self.entries = []

    @property
    def scope_id(self):
        return self.scope.scope

    @property
    def filename(self):
        return self.scope.filename

    @property
    def source(self):
        return self.scope.source

    @property
    def syntax_supported(self):
        return self.syntax.supported

    @property
    def syntax_error(self):
        return self.syntax.syntax_error

    @property
    def skipped(self):
        return self.status in SKIPPED_STATUSES

    @property
    def eligible_items(self):
        return [
            entry for entry in self.entries
            if entry.status == ELIGIBLE
        ]

    @property
    def rule_not_applicable(self):
        return [
            entry for entry in self.entries
            if entry.status == RULE_NOT_APPLICABLE
        ]

    @property
    def not_applicable(self):
        return self.rule_not_applicable

    @property
    def syntax_unsupported(self):
        return [
            entry for entry in self.entries
            if entry.status == SYNTAX_UNSUPPORTED
        ]

    @property
    def rule_not_enabled(self):
        return [
            entry for entry in self.entries
            if entry.status == RULE_NOT_ENABLED
        ]

    @property
    def no_findings(self):
        return [
            entry for entry in self.entries
            if entry.status == NO_FINDINGS
        ]

    eligible = eligible_items
    signable_items = eligible_items

    @property
    def status(self):
        if not self.syntax_supported:
            if self.syntax.reason == 'missing_source':
                return MISSING_SOURCE
            return SYNTAX_UNSUPPORTED
        statuses = [entry.status for entry in self.entries]
        if ELIGIBLE in statuses:
            return ELIGIBLE
        if RULE_NOT_ENABLED in statuses:
            return RULE_NOT_ENABLED
        if RULE_NOT_APPLICABLE in statuses:
            return RULE_NOT_APPLICABLE
        return NO_FINDINGS

    @property
    def checkable(self):
        return self.can_check()

    def can_check(self, code=None):
        if not self.syntax_supported:
            return False
        if code is None:
            return True
        rule = self.rules.get(normalize_rule_code(code))
        return bool(rule is not None and rule.checkable)

    def __getitem__(self, key):
        return self.to_dict()[key]

    def get(self, key, default=None):
        return self.to_dict().get(key, default)

    def to_dict(self):
        return {
            'scope': self.scope.scope,
            'filename': self.filename,
            'status': self.status,
            'skipped': self.skipped,
            'checkable': self.checkable,
            'syntax_supported': self.syntax_supported,
            'syntax_error': self.syntax_error,
            'rules': collections.OrderedDict(
                (code, rule.to_dict())
                for code, rule in self.rules.items()
            ),
            'report_items': [item.to_dict() for item in self.report_items],
            'entries': [entry.to_dict() for entry in self.entries],
            'rule_not_applicable': [
                entry.to_dict() for entry in self.rule_not_applicable
            ],
            'eligible_items': [
                entry.to_dict() for entry in self.eligible_items
            ],
            'eligible_item_count': len(self.eligible_items),
        }


class VersionAudit(object):
    """The audit result for one target interpreter version."""

    def __init__(self, version, source_results):
        self.version = version_string(version)
        self.version_tuple = normalize_version(version)
        self.target_version = self.version
        self.python_version = self.version_tuple
        self.source_results = collections.OrderedDict(
            (scope.scope, result)
            for scope, result in source_results
        )
        self.entries = []

    @property
    def results(self):
        return self.source_results

    @property
    def scope_results(self):
        return self.source_results

    @property
    def sources(self):
        return collections.OrderedDict(
            (scope, result.scope)
            for scope, result in self.source_results.items()
        )

    @property
    def scope_ids(self):
        return list(self.source_results)

    def add(self, entry):
        self.entries.append(entry)
        result = self.source_results.get(entry.scope)
        if result is not None:
            result.entries.append(entry)

    def _by_status(self, status):
        status = normalize_status(status)
        return [entry for entry in self.entries if entry.status == status]

    @property
    def eligible(self):
        return self._by_status(ELIGIBLE)

    @property
    def eligible_items(self):
        return self.eligible

    @property
    def signable_items(self):
        return self.eligible

    @property
    def eligible_report_items(self):
        return [
            entry.item for entry in self.eligible
            if entry.item is not None
        ]

    @property
    def signoff_items(self):
        return self.eligible_report_items

    @property
    def signable(self):
        return self.eligible

    @property
    def syntax_unsupported(self):
        return self._by_status(SYNTAX_UNSUPPORTED)

    @property
    def rule_not_enabled(self):
        return self._by_status(RULE_NOT_ENABLED)

    @property
    def rule_not_applicable(self):
        return self._by_status(RULE_NOT_APPLICABLE)

    @property
    def not_applicable(self):
        return self.rule_not_applicable

    @property
    def no_findings(self):
        return self._by_status(NO_FINDINGS)

    @property
    def missing_source(self):
        return self._by_status(MISSING_SOURCE)

    @property
    def rules(self):
        return RuleCodes(self.rules_list, self.rule_results)

    @property
    def rules_list(self):
        codes = []
        for result in self.source_results.values():
            for code in result.rules:
                if code not in codes:
                    codes.append(code)
        return codes

    @property
    def rule_results(self):
        result = collections.OrderedDict()
        for source_result in self.source_results.values():
            for code, rule in source_result.rules.items():
                result.setdefault(code, rule)
        return result

    @property
    def enabled_rules(self):
        return [
            code for code in self.rules
            if any(
                result.rules[code].enabled
                for result in self.source_results.values()
                if code in result.rules
            )
        ]

    @property
    def checked_scopes(self):
        return [
            result for result in self.source_results.values()
            if result.syntax_supported
        ]

    @property
    def syntax_unsupported_scopes(self):
        return [
            result for result in self.source_results.values()
            if not result.syntax_supported
        ]

    @property
    def skipped_scopes(self):
        seen = []
        for entry in self.skipped:
            if entry.scope not in seen:
                seen.append(entry.scope)
        return [
            self.source_results[scope]
            for scope in seen
            if scope in self.source_results
        ]

    @property
    def syntax_unsupported_scope_ids(self):
        return [
            result.scope.scope
            for result in self.syntax_unsupported_scopes
        ]

    @property
    def skipped_scope_ids(self):
        return [
            result.scope.scope
            for result in self.skipped_scopes
        ]

    @property
    def eligible_scope_ids(self):
        return self._scope_ids_for_status(ELIGIBLE)

    @property
    def rule_not_enabled_scope_ids(self):
        return self._scope_ids_for_status(RULE_NOT_ENABLED)

    @property
    def rule_not_applicable_scope_ids(self):
        return self._scope_ids_for_status(RULE_NOT_APPLICABLE)

    @property
    def no_findings_scope_ids(self):
        return self._scope_ids_for_status(NO_FINDINGS)

    def _scope_ids_for_status(self, status):
        seen = []
        for entry in self._by_status(status):
            if entry.scope not in seen:
                seen.append(entry.scope)
        return seen

    def scope_status(self, scope):
        return self.source_results.get(scope)

    def can_check(self, scope, code=None):
        result = self.source_results.get(scope)
        if result is None or not result.syntax_supported:
            return False
        if code is None:
            return True
        code = normalize_rule_code(code)
        rule = result.rules.get(code)
        if rule is None:
            return False
        return rule.enabled and rule.applicable

    @property
    def skipped(self):
        return (
            self.syntax_unsupported
            + self.rule_not_enabled
            + self.rule_not_applicable
            + self.missing_source
        )

    @property
    def by_status(self):
        result = collections.OrderedDict(
            (status, self._by_status(status))
            for status in STATUSES
        )
        if self.missing_source:
            result[MISSING_SOURCE] = self.missing_source
        return result

    @property
    def counts(self):
        result = collections.OrderedDict(
            (status, len(self._by_status(status)))
            for status in STATUSES
        )
        if self.missing_source:
            result[MISSING_SOURCE] = len(self.missing_source)
        return result

    def report_items(self, status=None):
        entries = self.entries if status is None else self._by_status(status)
        return [entry for entry in entries if entry.item is not None]

    def scopes(self, status=None):
        entries = self.entries if status is None else self._by_status(status)
        seen = []
        for entry in entries:
            if entry.scope not in seen:
                seen.append(entry.scope)
        return [
            self.source_results[scope]
            for scope in seen
            if scope in self.source_results
        ]

    def is_eligible(self, item, code=None):
        """Return whether a report item is signable for this version."""
        if isinstance(item, (dict, tuple, list)):
            item = _parse_report_item(item)
        if isinstance(item, ReportItem):
            key = item.key
            code = item.code
        else:
            key = None
            code = normalize_rule_code(code or item)
        for entry in self.eligible:
            if entry.code != code:
                continue
            if key is None or entry.key == key:
                return True
        return False

    def can_sign_off(self, item, code=None):
        return self.is_eligible(item, code=code)

    def entry_for(self, scope=None, code=None, lineno=None, col_offset=None):
        for entry in self.entries:
            if scope is not None and entry.scope != scope:
                continue
            if code is not None and entry.code != normalize_rule_code(code):
                continue
            if lineno is not None and entry.lineno != lineno:
                continue
            if col_offset is not None and entry.col_offset != col_offset:
                continue
            return entry
        return None

    def to_dict(self):
        result = collections.OrderedDict([
            ('version', self.version),
            ('counts', self.counts),
            ('eligible', [entry.to_dict() for entry in self.eligible]),
            (
                'syntax_unsupported',
                [entry.to_dict() for entry in self.syntax_unsupported],
            ),
            (
                'rule_not_enabled',
                [entry.to_dict() for entry in self.rule_not_enabled],
            ),
            (
                'rule_not_applicable',
                [entry.to_dict() for entry in self.rule_not_applicable],
            ),
            ('no_findings', [entry.to_dict() for entry in self.no_findings]),
            ('entries', [entry.to_dict() for entry in self.entries]),
            (
                'scopes',
                collections.OrderedDict(
                    (scope, result.to_dict())
                    for scope, result in self.source_results.items()
                ),
            ),
        ])
        result['missing_source'] = [
            entry.to_dict() for entry in self.missing_source
        ]
        return result

    def __getitem__(self, key):
        if key in self.source_results:
            return self.source_results[key]
        normalized = normalize_status(key)
        if normalized in ALL_STATUSES:
            return self._by_status(normalized)
        code = normalize_rule_code(key)
        entries = [entry for entry in self.entries if entry.code == code]
        if entries:
            return entries
        data = self.to_dict()
        if key in data:
            return data[key]
        raise KeyError(key)

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def summary(self):
        return self.to_dict()

    as_dict = to_dict

    def to_json(self, **kwargs):
        return json.dumps(self.to_dict(), **kwargs)

    def __iter__(self):
        return iter(self.entries)

    def __len__(self):
        return len(self.entries)


class ScopeAudit(object):
    """Cross-version audit of a Dlint report.

    ``sources`` may be a mapping of scope ids to source strings, a sequence of
    ``(scope, source)`` pairs/dictionaries, or one source string.  ``report``
    may be any iterable of report items, a flake8 text report, or a dictionary
    containing ``results``/``findings`` and optionally ``sources``.
    """

    def __init__(
            self,
            sources=None,
            report=None,
            versions=None,
            rules=None,
            select=None,
            ignore=None,
            verify_findings=False,
            filename=None,
            **kwargs):
        if (sources is not None
                and report is not None
                and _looks_like_report_collection(sources)
                and not _looks_like_report_collection(report)):
            sources, report = report, sources
        if sources is None:
            for key in (
                    'source', 'sources', 'files', 'file_sources',
                    'sources_by_scope'):
                if key in kwargs:
                    sources = kwargs.pop(key)
                    break
        if versions is None:
            for key in (
                    'target_versions', 'target_version', 'version',
                    'python_versions', 'targets'):
                if key in kwargs:
                    versions = kwargs.pop(key)
                    break
        if rules is None:
            for key in (
                    'enabled_rules', 'selected_rules', 'checks',
                    'codes', 'linters'):
                if key in kwargs:
                    rules = kwargs.pop(key)
                    break
        if ignore is None:
            for key in ('disabled_rules', 'disabled', 'ignored'):
                if key in kwargs:
                    ignore = kwargs.pop(key)
                    break
        if report is None:
            for key in (
                    'report_items', 'findings', 'results', 'items',
                    'dlint_results'):
                if key in kwargs:
                    report = kwargs.pop(key)
                    break
        if not verify_findings:
            verify_findings = kwargs.pop(
                'verify', kwargs.pop('reproduce', False)
            )
        if (report is not None
                and _looks_like_report_collection(sources)
                and not _looks_like_report_collection(report)):
            sources, report = report, sources
        if report is None and _looks_like_report_payload(sources):
            report = sources
            sources = None
        if isinstance(report, _STRING_TYPES):
            loaded_report = _load_report_payload(report)
            if loaded_report is not None:
                report = loaded_report

        payload_meta = report if isinstance(report, dict) else {}
        if versions is None:
            versions = _first_present(
                payload_meta,
                ('versions', 'target_versions', 'target_version', 'version', 'python_versions', 'targets'),
            )
        if versions is None:
            versions = [sys.version_info[:2]]
        elif isinstance(versions, _STRING_TYPES):
            text = _to_text(versions)
            if ',' in text or ';' in text:
                parts = [
                    part.strip() for part in re.split(r'[,;]+', text)
                    if part.strip()
                ]
                if (len(parts) == 2
                        and all(part.isdigit() and len(part) == 1
                                for part in parts)):
                    versions = [(int(parts[0]), int(parts[1]))]
                else:
                    versions = parts
            else:
                parts = text.split()
                if (len(parts) > 1
                        and all(_looks_like_version(part) for part in parts)):
                    versions = parts
                else:
                    versions = [versions]
        elif isinstance(versions, (int, float, PythonVersion)):
            versions = [versions]
        elif isinstance(versions, (tuple, list)) and versions:
            if (len(versions) <= 3
                    and all(isinstance(value, int)
                            and 0 <= value <= 9 for value in versions)):
                versions = [versions]

        expanded_versions = []
        for version in versions:
            if isinstance(version, _STRING_TYPES):
                text = _to_text(version)
                if ',' in text or ';' in text:
                    expanded_versions.extend(
                        part.strip() for part in re.split(r'[,;]+', text)
                        if part.strip()
                    )
                    continue
            expanded_versions.append(version)
        self.versions = [
            normalize_version(version) for version in expanded_versions
        ]
        if not self.versions:
            raise ValueError('at least one target version is required')
        self.version_strings = [
            version_string(version) for version in self.versions
        ]
        self.target_versions = self.version_strings
        self.python_versions = list(self.versions)

        self.report_payload = report
        self.verify_findings = bool(verify_findings)
        self.explicit_selectors = _normalize_selectors(
            select if select is not None else rules
        )
        self.ignore_selectors = _normalize_selectors(ignore)

        payload_sources = None
        payload_report = report
        payload_rules = None
        if isinstance(report, dict):
            payload_sources = _first_present(
                report,
                ('sources', 'files', 'file_sources', 'sources_by_scope'),
            )
            payload_rules = _first_present(
                report,
                ('rules', 'select', 'selected', 'selected_rules', 'checks', 'codes', 'enabled'),
            )
            payload_report = _first_present(
                report,
                ('results', 'findings', 'items', 'report', 'report_items', 'dlint_results'),
            )
            if payload_report is None:
                if _looks_like_report_item(report):
                    payload_report = [report]
                else:
                    payload_report = _report_mapping_to_items(report)

        if sources is None:
            sources = payload_sources
        if self.explicit_selectors is None and payload_rules is not None:
            self.explicit_selectors = _normalize_selectors(payload_rules)
        if self.ignore_selectors is None and isinstance(report, dict):
            payload_ignore = _first_present(
                report,
                ('ignore', 'ignored', 'disabled', 'disabled_rules'),
            )
            if payload_ignore is not None:
                self.ignore_selectors = _normalize_selectors(payload_ignore)

        if self.explicit_selectors is None:
            self.selected_rules = [
                code for code in _known_rule_codes()
                if self._rule_enabled(code)
            ]
        else:
            selected = []
            for selector in self.explicit_selectors:
                for code in _known_rule_codes():
                    if (_selector_matches(selector, code)
                            and code not in selected):
                        selected.append(code)
                if (_DUO_CODE_RE.match(selector)
                        and selector not in selected):
                    selected.append(selector)
            self.selected_rules = selected
        self.rules = self.selected_rules
        ignored = []
        for selector in (self.ignore_selectors or []):
            for code in _known_rule_codes():
                if _selector_matches(selector, code) and code not in ignored:
                    ignored.append(code)
            if (_DUO_CODE_RE.match(selector)
                    and selector not in ignored):
                ignored.append(selector)
        self.ignored_rules = ignored
        self.enabled_rules = [
            code for code in self.selected_rules
            if self._rule_enabled(code)
        ]

        self.sources = _coerce_sources(sources, filename=filename)
        items = _coerce_report_items(payload_report)
        self._add_embedded_sources(items)
        self.report_items = ReportItems(items, self)
        self._scope_index = _build_scope_index(self.sources)
        self._item_scopes = collections.OrderedDict()
        for item in items:
            scope_id = _resolve_item_scope(
                item,
                self.sources,
                self._scope_index,
            )
            self._item_scopes[id(item)] = scope_id
            if scope_id is not None and item.scope is None:
                item.scope = scope_id

        self.audits = collections.OrderedDict()
        self._source_cache = {}
        for version in self.versions:
            self.audits[version_string(version)] = self._audit_version(version)
        self.version_tuples = list(self.versions)
        self.versions = list(self.version_strings)

    @classmethod
    def from_report(cls, report, sources=None, **kwargs):
        return cls(sources=sources, report=report, **kwargs)

    @classmethod
    def from_sources(cls, sources, **kwargs):
        return cls(sources=sources, **kwargs)

    def _add_embedded_sources(self, items):
        for item in items:
            if item.source is None:
                continue
            scope = (
                item.scope if item.scope is not None else item.filename
            )
            if scope is None:
                scope = '<embedded-{}>'.format(len(self.sources))
                item.scope = scope
            if scope not in self.sources:
                self.sources[scope] = SourceScope(
                    scope,
                    _maybe_read_source(item.source),
                    filename=item.filename or scope,
                )

    def _audit_version(self, version):
        source_results = []
        for scope in self.sources.values():
            cache_key = (scope.scope, scope.filename, version)
            if cache_key not in self._source_cache:
                self._source_cache[cache_key] = parse_source(
                    scope.source,
                    version,
                    filename=scope.filename,
                )
            syntax = self._source_cache[cache_key]
            source_results.append((scope, ScopeResult(scope, syntax)))

        audit = VersionAudit(version, source_results)
        scope_items = collections.OrderedDict(
            (scope.scope, [])
            for scope in self.sources.values()
        )
        unresolved_items = []

        for item in self.report_items:
            scope_id = self._item_scopes.get(id(item))
            if scope_id is None:
                unresolved_items.append(item)
            else:
                scope_items.setdefault(scope_id, []).append(item)

        report_codes = [
            item.code for item in self.report_items
            if item.code is not None
        ]
        focus_codes = self._focus_codes(report_codes)

        for scope in self.sources.values():
            result = audit.source_results[scope.scope]
            syntax = result.syntax
            items = scope_items.get(scope.scope, [])
            result.report_items.extend(items)

            item_codes = set(
                item.code for item in items if item.code is not None
            )
            enabled_codes = self._enabled_codes_for_scope(items, focus_codes)
            for code in enabled_codes:
                enabled = self._rule_enabled(code)
                applicable = rule_supports_version(code, version)
                if not enabled:
                    status = RULE_NOT_ENABLED
                    reason = 'not_selected'
                elif not applicable:
                    status = RULE_NOT_APPLICABLE
                    reason = 'rule_not_applicable'
                else:
                    status = NO_FINDINGS
                    reason = 'no_report_item'
                rule = RuleResult(
                    code=code,
                    enabled=enabled,
                    applicable=applicable,
                    status=status,
                    reason=reason,
                )
                result.rules[code] = rule

            for item in items:
                entry = self._classify_item(
                    version,
                    scope,
                    syntax,
                    item,
                    result,
                )
                audit.add(entry)

            for rule in result.rules.values():
                if rule.eligible_items:
                    rule.status = ELIGIBLE
                    rule.reason = 'selected'

            if not syntax.supported:
                for rule in result.rules.values():
                    rule.status = (
                        MISSING_SOURCE
                        if syntax.reason == 'missing_source'
                        else SYNTAX_UNSUPPORTED
                    )
                    rule.reason = syntax.reason or 'syntax_error'
                if not items:
                    audit.add(AuditEntry(
                        version,
                        scope.scope,
                        (
                            MISSING_SOURCE
                            if syntax.reason == 'missing_source'
                            else SYNTAX_UNSUPPORTED
                        ),
                        filename=scope.filename,
                        reason=syntax.reason or 'syntax_error',
                        syntax_error=syntax.syntax_error,
                        applicable=False,
                        enabled=False,
                    ))
                continue

            for code in enabled_codes:
                if not self._rule_enabled(code) and code not in item_codes:
                    audit.add(AuditEntry(
                        version,
                        scope.scope,
                        RULE_NOT_ENABLED,
                        code=code,
                        filename=scope.filename,
                        reason='not_selected',
                        enabled=False,
                    ))

            clean_codes = [
                code for code in enabled_codes
                if code not in item_codes
                and self._rule_enabled(code)
            ]
            for code in clean_codes:
                applicable = rule_supports_version(code, version)
                status = NO_FINDINGS if applicable else RULE_NOT_APPLICABLE
                reason = (
                    'no_report_item'
                    if applicable
                    else 'rule_not_applicable'
                )
                rule = result.rules.get(code)
                if rule is not None:
                    rule.status = status
                    rule.reason = reason
                audit.add(AuditEntry(
                    version,
                    scope.scope,
                    status,
                    code=code,
                    filename=scope.filename,
                    applicable=applicable,
                    reason=reason,
                ))

            if not items and not clean_codes:
                scope_has_entries = any(
                    entry.scope == scope.scope for entry in audit.entries
                )
                if not scope_has_entries:
                    audit.add(AuditEntry(
                        version,
                        scope.scope,
                        NO_FINDINGS,
                        filename=scope.filename,
                        reason='no_report_item',
                    ))

        for item in unresolved_items:
            audit.add(AuditEntry(
                version,
                item.scope or item.filename or '<unresolved>',
                MISSING_SOURCE,
                code=item.code,
                reason='missing_source',
                filename=item.filename,
                lineno=item.lineno,
                col_offset=item.col_offset,
                message=item.message,
                item=item,
                applicable=False,
                enabled=False,
            ))

        return audit

    def _focus_codes(self, report_codes):
        if self.explicit_selectors is not None:
            codes = []
            for selector in self.explicit_selectors:
                for code in _known_rule_codes():
                    if _selector_matches(selector, code) and code not in codes:
                        codes.append(code)
            for selector in self.explicit_selectors:
                if _DUO_CODE_RE.match(selector) and selector not in codes:
                    codes.append(selector)
            return codes

        codes = []
        for code in report_codes:
            if code is not None and code not in codes:
                codes.append(code)
        if not codes and self.ignore_selectors:
            for selector in self.ignore_selectors:
                for code in _known_rule_codes():
                    if (_selector_matches(selector, code)
                            and code not in codes):
                        codes.append(code)
        return codes

    def _enabled_codes_for_scope(self, items, focus_codes):
        codes = list(focus_codes)
        for item in items:
            if item.code is not None and item.code not in codes:
                codes.append(item.code)
        return [
            code for code in codes
            if code in _known_rule_codes()
        ]

    def _rule_enabled(self, code):
        if code is None:
            return False
        code = normalize_rule_code(code)
        if self.ignore_selectors is not None:
            if any(_selector_matches(selector, code)
                   for selector in self.ignore_selectors):
                return False
        if self.explicit_selectors is None:
            linter_class = _rule_classes().get(code)
            if (linter_class is not None
                    and getattr(linter_class, 'off_by_default', False)):
                return False
            return True
        return any(
            _selector_matches(selector, code)
            for selector in self.explicit_selectors
        )

    def _classify_item(self, version, scope, syntax, item, result):
        code = item.code
        enabled = self._rule_enabled(code)
        applicable = rule_supports_version(code, version) if code else True

        rule = result.rules.get(code)
        if rule is None and code is not None:
            rule = RuleResult(
                code=code,
                enabled=enabled,
                applicable=applicable,
                status=NO_FINDINGS,
            )
            result.rules[code] = rule
        if rule is not None:
            rule.report_items.append(item)

        common = dict(
            filename=scope.filename,
            lineno=item.lineno,
            col_offset=item.col_offset,
            message=item.message,
            item=item,
            applicable=applicable,
            enabled=enabled,
        )

        if not syntax.supported:
            unsupported_status = (
                MISSING_SOURCE
                if syntax.reason == 'missing_source'
                else SYNTAX_UNSUPPORTED
            )
            common['applicable'] = False
            common['enabled'] = False
            if rule is not None:
                rule.status = unsupported_status
                rule.reason = syntax.reason or 'syntax_error'
            return AuditEntry(
                version,
                scope.scope,
                unsupported_status,
                code=code,
                reason=syntax.reason or 'syntax_error',
                syntax_error=syntax.syntax_error,
                **common
            )

        if not enabled:
            if rule is not None:
                rule.status = RULE_NOT_ENABLED
                rule.reason = 'not_selected'
            return AuditEntry(
                version,
                scope.scope,
                RULE_NOT_ENABLED,
                code=code,
                reason='not_selected',
                **common
            )

        if not applicable:
            if rule is not None:
                rule.status = RULE_NOT_APPLICABLE
                rule.reason = 'rule_not_applicable'
            return AuditEntry(
                version,
                scope.scope,
                RULE_NOT_APPLICABLE,
                code=code,
                reason='rule_not_applicable',
                **common
            )

        if self.verify_findings:
            reproduced = self._reproduce_item(
                version,
                scope.scope,
                syntax,
                item,
            )
            if reproduced is False:
                if rule is not None:
                    rule.status = NO_FINDINGS
                    rule.reason = 'finding_not_reproduced'
                return AuditEntry(
                    version,
                    scope.scope,
                    NO_FINDINGS,
                    code=code,
                    reason='finding_not_reproduced',
                    reproduced=False,
                    **common
                )
            if reproduced is True:
                if rule is not None:
                    rule.eligible_items.append(item)
                return AuditEntry(
                    version,
                    scope.scope,
                    ELIGIBLE,
                    code=code,
                    reason='selected',
                    reproduced=True,
                    **common
                )

        if rule is not None:
            rule.status = ELIGIBLE
            rule.eligible_items.append(item)
        return AuditEntry(
            version,
            scope.scope,
            ELIGIBLE,
            code=code,
            reason='selected',
            **common
        )

    def _reproduce_item(self, version, scope_id, syntax, item):
        if item.code is None or syntax.tree is None:
            return None
        cache = self.__dict__.setdefault('_reproduced', {})
        cache_key = (version, scope_id, item.code)
        if cache_key not in cache:
            cache[cache_key] = run_linter(item.code, syntax.tree, version)
        results = cache[cache_key]
        if results is None:
            return None
        return any(
            result.lineno == item.lineno
            for result in results
        )

    def __iter__(self):
        return iter(self.audits)

    def __len__(self):
        return len(self.audits)

    def keys(self):
        return self.audits.keys()

    def values(self):
        return self.audits.values()

    def items(self):
        return self.audits.items()

    def __getitem__(self, version):
        try:
            key = version_string(version)
        except (TypeError, ValueError):
            key = None
        if key in self.audits:
            return self.audits[key]
        text = str(version).strip().lower().replace('-', '_')
        normalized = normalize_status(text)
        if normalized in ALL_STATUSES:
            return getattr(self, normalized)
        if text == 'skipped':
            return self.skipped
        raise KeyError(version)

    def for_version(self, version):
        return self[version]

    def get(self, version, default=None):
        try:
            return self[version]
        except (KeyError, TypeError, ValueError):
            return default

    @property
    def eligible(self):
        return collections.OrderedDict(
            (key, audit.eligible)
            for key, audit in self.audits.items()
        )

    @property
    def signable(self):
        return self.eligible

    @property
    def syntax_unsupported(self):
        return collections.OrderedDict(
            (key, audit.syntax_unsupported)
            for key, audit in self.audits.items()
        )

    @property
    def rule_not_enabled(self):
        return collections.OrderedDict(
            (key, audit.rule_not_enabled)
            for key, audit in self.audits.items()
        )

    @property
    def rule_not_applicable(self):
        return collections.OrderedDict(
            (key, audit.rule_not_applicable)
            for key, audit in self.audits.items()
        )

    @property
    def not_applicable(self):
        return self.rule_not_applicable

    @property
    def no_findings(self):
        return collections.OrderedDict(
            (key, audit.no_findings)
            for key, audit in self.audits.items()
        )

    @property
    def missing_source(self):
        return collections.OrderedDict(
            (key, audit.missing_source)
            for key, audit in self.audits.items()
        )

    @property
    def skipped(self):
        return collections.OrderedDict(
            (key, audit.skipped)
            for key, audit in self.audits.items()
        )

    def eligible_items(self, version=None):
        if version is not None:
            return self[version].eligible
        return collections.OrderedDict(
            (key, audit.eligible)
            for key, audit in self.audits.items()
        )

    def signable_items(self, version=None):
        return self.eligible_items(version=version)

    def eligible_report_items(self, version=None):
        if version is not None:
            return self[version].eligible_report_items
        return collections.OrderedDict(
            (key, audit.eligible_report_items)
            for key, audit in self.audits.items()
        )

    def signoff_items(self, version=None):
        if version is not None:
            return self[version].eligible_report_items
        return collections.OrderedDict(
            (key, audit.eligible_report_items)
            for key, audit in self.audits.items()
        )

    @property
    def by_version(self):
        return self.audits

    @property
    def results(self):
        return self.audits

    @property
    def source_results(self):
        return collections.OrderedDict(
            (key, audit.source_results)
            for key, audit in self.audits.items()
        )

    @property
    def rule_results(self):
        return collections.OrderedDict(
            (key, audit.rule_results)
            for key, audit in self.audits.items()
        )

    @property
    def scope_ids(self):
        return list(self.sources)

    @property
    def by_status(self):
        return collections.OrderedDict(
            (key, audit.by_status)
            for key, audit in self.audits.items()
        )

    @property
    def counts(self):
        return collections.OrderedDict(
            (key, audit.counts)
            for key, audit in self.audits.items()
        )

    @property
    def eligible_scope_ids(self):
        return collections.OrderedDict(
            (key, audit.eligible_scope_ids)
            for key, audit in self.audits.items()
        )

    @property
    def syntax_unsupported_scope_ids(self):
        return collections.OrderedDict(
            (key, audit.syntax_unsupported_scope_ids)
            for key, audit in self.audits.items()
        )

    @property
    def rule_not_enabled_scope_ids(self):
        return collections.OrderedDict(
            (key, audit.rule_not_enabled_scope_ids)
            for key, audit in self.audits.items()
        )

    @property
    def rule_not_applicable_scope_ids(self):
        return collections.OrderedDict(
            (key, audit.rule_not_applicable_scope_ids)
            for key, audit in self.audits.items()
        )

    @property
    def no_findings_scope_ids(self):
        return collections.OrderedDict(
            (key, audit.no_findings_scope_ids)
            for key, audit in self.audits.items()
        )

    def _report_items_for(self, version=None, status=None):
        if version is not None:
            return self[version].report_items(status=status)
        return collections.OrderedDict(
            (key, audit.report_items(status=status))
            for key, audit in self.audits.items()
        )

    def scopes(self, version=None, status=None):
        if version is not None:
            return self[version].scopes(status=status)
        return collections.OrderedDict(
            (key, audit.scopes(status=status))
            for key, audit in self.audits.items()
        )

    def is_eligible(self, item, version):
        return self[version].is_eligible(item)

    def can_sign_off(self, item, version):
        return self.is_eligible(item, version)

    def can_check(self, scope, code=None, version=None):
        if version is None:
            version = list(self.audits)[0]
        return self[version].can_check(scope, code=code)

    def scope_status(self, scope, version=None):
        if version is None:
            version = list(self.audits)[0]
        return self[version].scope_status(scope)

    def _versions_for(self, predicate):
        return [
            version for version, audit in self.audits.items()
            if predicate(audit)
        ]

    def eligible_versions(self, scope=None, code=None):
        """Return target versions where ``code`` is eligible for sign-off."""
        code = normalize_rule_code(code) if code is not None else None
        return self._versions_for(
            lambda audit: any(
                (scope is None or entry.scope == scope)
                and (code is None or entry.code == code)
                for entry in audit.eligible
            )
        )

    def checkable_versions(self, scope=None, code=None):
        """Return target versions where the rule actually ran on the source."""
        code = normalize_rule_code(code) if code is not None else None
        versions = []
        for version, audit in self.audits.items():
            if scope is not None:
                if not audit.can_check(scope, code=code):
                    continue
            elif code is not None:
                if not any(
                        result.can_check(code)
                        for result in audit.source_results.values()):
                    continue
            versions.append(version)
        return versions

    def skipped_versions(self, scope=None, code=None):
        """Return versions where a source/rule was skipped by the target."""
        code = normalize_rule_code(code) if code is not None else None
        versions = []
        for version, audit in self.audits.items():
            skipped = any(
                (scope is None or entry.scope == scope)
                and (code is None or entry.code == code)
                for entry in audit.skipped
            )
            if not skipped and code is not None:
                for scope_id, result in audit.source_results.items():
                    if scope is not None and scope_id != scope:
                        continue
                    rule = result.rules.get(code)
                    if (rule is not None
                            and rule.status in SKIPPED_STATUSES):
                        skipped = True
                        break
            if skipped:
                versions.append(version)
        return versions

    def common_eligible(self):
        """Return items eligible in every target version.

        This is opt-in on purpose.  A fragment skipped by one target version
        is not required to be part of a shared result.
        """
        if not self.audits:
            return []
        versions = list(self.audits.values())
        keys = set(entry.key for entry in versions[0].eligible)
        for audit in versions[1:]:
            keys &= set(entry.key for entry in audit.eligible)
        return [
            entry for entry in versions[0].eligible
            if entry.key in keys
        ]

    common_signable = common_eligible

    def common_eligible_items(self):
        """Return the raw report items common to every target version."""
        return [
            entry.item for entry in self.common_eligible()
            if entry.item is not None
        ]

    def summary(self):
        by_version = collections.OrderedDict(
            (key, audit.to_dict())
            for key, audit in self.audits.items()
        )
        result = collections.OrderedDict([
            ('versions', list(self.audits.keys())),
            ('by_version', by_version),
            (
                'counts',
                collections.OrderedDict(
                    (key, audit.counts)
                    for key, audit in self.audits.items()
                ),
            ),
        ])
        for status in STATUSES:
            result[status] = collections.OrderedDict(
                (
                    key,
                    [entry.to_dict() for entry in audit._by_status(status)],
                )
                for key, audit in self.audits.items()
            )
        result['skipped'] = collections.OrderedDict(
            (
                key,
                [entry.to_dict() for entry in audit.skipped],
            )
            for key, audit in self.audits.items()
        )
        result['missing_source'] = collections.OrderedDict(
            (
                key,
                [entry.to_dict() for entry in audit.missing_source],
            )
            for key, audit in self.audits.items()
        )
        for key, value in by_version.items():
            result[key] = value
        return result

    summarize = summary

    def to_dict(self):
        result = self.summary()
        result['report_items'] = [
            item.to_dict()
            for item in self.report_items
        ]
        result['sources'] = [
            scope.to_dict()
            for scope in self.sources.values()
        ]
        result['source_map'] = collections.OrderedDict(
            (scope.scope, scope.to_dict())
            for scope in self.sources.values()
        )
        return result

    as_dict = to_dict

    def to_json(self, **kwargs):
        return json.dumps(self.to_dict(), **kwargs)


# Backwards/forwards-compatible names used by integrations.
DlintScopeAudit = ScopeAudit
DlintScope = ScopeAudit
ScopeAuditor = ScopeAudit
ReportAudit = ScopeAudit
AuditReport = ScopeAudit
ScopeReport = ScopeAudit
ReportScope = ScopeAudit
DlintAudit = ScopeAudit
AuditResult = ScopeAudit
AuditSummary = VersionAudit
Scope = ScopeAudit
Audit = ScopeAudit
VersionScopeAudit = ScopeAudit
VersionScope = VersionAudit
TargetVersion = PythonVersion
SYNTAX_NOT_SUPPORTED = SYNTAX_UNSUPPORTED
RULE_DISABLED = RULE_NOT_ENABLED
RULE_NOT_SUPPORTED = RULE_NOT_APPLICABLE
NOT_APPLICABLE = RULE_NOT_APPLICABLE
INAPPLICABLE = RULE_NOT_APPLICABLE
VERSION_SKIPPED = RULE_NOT_APPLICABLE
CLEAN = NO_FINDINGS
SIGN_OFF = ELIGIBLE
ELIGIBLE_FOR_SIGNOFF = ELIGIBLE
ELIGIBLE_TO_SIGN = ELIGIBLE


def audit_scope(
        sources=None,
        report=None,
        versions=None,
        rules=None,
        select=None,
        ignore=None,
        verify_findings=False,
        filename=None,
        source=None,
        version=None,
        target_version=None,
        target_versions=None,
        enabled=None,
        disabled=None,
        selected_rules=None,
        checks=None,
        codes=None,
        linters=None,
        **kwargs):
    """Audit a Dlint report against one or more target Python versions."""
    if (sources is not None
            and report is not None
            and _looks_like_report_collection(sources)
            and not _looks_like_report_collection(report)):
        sources, report = report, sources
    if _looks_like_version(report):
        if (rules is None and versions is not None
                and not _looks_like_version(versions)):
            rules = versions
        versions = report
        report = None
    if sources is None:
        sources = source
    if versions is None:
        if target_versions is not None:
            versions = target_versions
        elif version is not None:
            versions = version
        elif target_version is not None:
            versions = target_version
    if rules is None:
        for candidate in (
                selected_rules, checks, codes, linters, enabled):
            if candidate is not None and not isinstance(candidate, bool):
                rules = candidate
                break
    if ignore is None:
        ignore = disabled
    return ScopeAudit(
        sources=sources,
        report=report,
        versions=versions,
        rules=rules,
        select=select,
        ignore=ignore,
        verify_findings=verify_findings,
        filename=filename,
        **kwargs
    )


def audit_source(source=None, version=None, rules=None, report=None,
                 versions=None, **kwargs):
    """Audit one source string for one or more target versions."""
    if versions is None:
        versions = version
    return audit_scope(
        sources=source,
        versions=versions,
        rules=rules,
        report=report,
        **kwargs
    )


def audit_versions(source=None, versions=None, rules=None, report=None,
                   version=None, **kwargs):
    """Audit one source against multiple target versions."""
    if versions is None:
        versions = version
    return audit_scope(
        sources=source,
        versions=versions,
        rules=rules,
        report=report,
        **kwargs
    )


def scope_audit(*args, **kwargs):
    if (len(args) >= 2
            and _looks_like_version(args[1])
            and 'report' not in kwargs
            and 'versions' not in kwargs):
        rules = args[2] if len(args) > 2 else None
        report = args[3] if len(args) > 3 else None
        if _looks_like_report_collection(args[0]):
            return audit_scope(
                report=args[0],
                versions=args[1],
                rules=rules,
                **kwargs
            )
        return audit_source(
            args[0], args[1], rules, report=report, **kwargs
        )
    return audit_scope(*args, **kwargs)


def audit_report(report=None, sources=None, **kwargs):
    """Audit a report, accepting the report as the first positional value."""
    return audit_scope(sources=sources, report=report, **kwargs)


def audit(sources=None, report=None, versions=None, rules=None, **kwargs):
    if versions is None and _looks_like_version(report):
        versions = report
        report = None
    return audit_scope(
        sources=sources,
        report=report,
        versions=versions,
        rules=rules,
        **kwargs
    )


def _looks_like_version(value):
    if isinstance(value, (tuple, list)) and value:
        if all(isinstance(item, int) and 0 <= item <= 9
               for item in value) and len(value) <= 3:
            return True
        for item in value:
            if not isinstance(item, (str, bytes, int, float, PythonVersion)):
                return False
        try:
            for item in value:
                normalize_version(item)
        except (TypeError, ValueError):
            return False
        return True
    if not isinstance(value, (str, bytes, int, float, PythonVersion)):
        return False
    try:
        normalize_version(value)
    except (TypeError, ValueError):
        return False
    return True


def summarize_scope(audit_result):
    return audit_result.summary()


def summarize_report(audit_result):
    return audit_result.summary()


def eligible_report_items(audit_result, version=None):
    return audit_result.eligible_items(version=version)


def common_eligible_items(audit_result):
    return audit_result.common_eligible_items()


def eligible_versions(source=None, versions=None, rule=None, code=None,
                      rules=None, report=None, filename=None, **kwargs):
    """Return the target versions where a source/rule is sign-off eligible."""
    selected = rules
    if selected is None and rule is not None:
        selected = [rule]
    audit_result = audit_scope(
        sources=source,
        report=report,
        versions=versions,
        rules=selected,
        filename=filename,
        **kwargs
    )
    scope_ids = audit_result.scope_ids
    scope = scope_ids[0] if len(scope_ids) == 1 else None
    return audit_result.eligible_versions(scope=scope, code=code or rule)


def checkable_versions(source=None, versions=None, rule=None, code=None,
                       rules=None, report=None, filename=None, **kwargs):
    """Return versions where the target environment can actually run a rule."""
    selected = rules
    if selected is None and rule is not None:
        selected = [rule]
    audit_result = audit_scope(
        sources=source,
        report=report,
        versions=versions,
        rules=selected,
        filename=filename,
        **kwargs
    )
    scope_ids = audit_result.scope_ids
    scope = scope_ids[0] if len(scope_ids) == 1 else None
    return audit_result.checkable_versions(scope=scope, code=code or rule)


def skipped_versions(source=None, versions=None, rule=None, code=None,
                     rules=None, report=None, filename=None, **kwargs):
    """Return versions where the target environment skipped the check."""
    selected = rules
    if selected is None and rule is not None:
        selected = [rule]
    audit_result = audit_scope(
        sources=source,
        report=report,
        versions=versions,
        rules=selected,
        filename=filename,
        **kwargs
    )
    scope_ids = audit_result.scope_ids
    scope = scope_ids[0] if len(scope_ids) == 1 else None
    return audit_result.skipped_versions(scope=scope, code=code or rule)


def is_eligible(source, version, rule=None, code=None, report=None,
                filename=None, **kwargs):
    """Return whether a report item for ``source`` is signable at ``version``."""
    return version_string(version) in eligible_versions(
        source=source,
        versions=[version],
        rule=rule,
        code=code,
        report=report,
        filename=filename,
        **kwargs
    )


def can_check(source, version, rule=None, code=None, filename=None, **kwargs):
    """Return whether ``version`` can run the rule on ``source``."""
    return version_string(version) in checkable_versions(
        source=source,
        versions=[version],
        rule=rule,
        code=code,
        filename=filename,
        **kwargs
    )


def is_applicable(code, version):
    """Alias for :func:`rule_supports_version`."""
    return rule_supports_version(code, version)


def check_source(source, version=None, filename=None, target_version=None):
    if version is None:
        version = target_version
    return parse_source(source, version, filename=filename)


def syntax_supported(source, version=None, filename=None,
                     target_version=None):
    if version is None:
        version = target_version
    return parse_source(source, version, filename=filename).supported


def is_supported(source, version=None, filename=None, target_version=None):
    return syntax_supported(
        source,
        version=version,
        filename=filename,
        target_version=target_version,
    )


def _rule_version_range(code):
    """Return ``(lower, upper)`` bounds declared for a rule, if any."""
    code = normalize_rule_code(code)
    if code in RULE_VERSION_RANGES:
        return RULE_VERSION_RANGES[code]

    linter_class = _rule_classes().get(code)
    if linter_class is None:
        return None

    versions = getattr(
        linter_class, '_python_versions',
        getattr(linter_class, 'python_versions', None),
    )
    if versions is not None:
        if isinstance(versions, _STRING_TYPES):
            versions = [versions]
        try:
            accepted = tuple(normalize_version(item) for item in versions)
        except (TypeError, ValueError):
            accepted = ()
        if accepted:
            return ('supported', accepted)

    lower = getattr(
        linter_class, '_min_python_version',
        getattr(linter_class, 'min_python_version', None),
    )
    upper = getattr(
        linter_class, '_max_python_version',
        getattr(linter_class, 'max_python_version', None),
    )
    if lower is not None or upper is not None:
        return (
            normalize_version(lower) if lower is not None else None,
            normalize_version(upper) if upper is not None else None,
        )
    return None


def rule_supports_version(code, version):
    """Return whether a rule applies to a target Python version."""
    bounds = _rule_version_range(code)
    if bounds is None:
        return True
    version = normalize_version(version)
    if bounds[0] == 'supported':
        return version in bounds[1]
    lower, upper = bounds
    if lower is not None and version < lower:
        return False
    if upper is not None and version >= upper:
        return False
    return True


def parse_source(source=None, version=None, filename=None,
                 target_version=None):
    if version is None:
        version = target_version
    version = normalize_version(version)
    filename = filename or '<unknown>'
    if source is None:
        return _unsupported(
            version,
            filename,
            None,
            'source is not available',
            reason='missing_source',
        )

    source = _to_text(_maybe_read_source(source))
    if version[0] == 2:
        return _parse_python2(source, version, filename)
    if version[0] == 3:
        return _parse_python3(source, version, filename)
    return _unsupported(
        version,
        filename,
        None,
        'unsupported target Python version: {}'.format(version_string(version)),
        reason='unsupported_target',
    )


def _parse_python3(source, version, filename):
    feature_version = max(version[1], 4)
    runtime_minor = sys.version_info[1]
    if feature_version > runtime_minor:
        feature_version = runtime_minor
    try:
        tree = ast.parse(
            source,
            filename=filename,
            feature_version=(3, feature_version),
        )
    except TypeError:
        # Python < 3.8 does not accept feature_version.
        try:
            tree = ast.parse(source, filename=filename)
        except SyntaxError as exc:
            return _syntax_error_result(version, filename, exc)
        except (TypeError, ValueError) as exc:
            return _unsupported(
                version, filename, exc, str(exc), reason='syntax_error'
            )
    except SyntaxError as exc:
        dedented = textwrap.dedent(source)
        if (dedented != source
                and 'indent' in (getattr(exc, 'msg', '') or '').lower()):
            return _parse_python3(dedented, version, filename)
        return _syntax_error_result(version, filename, exc)
    except ValueError as exc:
        # A target newer than the running interpreter.
        return _unsupported(
            version,
            filename,
            exc,
            str(exc),
            reason='unsupported_target',
        )

    violation = _post_parse_violation(tree, source, version)
    if violation is not None:
        node, message = violation
        exc = SyntaxError(
            message,
            (
                filename,
                getattr(node, 'lineno', 1),
                getattr(node, 'col_offset', 0) + 1,
                None,
            ),
        )
        return _syntax_error_result(version, filename, exc)

    return SyntaxResult(version, True, tree=tree, filename=filename)


def _parse_python2(source, version, filename):
    violation = _python3_only_violation(source)
    if violation is not None:
        lineno, offset, message = violation
        exc = SyntaxError(message, (filename, lineno, offset, None))
        return _syntax_error_result(version, filename, exc)

    try:
        tree = ast.parse(source, filename=filename)
        return SyntaxResult(version, True, tree=tree, filename=filename)
    except SyntaxError:
        original_error = sys.exc_info()[1]

    dedented = textwrap.dedent(source)
    if (dedented != source
            and 'indent' in (getattr(original_error, 'msg', '') or '').lower()):
        return _parse_python2(dedented, version, filename)

    refactored = _refactor_python2(source, filename)
    if refactored is not None:
        try:
            tree = ast.parse(refactored, filename=filename)
            return SyntaxResult(version, True, tree=tree, filename=filename)
        except SyntaxError:
            pass
        except (TypeError, ValueError) as exc:
            return _unsupported(
                version, filename, exc, str(exc), reason='syntax_error'
            )

    masked = _mask_python2_soft_keywords(source)
    if masked != source:
        refactored = _refactor_python2(masked, filename)
        if refactored is not None:
            try:
                tree = ast.parse(refactored, filename=filename)
                return SyntaxResult(version, True, tree=tree, filename=filename)
            except SyntaxError:
                pass
            except (TypeError, ValueError) as exc:
                return _unsupported(
                    version, filename, exc, str(exc), reason='syntax_error'
                )

    return _syntax_error_result(version, filename, original_error)


def _syntax_error_result(version, filename, exc):
    return SyntaxResult(
        version,
        False,
        error=exc,
        message=getattr(exc, 'msg', None) or str(exc),
        lineno=getattr(exc, 'lineno', None),
        offset=getattr(exc, 'offset', None),
        text=getattr(exc, 'text', None),
        reason='syntax_error',
        filename=filename,
    )


def _unsupported(version, filename, exc, message, reason):
    return SyntaxResult(
        version,
        False,
        error=exc,
        message=message,
        reason=reason,
        filename=filename,
    )


def _position_node(line, column):
    return collections.namedtuple(
        '_Position', ['lineno', 'col_offset']
    )(line, column)


def _print_chevron_violation(source):
    tokens = list(_generate_tokens(source))
    for index, token in enumerate(tokens):
        if token.type != tokenize.NAME or token.string != 'print':
            continue
        previous = _previous_significant(tokens, index)
        if previous is not None and previous.type not in (
                tokenize.NEWLINE, tokenize.NL, tokenize.INDENT,
                tokenize.DEDENT) and previous.string != ';':
            continue
        following = _next_significant(tokens, index)
        if following is not None and following.type == tokenize.OP                 and following.string == '>>':
            return (
                _position_node(token.start[0], token.start[1]),
                'print >> is not available in Python 3',
            )
    return None


def _post_parse_violation(tree, source, version):
    if version < (3, 3):
        yield_from = getattr(ast, 'YieldFrom', None)
        if yield_from is not None:
            for node in ast.walk(tree):
                if isinstance(node, yield_from):
                    return (
                        node,
                        'yield from requires Python 3.3',
                    )

    if version < (3, 5):
        dict_node = getattr(ast, 'Dict', None)
        list_node = getattr(ast, 'List', None)
        set_node = getattr(ast, 'Set', None)
        tuple_node = getattr(ast, 'Tuple', None)
        starred_node = getattr(ast, 'Starred', None)
        if dict_node is not None:
            for node in ast.walk(tree):
                if isinstance(node, dict_node) and any(
                        key is None for key in node.keys):
                    return (
                        node,
                        'dictionary unpacking requires Python 3.5',
                    )
        if starred_node is not None:
            display_nodes = tuple(
                item for item in (list_node, set_node, tuple_node)
                if item is not None
            )
            for node in ast.walk(tree):
                if not isinstance(node, display_nodes):
                    continue
                if any(isinstance(element, starred_node)
                       for element in node.elts):
                    return (
                        node,
                        'display unpacking requires Python 3.5',
                    )

    if version < (3, 5):
        for node in getattr(tree, 'body', []):
            if (isinstance(node, ast.ImportFrom)
                    and node.module == '__future__'
                    and any(alias.name == 'generator_stop'
                            for alias in node.names)):
                return (
                    node,
                    'from __future__ import generator_stop requires Python 3.5',
                )

    if version < (3, 7):
        for node in getattr(tree, 'body', []):
            if (isinstance(node, ast.ImportFrom)
                    and node.module == '__future__'
                    and any(alias.name == 'annotations'
                            for alias in node.names)):
                return (
                    node,
                    'from __future__ import annotations requires Python 3.7',
                )

    if version < (3, 8):
        debug = _fstring_debug_violation(source)
        if debug is not None:
            return debug

    if version < (3, 9):
        with_violation = _parenthesized_with_violation(source)
        if with_violation is not None:
            return with_violation

    if version >= (3, 5):
        await_violation = _await_outside_async(tree)
        if await_violation is not None:
            return await_violation

    if version < (3, 6):
        async_def = getattr(ast, 'AsyncFunctionDef', None)
        yield_nodes = tuple(
            item for item in (
                getattr(ast, 'Yield', None),
                getattr(ast, 'YieldFrom', None),
            )
            if item is not None
        )
        if async_def is not None and yield_nodes:
            for node in ast.walk(tree):
                if not isinstance(node, async_def):
                    continue
                for child in ast.walk(node):
                    if isinstance(child, yield_nodes):
                        return (
                            child,
                            'async generators require Python 3.6',
                        )

    print_violation = _print_chevron_violation(source)
    if print_violation is not None:
        return print_violation

    if version >= (3, 6):
        async_def = getattr(ast, 'AsyncFunctionDef', None)
        yield_from = getattr(ast, 'YieldFrom', None)
        if async_def is not None and yield_from is not None:
            for node in ast.walk(tree):
                if not isinstance(node, async_def):
                    continue
                for child in ast.walk(node):
                    if isinstance(child, yield_from):
                        return (
                            child,
                            'yield from is not allowed in an async function',
                        )
        return None

    joined_str = getattr(ast, 'JoinedStr', None)
    formatted_value = getattr(ast, 'FormattedValue', None)
    if joined_str is not None:
        for node in ast.walk(tree):
            if isinstance(node, joined_str):
                return (
                    node,
                    'f-strings require Python 3.6 or newer',
                )
            if formatted_value is not None and isinstance(
                    node, formatted_value):
                return (
                    node,
                    'f-strings require Python 3.6 or newer',
                )

    comprehension = getattr(ast, 'comprehension', None)
    if comprehension is not None:
        for node in ast.walk(tree):
            if isinstance(node, comprehension) and getattr(
                    node, 'is_async', 0):
                return (
                    node,
                    'asynchronous comprehensions require Python 3.6 or newer',
                )
    return None


def _future_import_violation(tokens):
    for index, token in enumerate(tokens):
        if token.type != tokenize.NAME or token.string != 'from':
            continue
        module = _next_significant(tokens, index)
        if (module is None
                or module.type != tokenize.NAME
                or module.string != '__future__'):
            continue
        import_token = _next_significant(tokens, tokens.index(module))
        if (import_token is None
                or import_token.type != tokenize.NAME
                or import_token.string != 'import'):
            continue
        for later in tokens[tokens.index(import_token) + 1:]:
            if later.type in (tokenize.NEWLINE, tokenize.ENDMARKER):
                break
            if (later.type == tokenize.NAME
                    and later.string in (
                        'annotations', 'generator_stop')):
                return (
                    later.start[0],
                    later.start[1] + 1,
                    'from __future__ import {} is not available '
                    'in Python 2'.format(later.string),
                )
    return None


def _python3_only_violation(source):
    """Find syntax that Python 2.7 cannot parse."""
    tokens = list(_generate_tokens(source))
    future_violation = _future_import_violation(tokens)
    if future_violation is not None:
        return future_violation
    if not tokens:
        return None

    statement_starts = set([
        tokenize.NEWLINE,
        tokenize.NL,
        tokenize.INDENT,
        tokenize.DEDENT,
    ])

    for index, token in enumerate(tokens):
        if _is_fstring_start(token):
            return (
                token.start[0],
                token.start[1] + 1,
                'f-strings are not available in Python 2',
            )

        if token.type == tokenize.STRING:
            prefix = _string_prefix(token.string)
            if 'f' in prefix:
                return (
                    token.start[0],
                    token.start[1] + 1,
                    'f-strings are not available in Python 2',
                )

        fstring_start = getattr(tokenize, 'FSTRING_START', None)
        if fstring_start is not None and token.type == fstring_start:
            return (
                token.start[0],
                token.start[1] + 1,
                'f-strings are not available in Python 2',
            )

        if token.type == tokenize.OP:
            if token.string in (':=', '->'):
                return (
                    token.start[0],
                    token.start[1] + 1,
                    '{} is not available in Python 2'.format(token.string),
                )
            previous_op = _previous_significant(tokens, index)
            if token.string == '@' and previous_op is not None:
                if (previous_op.type in (
                        tokenize.NAME, tokenize.NUMBER, tokenize.STRING)
                        or previous_op.string in (')', ']')):
                    return (
                        token.start[0],
                        token.start[1] + 1,
                        'matrix multiplication is not available in Python 2',
                    )
            if token.string == '**' and previous_op is not None:
                if previous_op.string == '{':
                    return (
                        token.start[0],
                        token.start[1] + 1,
                        'dictionary unpacking is not available in Python 2',
                    )
            if token.string == '*':
                if previous_op is not None and previous_op.string in (
                        '[', '{'):
                    return (
                        token.start[0],
                        token.start[1] + 1,
                        'display unpacking is not available in Python 2',
                    )
                at_statement_start = (
                    previous_op is None
                    or previous_op.type in statement_starts
                )
                after_separator = (
                    previous_op is not None
                    and not _in_call_header(tokens, index)
                    and previous_op.string in (',', '=')
                )
                if at_statement_start or after_separator:
                    following_op = _next_significant(tokens, index)
                    if (following_op is not None
                            and (following_op.type == tokenize.NAME
                                 or following_op.string in ('(', '['))):
                        return (
                            token.start[0],
                            token.start[1] + 1,
                            'extended unpacking is not available in Python 2',
                        )
            if token.string == '/' and _in_call_header(tokens, index):
                return (
                    token.start[0],
                    token.start[1] + 1,
                    'positional-only parameters are not available in Python 2',
                )

        if token.type == tokenize.NUMBER and '_' in token.string:
            return (
                token.start[0],
                token.start[1] + 1,
                'numeric underscores are not available in Python 2',
            )

        if token.type != tokenize.NAME:
            continue

        previous = _previous_significant(tokens, index)
        following = _next_significant(tokens, index)

        if (token.string not in ('if', 'elif', 'else', 'for',
                                 'while', 'with', 'def', 'class',
                                 'lambda', 'try', 'except',
                                 'finally', 'case')
                and following is not None
                and following.type == tokenize.OP
                and following.string == ':'
                and (previous is None
                     or previous.type in statement_starts
                     or previous.string == ';')):
            return (
                token.start[0],
                token.start[1] + 1,
                'variable annotations are not available in Python 2',
            )

        if token.string == 'nonlocal' and (
                previous is None or previous.type in statement_starts
                or previous.string == ';'):
            is_statement = (
                following is not None
                and following.type == tokenize.NAME
            )
            if is_statement:
                return (
                    token.start[0],
                    token.start[1] + 1,
                    'nonlocal is not available in Python 2',
                )

        if token.string == 'async' and following is not None:
            if following.type == tokenize.NAME and following.string in (
                    'def', 'for', 'with'):
                return (
                    token.start[0],
                    token.start[1] + 1,
                    'async syntax is not available in Python 2',
                )

        if token.string == 'yield' and following is not None:
            if following.type == tokenize.NAME and following.string == 'from':
                return (
                    token.start[0],
                    token.start[1] + 1,
                    'yield from is not available in Python 2',
                )

        if token.string == 'except' and following is not None:
            if following.type == tokenize.OP and following.string == '*':
                return (
                    token.start[0],
                    token.start[1] + 1,
                    'except* is not available in Python 2',
                )

        if token.string == 'match' and (
                previous is None or previous.type in statement_starts
                or previous.string == ';'):
            line_tokens = [
                later for later in tokens[index + 1:]
                if later.start == token.start
                or later.start[0] == token.start[0]
            ]
            has_case = any(
                later.type == tokenize.NAME and later.string == 'case'
                for later in tokens[index + 1:]
                if later.start[0] > token.start[0]
            )
            ends_with_colon = any(
                later.type == tokenize.OP and later.string == ':'
                for later in line_tokens
            )
            if has_case and ends_with_colon:
                return (
                    token.start[0],
                    token.start[1] + 1,
                    'match statements are not available in Python 2',
                )

        if token.string == 'raise':
            line_end = token.start[0]
            for later in tokens[index + 1:]:
                if later.start[0] != line_end:
                    break
                if later.type == tokenize.NAME and later.string == 'from':
                    return (
                        token.start[0],
                        token.start[1] + 1,
                        'raise ... from is not available in Python 2',
                    )

        if token.string == 'class' and _class_uses_metaclass(
                tokens, index):
            return (
                token.start[0],
                token.start[1] + 1,
                'metaclass= is not available in Python 2',
            )

        if token.string == 'def':
            header_violation = _function_header_violation(
                tokens, index
            )
            if header_violation is not None:
                return header_violation

    # Some valid Python 2 code has no Python 3 equivalent and is not covered
    # by the token checks above.  The caller only reaches this function when
    # it is considering Python 2, so a successful lib2to3 parse is sufficient.
    return None


def _parenthesized_with_violation(source):
    tokens = list(_generate_tokens(source))
    for index, token in enumerate(tokens):
        if token.type != tokenize.NAME or token.string != 'with':
            continue
        next_token = _next_significant(tokens, index)
        if (next_token is None
                or next_token.type != tokenize.OP
                or next_token.string != '('):
            continue
        depth = 0
        for inner in tokens[index + 1:]:
            if inner.type != tokenize.OP:
                continue
            if inner.string == '(':
                depth += 1
            elif inner.string == ')':
                depth -= 1
                if depth <= 0:
                    break
            elif inner.string == ',' and depth == 1:
                node = collections.namedtuple(
                    'ParenthesizedWithPosition', ['lineno', 'col_offset']
                )(inner.start[0], inner.start[1])
                return (
                    node,
                    'parenthesized context managers require Python 3.9',
                )
    return None


def _await_outside_async(tree):
    async_types = tuple(
        item for item in (
            getattr(ast, 'Await', None),
            getattr(ast, 'AsyncFor', None),
            getattr(ast, 'AsyncWith', None),
        )
        if item is not None
    )
    async_def = getattr(ast, 'AsyncFunctionDef', None)
    if not async_types or async_def is None:
        return None
    stack = [(tree, False)]
    sync_def = getattr(ast, 'FunctionDef', None)
    lambda_node = getattr(ast, 'Lambda', None)
    while stack:
        node, in_async = stack.pop()
        if isinstance(node, async_def):
            is_async = True
        elif ((sync_def is not None and isinstance(node, sync_def))
                or (lambda_node is not None and isinstance(node, lambda_node))
                or isinstance(node, getattr(ast, 'ClassDef', ()))):
            is_async = False
        else:
            is_async = in_async
        if isinstance(node, async_types) and not in_async:
            return (
                node,
                'async syntax requires an async function context',
            )
        for child in ast.iter_child_nodes(node):
            stack.append((child, is_async))
    return None


def _fstring_debug_violation(source):
    tokens = list(_generate_tokens(source))
    if not tokens:
        return None
    fstring_start = getattr(tokenize, 'FSTRING_START', None)
    fstring_end = getattr(tokenize, 'FSTRING_END', None)
    if fstring_start is None or fstring_end is None:
        match = re.search(
            r'(?is)f(?:r|b|u|br|rb)?[\x22\x27].*?\{[^{}]*=\s*(?:![rsa])?(?::[^{}]*)?\}',
            source,
        )
        if match is None:
            return None
        equals = source.find('=', match.start(), match.end())
        if equals < 0:
            return None
        node = collections.namedtuple(
            'FStringDebugPosition', ['lineno', 'col_offset']
        )(
            source.count(chr(10), 0, equals) + 1,
            equals - source.rfind(chr(10), 0, equals) - 1,
        )
        return (
            node,
            'f-string debug expressions require Python 3.8',
        )
    depth = 0
    for index, token in enumerate(tokens):
        if token.type == fstring_start:
            depth += 1
            continue
        if token.type == fstring_end:
            depth = max(0, depth - 1)
            continue
        if depth <= 0:
            continue
        if token.type == tokenize.OP and token.string == '=':
            following = _next_significant(tokens, index)
            if (following is not None
                    and following.type == tokenize.OP
                    and following.string == '}'):
                node = collections.namedtuple(
                    'FStringDebugPosition', ['lineno', 'col_offset']
                )(token.start[0], token.start[1])
                return (
                    node,
                    'f-string debug expressions require Python 3.8',
                )
    return None


def _string_prefix(value):
    match = re.match(r'([A-Za-z]*)', value)
    return (match.group(1) if match else '').lower()


def _is_fstring_start(token):
    fstring_start = getattr(tokenize, 'FSTRING_START', None)
    if fstring_start is not None and token.type == fstring_start:
        return True
    return tokenize.tok_name.get(token.type) == 'FSTRING_START'


def _previous_significant(tokens, index):
    for token in reversed(tokens[:index]):
        if token.type in (tokenize.NL, tokenize.COMMENT):
            continue
        return token
    return None


def _next_significant(tokens, index):
    for token in tokens[index + 1:]:
        if token.type in (tokenize.NL, tokenize.COMMENT):
            continue
        return token
    return None


def _in_call_header(tokens, index):
    depth = 0
    for token in tokens[:index]:
        if token.type == tokenize.OP:
            if token.string == '(':
                depth += 1
            elif token.string == ')':
                depth = max(0, depth - 1)
    return depth > 0


def _class_uses_metaclass(tokens, index):
    depth = 0
    for token in tokens[index + 1:]:
        if token.type == tokenize.OP:
            if token.string == '(':
                depth += 1
            elif token.string == ')':
                depth -= 1
                if depth <= 0:
                    return False
            elif token.string == ':' and depth == 0:
                return False
        if (depth > 0
                and token.type == tokenize.NAME
                and token.string == 'metaclass'):
            return True
    return False


def _function_header_violation(tokens, index):
    depth = 0
    started = False
    for position in range(index + 1, len(tokens)):
        token = tokens[position]
        if token.type == tokenize.OP:
            if token.string == '(':
                depth += 1
                started = True
            elif token.string == ')':
                depth -= 1
                if started and depth == 0:
                    return None
            elif token.string == ':' and depth == 1:
                return (
                    token.start[0],
                    token.start[1] + 1,
                    'parameter annotations are not available in Python 2',
                )
            elif token.string == '*' and depth == 1:
                next_token = _next_significant(tokens, position)
                if next_token is not None and (
                        next_token.type == tokenize.OP
                        and next_token.string in (',', ')')):
                    return (
                        token.start[0],
                        token.start[1] + 1,
                        'keyword-only parameters are not available in Python 2',
                    )
        if token.type == tokenize.NEWLINE and started:
            return None
    return None


def _generate_tokens(source):
    try:
        return list(tokenize.generate_tokens(io.StringIO(source).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return []


_PY2_SOFT_KEYWORD_REPLACEMENTS = {
    'nonlocal': 'n0nl0cal',
    'async': 'asy1c',
    'await': 'awa1t',
}


def _mask_python2_soft_keywords(source):
    replacements = []
    for token in _generate_tokens(source):
        if token.type != tokenize.NAME:
            continue
        replacement = _PY2_SOFT_KEYWORD_REPLACEMENTS.get(token.string)
        if replacement is None:
            continue
        if token.start[0] != token.end[0]:
            continue
        replacements.append((
            token.start[0] - 1,
            token.start[1],
            token.end[1],
            replacement,
        ))
    if not replacements:
        return source

    lines = source.splitlines(True)
    for line_index, start, end, replacement in sorted(
            replacements, reverse=True):
        line = lines[line_index]
        lines[line_index] = line[:start] + replacement + line[end:]
    return ''.join(lines)


_PY2_TOOL = None


def _refactor_python2(source, filename):
    global _PY2_TOOL
    if _PY2_TOOL is None:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', DeprecationWarning)
                from lib2to3 import refactor
            fixers = [
                'lib2to3.fixes.fix_print',
                'lib2to3.fixes.fix_exec',
                'lib2to3.fixes.fix_except',
                'lib2to3.fixes.fix_raise',
                'lib2to3.fixes.fix_ne',
                'lib2to3.fixes.fix_repr',
                'lib2to3.fixes.fix_numliterals',
                'lib2to3.fixes.fix_tuple_params',
                'lib2to3.fixes.fix_xrange',
                'lib2to3.fixes.fix_raw_input',
                'lib2to3.fixes.fix_unicode',
                'lib2to3.fixes.fix_basestring',
                'lib2to3.fixes.fix_standarderror',
            ]
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', DeprecationWarning)
                _PY2_TOOL = refactor.RefactoringTool(fixers)
        except Exception:
            return None

    if not source.endswith('\n'):
        source += '\n'

    try:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', DeprecationWarning)
            return str(_PY2_TOOL.refactor_string(source, filename))
    except Exception:
        return None


def run_linter(code, tree, version=None):
    """Run one Dlint linter against ``tree`` using target-version semantics.

    Returns a list of ``Flake8Result`` objects, or ``None`` if the rule is not
    known to this Dlint installation.
    """
    code = normalize_rule_code(code)
    linter_class = _rule_classes().get(code)
    if linter_class is None:
        return None

    previous_version = sys.version_info
    if version is not None:
        major, minor = normalize_version(version)
        sys.version_info = (major, minor, 0, 'final', 0)
    try:
        linter = linter_class()
        linter.visit(tree)
        return linter.get_results()
    except Exception:
        return None
    finally:
        sys.version_info = previous_version


def normalize_rule_code(value):
    """Normalize a rule code, class name, or module name to ``DUOxxx``."""
    if value is None:
        return None
    if hasattr(value, '_code'):
        return getattr(value, '_code', None)
    if isinstance(value, type):
        return getattr(value, '_code', None)
    if isinstance(value, (int, float)):
        number = int(value)
        if 100 <= number <= 999:
            return 'DUO{}'.format(number)
    text = str(value).strip()
    if not text:
        return None
    if text.isdigit() and len(text) == 3:
        return 'DUO{}'.format(text)
    match = _DUO_CODE_RE.search(text)
    if match:
        return 'DUO' + re.sub(r'[\s_-]+', '', match.group(1))[3:]
    key = text.lower()
    if '.' in key:
        key = key.rsplit('.', 1)[-1]
    classes = _rule_classes()
    for code, linter_class in classes.items():
        if key == linter_class.__name__.lower():
            return code
        module = linter_class.__module__.split('.')[-1].lower()
        if key in (module, module.replace('_linter', '')):
            return code
    return text.upper()


def refresh_rules():
    """Forget cached linter classes and rediscover plugins."""
    _RULE_CLASS_CACHE.clear()
    return known_rule_codes()


def known_rule_codes():
    return tuple(sorted(_rule_classes()))


def _known_rule_codes():
    _rule_classes()
    return _RULE_CLASS_CACHE['codes']


_RULE_CLASS_CACHE = {}


def _rule_classes():
    if 'classes' not in _RULE_CLASS_CACHE:
        from . import linters
        classes = collections.OrderedDict()
        for linter_class in linters.ALL:
            code = getattr(linter_class, '_code', None)
            if code:
                classes[code] = linter_class
        try:
            import importlib
            import inspect
            import pkgutil
            for finder, module_name, is_package in pkgutil.iter_modules():
                if not module_name.startswith('dlint_plugin_'):
                    continue
                module = importlib.import_module(module_name)
                for name, value in inspect.getmembers(
                        module, predicate=inspect.isclass):
                    if not name.startswith('Dlint'):
                        continue
                    code = getattr(value, '_code', None)
                    if code:
                        classes[code] = value
        except Exception:
            pass
        _RULE_CLASS_CACHE['classes'] = classes
        _RULE_CLASS_CACHE['codes'] = tuple(sorted(classes))
    return _RULE_CLASS_CACHE['classes']


def _normalize_selectors(selectors):
    if selectors is None:
        return None
    if selectors is True:
        return None
    if selectors is False:
        return []
    if isinstance(selectors, _STRING_TYPES):
        values = re.split(r'[,\s;]+', _to_text(selectors))
    elif isinstance(selectors, dict):
        values = [
            key for key, enabled in selectors.items()
            if enabled
        ]
    elif isinstance(selectors, type) or not hasattr(selectors, '__iter__'):
        values = [selectors]
    else:
        values = list(selectors)

    result = []
    for value in values:
        if isinstance(value, _STRING_TYPES):
            parts = re.split(r'[,\s;]+', _to_text(value))
        else:
            parts = [value]
        for part in parts:
            normalized = normalize_rule_code(part)
            if normalized and normalized not in result:
                result.append(normalized)
    return result


def _selector_matches(selector, code):
    if code is None:
        return False
    selector = normalize_rule_code(selector)
    code = normalize_rule_code(code)
    if selector in ('*', 'ALL', 'DUO'):
        return True
    if selector == code:
        return True
    # flake8 allows a prefix such as DUO10 or DUO1.
    if selector.startswith('DUO') and code.startswith(selector):
        return True
    return False


def _coerce_sources(sources, filename=None):
    result = collections.OrderedDict()
    if sources is None:
        return result
    path_type = getattr(os, 'PathLike', None)
    if path_type is not None and isinstance(sources, path_type):
        sources = os.fspath(sources)
    if isinstance(sources, SourceScope):
        result[sources.scope] = sources
        return result
    if isinstance(sources, _STRING_TYPES):
        text = _to_text(sources)
        stripped = text.lstrip()
        if stripped.startswith('{'):
            try:
                decoded = json.loads(text)
            except (TypeError, ValueError):
                decoded = None
            if (isinstance(decoded, dict)
                    and not _looks_like_report_payload(decoded)
                    and all(isinstance(value, (str, bytes, dict))
                            for value in decoded.values())):
                return _coerce_sources(decoded, filename=filename)
        source = _maybe_read_source(text)
        scope = filename
        if scope is None:
            try:
                exists = os.path.isfile(text)
            except (IOError, OSError, ValueError, TypeError):
                exists = False
            scope = text if exists else '<source>'
        result[scope] = SourceScope(scope, source, filename=scope)
        return result
    if isinstance(sources, dict):
        for scope, source in sources.items():
            if isinstance(source, SourceScope):
                result[scope] = source
            elif isinstance(source, dict):
                value = _first_present(
                    source,
                    ('source', 'text', 'code', 'content', 'source_text'),
                )
                source_filename = _first_present(
                    source,
                    ('filename', 'path', 'file', 'name'),
                ) or scope
                metadata = dict(
                    (key, value)
                    for key, value in source.items()
                    if key not in (
                        'source', 'text', 'code', 'content', 'source_text',
                        'filename', 'path', 'file', 'name',
                    )
                )
                result[scope] = SourceScope(
                    scope,
                    _maybe_read_source(value),
                    filename=source_filename,
                    metadata=metadata,
                )
            else:
                result[scope] = SourceScope(
                    scope,
                    _maybe_read_source(source),
                    filename=scope,
                )
        return result

    for entry in sources:
        if isinstance(entry, SourceScope):
            result[entry.scope] = entry
            continue
        if isinstance(entry, dict):
            scope = _first_present(
                entry,
                ('scope', 'id', 'name', 'filename', 'path', 'file',
                 'scope_id', 'snippet_id', 'source_id'),
            )
            source = _first_present(
                entry,
                ('source', 'text', 'code', 'content', 'source_text'),
            )
            source_filename = _first_present(
                entry,
                ('filename', 'path', 'file', 'name'),
            ) or scope
            result[scope] = SourceScope(
                scope,
                _maybe_read_source(source),
                filename=source_filename,
            )
            continue
        if isinstance(entry, (tuple, list)) and len(entry) >= 2:
            result[entry[0]] = SourceScope(entry[0], entry[1])
            continue
        if isinstance(entry, _STRING_TYPES):
            text = _to_text(entry)
            try:
                exists = os.path.isfile(text)
            except (IOError, OSError, ValueError, TypeError):
                exists = False
            scope = text if exists else '<snippet-{}>'.format(len(result))
            result[scope] = SourceScope(
                scope,
                _maybe_read_source(entry),
                filename=scope,
            )
            continue
        raise TypeError('unrecognized source entry: {!r}'.format(entry))
    return result


def _load_report_payload(value):
    path_type = getattr(os, 'PathLike', None)
    if path_type is not None and isinstance(value, path_type):
        value = os.fspath(value)
    if not isinstance(value, _STRING_TYPES):
        return None
    text = _to_text(value)
    if '\n' not in text and '\r' not in text:
        try:
            if os.path.isfile(text):
                with io.open(text, 'rb') as report_file:
                    text = _to_text(report_file.read())
        except (IOError, OSError, ValueError, UnicodeError):
            return None
    stripped = text.lstrip()
    if not stripped.startswith(('{', '[')):
        return None
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return None


def _looks_like_report_collection(value):
    if isinstance(value, dict):
        if _looks_like_report_payload(value):
            return True
        return any(
            key in value
            for key in ('lineno', 'line', 'line_number', 'start_line')
        )
    if isinstance(value, _STRING_TYPES):
        text = _to_text(value)
        if '\n' in text or '\r' in text:
            return any(
                _SOURCE_RE.match(line.strip())
                for line in text.splitlines()
                if line.strip()
            )
        return bool(_SOURCE_RE.match(text.strip()))
    if isinstance(value, (list, tuple)) and value:
        first = value[0]
        if isinstance(first, dict):
            return any(
                key in first
                for key in ('lineno', 'line', 'line_number', 'start_line')
            )
        if isinstance(first, (tuple, list)) and first:
            return isinstance(first[0], int)
        if isinstance(first, _STRING_TYPES):
            return bool(_SOURCE_RE.match(_to_text(first).strip()))
    return False


def _looks_like_report_payload(value):
    payload_keys = (
        'sources', 'files', 'file_sources', 'sources_by_scope',
        'results', 'findings', 'items', 'report',
        'report_items', 'dlint_results',
    )
    if isinstance(value, dict):
        return any(key in value for key in payload_keys)
    if isinstance(value, _STRING_TYPES):
        text = _to_text(value).lstrip()
        if not text.startswith(('{', '[')):
            return False
        try:
            decoded = json.loads(text)
        except (TypeError, ValueError):
            return False
        return isinstance(decoded, dict) and any(
            key in decoded for key in payload_keys
        )
    return False


def _coerce_report_items(report):
    if report is None:
        return []
    path_type = getattr(os, 'PathLike', None)
    if path_type is not None and isinstance(report, path_type):
        report = os.fspath(report)
    if isinstance(report, ReportItem):
        return [report]
    if isinstance(report, _STRING_TYPES):
        text = _to_text(report)
        if '\n' not in text and '\r' not in text:
            try:
                if os.path.isfile(text):
                    with io.open(text, 'rb') as report_file:
                        text = _to_text(report_file.read())
            except (IOError, OSError, ValueError, UnicodeError):
                pass
        stripped = text.lstrip()
        if stripped.startswith(('{', '[')):
            try:
                return _coerce_report_items(json.loads(text))
            except (TypeError, ValueError):
                pass
        lines = [line for line in text.splitlines() if line.strip()]
        if len(lines) > 1:
            return [_parse_report_string(line) for line in lines]
        return [_parse_report_string(text)]
    if isinstance(report, dict):
        if _looks_like_report_item(report):
            return [_parse_report_item(report)]
        return _report_mapping_to_items(report)
    if _looks_like_report_item(report):
        return [_parse_report_item(report)]

    result = []
    for entry in report:
        if isinstance(entry, ReportItem):
            result.append(entry)
        elif isinstance(entry, dict):
            result.append(_parse_report_item(entry))
        elif isinstance(entry, (tuple, list)):
            result.append(_parse_report_item(entry))
        else:
            result.append(_parse_report_item(entry))
    return result


def _report_mapping_to_items(report):
    result = []
    for key, value in report.items():
        if key in ('results', 'findings', 'items', 'report'):
            result.extend(_coerce_report_items(value))
        elif isinstance(value, (list, tuple)):
            for entry in value:
                item = _parse_report_item(entry)
                if item.filename is None:
                    item.filename = key
                    item.scope = item.scope or key
                result.append(item)
        elif isinstance(value, dict):
            item = _parse_report_item(value)
            if item.filename is None:
                item.filename = key
                item.scope = item.scope or key
            result.append(item)
    return result


def _looks_like_report_item(value):
    if isinstance(value, ReportItem):
        return True
    if isinstance(value, dict):
        return any(
            key in value
            for key in (
                'lineno', 'line', 'line_number', 'col_offset', 'column',
                'code', 'rule', 'message', 'issue_text',
            )
        )
    if isinstance(value, (tuple, list)):
        if len(value) in (3, 4, 5) and isinstance(value[0], int):
            return True
        return (
            len(value) in (4, 5)
            and isinstance(value[0], _STRING_TYPES)
            and isinstance(value[1], int)
        )
    return hasattr(value, 'lineno') or hasattr(value, 'line_number')


def _parse_report_item(value):
    if isinstance(value, ReportItem):
        return value
    if isinstance(value, _STRING_TYPES):
        return _parse_report_string(_to_text(value))
    if isinstance(value, dict):
        code_value = _first_present(
            value,
            ('code', 'rule', 'rule_code', 'linter',
             'linter_class', 'check', 'test_id'),
        )
        if code_value is None:
            type_value = value.get('type')
            if (hasattr(type_value, '_code')
                    or (isinstance(type_value, str)
                        and _DUO_CODE_RE.search(type_value))):
                code_value = type_value
        return ReportItem(
            filename=_first_present(
                value,
                ('filename', 'path', 'file', 'file_name', 'name')),
            lineno=_first_present(
                value,
                ('lineno', 'line', 'line_number', 'start_line')),
            col_offset=_first_present(
                value,
                ('col_offset', 'col', 'column', 'column_number', 'start_col')),
            code=code_value,
            message=_first_present(
                value, ('message', 'issue_text', 'text', 'description')),
            scope=_first_present(
                value,
                ('scope', 'fragment', 'snippet',
                 'scope_id', 'snippet_id', 'source_id')),
            source=_first_present(
                value,
                ('source', 'source_text', 'content', 'code_text')),
            raw=value,
        )
    if isinstance(value, (tuple, list)):
        return _parse_report_tuple(value)
    code_value = getattr(
        value, 'code', getattr(value, 'rule_code', None))
    if code_value is None:
        type_value = getattr(value, 'type', None)
        if (hasattr(type_value, '_code')
                or (isinstance(type_value, str)
                    and _DUO_CODE_RE.search(type_value))):
            code_value = type_value
    return ReportItem(
        filename=getattr(
            value, 'filename', getattr(value, 'path', None)),
        lineno=getattr(
            value, 'lineno', getattr(value, 'line', None)),
        col_offset=getattr(
            value, 'col_offset', getattr(value, 'column', None)),
        code=code_value,
        message=getattr(
            value, 'message', getattr(value, 'text', None)),
        scope=getattr(
            value, 'scope', getattr(value, 'scope_id', None)),
        source=getattr(
            value, 'source', getattr(value, 'source_text', None)),
        raw=value,
    )


def _parse_report_tuple(value):
    values = list(value)
    filename = None
    scope = None
    code = None
    message = None
    source = None

    if len(values) == 3:
        lineno, col_offset, message = values
    elif len(values) == 4:
        if isinstance(values[0], str):
            filename, lineno, col_offset, message = values
        else:
            lineno, col_offset, message, linter = values
            code = getattr(linter, '_code', linter)
    elif len(values) == 5:
        filename, lineno, col_offset, message, code = values
    else:
        lineno = values[0] if values else None
        col_offset = values[1] if len(values) > 1 else None
        message = values[2] if len(values) > 2 else None
        code = values[3] if len(values) > 3 else None

    for field in values:
        if isinstance(field, str) and _DUO_CODE_RE.search(field):
            code = code or _DUO_CODE_RE.search(field).group(1)

    return ReportItem(
        filename=filename,
        lineno=lineno,
        col_offset=col_offset,
        code=code,
        message=message,
        scope=scope,
        source=source,
        raw=value,
    )


def _parse_report_string(value):
    match = _SOURCE_RE.match(value.strip())
    if match:
        filename = match.group('filename')
        lineno = int(match.group('lineno'))
        col_offset = match.group('col_offset')
        rest = match.group('rest')
        code_match = _DUO_CODE_RE.search(rest)
        return ReportItem(
            filename=filename,
            lineno=lineno,
            col_offset=int(col_offset) if col_offset else None,
            code=code_match.group(1) if code_match else None,
            message=rest,
            raw=value,
        )

    code_match = _DUO_CODE_RE.search(value)
    return ReportItem(
        lineno=None,
        col_offset=None,
        code=code_match.group(1) if code_match else None,
        message=value,
        raw=value,
    )


def _build_scope_index(sources):
    index = {}
    for scope in sources.values():
        index[scope.scope] = scope.scope
        index[scope.filename] = scope.scope
        index.setdefault(_basename(scope.filename), scope.scope)
    return index


def _resolve_item_scope(item, sources, scope_index):
    if item.scope is not None and item.scope in sources:
        return item.scope
    if item.filename is not None and item.filename in sources:
        return item.filename
    if item.filename is not None and item.filename in scope_index:
        return scope_index[item.filename]
    if item.filename is not None:
        basename = _basename(item.filename)
        if basename in scope_index:
            return scope_index[basename]
        normalized_filename = str(item.filename).replace(chr(92), '/')
        for scope in sources.values():
            normalized_scope = str(scope.filename).replace(chr(92), '/')
            if (normalized_filename.endswith(normalized_scope)
                    or normalized_scope.endswith(normalized_filename)):
                return scope.scope
    if (len(sources) == 1
            and item.filename is None and item.scope is None):
        return next(iter(sources))
    return None


def _basename(path):
    path = str(path).replace('\\', '/')
    return path.rsplit('/', 1)[-1]


def _first_present(mapping, keys):
    for key in keys:
        if key in mapping and mapping[key] is not None:
            return mapping[key]
    return None


def _optional_int(value):
    if value is None or value == '':
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _maybe_read_source(value):
    path_type = getattr(os, 'PathLike', None)
    if path_type is not None and isinstance(value, path_type):
        value = os.fspath(value)
    if not isinstance(value, _STRING_TYPES):
        return value
    text = _to_text(value)
    if '\n' in text or '\r' in text:
        return text
    try:
        if os.path.isfile(text):
            with io.open(text, 'rb') as source_file:
                return _to_text(source_file.read())
    except (IOError, OSError, ValueError, UnicodeError):
        pass
    return text


def _to_text(source):
    text = _to_text_inner(source)
    if isinstance(text, str) and text.startswith('﻿'):
        return text[1:]
    return text


def _to_text_inner(source):
    if isinstance(source, (list, tuple)):
        return '\n'.join(str(part) for part in source)
    if isinstance(source, dict):
        return '\n'.join(
            str(source[key]) for key in sorted(source)
        )
    if hasattr(source, 'read') and callable(source.read):
        return _to_text(source.read())
    if isinstance(source, (bytes, bytearray)):
        source = bytes(source)
        try:
            encoding, _ = tokenize.detect_encoding(
                io.BytesIO(source).readline
            )
        except SyntaxError:
            encoding = 'utf-8'
        try:
            return source.decode(encoding)
        except UnicodeError:
            return source.decode('utf-8', 'replace')
    return source


def main(argv=None):
    """Command-line entry point for the cross-version scope audit."""
    import argparse

    parser = argparse.ArgumentParser(
        description=(
            'Audit a Dlint report against one or more target Python versions.'
        )
    )
    parser.add_argument(
        '--report', '-r',
        help='Report JSON/text file, or - to read standard input.',
    )
    parser.add_argument(
        '--source', '-s', action='append', default=[],
        metavar='PATH', help='Source file to audit (repeatable).',
    )
    parser.add_argument(
        '--source-text', action='append', default=[],
        help='Inline source text to audit (repeatable).',
    )
    parser.add_argument(
        '--version', '-V', action='append', dest='versions',
        metavar='VERSION', help='Target version, e.g. 2.7 or 3.8.',
    )
    parser.add_argument(
        '--target', '-t', '--target-version', action='append',
        dest='versions', metavar='VERSION',
        help='Alias for --version.',
    )
    parser.add_argument(
        '--select', action='append', dest='rules',
        metavar='RULE', help='Rule code or prefix to enable.',
    )
    parser.add_argument(
        '--ignore', action='append', dest='ignored',
        metavar='RULE', help='Rule code or prefix to disable.',
    )
    parser.add_argument(
        '--indent', type=int, default=2, help='JSON indentation width.',
    )
    args = parser.parse_args(argv)

    sources = collections.OrderedDict()
    for path in args.source:
        with io.open(path, 'rb') as source_file:
            sources[path] = _to_text(source_file.read())
    for index, text in enumerate(args.source_text):
        sources['<inline-{}>'.format(index)] = text

    report = None
    if args.report:
        if args.report == '-':
            stdin = getattr(sys.stdin, 'buffer', sys.stdin)
            report = _to_text(stdin.read())
        else:
            report = args.report

    audit_result = audit_scope(
        sources=sources or None,
        report=report,
        versions=args.versions,
        rules=args.rules,
        ignore=args.ignored,
    )
    print(json.dumps(audit_result.to_dict(), indent=args.indent))
    return 0


if __name__ == '__main__':
    sys.exit(main())


audit_sources = scope_audit
classify = audit_scope
evaluate = audit_scope
versions_for_source = checkable_versions
signoff_versions = eligible_versions
runnable_versions = checkable_versions
scope_summary = summarize_scope
version_scope = scope_audit
classify_scope = scope_audit
is_syntax_supported = syntax_supported
supports_syntax = syntax_supported
can_parse = syntax_supported
check_syntax = check_source
summarize = summarize_scope
audit_report_items = scope_audit
check_report = scope_audit
check_scope = scope_audit
classify_report = scope_audit
classify_items = scope_audit
version_audit = audit_scope
summarize_versions = summarize_scope
scopes = audit_scope
analyze = audit_scope
analyze_scope = scope_audit
analyze_report = audit_scope
evaluate_scope = scope_audit
audit_source_scope = scope_audit
scope_report = scope_audit
check_versions = scope_audit


__all__ = [
    'AuditEntry',
    'AuditStatus',
    'AuditResult',
    'AuditSummary',
    'DlintScopeAudit',
    'ELIGIBLE',
    'MISSING_SOURCE',
    'NO_FINDINGS',
    'PythonVersion',
    'RULE_NOT_ENABLED',
    'RULE_NOT_APPLICABLE',
    'RULE_NOT_SUPPORTED',
    'NOT_APPLICABLE',
    'INAPPLICABLE',
    'VERSION_SKIPPED',
    'SKIPPED_STATUSES',
    'STATUS_RULE_NOT_APPLICABLE',
    'ScopeStatus',
    'RULE_VERSION_RANGES',
    'ReportAudit',
    'ReportItem',
    'ReportItems',
    'RuleResult',
    'RuleCodes',
    'SYNTAX_UNSUPPORTED',
    'ScopeAudit',
    'ScopeAuditor',
    'ScopeResult',
    'SourceScope',
    'Status',
    'ALL_STATUSES',
    'STATUSES',
    'SUPPORTED_PYTHON_VERSIONS',
    'SyntaxResult',
    'VersionAudit',
    'audit',
    'audit_report',
    'audit_scope',
    'check_source',
    'eligible_report_items',
    'eligible_versions',
    'is_eligible',
    'can_check',
    'is_applicable',
    'common_eligible_items',
    'checkable_versions',
    'skipped_versions',
    'is_supported',
    'known_rule_codes',
    'main',
    'normalize_rule_code',
    'normalize_status',
    'normalize_version',
    'parse_source',
    'refresh_rules',
    'parse_version',
    'rule_supports_version',
    'run_linter',
    'scope_audit',
    'summarize_report',
    'summarize_scope',
    'supported_versions',
    'syntax_supported',
    'version_string',
    'Audit',
    'AuditReport',
    'CLEAN',
    'DlintScope',
    'DlintAudit',
    'ELIGIBLE_FOR_SIGNOFF',
    'ELIGIBLE_TO_SIGN',
    'RULE_DISABLED',
    'SIGN_OFF',
    'SYNTAX_NOT_SUPPORTED',
    'Scope',
    'ScopeReport',
    'ReportScope',
    'DlintAudit',
    'TargetVersion',
    'VersionScope',
    'VersionScopeAudit',
    'audit_report_items',
    'audit_source',
    'audit_sources',
    'audit_versions',
    'can_parse',
    'check_report',
    'check_scope',
    'classify_items',
    'classify_report',
    'classify_scope',
    'classify',
    'evaluate',
    'versions_for_source',
    'signoff_versions',
    'runnable_versions',
    'is_syntax_supported',
    'supports_syntax',
    'check_syntax',
    'scope_summary',
    'scopes',
    'summarize',
    'summarize_versions',
    'version_audit',
    'version_scope',
]
