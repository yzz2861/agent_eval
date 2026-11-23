#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import collections
import fnmatch


def _normalize_codes(codes):
    if not codes:
        return ()

    return tuple(
        code.strip() for code in codes
        if code and str(code).strip()
    )


class RuleConfig(collections.namedtuple(
    'RuleConfig',
    ['select', 'ignore', 'extended_default_select', 'extend_ignore']
)):
    """flake8-style rule selection for one maintenance group.

    Codes match by prefix, e.g. selecting ``DUO`` enables every Dlint rule
    while ignoring ``DUO10`` disables the DUO10x family. A more specific
    rule always overrides a broader prefix.
    """

    __slots__ = ()

    def __new__(cls, select=None, ignore=None,
                extended_default_select=None, extend_ignore=None):
        if extended_default_select is None:
            extended_default_select = ('DUO',)

        return super(RuleConfig, cls).__new__(
            cls,
            _normalize_codes(select),
            _normalize_codes(ignore),
            _normalize_codes(extended_default_select),
            _normalize_codes(extend_ignore),
        )

    @classmethod
    def from_options(cls, options):
        """Build a config from a flake8-style options namespace."""
        return cls(
            select=getattr(options, 'select', None),
            ignore=getattr(options, 'ignore', None),
            extended_default_select=getattr(
                options, 'extended_default_select', ('DUO',)
            ),
            extend_ignore=getattr(options, 'extend_ignore', None),
        )

    @staticmethod
    def _matches(code, pattern):
        if any(char in pattern for char in '*?['):
            return fnmatch.fnmatchcase(code, pattern)

        return code.startswith(pattern)

    def _matching(self, code, patterns):
        return [
            pattern for pattern in patterns
            if self._matches(code, pattern)
        ]

    def is_enabled(self, code):
        selected = self.select + self.extended_default_select
        ignored = self.ignore + self.extend_ignore

        matching_selected = self._matching(code, selected)
        matching_ignored = self._matching(code, ignored)

        if not matching_selected:
            return False

        if not matching_ignored:
            return True

        longest_selected = max(len(pattern) for pattern in matching_selected)
        longest_ignored = max(len(pattern) for pattern in matching_ignored)

        return longest_selected >= longest_ignored


def code_is_selected(code, rule_config):
    """Module-level convenience wrapper around :meth:`RuleConfig.is_enabled`."""
    return rule_config.is_enabled(code)
