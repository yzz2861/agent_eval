#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import argparse
import unittest

from dlint.audit import RuleConfig
from dlint.audit._selection import code_is_selected


class TestRuleConfig(unittest.TestCase):

    def test_default_config_selects_all_dlint_codes(self):
        config = RuleConfig()

        assert config.is_enabled('DUO104')
        assert config.is_enabled('DUO138')
        assert code_is_selected('DUO105', config)

    def test_explicit_select_prefix(self):
        config = RuleConfig(
            select=('DUO10',), extended_default_select=()
        )

        assert config.is_enabled('DUO104')
        assert not config.is_enabled('DUO110')

    def test_ignore_prefix(self):
        config = RuleConfig(
            select=('DUO',), ignore=('DUO10',),
            extended_default_select=()
        )

        assert not config.is_enabled('DUO104')
        assert config.is_enabled('DUO110')

    def test_specific_select_overrides_broader_ignore(self):
        config = RuleConfig(
            select=('DUO', 'DUO104'),
            ignore=('DUO10',),
            extended_default_select=(),
        )

        assert config.is_enabled('DUO104')
        assert not config.is_enabled('DUO105')

    def test_specific_ignore_overrides_broader_select(self):
        config = RuleConfig(
            select=('DUO',),
            ignore=('DUO104',),
            extended_default_select=(),
        )

        assert not config.is_enabled('DUO104')
        assert config.is_enabled('DUO105')

    def test_extend_ignore_accumulates(self):
        config = RuleConfig(
            select=('DUO',),
            extend_ignore=('DUO104',),
            extended_default_select=(),
        )

        assert not config.is_enabled('DUO104')
        assert config.is_enabled('DUO105')

    def test_unselected_code_is_disabled(self):
        config = RuleConfig(
            select=('DUO104',), extended_default_select=()
        )

        assert config.is_enabled('DUO104')
        assert not config.is_enabled('DUO105')

    def test_from_options_namespace(self):
        options = argparse.Namespace(
            select=[],
            ignore=['DUO101'],
            extended_default_select=['DUO'],
            extend_ignore=[],
        )

        config = RuleConfig.from_options(options)

        assert not config.is_enabled('DUO101')
        assert config.is_enabled('DUO104')

    def test_from_options_fills_defaults(self):
        config = RuleConfig.from_options(argparse.Namespace())

        assert config.is_enabled('DUO104')


if __name__ == '__main__':
    unittest.main()
