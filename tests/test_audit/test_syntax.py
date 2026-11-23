#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import unittest

import dlint
from dlint.audit import _syntax


class TestSyntaxSupport(unittest.TestCase):

    def assertSupported(self, source, version):
        supported, unsupported = _syntax.is_supported(source, version)
        assert supported, (version, unsupported)

    def assertNotSupported(self, source, version):
        supported, unsupported = _syntax.is_supported(source, version)
        assert not supported, (version, source)
        assert unsupported, version

    def test_python2_print_statement(self):
        source = "print 'legacy'\n"

        self.assertSupported(source, (2, 7))
        self.assertNotSupported(source, (3, 0))
        self.assertNotSupported(source, (3, 8))

        unsupported = _syntax.unsupported_features(source, (3, 8))
        assert unsupported[0]['name'] == 'print_statement'
        assert unsupported[0]['lineno'] == 1

    def test_python2_exec_statement(self):
        source = "exec 'legacy'\n"

        self.assertSupported(source, (2, 7))
        self.assertNotSupported(source, (3, 8))

    def test_python2_backtick_repr(self):
        source = "x = `value`\n"

        self.assertSupported(source, (2, 7))
        self.assertNotSupported(source, (3, 8))

    def test_python2_inequality_alias(self):
        source = "x = 1 <> 2\n"

        self.assertSupported(source, (2, 7))
        self.assertNotSupported(source, (3, 8))

    def test_exec_call_is_not_a_statement(self):
        source = "exec('print(1)')\n"

        self.assertSupported(source, (2, 7))
        self.assertSupported(source, (3, 8))

        features = [name for name, _, _ in _syntax.detect_features(source)[0]]
        assert 'exec_statement' not in features

    def test_async_await(self):
        source = "async def f():\n    await g()\n"

        self.assertNotSupported(source, (3, 4))
        self.assertSupported(source, (3, 5))

    def test_f_strings(self):
        source = 'x = f"value {y}"\n'

        self.assertNotSupported(source, (3, 5))
        self.assertSupported(source, (3, 6))

    def test_variable_annotations(self):
        source = "x: int = 1\n"

        self.assertNotSupported(source, (3, 5))
        self.assertSupported(source, (3, 6))

    def test_walrus_operator(self):
        source = "if (y := f()):\n    pass\n"

        self.assertNotSupported(source, (3, 7))
        self.assertSupported(source, (3, 8))

    def test_match_statement(self):
        source = "match x:\n    case 1:\n        pass\n"

        self.assertNotSupported(source, (3, 9))
        self.assertSupported(source, (3, 10))

    def test_exception_groups(self):
        source = "try:\n    pass\nexcept* ValueError:\n    pass\n"

        self.assertNotSupported(source, (3, 10))
        self.assertSupported(source, (3, 11))

    def test_type_alias_statement(self):
        source = "type Point = tuple[int, int]\n"

        self.assertNotSupported(source, (3, 11))
        self.assertSupported(source, (3, 12))

    def test_plain_source_everywhere(self):
        source = "x = 1\ny = x + 2\n"

        for version in ((2, 7), (3, 5), (3, 8), (3, 12)):
            self.assertSupported(source, version)

    def test_normalize_version_accepts_strings_and_tuples(self):
        assert _syntax.normalize_version((3, 8)) == (3, 8)
        assert _syntax.normalize_version('3.10.2') == (3, 10)
        assert _syntax.normalize_version(2) == (2, 0)

    def test_unsupported_features_include_position(self):
        source = "x = 1\nif (y := f()):\n    pass\n"
        unsupported = _syntax.unsupported_features(source, (3, 7))

        assert len(unsupported) == 1
        feature = unsupported[0]
        assert feature['name'] == 'walrus_operator'
        assert feature['lineno'] == 2
        assert feature['min_version'] == (3, 8)


if __name__ == '__main__':
    unittest.main()
