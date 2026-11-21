#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import unittest

import dlint


class TestBadXMLParserUse(dlint.test.base.BaseTest):

    def run_linter(self, snippet):
        python_node = self.get_ast_node(snippet)
        linter = dlint.linters.BadXMLParserUseLinter()
        linter.visit(python_node)
        return linter

    def test_insecure_compatibility_fallback(self):
        linter = self.run_linter(
            """
            try:
                from defusedxml.ElementTree import fromstring
            except ImportError:
                from xml.etree.ElementTree import fromstring

            def load(stream):
                return fromstring(stream)
            """
        )

        result = linter.get_results()
        expected = [
            dlint.linters.base.Flake8Result(
                lineno=5,
                col_offset=4,
                message=dlint.linters.BadXMLParserUseLinter._error_tmpl
            ),
        ]

        assert result == expected
        assert linter.summary.by_entry_point['fromstring'][0].fallback

    def test_insecure_compatibility_module_fallback(self):
        linter = self.run_linter(
            """
            try:
                import defusedxml.ElementTree as ET
            except ImportError:
                import xml.etree.ElementTree as ET

            def load(stream):
                return ET.fromstring(
                    stream,
                    forbid_dtd=True,
                    forbid_entities=True,
                    forbid_external=True,
                )
            """
        )

        result = linter.get_results()
        expected = [
            dlint.linters.base.Flake8Result(
                lineno=5,
                col_offset=4,
                message=dlint.linters.BadXMLParserUseLinter._error_tmpl
            ),
        ]

        assert result == expected

    def test_per_request_decision_is_secure(self):
        linter = self.run_linter(
            """
            from defusedxml.ElementTree import fromstring

            def load(stream):
                return fromstring(
                    stream,
                    forbid_dtd=True,
                    forbid_entities=True,
                    forbid_external=True,
                )
            """
        )

        assert linter.get_results() == []

        decisions = linter.summary.by_entry_point['fromstring']
        assert len(decisions) == 1
        assert decisions[0].scope == dlint.xml_parser.PER_REQUEST
        assert decisions[0].secure is True

    def test_import_build_time_parser_decision(self):
        linter = self.run_linter(
            """
            from defusedxml.ElementTree import XMLParser
            from defusedxml.ElementTree import fromstring

            PARSER = XMLParser(
                forbid_dtd=True,
                forbid_entities=True,
                forbid_external=True,
            )

            def load(stream):
                return fromstring(stream, parser=PARSER)
            """
        )

        assert linter.get_results() == []

        decisions = linter.summary.by_entry_point['fromstring']
        assert len(decisions) == 1
        assert decisions[0].scope == dlint.xml_parser.IMPORT_BUILD_TIME
        assert decisions[0].secure is True

    def test_unknown_decision_requires_review(self):
        linter = self.run_linter(
            """
            from defusedxml.ElementTree import fromstring

            def load(stream, **options):
                return fromstring(stream, **options)
            """
        )

        result = linter.get_results()
        expected = [
            dlint.linters.base.Flake8Result(
                lineno=5,
                col_offset=11,
                message=dlint.linters.BadXMLParserUseLinter._error_tmpl
            ),
        ]

        assert result == expected

        decisions = linter.summary.by_entry_point['fromstring']
        assert decisions[0].scope == dlint.xml_parser.UNKNOWN
        assert decisions[0].secure is None

    def test_three_entry_points_are_always_summarized(self):
        linter = self.run_linter(
            """
            import json
            """
        )

        assert linter.get_results() == []
        assert list(linter.summary.by_entry_point) == [
            'fromstring',
            'iterparse',
            'parse',
        ]

    def test_unaliased_import_resolves_full_module_path(self):
        linter = self.run_linter(
            """
            import xml.etree.ElementTree

            def load(stream):
                return xml.etree.ElementTree.fromstring(stream)
            """
        )

        result = linter.get_results()
        expected = [
            dlint.linters.base.Flake8Result(
                lineno=5,
                col_offset=11,
                message=dlint.linters.BadXMLParserUseLinter._error_tmpl
            ),
        ]

        assert result == expected

    def test_lxml_import_build_time_parser(self):
        linter = self.run_linter(
            """
            from lxml import etree

            PARSER = etree.XMLParser(resolve_entities=False, no_network=True)

            def load(stream):
                return etree.fromstring(stream, parser=PARSER)
            """
        )

        assert linter.get_results() == []

        decisions = linter.summary.by_entry_point['fromstring']
        assert decisions[0].scope == dlint.xml_parser.IMPORT_BUILD_TIME
        assert decisions[0].secure is True


if __name__ == "__main__":
    unittest.main()
