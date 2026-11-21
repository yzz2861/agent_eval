#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

from . import base

from .. import xml_parser


class BadXMLParserUseLinter(base.BaseLinter):
    """This linter audits the security decision made for the three finite XML
    parsing entry points: "fromstring", "iterparse", and "parse".

    Decisions are classified as being made at import/build time, on every
    request, or as undetermined. A compatibility import that falls back from
    "defusedxml" to a standard XML parser is reported at the fallback import
    itself.
    """
    off_by_default = False

    _code = 'DUO139'
    _error_tmpl = (
        'DUO139 XML parser security decision requires review: '
        'insecure fallback or undetermined protection'
    )

    report_unknown = True

    def __init__(self, *args, **kwargs):
        self.module_node = None
        self._summary = None

        super(BadXMLParserUseLinter, self).__init__(*args, **kwargs)

    def visit_Module(self, node):
        self.module_node = node

    def _ensure_summary(self):
        if self._summary is not None:
            return

        if self.module_node is None:
            self._summary = xml_parser.XMLParserSummary([])
        else:
            self._summary = xml_parser.summarize_xml_parser_decisions(
                self.module_node
            )

    @property
    def summary(self):
        self._ensure_summary()
        return self._summary

    @property
    def report(self):
        return self.summary

    @property
    def decisions(self):
        return self.summary.decisions

    def audit(self):
        return self.summary

    def get_results(self):
        self._ensure_summary()

        results = []
        seen = set()

        for decision in self.summary.findings():
            if decision.secure is None and not self.report_unknown:
                continue

            key = (decision.lineno, decision.col_offset, self._error_tmpl)
            if key in seen:
                continue

            seen.add(key)
            results.append(
                base.Flake8Result(
                    lineno=decision.lineno,
                    col_offset=decision.col_offset,
                    message=self._error_tmpl,
                )
            )

        return results


class BadXMLFallbackUseLinter(BadXMLParserUseLinter):
    """Compatibility name for the XML parser fallback audit."""


class BadXMLFactoryUseLinter(BadXMLParserUseLinter):
    """Compatibility name for the XML parser factory audit."""


class BadXMLParserFactoryUseLinter(BadXMLParserUseLinter):
    """Compatibility name for the XML parser factory audit."""


class BadDefusedxmlFallbackUseLinter(BadXMLParserUseLinter):
    """Compatibility name for the defusedxml fallback audit."""

