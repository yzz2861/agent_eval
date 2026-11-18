#!/usr/bin/env python

# Reusable linter base class that turns a dlint.flow.RuleSpec into flake8
# results. Concrete rules only declare a RuleSpec and a message template; the
# base walks every scope (module plus each function), runs the control flow
# analysis and reports deterministically ordered findings.

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import abc
import ast

from .. import base
from ... import util
from ...flow import FlowVerdict, analyze_function


class FlowAnalysisLinter(base.BaseLinter, util.ABC):
    # Subclasses provide a RuleSpec describing source/validator/sink names.

    @property
    @abc.abstractmethod
    def rule_spec(self):
        pass

    def visit_Module(self, node):
        findings = []
        findings.extend(self._analyze_scope(node))

        for scope in self._iter_scopes(node):
            findings.extend(self._analyze_scope(scope))

        # Deterministic output regardless of scope traversal order.
        findings.sort(key=lambda result: (
            result.lineno, result.col_offset, result.message
        ))
        self.results.extend(findings)
        self.generic_visit(node)

    def _iter_scopes(self, module):
        for node in ast.walk(module):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                yield node

    def _analyze_scope(self, scope):
        result = analyze_function(scope, self.rule_spec)
        if result.verdict == FlowVerdict.SAFE:
            return []

        col_offset = self._sink_col_offset(scope, result.sink_lineno)
        message = self._format_message(result)
        return [
            base.Flake8Result(
                lineno=result.sink_lineno or 1,
                col_offset=col_offset,
                message=message,
            )
        ]

    def _format_message(self, result):
        sink = result.sink_name or "sink"
        if result.verdict == FlowVerdict.UNKNOWN:
            return self._unknown_tmpl.format(sink=sink)
        evidence = ", ".join(result.evidence) if result.evidence else "entry"
        return self._error_tmpl.format(sink=sink, evidence=evidence)

    @staticmethod
    def _sink_col_offset(scope, lineno):
        for node in ast.walk(scope):
            if (
                isinstance(node, ast.Call)
                and getattr(node, "lineno", None) == lineno
            ):
                return node.col_offset
        return 0
