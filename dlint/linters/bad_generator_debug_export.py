#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

from . import base
from .helpers import generator_debug_export


class BadGeneratorDebugExportLinter(base.BaseLinter):
    """This linter looks for classified sample data flowing out of generators
    into debug exporters that are only allowed to receive public fields.

    Generator outputs, delegated outputs (``yield from``), values supplied via
    ``send``, and final return values are tracked independently.
    """
    off_by_default = False

    _code = 'DUO139'
    _error_tmpl = (
        'DUO139 classified data may reach a public-only debug export'
    )

    def visit_Module(self, node):
        analyzer = generator_debug_export.Analyzer(node)

        for violation in analyzer.run():
            details = '; '.join(
                origin.describe()
                for origin in sorted(
                    violation.origins,
                    key=lambda origin: origin.path_sort_key(),
                )
            )
            message = self._error_tmpl
            if details:
                message = '{} (path: {})'.format(message, details)

            self.results.append(
                base.Flake8Result(
                    lineno=violation.node.lineno,
                    col_offset=violation.node.col_offset,
                    message=message,
                )
            )
