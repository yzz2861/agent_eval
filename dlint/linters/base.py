#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import ast
import collections

from .. import namespace

Flake8Result = collections.namedtuple(
    'Flake8Result',
    ['lineno', 'col_offset', 'message']
)


class BaseLinter(ast.NodeVisitor):
    _python_versions = None
    python_versions = None
    _min_python_version = None
    _max_python_version = None

    @classmethod
    def supports_version(cls, version):
        """Return whether this rule applies to ``version``.

        The authoritative bounds live in :mod:`dlint.scope`; this convenience
        method lets integrations query a linter class directly.
        """
        from .. import scope

        return scope.rule_supports_version(cls._code, version)

    def __init__(self, *args, **kwargs):
        self.results = []
        self.namespace = None

        super(BaseLinter, self).__init__(*args, **kwargs)

    def get_results(self):

        return self.results

    def visit(self, node):
        if not self.namespace:
            # In MultiNodeVisitor runs this will have already been set since
            # the namespace remains the same for each linter. However, during
            # testing or single-linter runs we still need to initialize the
            # namespace for the linter.
            self.namespace = namespace.Namespace.from_module_node(node)

        super(BaseLinter, self).visit(node)
