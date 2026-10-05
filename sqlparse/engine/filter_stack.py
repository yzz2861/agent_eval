#
# Copyright (C) 2009-2020 the sqlparse authors and contributors
# <see AUTHORS file>
#
# This module is part of python-sqlparse and is released under
# the BSD License: https://opensource.org/licenses/BSD-3-Clause

"""filter"""

from sqlparse import lexer
from sqlparse.engine import grouping
from sqlparse.engine.statement_splitter import StatementSplitter
from sqlparse.exceptions import SQLParseError
from sqlparse.filters import StripTrailingSemicolonFilter


class FilterStack:
    def __init__(self, strip_semicolon=False, lexer_config=None):
        self.preprocess = []
        self.stmtprocess = []
        self.postprocess = []
        self._grouping = False
        # Resolve the lexer eagerly, at construction time: every token,
        # grouping and formatting step within one run then shares the same
        # immutable rule snapshot, even if the caller keeps mutating the
        # originating builder while iterating the results.
        self.lexer = lexer.resolve_lexer(lexer_config)
        if strip_semicolon:
            self.stmtprocess.append(StripTrailingSemicolonFilter())

    def enable_grouping(self):
        self._grouping = True

    def run(self, sql, encoding=None):
        try:
            stream = self.lexer.get_tokens(sql, encoding)
            # Process token stream
            for filter_ in self.preprocess:
                stream = filter_.process(stream)

            stream = StatementSplitter().process(stream)

            # Output: Stream processed Statements
            for stmt in stream:
                if self._grouping:
                    stmt = grouping.group(stmt)

                for filter_ in self.stmtprocess:
                    filter_.process(stmt)

                for filter_ in self.postprocess:
                    stmt = filter_.process(stmt)

                yield stmt
        except RecursionError as err:
            raise SQLParseError('Maximum recursion depth exceeded') from err
