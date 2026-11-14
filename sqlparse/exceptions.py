#
# Copyright (C) 2009-2020 the sqlparse authors and contributors
# <see AUTHORS file>
#
# This module is part of python-sqlparse and is released under
# the BSD License: https://opensource.org/licenses/BSD-3-Clause

"""Exceptions used in this package."""


class SQLParseError(Exception):
    """Base class for exceptions in this module."""


class SQLParseLimitError(SQLParseError):
    """Raised when a per-parse resource budget is exhausted.

    The :attr:`limit` names the budget that was exceeded and
    :attr:`consumed` is the position (character offset) in the input that
    had already been consumed when the limit was reached.  The offset allows
    callers to reject a request without re-running the parser.
    """

    def __init__(self, message, limit, consumed=0):
        super().__init__(message)
        self.limit = limit
        self.consumed = consumed
