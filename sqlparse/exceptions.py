#
# Copyright (C) 2009-2020 the sqlparse authors and contributors
# <see AUTHORS file>
#
# This module is part of python-sqlparse and is released under
# the BSD License: https://opensource.org/licenses/BSD-3-Clause

"""Exceptions used in this package."""


class SQLParseError(Exception):
    """Base class for exceptions in this module."""


class SQLStreamError(SQLParseError):
    """Base class for errors raised while parsing streamed input."""


class UnclosedTokenError(SQLStreamError):
    """Raised when streamed input ends inside an unterminated token.

    A token such as a quoted string, a dollar-quoted literal or a
    multiline comment was opened but never closed before the input
    stream was exhausted.
    """


class StreamLimitExceededError(SQLStreamError):
    """Raised when a configured streaming size limit is exceeded.

    Either a single unterminated token or a single not yet completed
    statement grew beyond the configured maximum size.  The error is
    raised instead of accumulating more input without bounds.
    """
