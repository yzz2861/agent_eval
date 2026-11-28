from __future__ import annotations


class Error(Exception):
    pass


class LexerError(Error):
    pass


class ParserError(Error):
    pass


class ResolveError(Error):
    pass


class NullPointerDereference(Error):
    pass


class ArraySizeError(Error):
    pass


class ExpressionParserError(Error):
    pass


class UnknownIdentifierError(ExpressionParserError):
    pass


class RedactionError(Error, ValueError):
    """Raised when a controlled copy cannot be produced without leaking or corrupting data."""


class NonInferableError(RedactionError):
    """Raised when a summary field cannot be safely derived for an external copy."""
