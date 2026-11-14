"""JOSE errors."""

from typing import Any


class Error(Exception):
    """Generic JOSE Error."""


class DeserializationError(Error):
    """JSON deserialization error."""

    def __str__(self) -> str:
        return "Deserialization error: {0}".format(super().__str__())


class SerializationError(Error):
    """JSON serialization error."""


class KeyAuthorizationError(SerializationError, ValueError):
    """Invalid ACME key authorization input.

    Inherits from :class:`SerializationError` for the JOSE error
    hierarchy and from :class:`ValueError` for callers that treat
    malformed challenge inputs as value errors.

    Messages must never contain account key material; only the nature
    of the invalid input is described.
    """


class UnrecognizedTypeError(DeserializationError):
    """Unrecognized type error.

    :ivar str typ: The unrecognized type of the JSON object.
    :ivar jobj: Full JSON object.

    """

    def __init__(self, typ: str, jobj: Any) -> None:
        self.typ = typ
        self.jobj = jobj
        super().__init__(str(self))

    def __str__(self) -> str:
        return "{0} was not recognized, full message: {1}".format(self.typ, self.jobj)
