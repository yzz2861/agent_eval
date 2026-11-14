"""JOSE errors."""

from typing import Any, Optional


class Error(Exception):
    """Generic JOSE Error."""


class DeserializationError(Error):
    """JSON deserialization error."""

    def __str__(self) -> str:
        return "Deserialization error: {0}".format(super().__str__())


class SerializationError(Error):
    """JSON serialization error."""


class IdentifierError(Error):
    """Invalid ACME identifier error.

    The error message deliberately contains only the identifier type,
    its position in the request and a short reason. The offending value
    (and never the full CSR) is not echoed back.

    :ivar str identifier_type: Type of the identifier, e.g. 'dns' or 'ip'.
    :ivar str reason: Short human readable reason for the failure.
    :ivar int position: Position of the identifier in the request,
        or None if not applicable.

    """

    def __init__(self, identifier_type: str, reason: str, position: Optional[int] = None) -> None:
        self.identifier_type = identifier_type
        self.reason = reason
        self.position = position
        super().__init__(str(self))

    def __str__(self) -> str:
        if self.position is not None:
            return "Invalid {0} identifier at position {1}: {2}".format(
                self.identifier_type, self.position, self.reason
            )
        return "Invalid {0} identifier: {1}".format(self.identifier_type, self.reason)


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
