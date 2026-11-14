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


class JWSHeaderError(DeserializationError):
    """Base class for errors detected while merging JWS header layers.

    Subclasses classify the failure so callers can distinguish cross-layer
    header conflicts, algorithm confusion, invalid ``crit`` entries and
    similar attacks without inspecting free-form error messages.

    Error messages intentionally reference header parameter names only and
    never embed header values (in particular ``nonce`` and JWK material).

    """


class HeaderConflictError(JWSHeaderError):
    """A header parameter appears in both the protected and unprotected header.

    Per RFC 7515 the same Header Parameter Name MUST NOT be present in both
    the JWS Protected Header and the JWS Unprotected Header. The duplicate is
    rejected even when both layers carry the same value, so that the origin
    of every merged parameter stays unambiguous.

    """


class HeaderSourceError(JWSHeaderError):
    """A header parameter violates the ACME protected-header source rules.

    RFC 8555 requires the ``alg``, ``kid``, ``jwk``, ``crit``, ``nonce`` and
    ``url`` parameters to be carried in the JWS Protected Header.

    """


class AlgorithmError(JWSHeaderError):
    """The ``alg`` header parameter is missing, empty or unregistered.

    Algorithm names are matched case-sensitively against the JWA registry,
    so casing variants (e.g. ``rs256`` or ``RS256 ``) cannot select a
    different algorithm.

    """


class CriticalHeaderError(JWSHeaderError):
    """The ``crit`` header parameter is malformed or not understood.

    Every name listed in ``crit`` must be present in the same JOSE header and
    must be confirmed against a registry of supported extensions before the
    signature is verified.

    """


class KeySelectorError(JWSHeaderError):
    """The key selection parameters are ambiguous.

    At most one of ``jwk`` and ``kid`` may be present, and an ACME request
    must identify its account key with exactly one of them.

    """
