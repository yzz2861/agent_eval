"""
Exceptions used in hpack.
"""
from __future__ import annotations


class HPACKError(Exception):
    """
    The base class for all ``hpack`` exceptions.
    """


class HPACKEncodingError(HPACKError):
    """
    An error has been encountered while performing HPACK encoding.

    .. versionadded:: 4.3.0
    """


class SecurityDomainMismatchError(HPACKEncodingError, ValueError):
    """
    An encoder was asked to reuse compression state across security domains.

    HPACK compression state is shared by every header block encoded on a
    connection. Applications that use the encoder for requests belonging to
    different security domains must start a fresh compression context with
    :meth:`hpack.Encoder.reset` before encoding for the new domain.

    .. versionadded:: 4.3.0
    """

    def __init__(
        self,
        current_domain: object | None = None,
        requested_domain: object | None = None,
    ) -> None:
        self.current_domain = current_domain
        self.requested_domain = requested_domain
        self.encoder_domain = current_domain
        self.domain = requested_domain

        if current_domain is None:
            message = (
                "Encoder already contains compression state that is not bound to a "
                f"security domain; refusing to encode for domain {requested_domain!r}. "
                "Call reset(security_domain=...) to start a fresh compression context."
            )
        else:
            message = (
                f"Encoder compression state is bound to security domain {current_domain!r}, "
                f"but a header block for domain {requested_domain!r} was requested. "
                "Call reset(security_domain=...) to start a fresh compression context."
            )

        super().__init__(message)


# Keep the exception easy to discover for callers that use domain-oriented
# terminology rather than the full "security domain" name.
DomainMismatchError = SecurityDomainMismatchError
CompressionDomainMismatchError = SecurityDomainMismatchError
CompressionContextMismatchError = SecurityDomainMismatchError
ContextDomainMismatchError = SecurityDomainMismatchError
SecurityDomainError = SecurityDomainMismatchError



class HPACKDecodingError(HPACKError):
    """
    An error has been encountered while performing HPACK decoding.
    """



class InvalidTableIndexError(HPACKDecodingError):
    """
    An invalid table index was received.

    .. versionadded:: 4.1.0
    """

class InvalidTableIndex(InvalidTableIndexError):  # noqa: N818
    """
    An invalid table index was received.

    .. deprecated:: 4.1.0
       Renamed to :class:`InvalidTableIndexError`, use it instead.
    """


class OversizedHeaderListError(HPACKDecodingError):
    """
    A header list that was larger than we allow has been received. This may be
    a DoS attack.

    .. versionadded:: 2.3.0
    """


class InvalidTableSizeError(HPACKDecodingError):
    """
    An attempt was made to change the decoder table size to a value larger than
    allowed, or the list was shrunk and the remote peer didn't shrink their
    table size.

    .. versionadded:: 3.0.0
    """
