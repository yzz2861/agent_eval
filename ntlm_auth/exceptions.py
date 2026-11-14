# Copyright: (c) 2018, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)


class NoAuthContextError(Exception):
    pass


class NtlmMessageError(Exception):
    """Base class for NTLM message parsing and MIC verification errors."""
    pass


class MicNotNegotiatedError(NtlmMessageError):
    """Raised when the protocol exchange did not negotiate a MIC.

    The CHALLENGE_MESSAGE TargetInfo did not contain an MsvAvFlags value
    advertising MsvAvFlags.MIC_PROVIDED, so neither peer is expected to
    produce or validate a MIC.
    """
    pass


class MicMissingError(NtlmMessageError):
    """Raised when a MIC was negotiated but the message contains none."""
    pass


class MicMismatchError(NtlmMessageError):
    """Raised when the MIC in the message does not match the recomputed MIC.

    This also covers truncated MIC fields and any tampering with the raw
    NEGOTIATE_MESSAGE, CHALLENGE_MESSAGE or AUTHENTICATE_MESSAGE bytes.
    """
    pass
