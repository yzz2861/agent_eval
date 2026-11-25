"""Exceptions raised by the DSSE release gate (see ``securesystemslib.gate``)."""

from __future__ import annotations

from securesystemslib.exceptions import Error


class PolicyError(Error):
    """Indicate that a release policy is malformed or unsupported."""


class GateInputError(Error):
    """Indicate that the input handed to a release gate is malformed.

    Malformed individual envelopes never raise: they are reported as
    findings on the envelope gate. This error is reserved for inputs that
    make a gate run impossible as a whole (e.g. no envelopes at all).
    """
