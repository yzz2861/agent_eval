# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

# TODO: Add module docstring and remove pylint exemption in in-toto/in-toto#126
# pylint: disable=missing-docstring
from securesystemslib.exceptions import Error


class SignatureVerificationError(Error):
    """Indicates a signature verification Error."""


class LayoutExpiredError(Error):
    """Indicates that the layout expired."""


class RuleVerificationError(Error):
    """Indicates that artifact rule verification failed."""


class ThresholdVerificationError(Error):
    """Indicates that signature threshold verification failed."""


class BadReturnValueError(Error):
    """Indicates that a ran command exited with non-int or non-zero return
    value."""


class LinkNotFoundError(Error):
    """Indicates that a link file was not found."""


class UnsupportedKeyTypeError(Error):
    """Indicates that the specified key type is not yet supported."""


class PrefixError(Error):
    """Indicates that there is an error because of the prefixes passed."""


class InvalidMetadata(Error):  # noqa: N818
    """Indicates that the metadata is not valid."""


class RejectionTicketError(Error):
    """Indicates that an offline rejection ticket is malformed or invalid."""


class OfflineVerificationError(Error):
    """Raised when offline verification has unmet signatures or rejections."""

    def __init__(self, message="Offline verification failed", report=None):
        super().__init__(message)
        self.report = report


class RejectionVerificationError(OfflineVerificationError):
    """Offline verification failed because a rejection remains active."""


class RejectedArtifactError(RejectionVerificationError):
    """A verified rejection ticket blocks the bound artifact."""


class ActiveRejectionError(RejectionVerificationError):
    """One or more currently valid rejection tickets remain."""


OfflineVerificationFailed = OfflineVerificationError
