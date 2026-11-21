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


class SeparationOfDutiesError(Error):
    """Indicates that cross-layout separation of duties verification failed.

    Attributes:
      conflicts: A list of confirmed conflicts. Each conflict is a minimal
          combination of steps (a pair) in different layouts that were signed
          by different keys of the same entity.
      suspensions: A list of cross-layout step pairs whose independence could
          not be assessed, because at least one signing key is not mapped to
          an entity.
    """

    def __init__(self, message, conflicts=None, suspensions=None):
        super().__init__(message)
        self.conflicts = conflicts if conflicts is not None else []
        self.suspensions = suspensions if suspensions is not None else []


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
