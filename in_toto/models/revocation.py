# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  revocation.py

<Purpose>
  Provides signable metadata models for optional, layout-authorized artifact
  revocations and offline replacement proofs.

  A ``Revocation`` invalidates a specific artifact version, identified by its
  path and content hashes, within an explicitly declared validity scope. It does
  not invalidate other versions at the same path.

  A ``ReplacementProof`` binds an acceptable replacement artifact to a release
  order (``release_id``) and to the revocation it supersedes, so that offline
  verification can accept the replacement without contacting any remote
  artifact repository.

  Both objects are usually wrapped in a generic ``Metablock`` for signing,
  serialization and I/O, and their signatures are verified with keys that the
  layout explicitly authorizes for this purpose.
"""

import attr
import securesystemslib.exceptions

from in_toto.formats import _check_hash_dict, _check_str, _check_str_list
from in_toto.models.common import Signable


@attr.s(repr=False, init=False)
class Revocation(Signable):
    """A layout-authorized statement that an artifact version is obsolete.

    A revocation targets one exact artifact version, identified by the
    combination of ``artifact_path`` and ``artifact_hashes``. Other versions
    that happen to be recorded at the same path are not affected.

    Attributes:
      revocation_id: A unique identifier of the revocation statement.
      artifact_path: The path of the artifact whose version is revoked.
      artifact_hashes: A hash dictionary identifying the revoked version.
      scope: The steps and/or inspections within which the revocation is
          valid. An empty list means the whole supply chain (global scope).
      release_id: An optional identifier of the release order the revocation
          is bound to. If present it must match the layout's ``release_id``.
      expires: An ISO-8601 UTC timestamp after which the revocation is invalid.
      reason: An optional human readable description of the revocation.
    """

    _type = attr.ib()
    revocation_id = attr.ib()
    artifact_path = attr.ib()
    artifact_hashes = attr.ib()
    scope = attr.ib()
    release_id = attr.ib()
    expires = attr.ib()
    reason = attr.ib()

    def __init__(self, **kwargs):
        super().__init__()
        self._type = "revocation"
        self.revocation_id = kwargs.get("revocation_id")
        self.artifact_path = kwargs.get("artifact_path")
        self.artifact_hashes = kwargs.get("artifact_hashes")
        self.scope = kwargs.get("scope", [])
        self.release_id = kwargs.get("release_id", "")
        self.expires = kwargs.get("expires")
        self.reason = kwargs.get("reason", "")

        self.validate()

    @property
    def type_(self):
        """The string "revocation" identifying the metadata type."""
        return self._type

    @staticmethod
    def read(data):
        """Creates a Revocation object from its dictionary representation.

        Arguments:
          data: A dictionary with revocation metadata fields.

        Raises:
          securesystemslib.exceptions.FormatError: Passed data is invalid.

        Returns:
          The created Revocation object.
        """
        return Revocation(**data)

    def _validate_type(self):
        """Check that the type string is set to "revocation"."""
        if self._type != "revocation":
            raise securesystemslib.exceptions.FormatError(
                "Invalid Revocation: field `_type` must be set to "
                f"'revocation', got: {self._type}"
            )

    def _validate_identity(self):
        """Check that the identifying string fields are strings."""
        _check_str(self.revocation_id)
        _check_str(self.artifact_path)

    def _validate_artifact_hashes(self):
        """Check that the revoked version is identified by a hash dict."""
        _check_hash_dict(self.artifact_hashes)

    def _validate_scope(self):
        """Check that the scope is a list of supply chain item names."""
        _check_str_list(self.scope)

    def _validate_release_id(self):
        """Check that the release identifier is a string."""
        _check_str(self.release_id)

    def _validate_expires(self):
        """Check that the expiration is a string."""
        _check_str(self.expires)

    def _validate_reason(self):
        """Check that the reason is a string."""
        _check_str(self.reason)


@attr.s(repr=False, init=False)
class ReplacementProof(Signable):
    """Offline evidence that a replacement artifact is acceptable.

    A replacement proof is the only evidence accepted offline for an artifact
    whose original version was revoked. It binds the replacement version to a
    release order (``release_id``) and to the revocation it responds to
    (``revocation_id``).

    Attributes:
      proof_id: A unique identifier of the replacement proof.
      revocation_id: The identifier of the revocation this proof responds to.
      release_id: The identifier of the release order binding this proof.
      artifact_path: The path at which the replacement is delivered.
      artifact_hashes: A hash dictionary identifying the replacement version.
      expires: An ISO-8601 UTC timestamp after which the proof is invalid.
    """

    _type = attr.ib()
    proof_id = attr.ib()
    revocation_id = attr.ib()
    release_id = attr.ib()
    artifact_path = attr.ib()
    artifact_hashes = attr.ib()
    expires = attr.ib()

    def __init__(self, **kwargs):
        super().__init__()
        self._type = "replacement_proof"
        self.proof_id = kwargs.get("proof_id")
        self.revocation_id = kwargs.get("revocation_id")
        self.release_id = kwargs.get("release_id")
        self.artifact_path = kwargs.get("artifact_path")
        self.artifact_hashes = kwargs.get("artifact_hashes")
        self.expires = kwargs.get("expires")

        self.validate()

    @property
    def type_(self):
        """The string "replacement_proof" identifying the metadata type."""
        return self._type

    @staticmethod
    def read(data):
        """Creates a ReplacementProof object from its dictionary representation.

        Arguments:
          data: A dictionary with replacement proof metadata fields.

        Raises:
          securesystemslib.exceptions.FormatError: Passed data is invalid.

        Returns:
          The created ReplacementProof object.
        """
        return ReplacementProof(**data)

    def _validate_type(self):
        """Check that the type string is set to "replacement_proof"."""
        if self._type != "replacement_proof":
            raise securesystemslib.exceptions.FormatError(
                "Invalid ReplacementProof: field `_type` must be set to "
                f"'replacement_proof', got: {self._type}"
            )

    def _validate_identity(self):
        """Check that the identifying string fields are strings."""
        _check_str(self.proof_id)
        _check_str(self.revocation_id)
        _check_str(self.release_id)
        _check_str(self.artifact_path)

    def _validate_artifact_hashes(self):
        """Check that the replacement version is identified by a hash dict."""
        _check_hash_dict(self.artifact_hashes)

    def _validate_expires(self):
        """Check that the expiration is a string."""
        _check_str(self.expires)
