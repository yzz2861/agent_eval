# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Tests for the revocation and replacement proof metadata models."""

import unittest

from securesystemslib.exceptions import FormatError

from in_toto.models.revocation import ReplacementProof, Revocation

HASHES = {"sha256": "a" * 64}


class TestRevocation(unittest.TestCase):
    """Test Revocation construction, reading and validation."""

    def _kwargs(self):
        return {
            "revocation_id": "rev-1",
            "artifact_path": "foo/bar.tar.gz",
            "artifact_hashes": dict(HASHES),
            "scope": ["package"],
            "release_id": "release-42",
            "expires": "2030-01-01T00:00:00Z",
            "reason": "known vulnerable build",
        }

    def test_read_and_defaults(self):
        """A minimal revocation gets default scope, release and reason."""
        data = {
            "_type": "revocation",
            "revocation_id": "rev-1",
            "artifact_path": "foo",
            "artifact_hashes": dict(HASHES),
            "expires": "2030-01-01T00:00:00Z",
        }
        revocation = Revocation.read(data)
        self.assertEqual(revocation.type_, "revocation")
        self.assertEqual(revocation.scope, [])
        self.assertEqual(revocation.release_id, "")
        self.assertEqual(revocation.reason, "")
        revocation.validate()

    def test_full_construction(self):
        """All fields round-trip through read and validate."""
        data = {"_type": "revocation"}
        data.update(self._kwargs())
        revocation = Revocation.read(data)
        self.assertEqual(revocation.revocation_id, "rev-1")
        self.assertEqual(revocation.artifact_hashes, HASHES)

    def test_wrong_type(self):
        """A wrong type string fails validation."""
        revocation = Revocation(**self._kwargs())
        revocation._type = "link"
        with self.assertRaises(FormatError):
            revocation.validate()

    def test_bad_identity(self):
        """Non-string identifiers fail validation."""
        revocation = Revocation(**self._kwargs())
        revocation.revocation_id = 42
        with self.assertRaises(FormatError):
            revocation.validate()

    def test_bad_artifact_hashes(self):
        """Malformed hash dictionaries fail validation."""
        revocation = Revocation(**self._kwargs())
        revocation.artifact_hashes = {"sha256": "not-hex"}
        with self.assertRaises(FormatError):
            revocation.validate()

    def test_bad_scope(self):
        """A non-list scope fails validation."""
        revocation = Revocation(**self._kwargs())
        revocation.scope = "package"
        with self.assertRaises(FormatError):
            revocation.validate()

    def test_bad_release_id(self):
        """A non-string release id fails validation."""
        revocation = Revocation(**self._kwargs())
        revocation.release_id = 7
        with self.assertRaises(FormatError):
            revocation.validate()


class TestReplacementProof(unittest.TestCase):
    """Test ReplacementProof construction, reading and validation."""

    def _kwargs(self):
        return {
            "proof_id": "proof-1",
            "revocation_id": "rev-1",
            "release_id": "release-42",
            "artifact_path": "foo/bar.tar.gz",
            "artifact_hashes": dict(HASHES),
            "expires": "2030-01-01T00:00:00Z",
        }

    def test_read(self):
        """A proof round-trips through read and validates."""
        data = {"_type": "replacement_proof"}
        data.update(self._kwargs())
        proof = ReplacementProof.read(data)
        self.assertEqual(proof.type_, "replacement_proof")
        self.assertEqual(proof.proof_id, "proof-1")
        proof.validate()

    def test_wrong_type(self):
        """A wrong type string fails validation."""
        proof = ReplacementProof(**self._kwargs())
        proof._type = "revocation"
        with self.assertRaises(FormatError):
            proof.validate()

    def test_bad_identity(self):
        """Non-string identifiers fail validation."""
        proof = ReplacementProof(**self._kwargs())
        proof.release_id = 9
        with self.assertRaises(FormatError):
            proof.validate()

    def test_bad_artifact_hashes(self):
        """Malformed hash dictionaries fail validation."""
        proof = ReplacementProof(**self._kwargs())
        proof.artifact_hashes = "not-a-dict"
        with self.assertRaises(FormatError):
            proof.validate()


if __name__ == "__main__":
    unittest.main()
