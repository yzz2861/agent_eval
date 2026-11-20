# Copyright 2026, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Test local quarantine policy enforcement in the ngclient Updater."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
import unittest

from tests.repository_simulator import RepositorySimulator
from tuf.ngclient import (
    QuarantinedTargetError,
    QuarantinePolicy,
    QuarantinePolicyError,
    Updater,
)

METADATA_URL = "https://example.com/metadata/"
TARGETS_URL = "https://example.com/targets/"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _policy_bytes(digest: str, repository: str = METADATA_URL) -> bytes:
    return json.dumps(
        {
            "version": 1,
            "repositories": {repository: {"sha256": [digest]}},
        }
    ).encode()


class TestUpdaterQuarantine(unittest.TestCase):
    """Test quarantine of target content in the client update workflow."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.metadata_dir = os.path.join(self.temp_dir.name, "metadata")
        self.targets_dir = os.path.join(self.temp_dir.name, "targets")
        os.mkdir(self.metadata_dir)
        os.mkdir(self.targets_dir)

        self.sim = RepositorySimulator()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _init_updater(
        self, quarantine_policy: QuarantinePolicy | None = None
    ) -> Updater:
        return Updater(
            self.metadata_dir,
            METADATA_URL,
            self.targets_dir,
            TARGETS_URL,
            self.sim,
            bootstrap=self.sim.signed_roots[0],
            quarantine_policy=quarantine_policy,
        )

    def _add_target(self, content: bytes, path: str) -> None:
        self.sim.targets.version += 1
        self.sim.add_target("targets", content, path)
        self.sim.update_snapshot()

    def test_quarantine_blocks_all_paths_with_same_digest(self) -> None:
        """Acceptance: two paths caching the same digest are both blocked."""
        content = b"compromised artifact"
        self._add_target(content, "path-a.bin")
        self._add_target(content, "path-b.bin")

        updater = self._init_updater()
        info_a = updater.get_targetinfo("path-a.bin")
        info_b = updater.get_targetinfo("path-b.bin")
        assert info_a is not None and info_b is not None

        # Both paths get cached before the incident response
        path_a = updater.download_target(info_a)
        path_b = updater.download_target(info_b)
        self.assertEqual(path_a, updater.find_cached_target(info_a))
        self.assertEqual(path_b, updater.find_cached_target(info_b))

        # Incident team quarantines the digest: policy is loaded locally
        updater.load_quarantine_policy(_policy_bytes(_sha256(content)))

        # Neither cached copy is delivered anymore
        with self.assertLogs("tuf.ngclient.updater", logging.WARNING):
            self.assertIsNone(updater.find_cached_target(info_a))
        with self.assertLogs("tuf.ngclient.updater", logging.WARNING):
            self.assertIsNone(updater.find_cached_target(info_b))

        # Neither path can be re-downloaded and delivered
        with (
            self.assertLogs("tuf.ngclient.updater", logging.WARNING),
            self.assertRaises(QuarantinedTargetError),
        ):
            updater.download_target(info_a)
        with (
            self.assertLogs("tuf.ngclient.updater", logging.WARNING),
            self.assertRaises(QuarantinedTargetError),
        ):
            updater.download_target(info_b)

    def test_rename_does_not_bypass_quarantine(self) -> None:
        """Content identity, not target path, defines the quarantine."""
        content = b"quarantined bytes"
        self._add_target(content, "old-name.bin")

        policy = QuarantinePolicy.from_bytes(_policy_bytes(_sha256(content)))

        # Repository renames the target: same bytes, new path
        self._add_target(content, "new-name.bin")
        # New updater instance (e.g. after app restart): the integrator
        # re-applies their stored policy through the trusted entry point
        updater = self._init_updater(quarantine_policy=policy)
        info = updater.get_targetinfo("new-name.bin")
        assert info is not None

        with (
            self.assertLogs("tuf.ngclient.updater", logging.WARNING),
            self.assertRaises(QuarantinedTargetError),
        ):
            updater.download_target(info)

    def test_same_path_new_digest_still_delivered(self) -> None:
        """Same target path with new content passes normal verification."""
        self._add_target(b"version 1", "target.bin")

        updater = self._init_updater()
        updater.load_quarantine_policy(_policy_bytes(_sha256(b"version 1")))

        # Repository publishes fixed content under the same path
        self._add_target(b"version 2", "target.bin")
        updater = self._init_updater()
        info = updater.get_targetinfo("target.bin")
        assert info is not None

        path = updater.download_target(info)
        self.assertEqual(path, updater.find_cached_target(info))
        with open(path, "rb") as f:
            self.assertEqual(f.read(), b"version 2")

    def test_default_policy_is_tuf_verification_only(self) -> None:
        """Without a policy, valid targets are delivered as before."""
        self._add_target(b"content", "target.bin")

        updater = self._init_updater()
        info = updater.get_targetinfo("target.bin")
        assert info is not None
        path = updater.download_target(info)
        self.assertEqual(path, updater.find_cached_target(info))

    def test_policy_is_scoped_to_repository(self) -> None:
        """Entries for another repository do not affect this updater."""
        content = b"content"
        self._add_target(content, "target.bin")

        updater = self._init_updater()
        updater.load_quarantine_policy(
            _policy_bytes(
                _sha256(content), "https://other.example.com/metadata/"
            )
        )

        info = updater.get_targetinfo("target.bin")
        assert info is not None
        path = updater.download_target(info)
        self.assertEqual(path, updater.find_cached_target(info))

    def test_policy_load_failure_keeps_previous_policy(self) -> None:
        """A failed load is observable and does not clear the old policy."""
        content = b"quarantined bytes"
        self._add_target(content, "target.bin")

        updater = self._init_updater()
        updater.load_quarantine_policy(_policy_bytes(_sha256(content)))
        active_policy = updater.quarantine_policy

        for invalid in (
            b"not json",
            b"{}",
            b'{"version": 2, "repositories": {}}',
            b'{"version": 1, "repositories": []}',
            b'{"version": 1, "repositories": {"r": {"sha256": [""]}}}',
        ):
            with (
                self.assertLogs("tuf.ngclient.updater", logging.ERROR),
                self.assertRaises(QuarantinePolicyError),
            ):
                updater.load_quarantine_policy(invalid)
            # Previous policy is still active
            self.assertIs(updater.quarantine_policy, active_policy)

        info = updater.get_targetinfo("target.bin")
        assert info is not None
        with (
            self.assertLogs("tuf.ngclient.updater", logging.WARNING),
            self.assertRaises(QuarantinedTargetError),
        ):
            updater.download_target(info)

    def test_policy_snapshot_boundary(self) -> None:
        """Old handles keep their snapshot; new attempts see new policy."""
        content = b"content"
        self._add_target(content, "target.bin")

        updater = self._init_updater()
        quarantining = QuarantinePolicy(
            {METADATA_URL: {"sha256": [_sha256(content)]}}
        )
        updater.set_quarantine_policy(quarantining)

        info = updater.get_targetinfo("target.bin")
        assert info is not None
        with (
            self.assertLogs("tuf.ngclient.updater", logging.WARNING),
            self.assertRaises(QuarantinedTargetError),
        ):
            updater.download_target(info)

        # Replacing the policy affects new attempts ...
        updater.set_quarantine_policy(QuarantinePolicy())
        path = updater.download_target(info)
        self.assertEqual(path, updater.find_cached_target(info))

        # ... but the old snapshot (old handle) is unchanged
        self.assertTrue(quarantining.is_quarantined(METADATA_URL, info.hashes))

    def test_constructor_accepts_initial_policy(self) -> None:
        content = b"content"
        self._add_target(content, "target.bin")

        policy = QuarantinePolicy(
            {METADATA_URL: {"sha256": [_sha256(content)]}}
        )
        updater = self._init_updater(quarantine_policy=policy)
        self.assertIs(updater.quarantine_policy, policy)

        info = updater.get_targetinfo("target.bin")
        assert info is not None
        with (
            self.assertLogs("tuf.ngclient.updater", logging.WARNING),
            self.assertRaises(QuarantinedTargetError),
        ):
            updater.download_target(info)


class TestQuarantinePolicy(unittest.TestCase):
    """Test QuarantinePolicy parsing and matching."""

    def test_matching_normalizes_url_and_digest_case(self) -> None:
        digest = _sha256(b"content")
        policy = QuarantinePolicy(
            {"https://example.com/metadata": {"sha256": [digest.upper()]}}
        )
        # Repository URL without trailing slash and upper-case digest
        # still match
        self.assertTrue(
            policy.is_quarantined(
                "https://example.com/metadata", {"sha256": digest}
            )
        )
        self.assertFalse(
            policy.is_quarantined(
                "https://example.com/metadata", {"sha256": _sha256(b"x")}
            )
        )
        self.assertFalse(
            policy.is_quarantined(
                "https://other.example.com/metadata/", {"sha256": digest}
            )
        )

    def test_from_bytes_roundtrip(self) -> None:
        digest = _sha256(b"content")
        policy = QuarantinePolicy.from_bytes(_policy_bytes(digest))
        self.assertEqual(len(policy), 1)
        self.assertTrue(policy.is_quarantined(METADATA_URL, {"sha256": digest}))

    def test_from_bytes_rejects_invalid_data(self) -> None:
        for invalid in (
            b"not json",
            b'"just a string"',
            b"{}",
            b'{"version": 2, "repositories": {}}',
            b'{"version": 1}',
            b'{"version": 1, "repositories": []}',
            b'{"version": 1, "repositories": {"r": []}}',
            b'{"version": 1, "repositories": {"r": {"sha256": "x"}}}',
            b'{"version": 1, "repositories": {"r": {"sha256": [""]}}}',
        ):
            with self.assertRaises(QuarantinePolicyError):
                QuarantinePolicy.from_bytes(invalid)


if __name__ == "__main__":
    unittest.main()
