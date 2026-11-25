"""Unit tests for custody manifest serialization and approval state."""

import os
import tempfile
import unittest

from oletools.custody.manifest import (
    APPROVAL_ACTIVE,
    APPROVAL_REVOKED,
    Approval,
    CustodyManifest,
    Observation,
    REASON_OBJECT_MOVED,
    sha256_bytes,
)


class TestObservation(unittest.TestCase):

    def test_location_match_detects_move(self):
        first = Observation('zip-1', 'zip-member', 'word/embeddings/a.bin',
                            100, 50, False)
        moved = Observation('zip-1', 'zip-member', 'word/embeddings/a.bin',
                            200, 50, False)
        same = Observation('zip-1', 'zip-member', 'word/embeddings/a.bin',
                           100, 50, False)
        self.assertTrue(first.location_matches(same))
        self.assertFalse(first.location_matches(moved))

    def test_dict_round_trip(self):
        obs = Observation('ole-3', 'ole-stream', 'Data', 512, 4096, True,
                          container='ole', detail={'sid': 3})
        rebuilt = Observation.from_dict(obs.to_dict())
        self.assertEqual(rebuilt.object_id, obs.object_id)
        self.assertEqual(rebuilt.detail['sid'], 3)
        self.assertTrue(rebuilt.has_macros)


class TestApproval(unittest.TestCase):

    def test_revoke_is_explicit(self):
        approval = Approval('ap-1', 'zip-1', 'a.bin', 10, 20,
                            content_digest=sha256_bytes(b'x'))
        self.assertEqual(approval.status, APPROVAL_ACTIVE)
        self.assertTrue(approval.is_active)
        approval.revoke(REASON_OBJECT_MOVED, '2026-11-23T00:00:00+00:00')
        self.assertEqual(approval.status, APPROVAL_REVOKED)
        self.assertEqual(approval.revoke_reason, REASON_OBJECT_MOVED)
        self.assertFalse(approval.is_active)


class TestManifest(unittest.TestCase):

    def test_json_round_trip_preserves_state(self):
        manifest = CustodyManifest(
            source_path='/tmp/sample.docx',
            root_digest=sha256_bytes(b'root'), root_size=128,
            observations=[Observation('zip-0', 'zip-member', 'a', 0, 1,
                                      False)])
        approval = Approval('ap-1', 'zip-0', 'a', 0, 1)
        approval.revoke(REASON_OBJECT_MOVED, '2026-11-23T00:00:00+00:00')
        manifest.approvals.append(approval)
        manifest.add_history({'event': 'sealed'})

        path = tempfile.mktemp(suffix='.json')
        try:
            manifest.save(path)
            rebuilt = CustodyManifest.load(path)
        finally:
            os.unlink(path)
        self.assertEqual(rebuilt.root_digest, manifest.root_digest)
        self.assertEqual(len(rebuilt.observations), 1)
        self.assertEqual(len(rebuilt.approvals), 1)
        self.assertEqual(rebuilt.approvals[0].status, APPROVAL_REVOKED)
        self.assertEqual(rebuilt.approvals[0].revoke_reason,
                         REASON_OBJECT_MOVED)
        self.assertEqual(rebuilt.history, [{'event': 'sealed'}])
        self.assertEqual(rebuilt.active_approvals(), [])


if __name__ == '__main__':
    unittest.main()
