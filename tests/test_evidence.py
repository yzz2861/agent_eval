"""
Tests for olefile.evidence (offline evidence query)
"""

from __future__ import print_function
import unittest

import hashlib
import json
import os
import shutil
import sys
import tempfile

# Insert the olefile package relative to this test dir in the sys.path
# to make sure we test the right one, in case another olefile version
# is also installed in the main python path.
_thismodule_dir = os.path.normpath(os.path.abspath(os.path.dirname(__file__)))
_parent_dir = os.path.normpath(os.path.join(_thismodule_dir, '..'))
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)

import olefile
from olefile.evidence import (
    EvidenceIndex,
    ExcerptRecord,
    CLEARANCE_HANDOVER,
    CLEARANCE_RESTRICTED,
    CLEARANCE_CUSTODIAN,
)


OLE_SAMPLE = os.path.join(_thismodule_dir, 'images', 'test-ole-file.doc')

# fixed key so pseudonyms are deterministic within a test run
TEST_KEY = b'evidence-index-test-key'

EVIDENCE_HANDOVER = 'EV-HANDOVER'
EVIDENCE_RESTRICTED = 'EV-RESTRICTED'

# stream present in both documents under the identical name
SHARED_STREAM = '1Table'
# excerpt ranges approved for the shared stream: intersection is
# [1024, 3072)
EXCERPT_A = (0, 4096)
EXCERPT_B = (1024, 2048)
# bytes of the restricted copy are altered inside the intersection
TAMPER_RANGE = (1500, 2000)


def _make_restricted_copy(path):
    'Copy the sample OLE file and alter part of the shared stream.'
    shutil.copy2(OLE_SAMPLE, path)
    ole = olefile.OleFileIO(path, write_mode=True)
    try:
        data = bytearray(ole.openstream(SHARED_STREAM).read())
        start, end = TAMPER_RANGE
        for i in range(start, end):
            data[i] ^= 0xFF
        ole.write_stream(SHARED_STREAM, bytes(data))
    finally:
        ole.close()


class TestEvidenceIndex(unittest.TestCase):
    'Tests for the offline evidence query combining permissions and excerpts'

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix='olefile-evidence-')
        handover_doc = os.path.join(cls.tmpdir, 'handover.doc')
        restricted_doc = os.path.join(cls.tmpdir, 'restricted.doc')
        shutil.copy2(OLE_SAMPLE, handover_doc)
        _make_restricted_copy(restricted_doc)

        index = EvidenceIndex(pseudonym_key=TEST_KEY)
        # root storage approved for handover: visible at CLEARANCE_HANDOVER
        index.register_document(EVIDENCE_HANDOVER, handover_doc,
                                min_clearance=CLEARANCE_CUSTODIAN,
                                handover_allowed=True)
        # restricted copy: only visible at CLEARANCE_RESTRICTED and above
        index.register_document(EVIDENCE_RESTRICTED, restricted_doc,
                                min_clearance=CLEARANCE_RESTRICTED)
        # approved excerpt records (截取记录) for the shared stream
        index.add_excerpt(ExcerptRecord(
            'EXC-A', EVIDENCE_HANDOVER, SHARED_STREAM,
            offset=EXCERPT_A[0], length=EXCERPT_A[1],
            clearance=CLEARANCE_HANDOVER))
        index.add_excerpt(ExcerptRecord(
            'EXC-B', EVIDENCE_RESTRICTED, SHARED_STREAM,
            offset=EXCERPT_B[0], length=EXCERPT_B[1],
            clearance=CLEARANCE_HANDOVER))
        # excerpts for a stream that is byte-identical in both documents
        index.add_excerpt(ExcerptRecord(
            'EXC-C', EVIDENCE_HANDOVER, 'WordDocument',
            offset=0, length=2048, clearance=CLEARANCE_HANDOVER))
        index.add_excerpt(ExcerptRecord(
            'EXC-D', EVIDENCE_RESTRICTED, 'WordDocument',
            offset=0, length=2048, clearance=CLEARANCE_HANDOVER))
        cls.index = index

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_confirmable_range_is_intersection(self):
        'Approved excerpts retained for one stream yield their intersection'
        self.assertEqual(
            self.index.confirmable_range(SHARED_STREAM, CLEARANCE_CUSTODIAN),
            (EXCERPT_B[0], EXCERPT_B[0] + EXCERPT_B[1]))

    def test_same_name_does_not_imply_same_content(self):
        'Identical stream names with different bytes are reported as such'
        result = self.index.query_stream(SHARED_STREAM, CLEARANCE_CUSTODIAN)
        self.assertEqual(len(result['visible']), 2)
        self.assertEqual(result['confirmable_range'],
                         (EXCERPT_B[0], EXCERPT_B[0] + EXCERPT_B[1]))
        self.assertIs(result['content_consistent'], False)
        # the tamper range lies inside the confirmable range, so the two
        # range digests must differ
        self.assertNotEqual(
            result['range_sha256'][EVIDENCE_HANDOVER],
            result['range_sha256'][EVIDENCE_RESTRICTED])

    def test_consistent_content_over_confirmable_range(self):
        'An untampered stream is confirmed identical over the range'
        result = self.index.query_stream('WordDocument', CLEARANCE_CUSTODIAN)
        self.assertEqual(len(result['visible']), 2)
        self.assertIs(result['content_consistent'], True)

    def test_clearance_changes_provenance_index(self):
        'Each clearance level yields a different provenance index'
        handover = self.index.provenance_index(CLEARANCE_HANDOVER)
        restricted = self.index.provenance_index(CLEARANCE_RESTRICTED)
        custodian = self.index.provenance_index(CLEARANCE_CUSTODIAN)

        handover_ids = set(e['evidence_id'] for e in handover['entries'])
        custodian_ids = set(e['evidence_id'] for e in custodian['entries'])
        self.assertEqual(handover_ids, set([EVIDENCE_HANDOVER]))
        self.assertEqual(custodian_ids,
                         set([EVIDENCE_HANDOVER, EVIDENCE_RESTRICTED]))
        # the restricted copy only appears from CLEARANCE_RESTRICTED up
        self.assertEqual(restricted['entries'], custodian['entries'])
        self.assertGreater(len(restricted['entries']),
                           len(handover['entries']))
        # hidden material shows up as pseudonyms for the handover caller
        self.assertGreater(len(handover['redacted']), 0)
        self.assertEqual(custodian['redacted'], [])
        # all three indexes differ from each other
        self.assertNotEqual(handover['entries'], custodian['entries'])
        self.assertNotEqual(handover, restricted)

    def test_unauthorised_caller_cannot_infer_hidden_stream_name(self):
        'Redacted entries reveal neither stream names nor evidence ids'
        result = self.index.provenance_index(CLEARANCE_HANDOVER)
        redacted_json = json.dumps(result['redacted'], sort_keys=True)

        # every stream name of the restricted copy stays hidden
        ole = olefile.OleFileIO(OLE_SAMPLE)
        try:
            hidden_names = ['/'.join(p) for p in ole.listdir()]
        finally:
            ole.close()
        for name in hidden_names + [EVIDENCE_RESTRICTED]:
            self.assertNotIn(name, redacted_json)

        # pseudonyms are keyed: they match neither a plain hash of the
        # stream name nor a plain hash of evidence id + name
        for entry in result['redacted']:
            token = entry['token']
            self.assertEqual(set(entry), set(['token', 'min_clearance']))
            for name in hidden_names:
                self.assertNotEqual(
                    token,
                    hashlib.sha256(name.encode('utf-8')).hexdigest())
                self.assertNotEqual(
                    token,
                    hashlib.sha256(
                        (EVIDENCE_RESTRICTED + name).encode('utf-8')
                    ).hexdigest())

    def test_unauthorised_query_hides_other_document(self):
        'A handover caller querying the shared stream gets one source only'
        result = self.index.query_stream(SHARED_STREAM, CLEARANCE_HANDOVER)
        self.assertEqual([v['evidence_id'] for v in result['visible']],
                         [EVIDENCE_HANDOVER])
        self.assertEqual(result['redacted_count'], 1)
        # with a single visible source, no consistency verdict is made
        self.assertIsNone(result['content_consistent'])
        self.assertNotIn(EVIDENCE_RESTRICTED, result['range_sha256'])
        redacted_json = json.dumps(result['redacted'])
        self.assertNotIn(SHARED_STREAM, redacted_json)
        self.assertNotIn(EVIDENCE_RESTRICTED, redacted_json)


if __name__ == '__main__':
    unittest.main()
