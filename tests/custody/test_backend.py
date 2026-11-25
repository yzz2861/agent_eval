"""End-to-end tests for the progressive custody backend."""

import io
import os
import shutil
import tempfile
import unittest
import zipfile

from oletools.custody import Backend, CustodyManifest
from oletools.custody.errors import (
    AccessDeniedError,
    ManifestError,
)
from oletools.custody.guard import GuardedFile, RangeGate
from oletools.custody.manifest import sha256_bytes


MACRO_FREE_DOC = os.path.join(
    'tests', 'test-data', 'oleobj', 'embedded-simple-2007.docx')
OLE_DOC = os.path.join(
    'tests', 'test-data', 'oleobj', 'sample_with_calc_embedded.doc')
MACRO_DOC = os.path.join(
    'tests', 'test-data', 'oleform', 'oleform-PR314.docm')


def make_zip(path, members):
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as archive:
        for name, data in members:
            archive.writestr(name, data)


class TestFirstPassIsStructureOnly(unittest.TestCase):

    def setUp(self):
        self.backend = Backend()
        self.manifest, self.observation = \
            self.backend.create_manifest(MACRO_FREE_DOC)

    def test_manifest_seals_every_object_but_no_payload(self):
        self.assertGreater(len(self.observation.objects), 1)
        self.assertEqual(len(self.manifest.observations),
                         len(self.observation.objects))
        self.assertIsNotNone(self.manifest.root_digest)
        self.assertEqual(self.manifest.approvals, [])

    def test_macro_free_document_is_flagged_macro_free(self):
        self.assertFalse(self.observation.has_macro)

    def test_macro_document_is_flagged(self):
        _, macro_observation = self.backend.create_manifest(MACRO_DOC)
        self.assertTrue(macro_observation.has_macro)
        self.assertIn('word/vbaProject.bin',
                      macro_observation.macro_evidence)


class TestProgressiveRelease(unittest.TestCase):

    def setUp(self):
        self.backend = Backend()
        self.tmp = tempfile.mkdtemp()
        self.doc = os.path.join(self.tmp, 'sample.docx')
        shutil.copy(MACRO_FREE_DOC, self.doc)
        self.manifest, self.observation = \
            self.backend.create_manifest(self.doc)
        self.target = next(obj for obj in self.observation.objects
                           if obj.detail.get('embedded'))
        self.neighbour = next(obj for obj in self.observation.objects
                              if obj.object_id != self.target.object_id)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_only_approved_object_is_unsealed(self):
        self.backend.grant_approval(self.manifest, self.target.object_id)
        result = self.backend.inspect(
            self.doc, self.manifest,
            release_ids=[self.target.object_id])
        self.assertEqual(result.released, [self.target.object_id])
        self.assertEqual(result.denied, [])
        self.assertEqual(result.revoked, {})
        with zipfile.ZipFile(self.doc) as archive:
            expected = archive.read(self.target.name)
        self.assertEqual(result.data_for(self.target.object_id), expected)
        self.assertEqual(
            self.manifest.approvals[0].content_digest,
            sha256_bytes(expected))

    def test_neighbour_remains_sealed_and_absent_from_new_results(self):
        self.backend.grant_approval(self.manifest, self.target.object_id)
        result = self.backend.inspect(
            self.doc, self.manifest,
            release_ids=[self.target.object_id, self.neighbour.object_id])
        self.assertEqual(result.released, [self.target.object_id])
        self.assertIn(self.neighbour.object_id, result.denied)
        with self.assertRaises(AccessDeniedError):
            result.data_for(self.neighbour.object_id)
        neighbour_names = [
            item.observation.object_id for item in result.released_objects]
        self.assertNotIn(self.neighbour.object_id, neighbour_names)

    def test_neighbour_still_visible_in_structural_observation(self):
        result = self.backend.inspect(self.doc, self.manifest)
        observable = {obj.object_id for obj in
                      result.objects_still_observable()}
        self.assertIn(self.neighbour.object_id, observable)
        self.assertIn(self.target.object_id, observable)
        self.assertEqual(result.released, [])

    def test_guard_blocks_bytes_outside_approved_object(self):
        detail = self.target.detail
        start = detail['physical_offset']
        length = detail['physical_length']
        gate = RangeGate(((start, start + length),))
        with open(self.doc, 'rb') as raw:
            guarded = GuardedFile(raw, gate, name=self.doc)
            with self.assertRaises(AccessDeniedError):
                guarded.read_range(start - 1, 1)
            with self.assertRaises(AccessDeniedError):
                guarded.read_range(start + length, 1)
            inside = guarded.read_range(start, min(16, length))
        self.assertEqual(len(inside), min(16, length))


class TestRevocationOnChange(unittest.TestCase):

    def setUp(self):
        self.backend = Backend()
        self.tmp = tempfile.mkdtemp()
        self.doc = os.path.join(self.tmp, 'container.zip')
        self.payload_a = b'A' * 200
        self.payload_b = b'B' * 300
        make_zip(self.doc, (
            ('word/embeddings/object_a.bin', self.payload_a),
            ('word/embeddings/object_b.bin', self.payload_b),
        ))
        self.manifest, self.observation = \
            self.backend.create_manifest(self.doc)
        self.first = self.observation.objects[0]
        self.backend.grant_approval(self.manifest, self.first.object_id)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_replacing_original_file_revokes_old_approval(self):
        replacement = os.path.join(self.tmp, 'replacement.zip')
        different_payload = b'X' * (len(self.payload_a) + 1234)
        make_zip(replacement, (
            ('word/embeddings/object_a.bin', different_payload),
            ('word/embeddings/object_b.bin', self.payload_b),
        ))
        result = self.backend.inspect(
            replacement, self.manifest,
            release_ids=[self.first.object_id])
        self.assertEqual(result.released, [])
        self.assertIn(self.first.object_id, result.denied)
        approval = self.manifest.approvals[0]
        self.assertFalse(approval.is_active)
        self.assertEqual(result.revoked[approval.approval_id],
                         'file_replaced')
        with self.assertRaises(AccessDeniedError):
            result.data_for(self.first.object_id)

    def test_same_size_same_place_content_swap_is_replacement(self):
        swapped = os.path.join(self.tmp, 'swapped.zip')
        same_size = b'C' * len(self.payload_a)
        make_zip(swapped, (
            ('word/embeddings/object_a.bin', same_size),
            ('word/embeddings/object_b.bin', self.payload_b),
        ))
        result = self.backend.inspect(
            swapped, self.manifest,
            release_ids=[self.first.object_id])
        approval = self.manifest.approvals[0]
        self.assertEqual(result.revoked[approval.approval_id],
                         'file_replaced')
        self.assertFalse(approval.is_active)

    def test_same_named_object_moving_loses_approval(self):
        moved = os.path.join(self.tmp, 'moved.zip')
        padding = b'P' * 5000
        make_zip(moved, (
            ('word/embeddings/padding.bin', padding),
            ('word/embeddings/object_a.bin', self.payload_a),
            ('word/embeddings/object_b.bin', self.payload_b),
        ))
        result = self.backend.inspect(
            moved, self.manifest,
            release_ids=[self.first.object_id])
        approval = self.manifest.approvals[0]
        self.assertFalse(approval.is_active)
        self.assertEqual(result.revoked[approval.approval_id],
                         'object_moved')
        self.assertEqual(result.released, [])
        fresh = next(obj for obj in result.observation.objects
                     if obj.name == self.first.name)
        self.assertNotEqual(fresh.offset, self.first.offset)

    def test_removed_object_revokes_approval(self):
        shrunk = os.path.join(self.tmp, 'shrunk.zip')
        make_zip(shrunk, (
            ('word/embeddings/object_b.bin', self.payload_b),
        ))
        result = self.backend.inspect(
            shrunk, self.manifest,
            release_ids=[self.first.object_id])
        approval = self.manifest.approvals[0]
        self.assertEqual(result.revoked[approval.approval_id],
                         'object_removed')
        self.assertFalse(approval.is_active)
        self.assertIn(self.first.object_id, result.denied)


class TestNoUnapprovedReads(unittest.TestCase):

    def setUp(self):
        self.backend = Backend()
        self.tmp = tempfile.mkdtemp()
        self.doc = os.path.join(self.tmp, 'container.zip')
        make_zip(self.doc, (
            ('word/embeddings/object_a.bin', b'aaaa' * 50),
            ('word/embeddings/object_b.bin', b'bbbb' * 50),
        ))
        self.manifest, self.observation = \
            self.backend.create_manifest(self.doc)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_inspection_without_approval_reads_no_payload(self):
        result = self.backend.inspect(self.doc, self.manifest)
        self.assertEqual(result.released_objects, [])
        self.assertEqual(result.released, [])
        self.assertTrue(result.is_resealed)

    def test_deny_all_gate_cannot_open_any_object(self):
        target = self.observation.objects[0]
        with open(self.doc, 'rb') as raw:
            guarded = GuardedFile(raw, RangeGate.deny_all(), name=self.doc)
            with self.assertRaises(AccessDeniedError):
                guarded.read_range(target.offset, 1)

    def test_unsealing_one_object_cannot_reach_neighbour_bytes(self):
        target = self.observation.objects[0]
        neighbour = self.observation.objects[1]
        self.backend.grant_approval(self.manifest, target.object_id)
        result = self.backend.inspect(
            self.doc, self.manifest,
            release_ids=[target.object_id, neighbour.object_id])
        self.assertEqual(result.released, [target.object_id])
        self.assertEqual(result.denied, [neighbour.object_id])

    def test_wrong_expected_digest_revokes_release(self):
        target = self.observation.objects[0]
        self.backend.grant_approval(self.manifest, target.object_id)
        result = self.backend.inspect(
            self.doc, self.manifest,
            release_ids=[target.object_id],
            expected_digests={target.object_id: 'deadbeef'})
        self.assertEqual(result.released, [])
        approval = self.manifest.approvals[0]
        self.assertFalse(approval.is_active)
        self.assertEqual(
            result.revoked[approval.approval_id], 'content_mismatch')


class TestOleContainer(unittest.TestCase):

    def test_ole_streams_round_trip_through_gated_reads(self):
        import olefile
        backend = Backend()
        manifest, observation = backend.create_manifest(OLE_DOC)
        reference = {}
        ole = olefile.OleFileIO(OLE_DOC)

        def walk(node, parts):
            for kid in node.kids:
                next_parts = parts + [kid.name]
                if kid.entry_type == 2 and kid.size > 0:
                    reference[kid.sid] = ole.openstream(next_parts).read()
                else:
                    walk(kid, next_parts)

        walk(ole.root, [])
        ole.close()
        for obj in observation.objects:
            backend.grant_approval(manifest, obj.object_id)
        result = backend.inspect(
            OLE_DOC, manifest,
            release_ids=[obj.object_id for obj in observation.objects])
        self.assertEqual(len(result.released), len(reference))
        for released in result.released_objects:
            sid = released.observation.detail['sid']
            self.assertEqual(released.data, reference[sid])


class TestManifestInputValidation(unittest.TestCase):

    def test_foreign_manifest_type_is_rejected(self):
        backend = Backend()
        with self.assertRaises(ManifestError):
            backend.inspect(MACRO_FREE_DOC, {'root_digest': '0' * 64})

    def test_grant_for_unknown_object_fails(self):
        backend = Backend()
        manifest, _ = backend.create_manifest(MACRO_FREE_DOC)
        with self.assertRaises(ManifestError):
            backend.grant_approval(manifest, 'does-not-exist')


class TestRawContainer(unittest.TestCase):

    def test_raw_file_requires_approval_and_gates_bytes(self):
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, 'blob.bin')
            payload = b'flat-bytes-' * 64
            with open(path, 'wb') as handle:
                handle.write(payload)
            backend = Backend()
            manifest, observation = backend.create_manifest(path)
            self.assertEqual(observation.container_format, 'raw')
            self.assertEqual(len(observation.objects), 1)
            result = backend.inspect(path, manifest)
            self.assertTrue(result.is_resealed)
            obj = observation.objects[0]
            backend.grant_approval(manifest, obj.object_id)
            result = backend.inspect(
                path, manifest, release_ids=[obj.object_id])
            self.assertEqual(result.data_for(obj.object_id), payload)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestScanDoesNotReadPayloads(unittest.TestCase):

    def test_zip_payload_bytes_are_never_consumed_during_scan(self):
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, 'sealed.zip')
            secret = b'UNAPPROVED-PAYLOAD' * 100
            make_zip(path, (
                ('word/embeddings/secret.bin', secret),
                ('word/document.xml', b'<doc/>'),
            ))
            from oletools.custody.guard import RangeGate
            tracked = []

            class TrackingFile(object):
                def __init__(self, real):
                    self._real = real
                    self.name = real.name

                def read(self, size=-1):
                    tracked.append(size)
                    return self._real.read(size)

                def seek(self, offset, whence=0):
                    return self._real.seek(offset, whence)

                def tell(self):
                    return self._real.tell()

                def close(self):
                    return self._real.close()

                def __enter__(self):
                    return self

                def __exit__(self, *exc):
                    self.close()

            import builtins
            real_open = builtins.open

            def tracking_open(file, mode='rb', *args, **kwargs):
                handle = real_open(file, mode, *args, **kwargs)
                return TrackingFile(handle)

            builtins.open = tracking_open
            try:
                from oletools.custody.scan import detect_format, _scan_zip
                fmt = detect_format(path)
                objects, _ = _scan_zip(path)
            finally:
                builtins.open = real_open
            # Structure-only reads stay in the central directory / local
            # headers; the 2000-byte payload itself is never consumed.
            self.assertTrue(all(size is not None and size < 1024
                                for size in tracked))
            target = next(obj for obj in objects
                          if obj.name == 'word/embeddings/secret.bin')
            self.assertEqual(target.size, len(secret))
            self.assertEqual(fmt, 'zip')
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
