# -*- coding: utf-8 -*-

from __future__ import absolute_import

import unittest
import zipfile

from filetype.layers import (
    ContainerAdapter,
    Entry,
    IDENTIFIED,
    PENDING,
    UNKNOWN,
    inspect_layers,
)


PNG_HEADER = bytearray([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
GIF_HEADER = bytearray([0x47, 0x49, 0x46, 0x38, 0x39, 0x61])
ZIP_HEADER = bytearray([0x50, 0x4B, 0x03, 0x04])
UNKNOWN_HEADER = bytearray([0x00, 0x01, 0x02, 0x03])


class InMemoryAdapter(ContainerAdapter):
    """Caller-supplied local adapter backed by an in-memory tree."""

    def __init__(self, tree, truncated=None, read_failures=None,
                 children_failures=None):
        self._tree = tree
        self._truncated = truncated or set()
        self._read_failures = read_failures or set()
        self._children_failures = children_failures or set()

    def children(self, entry):
        if entry.reference in self._children_failures:
            raise RuntimeError("children unavailable")
        node = self._tree.get(entry.reference)
        if node is None:
            return ()
        return node[1]

    def read_signature(self, entry):
        if entry.reference in self._read_failures:
            raise IOError("local read rejected")
        node = self._tree.get(entry.reference)
        if node is None:
            return None
        return node[0]

    def is_truncated(self, entry):
        return entry.reference in self._truncated


def make_zip_bytes(members):
    import io
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, payload in members:
            archive.writestr(name, bytes(payload))
    return bytearray(buffer.getvalue())



class TestInspectLayers(unittest.TestCase):
    def _adapter(self):
        inner_zip = make_zip_bytes([("pic.png", PNG_HEADER)])
        tree = {
            None: (
                None,
                [
                    Entry("top-png", "a.png", "image/png", "png"),
                    Entry("top-unknown", "note.txt", "text/plain", "txt"),
                    Entry("top-pending", "missing.bin", None, "bin"),
                    Entry("nested", "bundle.zip", "application/zip", "zip"),
                ],
            ),
            "top-png": (PNG_HEADER, ()),
            "top-unknown": (UNKNOWN_HEADER, ()),
            "top-pending": (None, ()),
            "nested": (
                inner_zip,
                [Entry("nested-pic", "pic.png", "image/png", "png")],
            ),
            "nested-pic": (PNG_HEADER, ()),
        }
        return InMemoryAdapter(tree)

    def test_reports_every_layer_with_evidence_and_declared_type(self):
        records = inspect_layers(self._adapter())
        by_ref = {record.entry.reference: record for record in records}

        self.assertEqual(by_ref["top-png"].status, IDENTIFIED)
        self.assertEqual(by_ref["top-png"].mime, "image/png")
        self.assertEqual(by_ref["top-png"].declared_mime, "image/png")
        self.assertEqual(by_ref["top-png"].signature, PNG_HEADER)
        self.assertEqual(by_ref["top-png"].depth, 0)
        self.assertEqual(by_ref["top-png"].path, ("a.png",))

    def test_unknown_signature_is_reported_not_guessed(self):
        records = inspect_layers(self._adapter())
        record = next(r for r in records
                      if r.entry.reference == "top-unknown")
        self.assertEqual(record.status, UNKNOWN)
        self.assertIsNone(record.kind)
        self.assertEqual(record.signature, UNKNOWN_HEADER)
        self.assertEqual(record.declared_extension, "txt")

    def test_claimed_child_without_evidence_is_pending(self):
        records = inspect_layers(self._adapter())
        record = next(r for r in records
                      if r.entry.reference == "top-pending")
        self.assertEqual(record.status, PENDING)
        self.assertTrue(record.pending)
        self.assertEqual(len(record.signature), 0)
        self.assertIn("no read evidence", record.reason)

    def test_read_exception_is_treated_as_missing_evidence(self):
        adapter = self._adapter()
        adapter._read_failures.add("top-png")
        records = inspect_layers(adapter)
        record = next(r for r in records
                      if r.entry.reference == "top-png")
        self.assertEqual(record.status, PENDING)
        self.assertIn("read failed", record.reason)

    def test_nested_container_is_walked_layer_by_layer(self):
        records = inspect_layers(self._adapter())
        nested = next(r for r in records if r.entry.reference == "nested")
        nested_pic = next(r for r in records
                          if r.entry.reference == "nested-pic")
        self.assertEqual(nested.status, IDENTIFIED)
        self.assertEqual(nested.mime, "application/zip")
        self.assertEqual(nested.depth, 0)
        self.assertEqual(nested_pic.status, IDENTIFIED)
        self.assertEqual(nested_pic.mime, "image/png")
        self.assertEqual(nested_pic.depth, 1)
        self.assertEqual(nested_pic.path, ("bundle.zip", "pic.png"))
        self.assertEqual(nested_pic.index, 0)

    def test_pending_layer_does_not_trigger_child_reads(self):
        records = inspect_layers(self._adapter())
        pending = next(r for r in records
                       if r.entry.reference == "top-pending")
        self.assertEqual(pending.status, PENDING)
        self.assertNotIn(("missing.bin", "pic.png"),
                         [r.path for r in records])


    def test_shared_name_candidates_stay_distinguishable(self):
        tree = {
            None: (
                None,
                [
                    Entry("ref-a", "attachment.bin", None, "bin"),
                    Entry("ref-b", "attachment.bin", None, "bin"),
                ],
            ),
            "ref-a": (PNG_HEADER, ()),
            "ref-b": (GIF_HEADER, ()),
        }
        records = inspect_layers(InMemoryAdapter(tree))
        self.assertEqual([r.entry.name for r in records],
                         ["attachment.bin", "attachment.bin"])
        self.assertEqual(records[0].entry.reference, "ref-a")
        self.assertEqual(records[1].entry.reference, "ref-b")
        self.assertEqual(records[0].mime, "image/png")
        self.assertEqual(records[1].mime, "image/gif")
        self.assertEqual(records[0].index, 0)
        self.assertEqual(records[1].index, 1)
        self.assertNotEqual(records[0].signature, records[1].signature)

    def test_truncated_candidate_keeps_evidence_and_flag(self):
        tree = {
            None: (None, [Entry("cut", "clip.png", "image/png", "png")]),
            "cut": (PNG_HEADER[:4], ()),
        }
        adapter = InMemoryAdapter(tree, truncated={"cut"})
        record = inspect_layers(adapter)[0]
        self.assertEqual(record.status, IDENTIFIED)
        self.assertTrue(record.truncated)
        self.assertEqual(record.signature, PNG_HEADER[:4])
        self.assertIn("truncated", record.reason)

    def test_truncated_unmatched_signature_is_unknown_with_evidence(self):
        tree = {
            None: (None, [Entry("cut", "clip.dat", None, "dat")]),
            "cut": (UNKNOWN_HEADER[:2], ()),
        }
        adapter = InMemoryAdapter(tree, truncated={"cut"})
        record = inspect_layers(adapter)[0]
        self.assertEqual(record.status, UNKNOWN)
        self.assertTrue(record.truncated)
        self.assertEqual(record.signature, UNKNOWN_HEADER[:2])

    def test_children_enumeration_failure_is_recorded_pending(self):
        tree = {
            None: (None, [Entry("box", "bundle.zip",
                                "application/zip", "zip")]),
            "box": (ZIP_HEADER, [Entry("hidden", "x.png", None, "png")]),
        }
        adapter = InMemoryAdapter(tree, children_failures={"box"})
        records = inspect_layers(adapter)
        self.assertEqual(records[0].status, IDENTIFIED)
        self.assertEqual(records[1].status, PENDING)
        self.assertIn("cannot be enumerated", records[1].reason)

    def test_non_adapter_input_raises_type_error(self):
        with self.assertRaises(TypeError):
            inspect_layers(object())

    def test_explicit_root_is_itself_reported(self):
        tree = {
            "root-ref": (
                ZIP_HEADER,
                [Entry("child", "a.png", "image/png", "png")],
            ),
            "child": (PNG_HEADER, ()),
        }
        root = Entry("root-ref", "bundle.zip", "application/zip", "zip")
        records = inspect_layers(InMemoryAdapter(tree), root=root)
        self.assertEqual(records[0].entry.reference, "root-ref")
        self.assertEqual(records[0].depth, 0)
        self.assertEqual(records[1].entry.reference, "child")
        self.assertEqual(records[1].depth, 1)



class TestZipArchiveEndToEnd(unittest.TestCase):
    def test_two_same_named_archives_identified_vs_pending(self):
        import os
        import sys
        import tempfile

        repo_root = os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))
        )
        if repo_root not in sys.path:
            sys.path.insert(0, repo_root)

        from examples.layered_archive import (
            ATTACHMENT_NAME,
            PNG_SIGNATURE,
            ZipArchiveAdapter,
            build_archive,
        )

        workdir = tempfile.mkdtemp(prefix="layers-test-")
        path_a = os.path.join(workdir, "a.zip")
        path_b = os.path.join(workdir, "b.zip")
        build_archive(path_a, PNG_SIGNATURE + b"\x00" * 8)
        build_archive(path_b, PNG_SIGNATURE + b"\x00" * 8)

        with zipfile.ZipFile(path_a) as archive:
            records_a = inspect_layers(ZipArchiveAdapter(archive))
        with zipfile.ZipFile(path_b) as archive:
            records_b = inspect_layers(
                ZipArchiveAdapter(archive, missing=(ATTACHMENT_NAME,))
            )

        attachment_a = next(
            r for r in records_a if r.entry.name == ATTACHMENT_NAME
        )
        attachment_b = next(
            r for r in records_b if r.entry.name == ATTACHMENT_NAME
        )
        self.assertEqual(attachment_a.status, IDENTIFIED)
        self.assertEqual(attachment_a.mime, "image/png")
        self.assertEqual(attachment_b.status, PENDING)
        self.assertEqual(len(attachment_b.signature), 0)


if __name__ == "__main__":
    unittest.main()
