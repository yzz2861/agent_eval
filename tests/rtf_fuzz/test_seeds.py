"""Equivalent-encoding tests for the benign synthetic seed corpus."""

import unittest

from oletools import oleobj, rtfobj
from oletools.rtf_fuzz import seeds


def _extract(document):
    parser = rtfobj.RtfObjParser(document)
    parser.parse()
    return [rtf_object.rawdata for rtf_object in parser.objects]


class SeedCorpusTest(unittest.TestCase):
    def setUp(self):
        self.payload, self.documents = seeds.default_seed_corpus()

    def test_payload_is_valid_ole1_embedded_object(self):
        obj = oleobj.OleObject()
        obj.parse(self.payload)
        self.assertEqual(obj.format_id, oleobj.OleObject.TYPE_EMBEDDED)
        self.assertEqual(obj.data, seeds.DEFAULT_MARKER)

    def test_payload_is_harmless_ascii(self):
        self.assertTrue(all(32 <= byte < 127 or byte < 32
                            for byte in seeds.DEFAULT_MARKER))

    def test_all_seeds_extract_identical_object_bytes(self):
        reference = _extract(self.documents["hex_plain"])
        self.assertEqual(len(reference), 1)
        for name, document in sorted(self.documents.items()):
            self.assertEqual(_extract(document), reference, name)

    def test_all_seeds_extract_the_ole1_payload(self):
        for name, document in sorted(self.documents.items()):
            extracted = _extract(document)
            self.assertEqual(extracted[0], self.payload, name)


if __name__ == "__main__":
    unittest.main()
