"""Round-trip and semantic tests for the structure-aware RTF model."""

import unittest

from oletools import rtfobj
from oletools.rtf_fuzz import model


class ModelRoundTripTest(unittest.TestCase):
    def test_plain_hex_roundtrip(self):
        data = b"{\\rtf1 {\\objdata {41424344}}}"
        tree = model.parse_rtf(data)
        self.assertEqual(model.render(tree), data)

    def test_control_word_space_delimiter_roundtrip(self):
        data = b"{\\rtf1 \\ansi \\objw105 x}"
        tree = model.parse_rtf(data)
        self.assertEqual(model.render(tree), data)

    def test_apostrophe_control_symbol_roundtrip(self):
        data = b"{\\objdata 4142\\'4344}"
        tree = model.parse_rtf(data)
        self.assertEqual(model.render(tree), data)

    def test_bin_payload_and_leading_space(self):
        data = b"{\\objdata \\bin3 414}"
        tree = model.parse_rtf(data)
        node = model.find_bin_nodes(tree)[0]
        self.assertEqual(node.payload, b"414")
        self.assertTrue(node.leading_space)
        self.assertFalse(node.truncated)
        self.assertEqual(model.render(tree), data)

    def test_bin_truncation_is_marked(self):
        tree = model.parse_rtf(b"{\\objdata \\bin9 ABC}")
        node = model.find_bin_nodes(tree)[0]
        self.assertTrue(node.truncated)
        self.assertTrue(node.length_contradiction)

    def test_negative_bin_length(self):
        tree = model.parse_rtf(b"{\\objdata \\bin-3 ABC}")
        node = model.find_bin_nodes(tree)[0]
        self.assertEqual(node.declared_length, -3)
        self.assertEqual(node.payload, b"")
        self.assertTrue(node.truncated)

    def test_bin_without_argument_reads_zero(self):
        tree = model.parse_rtf(b"{\\objdata \\bin ABC}")
        node = model.find_bin_nodes(tree)[0]
        self.assertEqual(node.declared_length, 0)
        self.assertEqual(node.payload, b"")

    def test_model_matches_rtfobj_bin_extraction(self):
        data = b"{\\objdata \\bin3 ABC}"
        tree = model.parse_rtf(data)
        self.assertEqual(model.render(tree), data)
        parser = rtfobj.RtfObjParser(data)
        parser.parse()
        self.assertEqual(len(parser.objects), 1)
        self.assertEqual(parser.objects[0].rawdata, b"ABC")


if __name__ == "__main__":
    unittest.main()
