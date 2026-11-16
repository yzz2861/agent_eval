import unittest

import idna
import idna.compat


class IDNACompatTests(unittest.TestCase):
    def testToASCII(self):
        self.assertEqual(
            idna.compat.ToASCII("\u30c6\u30b9\u30c8.xn--zckzah"),
            b"xn--zckzah.xn--zckzah",
        )

    def testToUnicode(self):
        self.assertEqual(
            idna.compat.ToUnicode(b"xn--zckzah.xn--zckzah"),
            "\u30c6\u30b9\u30c8.\u30c6\u30b9\u30c8",
        )

    def test_nameprep(self):
        self.assertRaises(NotImplementedError, idna.compat.nameprep, "a")


class IDNA2003LegacyTests(unittest.TestCase):
    # IDNA 2003 (encodings.idna, via Nameprep) handled case, the sharp s
    # and other characters differently from IDNA 2008 with UTS #46. These
    # samples pin the divergence and show how the canonical comparison
    # pipeline treats names that originated from an IDNA 2003 stack.

    def test_sharp_s_deviation_is_kept(self):
        import encodings.idna as idna2003

        # IDNA 2003 maps U+00DF to "ss"; IDNA 2008 keeps the sharp s and
        # emits its own A-label, so the two wire names are not equivalent.
        self.assertEqual(idna2003.ToASCII("faß.de"), b"fass.de")
        self.assertEqual(idna.canonicalize("faß.de").alabel, b"xn--fa-hia.de")
        self.assertFalse(idna.match("faß.de", "fass.de"))
        # The IDNA 2008 A-label itself round-trips through the pipeline.
        self.assertTrue(idna.match("xn--fa-hia.de", "faß.de"))

    def test_legacy_wire_labels_remain_valid(self):
        # An ASCII label an IDNA 2003 deployment put on the wire is still a
        # valid IDNA 2008 label and canonicalises to itself, lowercased.
        self.assertEqual(idna.canonicalize("fass.de").alabel, b"fass.de")
        self.assertEqual(idna.canonicalize("strasse.de").alabel, b"strasse.de")
        self.assertTrue(idna.match("FASS.DE", "fass.de"))

    def test_idna2003_did_not_casefold_ascii(self):
        import encodings.idna as idna2003

        # Nameprep only touched non-ASCII labels; an all-ASCII label kept
        # its case under IDNA 2003, whereas canonicalize() folds case so
        # the two spellings compare equal.
        self.assertEqual(idna2003.ToASCII("WWW.Example.COM."), b"WWW.Example.COM.")
        self.assertTrue(idna.match("WWW.Example.COM.", "www.example.com"))
        self.assertEqual(idna.canonicalize("WWW.Example.COM.").alabel, b"www.example.com")

    def test_multilabel_idna2003_encoding_differences(self):
        import encodings.idna as idna2003

        # IDNA 2003 punycode-encoded the whole domain including separators
        # in one label; IDNA 2008 encodes each label separately.
        self.assertEqual(
            idna2003.ToASCII("ドメイン.テスト"),
            b"xn--.-ieuyc7blb2ouf",
        )
        self.assertEqual(
            idna.canonicalize("ドメイン.テスト").alabel,
            b"xn--eckwd4c7c.xn--zckzah",
        )
        self.assertTrue(idna.match("xn--eckwd4c7c.xn--zckzah", "ドメイン.テスト"))
        # Greek uppercase: IDNA 2003 produced a malformed-looking label
        # while the UTS #46 plus IDNA 2008 pipeline yields a per-label
        # A-label.
        self.assertEqual(idna.canonicalize("ΒΌΛΟΣ.com").alabel, b"xn--nxasmq6b.com")
        self.assertTrue(idna.match("xn--nxasmq6b.com", "ΒΌΛΟΣ.com"))


if __name__ == "__main__":
    unittest.main()
