"""Tests for the offline UserForm control-default forensic interface."""

import io
import struct
import unittest
import zipfile
from os.path import join

import olefile

from tests.test_utils import DATA_BASE_DIR
from oletools import form_forensics as ff
from oletools.olevba import VBA_Parser


SAMPLE = join(DATA_BASE_DIR, "oleform", "oleform-PR314.docm")
COMPRESSED = 0x80000000


class FakeOle(object):
    """In-memory olefile-like object used to control stream listing order."""

    def __init__(self, streams, reverse=False, project_stream=None):
        self._streams = dict(streams)
        self._reverse = reverse
        if project_stream is not None:
            self._streams[("PROJECT",)] = project_stream

    def listdir(self, streams=True, storages=False):
        keys = list(self._streams.keys())
        if self._reverse:
            keys.reverse()
        return keys

    def openstream(self, path):
        key = tuple(path.split("/")) if isinstance(path, str) else tuple(path)
        return io.BytesIO(self._streams[key])

    def exists(self, path):
        key = tuple(path.split("/")) if isinstance(path, str) else tuple(path)
        return key in self._streams


def load_sample_streams():
    with open(SAMPLE, "rb") as handle:
        document = zipfile.ZipFile(io.BytesIO(handle.read()))
    ole = olefile.OleFileIO(io.BytesIO(document.read("word/vbaProject.bin")))
    return {tuple(entry): ole.openstream(entry).read()
            for entry in ole.listdir(streams=True, storages=False)}


def morph_stream(value=None, compressed=True, empty=False):
    """Build a minimal MorphData o-stream (see scratch_build for the rationale)."""
    fields = bytearray()
    mask = 0
    raw = b""
    if value is not None:
        mask |= 1 << 22  # fValue
        raw = b"" if empty else (
            value.encode("cp1252") if compressed else value.encode("utf-16-le"))
        fields += struct.pack("<I", len(raw) | (COMPRESSED if compressed else 0))
    value_part = raw if value is not None else b""
    value_pad = b"\x00" * ((-(8 + len(fields) + 8 + len(value_part))) % 4)
    cb = 8 + len(fields) + 8 + len(value_part) + len(value_pad)
    out = struct.pack("<BB", 0, 2) + struct.pack("<H", cb)
    out += struct.pack("<Q", mask) + bytes(fields)
    out += b"\x00" * 8 + value_part + value_pad
    out += struct.pack("<BBH", 0, 2, 0)
    return out

class MorphParserTest(unittest.TestCase):
    def test_ansi_present_value(self):
        stream = ff.ForensicStream(io.BytesIO(morph_stream("abc")),"o")
        result = ff._parse_morph(stream, 1252)
        self.assertIsNone(result["error"])
        status, _ = ff._field_status(result["value"])
        self.assertEqual(status, ff.STATUS_PRESENT)
        self.assertEqual(result["value"]["text"], "abc")
        self.assertEqual(result["value"]["encoding"], "ansi:cp1252")
        self.assertTrue(result["value"]["compressed"])

    def test_utf16_value_uses_different_encoding(self):
        stream = ff.ForensicStream(io.BytesIO(
            morph_stream("h\u00e9llo", compressed=False)), "o")
        result = ff._parse_morph(stream, 1252)
        self.assertIsNone(result["error"])
        status, _ = ff._field_status(result["value"])
        self.assertEqual(status, ff.STATUS_PRESENT)
        self.assertEqual(result["value"]["text"], "h\u00e9llo")
        self.assertEqual(result["value"]["encoding"], ff.ENCODING_UTF16)
        self.assertFalse(result["value"]["compressed"])

    def test_empty_string_is_distinct_from_missing(self):
        empty = ff._parse_morph(ff.ForensicStream(io.BytesIO(
            morph_stream("x", empty=True)), "o"), 1252)
        missing = ff._parse_morph(ff.ForensicStream(io.BytesIO(
            morph_stream(value=None)), "o"), 1252)
        self.assertEqual(ff._field_status(empty["value"])[0],
                         ff.STATUS_EMPTY_DEFAULT)
        self.assertEqual(ff._field_status(missing["value"])[0],
                         ff.STATUS_NO_DEFAULT)
        self.assertTrue(empty["value"]["stored"])
        self.assertFalse(missing["value"]["stored"])

    def test_value_encoding_independent_of_name(self):
        stream = ff.ForensicStream(io.BytesIO(
            morph_stream("wt", compressed=False)), "o")
        result = ff._parse_morph(stream, 1252)
        self.assertEqual(result["value"]["encoding"], ff.ENCODING_UTF16)

class FakeOleOrderTest(unittest.TestCase):
    def test_reversed_enumeration_keeps_attribution(self):
        streams = load_sample_streams()
        normal = ff.records_as_dicts(ff.extract_control_defaults(
            FakeOle(streams, reverse=False), "Project", "word/vbaProject.bin"))
        reversed_order = ff.records_as_dicts(ff.extract_control_defaults(
            FakeOle(streams, reverse=True), "Project", "word/vbaProject.bin"))
        self.assertEqual(normal, reversed_order)
        self.assertGreater(len(normal), 10)

    def test_record_ids_are_unique_and_stable(self):
        streams = load_sample_streams()
        records = ff.extract_control_defaults(FakeOle(streams), "P", "c")
        ids = [record.record_id for record in records]
        self.assertEqual(len(ids), len(set(ids)))
        again = ff.extract_control_defaults(FakeOle(streams), "P", "c")
        self.assertEqual([r.record_id for r in again], ids)


class RealSampleTest(unittest.TestCase):
    def setUp(self):
        self.parser = VBA_Parser(SAMPLE)
        self.records = list(self.parser.extract_form_control_defaults())

    def test_three_missing_semantics_are_distinct(self):
        by_key = {(r.form_path, r.name): r for r in self.records}
        textbox = by_key[("UserFormTEST1", "TextBox1")]
        self.assertEqual(textbox.status, ff.STATUS_PRESENT)
        self.assertEqual(textbox.value, "heyhey")
        button = by_key[("UserFormTEST1", "CommandButton1")]
        self.assertEqual(button.status, ff.STATUS_NO_DEFAULT)
        self.assertIsNone(button.value)
        frame = by_key[("UserFormTEST1", "Frame1")]
        self.assertEqual(frame.status, ff.STATUS_NOT_SUPPORTED)
        self.assertIn("i08", frame.value_source["child_storage"])

    def test_same_name_controls_have_distinct_identity(self):
        labels = [r for r in self.records if r.name == "Label1"]
        self.assertGreaterEqual(len(labels), 2)
        identities = {(r.form_path, r.site_index, r.site_id) for r in labels}
        self.assertEqual(len(identities), len(labels))
        streams_used = {r.value_source["stream"] for r in labels}
        self.assertEqual(len(streams_used), len(labels))

    def test_nested_control_attributed_to_child_form(self):
        nested = [r for r in self.records
                  if r.form_path == "UserFormTEST1/i08" and r.name == "TextBox2"]
        self.assertEqual(len(nested), 1)
        self.assertEqual(nested[0].value, "abcd")
        self.assertTrue(nested[0].value_source["stream"].endswith("i08/o"))

    def test_report_deterministic_and_grouped(self):
        text = ff.render_text_report(self.records)
        self.assertIn("Project:", text)
        self.assertIn("UserFormTEST1", text)
        as_dicts = ff.records_as_dicts(self.records)
        self.assertEqual(as_dicts, sorted(as_dicts, key=lambda d: d["record_id"]))

    def test_codepage_fallback_reported(self):
        streams = load_sample_streams()
        codepage, source = ff.resolve_codepage(FakeOle(streams))
        self.assertEqual(codepage, ff.DEFAULT_CODEPAGE)
        self.assertIn("default", source)

    def test_explicit_codepage_used(self):
        fake = FakeOle({("PROJECT",): b"Name=\x22P\x22\nCodePage=1252\n"})
        codepage, source = ff.resolve_codepage(fake)
        self.assertEqual(codepage, 1252)
        self.assertIn("PROJECT", source)


class UnreadableTest(unittest.TestCase):
    def test_missing_o_stream_marks_unreadable(self):
        streams = load_sample_streams()
        broken = {path: data for path, data in streams.items()
                  if not (path and path[0] == "UserFormTest2" and path[-1] == "o")}
        records = ff.extract_control_defaults(FakeOle(broken), "P", "c")
        target = [r for r in records if r.form_path == "UserFormTest2"]
        self.assertTrue(target)
        self.assertTrue(all(r.status == ff.STATUS_UNREADABLE for r in target))
        self.assertTrue(all(r.value_source.get("reason") == "missing o stream"
                            for r in target))

    def test_malformed_o_stream_not_silently_dropped(self):
        streams = load_sample_streams()
        broken = dict(streams)
        broken[("UserFormTest2", "o")] = b"\x00\x02\xff\xff" + b"\x00" * 8
        records = ff.extract_control_defaults(FakeOle(broken), "P", "c")
        target = [r for r in records if r.form_path == "UserFormTest2"]
        self.assertTrue(target)
        self.assertTrue(any(r.status == ff.STATUS_UNREADABLE for r in target))

    def test_same_name_controls_survive_reversed_listing(self):
        streams = load_sample_streams()
        forward = {(r.form_path, r.record_id): r
                   for r in ff.extract_control_defaults(FakeOle(streams, False),"P","c")}
        backward = {(r.form_path, r.record_id): r
                    for r in ff.extract_control_defaults(FakeOle(streams, True),"P","c")}
        self.assertEqual(set(forward), set(backward))
        labels_f = {r.form_path: r for r in forward.values() if r.name == "Label1"}
        labels_b = {r.form_path: r for r in backward.values() if r.name == "Label1"}
        self.assertEqual(set(labels_f), set(labels_b))
        self.assertGreaterEqual(len(labels_f), 2)
        for form_path, record in labels_f.items():
            self.assertEqual(record.value_source, labels_b[form_path].value_source)
            self.assertEqual(record.status, labels_b[form_path].status)


if __name__ == "__main__":
    unittest.main()
