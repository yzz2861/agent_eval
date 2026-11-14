from __future__ import absolute_import, division, unicode_literals

import os

import pytest

from .support import get_data_files, test_dir, errorMessage, TestData as _TestData
from html5lib import HTMLParser, _inputstream
from html5lib._inputstream import EncodingError


class CountingStream(object):
    """A file-like object that counts the bytes actually read."""

    def __init__(self, data):
        self._stream = _inputstream.BytesIO(data)
        self.bytesRead = 0

    def read(self, size=-1):
        data = self._stream.read(size)
        self.bytesRead += len(data)
        return data

    def seek(self, *args):
        return self._stream.seek(*args)

    def tell(self):
        return self._stream.tell()


def test_sniffing_reads_are_bounded():
    # A document far larger than the prescan window must not be pulled
    # into memory while sniffing for the encoding
    data = b"<meta charset=utf-8>" + b"a" * (10 * 1024 * 1024)
    source = CountingStream(data)
    stream = _inputstream.HTMLBinaryInputStream(source, useChardet=False)
    assert stream.charEncoding[0].name == "utf-8"
    # 4 bytes for the BOM check plus at most numBytesMeta for the prescan
    assert stream.bytesRead == 4 + stream.numBytesMeta
    assert source.bytesRead == stream.bytesRead


def test_prescan_bytes_kwarg_limits_window():
    pad = b"<!--" + b"a" * 600 + b"-->"
    data = pad + b"<meta charset=utf-8>"
    stream = _inputstream.HTMLBinaryInputStream(
        data, useChardet=False, prescan_bytes=64)
    assert stream.numBytesMeta == 64
    # The meta element is outside the sampling window
    assert stream.charEncoding[0].name == "windows-1252"
    assert stream.bytesRead == 4 + 64
    stream = _inputstream.HTMLBinaryInputStream(
        data, useChardet=False, prescan_bytes=4096)
    assert stream.charEncoding[0].name == "utf-8"


def test_bom_meta_conflict():
    import codecs
    data = codecs.BOM_UTF8 + b"<meta charset=gbk>"
    stream = _inputstream.HTMLBinaryInputStream(data, useChardet=False)
    # The BOM wins over the meta declaration
    assert stream.charEncoding[1] == "certain"
    assert stream.charEncoding[0].name == "utf-8"
    assert stream.encodingDecision.source == "bom"
    assert stream.encodingDecision.selected
    assert stream.bytesRead == 4


def test_transport_meta_conflict_recorded():
    data = b"<meta charset=iso-8859-3>"
    stream = _inputstream.HTMLBinaryInputStream(
        data, useChardet=False, transport_encoding="iso-8859-2")
    assert stream.charEncoding[0].name == "iso-8859-2"
    assert stream.encodingDecision.source == "transport"
    # The transport layer short-circuits the meta prescan
    assert [c.source for c in stream.encodingCandidates] == ["transport"]


def test_invalid_declared_label_falls_back():
    data = b"<meta charset=iso-8859-2>"
    stream = _inputstream.HTMLBinaryInputStream(
        data, useChardet=False, transport_encoding="totally-bogus")
    # No LookupError escapes; the invalid label is recorded and skipped
    assert stream.charEncoding[0].name == "iso-8859-2"
    invalid = [c for c in stream.encodingCandidates if not c.valid]
    assert len(invalid) == 1
    assert invalid[0].source == "transport"
    assert invalid[0].label == "totally-bogus"
    assert stream.encodingDecision.source == "meta"


def test_invalid_meta_label_falls_back():
    data = b"<meta charset=bogus><meta charset=utf-8>"
    stream = _inputstream.HTMLBinaryInputStream(data, useChardet=False)
    assert stream.charEncoding[0].name == "utf-8"
    assert stream.metaLabels == [b"bogus", b"utf-8"]
    assert stream.invalidMetaLabels == [b"bogus"]


def test_duplicate_meta_first_wins():
    data = b"<meta charset=utf-8><meta charset=gbk>"
    stream = _inputstream.HTMLBinaryInputStream(data, useChardet=False)
    assert stream.charEncoding[0].name == "utf-8"
    assert stream.metaEncodingLabel == b"utf-8"


def test_strict_mode_rejects_invalid_labels():
    with pytest.raises(EncodingError):
        _inputstream.HTMLBinaryInputStream(
            b"", useChardet=False, strict=True,
            transport_encoding="totally-bogus")
    with pytest.raises(EncodingError):
        _inputstream.HTMLBinaryInputStream(
            b"<meta charset=bogus>", useChardet=False, strict=True)
    with pytest.raises(EncodingError):
        _inputstream.HTMLBinaryInputStream(
            b"", useChardet=False, strict=True,
            default_encoding="totally-bogus")
    # Strict mode still accepts valid declarations
    stream = _inputstream.HTMLBinaryInputStream(
        b"<meta charset=utf-8>", useChardet=False, strict=True)
    assert stream.charEncoding[0].name == "utf-8"


def test_utf16_bom_and_truncated_bom():
    import codecs
    for bom, name in ((codecs.BOM_UTF16_LE, "utf-16le"),
                      (codecs.BOM_UTF16_BE, "utf-16be")):
        data = bom + "<meta charset=utf-8>".encode("utf-16-le" if "le" in name else "utf-16-be")
        stream = _inputstream.HTMLBinaryInputStream(data, useChardet=False)
        # The UTF-16 BOM wins over the conflicting meta declaration
        assert stream.charEncoding[0].name == name
        assert stream.encodingDecision.source == "bom"
    # A truncated UTF-8 BOM is not a BOM and must not raise
    stream = _inputstream.HTMLBinaryInputStream(b"\xef\xbb", useChardet=False)
    assert stream.charEncoding[0].name == "windows-1252"


def test_truncated_multibyte_and_nul():
    data = b"<meta charset=utf-8><title>a\xe4\x00b</title>\xc3"
    stream = _inputstream.HTMLBinaryInputStream(data, useChardet=False)
    assert stream.charEncoding[0].name == "utf-8"
    text = "".join(iter(stream.char, _inputstream.EOF))
    # A truncated multi-byte sequence becomes U+FFFD, NUL is preserved,
    # and the stream terminates cleanly instead of raising
    assert "a\ufffd\x00b" in text


def test_encoding_decision_observable():
    stream = _inputstream.HTMLBinaryInputStream(
        b"<meta charset=utf-8>", useChardet=False)
    assert stream.encodingDecision is not None
    assert stream.encodingDecision.source == "meta"
    assert stream.encodingDecision.name == "utf-8"
    assert stream.encodingDecision.confidence == "tentative"
    selected = [c for c in stream.encodingCandidates if c.selected]
    assert selected == [stream.encodingDecision]
    assert stream.encodingDecision.sampled == len(b"<meta charset=utf-8>")


def test_basic_prescan_length():
    data = "<title>Caf\u00E9</title><!--a--><meta charset='utf-8'>".encode('utf-8')
    pad = 1024 - len(data) + 1
    data = data.replace(b"-a-", b"-" + (b"a" * pad) + b"-")
    assert len(data) == 1024  # Sanity
    stream = _inputstream.HTMLBinaryInputStream(data, useChardet=False)
    assert 'utf-8' == stream.charEncoding[0].name


def test_parser_reparse():
    data = "<title>Caf\u00E9</title><!--a--><meta charset='utf-8'>".encode('utf-8')
    pad = 10240 - len(data) + 1
    data = data.replace(b"-a-", b"-" + (b"a" * pad) + b"-")
    assert len(data) == 10240  # Sanity
    stream = _inputstream.HTMLBinaryInputStream(data, useChardet=False)
    assert 'windows-1252' == stream.charEncoding[0].name
    p = HTMLParser(namespaceHTMLElements=False)
    doc = p.parse(data, useChardet=False)
    assert 'utf-8' == p.documentEncoding
    assert doc.find(".//title").text == "Caf\u00E9"


@pytest.mark.parametrize("expected,data,kwargs", [
    ("utf-16le", b"\xFF\xFE", {"override_encoding": "iso-8859-2"}),
    ("utf-16be", b"\xFE\xFF", {"override_encoding": "iso-8859-2"}),
    ("utf-8", b"\xEF\xBB\xBF", {"override_encoding": "iso-8859-2"}),
    ("iso-8859-2", b"", {"override_encoding": "iso-8859-2", "transport_encoding": "iso-8859-3"}),
    ("iso-8859-2", b"<meta charset=iso-8859-3>", {"transport_encoding": "iso-8859-2"}),
    ("iso-8859-2", b"<meta charset=iso-8859-2>", {"same_origin_parent_encoding": "iso-8859-3"}),
    ("iso-8859-2", b"", {"same_origin_parent_encoding": "iso-8859-2", "likely_encoding": "iso-8859-3"}),
    ("iso-8859-2", b"", {"same_origin_parent_encoding": "utf-16", "likely_encoding": "iso-8859-2"}),
    ("iso-8859-2", b"", {"same_origin_parent_encoding": "utf-16be", "likely_encoding": "iso-8859-2"}),
    ("iso-8859-2", b"", {"same_origin_parent_encoding": "utf-16le", "likely_encoding": "iso-8859-2"}),
    ("iso-8859-2", b"", {"likely_encoding": "iso-8859-2", "default_encoding": "iso-8859-3"}),
    ("iso-8859-2", b"", {"default_encoding": "iso-8859-2"}),
    ("windows-1252", b"", {"default_encoding": "totally-bogus-string"}),
    ("windows-1252", b"", {}),
])
def test_parser_args(expected, data, kwargs):
    stream = _inputstream.HTMLBinaryInputStream(data, useChardet=False, **kwargs)
    assert expected == stream.charEncoding[0].name
    p = HTMLParser()
    p.parse(data, useChardet=False, **kwargs)
    assert expected == p.documentEncoding


@pytest.mark.parametrize("kwargs", [
    {"override_encoding": "iso-8859-2"},
    {"override_encoding": None},
    {"transport_encoding": "iso-8859-2"},
    {"transport_encoding": None},
    {"same_origin_parent_encoding": "iso-8859-2"},
    {"same_origin_parent_encoding": None},
    {"likely_encoding": "iso-8859-2"},
    {"likely_encoding": None},
    {"default_encoding": "iso-8859-2"},
    {"default_encoding": None},
    {"foo_encoding": "iso-8859-2"},
    {"foo_encoding": None},
])
def test_parser_args_raises(kwargs):
    with pytest.raises(TypeError) as exc_info:
        p = HTMLParser()
        p.parse("", useChardet=False, **kwargs)
    assert exc_info.value.args[0].startswith("Cannot set an encoding with a unicode input")


def param_encoding():
    for filename in get_data_files("encoding"):
        tests = _TestData(filename, b"data", encoding=None)
        for test in tests:
            yield test[b'data'], test[b'encoding']


@pytest.mark.parametrize("data, encoding", param_encoding())
def test_parser_encoding(data, encoding):
    p = HTMLParser()
    assert p.documentEncoding is None
    p.parse(data, useChardet=False)
    encoding = encoding.lower().decode("ascii")

    assert encoding == p.documentEncoding, errorMessage(data, encoding, p.documentEncoding)


@pytest.mark.parametrize("data, encoding", param_encoding())
def test_prescan_encoding(data, encoding):
    stream = _inputstream.HTMLBinaryInputStream(data, useChardet=False)
    encoding = encoding.lower().decode("ascii")

    # Very crude way to ignore irrelevant tests
    if len(data) > stream.numBytesMeta:
        return

    assert encoding == stream.charEncoding[0].name, errorMessage(data, encoding, stream.charEncoding[0].name)


# pylint:disable=wrong-import-position
try:
    import chardet  # noqa
except ImportError:
    print("chardet not found, skipping chardet tests")
else:
    def test_chardet():
        with open(os.path.join(test_dir, "encoding", "chardet", "test_big5.txt"), "rb") as fp:
            encoding = _inputstream.HTMLInputStream(fp.read()).charEncoding
            assert encoding[0].name == "big5"
# pylint:enable=wrong-import-position
