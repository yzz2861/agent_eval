import xml.etree.ElementTree as ET

import pytest

import Evtx.Evtx as evtx
import Evtx.Nodes as e_nodes
import Evtx.Views as e_views
import Evtx.Sanitizers as e_sanitizers


def one(iterable):
    for i in iterable:
        return i


def utf16le(s):
    return s.encode("utf-16-le")


def wstring_node(data):
    return e_nodes.get_variant_value(data, 0, None, None, e_nodes.NODE_TYPES.WSTRING, length=len(data))


def parse_text(xml_text):
    return ET.fromstring("<root>%s</root>" % xml_text).text or ""


def parse_attr(xml_attr):
    return ET.fromstring('<root a="%s"/>' % xml_attr).get("a")


def parse_cdata(xml_cdata):
    return ET.fromstring("<root><![CDATA[%s]]></root>" % xml_cdata).text or ""


class TestDecodeUtf16:
    def test_valid_bmp(self):
        assert e_sanitizers.decode_utf16le(utf16le("hello world")) == "hello world"

    def test_valid_non_bmp_and_combining(self):
        s = "emoji 🚀 combining é 𝄞"
        assert e_sanitizers.decode_utf16le(utf16le(s)) == s

    def test_truncated_final_unit_replaced(self):
        assert e_sanitizers.decode_utf16le(b"a\x00\x61") == "a\ufffd"

    def test_unpaired_high_surrogate_replaced(self):
        assert e_sanitizers.decode_utf16le(b"a\x00\x00\xd8b\x00") == "a\ufffdb"

    def test_unpaired_low_surrogate_replaced(self):
        assert e_sanitizers.decode_utf16le(b"a\x00\x00\xdc") == "a\ufffd"

    def test_high_surrogate_followed_by_non_low_replaced(self):
        assert e_sanitizers.decode_utf16le(b"\x00\xd8A\x00") == "\ufffdA"

    def test_valid_surrogate_pair_kept(self):
        assert e_sanitizers.decode_utf16le(b"\x00\xd8\x00\xdc") == "\U00010000"

    def test_strict_rejects_unpaired_surrogate(self):
        with pytest.raises(UnicodeDecodeError):
            e_sanitizers.decode_utf16le(b"\x00\xd8", strict=True)

    def test_strict_rejects_truncation(self):
        with pytest.raises(UnicodeDecodeError):
            e_sanitizers.decode_utf16le(b"\x61", strict=True)

    def test_budget_exceeded(self, monkeypatch):
        monkeypatch.setattr(e_sanitizers, "MAX_STRING_CHARS", 4)
        with pytest.raises(e_sanitizers.StringBudgetExceededError):
            e_sanitizers.decode_utf16le(utf16le("12345"))


class TestSanitizeChars:
    def test_nul_replaced(self):
        assert e_sanitizers.sanitize_chars("a\x00b") == "a\ufffdb"

    def test_control_characters_replaced(self):
        assert e_sanitizers.sanitize_chars("\x01\x0b\x1f\x7f\x84") == "\ufffd\ufffd\ufffd\ufffd\ufffd"

    def test_lone_surrogate_replaced(self):
        assert e_sanitizers.sanitize_chars("a\ud800b") == "a\ufffdb"

    def test_tab_lf_cr_kept(self):
        assert e_sanitizers.sanitize_chars("\t\n\r") == "\t\n\r"

    def test_legal_unicode_untouched(self):
        s = "héllo 🚀 é 𝄞 中文"
        assert e_sanitizers.sanitize_chars(s) == s

    def test_strict_rejects(self):
        with pytest.raises(e_sanitizers.DisallowedCharacterError):
            e_sanitizers.sanitize_chars("a\x00b", strict=True)

    def test_replacement_is_auditable(self, caplog):
        with caplog.at_level("WARNING", logger="Evtx.Sanitizers"):
            e_sanitizers.sanitize_chars("a\x00\x01b")
        assert "2 restricted character(s)" in caplog.text


class TestEscapeContexts:
    def test_text_escapes_markup(self):
        assert e_sanitizers.escape_text("""<a>&'"</a>""") == """&lt;a&gt;&amp;'"&lt;/a&gt;"""

    def test_text_escapes_cdata_close(self):
        assert e_sanitizers.escape_text("x]]>y") == "x]]&gt;y"

    def test_text_escapes_cr_for_round_trip(self):
        assert e_sanitizers.escape_text("a\rb") == "a&#xD;b"

    def test_text_keeps_legal_unicode_raw(self):
        s = "emoji 🚀 combining é 𝄞"
        assert e_sanitizers.escape_text(s) == s

    def test_attr_escapes_quotes(self):
        assert e_sanitizers.escape_attr('a"b') == "a&quot;b"

    def test_attr_escapes_whitespace_for_round_trip(self):
        assert e_sanitizers.escape_attr("\t\n\r") == "&#x9;&#xA;&#xD;"

    def test_attr_escapes_markup(self):
        assert e_sanitizers.escape_attr("<a>&") == "&lt;a&gt;&amp;"

    def test_cdata_splits_close_delimiter(self):
        assert e_sanitizers.escape_cdata("x]]>y") == "x]]]]><![CDATA[>y"

    def test_cdata_keeps_markup_raw(self):
        assert e_sanitizers.escape_cdata("<a>&amp;") == "<a>&amp;"

    def test_cdata_splits_cr(self):
        assert e_sanitizers.escape_cdata("a\rb") == "a]]>&#xD;<![CDATA[b"

    def test_name_validation_accepts_legal_names(self):
        for name in ("Event", "xmlns", "xmlns:auto-ns3", "_x-1", "a.b", "A9"):
            assert e_sanitizers.validate_name(name) == name

    @pytest.mark.parametrize("name", ["", "1a", "a b", "<a", "a/b", "a>b", "-a", "a\x00b"])
    def test_name_validation_rejects_illegal_names(self, name):
        with pytest.raises(RuntimeError):
            e_sanitizers.validate_name(name)


class TestRoundTrip:
    @pytest.mark.parametrize(
        "s",
        [
            "plain text",
            "emoji 🚀 and non-bmp 𝄞 and combining é",
            "markup <>&'\"",
            "cdata close ]]> and ]]>>",
            "line\rbreaks\r\nhere\n",
            "tabs\tand unicode 中文",
        ],
    )
    def test_text_round_trip(self, s):
        assert parse_text(e_sanitizers.escape_text(s)) == s

    @pytest.mark.parametrize(
        "s",
        [
            "plain",
            "quote\" and apostrophe'",
            "emoji 🚀 𝄞",
            "whitespace \t\n\r preserved",
            "markup <>&",
        ],
    )
    def test_attr_round_trip(self, s):
        assert parse_attr(e_sanitizers.escape_attr(s)) == s

    @pytest.mark.parametrize(
        "s",
        [
            "plain",
            "close ]]> delimiter",
            "double ]]>]]> close",
            "trailing ]]",
            "markup <>& kept raw",
            "cr\rhere",
            "emoji 🚀",
        ],
    )
    def test_cdata_round_trip(self, s):
        assert parse_cdata(e_sanitizers.escape_cdata(s)) == s


class TestInjection:
    def test_text_injection_neutralized(self):
        payload = "</Event><script>alert(1)</script>"
        esc = e_sanitizers.escape_text(payload)
        assert "<script>" not in esc
        assert "</Event>" not in esc
        assert parse_text(esc) == payload

    def test_attribute_injection_neutralized(self):
        payload = '" onload="alert(1)'
        esc = e_sanitizers.escape_attr(payload)
        assert '"' not in esc
        assert parse_attr(esc) == payload

    def test_cdata_breakout_neutralized(self):
        payload = "]]></Event><script>alert(1)</script>"
        esc = e_sanitizers.escape_cdata(payload)
        assert parse_cdata(esc) == payload

    def test_decode_escape_chain_with_bad_utf16(self):
        # an unpaired surrogate followed by an XML injection attempt,
        # decoded from BinXML bytes and escaped for output.
        data = b"\x00\xd8" + utf16le("</Event><script>alert(1)</script>")
        node = wstring_node(data)
        esc = e_views.escape_value(node.string())
        assert esc.startswith("\ufffd")
        assert "<script>" not in esc
        assert parse_text(esc) == "\ufffd</Event><script>alert(1)</script>"

    def test_decode_escape_chain_with_nul(self, caplog):
        data = utf16le("a\x00b")
        node = wstring_node(data)
        with caplog.at_level("WARNING", logger="Evtx.Sanitizers"):
            esc = e_views.escape_value(node.string())
        assert esc == "a\ufffdb"
        assert "restricted character" in caplog.text

    def test_attribute_chain_escapes_quotes(self):
        data = utf16le('x" onload="evil')
        node = wstring_node(data)
        esc = e_views.escape_attr(node.string())
        assert '"' not in esc
        assert parse_attr(esc) == 'x" onload="evil'

    def test_wstring_array_decode(self):
        data = utf16le("one\x00") + utf16le("two\x00")
        node = e_nodes.get_variant_value(data, 0, None, None, e_nodes.NODE_TYPES.WSTRINGARRAY, length=len(data))
        assert node.string() == "<string>one</string>\n<string>two</string>\n"

    def test_wstring_array_non_bmp(self):
        data = utf16le("a🚀\x00")
        node = e_nodes.get_variant_value(data, 0, None, None, e_nodes.NODE_TYPES.WSTRINGARRAY, length=len(data))
        assert node.string() == "<string>a🚀</string>\n"


class TestStrictMode:
    def test_global_strict_flag(self):
        assert e_sanitizers.is_strict() is False
        e_sanitizers.set_strict(True)
        try:
            assert e_sanitizers.is_strict() is True
            with pytest.raises(e_sanitizers.DisallowedCharacterError):
                e_sanitizers.sanitize_chars("a\x00b")
        finally:
            e_sanitizers.set_strict(False)

    def test_strict_mode_context_manager(self):
        with e_sanitizers.strict_mode(True):
            with pytest.raises(UnicodeDecodeError):
                e_sanitizers.decode_utf16le(b"\x00\xd8")
        assert e_sanitizers.is_strict() is False
        assert e_sanitizers.decode_utf16le(b"\x00\xd8") == "\ufffd"


class TestRecordRendering:
    def first_record(self, buf):
        fh = evtx.FileHeader(buf, 0x0)
        chunk = one(fh.chunks())
        return one(chunk.records())

    def test_render_depth_budget(self, system, monkeypatch):
        record = self.first_record(system)
        monkeypatch.setattr(e_sanitizers, "MAX_RENDER_DEPTH", 1)
        with pytest.raises(e_views.UnexpectedElementException):
            e_views.evtx_record_xml_view(record)

    def test_render_depth_budget_default_ok(self, system):
        record = self.first_record(system)
        assert e_views.evtx_record_xml_view(record) is not None

    def test_strict_render_of_clean_record(self, system):
        record = self.first_record(system)
        xml = e_views.evtx_record_xml_view(record, strict=True)
        assert xml == e_views.evtx_record_xml_view(record)

    def test_rendered_record_is_well_formed_xml(self, system):
        record = self.first_record(system)
        root = ET.fromstring(e_views.evtx_record_xml_view(record))
        ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
        assert root.tag == ns + "Event"
        assert root.find("%sSystem/%sProvider" % (ns, ns)).get("Name") == "Microsoft-Windows-Eventlog"
