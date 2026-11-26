import pytest

import bleach
from bleach import (
    ClipboardBoundaryError,
    clean,
    clean_clipboard,
    clean_clipboard_html,
    extract_clipboard_fragment,
)
from bleach.sanitizer import Cleaner


def make_clipboard_html(
    fragment, prefix="<div>选区外便笺</div>", suffix="<div>尾部便笺</div>"
):
    selected = f"<!--StartFragment-->{fragment}<!--EndFragment-->"
    template = (
        "Version:0.9\n"
        "StartHTML:{start_html}\n"
        "EndHTML:{end_html}\n"
        "StartFragment:{start_fragment}\n"
        "EndFragment:{end_fragment}\n"
        "\n"
        f"{prefix}{selected}{suffix}"
    )
    placeholders = "0" * 10
    header_prefix = template.format(
        start_html=placeholders,
        end_html=placeholders,
        start_fragment=placeholders,
        end_fragment=placeholders,
    ).split(selected)[0]

    start_fragment = len(header_prefix.encode("utf-8"))
    end_fragment = start_fragment + len(selected.encode("utf-8"))
    payload = template.format(
        start_html=placeholders,
        end_html=placeholders,
        start_fragment=f"{start_fragment:010d}",
        end_fragment=f"{end_fragment:010d}",
    ).encode("utf-8")
    start_html = payload.index(b"<div>")
    end_html = len(payload)
    payload = payload.replace(placeholders.encode(), f"{start_html:010d}".encode(), 1)
    payload = payload.replace(placeholders.encode(), f"{end_html:010d}".encode(), 1)
    return payload


def test_clean_clipboard_html_keeps_only_selected_text_and_link():
    fragment = (
        '<p>中文 English 混合 <a href="https://example.com/路径">普通链接</a></p>'
    )
    payload = make_clipboard_html(fragment)

    cleaned = clean_clipboard_html(
        payload,
        tags={"p", "a"},
        attributes={"a": ["href"]},
    )

    assert cleaned == (
        '<p>中文 English 混合 <a href="https://example.com/路径">普通链接</a></p>'
    )
    assert "选区外便笺" not in cleaned
    assert "尾部便笺" not in cleaned


def test_clean_clipboard_html_accepts_utf8_text_and_byte_offsets():
    fragment = "<p>中文和English及😀混合</p>"
    payload = make_clipboard_html(fragment)

    assert (
        extract_clipboard_fragment(payload)
        == f"<!--StartFragment-->{fragment}<!--EndFragment-->"
    )
    assert extract_clipboard_fragment(payload.decode("utf-8")) == (
        f"<!--StartFragment-->{fragment}<!--EndFragment-->"
    )
    assert clean_clipboard_html(payload, tags={"p"}) == fragment
    assert clean_clipboard(payload.decode("utf-8"), tags={"p"}) == fragment


def test_clean_clipboard_html_uses_existing_cleaner():
    fragment = '<p>正文 <a href="https://example.com">普通链接</a></p>'
    payload = make_clipboard_html(fragment)
    cleaner = Cleaner(tags={"p", "a"}, attributes={"a": ["href"]})

    assert clean_clipboard_html(payload, cleaner=cleaner) == fragment


def test_clean_clipboard_html_passes_strip_options_to_cleaner():
    payload = make_clipboard_html("<p>正文</p><span>片段</span>")

    assert clean_clipboard_html(payload, tags={"p"}, strip=True) == ("<p>正文</p>片段")


def test_only_selected_fragment_is_sent_to_cleaner():
    fragment = "<p>选区正文</p>"
    payload = make_clipboard_html(fragment)

    class RecordingCleaner(Cleaner):
        def clean(self, text):
            self.received_text = text
            return super().clean(text)

    cleaner = RecordingCleaner(tags={"p"})
    clean_clipboard_html(payload, cleaner=cleaner)

    assert cleaner.received_text == f"<!--StartFragment-->{fragment}<!--EndFragment-->"
    assert "选区外便笺" not in cleaner.received_text
    assert "尾部便笺" not in cleaner.received_text


def test_clean_clipboard_html_rejects_conflicting_fragment_offsets():
    payload = make_clipboard_html("<p>中文 English</p>")
    ambiguous = payload.replace(b"StartFragment:0", b"StartFragment:1", 1)

    with pytest.raises(ClipboardBoundaryError, match="StartFragment header and marker"):
        clean_clipboard_html(ambiguous)


def test_clean_clipboard_html_rejects_ambiguous_end_offset():
    payload = make_clipboard_html("<p>中文 English</p>")
    ambiguous = payload.replace(b"EndFragment:0", b"EndFragment:9", 1)

    with pytest.raises(ClipboardBoundaryError, match="EndFragment header and marker"):
        clean_clipboard_html(ambiguous)


def test_clean_clipboard_html_rejects_multibyte_split_boundary():
    payload = make_clipboard_html("<p>中文</p>")
    marker = b"<!--EndFragment-->"
    marker_start = payload.index(marker)
    split_offset = marker_start - 6
    ambiguous = payload.replace(
        b"EndFragment:" + f"{marker_start + len(marker):010d}".encode(),
        b"EndFragment:" + f"{split_offset:010d}".encode(),
    )

    with pytest.raises(ClipboardBoundaryError, match="EndFragment header and marker"):
        clean_clipboard_html(ambiguous)


def test_clean_clipboard_html_rejects_missing_marker():
    payload = make_clipboard_html("<p>中文 English</p>").replace(
        b"<!--StartFragment-->", b"<!--OtherFragment-->"
    )

    with pytest.raises(ClipboardBoundaryError, match="StartFragment marker"):
        extract_clipboard_fragment(payload)


def test_clean_clipboard_html_rejects_invalid_type_before_cleaning():
    with pytest.raises(TypeError, match="must be of text or bytes type"):
        clean_clipboard_html(None)


def test_cleaner_and_cleaner_arguments_cannot_be_combined():
    payload = make_clipboard_html("<p>正文</p>")
    cleaner = Cleaner(tags={"p"})

    with pytest.raises(TypeError, match="cleaner cannot be combined"):
        clean_clipboard_html(payload, tags={"p"}, cleaner=cleaner)


def test_ordinary_clean_interface_still_accepts_html():
    html = '<p>普通 HTML <a href="https://example.com">链接</a></p>'

    assert clean(html, tags={"p", "a"}, attributes={"a": ["href"]}) == html
    assert bleach.clean("<span>普通文本</span>") == "&lt;span&gt;普通文本&lt;/span&gt;"
