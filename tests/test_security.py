"""Tests for the read-only active content audit API in pypdf.security."""

import json
from io import BytesIO
from typing import NoReturn

import pytest

from pypdf import PdfReader, PdfWriter
from pypdf.annotations import Link, Text
from pypdf.errors import ActiveContentError, AuditBudgetExceededError
from pypdf.generic import (
    ArrayObject,
    DecodedStreamObject,
    DictionaryObject,
    NameObject,
    NullObject,
    NumberObject,
    TextStringObject,
)
from pypdf.security import (
    ActiveContentKind,
    ActiveContentLocation,
    ActiveContentPolicy,
    ActiveContentScanner,
    AuditBudget,
    audit_active_content,
)


def _action(subtype: str, **entries: object) -> DictionaryObject:
    action = DictionaryObject()
    action[NameObject("/S")] = NameObject(f"/{subtype}")
    for key, value in entries.items():
        action[NameObject(key)] = value
    return action


def _js_action(script: str) -> DictionaryObject:
    return _action("JavaScript", **{"/JS": TextStringObject(script)})


def _reader_from_writer(writer: PdfWriter) -> PdfReader:
    buffer = BytesIO()
    writer.write(buffer)
    buffer.seek(0)
    return PdfReader(buffer)


@pytest.fixture
def writer() -> PdfWriter:
    output = PdfWriter()
    output.add_blank_page(width=200, height=200)
    return output


def _entry_kinds(report) -> set[str]:
    return {str(entry.kind) for entry in report.entries}


def test_clean_document_has_no_active_content(writer):
    # A text field value and a read-only comment are not active content.
    writer.add_annotation(0, Text(rect=(0, 0, 10, 10), text="just a comment"))
    reader = _reader_from_writer(writer)

    report = ActiveContentScanner(reader).scan()

    assert not report.has_active_content
    assert report.entries == []
    assert json.loads(json.dumps(report.to_dict())) == report.to_dict()


def test_plain_link_annotation_is_not_active_content(writer):
    writer.add_annotation(0, Link(rect=(0, 0, 10, 10), url="https://example.invalid/docs"))
    reader = _reader_from_writer(writer)

    report = audit_active_content(reader)

    assert not report.has_active_content
    assert report.entries == []


def test_uri_and_goto_annotation_actions_are_not_active_content(writer):
    uri_annotation = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Annot"),
            NameObject("/Subtype"): NameObject("/Link"),
            NameObject("/Rect"): ArrayObject([NumberObject(0)] * 4),
            NameObject("/A"): _action("URI", **{"/URI": TextStringObject("https://example.invalid")}),
        }
    )
    goto_annotation = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Annot"),
            NameObject("/Subtype"): NameObject("/Link"),
            NameObject("/Rect"): ArrayObject([NumberObject(0)] * 4),
            NameObject("/A"): _action("GoTo", **{"/D": TextStringObject("section")}),
        }
    )
    writer.pages[0][NameObject("/Annots")] = ArrayObject(
        [writer._add_object(uri_annotation), writer._add_object(goto_annotation)]
    )
    reader = _reader_from_writer(writer)

    report = ActiveContentScanner(reader).scan()

    assert not report.has_active_content


def test_javascript_name_tree_is_reported(writer):
    js_action = writer._add_object(_js_action("this.print();"))
    names = DictionaryObject(
        {
            NameObject("/JavaScript"): DictionaryObject(
                {NameObject("/Names"): ArrayObject([TextStringObject("script-1"), js_action])}
            )
        }
    )
    writer.root_object[NameObject("/Names")] = names
    reader = _reader_from_writer(writer)

    report = ActiveContentScanner(reader).scan()

    entry = report.entries[0]
    assert str(entry.kind) == ActiveContentKind.JAVASCRIPT
    assert entry.location == ActiveContentLocation.NAME_TREE_JAVASCRIPT
    assert entry.script_preview == "this.print();"


def test_field_launch_action_is_reported(writer):
    launch = _action("Launch", **{"/F": TextStringObject("x.sh")})
    field = DictionaryObject(
        {
            NameObject("/T"): TextStringObject("f"),
            NameObject("/FT"): NameObject("/Tx"),
            NameObject("/AA"): DictionaryObject({NameObject("/F"): launch}),
        }
    )
    writer.root_object[NameObject("/AcroForm")] = writer._add_object(
        DictionaryObject({NameObject("/Fields"): ArrayObject([writer._add_object(field)])})
    )
    reader = _reader_from_writer(writer)

    entry = ActiveContentScanner(reader).scan().entries[0]

    assert str(entry.kind) == ActiveContentKind.LAUNCH
    assert entry.location == ActiveContentLocation.FIELD_AA
    assert entry.trigger == "/F"
    assert entry.field_name == "f"
    assert entry.target == "x.sh"


def test_open_action_javascript_is_reported(writer):
    js = writer._add_object(_js_action("app.alert('open');"))
    writer.root_object[NameObject("/OpenAction")] = js
    reader = _reader_from_writer(writer)

    report = ActiveContentScanner(reader).scan()

    assert len(report.entries) == 1
    entry = report.entries[0]
    assert str(entry.kind) == ActiveContentKind.JAVASCRIPT
    assert entry.location == ActiveContentLocation.CATALOG_OPEN_ACTION
    assert entry.action_type == "JavaScript"
    assert entry.object_number is not None
    assert entry.generation == 0
    assert entry.reference_chain == ("/Catalog", "/OpenAction")
    assert entry.script_preview == "app.alert('open');"
    assert entry.script_length == len("app.alert('open');")
    assert not entry.script_truncated


def test_array_open_action_destination_is_not_active_content(writer):
    page_ref = writer.pages[0].indirect_reference
    writer.root_object[NameObject("/OpenAction")] = ArrayObject([page_ref, NameObject("/Fit")])
    reader = _reader_from_writer(writer)

    report = ActiveContentScanner(reader).scan()

    assert not report.has_active_content


def test_launch_action_target_is_reported_but_not_resolved(writer, monkeypatch):
    def fail(*args: object, **kwargs: object) -> NoReturn:  # pragma: no cover
        raise AssertionError("auditing must not resolve external programs")

    monkeypatch.setattr("subprocess.Popen", fail)
    monkeypatch.setattr("os.system", fail)
    launch = writer._add_object(
        _action(
            "Launch",
            **{"/Win": DictionaryObject({NameObject("/F"): TextStringObject("calc.exe")})},
        )
    )
    writer.root_object[NameObject("/OpenAction")] = launch
    reader = _reader_from_writer(writer)

    report = ActiveContentScanner(reader).scan()

    assert str(report.entries[0].kind) == ActiveContentKind.LAUNCH
    assert report.entries[0].target == "calc.exe"
    assert report.entries[0].action_type == "Launch"


def test_submit_form_action_is_reported(writer):
    submit = writer._add_object(
        _action(
            "SubmitForm",
            **{"/F": TextStringObject("https://example.invalid/collect")},
        )
    )
    field = DictionaryObject(
        {
            NameObject("/T"): TextStringObject("send"),
            NameObject("/FT"): NameObject("/Btn"),
            NameObject("/A"): submit,
        }
    )
    acroform = DictionaryObject({NameObject("/Fields"): ArrayObject([writer._add_object(field)])})
    writer.root_object[NameObject("/AcroForm")] = writer._add_object(acroform)
    reader = _reader_from_writer(writer)

    report = ActiveContentScanner(reader).scan()
    kinds = _entry_kinds(report)
    assert ActiveContentKind.SUBMIT_FORM in kinds
    submit_entry = next(entry for entry in report.entries if str(entry.kind) == ActiveContentKind.SUBMIT_FORM)
    assert submit_entry.target == "https://example.invalid/collect"
    assert submit_entry.field_name == "send"


def test_field_additional_actions_are_reported_with_full_name_and_page(writer):
    child = DictionaryObject(
        {
            NameObject("/T"): TextStringObject("child"),
            NameObject("/FT"): NameObject("/Tx"),
            NameObject("/AA"): DictionaryObject({NameObject("/K"): _js_action("event.change = '';")}),
        }
    )
    parent = DictionaryObject(
        {
            NameObject("/T"): TextStringObject("parent"),
            NameObject("/Kids"): ArrayObject([writer._add_object(child)]),
        }
    )
    acroform = DictionaryObject({NameObject("/Fields"): ArrayObject([writer._add_object(parent)])})
    writer.root_object[NameObject("/AcroForm")] = writer._add_object(acroform)
    reader = _reader_from_writer(writer)

    report = ActiveContentScanner(reader).scan()

    entry = report.entries[0]
    assert str(entry.kind) == ActiveContentKind.JAVASCRIPT
    assert entry.location == ActiveContentLocation.FIELD_AA
    assert entry.trigger == "/K"
    assert entry.field_name == "parent.child"
    assert entry.reference_chain[-2:] == ("/AA", "/K")


def test_embedded_file_is_reported(writer):
    writer.add_attachment("payload.bin", b"binary contents")
    reader = _reader_from_writer(writer)

    report = ActiveContentScanner(reader).scan()

    entry = report.entries[0]
    assert str(entry.kind) == ActiveContentKind.EMBEDDED_FILE
    assert entry.location == ActiveContentLocation.NAME_TREE_EMBEDDED_FILE
    assert entry.target == "payload.bin"
    assert entry.object_number is not None
    assert "/EmbeddedFiles" in entry.reference_chain


def test_rich_media_annotation_is_reported(writer):
    rich_media = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Annot"),
            NameObject("/Subtype"): NameObject("/RichMedia"),
            NameObject("/Rect"): ArrayObject([NumberObject(0)] * 4),
        }
    )
    writer.pages[0][NameObject("/Annots")] = ArrayObject([writer._add_object(rich_media)])
    reader = _reader_from_writer(writer)

    report = ActiveContentScanner(reader).scan()

    assert str(report.entries[0].kind) == ActiveContentKind.RICH_MEDIA
    assert report.entries[0].page_number == 0
    assert report.entries[0].location == ActiveContentLocation.RICH_MEDIA_ANNOTATION


def test_recursive_action_chain_is_bounded_and_enumerated(writer):
    first = _js_action("step 1")
    second = _js_action("step 2")
    first_ref = writer._add_object(first)
    second_ref = writer._add_object(second)
    first[NameObject("/Next")] = second_ref
    second[NameObject("/Next")] = first_ref  # cycle back to the first action
    writer.root_object[NameObject("/OpenAction")] = first_ref
    reader = _reader_from_writer(writer)

    report = ActiveContentScanner(reader).scan()

    scripts = sorted(entry.script_preview for entry in report.entries)
    assert scripts == ["step 1", "step 2"]
    assert report.duplicates_seen >= 1


def test_repeated_objects_are_counted_not_reported_twice(writer):
    shared = writer._add_object(_js_action("shared"))
    aa = DictionaryObject(
        {
            NameObject("/O"): shared,
            NameObject("/C"): shared,
        }
    )
    writer.pages[0][NameObject("/AA")] = aa
    reader = _reader_from_writer(writer)

    report = ActiveContentScanner(reader).scan()

    assert len(report.entries) == 2  # distinct triggers, same object
    assert report.duplicates_seen >= 1


def test_oversized_script_is_truncated_with_budget(writer):
    big_script = "x" * 500
    writer.root_object[NameObject("/OpenAction")] = writer._add_object(_js_action(big_script))
    reader = _reader_from_writer(writer)

    report = ActiveContentScanner(reader, budget=AuditBudget(max_script_length=100)).scan()

    entry = report.entries[0]
    assert entry.script_truncated is True
    assert entry.script_length == 500
    assert len(entry.script_preview) == 100
    assert report.truncated_scripts == 1


def test_stream_script_is_read_within_budget(writer):
    stream = DecodedStreamObject()
    stream.set_data(b"app.alert('streamed');")
    action = _action("JavaScript", **{"/JS": writer._add_object(stream)})
    writer.root_object[NameObject("/OpenAction")] = writer._add_object(action)
    reader = _reader_from_writer(writer)

    entry = ActiveContentScanner(reader, budget=AuditBudget(max_script_bytes=8, max_script_length=8)).scan().entries[0]

    assert entry.script_truncated is True
    assert entry.script_preview == "app.aler"
    assert entry.script_length == 8


def test_depth_budget_stops_recursive_dictionaries(writer):
    # Build a deeply nested /Next chain by hand.
    head = _js_action("depth")
    current = head
    for _ in range(50):
        nxt = _js_action("depth")
        current[NameObject("/Next")] = nxt
        current = nxt
    writer.root_object[NameObject("/OpenAction")] = writer._add_object(head)
    reader = _reader_from_writer(writer)

    with pytest.raises(AuditBudgetExceededError):
        ActiveContentScanner(reader, budget=AuditBudget(max_depth=5)).scan()


def test_corrupt_dictionary_is_handled(writer):
    writer.root_object[NameObject("/AA")] = NameObject("/broken")
    reader = _reader_from_writer(writer)

    report = ActiveContentScanner(reader).scan()

    assert not report.has_active_content
    assert report.malformed_seen == 1


def test_reject_policy_raises_and_keeps_report(writer):
    writer.root_object[NameObject("/OpenAction")] = writer._add_object(_js_action("app.alert('no');"))
    reader = _reader_from_writer(writer)

    with pytest.raises(ActiveContentError) as exc_info:
        ActiveContentScanner(reader, policy=ActiveContentPolicy.REJECT).scan()

    assert exc_info.value.report is not None
    assert exc_info.value.report.has_active_content


def test_purge_policy_removes_actions_and_embedded_files(writer):
    writer.root_object[NameObject("/OpenAction")] = writer._add_object(_js_action("app.alert('go');"))
    writer.pages[0][NameObject("/AA")] = DictionaryObject({NameObject("/O"): _js_action("page open")})
    writer.add_attachment("note.txt", b"data")
    reader = _reader_from_writer(writer)

    report = ActiveContentScanner(reader, policy=ActiveContentPolicy.PURGE).scan()

    assert report.purged is True
    assert "/OpenAction" not in reader.root_object
    assert "/AA" not in reader.pages[0]
    assert "/EmbeddedFiles" not in reader.root_object.get("/Names", {})

    second = ActiveContentScanner(reader).scan()
    assert not second.has_active_content


def test_purge_keeps_plain_links_and_form_values(writer):
    writer.add_annotation(0, Link(rect=(0, 0, 10, 10), url="https://example.invalid/keep"))
    field = DictionaryObject(
        {
            NameObject("/T"): TextStringObject("name"),
            NameObject("/FT"): NameObject("/Tx"),
            NameObject("/V"): TextStringObject("filled value"),
        }
    )
    writer.root_object[NameObject("/AcroForm")] = writer._add_object(
        DictionaryObject({NameObject("/Fields"): ArrayObject([writer._add_object(field)])})
    )
    reader = _reader_from_writer(writer)

    ActiveContentScanner(reader, policy=ActiveContentPolicy.PURGE).scan()

    assert reader.pages[0].annotations
    assert reader.root_object["/AcroForm"]["/Fields"]


def test_purge_keeps_non_active_trigger_actions(writer):
    goto = _action("GoTo", **{"/D": TextStringObject("destination")})
    writer.pages[0][NameObject("/AA")] = DictionaryObject({NameObject("/O"): goto})
    reader = _reader_from_writer(writer)

    report = ActiveContentScanner(reader, policy=ActiveContentPolicy.PURGE).scan()

    assert not report.has_active_content
    assert "/AA" in reader.pages[0]
    assert "/O" in reader.pages[0]["/AA"]


def test_report_is_stably_json_serialisable(writer):
    writer.root_object[NameObject("/OpenAction")] = writer._add_object(_js_action("app.alert(1);"))
    reader = _reader_from_writer(writer)

    report = reader.audit_active_content()
    encoded = json.dumps(report.to_dict(), sort_keys=True)
    encoded_again = json.dumps(ActiveContentScanner(reader).scan().to_dict(), sort_keys=True)

    assert encoded == encoded_again
    data = json.loads(encoded)
    assert data["entries"][0]["reference_chain"] == ["/Catalog", "/OpenAction"]


def test_null_action_entries_are_ignored(writer):
    writer.root_object[NameObject("/OpenAction")] = NullObject()
    reader = _reader_from_writer(writer)

    report = ActiveContentScanner(reader).scan()

    assert not report.has_active_content
