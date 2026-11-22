"""Tests for read-only navigation forensics."""

import json
from io import BytesIO

from pypdf import NavigationChain, PdfReader, PdfWriter, analyze_navigation
from pypdf.generic import (
    ArrayObject,
    DictionaryObject,
    NameObject,
    NullObject,
    NumberObject,
    TextStringObject,
)


def _writer_with_pages(page_count: int = 3) -> PdfWriter:
    writer = PdfWriter()
    for _ in range(page_count):
        writer.add_blank_page(width=200, height=200)
    return writer


def _roundtrip(writer: PdfWriter) -> PdfReader:
    stream = BytesIO()
    writer.write(stream)
    stream.seek(0)
    return PdfReader(stream)


def _link_annotation(**entries: object) -> DictionaryObject:
    annotation = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Annot"),
            NameObject("/Subtype"): NameObject("/Link"),
            NameObject("/Rect"): ArrayObject([NumberObject(10), NumberObject(10), NumberObject(100), NumberObject(40)]),
        }
    )
    for key, value in entries.items():
        annotation[NameObject("/" + key.lstrip("/"))] = value
    return annotation


def _chain_for(report, *, kind: str, index: int = 0) -> NavigationChain:
    return [chain for chain in report.chains if chain.origin.kind == kind][index]


def test_navigation_forensics__outline_annotations_destinations_and_external() -> None:
    writer = _writer_with_pages()
    writer.add_named_destination("named-target", 2)
    writer.add_named_destination("duplicate", 0)
    writer.add_named_destination("duplicate", 1)

    writer.add_outline_item("Direct outline", 1)
    writer.add_outline_item_dict(
        {
            NameObject("/Title"): TextStringObject("Named outline"),
            NameObject("/Dest"): TextStringObject("named-target"),
        }
    )
    writer.add_outline_item_dict(
        {
            NameObject("/Title"): TextStringObject("Missing outline"),
            NameObject("/Dest"): TextStringObject("not-registered"),
        }
    )

    writer.add_annotation(
        0,
        _link_annotation(Dest=ArrayObject([writer.pages[2].indirect_reference, NameObject("/Fit")])),
    )
    writer.add_annotation(
        1,
        _link_annotation(
            A=DictionaryObject(
                {
                    NameObject("/S"): NameObject("/URI"),
                    NameObject("/URI"): TextStringObject("file:///sealed/external.pdf"),
                }
            )
        ),
    )

    report = analyze_navigation(_roundtrip(writer))

    assert report.pages == 3
    assert len(report.named_destinations) == 3
    assert report.summary["direct_references"] >= 2
    assert report.summary["duplicate_names"] == 1

    outline_chains = [chain for chain in report.chains if chain.origin.kind == "outline"]
    assert [chain.origin.title for chain in outline_chains] == [
        "Direct outline",
        "Named outline",
        "Missing outline",
    ]
    assert outline_chains[0].status == "resolved"
    assert outline_chains[0].target_page_index == 1
    assert outline_chains[0].hop_count == 1
    assert outline_chains[1].status == "resolved"
    assert outline_chains[1].target_page_index == 2
    assert outline_chains[1].hop_count == 2
    assert outline_chains[2].status == "broken"
    assert outline_chains[2].broken_at_hop == 2

    annotation_chains = [chain for chain in report.chains if chain.origin.kind == "annotation"]
    assert annotation_chains[0].origin.page_index == 0
    assert annotation_chains[0].target_page_index == 2
    assert annotation_chains[1].status == "external"
    assert annotation_chains[1].hops[0].followed is False
    assert annotation_chains[1].hops[0].source.page_index == 1

    external = report.external_references[0]
    assert external.external_target == "file:///sealed/external.pdf"
    assert external.followed is False
    assert external.source.kind == "annotation"

    duplicate_group = report.duplicate_name_groups[0]
    assert duplicate_group.name == "duplicate"
    assert len(duplicate_group.entries) == 2
    assert duplicate_group.entries[0].source.name_tree_path != duplicate_group.entries[1].source.name_tree_path

    missing = report.missing_targets[0]
    assert missing.name == "not-registered"
    assert missing.hop_index == 2
    assert missing.source.outline_path == (2,)
    assert report.ok is False

    json.dumps(report.to_dict())


def test_two_hop_navigation_reports_break_at_second_hop_after_registration_removed() -> None:
    writer = _writer_with_pages()
    writer.add_named_destination("hop-target", 1)
    writer.add_annotation(
        0,
        _link_annotation(Dest=TextStringObject("hop-target")),
    )

    before = analyze_navigation(_roundtrip(writer))
    before_chain = _chain_for(before, kind="annotation")
    assert before_chain.status == "resolved"
    assert before_chain.target_page_index == 1
    assert before_chain.hop_count == 2
    assert before_chain.broken_at_hop is None
    assert not before.missing_targets

    root = writer.get_named_dest_root()
    for index in range(0, len(root), 2):
        if str(root[index]) == "hop-target":
            del root[index : index + 2]
            break
    else:  # pragma: no cover - assertion aid
        raise AssertionError("The named destination registration was not found.")

    after = analyze_navigation(_roundtrip(writer))
    after_chain = _chain_for(after, kind="annotation")
    assert after_chain.status == "broken"
    assert after_chain.hop_count == 2
    assert after_chain.hops[0].status == "ok"
    assert after_chain.hops[0].kind == "named"
    assert after_chain.hops[1].status == "missing"
    assert after_chain.broken_at_hop == 2
    assert after_chain.break_reason == "Named destination 'hop-target' is not registered."

    assert len(after.missing_targets) == 1
    missing = after.missing_targets[0]
    assert missing.hop_index == 2
    assert missing.name == "hop-target"
    assert missing.source.page_index == 0
    assert missing.source.annotation_index == 0
    assert missing.provenance == (missing.source,)


def test_direct_destination_with_missing_page_reports_first_hop() -> None:
    writer = _writer_with_pages()
    writer.add_annotation(
        0,
        _link_annotation(Dest=ArrayObject([NullObject(), NameObject("/Fit")])),
    )

    report = analyze_navigation(_roundtrip(writer))
    chain = _chain_for(report, kind="annotation")
    assert chain.status == "broken"
    assert chain.broken_at_hop == 1
    assert chain.hop_count == 1
    assert chain.hops[0].kind == "direct"
    assert chain.hops[0].status == "missing"
    assert report.direct_references[0].source.page_index == 0
    assert report.missing_targets[0].source.annotation_index == 0


def test_flat_named_destination_dictionary_is_read_with_provenance() -> None:
    writer = _writer_with_pages()
    dests = DictionaryObject(
        {NameObject("/flat"): ArrayObject([writer.pages[1].indirect_reference, NameObject("/Fit")])}
    )
    names = DictionaryObject({NameObject("/Dests"): dests})
    writer.root_object[NameObject("/Names")] = names

    report = analyze_navigation(_roundtrip(writer))
    assert len(report.named_destinations) == 1
    entry = report.named_destinations[0]
    assert entry.name == "flat"
    assert entry.page_index == 1
    assert entry.source.name_tree_path == ("catalog", "/Names", "/Dests", "/flat")


def test_reader_navigation_forensics_accessor_is_read_only_and_callable() -> None:
    writer = _writer_with_pages()
    reader = _roundtrip(writer)

    assert reader.navigation_forensics.summary["pages"] == 3
    assert reader.navigation_forensics().pages == 3
