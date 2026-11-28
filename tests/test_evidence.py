import os
import re

import Evtx.Evtx as evtx
import Evtx.Views as e_views


def _chunks(system, count):
    return list(evtx.FileHeader(system, 0x0).chunks())[:count]


def _event_id(record):
    match = re.search(r"<EventID[^>]*>(.*?)</EventID>", record.xml())
    return match.group(1)


def test_record_evidence_reports_template_and_value_ranges(system):
    fh = evtx.FileHeader(system, 0x0)
    chunk = next(fh.chunks())
    record = chunk.first_record()

    evidence = e_views.evtx_record_evidence_view(record)
    source = evidence["template_source"]

    assert evidence["record_number"] == record.record_num()
    assert source["chunk_offset"] == chunk.offset()
    assert source["template_absolute_offset"] == source["range"]["start"]
    assert source["data_range"]["start"] == source["template_absolute_offset"] + 0x18
    assert source["data_range"]["end"] == source["range"]["end"]

    assert evidence["value_ranges"]
    for value in evidence["value_ranges"]:
        assert value["scope"] == "record"
        assert value["range"]["start"] == value["offset"]
        assert value["range"]["end"] == value["offset"] + value["length"]
        assert value["range"]["record_start"] == value["offset"] - record.offset()
        assert value["range"]["chunk_start"] == value["offset"] - chunk.offset()

    missing_types = evidence["missing_node_types"]
    assert "StreamStartNode" in missing_types
    assert "EndOfStreamNode" in missing_types
    assert "CloseElementNode" in missing_types


def test_cache_is_reused_within_one_chunk(system):
    chunk = _chunks(system, 1)[0]
    records = list(chunk.records())
    first = records[1]
    second = records[2]
    cache = {}

    first_evidence = e_views.evtx_record_evidence_view(first, cache=cache)
    second_evidence = e_views.evtx_record_evidence_view(second, cache=cache)

    # Both records use the resident template at the same chunk-relative
    # offset.  Within this chunk that is genuinely the same origin.
    assert first_evidence["template_source"]["template_offset"] == 0xAA6
    assert second_evidence["template_source"]["template_offset"] == 0xAA6
    assert first_evidence["template_source"]["source_id"] == second_evidence["template_source"]["source_id"]
    assert first_evidence["template_source"] is second_evidence["template_source"]


def test_identical_template_bytes_in_different_chunks_keep_distinct_origins(system):
    chunks = _chunks(system, 4)
    record_one = chunks[1].first_record()
    record_three = chunks[3].first_record()

    # These chunks store byte-identical templates at the same chunk-relative
    # offset.  The rendered template skeleton is therefore identical, but the
    # two binary artifacts are not the same evidence.
    assert e_views.evtx_template_readable_view(record_one.root()) == e_views.evtx_template_readable_view(
        record_three.root()
    )

    cache = {}
    one = e_views.evtx_record_evidence_view(record_one, cache=cache)
    three = e_views.evtx_record_evidence_view(record_three, cache=cache)

    assert one["template_source"]["template_offset"] == 0x226
    assert three["template_source"]["template_offset"] == 0x226
    assert one["template_source"]["digest"] == three["template_source"]["digest"]

    assert one["template_source"]["chunk_offset"] != three["template_source"]["chunk_offset"]
    assert one["template_source"]["template_absolute_offset"] != three["template_source"]["template_absolute_offset"]
    assert one["template_source"]["source_id"] != three["template_source"]["source_id"]


def test_same_event_id_in_two_chunks_keeps_per_record_sources(system):
    chunks = _chunks(system, 2)
    first = chunks[0].records()
    second = chunks[1].records()

    first_record = next(record for record in first if _event_id(record) == "7036")
    second_record = next(record for record in second if _event_id(record) == "7036")

    cache = {}
    first_evidence = e_views.evtx_record_evidence_view(first_record, cache=cache)
    second_evidence = e_views.evtx_record_evidence_view(second_record, cache=cache)

    assert _event_id(first_record) == _event_id(second_record)
    assert first_evidence["template_source"]["chunk_offset"] != second_evidence["template_source"]["chunk_offset"]
    assert first_evidence["template_source"]["source_id"] != second_evidence["template_source"]["source_id"]


def test_record_convenience_methods(system):
    record = _chunks(system, 1)[0].first_record()

    assert record.evidence()["template_source"] == record.template_source()
    assert record.evidence()["value_ranges"] == record.value_ranges()
    assert record.evidence()["uncaptured_nodes"] == record.uncaptured_nodes()


def test_replaced_template_changes_evidence_but_not_xml(data_path):
    with open(os.path.join(data_path, "system.evtx"), "rb") as f:
        buf = bytearray(f.read())

    record = evtx.FileHeader(buf, 0x0).first_chunk().first_record()
    cache = {}

    xml_before = record.xml()
    before = e_views.evtx_record_evidence_view(record, cache=cache)

    # Replace the template's GUID (and template id), without touching the
    # template body that is rendered into XML.  The XML is unchanged, but the
    # evidence must point at the new template bytes rather than reuse the
    # cached source for the old content.
    template_offset = before["template_source"]["template_absolute_offset"]
    buf[template_offset + 0x4 : template_offset + 0x4 + 16] = b"\x11" * 16

    xml_after = record.xml()
    after = e_views.evtx_record_evidence_view(record, cache=cache)

    assert xml_before == xml_after
    assert before["template_source"]["digest"] != after["template_source"]["digest"]
    assert before["template_source"]["guid"] != after["template_source"]["guid"]
    assert before["template_source"]["source_id"] != after["template_source"]["source_id"]
    assert before["value_ranges"] != after["value_ranges"]


def test_same_bytes_in_two_artifacts_keep_distinct_origins(data_path):
    with open(os.path.join(data_path, "system.evtx"), "rb") as f:
        data = f.read()

    first_buf = bytearray(data)
    second_buf = bytearray(data)

    first_record = evtx.FileHeader(first_buf, 0x0).first_chunk().first_record()
    second_record = evtx.FileHeader(second_buf, 0x0).first_chunk().first_record()
    cache = {}

    first = e_views.evtx_record_evidence_view(first_record, cache=cache)
    second = e_views.evtx_record_evidence_view(second_record, cache=cache)

    assert first["template_source"]["template_offset"] == second["template_source"]["template_offset"]
    assert first["template_source"]["digest"] == second["template_source"]["digest"]
    assert first["template_source"]["artifact_id"] != second["template_source"]["artifact_id"]
    assert first["template_source"]["source_id"] != second["template_source"]["source_id"]
