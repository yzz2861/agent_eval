"""
Security regression tests for the explicit BinXML template graph.

These build small synthetic EVTX files that reproduce the malicious structures
described in the hardening work:

  - a template instance that references its own definition (self cycle);
  - two templates that reference each other (an A -> B -> A cycle);
  - two definitions in one chunk claiming the same template id;
  - malformed substitution arrays (bad count, unknown type, bad index);
  - the same template id used by different definitions in two chunks;
  - legitimate template reuse with observable cache hits and node budgets.
"""

import os

import pytest

import Evtx.Evtx as evtx
import Evtx.Nodes as e_nodes
from _malicious_evtx import (
    ChunkBuilder,
    EvtxBuilder,
    simple_template_body,
    substitution_array,
    template_definition,
    template_instance,
    record,
    _byte,
    _word,
)


def _write(tmp_path, chunks, name="sample.evtx"):
    path = os.path.join(str(tmp_path), name)
    with open(path, "wb") as f:
        f.write(EvtxBuilder(chunks).build())
    return path


def _good_substitutions():
    return [(4, e_nodes.NODE_TYPES.UNSIGNED_DWORD, b"\x07\x00\x00\x00")]


def _good_chunk():
    chunk = ChunkBuilder([1])
    body = simple_template_body("Test")
    chunk.add_resident_record(1, 0x11111111, body, _good_substitutions())
    return chunk


def test_legitimate_record_renders_and_caches(tmp_path):
    chunk = _good_chunk()
    path = _write(tmp_path, [chunk.build()])

    with evtx.Evtx(path) as log:
        records = list(log.records())
        assert len(records) == 1
        assert records[0].xml() == "<Test>7</Test>\n"
        chunk_obj = records[0]._chunk
        first = chunk_obj.template_cache_hits()
        # rendering again reuses the cached definition rather than parsing it
        records[0].xml()
        assert chunk_obj.template_cache_hits() > first


def test_shared_non_resident_template_cache_hit(tmp_path):
    chunk = ChunkBuilder([1, 2])
    # two records render the same template; repeated resolution must be served
    # from the chunk cache whose key includes the chunk, offset and template
    # id rather than the id alone.
    body = simple_template_body("Shared")
    chunk.add_resident_record(1, 0x22222222, body, _good_substitutions())
    chunk.add_resident_record(2, 0x33333333, simple_template_body("Shared2"), _good_substitutions())
    path = _write(tmp_path, [chunk.build()])

    with evtx.Evtx(path) as log:
        records = list(log.records())
        assert [r.record_num() for r in records] == [1, 2]
        first_xml = records[0].xml()
        assert "<Shared>7</Shared>" in first_xml
        hits_before = records[0]._chunk.template_cache_hits()
        records[0].xml()
        assert records[0]._chunk.template_cache_hits() > hits_before


def test_self_referencing_template_fails_without_recursion(tmp_path):
    chunk = ChunkBuilder([1])
    definition_offset = 0x8000
    # the body's instance token points back at the definition's own offset.
    cyclic_body = (
        _byte(0x0F) + _byte(0x01) + _word(0x0001)
        + template_instance(0x33333333, definition_offset)
        + _byte(0x00)
    )
    chunk.place_raw_template_at(definition_offset, 0x33333333, cyclic_body)
    root = bytearray(
        _byte(0x0F) + _byte(0x01) + _word(0x0001)
        + template_instance(0x33333333, definition_offset)
        + substitution_array(_good_substitutions())
    )
    chunk.add_record(record(1, bytes(root)))
    path = _write(tmp_path, [chunk.build()])

    with evtx.Evtx(path) as log:
        rec = list(log.records())[0]
        with pytest.raises(e_nodes.TemplateCycleException):
            rec.xml()


def test_a_b_template_cycle_fails(tmp_path):
    chunk = ChunkBuilder([1])
    offset_a = 0x8000
    offset_b = 0x8100
    body_a = (
        _byte(0x0F) + _byte(0x01) + _word(0x0001)
        + template_instance(0x55555555, offset_b)
        + _byte(0x00)
    )
    body_b = (
        _byte(0x0F) + _byte(0x01) + _word(0x0001)
        + template_instance(0x44444444, offset_a)
        + _byte(0x00)
    )
    chunk.place_raw_template_at(offset_a, 0x44444444, body_a)
    chunk.place_raw_template_at(offset_b, 0x55555555, body_b)
    root = bytearray(
        _byte(0x0F) + _byte(0x01) + _word(0x0001)
        + template_instance(0x44444444, offset_a)
        + substitution_array(_good_substitutions())
    )
    chunk.add_record(record(1, bytes(root)))
    path = _write(tmp_path, [chunk.build()])

    with evtx.Evtx(path) as log:
        rec = list(log.records())[0]
        with pytest.raises(e_nodes.TemplateCycleException):
            rec.xml()


def test_duplicate_template_id_within_chunk_fails(tmp_path):
    chunk = ChunkBuilder([1])
    body_one = simple_template_body("One")
    body_two = simple_template_body("Two")
    first = chunk.place_standalone_template(0x66666666, body_one, table=False)
    second = chunk.place_standalone_template(0x66666666, body_two, table=False)
    assert first != second
    path = _write(tmp_path, [chunk.build()])

    with evtx.Evtx(path) as log:
        chunk_obj = list(log.chunks())[0]
        chunk_obj.add_template(first, expected_template_id=0x66666666)
        with pytest.raises(e_nodes.DuplicateTemplateException):
            chunk_obj.add_template(second, expected_template_id=0x66666666)


def test_undefined_template_reference_fails(tmp_path):
    chunk = ChunkBuilder([1])
    body = simple_template_body("Test")
    # point the instance at an offset that holds no template definition.
    missing_offset = 0x900
    chunk.add_non_resident_record(1, 0x77777777, missing_offset, body, _good_substitutions())
    path = _write(tmp_path, [chunk.build()])

    with evtx.Evtx(path) as log:
        rec = list(log.records())[0]
        with pytest.raises(e_nodes.UndefinedTemplateException):
            rec.xml()


def test_substitution_index_out_of_range_fails(tmp_path):
    chunk = ChunkBuilder([1])
    body = simple_template_body("Test", sub_index=5)
    chunk.add_resident_record(1, 0x88888888, body, _good_substitutions())
    path = _write(tmp_path, [chunk.build()])

    with evtx.Evtx(path) as log:
        rec = list(log.records())[0]
        with pytest.raises(e_nodes.InvalidSubstitutionException):
            rec.xml()


def test_unknown_substitution_type_fails(tmp_path):
    chunk = ChunkBuilder([1])
    body = simple_template_body("Test")
    chunk.add_resident_record(
        1, 0x99999999, body, [(4, 0x7F, b"\x07\x00\x00\x00")]
    )
    path = _write(tmp_path, [chunk.build()])

    with evtx.Evtx(path) as log:
        rec = list(log.records())[0]
        with pytest.raises(e_nodes.InvalidSubstitutionException):
            rec.xml()


def test_oversized_substitution_count_fails(tmp_path):
    import struct

    chunk = ChunkBuilder([1])
    body = simple_template_body("Test")
    chunk.add_resident_record(
        1, 0xAAAAAAAA, body, [(1, e_nodes.NODE_TYPES.UNSIGNED_BYTE, b"\x01")]
    )
    # the root stream is the 0x18 record header plus a 4-byte stream start,
    # a 10-byte instance and the resident template definition.
    definition = template_definition(0xAAAAAAAA, body, prefix=False)
    count_offset = 0x200 + 0x18 + 4 + 10 + len(definition)
    struct.pack_into("<I", chunk.buf, count_offset, e_nodes.MAX_SUBSTITUTIONS + 1)
    path = _write(tmp_path, [chunk.build()])

    with evtx.Evtx(path) as log:
        rec = list(log.records())[0]
        with pytest.raises(e_nodes.InvalidSubstitutionException):
            rec.xml()


def test_cross_chunk_same_id_conflict_fails_in_strict_mode(tmp_path):
    good = _good_chunk()
    other = ChunkBuilder([2])
    other_body = simple_template_body("Different")
    other.add_resident_record(2, 0x11111111, other_body, _good_substitutions())
    path = _write(tmp_path, [good.build(), other.build()])

    with evtx.Evtx(path) as log:
        fh = evtx.FileHeader(log._buf, 0, strict_templates=True)
        chunks = list(fh.chunks())
        # touch the first chunk's template so the registry learns its id.
        list(chunks[0].records())[0].root().template()
        with pytest.raises(e_nodes.TemplateConflictException):
            list(chunks[1].records())[0].xml()


def test_cross_chunk_same_id_allowed_in_default_mode(tmp_path):
    good = _good_chunk()
    other = ChunkBuilder([2])
    other_body = simple_template_body("Different")
    other.add_resident_record(2, 0x11111111, other_body, _good_substitutions())
    path = _write(tmp_path, [good.build(), other.build()])

    with evtx.Evtx(path) as log:
        rendered = [r.xml() for chunk in log.chunks() for r in chunk.records()]
    assert any("<Test>7</Test>" in x for x in rendered)
    assert any("<Different>7</Different>" in x for x in rendered)


def test_bad_record_does_not_break_other_records(tmp_path):
    good = _good_chunk()
    # append a second, malformed record whose instance points nowhere.
    bad_body = simple_template_body("Bad")
    good.add_non_resident_record(2, 0xBBBBBBBB, 0x950, bad_body, _good_substitutions())
    path = _write(tmp_path, [good.build()])

    import Evtx.Views as e_views

    with evtx.Evtx(path) as log:
        rendered = [xml for xml, _ in e_views.evtx_file_xml_view(log.get_file_header())]
    # the good record survives while the bad one is skipped.
    assert any("<Test>7</Test>" in x for x in rendered)
    assert all("<Bad>" not in x for x in rendered)


def test_expansion_node_budget_enforced(tmp_path):
    chunk = ChunkBuilder([1])
    body = simple_template_body("Test")
    original = e_nodes.MAX_TEMPLATE_EXPANSION_NODES
    e_nodes.MAX_TEMPLATE_EXPANSION_NODES = 1
    try:
        chunk.add_resident_record(1, 0xCCCCCCCC, body, _good_substitutions())
        path = _write(tmp_path, [chunk.build()])
        with evtx.Evtx(path) as log:
            rec = list(log.records())[0]
            with pytest.raises(e_nodes.TemplateNodeBudgetExceededException):
                rec.xml()
    finally:
        e_nodes.MAX_TEMPLATE_EXPANSION_NODES = original


def test_expansion_depth_limit_enforced(tmp_path):
    chunk = ChunkBuilder([1])
    # build a long acyclic chain of distinct templates, each referencing the
    # next; the depth guard must stop expansion before the stack overflows.
    chain_length = e_nodes.MAX_TEMPLATE_EXPANSION_DEPTH + 5
    offsets = [0x8000 + index * 0x80 for index in range(chain_length)]
    for index, offset in enumerate(offsets):
        if index + 1 < len(offsets):
            body = (
                _byte(0x0F) + _byte(0x01) + _word(0x0001)
                + template_instance(0x1000 + index + 1, offsets[index + 1])
                + _byte(0x00)
            )
        else:
            body = simple_template_body("Deep", sub_index=0)
        chunk.place_raw_template_at(offset, 0x1000 + index, body)
    root = bytearray(
        _byte(0x0F) + _byte(0x01) + _word(0x0001)
        + template_instance(0x1000, offsets[0])
        + substitution_array(_good_substitutions())
    )
    chunk.add_record(record(1, bytes(root)))
    path = _write(tmp_path, [chunk.build()])

    with evtx.Evtx(path) as log:
        rec = list(log.records())[0]
        with pytest.raises(e_nodes.TemplateDepthExceededException):
            rec.xml()
