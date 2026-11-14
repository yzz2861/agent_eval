"""
Focused tests for the chunk+offset+id template cache key and cross-record
reuse, kept separate from the attack-structure tests.
"""

import os

import Evtx.Evtx as evtx
from _malicious_evtx import ChunkBuilder, EvtxBuilder, simple_template_body
import Evtx.Nodes as e_nodes


def _subs():
    return [(4, e_nodes.NODE_TYPES.UNSIGNED_DWORD, b"\x07\x00\x00\x00")]


def test_cache_key_keeps_chunk_offset_and_id(tmp_path):
    chunk = ChunkBuilder([1])
    body = simple_template_body("Test")
    chunk.add_resident_record(1, 0x11111111, body, _subs())
    path = os.path.join(str(tmp_path), "cache.evtx")
    with open(path, "wb") as f:
        f.write(EvtxBuilder([chunk.build()]).build())

    with evtx.Evtx(path) as log:
        chunk_obj = list(log.chunks())[0]
        record = list(chunk_obj.records())[0]
        instance = record.root().template_instance()
        template = instance.template()
        # the cache is indexed by chunk-relative offset, not template id.
        assert instance.template_offset() in chunk_obj.templates()
        assert chunk_obj.templates()[instance.template_offset()] is template
        # the id index also carries the same definition.
        assert chunk_obj._template_ids[template.template_id()] == instance.template_offset()


def test_repeated_render_accumulates_cache_hits(tmp_path):
    chunk = ChunkBuilder([1])
    chunk.add_resident_record(1, 0x22222222, simple_template_body("Repeat"), _subs())
    path = os.path.join(str(tmp_path), "repeat.evtx")
    with open(path, "wb") as f:
        f.write(EvtxBuilder([chunk.build()]).build())

    with evtx.Evtx(path) as log:
        chunk_obj = list(log.chunks())[0]
        record = list(chunk_obj.records())[0]
        record.xml()
        first = chunk_obj.template_cache_hits()
        record.xml()
        assert chunk_obj.template_cache_hits() > first
