#    This file is part of python-evtx.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
"""
Tests for single-source incremental handoff (Evtx.Incremental).

The host collector snapshots the same EVTX source every few seconds.  These
tests simulate that lifecycle: an early snapshot ends inside an unfinished
chunk, the collection pauses, and a later snapshot completes the tail.  They
prove that records enter an in-memory evidence store exactly once, that a
lost acknowledgement is safely retried via the stable handoff key, that a
rewritten confirmed range raises an explicit fork, and that the stored
locator finds the original record again.
"""
import os

import pytest

import Evtx.Evtx as evtx
import Evtx.Incremental as inc

SOURCE_ID = "host://C:/Windows/System32/winevt/Logs/System.evtx"


@pytest.fixture
def system_bytes():
    """The on-disk system.evtx fixture as plain bytes."""
    path = os.path.join(os.path.dirname(__file__), "data", "system.evtx")
    with open(path, "rb") as f:
        return f.read()


@pytest.fixture
def expected_record_counts(system):
    """Per-chunk record counts of the fixture, collected empirically."""
    fh = evtx.FileHeader(system, 0x0)
    return [sum(1 for _ in chunk.records()) for chunk in fh.chunks()]


def test_empty_source_only_contains_file_header():
    """A snapshot shorter than one chunk hands nothing off."""
    store = inc.InMemoryEvidenceStore()
    records, checkpoint = inc.handoff_incremental(SOURCE_ID, b"\x00" * inc.HEADER_SIZE, store)

    assert list(records) == []
    assert len(store) == 0
    assert checkpoint.source_id == SOURCE_ID
    assert checkpoint.confirmed_end == inc.HEADER_SIZE


def test_partial_tail_chunk_is_deferred_until_complete(system_bytes, expected_record_counts):
    """
    Acceptance scenario, phase one: an early collection ends in the middle of
    the sixth chunk.  Only the five complete chunks may be confirmed; the
    unfinished tail must wait.
    """
    complete_chunks = 5
    snapshot = bytearray(system_bytes)
    # truncate inside chunk index five, before the 64 KiB chunk boundary
    cut = inc.HEADER_SIZE + complete_chunks * inc.CHUNK_SIZE + 0x9000
    del snapshot[cut:]

    store = inc.InMemoryEvidenceStore()
    records, checkpoint = inc.handoff_incremental(SOURCE_ID, bytes(snapshot), store)

    expected = sum(expected_record_counts[:complete_chunks])
    assert len(list(records)) == expected
    assert len(store) == expected
    assert checkpoint.confirmed_end == inc.HEADER_SIZE + complete_chunks * inc.CHUNK_SIZE


def test_resume_completes_tail_and_ingests_each_record_once(system_bytes, expected_record_counts):
    """
    Acceptance scenario, phase two: after a pause, the next collection
    contains the fully written tail.  Resuming from the checkpoint must hand
    off exactly the remaining records, with no duplicate in the store.
    """
    first_chunks = 5
    partial = bytearray(system_bytes)
    del partial[inc.HEADER_SIZE + first_chunks * inc.CHUNK_SIZE + 0x9000 :]

    store = inc.InMemoryEvidenceStore()
    first_records, checkpoint = inc.handoff_incremental(SOURCE_ID, bytes(partial), store)
    first_count = len(list(first_records))

    # the pause happens here; a later collection delivers the complete file
    second_records, final_checkpoint = inc.handoff_incremental(
        SOURCE_ID, system_bytes, store, checkpoint
    )
    second_count = len(list(second_records))

    total = sum(expected_record_counts)
    assert first_count == sum(expected_record_counts[:first_chunks])
    assert second_count == total - first_count
    assert first_count + second_count == total
    assert len(store) == total
    assert final_checkpoint.confirmed_end == inc.HEADER_SIZE + len(expected_record_counts) * inc.CHUNK_SIZE

    # a further identical scan has nothing new to hand off
    third_records, same_checkpoint = inc.handoff_incremental(
        SOURCE_ID, system_bytes, store, final_checkpoint
    )
    assert list(third_records) == []
    assert same_checkpoint.confirmed_end == final_checkpoint.confirmed_end
    assert len(store) == total


def test_lost_acknowledgement_is_safely_retried(system_bytes):
    """
    The store accepted a write but the acknowledgement was lost, so the same
    confirmed range is scanned again.  The stable handoff key makes the retry
    idempotent: the store keeps one entry per record.
    """
    first_chunks = 3
    partial = bytearray(system_bytes)
    del partial[inc.HEADER_SIZE + first_chunks * inc.CHUNK_SIZE :]

    store = inc.InMemoryEvidenceStore()
    _, checkpoint = inc.handoff_incremental(SOURCE_ID, bytes(partial), store)
    size_before = len(store)

    # retry the exact same material with the older checkpoint
    retried, _ = inc.handoff_incremental(SOURCE_ID, bytes(partial), store, inc.Checkpoint.initial(SOURCE_ID))
    retried = list(retried)

    assert len(retried) == size_before
    assert all(not record.created for record in retried)
    assert len(store) == size_before


def test_locator_recovers_original_record(system_bytes, expected_record_counts):
    """The position marker stored alongside the entry finds the same record."""
    store = inc.InMemoryEvidenceStore()
    _, checkpoint = inc.handoff_incremental(SOURCE_ID, system_bytes, store)

    key = next(iter(store.keys()))
    entry = store.get(key)
    locator = inc.RecordLocator.from_dict(entry["locator"])

    assert locator.key == key
    assert inc.handoff_key(
        locator.source_id, locator.chunk_offset, locator.record_offset, locator.record_num
    ) == key

    chunk = evtx.ChunkHeader(system_bytes, locator.chunk_offset)
    record = evtx.Record(system_bytes, locator.record_offset, chunk)
    assert record.record_num() == locator.record_num
    assert record.xml() == entry["payload"]["xml"]
    assert record.data().hex() == entry["payload"]["data"]
    assert checkpoint.confirmed_end == inc.HEADER_SIZE + len(expected_record_counts) * inc.CHUNK_SIZE


def test_rewriting_confirmed_bytes_raises_fork(system_bytes):
    """Any in-place rewrite of a confirmed range must be reported as a fork."""
    store = inc.InMemoryEvidenceStore()
    _, checkpoint = inc.handoff_incremental(SOURCE_ID, system_bytes, store)

    rewritten = bytearray(system_bytes)
    rewritten[inc.HEADER_SIZE + 1234] ^= 0xFF

    with pytest.raises(inc.ForkDetectedError):
        inc.handoff_incremental(SOURCE_ID, bytes(rewritten), store, checkpoint)


def test_truncating_confirmed_bytes_raises_fork(system_bytes):
    """Shrinking the source below the confirmed range is also a fork."""
    store = inc.InMemoryEvidenceStore()
    _, checkpoint = inc.handoff_incremental(SOURCE_ID, system_bytes, store)

    with pytest.raises(inc.ForkDetectedError):
        inc.handoff_incremental(SOURCE_ID, system_bytes[: inc.HEADER_SIZE], store, checkpoint)


def test_checkpoint_bound_to_source_identifier(system_bytes):
    """A checkpoint must never be resumed against a different source."""
    store = inc.InMemoryEvidenceStore()
    _, checkpoint = inc.handoff_incremental(SOURCE_ID, system_bytes, store)

    with pytest.raises(inc.ForkDetectedError):
        inc.handoff_incremental("host://other/Security.evtx", system_bytes, store, checkpoint)


def test_checkpoint_json_roundtrip(system_bytes):
    """Checkpoint state survives serialization across collector runs."""
    store = inc.InMemoryEvidenceStore()
    _, checkpoint = inc.handoff_incremental(SOURCE_ID, system_bytes, store)

    restored = inc.Checkpoint.from_json(checkpoint.to_json())
    assert restored.source_id == checkpoint.source_id
    assert restored.confirmed_end == checkpoint.confirmed_end
    assert restored.digest == checkpoint.digest

    # the restored checkpoint resumes normally without raising a fork
    records, _ = inc.handoff_incremental(SOURCE_ID, system_bytes, store, restored)
    assert list(records) == []


def test_corrupt_full_chunk_is_not_confirmed(system_bytes, expected_record_counts):
    """
    A complete-but-corrupt tail chunk fails checksum verification and must be
    deferred rather than handed off as stable evidence.
    """
    tail_index = len(expected_record_counts) - 1
    tail_start = inc.HEADER_SIZE + tail_index * inc.CHUNK_SIZE
    corrupted = bytearray(system_bytes)
    corrupted[tail_start + 0x4000] ^= 0xFF

    store = inc.InMemoryEvidenceStore()
    records, checkpoint = inc.handoff_incremental(SOURCE_ID, bytes(corrupted), store)

    assert len(list(records)) == sum(expected_record_counts[:tail_index])
    assert checkpoint.confirmed_end == tail_start

    # once a later, intact snapshot arrives, the tail is confirmed
    repaired_records, final_checkpoint = inc.handoff_incremental(
        SOURCE_ID, system_bytes, store, checkpoint
    )
    assert len(list(repaired_records)) == expected_record_counts[tail_index]
    assert len(store) == sum(expected_record_counts)
    assert final_checkpoint.confirmed_end == inc.HEADER_SIZE + len(expected_record_counts) * inc.CHUNK_SIZE


def test_file_based_entry_point(tmp_path, system_bytes, expected_record_counts):
    """The mmap-based convenience entry point behaves like the buffer one."""
    path = tmp_path / "system.evtx"
    path.write_bytes(system_bytes)

    store = inc.InMemoryEvidenceStore()
    records, checkpoint = inc.handoff_file_incremental(SOURCE_ID, str(path), store)

    assert len(list(records)) == sum(expected_record_counts)
    assert len(store) == sum(expected_record_counts)


def test_custom_serializer_is_used(system_bytes):
    """Callers may replace the default XML/bytes payload."""
    store = inc.InMemoryEvidenceStore()
    records, _ = inc.handoff_incremental(
        SOURCE_ID,
        system_bytes,
        store,
        serializer=lambda record: {"record_num": record.record_num()},
    )

    handed = list(records)
    assert handed
    assert all(record.entry["payload"] == {"record_num": record.locator.record_num} for record in handed)


def test_store_rejects_conflicting_content_under_same_key(system_bytes):
    """Identical keys with different payloads signal a real collision."""
    store = inc.InMemoryEvidenceStore()
    key = inc.handoff_key(SOURCE_ID, inc.HEADER_SIZE, inc.HEADER_SIZE + 0x200, 1)
    assert store.put(key, {"payload": "first"}) is True
    assert store.put(key, {"payload": "first"}) is False
    with pytest.raises(inc.IncrementalException):
        store.put(key, {"payload": "different"})
