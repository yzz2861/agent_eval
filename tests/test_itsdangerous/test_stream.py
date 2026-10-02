from __future__ import annotations

import pytest

from itsdangerous import BadRecordStream
from itsdangerous import RecordStreamSigner
from itsdangerous import Signer


@pytest.fixture()
def signer():
    return RecordStreamSigner("secret-key")


def frames(stream: bytes) -> list[bytes]:
    return stream.splitlines(keepends=True)


def consume(
    signer: RecordStreamSigner, stream: bytes, chunk_size: int
) -> list[bytes]:
    reader = signer.reader()
    records: list[bytes] = []

    for index in range(0, len(stream), chunk_size):
        records.extend(reader.feed(stream[index : index + chunk_size]))

        if reader.complete:
            assert index + chunk_size >= len(stream)

    reader.eof()
    assert reader.complete
    return records


def test_empty_stream(signer):
    stream = signer.sign_stream([])
    assert consume(signer, stream, 1) == []


@pytest.mark.parametrize("chunk_size", (1, 3, 16, 4096))
def test_records_are_authenticated_incrementally(signer, chunk_size):
    records = [b"first", b"", b"second", b"\x00\xff|~\n"]
    stream = signer.sign_stream(records)

    assert consume(signer, stream, chunk_size) == records


def test_delete_tail_reports_early_eof(signer):
    stream = frames(signer.sign_stream([b"one", b"two", b"three"]))
    truncated = b"".join(stream[:-2])
    reader = signer.reader()

    assert reader.feed(truncated) == [b"one", b"two"]
    assert not reader.complete

    with pytest.raises(BadRecordStream, match="ended before the end frame"):
        reader.eof()

    with pytest.raises(BadRecordStream, match="already failed"):
        reader.feed(stream[-1])


def test_splice_two_valid_streams_rejects_foreign_records(signer):
    first = frames(signer.sign_stream([b"shared", b"first-only"]))
    second = frames(signer.sign_stream([b"shared", b"second-only"]))
    reader = signer.reader()

    assert reader.feed(first[0] + first[1]) == [b"shared"]

    with pytest.raises(BadRecordStream, match="authentication chain"):
        reader.feed(second[2])

    assert not reader.complete


def test_splice_two_valid_streams_rejects_foreign_end(signer):
    first = frames(signer.sign_stream([b"one"]))
    second = frames(signer.sign_stream([b"one"]))
    reader = signer.reader()

    assert reader.feed(first[0] + first[1]) == [b"one"]

    with pytest.raises(BadRecordStream, match="authentication chain"):
        reader.feed(second[2])

    assert not reader.complete


def test_records_out_of_order_are_rejected(signer):
    stream = frames(signer.sign_stream([b"one", b"two"]))
    reordered = b"".join((stream[0], stream[2], stream[1], stream[3]))
    reader = signer.reader()

    with pytest.raises(BadRecordStream, match="out of order|authentication chain"):
        reader.feed(reordered)

    with pytest.raises(BadRecordStream, match="already failed"):
        reader.feed(b"")


def test_duplicate_end_is_rejected(signer):
    stream = signer.sign_stream([])
    end = frames(stream)[1]
    reader = signer.reader()

    assert reader.feed(stream) == []
    assert reader.complete
    reader.eof()

    with pytest.raises(BadRecordStream, match="Unexpected data"):
        reader.feed(end)

    assert not reader.complete


def test_partial_data_after_end_is_rejected(signer):
    stream = signer.sign_stream([])
    reader = signer.reader()

    with pytest.raises(BadRecordStream, match="Unexpected data"):
        reader.feed(stream + b"IDS1|partial")

    assert not reader.complete

    with pytest.raises(BadRecordStream, match="already failed"):
        reader.feed(b"\n")


def test_plain_itsdangerous_token_is_not_a_stream_record():
    token = Signer("secret-key").sign(b"ordinary token")
    reader = RecordStreamSigner("secret-key").reader()

    with pytest.raises(BadRecordStream, match="Not a versioned"):
        reader.feed(token + b"\n")


def test_writer_rejects_records_after_finish(signer):
    writer = signer.writer()
    assert writer.record(b"one")
    assert writer.finish()

    with pytest.raises(RuntimeError):
        writer.record(b"two")

    with pytest.raises(RuntimeError):
        writer.finish()


def test_max_record_length_is_enforced():
    signer = RecordStreamSigner("secret-key", max_record_length=1)

    with pytest.raises(ValueError, match="longer than the configured maximum"):
        signer.sign_stream([b"ab"])

    valid = RecordStreamSigner("secret-key").sign_stream([b"ab"])

    with pytest.raises(BadRecordStream, match="longer than the configured maximum"):
        consume(signer, valid, len(valid))
