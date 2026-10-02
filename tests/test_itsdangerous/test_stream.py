import pytest

from itsdangerous import Serializer
from itsdangerous import Signer
from itsdangerous.stream import BadStream
from itsdangerous.stream import BadStreamSignature
from itsdangerous.stream import RecordStreamReader
from itsdangerous.stream import RecordStreamWriter
from itsdangerous.stream import StreamStateError
from itsdangerous.stream import TruncatedStream

KEY = "stream-secret"
RECORDS = [b"first", b"second", b"third", b"", b"last \xc3\xa9"]


def build_stream(records=RECORDS, key=KEY, **kwargs):
    writer = RecordStreamWriter(key, **kwargs)
    frames = [writer.start()]
    frames.extend(writer.record(record) for record in records)
    frames.append(writer.end())
    return frames


def read_stream(data, key=KEY, chunk_size=None, **kwargs):
    reader = RecordStreamReader(key, **kwargs)
    out = []

    if chunk_size is None:
        out.extend(reader.feed(data))
    else:
        for i in range(0, len(data), chunk_size):
            out.extend(reader.feed(data[i : i + chunk_size]))

    count = reader.finish()
    return out, count


class TestRoundTrip:
    def test_records_verified_in_order(self):
        out, count = read_stream(b"".join(build_stream()))
        assert out == RECORDS
        assert count == len(RECORDS)

    @pytest.mark.parametrize("chunk_size", [1, 2, 3, 7, 64])
    def test_arbitrary_byte_chunking(self, chunk_size):
        out, count = read_stream(b"".join(build_stream()), chunk_size=chunk_size)
        assert out == RECORDS
        assert count == len(RECORDS)

    def test_empty_stream_has_verifiable_end(self):
        frames = build_stream([])
        assert len(frames) == 2
        out, count = read_stream(b"".join(frames))
        assert out == []
        assert count == 0

    def test_records_emitted_incrementally(self):
        frames = build_stream([b"a", b"b"])
        reader = RecordStreamReader(KEY)
        assert reader.feed(frames[0]) == []
        assert reader.stream_id is not None
        assert reader.feed(frames[1]) == [b"a"]
        assert reader.record_count == 1
        assert not reader.done
        assert reader.feed(frames[2] + frames[3]) == [b"b"]
        assert reader.done
        assert reader.finish() == 2

    def test_stream_id_is_random_per_stream(self):
        writer_a = RecordStreamWriter(KEY)
        writer_b = RecordStreamWriter(KEY)
        assert writer_a.stream_id != writer_b.stream_id
        reader = RecordStreamReader(KEY)
        reader.feed(writer_a.start())
        assert reader.stream_id == writer_a.stream_id

    def test_key_rotation(self):
        data = b"".join(build_stream([b"x"], key="new-key"))
        out, count = read_stream(data, key=["old-key", "new-key"])
        assert out == [b"x"]
        assert count == 1

    def test_wrong_key_rejected(self):
        reader = RecordStreamReader("other-key")

        with pytest.raises(BadStreamSignature):
            reader.feed(b"".join(build_stream()))


class TestTruncation:
    def test_missing_end_frame(self):
        frames = build_stream()
        reader = RecordStreamReader(KEY)
        assert reader.feed(b"".join(frames[:-1])) == RECORDS

        with pytest.raises(TruncatedStream):
            reader.finish()

    def test_missing_everything(self):
        reader = RecordStreamReader(KEY)

        with pytest.raises(TruncatedStream):
            reader.finish()

    def test_partial_frame_at_eof(self):
        data = b"".join(build_stream())
        reader = RecordStreamReader(KEY)
        reader.feed(data[:-5])

        with pytest.raises(TruncatedStream):
            reader.finish()

    def test_deleted_tail_records(self):
        frames = build_stream()
        # Drop the last two record frames, keep the end frame.
        data = b"".join(frames[:-3]) + frames[-1]
        reader = RecordStreamReader(KEY)

        with pytest.raises(BadStreamSignature):
            reader.feed(data)


class TestTampering:
    def test_reordered_records(self):
        frames = build_stream()
        # Swap the first two record frames.
        data = frames[0] + frames[2] + frames[1] + b"".join(frames[3:])
        reader = RecordStreamReader(KEY)

        with pytest.raises(StreamStateError):
            reader.feed(data)

    def test_duplicate_record(self):
        frames = build_stream()
        data = frames[0] + frames[1] + frames[1] + b"".join(frames[2:])
        reader = RecordStreamReader(KEY)

        with pytest.raises(StreamStateError):
            reader.feed(data)

    def test_modified_payload(self):
        frames = build_stream([b"hello"])
        frame = frames[1].replace(b"aGVsbG8", b"bGVsbG8")
        reader = RecordStreamReader(KEY)

        with pytest.raises(BadStreamSignature):
            reader.feed(frames[0] + frame + frames[2])

    def test_splice_header_from_other_stream(self):
        stream_a = build_stream([b"a1", b"a2"])
        stream_b = build_stream([b"b1", b"b2"])
        reader = RecordStreamReader(KEY)
        reader.feed(stream_a[0])

        with pytest.raises(BadStreamSignature):
            reader.feed(b"".join(stream_b[1:]))

    def test_splice_end_from_other_stream(self):
        stream_a = build_stream([b"a1", b"a2"])
        stream_b = build_stream([b"b1", b"b2"])
        reader = RecordStreamReader(KEY)
        assert reader.feed(b"".join(stream_a[:-1])) == [b"a1", b"a2"]

        with pytest.raises(BadStreamSignature):
            reader.feed(stream_b[-1])

    def test_splice_middle_from_other_stream(self):
        stream_a = build_stream([b"a1", b"a2", b"a3"])
        stream_b = build_stream([b"b1", b"b2", b"b3"])
        # Same length, but the middle record comes from another stream.
        data = stream_a[0] + stream_a[1] + stream_b[2] + stream_a[3] + stream_a[4]
        reader = RecordStreamReader(KEY)

        with pytest.raises(BadStreamSignature):
            reader.feed(data)

    def test_duplicate_end_frame(self):
        frames = build_stream()
        reader = RecordStreamReader(KEY)

        with pytest.raises(StreamStateError):
            reader.feed(b"".join(frames) + frames[-1])

    def test_data_after_end(self):
        frames = build_stream()
        reader = RecordStreamReader(KEY)

        with pytest.raises(StreamStateError):
            reader.feed(b"".join(frames) + b"trailing")

    def test_record_before_header(self):
        frames = build_stream()
        reader = RecordStreamReader(KEY)

        with pytest.raises(StreamStateError):
            reader.feed(frames[1])

    def test_duplicate_header(self):
        frames = build_stream()
        reader = RecordStreamReader(KEY)

        with pytest.raises(StreamStateError):
            reader.feed(frames[0] + frames[0])

    def test_unknown_frame_type(self):
        frames = build_stream()
        reader = RecordStreamReader(KEY)
        reader.feed(frames[0])

        with pytest.raises(BadStream):
            reader.feed(b"IDSR1.X.0.abcd\n")


class TestDomainSeparation:
    @pytest.mark.parametrize(
        "token",
        [
            Signer(KEY).sign(b"hello"),
            Signer(KEY, salt="itsdangerous.RecordStream.v1").sign(b"hello"),
            Serializer(KEY).dumps({"a": 1}).encode(),
        ],
    )
    def test_plain_token_is_not_a_stream_record(self, token):
        reader = RecordStreamReader(KEY)

        with pytest.raises(BadStream):
            reader.feed(token + b"\n")

    def test_different_salt_rejected(self):
        data = b"".join(build_stream([b"x"], salt="other-salt"))
        reader = RecordStreamReader(KEY)

        with pytest.raises(BadStreamSignature):
            reader.feed(data)


class TestLimits:
    def test_writer_rejects_oversized_record(self):
        writer = RecordStreamWriter(KEY, max_record_size=4)
        writer.start()

        with pytest.raises(ValueError):
            writer.record(b"12345")

    def test_reader_rejects_oversized_record(self):
        data = b"".join(build_stream([b"x" * 100]))
        reader = RecordStreamReader(KEY, max_record_size=64)

        with pytest.raises(StreamStateError):
            reader.feed(data)

    def test_reader_rejects_oversized_frame(self):
        data = b"".join(build_stream([b"x" * 100]))
        reader = RecordStreamReader(KEY, max_record_size=8)

        with pytest.raises(StreamStateError):
            reader.feed(data)


class TestErrorIsFinal:
    def test_no_records_after_error(self):
        frames = build_stream([b"a", b"b"])
        other = build_stream([b"x", b"y"])
        reader = RecordStreamReader(KEY)
        reader.feed(frames[0])

        with pytest.raises(BadStreamSignature):
            reader.feed(other[1])

        # The reader is poisoned: further feeds and finish re-raise.
        with pytest.raises(BadStreamSignature):
            reader.feed(frames[1])

        with pytest.raises(BadStreamSignature):
            reader.finish()

    def test_no_feed_after_truncated_finish(self):
        frames = build_stream([b"a"])
        reader = RecordStreamReader(KEY)
        reader.feed(b"".join(frames[:-1]))

        with pytest.raises(TruncatedStream):
            reader.finish()

        with pytest.raises(TruncatedStream):
            reader.feed(frames[-1])


class TestWriterMisuse:
    def test_record_before_start(self):
        writer = RecordStreamWriter(KEY)

        with pytest.raises(RuntimeError):
            writer.record(b"x")

    def test_end_before_start(self):
        writer = RecordStreamWriter(KEY)

        with pytest.raises(RuntimeError):
            writer.end()

    def test_double_start(self):
        writer = RecordStreamWriter(KEY)
        writer.start()

        with pytest.raises(RuntimeError):
            writer.start()

    def test_double_end(self):
        writer = RecordStreamWriter(KEY)
        writer.start()
        writer.end()

        with pytest.raises(RuntimeError):
            writer.end()

    def test_record_after_end(self):
        writer = RecordStreamWriter(KEY)
        writer.start()
        writer.end()

        with pytest.raises(RuntimeError):
            writer.record(b"x")
