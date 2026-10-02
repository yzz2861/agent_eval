from __future__ import annotations

import collections.abc as cabc
import os
import typing as t

from .encoding import base64_decode
from .encoding import base64_encode
from .encoding import want_bytes
from .exc import BadData
from .exc import BadRecordStream
from .exc import BadSignature
from .signer import Signer
from .signer import SigningAlgorithm

__all__ = ["RecordStreamSigner", "StreamReader", "StreamWriter"]

_VERSION = b"IDS1"
_SEP = b"~"
_FIELD_SEP = b"|"
_FRAME_TYPES = frozenset((b"H", b"R", b"E"))
_DEFAULT_MAX_RECORD_LENGTH = 1024 * 1024
_FRAME_OVERHEAD = 4096
_MAX_STREAM_ID_LENGTH = 256


def _unsigned_int(value: bytes, name: str) -> int:
    if not value or len(value) > 20 or not value.isascii() or not value.isdigit():
        raise BadRecordStream(f"Invalid {name}")

    return int(value)


def _base64_value(value: bytes, name: str) -> bytes:
    if not value.isascii() or not all(
        c in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        for c in value
    ):
        raise BadRecordStream(f"Invalid {name}")

    try:
        return base64_decode(value)
    except BadData:
        raise BadRecordStream(f"Invalid {name}") from None


class StreamWriter:
    """Produces a signed record stream.

    The header is generated when the writer is created. Call
    :meth:`record` for each record in order, then :meth:`finish` exactly
    once.
    """

    def __init__(self, signer: "RecordStreamSigner") -> None:
        self._signer = signer
        self._stream_id = base64_encode(os.urandom(16))
        self._previous = b""
        self._count = 0
        self._finished = False
        self.header = self._header()

    @property
    def stream_id(self) -> bytes:
        """The random identifier embedded in every frame."""
        return self._stream_id

    @property
    def count(self) -> int:
        """Number of records written so far."""
        return self._count

    @property
    def finished(self) -> bool:
        """Whether :meth:`finish` has been called."""
        return self._finished

    def _frame(self, kind: bytes, fields: list[bytes]) -> tuple[bytes, bytes]:
        message = _FIELD_SEP.join([_VERSION, kind, *fields])
        signed = self._signer._sign_frame(kind, message)
        signature = signed.rsplit(_SEP, 1)[1]
        return signed + b"\n", signature

    def _header(self) -> bytes:
        frame, signature = self._frame(b"H", [self._stream_id])
        self._previous = signature
        return frame

    def record(self, data: str | bytes) -> bytes:
        """Sign one record and return its newline-terminated frame."""
        if self._finished:
            raise RuntimeError("Cannot write to a finished record stream")

        data = want_bytes(data)

        if len(data) > self._signer.max_record_length:
            raise ValueError("Record is longer than the configured maximum")

        encoded = base64_encode(data)
        frame, signature = self._frame(
            b"R",
            [
                self._stream_id,
                str(self._count).encode("ascii"),
                self._previous,
                encoded,
            ],
        )
        self._previous = signature
        self._count += 1
        return frame

    def finish(self) -> bytes:
        """Return the authenticated end frame."""
        if self._finished:
            raise RuntimeError("Record stream is already finished")

        frame, _ = self._frame(
            b"E",
            [self._stream_id, self._previous, str(self._count).encode("ascii")],
        )
        self._finished = True
        return frame


class StreamReader:
    """Incrementally verifies a signed record stream.

    Feed arbitrary byte chunks to :meth:`feed`, which returns the records
    whose complete frames have been authenticated. After all input has
    been fed, call :meth:`eof`; it succeeds only when a valid end frame
    was received and no partial frame remains. Any error permanently
    invalidates the reader.
    """

    def __init__(self, signer: "RecordStreamSigner") -> None:
        self._signer = signer
        self._buffer = b""
        self._stream_id: bytes | None = None
        self._previous = b""
        self._next_index = 0
        self.complete = False
        self._failed = False

    def _fail(self, message: str) -> t.NoReturn:
        self._failed = True
        self.complete = False
        self._buffer = b""
        raise BadRecordStream(message)

    def _frame(self, line: bytes) -> tuple[bytes, bytes, bytes]:
        if not line.startswith(_VERSION + _FIELD_SEP):
            self._fail("Not a versioned record stream frame")

        try:
            message, signature = line.rsplit(_SEP, 1)
            frame_fields = message.split(_FIELD_SEP)
        except ValueError:
            self._fail("Invalid record stream frame")

        if len(frame_fields) < 2:
            self._fail("Invalid record stream frame")

        kind = frame_fields[1]
        fields = frame_fields[2:]
        allowed_field_count = {
            b"H": 1,
            b"R": 4,
            b"E": 3,
        }.get(kind)
        if allowed_field_count is None or not signature:
            self._fail("Invalid record stream frame")

        try:
            self._signer._verify_frame(kind, message, signature)
        except BadSignature as e:
            self._fail(str(e))

        if len(fields) != allowed_field_count:
            self._fail("Invalid record stream frame")

        return kind, signature, fields

    def _read_header(self, fields: list[bytes]) -> None:
        if self._stream_id is not None or len(fields) != 1:
            self._fail("Invalid stream header")

        stream_id = fields[0]

        if not 1 <= len(stream_id) <= _MAX_STREAM_ID_LENGTH:
            self._fail("Invalid stream identifier")

        _base64_value(stream_id, "stream identifier")

        self._stream_id = stream_id

    def _read_record(self, fields: list[bytes]) -> bytes:
        if self._stream_id is None or len(fields) != 4:
            self._fail("Invalid stream record")

        stream_id, index_value, previous, encoded = fields

        if stream_id != self._stream_id or previous != self._previous:
            self._fail("Record stream authentication chain is broken")

        index = _unsigned_int(index_value, "record index")

        if index != self._next_index:
            self._fail("Record stream index is out of order")

        encoded_limit = 4 * ((self._signer.max_record_length + 2) // 3)

        if len(encoded) > encoded_limit:
            self._fail("Record is longer than the configured maximum")

        data = _base64_value(encoded, "record payload")

        if len(data) > self._signer.max_record_length:
            self._fail("Record is longer than the configured maximum")

        self._next_index += 1
        return data

    def _read_end(self, fields: list[bytes]) -> None:
        if self._stream_id is None or len(fields) != 3:
            self._fail("Invalid stream end record")

        stream_id, previous, count_value = fields

        if stream_id != self._stream_id or previous != self._previous:
            self._fail("Record stream authentication chain is broken")

        count = _unsigned_int(count_value, "record count")

        if count != self._next_index:
            self._fail("Record stream count does not match")

        self.complete = True

    def _read_line(self, line: bytes) -> bytes | None:
        if self.complete:
            self._fail("Unexpected data after stream end")

        if len(line) > self._signer.max_frame_length:
            self._fail("Record stream frame is too long")

        kind, signature, fields = self._frame(line)

        if kind == b"H":
            self._read_header(fields)
            self._previous = signature
            return None

        if kind == b"R":
            data = self._read_record(fields)
            self._previous = signature
            return data

        self._read_end(fields)
        return None

    def feed(self, data: str | bytes = b"") -> list[bytes]:
        """Consume a chunk and return newly authenticated records."""
        if self._failed:
            raise BadRecordStream("Record stream reader has already failed")

        if self.complete:
            if not data:
                return []

            self._fail("Unexpected data after stream end")

        self._buffer += want_bytes(data)
        records: list[bytes] = []

        while b"\n" in self._buffer:
            line, self._buffer = self._buffer.split(b"\n", 1)

            if not line:
                self._fail("Invalid empty record stream frame")

            record = self._read_line(line)

            if record is not None:
                records.append(record)

            if self.complete and self._buffer:
                self._fail("Unexpected data after stream end")

        if len(self._buffer) > self._signer.max_frame_length:
            self._fail("Record stream frame is too long")

        return records

    def eof(self) -> None:
        """Assert that the stream ended cleanly after a valid end frame."""
        if self._failed:
            raise BadRecordStream("Record stream reader has already failed")

        if not self.complete or self._buffer:
            self._fail("Record stream ended before the end frame")


class RecordStreamSigner:
    """Sign and verify an ordered stream of byte-string records.

    :param secret_key: The secret key, oldest to newest when more than
        one key is provided for key rotation.
    :param max_record_length: Maximum decoded length for one record.
        Defaults to 1 MiB.
    """

    def __init__(
        self,
        secret_key: str | bytes | cabc.Iterable[str] | cabc.Iterable[bytes],
        *,
        max_record_length: int = _DEFAULT_MAX_RECORD_LENGTH,
        key_derivation: str | None = None,
        digest_method: t.Any | None = None,
        algorithm: SigningAlgorithm | None = None,
    ) -> None:
        if max_record_length < 0:
            raise ValueError("max_record_length must be non-negative")

        self.max_record_length = max_record_length
        self.max_frame_length = (
            max_record_length
            + 4 * ((max_record_length + 2) // 3)
            + _FRAME_OVERHEAD
        )
        self._signers = {
            kind: Signer(
                secret_key,
                salt=f"itsdangerous.RecordStream.v1.{kind}",
                sep=_SEP,
                key_derivation=key_derivation,
                digest_method=digest_method,
                algorithm=algorithm,
            )
            for kind in ("header", "record", "end")
        }

    def _signer_for(self, kind: bytes) -> Signer:
        return self._signers[{b"H": "header", b"R": "record", b"E": "end"}[kind]]

    def _sign_frame(self, kind: bytes, message: bytes) -> bytes:
        return self._signer_for(kind).sign(message)

    def _verify_frame(self, kind: bytes, message: bytes, signature: bytes) -> None:
        self._signer_for(kind).unsign(message + _SEP + signature)

    def writer(self) -> StreamWriter:
        """Create a new writer with a random stream identifier."""
        return StreamWriter(self)

    def sign_stream(self, records: cabc.Iterable[str | bytes]) -> bytes:
        """Sign all records and return the complete byte stream."""
        writer = self.writer()
        return (
            writer.header
            + b"".join(writer.record(record) for record in records)
            + writer.finish()
        )

    def reader(self) -> StreamReader:
        """Create a fresh incremental reader."""
        return StreamReader(self)
