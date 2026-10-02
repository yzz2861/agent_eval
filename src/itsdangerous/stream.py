from __future__ import annotations

import collections.abc as cabc
import hashlib
import hmac
import secrets
import typing as t

from .encoding import base64_decode
from .encoding import base64_encode
from .encoding import want_bytes
from .exc import BadData
from .exc import BadSignature
from .signer import _make_keys_list

#: Version tag prefixing every frame. Bumping it produces an incompatible
#: format, so old readers reject new streams instead of mis-parsing them.
_stream_version = b"IDSR1"

#: Separator between the domain prefix and the signed fields.
_nul = bytes(1)

#: Default salt, keeping stream signatures separate from every other
#: itsdangerous signing context.
_default_salt = b"itsdangerous.RecordStream.v1"

#: Domain separation prefixes inside the signed messages, so a signature
#: for one frame type can never be reinterpreted as another.
_msg_header = _stream_version + b".H" + _nul
_msg_record = _stream_version + b".R" + _nul
_msg_end = _stream_version + b".E" + _nul

#: Size in bytes of the random stream identifier.
_stream_id_size = 16

#: Default maximum size of a single record payload.
_default_max_record_size = 1024 * 1024


class BadStream(BadData):
    """Base class for all record stream errors. Once a reader raises any
    of these, it will not emit any further records.
    """


class BadStreamSignature(BadStream, BadSignature):
    """A frame signature or chain value did not match. This indicates
    tampering, truncation, or splicing of the stream.
    """


class TruncatedStream(BadStream):
    """The stream ended before its authenticating end frame was received."""


class StreamStateError(BadStream):
    """Frames arrived in an invalid order, after the end of the stream, or
    exceeded a configured limit.
    """


class _RecordStreamBase:
    """Shared key handling for the stream writer and reader."""

    def __init__(
        self,
        secret_key: str | bytes | cabc.Iterable[str] | cabc.Iterable[bytes],
        *,
        salt: str | bytes,
        digest_method: t.Any,
        max_record_size: int,
    ):
        self.secret_keys: list[bytes] = _make_keys_list(secret_key)
        self.salt: bytes = want_bytes(salt)
        self.digest_method: t.Any = digest_method
        self.max_record_size: int = max_record_size

    def _derive_key(self, secret_key: bytes) -> bytes:
        mac = hmac.new(secret_key, digestmod=self.digest_method)
        mac.update(self.salt)
        return mac.digest()

    def _mac(self, key: bytes, message: bytes) -> bytes:
        return hmac.new(key, msg=message, digestmod=self.digest_method).digest()


class RecordStreamWriter(_RecordStreamBase):
    """Writes a stream of individually authenticated records that is also
    authenticated as a whole, so reordering, truncation, and splicing are
    detectable when reading.

    The stream is a sequence of newline-delimited frames::

        IDSR1.H.<stream id>.<sig>
        IDSR1.R.<seq>.<payload>.<sig>   (one per record, seq from 0)
        IDSR1.E.<count>.<sig>

    The header carries a random stream id. Every record signature binds
    the stream id, the record's sequence number, the previous frame's
    signature (a hash chain), and the record content. The end frame
    authenticates the total record count and the final chain value, so a
    stream is only complete once it has been received and verified.

    :param secret_key: The secret key to sign with. Can be a list of keys,
        oldest to newest, to support key rotation. The newest key signs.
    :param salt: Extra key to distinguish this stream's signatures from
        other contexts. The default isolates streams from plain
        itsdangerous tokens.
    :param digest_method: Hash function for the HMAC signatures. Defaults
        to hashlib.sha256.
    :param max_record_size: Maximum size in bytes of a single record
        payload. Larger records raise ValueError.

    .. versionadded:: 2.3
    """

    def __init__(
        self,
        secret_key: str | bytes | cabc.Iterable[str] | cabc.Iterable[bytes],
        *,
        salt: str | bytes = _default_salt,
        digest_method: t.Any = hashlib.sha256,
        max_record_size: int = _default_max_record_size,
    ):
        super().__init__(
            secret_key,
            salt=salt,
            digest_method=digest_method,
            max_record_size=max_record_size,
        )
        self._key = self._derive_key(self.secret_keys[-1])

        #: Random identifier for this stream, binding all frames together
        #: and preventing frames from other streams being spliced in.
        self.stream_id: bytes = secrets.token_bytes(_stream_id_size)

        self._chain: bytes | None = None
        self._count = 0
        self._ended = False

    def _frame(self, kind: bytes, fields: list[bytes], message: bytes) -> bytes:
        mac = self._mac(self._key, message)
        self._chain = mac
        return b".".join([_stream_version, kind, *fields, base64_encode(mac)]) + b"\n"

    def start(self) -> bytes:
        """Return the signed header frame. Must be called exactly once,
        before any records.
        """
        if self._chain is not None:
            raise RuntimeError("start() was already called")

        return self._frame(
            b"H", [base64_encode(self.stream_id)], _msg_header + self.stream_id
        )

    def record(self, payload: str | bytes) -> bytes:
        """Return the signed frame for one record. The frame binds the
        record's sequence number, the previous frame's signature, and the
        payload.
        """
        if self._chain is None:
            raise RuntimeError("start() must be called before adding records")

        if self._ended:
            raise RuntimeError("cannot add records after end()")

        payload = want_bytes(payload)

        if len(payload) > self.max_record_size:
            raise ValueError(
                f"record of {len(payload)} bytes exceeds max_record_size"
                f" of {self.max_record_size}"
            )

        seq = self._count
        message = (
            _msg_record
            + self.stream_id
            + seq.to_bytes(8, "big")
            + self._chain
            + len(payload).to_bytes(8, "big")
            + payload
        )
        self._count += 1
        return self._frame(
            b"R", [str(seq).encode("ascii"), base64_encode(payload)], message
        )

    def end(self) -> bytes:
        """Return the signed end frame, which authenticates the total
        record count and the final chain value. Must be called exactly
        once, after start().
        """
        if self._chain is None:
            raise RuntimeError("start() must be called before end()")

        if self._ended:
            raise RuntimeError("end() was already called")

        self._ended = True
        message = (
            _msg_end + self.stream_id + self._count.to_bytes(8, "big") + self._chain
        )
        return self._frame(b"E", [str(self._count).encode("ascii")], message)


class RecordStreamReader(_RecordStreamBase):
    """Reads a stream written by RecordStreamWriter, verifying each frame
    before emitting its record.

    Bytes can be fed in arbitrary chunks with feed(), which returns the
    records that became complete and verified. The stream is only known
    to be complete and untampered once an end frame was received and
    finish() succeeds. If any error is raised, the reader is poisoned and
    will not emit further records.

    Accepts the same arguments as RecordStreamWriter.

    .. versionadded:: 2.3
    """

    def __init__(
        self,
        secret_key: str | bytes | cabc.Iterable[str] | cabc.Iterable[bytes],
        *,
        salt: str | bytes = _default_salt,
        digest_method: t.Any = hashlib.sha256,
        max_record_size: int = _default_max_record_size,
    ):
        super().__init__(
            secret_key,
            salt=salt,
            digest_method=digest_method,
            max_record_size=max_record_size,
        )
        self._keys = [self._derive_key(key) for key in reversed(self.secret_keys)]
        digest_size: int = self.digest_method().digest_size
        # Generous upper bound for a single frame line, used to reject
        # oversized frames before they are buffered without limit.
        self._max_frame_size = (
            32
            + 4 * ((_stream_id_size + 2) // 3)
            + 4 * ((max_record_size + 2) // 3)
            + 4 * ((digest_size + 2) // 3)
        )
        self._buffer = b""
        self._stream_id: bytes | None = None
        self._chain = b""
        self._count = 0
        self._done = False
        self._failed: BadStream | None = None

    @property
    def stream_id(self) -> bytes | None:
        """The stream's random identifier, available once the header frame
        has been verified.
        """
        return self._stream_id

    @property
    def record_count(self) -> int:
        """The number of records verified so far."""
        return self._count

    @property
    def done(self) -> bool:
        """Whether the authenticating end frame has been verified."""
        return self._done

    def feed(self, data: str | bytes) -> list[bytes]:
        """Feed a chunk of stream data, returning any records that became
        complete and verified. Chunks may split the stream at arbitrary
        byte positions.

        :raises BadStream: if any frame is invalid. After an error the
            reader is poisoned and raises on all further use.
        """
        if self._failed is not None:
            raise self._failed

        try:
            return self._feed(want_bytes(data))
        except BadStream as e:
            self._failed = e
            raise

    def _feed(self, data: bytes) -> list[bytes]:
        self._buffer += data
        out: list[bytes] = []

        while True:
            line, sep, rest = self._buffer.partition(b"\n")

            if not sep:
                if len(self._buffer) > self._max_frame_size:
                    raise StreamStateError("frame exceeds the maximum allowed size")

                break

            self._buffer = rest
            record = self._handle_frame(line)

            if record is not None:
                out.append(record)

        if self._done and self._buffer:
            raise StreamStateError("received data after the end of the stream")

        return out

    def finish(self) -> int:
        """Signal that no more data will be fed. Returns the total number
        of records in the stream.

        :raises TruncatedStream: if the authenticating end frame was not
            received, meaning the stream was cut short.
        """
        if self._failed is not None:
            raise self._failed

        if not self._done:
            self._failed = TruncatedStream(
                "stream ended before the end frame was received"
            )
            raise self._failed

        return self._count

    def _verify(self, message: bytes, sig: bytes) -> bool:
        return any(
            hmac.compare_digest(self._mac(key, message), sig) for key in self._keys
        )

    @staticmethod
    def _b64(field: bytes, what: str) -> bytes:
        try:
            return base64_decode(field)
        except BadData as e:
            raise BadStream(f"invalid base64 in {what}") from e

    @staticmethod
    def _decimal(field: bytes, what: str) -> int:
        if not field.isdigit():
            raise BadStream(f"invalid {what} in frame")

        return int(field)

    def _handle_frame(self, line: bytes) -> bytes | None:
        if self._done:
            raise StreamStateError("received a frame after the end of the stream")

        parts = line.split(b".")

        if len(parts) < 2 or parts[0] != _stream_version:
            raise BadStream("frame is not a versioned record stream frame")

        kind = parts[1]

        if self._stream_id is None:
            if kind != b"H":
                raise StreamStateError("stream must begin with a header frame")

            self._handle_header(parts)
            return None

        if kind == b"H":
            raise StreamStateError("duplicate header frame")
        elif kind == b"R":
            return self._handle_record(parts)
        elif kind == b"E":
            self._handle_end(parts)
            return None
        else:
            raise BadStream(f"unknown frame type {kind!r}")

    def _handle_header(self, parts: list[bytes]) -> None:
        if len(parts) != 4:
            raise BadStream("malformed header frame")

        stream_id = self._b64(parts[2], "stream id")

        if len(stream_id) != _stream_id_size:
            raise BadStream("invalid stream id in header frame")

        sig = self._b64(parts[3], "signature")

        if not self._verify(_msg_header + stream_id, sig):
            raise BadStreamSignature("header signature does not match")

        self._stream_id = stream_id
        self._chain = sig

    def _handle_record(self, parts: list[bytes]) -> bytes:
        if len(parts) != 5:
            raise BadStream("malformed record frame")

        seq = self._decimal(parts[2], "sequence number")

        if seq != self._count:
            raise StreamStateError(
                f"out-of-order record: expected sequence {self._count}, got {seq}"
            )

        payload = self._b64(parts[3], "record payload")

        if len(payload) > self.max_record_size:
            raise StreamStateError("record exceeds max_record_size")

        sig = self._b64(parts[4], "signature")
        stream_id = t.cast(bytes, self._stream_id)
        message = (
            _msg_record
            + stream_id
            + seq.to_bytes(8, "big")
            + self._chain
            + len(payload).to_bytes(8, "big")
            + payload
        )

        if not self._verify(message, sig):
            raise BadStreamSignature("record signature does not match", payload)

        self._chain = sig
        self._count += 1
        return payload

    def _handle_end(self, parts: list[bytes]) -> None:
        if len(parts) != 4:
            raise BadStream("malformed end frame")

        count = self._decimal(parts[2], "record count")

        if count != self._count:
            raise BadStreamSignature(
                f"end frame authenticates {count} records, but"
                f" {self._count} were received"
            )

        sig = self._b64(parts[3], "signature")
        stream_id = t.cast(bytes, self._stream_id)
        message = _msg_end + stream_id + count.to_bytes(8, "big") + self._chain

        if not self._verify(message, sig):
            raise BadStreamSignature("end signature does not match")

        self._done = True
