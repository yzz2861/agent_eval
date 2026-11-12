"""
wsproto/frame_protocol
~~~~~~~~~~~~~~~~~~~~~~

WebSocket frame protocol implementation.
"""
from __future__ import annotations

import contextlib
import os
import struct
from codecs import IncrementalDecoder, getincrementaldecoder
from collections.abc import Callable
from enum import IntEnum
from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from collections.abc import Generator

    from .extensions import Extension  # pragma: no cover


_XOR_TABLE = [bytes(a ^ b for a in range(256)) for b in range(256)]


class XorMaskerSimple:
    def __init__(self, masking_key: bytearray | bytes) -> None:
        self._masking_key = masking_key

    def process(self, data: bytearray) -> bytearray:
        data = bytearray(data)
        if data:
            data_array = data
            a, b, c, d = (_XOR_TABLE[n] for n in self._masking_key)
            data_array[::4] = data_array[::4].translate(a)
            data_array[1::4] = data_array[1::4].translate(b)
            data_array[2::4] = data_array[2::4].translate(c)
            data_array[3::4] = data_array[3::4].translate(d)

            # Rotate the masking key so that the next usage continues
            # with the next key element, rather than restarting.
            key_rotation = len(data) % 4
            self._masking_key = (
                self._masking_key[key_rotation:] + self._masking_key[:key_rotation]
            )

            return data_array
        return data


class XorMaskerNull:
    def process(self, data: bytearray) -> bytearray:
        return data


# RFC6455, Section 5.2 - Base Framing Protocol

# Payload length constants
PAYLOAD_LENGTH_TWO_BYTE = 126
PAYLOAD_LENGTH_EIGHT_BYTE = 127
MAX_PAYLOAD_NORMAL = 125
MAX_PAYLOAD_TWO_BYTE = 2**16 - 1
MAX_PAYLOAD_EIGHT_BYTE = 2**64 - 1
MAX_FRAME_PAYLOAD = MAX_PAYLOAD_EIGHT_BYTE

# MASK and PAYLOAD LEN are packed into a byte
MASK_MASK = 0x80
PAYLOAD_LEN_MASK = 0x7F

# FIN, RSV[123] and OPCODE are packed into a single byte
FIN_MASK = 0x80
RSV1_MASK = 0x40
RSV2_MASK = 0x20
RSV3_MASK = 0x10
OPCODE_MASK = 0x0F


class Opcode(IntEnum):
    """
    RFC 6455, Section 5.2 - Base Framing Protocol
    """

    #: Continuation frame
    CONTINUATION = 0x0

    #: Text message
    TEXT = 0x1

    #: Binary message
    BINARY = 0x2

    #: Close frame
    CLOSE = 0x8

    #: Ping frame
    PING = 0x9

    #: Pong frame
    PONG = 0xA

    def iscontrol(self) -> bool:
        return bool(self & 0x08)


class CloseReason(IntEnum):
    """
    RFC 6455, Section 7.4.1 - Defined Status Codes
    """

    #: indicates a normal closure, meaning that the purpose for
    #: which the connection was established has been fulfilled.
    NORMAL_CLOSURE = 1000

    #: indicates that an endpoint is "going away", such as a server
    #: going down or a browser having navigated away from a page.
    GOING_AWAY = 1001

    #: indicates that an endpoint is terminating the connection due
    #: to a protocol error.
    PROTOCOL_ERROR = 1002

    #: indicates that an endpoint is terminating the connection
    #: because it has received a type of data it cannot accept (e.g., an
    #: endpoint that understands only text data MAY send this if it
    #: receives a binary message).
    UNSUPPORTED_DATA = 1003

    #: Reserved.  The specific meaning might be defined in the future.
    # DON'T DEFINE THIS: RESERVED_1004 = 1004

    #: is a reserved value and MUST NOT be set as a status code in a
    #: Close control frame by an endpoint.  It is designated for use in
    #: applications expecting a status code to indicate that no status
    #: code was actually present.
    NO_STATUS_RCVD = 1005

    #: is a reserved value and MUST NOT be set as a status code in a
    #: Close control frame by an endpoint.  It is designated for use in
    #: applications expecting a status code to indicate that the
    #: connection was closed abnormally, e.g., without sending or
    #: receiving a Close control frame.
    ABNORMAL_CLOSURE = 1006

    #: indicates that an endpoint is terminating the connection
    #: because it has received data within a message that was not
    #: consistent with the type of the message (e.g., non-UTF-8 [RFC3629]
    #: data within a text message).
    INVALID_FRAME_PAYLOAD_DATA = 1007

    #: indicates that an endpoint is terminating the connection
    #: because it has received a message that violates its policy.  This
    #: is a generic status code that can be returned when there is no
    #: other more suitable status code (e.g., 1003 or 1009) or if there
    #: is a need to hide specific details about the policy.
    POLICY_VIOLATION = 1008

    #: indicates that an endpoint is terminating the connection
    #: because it has received a message that is too big for it to
    #: process.
    MESSAGE_TOO_BIG = 1009

    #: indicates that an endpoint (client) is terminating the
    #: connection because it has expected the server to negotiate one or
    #: more extension, but the server didn't return them in the response
    #: message of the WebSocket handshake.  The list of extensions that
    #: are needed SHOULD appear in the /reason/ part of the Close frame.
    #: Note that this status code is not used by the server, because it
    #: can fail the WebSocket handshake instead.
    MANDATORY_EXT = 1010

    #: indicates that a server is terminating the connection because
    #: it encountered an unexpected condition that prevented it from
    #: fulfilling the request.
    INTERNAL_ERROR = 1011

    #: Server/service is restarting
    #: (not part of RFC6455)
    SERVICE_RESTART = 1012

    #: Temporary server condition forced blocking client's request
    #: (not part of RFC6455)
    TRY_AGAIN_LATER = 1013

    #: is a reserved value and MUST NOT be set as a status code in a
    #: Close control frame by an endpoint.  It is designated for use in
    #: applications expecting a status code to indicate that the
    #: connection was closed due to a failure to perform a TLS handshake
    #: (e.g., the server certificate can't be verified).
    TLS_HANDSHAKE_FAILED = 1015


# RFC 6455, Section 7.4.1 - Defined Status Codes
LOCAL_ONLY_CLOSE_REASONS = (
    CloseReason.NO_STATUS_RCVD,
    CloseReason.ABNORMAL_CLOSURE,
    CloseReason.TLS_HANDSHAKE_FAILED,
)


# RFC 6455, Section 5.5.1: a control frame payload is at most 125 bytes and
# the first two bytes of a CLOSE payload are the status code.
MAX_CLOSE_REASON_BYTES = MAX_PAYLOAD_NORMAL - 2

# RFC 6455, Section 7.4.1 registers 1014, but does not give it a name.
REGISTERED_CLOSE_REASON_BAD_GATEWAY = 1014


class CloseAuditCode(IntEnum):
    """Stable identifiers for close-handshake audit findings."""

    #: A CLOSE frame was received after the CLOSE handshake had started.
    DUPLICATE_CLOSE = 1
    #: A data or control frame other than the first CLOSE arrived after CLOSE.
    DATA_AFTER_CLOSE = 2
    #: The peer or local caller used a status code that cannot be sent.
    INVALID_CLOSE_CODE = 3
    #: The CLOSE reason was not valid UTF-8 or was the wrong Python type.
    INVALID_CLOSE_REASON = 4
    #: The encoded CLOSE reason did not fit in the control frame payload.
    CLOSE_REASON_TOO_LONG = 5
    #: The CLOSE frame payload could not be parsed as code plus reason.
    MALFORMED_CLOSE_FRAME = 6
    #: The transport reached EOF without a CLOSE frame.
    ABNORMAL_EOF = 7


class CloseAuditEvent(NamedTuple):
    reason_code: CloseAuditCode
    detail: str
    close_code: int | None = None
    close_reason: str | None = None


class CloseAuditError(Exception):
    """A local close request failed close-audit validation."""

    def __init__(
        self,
        reason_code: CloseAuditCode,
        message: str,
        close_code: int | None = None,
        close_reason: str | None = None,
    ) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.close_code = close_code
        self.close_reason = close_reason


CloseAuditCallback = Callable[
    [CloseAuditCode, str, int | None, str | None], None,
]


# RFC 6455, Section 7.4.2 - Status Code Ranges
MIN_CLOSE_REASON = 1000
MIN_PROTOCOL_CLOSE_REASON = 1000
MAX_PROTOCOL_CLOSE_REASON = 2999
MIN_LIBRARY_CLOSE_REASON = 3000
MAX_LIBRARY_CLOSE_REASON = 3999
MIN_PRIVATE_CLOSE_REASON = 4000
MAX_PRIVATE_CLOSE_REASON = 4999
MAX_CLOSE_REASON = 4999

# Status codes that an endpoint is allowed to send in a CLOSE frame. The
# reserved 1004 and local-only 1005/1006/1015 codes are deliberately absent.
SENDABLE_CLOSE_REASONS = frozenset(
    {int(code) for code in CloseReason if code not in LOCAL_ONLY_CLOSE_REASONS}
    | {REGISTERED_CLOSE_REASON_BAD_GATEWAY}
    | set(range(MIN_LIBRARY_CLOSE_REASON, MAX_PRIVATE_CLOSE_REASON + 1)),
)


NULL_MASK = struct.pack("!I", 0)


class ParseFailed(Exception):
    def __init__(
        self, msg: str, code: CloseReason = CloseReason.PROTOCOL_ERROR,
    ) -> None:
        super().__init__(msg)
        self.code = code


class RsvBits(NamedTuple):
    rsv1: bool
    rsv2: bool
    rsv3: bool


class Header(NamedTuple):
    fin: bool
    rsv: RsvBits
    opcode: Opcode
    payload_len: int
    masking_key: bytes | None


class Frame(NamedTuple):
    opcode: Opcode
    payload: bytes | str | tuple[int, str]
    frame_finished: bool
    message_finished: bool


def _truncate_utf8(data: bytes, nbytes: int) -> bytes:
    if len(data) <= nbytes:
        return data

    # Truncate
    data = data[:nbytes]
    # But we might have cut a codepoint in half, in which case we want to
    # discard the partial character so the data is at least
    # well-formed. This is a little inefficient since it processes the
    # whole message twice when in theory we could just peek at the last
    # few characters, but since this is only used for close messages (max
    # length = 125 bytes) it really doesn't matter.
    return data.decode("utf-8", errors="ignore").encode("utf-8")


class Buffer:
    def __init__(self, initial_bytes: bytes | None = None) -> None:
        self.buffer = bytearray()
        self.bytes_used = 0
        if initial_bytes:
            self.feed(initial_bytes)

    def feed(self, new_bytes: bytes) -> None:
        self.buffer += new_bytes

    def consume_at_most(self, nbytes: int) -> bytearray:
        if not nbytes:
            return bytearray()

        data = self.buffer[self.bytes_used : self.bytes_used + nbytes]
        self.bytes_used += len(data)
        return data

    def consume_exactly(self, nbytes: int) -> bytearray | None:
        if len(self.buffer) - self.bytes_used < nbytes:
            return None

        return self.consume_at_most(nbytes)

    def commit(self) -> None:
        # In CPython 3.4+, del[:n] is amortized O(n), *not* quadratic
        del self.buffer[: self.bytes_used]
        self.bytes_used = 0

    def rollback(self) -> None:
        self.bytes_used = 0

    def __len__(self) -> int:
        return len(self.buffer)


class MessageDecoder:
    def __init__(self) -> None:
        self.opcode: Opcode | None = None
        self.decoder: IncrementalDecoder | None = None

    def process_frame(self, frame: Frame) -> Frame:
        assert not frame.opcode.iscontrol()

        if self.opcode is None:
            if frame.opcode is Opcode.CONTINUATION:
                msg = "unexpected CONTINUATION"
                raise ParseFailed(msg)
            self.opcode = frame.opcode
        elif frame.opcode is not Opcode.CONTINUATION:
            msg = f"expected CONTINUATION, got {frame.opcode!r}"
            raise ParseFailed(msg)

        if frame.opcode is Opcode.TEXT:
            self.decoder = getincrementaldecoder("utf-8")()

        finished = frame.frame_finished and frame.message_finished

        if self.decoder is None:
            data = frame.payload
        else:
            assert isinstance(frame.payload, (bytes, bytearray))
            try:
                data = self.decoder.decode(frame.payload, finished)
            except UnicodeDecodeError as exc:
                raise ParseFailed(str(exc), CloseReason.INVALID_FRAME_PAYLOAD_DATA)

        frame = Frame(self.opcode, data, frame.frame_finished, finished)

        if finished:
            self.opcode = None
            self.decoder = None

        return frame


class FrameDecoder:
    def __init__(
        self,
        client: bool,
        extensions: list[Extension] | None = None,
        close_audit: CloseAuditCallback | None = None,
    ) -> None:
        self.client = client
        self.extensions = extensions or []
        self._close_audit = close_audit

        self.buffer = Buffer()

        self.header: Header | None = None
        self.effective_opcode: Opcode | None = None
        self.masker: None | XorMaskerNull | XorMaskerSimple = None
        self.payload_required = 0
        self.payload_consumed = 0

    def receive_bytes(self, data: bytes) -> None:
        self.buffer.feed(data)

    def process_buffer(self) -> Frame | None:
        if not self.header and not self.parse_header():
            return None
        # parse_header() sets these.
        assert self.header is not None
        assert self.masker is not None
        assert self.effective_opcode is not None

        if len(self.buffer) < self.payload_required:
            return None

        payload_remaining = self.header.payload_len - self.payload_consumed
        payload = self.buffer.consume_at_most(payload_remaining)
        if not payload and self.header.payload_len > 0:
            return None
        self.buffer.commit()

        self.payload_consumed += len(payload)
        finished = self.payload_consumed == self.header.payload_len

        payload = self.masker.process(payload)

        for extension in self.extensions:
            payload_ = extension.frame_inbound_payload_data(self, bytes(payload))
            if isinstance(payload_, CloseReason):
                msg = "error in extension"
                raise ParseFailed(msg, payload_)
            payload = bytearray(payload_)

        if finished:
            final = bytearray()
            for extension in self.extensions:
                result = extension.frame_inbound_complete(self, self.header.fin)
                if isinstance(result, CloseReason):
                    msg = "error in extension"
                    raise ParseFailed(msg, result)
                if result is not None:
                    final += result
            payload += final

        frame = Frame(self.effective_opcode, bytes(payload), finished, self.header.fin)

        if finished:
            self.header = None
            self.effective_opcode = None
            self.masker = None
        else:
            self.effective_opcode = Opcode.CONTINUATION

        return frame

    def parse_header(self) -> bool:
        data = self.buffer.consume_exactly(2)
        if data is None:
            self.buffer.rollback()
            return False

        fin = bool(data[0] & FIN_MASK)
        rsv = RsvBits(
            bool(data[0] & RSV1_MASK),
            bool(data[0] & RSV2_MASK),
            bool(data[0] & RSV3_MASK),
        )
        opcode = data[0] & OPCODE_MASK
        try:
            opcode = Opcode(opcode)
        except ValueError:
            msg = f"Invalid opcode {opcode:#x}"
            raise ParseFailed(msg)

        if opcode.iscontrol() and not fin:
            msg = "Invalid attempt to fragment control frame"
            raise ParseFailed(msg)

        has_mask = bool(data[1] & MASK_MASK)
        payload_len_short = data[1] & PAYLOAD_LEN_MASK
        payload_len = self.parse_extended_payload_length(opcode, payload_len_short)
        if payload_len is None:
            self.buffer.rollback()
            return False

        self.extension_processing(opcode, rsv, payload_len)

        if has_mask and self.client:
            msg = "client received unexpected masked frame"
            raise ParseFailed(msg)
        if not has_mask and not self.client:
            msg = "server received unexpected unmasked frame"
            raise ParseFailed(msg)
        if has_mask:
            masking_key = self.buffer.consume_exactly(4)
            if masking_key is None:
                self.buffer.rollback()
                return False
            self.masker = XorMaskerSimple(masking_key)
        else:
            self.masker = XorMaskerNull()

        self.buffer.commit()
        self.header = Header(fin, rsv, opcode, payload_len, None)
        self.effective_opcode = self.header.opcode
        if self.header.opcode.iscontrol():
            self.payload_required = payload_len
        else:
            self.payload_required = 0
        self.payload_consumed = 0
        return True

    def parse_extended_payload_length(
        self, opcode: Opcode, payload_len: int,
    ) -> int | None:
        if opcode.iscontrol() and payload_len > MAX_PAYLOAD_NORMAL:
            if opcode is Opcode.CLOSE and self._close_audit is not None:
                self._close_audit(
                    CloseAuditCode.CLOSE_REASON_TOO_LONG,
                    "CLOSE frame payload exceeds 125 bytes",
                    None,
                    None,
                )
            msg = "Control frame with payload len > 125"
            raise ParseFailed(msg)
        if payload_len == PAYLOAD_LENGTH_TWO_BYTE:
            data = self.buffer.consume_exactly(2)
            if data is None:
                return None
            (payload_len,) = struct.unpack("!H", data)
            if payload_len <= MAX_PAYLOAD_NORMAL:
                msg = "Payload length used 2 bytes when 1 would have sufficed"
                raise ParseFailed(
                    msg,
                )
        elif payload_len == PAYLOAD_LENGTH_EIGHT_BYTE:
            data = self.buffer.consume_exactly(8)
            if data is None:
                return None
            (payload_len,) = struct.unpack("!Q", data)
            if payload_len <= MAX_PAYLOAD_TWO_BYTE:
                msg = "Payload length used 8 bytes when 2 would have sufficed"
                raise ParseFailed(
                    msg,
                )
            if payload_len >> 63:
                # I'm not sure why this is illegal, but that's what the RFC
                # says, so...
                msg = "8-byte payload length with non-zero MSB"
                raise ParseFailed(msg)

        return payload_len

    def extension_processing(
        self, opcode: Opcode, rsv: RsvBits, payload_len: int,
    ) -> None:
        rsv_used = [False, False, False]
        for extension in self.extensions:
            result = extension.frame_inbound_header(self, opcode, rsv, payload_len)
            if isinstance(result, CloseReason):
                msg = "error in extension"
                raise ParseFailed(msg, result)
            for bit, used in enumerate(result):
                if used:
                    rsv_used[bit] = True
        for expected, found in zip(rsv_used, rsv):
            if found and not expected:
                msg = "Reserved bit set unexpectedly"
                raise ParseFailed(msg)


class FrameProtocol:
    def __init__(
        self,
        client: bool,
        extensions: list[Extension],
        close_audit: bool = False,
    ) -> None:
        self.client = client
        self.extensions = [ext for ext in extensions if ext.enabled()]
        self.close_audit = close_audit
        self._audit_events: list[CloseAuditEvent] = []
        self._close_received = False

        # Global state
        audit_callback = self._record_audit if close_audit else None
        self._frame_decoder = FrameDecoder(
            self.client,
            self.extensions,
            close_audit=audit_callback,
        )
        self._message_decoder = MessageDecoder()
        self._parse_more = self._parse_more_gen()

        self._outbound_opcode: Opcode | None = None

    @property
    def audit_events(self) -> tuple[CloseAuditEvent, ...]:
        return tuple(self._audit_events)

    def _record_audit(
        self,
        reason_code: CloseAuditCode,
        detail: str,
        close_code: int | None = None,
        close_reason: str | None = None,
    ) -> None:
        self._audit_events.append(
            CloseAuditEvent(reason_code, detail, close_code, close_reason),
        )

    def _raise_close_audit(
        self,
        reason_code: CloseAuditCode,
        detail: str,
        close_code: int | None = None,
        close_reason: str | None = None,
    ) -> None:
        self._record_audit(reason_code, detail, close_code, close_reason)
        raise CloseAuditError(reason_code, detail, close_code, close_reason)

    def _audit_close_failure(
        self,
        record_audit: bool,
        reason_code: CloseAuditCode,
        detail: str,
        close_code: int | None = None,
    ) -> None:
        if self.close_audit and record_audit:
            self._record_audit(reason_code, detail, close_code)

    def _process_close(self, frame: Frame, record_audit: bool = True) -> Frame:
        data = frame.payload
        assert isinstance(data, (bytes, bytearray))

        if not data:
            # "If this Close control frame contains no status code, _The
            # WebSocket Connection Close Code_ is considered to be 1005"
            data = (CloseReason.NO_STATUS_RCVD, "")
        elif len(data) == 1:
            self._audit_close_failure(
                record_audit,
                CloseAuditCode.MALFORMED_CLOSE_FRAME,
                "CLOSE with 1 byte payload",
            )
            msg = "CLOSE with 1 byte payload"
            raise ParseFailed(msg)
        else:
            (code,) = struct.unpack("!H", data[:2])
            if code < MIN_CLOSE_REASON or code > MAX_CLOSE_REASON:
                self._audit_close_failure(
                    record_audit,
                    CloseAuditCode.INVALID_CLOSE_CODE,
                    "CLOSE with invalid code",
                    code,
                )
                msg = "CLOSE with invalid code"
                raise ParseFailed(msg)
            with contextlib.suppress(ValueError):
                code = CloseReason(code)
            if code in LOCAL_ONLY_CLOSE_REASONS:
                self._audit_close_failure(
                    record_audit,
                    CloseAuditCode.INVALID_CLOSE_CODE,
                    "remote CLOSE with local-only reason",
                    int(code),
                )
                msg = "remote CLOSE with local-only reason"
                raise ParseFailed(msg)
            if not isinstance(code, CloseReason) and code <= MAX_PROTOCOL_CLOSE_REASON:
                self._audit_close_failure(
                    record_audit,
                    CloseAuditCode.INVALID_CLOSE_CODE,
                    "CLOSE with unknown reserved code",
                    code,
                )
                msg = "CLOSE with unknown reserved code"
                raise ParseFailed(msg)
            try:
                reason = data[2:].decode("utf-8")
            except UnicodeDecodeError as exc:
                self._audit_close_failure(
                    record_audit,
                    CloseAuditCode.INVALID_CLOSE_REASON,
                    "Error decoding CLOSE reason: " + str(exc),
                    int(code),
                )
                raise ParseFailed(
                    "Error decoding CLOSE reason: " + str(exc),
                    CloseReason.INVALID_FRAME_PAYLOAD_DATA,
                )
            data = (code, reason)

        return Frame(frame.opcode, data, frame.frame_finished, frame.message_finished)

    def _parse_more_gen(self) -> Generator[Frame | None, None, None]:
        # Consume as much as we can from self._buffer, yielding events, and
        # then yield None when we need more data. Or raise ParseFailed.

        # XX FIXME this should probably be refactored so that we never see
        # disabled extensions in the first place...
        self.extensions = [ext for ext in self.extensions if ext.enabled()]
        closed = False

        while not closed:
            frame = self._frame_decoder.process_buffer()

            if frame is not None:
                if not frame.opcode.iscontrol():
                    frame = self._message_decoder.process_frame(frame)
                elif frame.opcode == Opcode.CLOSE:
                    frame = self._process_close(frame)
                    self._close_received = True
                    closed = True

            yield frame

        if self.close_audit:
            yield from self._watch_after_close()

    def _watch_after_close(self) -> Generator[Frame | None, None, None]:
        while True:
            frame = self._frame_decoder.process_buffer()
            if frame is None:
                yield None
                continue

            while frame is not None:
                if frame.opcode is Opcode.CLOSE:
                    close_code: int | None = None
                    close_reason: str | None = None
                    frame_payload = frame.payload
                    if (
                        isinstance(frame_payload, (bytes, bytearray))
                        and len(frame_payload) >= 2
                    ):
                        (close_code,) = struct.unpack("!H", frame_payload[:2])
                    try:
                        duplicate = self._process_close(
                            frame, record_audit=False,
                        )
                        if isinstance(duplicate.payload, tuple):
                            close_code, close_reason = duplicate.payload
                    except ParseFailed as exc:
                        # The malformed/invalid second frame itself is the
                        # primary audit finding; do not add a second event for
                        # the same bytes merely because they were also a
                        # duplicate CLOSE.
                        self._record_audit(
                            self._audit_code_for_parse_failure(exc),
                            f"invalid second CLOSE frame: {exc}",
                            close_code,
                            close_reason,
                        )
                    else:
                        self._record_audit(
                            CloseAuditCode.DUPLICATE_CLOSE,
                            "received a second CLOSE frame",
                            close_code,
                            close_reason,
                        )
                else:
                    self._record_audit(
                        CloseAuditCode.DATA_AFTER_CLOSE,
                        f"received {frame.opcode.name} frame after CLOSE",
                    )

                frame = self._frame_decoder.process_buffer()

            # Only the first CLOSE is exposed as an event; keep waiting for
            # further audit findings without yielding another protocol frame.
            yield None

    @staticmethod
    def _audit_code_for_parse_failure(exc: ParseFailed) -> CloseAuditCode:
        if "1 byte payload" in str(exc):
            return CloseAuditCode.MALFORMED_CLOSE_FRAME
        if exc.code is CloseReason.INVALID_FRAME_PAYLOAD_DATA:
            return CloseAuditCode.INVALID_CLOSE_REASON
        return CloseAuditCode.INVALID_CLOSE_CODE

    def receive_bytes(self, data: bytes) -> None:
        self._frame_decoder.receive_bytes(data)

    def received_frames(self) -> Generator[Frame, None, None]:
        for event in self._parse_more:
            if event is None:
                break
            else:
                yield event

    def close(self, code: int | None = None, reason: str | None = None) -> bytearray:
        if self.close_audit:
            payload = self._audit_close(code, reason)
            return self._serialize_frame(Opcode.CLOSE, payload)

        payload = bytearray()
        if code is CloseReason.NO_STATUS_RCVD:
            code = None
        if code is None and reason:
            msg = "cannot specify a reason without a code"
            raise TypeError(msg)
        if code in LOCAL_ONLY_CLOSE_REASONS:
            code = CloseReason.NORMAL_CLOSURE
        if code is not None:
            payload += bytearray(struct.pack("!H", code))
            if reason is not None:
                payload += _truncate_utf8(
                    reason.encode("utf-8"), MAX_PAYLOAD_NORMAL - 2,
                )

        return self._serialize_frame(Opcode.CLOSE, payload)

    def _audit_close(
        self, code: int | None, reason: str | None,
    ) -> bytearray:
        if code is None:
            if reason is not None:
                self._raise_close_audit(
                    CloseAuditCode.INVALID_CLOSE_REASON,
                    "cannot specify a reason without a code",
                    None,
                    reason,
                )
            return bytearray()

        numeric_code = int(code)
        if (
            not isinstance(code, int)
            or isinstance(code, bool)
            or numeric_code not in SENDABLE_CLOSE_REASONS
        ):
            self._raise_close_audit(
                CloseAuditCode.INVALID_CLOSE_CODE,
                f"CLOSE code {code!r} is not allowed on the wire",
                numeric_code,
                reason,
            )

        payload = bytearray(struct.pack("!H", numeric_code))
        if reason is None:
            return payload

        if not isinstance(reason, str):
            self._raise_close_audit(
                CloseAuditCode.INVALID_CLOSE_REASON,
                "CLOSE reason must be a str",
                numeric_code,
                None,
            )
        try:
            reason_bytes = reason.encode("utf-8")
        except UnicodeEncodeError as exc:
            self._raise_close_audit(
                CloseAuditCode.INVALID_CLOSE_REASON,
                "CLOSE reason is not valid UTF-8: " + str(exc),
                numeric_code,
                reason,
            )

        if len(reason_bytes) > MAX_CLOSE_REASON_BYTES:
            self._raise_close_audit(
                CloseAuditCode.CLOSE_REASON_TOO_LONG,
                (
                    "CLOSE reason is "
                    f"{len(reason_bytes)} bytes; maximum is "
                    f"{MAX_CLOSE_REASON_BYTES}"
                ),
                numeric_code,
                reason,
            )

        payload += reason_bytes
        return payload

    def ping(self, payload: bytes = b"") -> bytearray:
        return self._serialize_frame(Opcode.PING, payload)

    def pong(self, payload: bytes = b"") -> bytearray:
        return self._serialize_frame(Opcode.PONG, payload)

    def send_data(
        self, payload: bytes | bytearray | str = b"", fin: bool = True,
    ) -> bytearray:
        if isinstance(payload, (bytes, bytearray, memoryview)):
            opcode = Opcode.BINARY
        elif isinstance(payload, str):
            opcode = Opcode.TEXT
            payload = payload.encode("utf-8")
        else:
            msg = "Must provide bytes or text"
            raise TypeError(msg)

        if self._outbound_opcode is None:
            self._outbound_opcode = opcode
        elif self._outbound_opcode is not opcode:
            msg = "Data type mismatch inside message"
            raise TypeError(msg)
        else:
            opcode = Opcode.CONTINUATION

        if fin:
            self._outbound_opcode = None

        return self._serialize_frame(opcode, payload, fin)

    def _make_fin_rsv_opcode(self, fin: bool, rsv: RsvBits, opcode: Opcode) -> int:
        fin_bits = int(fin) << 7
        rsv_bits = (int(rsv.rsv1) << 6) + (int(rsv.rsv2) << 5) + (int(rsv.rsv3) << 4)
        opcode_bits = int(opcode)

        return fin_bits | rsv_bits | opcode_bits

    def _serialize_frame(
        self, opcode: Opcode, payload: bytes | bytearray = b"", fin: bool = True,
    ) -> bytearray:
        payload = bytearray(payload)

        rsv = RsvBits(False, False, False)
        for extension in reversed(self.extensions):
            rsv, payload = extension.frame_outbound(self, opcode, rsv, bytes(payload), fin)

        fin_rsv_opcode = self._make_fin_rsv_opcode(fin, rsv, opcode)

        payload_length = len(payload)
        quad_payload = False
        if payload_length <= MAX_PAYLOAD_NORMAL:
            first_payload = payload_length
            second_payload = None
        elif payload_length <= MAX_PAYLOAD_TWO_BYTE:
            first_payload = PAYLOAD_LENGTH_TWO_BYTE
            second_payload = payload_length
        else:
            first_payload = PAYLOAD_LENGTH_EIGHT_BYTE
            second_payload = payload_length
            quad_payload = True

        if self.client:
            first_payload |= 1 << 7

        header = bytearray([fin_rsv_opcode, first_payload])
        if second_payload is not None:
            if opcode.iscontrol():
                msg = "payload too long for control frame"
                raise ValueError(msg)
            if quad_payload:
                header += bytearray(struct.pack("!Q", second_payload))
            else:
                header += bytearray(struct.pack("!H", second_payload))

        if self.client:
            # "The masking key is a 32-bit value chosen at random by the
            # client.  When preparing a masked frame, the client MUST pick a
            # fresh masking key from the set of allowed 32-bit values.  The
            # masking key needs to be unpredictable; thus, the masking key
            # MUST be derived from a strong source of entropy, and the masking
            # key for a given frame MUST NOT make it simple for a server/proxy
            # to predict the masking key for a subsequent frame.  The
            # unpredictability of the masking key is essential to prevent
            # authors of malicious applications from selecting the bytes that
            # appear on the wire."
            #   -- https://tools.ietf.org/html/rfc6455#section-5.3
            masking_key = bytearray(os.urandom(4))
            masker = XorMaskerSimple(masking_key)
            return bytearray(header + masking_key + masker.process(bytearray(payload)))

        return bytearray(header + payload)
