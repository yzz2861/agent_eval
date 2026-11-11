"""
wsproto/extensions
~~~~~~~~~~~~~~~~~~

WebSocket extensions.
"""
from __future__ import annotations

import zlib
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import ClassVar, Optional

from .frame_protocol import CloseReason, FrameDecoder, FrameProtocol, Opcode, RsvBits


class Extension(ABC):
    name: str

    def enabled(self) -> bool:
        return False

    @abstractmethod
    def offer(self) -> bool | str:
        pass

    def accept(self, offer: str) -> bool | str | None:
        pass

    def finalize(self, offer: str) -> None:
        pass

    def frame_inbound_header(
        self,
        proto: FrameDecoder | FrameProtocol,
        opcode: Opcode,
        rsv: RsvBits,
        payload_length: int,
    ) -> CloseReason | RsvBits:
        return RsvBits(False, False, False)

    def frame_inbound_payload_data(
        self, proto: FrameDecoder | FrameProtocol, data: bytes,
    ) -> bytes | CloseReason:
        return data

    def frame_inbound_complete(
        self, proto: FrameDecoder | FrameProtocol, fin: bool,
    ) -> bytes | CloseReason | None:
        pass

    def frame_outbound(
        self,
        proto: FrameDecoder | FrameProtocol,
        opcode: Opcode,
        rsv: RsvBits,
        data: bytes,
        fin: bool,
    ) -> tuple[RsvBits, bytes]:
        return (rsv, data)


@dataclass(frozen=True, init=False)
class PerMessageDeflateLimits:
    """
    Limits applied to data produced by inbound DEFLATE decompression.

    All limits are optional and measured in decompressed bytes. ``None``
    means unlimited. The limits are enforced while zlib is decoding, so a
    small compressed payload cannot force an unbounded allocation.
    """

    max_message_size: int | None
    max_total_size: int | None
    max_frame_size: int | None

    _ALIASES: ClassVar[dict[str, str]] = {
        "max_message_decompressed_size": "max_message_size",
        "max_message_decompressed_bytes": "max_message_size",
        "max_message_payload": "max_message_size",
        "max_decompressed_size": "max_message_size",
        "max_total_decompressed_size": "max_total_size",
        "max_total_decompressed_bytes": "max_total_size",
        "max_total_payload": "max_total_size",
        "max_frame_decompressed_size": "max_frame_size",
        "max_frame_decompressed_bytes": "max_frame_size",
        "max_frame_payload": "max_frame_size",
    }

    def __init__(
        self,
        max_message_size: int | None = None,
        max_total_size: int | None = None,
        max_frame_size: int | None = None,
        *,
        max_message_bytes: int | None = None,
        max_cumulative_size: int | None = None,
        max_cumulative_bytes: int | None = None,
        max_frame_bytes: int | None = None,
        **aliases: int | None,
    ) -> None:
        unknown = set(aliases) - set(self._ALIASES)
        if unknown:
            names = ", ".join(sorted(unknown))
            msg = f"unexpected decompression limit argument(s): {names}"
            raise TypeError(msg)

        max_message_size = self._resolve(
            "max_message_size", max_message_size, max_message_bytes,
        )
        max_total_size = self._resolve(
            "max_total_size", max_total_size, max_cumulative_size, max_cumulative_bytes,
        )
        max_frame_size = self._resolve(
            "max_frame_size", max_frame_size, max_frame_bytes,
        )
        grouped: dict[str, list[int | None]] = {}
        for alias, value in aliases.items():
            grouped.setdefault(self._ALIASES[alias], []).append(value)
        for field, values in grouped.items():
            if field == "max_message_size":
                max_message_size = self._resolve(
                    field, max_message_size, *values,
                )
            elif field == "max_total_size":
                max_total_size = self._resolve(field, max_total_size, *values)
            else:
                max_frame_size = self._resolve(field, max_frame_size, *values)
        for name, value in (
            ("max_message_size", max_message_size),
            ("max_total_size", max_total_size),
            ("max_frame_size", max_frame_size),
        ):
            if value is not None and (not isinstance(value, int) or value < 0):
                msg = f"{name} must be a non-negative integer or None"
                raise ValueError(msg)

        object.__setattr__(self, "max_message_size", max_message_size)
        object.__setattr__(self, "max_total_size", max_total_size)
        object.__setattr__(self, "max_frame_size", max_frame_size)

    @staticmethod
    def _resolve(name: str, *values: int | None) -> int | None:
        supplied = [value for value in values if value is not None]
        if len(set(supplied)) > 1:
            msg = f"conflicting values supplied for {name}"
            raise TypeError(msg)
        return supplied[0] if supplied else None

    @property
    def max_message_bytes(self) -> int | None:
        return self.max_message_size

    @property
    def max_cumulative_size(self) -> int | None:
        return self.max_total_size

    @property
    def max_cumulative_bytes(self) -> int | None:
        return self.max_total_size

    @property
    def max_frame_bytes(self) -> int | None:
        return self.max_frame_size


# Descriptive aliases for callers that prefer to name the direction of the
# budget explicitly. They intentionally refer to the same policy type.
InboundDecompressionLimits = PerMessageDeflateLimits
DecompressionLimits = PerMessageDeflateLimits
InboundLimits = PerMessageDeflateLimits
DecompressionBudget = PerMessageDeflateLimits


class PerMessageDeflate(Extension):
    name = "permessage-deflate"

    DEFAULT_CLIENT_MAX_WINDOW_BITS = 15
    DEFAULT_SERVER_MAX_WINDOW_BITS = 15

    def __init__(
        self,
        client_no_context_takeover: bool = False,
        client_max_window_bits: int | None = None,
        server_no_context_takeover: bool = False,
        server_max_window_bits: int | None = None,
        limits: PerMessageDeflateLimits | None = None,
        *,
        inbound_limits: PerMessageDeflateLimits | None = None,
        budget: PerMessageDeflateLimits | None = None,
        inbound_budget: PerMessageDeflateLimits | None = None,
        max_message_size: int | None = None,
        max_total_size: int | None = None,
        max_frame_size: int | None = None,
        max_message_bytes: int | None = None,
        max_cumulative_size: int | None = None,
        max_cumulative_bytes: int | None = None,
        max_frame_bytes: int | None = None,
        **limit_aliases: int | None,
    ) -> None:
        self.client_no_context_takeover = client_no_context_takeover
        self.server_no_context_takeover = server_no_context_takeover
        self._client_max_window_bits = self.DEFAULT_CLIENT_MAX_WINDOW_BITS
        self._server_max_window_bits = self.DEFAULT_SERVER_MAX_WINDOW_BITS
        if client_max_window_bits is not None:
            self.client_max_window_bits = client_max_window_bits
        if server_max_window_bits is not None:
            self.server_max_window_bits = server_max_window_bits

        policies = [
            value
            for value in (limits, inbound_limits, budget, inbound_budget)
            if value is not None
        ]
        if len(policies) > 1:
            msg = "specify only one inbound limits policy"
            raise TypeError(msg)
        limits = policies[0] if policies else None
        direct_limits = (
            max_message_size,
            max_total_size,
            max_frame_size,
            max_message_bytes,
            max_cumulative_size,
            max_cumulative_bytes,
            max_frame_bytes,
        )
        if limits is not None and (
            any(value is not None for value in direct_limits) or limit_aliases
        ):
            msg = "limits cannot be combined with individual limit arguments"
            raise TypeError(msg)
        if limits is None and (
            any(value is not None for value in direct_limits) or limit_aliases
        ):
            limits = PerMessageDeflateLimits(
                max_message_size=max_message_size,
                max_total_size=max_total_size,
                max_frame_size=max_frame_size,
                max_message_bytes=max_message_bytes,
                max_cumulative_size=max_cumulative_size,
                max_cumulative_bytes=max_cumulative_bytes,
                max_frame_bytes=max_frame_bytes,
                **limit_aliases,
            )
        self.limits = limits

        self._compressor: Optional[zlib._Compress] = None  # noqa
        self._decompressor: Optional[zlib._Decompress] = None  # noqa
        # This refers to the current frame
        self._inbound_is_compressible: bool | None = None
        # This refers to the ongoing message (which might span multiple
        # frames). Only the first frame in a fragmented message is flagged for
        # compression, so this carries that bit forward.
        self._inbound_compressed: bool | None = None

        # Inbound inflate budget accounting. The message and frame counters
        # reset at their respective boundaries; the total is connection-wide.
        self._inbound_message_output = 0
        self._inbound_frame_output = 0
        self._inbound_total_output = 0
        # Once an extension error has been reported, repeating it is safer
        # than allowing remaining bytes to be interpreted as a new message.
        self._inbound_error: CloseReason | None = None

        self._enabled = False

    @property
    def client_max_window_bits(self) -> int:
        return self._client_max_window_bits

    @client_max_window_bits.setter
    def client_max_window_bits(self, value: int) -> None:
        if value < 9 or value > 15:
            msg = "Window size must be between 9 and 15 inclusive"
            raise ValueError(msg)
        self._client_max_window_bits = value

    @property
    def server_max_window_bits(self) -> int:
        return self._server_max_window_bits

    @server_max_window_bits.setter
    def server_max_window_bits(self, value: int) -> None:
        if value < 9 or value > 15:
            msg = "Window size must be between 9 and 15 inclusive"
            raise ValueError(msg)
        self._server_max_window_bits = value

    def _compressible_opcode(self, opcode: Opcode) -> bool:
        return opcode in (Opcode.TEXT, Opcode.BINARY, Opcode.CONTINUATION)

    def enabled(self) -> bool:
        return self._enabled

    def offer(self) -> bool | str:
        parameters = [
            f"client_max_window_bits={self.client_max_window_bits}",
            f"server_max_window_bits={self.server_max_window_bits}",
        ]

        if self.client_no_context_takeover:
            parameters.append("client_no_context_takeover")
        if self.server_no_context_takeover:
            parameters.append("server_no_context_takeover")

        return "; ".join(parameters)

    def finalize(self, offer: str) -> None:
        bits = [b.strip() for b in offer.split(";")]
        for bit in bits[1:]:
            if bit.startswith("client_no_context_takeover"):
                self.client_no_context_takeover = True
            elif bit.startswith("server_no_context_takeover"):
                self.server_no_context_takeover = True
            elif bit.startswith("client_max_window_bits"):
                self.client_max_window_bits = int(bit.split("=", 1)[1].strip())
            elif bit.startswith("server_max_window_bits"):
                self.server_max_window_bits = int(bit.split("=", 1)[1].strip())

        self._enabled = True

    def _parse_params(self, params: str) -> tuple[int | None, int | None]:
        client_max_window_bits = None
        server_max_window_bits = None

        bits = [b.strip() for b in params.split(";")]
        for bit in bits[1:]:
            if bit.startswith("client_no_context_takeover"):
                self.client_no_context_takeover = True
            elif bit.startswith("server_no_context_takeover"):
                self.server_no_context_takeover = True
            elif bit.startswith("client_max_window_bits"):
                if "=" in bit:
                    client_max_window_bits = int(bit.split("=", 1)[1].strip())
                else:
                    client_max_window_bits = self.client_max_window_bits
            elif bit.startswith("server_max_window_bits"):
                if "=" in bit:
                    server_max_window_bits = int(bit.split("=", 1)[1].strip())
                else:
                    server_max_window_bits = self.server_max_window_bits

        return client_max_window_bits, server_max_window_bits

    def accept(self, offer: str) -> bool | None | str:
        client_max_window_bits, server_max_window_bits = self._parse_params(offer)

        parameters = []

        if self.client_no_context_takeover:
            parameters.append("client_no_context_takeover")
        if self.server_no_context_takeover:
            parameters.append("server_no_context_takeover")
        try:
            if client_max_window_bits is not None:
                parameters.append(f"client_max_window_bits={client_max_window_bits}")
                self.client_max_window_bits = client_max_window_bits
            if server_max_window_bits is not None:
                parameters.append(f"server_max_window_bits={server_max_window_bits}")
                self.server_max_window_bits = server_max_window_bits
        except ValueError:
            return None
        else:
            self._enabled = True
            return "; ".join(parameters)

    def frame_inbound_header(
        self,
        proto: FrameDecoder | FrameProtocol,
        opcode: Opcode,
        rsv: RsvBits,
        payload_length: int,
    ) -> CloseReason | RsvBits:
        if self._inbound_error is not None:
            return self._inbound_error
        if rsv.rsv1 and opcode.iscontrol():
            return CloseReason.PROTOCOL_ERROR
        if rsv.rsv1 and opcode is Opcode.CONTINUATION:
            return CloseReason.PROTOCOL_ERROR

        if opcode.iscontrol():
            # Control frames may be interleaved anywhere in a fragmented
            # message, so they must not touch the message/decompressor state.
            self._inbound_is_compressible = False
            return RsvBits(True, False, False)

        self._inbound_is_compressible = self._compressible_opcode(opcode)
        self._inbound_frame_output = 0

        if self._inbound_compressed is None:
            self._inbound_compressed = rsv.rsv1
            if self._inbound_compressed:
                assert self._inbound_is_compressible
                self._inbound_message_output = 0
                if proto.client:
                    bits = self.server_max_window_bits
                else:
                    bits = self.client_max_window_bits
                if self._decompressor is None:
                    self._decompressor = zlib.decompressobj(-int(bits))

        return RsvBits(True, False, False)

    def frame_inbound_payload_data(
        self, proto: FrameDecoder | FrameProtocol, data: bytes,
    ) -> bytes | CloseReason:
        if self._inbound_error is not None:
            return self._inbound_error
        if not self._inbound_compressed or not self._inbound_is_compressible:
            return data
        if self._decompressor is None:
            return self._fail_inbound(CloseReason.INVALID_FRAME_PAYLOAD_DATA)

        output, error = self._decompress_bounded(bytes(data))
        return self._fail_inbound(error) if error is not None else output

    def frame_inbound_complete(
        self, proto: FrameDecoder | FrameProtocol, fin: bool,
    ) -> bytes | CloseReason | None:
        if self._inbound_error is not None:
            return self._inbound_error
        if not self._inbound_is_compressible:
            # This is a control frame. Its FIN bit does not finish the data
            # message it may be interleaved with.
            return None
        if not fin:
            return None
        if not self._inbound_compressed:
            if self._no_context_takeover(proto):
                self._decompressor = None
            self._inbound_compressed = None
            self._inbound_message_output = 0
            self._inbound_frame_output = 0
            return None

        return self._complete_compressed(proto)

    def _complete_compressed(
        self, proto: FrameDecoder | FrameProtocol,
    ) -> bytes | CloseReason:
        if self._decompressor is None:
            return self._fail_inbound(CloseReason.INVALID_FRAME_PAYLOAD_DATA)

        data, error = self._decompress_bounded(b"\x00\x00\xff\xff")
        if error is not None:
            return self._fail_inbound(error)

        if not hasattr(self._decompressor, "eof"):
            # Custom decompressors (notably test doubles) may not expose the
            # zlib end-state attributes. Preserve validation of their
            # flush() error path without using flush() for real zlib streams.
            try:
                self._decompressor.flush()
            except zlib.error:
                return self._fail_inbound(CloseReason.INVALID_FRAME_PAYLOAD_DATA)

        if self._no_context_takeover(proto):
            self._decompressor = None

        self._inbound_compressed = None
        self._inbound_message_output = 0
        self._inbound_frame_output = 0

        return data

    def _no_context_takeover(
        self, proto: FrameDecoder | FrameProtocol,
    ) -> bool:
        if proto.client:
            return self.server_no_context_takeover
        return self.client_no_context_takeover

    def _remaining_inbound_output(self) -> int | None:
        if self.limits is None:
            return None

        remaining: int | None = None
        for limit, used in (
            (self.limits.max_message_size, self._inbound_message_output),
            (self.limits.max_total_size, self._inbound_total_output),
            (self.limits.max_frame_size, self._inbound_frame_output),
        ):
            if limit is not None:
                available = max(limit - used, 0)
                remaining = available if remaining is None else min(remaining, available)
        return remaining

    def _decompress_bounded(
        self, data: bytes,
    ) -> tuple[bytes, CloseReason | None]:
        assert self._decompressor is not None
        remaining = self._remaining_inbound_output()

        try:
            if remaining is None:
                output = self._decompressor.decompress(data)
            else:
                # ``max_length=0`` means unbounded in zlib. Probe with a
                # single byte when the budget is already exhausted so an
                # empty flush remains valid without risking an allocation.
                max_length = remaining if remaining > 0 else 1
                output = self._decompressor.decompress(data, max_length)
                if len(output) > remaining or getattr(
                    self._decompressor, "unconsumed_tail", b"",
                ):
                    self._record_inbound_output(min(len(output), remaining))
                    return b"", CloseReason.MESSAGE_TOO_BIG
        except zlib.error:
            return b"", CloseReason.INVALID_FRAME_PAYLOAD_DATA

        self._record_inbound_output(len(output))

        # A raw DEFLATE stream ending in BFINAL (or carrying bytes after its
        # end marker) is not a valid permessage-deflate payload. Reject it
        # rather than silently dropping the trailing data.
        if hasattr(self._decompressor, "eof") and (
            self._decompressor.eof
            or getattr(self._decompressor, "unused_data", b"")
        ):
            return b"", CloseReason.INVALID_FRAME_PAYLOAD_DATA

        return output, None

    def _record_inbound_output(self, nbytes: int) -> None:
        self._inbound_message_output += nbytes
        self._inbound_frame_output += nbytes
        self._inbound_total_output += nbytes

    def _fail_inbound(self, reason: CloseReason) -> CloseReason:
        # An error is connection-fatal. Drop the dictionary so no later bytes
        # can be decoded using state from the rejected message.
        self._decompressor = None
        self._inbound_compressed = None
        self._inbound_is_compressible = None
        self._inbound_message_output = 0
        self._inbound_frame_output = 0
        self._inbound_error = reason
        return reason

    def frame_outbound(
        self,
        proto: FrameDecoder | FrameProtocol,
        opcode: Opcode,
        rsv: RsvBits,
        data: bytes,
        fin: bool,
    ) -> tuple[RsvBits, bytes]:
        if not self._compressible_opcode(opcode):
            return (rsv, data)

        if opcode is not Opcode.CONTINUATION:
            rsv = RsvBits(True, rsv[1], rsv[2])

        if self._compressor is None:
            assert opcode is not Opcode.CONTINUATION
            if proto.client:
                bits = self.client_max_window_bits
            else:
                bits = self.server_max_window_bits
            self._compressor = zlib.compressobj(
                zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -int(bits),
            )

        data = self._compressor.compress(bytes(data))

        if fin:
            data += self._compressor.flush(zlib.Z_SYNC_FLUSH)
            data = data[:-4]

            if proto.client:
                no_context_takeover = self.client_no_context_takeover
            else:
                no_context_takeover = self.server_no_context_takeover

            if no_context_takeover:
                self._compressor = None

        return (rsv, data)

    def __repr__(self) -> str:
        descr = [f"client_max_window_bits={self.client_max_window_bits}"]
        if self.client_no_context_takeover:
            descr.append("client_no_context_takeover")
        descr.append(f"server_max_window_bits={self.server_max_window_bits}")
        if self.server_no_context_takeover:
            descr.append("server_no_context_takeover")

        return "<{} {}>".format(self.__class__.__name__, "; ".join(descr))


#: SUPPORTED_EXTENSIONS maps all supported extension names to their class.
#: This can be used to iterate all supported extensions of wsproto, instantiate
#: new extensions based on their name, or check if a given extension is
#: supported or not.
SUPPORTED_EXTENSIONS = {PerMessageDeflate.name: PerMessageDeflate}
