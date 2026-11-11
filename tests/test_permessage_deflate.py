from __future__ import annotations

import gzip
import struct
import zlib
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any, Optional, cast

import pytest

from wsproto import extensions as wpext
from wsproto import frame_protocol as fp

if TYPE_CHECKING:
    from typing import TypedDict

    class Params(TypedDict, total=False):
        client_no_context_takeover: bool
        client_max_window_bits: Optional[int]
        server_no_context_takeover: bool
        server_max_window_bits: Optional[int]

else:
    Params = dict


def compress_message(data: bytes, compressor: Any = None) -> bytes:
    compressor = compressor or zlib.compressobj(
        zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -15,
    )
    compressed = compressor.compress(data)
    compressed += compressor.flush(zlib.Z_SYNC_FLUSH)
    return compressed[:-4]


def make_frame(
    opcode: fp.Opcode, payload: bytes, *, fin: bool = True, rsv1: bool = False,
) -> bytes:
    first = int(opcode)
    if fin:
        first |= fp.FIN_MASK
    if rsv1:
        first |= fp.RSV1_MASK

    length = len(payload)
    if length <= fp.MAX_PAYLOAD_NORMAL:
        header = bytes((first, length))
    elif length <= fp.MAX_PAYLOAD_TWO_BYTE:
        header = bytes((first, fp.PAYLOAD_LENGTH_TWO_BYTE)) + struct.pack(
            "!H", length,
        )
    else:
        header = bytes((first, fp.PAYLOAD_LENGTH_EIGHT_BYTE)) + struct.pack(
            "!Q", length,
        )
    return header + payload


def split_for_output(compressed: bytes, output_size: int) -> int:
    """Find a prefix of compressed data that produces roughly output_size."""
    for end in range(1, len(compressed) + 1):
        decompressor = zlib.decompressobj(-15)
        try:
            output = decompressor.decompress(compressed[:end])
        except zlib.error:
            continue
        if len(output) >= output_size:
            return end
    return len(compressed)


class TestPerMessageDeflate:
    parameter_sets: Sequence[Params] = [
        {
            "client_no_context_takeover": False,
            "client_max_window_bits": 15,
            "server_no_context_takeover": False,
            "server_max_window_bits": 15,
        },
        {
            "client_no_context_takeover": True,
            "client_max_window_bits": 9,
            "server_no_context_takeover": False,
            "server_max_window_bits": 15,
        },
        {
            "client_no_context_takeover": False,
            "client_max_window_bits": 15,
            "server_no_context_takeover": True,
            "server_max_window_bits": 9,
        },
        {
            "client_no_context_takeover": True,
            "client_max_window_bits": 9,
            "server_no_context_takeover": True,
            "server_max_window_bits": 9,
        },
        {"client_no_context_takeover": True, "server_max_window_bits": 9},
        {"server_no_context_takeover": True, "client_max_window_bits": 9},
        {"client_max_window_bits": None, "server_max_window_bits": None},
        {},
    ]

    def make_offer_string(self, params: Params) -> str:
        offer = ["permessage-deflate"]

        if "client_max_window_bits" in params:
            if params["client_max_window_bits"] is None:
                offer.append("client_max_window_bits")
            else:
                offer.append(
                    "client_max_window_bits=%d" % params["client_max_window_bits"],
                )
        if "server_max_window_bits" in params:
            if params["server_max_window_bits"] is None:
                offer.append("server_max_window_bits")
            else:
                offer.append(
                    "server_max_window_bits=%d" % params["server_max_window_bits"],
                )
        if params.get("client_no_context_takeover", False):
            offer.append("client_no_context_takeover")
        if params.get("server_no_context_takeover", False):
            offer.append("server_no_context_takeover")

        return "; ".join(offer)

    def compare_params_to_string(
        self, params: Params, ext: wpext.PerMessageDeflate, param_string: str,
    ) -> None:
        if "client_max_window_bits" in params:
            if params["client_max_window_bits"] is None:
                bits = ext.client_max_window_bits
            else:
                bits = params["client_max_window_bits"]
            assert "client_max_window_bits=%d" % bits in param_string
        if "server_max_window_bits" in params:
            if params["server_max_window_bits"] is None:
                bits = ext.server_max_window_bits
            else:
                bits = params["server_max_window_bits"]
            assert "server_max_window_bits=%d" % bits in param_string
        if params.get("client_no_context_takeover", False):
            assert "client_no_context_takeover" in param_string
        if params.get("server_no_context_takeover", False):
            assert "server_no_context_takeover" in param_string

    @pytest.mark.parametrize("params", parameter_sets)
    def test_offer(self, params: Params) -> None:
        ext = wpext.PerMessageDeflate(**params)
        offer = ext.offer()
        offer = cast("str", offer)

        self.compare_params_to_string(params, ext, offer)

    @pytest.mark.parametrize("params", parameter_sets)
    def test_finalize(self, params: Params) -> None:
        ext = wpext.PerMessageDeflate()
        assert not ext.enabled()

        if "client_max_window_bits" in params:
            if params["client_max_window_bits"] is None:
                del params["client_max_window_bits"]
        if "server_max_window_bits" in params:
            if params["server_max_window_bits"] is None:
                del params["server_max_window_bits"]
        offer = self.make_offer_string(params)
        ext.finalize(offer)

        if params.get("client_max_window_bits", None):
            assert ext.client_max_window_bits == params["client_max_window_bits"]
        if params.get("server_max_window_bits", None):
            assert ext.server_max_window_bits == params["server_max_window_bits"]
        assert ext.client_no_context_takeover is params.get(
            "client_no_context_takeover", False,
        )
        assert ext.server_no_context_takeover is params.get(
            "server_no_context_takeover", False,
        )

        assert ext.enabled()

    def test_finalize_ignores_rubbish(self) -> None:
        ext = wpext.PerMessageDeflate()
        assert not ext.enabled()

        ext.finalize("i am the lizard queen; worship me")

        assert ext.enabled()

    @pytest.mark.parametrize("params", parameter_sets)
    def test_accept(self, params: Params) -> None:
        ext = wpext.PerMessageDeflate()
        assert not ext.enabled()

        offer = self.make_offer_string(params)
        response = ext.accept(offer)
        response = cast("str", response)

        if ext.client_no_context_takeover:
            assert "client_no_context_takeover" in response
        if ext.server_no_context_takeover:
            assert "server_no_context_takeover" in response
        if "client_max_window_bits" in params:
            if params["client_max_window_bits"] is None:
                bits = ext.client_max_window_bits
            else:
                bits = params["client_max_window_bits"]
            assert ext.client_max_window_bits == bits
            assert "client_max_window_bits=%d" % bits in response
        if "server_max_window_bits" in params:
            if params["server_max_window_bits"] is None:
                bits = ext.server_max_window_bits
            else:
                bits = params["server_max_window_bits"]
            assert ext.server_max_window_bits == bits
            assert "server_max_window_bits=%d" % bits in response

    def test_accept_ignores_rubbish(self) -> None:
        ext = wpext.PerMessageDeflate()
        assert not ext.enabled()

        ext.accept("i am the lizard queen; worship me")

        assert ext.enabled()

    def test_inbound_uncompressed_control_frame(self) -> None:
        payload = b"x" * 23

        ext = wpext.PerMessageDeflate()
        ext._enabled = True
        proto = fp.FrameProtocol(client=True, extensions=[ext])

        result = ext.frame_inbound_header(
            proto, fp.Opcode.PING, fp.RsvBits(False, False, False), len(payload),
        )
        assert isinstance(result, fp.RsvBits)
        assert result.rsv1

        data = ext.frame_inbound_payload_data(proto, payload)
        assert data == payload

        assert ext.frame_inbound_complete(proto, True) is None

    def test_inbound_compressed_control_frame(self) -> None:
        payload = b"x" * 23

        ext = wpext.PerMessageDeflate()
        ext._enabled = True
        proto = fp.FrameProtocol(client=True, extensions=[ext])

        result = ext.frame_inbound_header(
            proto, fp.Opcode.PING, fp.RsvBits(True, False, False), len(payload),
        )
        assert result == fp.CloseReason.PROTOCOL_ERROR

    def test_inbound_compressed_continuation_frame(self) -> None:
        payload = b"x" * 23

        ext = wpext.PerMessageDeflate()
        ext._enabled = True
        proto = fp.FrameProtocol(client=True, extensions=[ext])

        result = ext.frame_inbound_header(
            proto, fp.Opcode.CONTINUATION, fp.RsvBits(True, False, False), len(payload),
        )
        assert result == fp.CloseReason.PROTOCOL_ERROR

    def test_inbound_uncompressed_data_frame(self) -> None:
        payload = b"x" * 23

        ext = wpext.PerMessageDeflate()
        ext._enabled = True
        proto = fp.FrameProtocol(client=True, extensions=[ext])

        result = ext.frame_inbound_header(
            proto, fp.Opcode.BINARY, fp.RsvBits(False, False, False), len(payload),
        )
        assert isinstance(result, fp.RsvBits)
        assert result.rsv1

        data = ext.frame_inbound_payload_data(proto, payload)
        assert data == payload

        assert ext.frame_inbound_complete(proto, True) is None

    @pytest.mark.parametrize("client", [True, False])
    def test_client_inbound_compressed_single_data_frame(self, client: bool) -> None:
        payload = b"x" * 23
        compressed_payload = b"\xaa\xa8\xc0\n\x00\x00"

        ext = wpext.PerMessageDeflate()
        ext._enabled = True
        proto = fp.FrameProtocol(client=client, extensions=[ext])

        result = ext.frame_inbound_header(
            proto,
            fp.Opcode.BINARY,
            fp.RsvBits(True, False, False),
            len(compressed_payload),
        )
        assert isinstance(result, fp.RsvBits)
        assert result.rsv1

        data = ext.frame_inbound_payload_data(proto, compressed_payload)
        assert isinstance(data, bytes)
        data2 = ext.frame_inbound_complete(proto, True)
        assert isinstance(data2, bytes)
        assert data + data2 == payload

    @pytest.mark.parametrize("client", [True, False])
    def test_client_inbound_compressed_multiple_data_frames(self, client: bool) -> None:
        payload = b"x" * 23
        compressed_payload = b"\xaa\xa8\xc0\n\x00\x00"
        split = 3
        data = b""

        ext = wpext.PerMessageDeflate()
        ext._enabled = True
        proto = fp.FrameProtocol(client=client, extensions=[ext])

        result = ext.frame_inbound_header(
            proto, fp.Opcode.BINARY, fp.RsvBits(True, False, False), split,
        )
        assert isinstance(result, fp.RsvBits)
        assert result.rsv1
        result2 = ext.frame_inbound_payload_data(proto, compressed_payload[:split])
        assert not isinstance(result2, fp.CloseReason)
        data += result2
        assert ext.frame_inbound_complete(proto, False) is None

        result3 = ext.frame_inbound_header(
            proto,
            fp.Opcode.CONTINUATION,
            fp.RsvBits(False, False, False),
            len(compressed_payload) - split,
        )
        assert isinstance(result3, fp.RsvBits)
        assert result3.rsv1
        result4 = ext.frame_inbound_payload_data(proto, compressed_payload[split:])
        assert not isinstance(result4, fp.CloseReason)
        data += result4

        result5 = ext.frame_inbound_complete(proto, True)
        assert isinstance(result5, bytes)
        data += result5

        assert data == payload

    @pytest.mark.parametrize("client", [True, False])
    def test_client_decompress_after_uncompressible_frame(self, client: bool) -> None:
        ext = wpext.PerMessageDeflate()
        ext._enabled = True
        proto = fp.FrameProtocol(client=client, extensions=[ext])

        # A PING frame
        ext.frame_inbound_header(
            proto, fp.Opcode.PING, fp.RsvBits(False, False, False), 0,
        )
        result2 = ext.frame_inbound_payload_data(proto, b"")
        assert not isinstance(result2, fp.CloseReason)
        assert ext.frame_inbound_complete(proto, True) is None

        # A compressed TEXT frame
        payload = b"x" * 23
        compressed_payload = b"\xaa\xa8\xc0\n\x00\x00"

        result3 = ext.frame_inbound_header(
            proto,
            fp.Opcode.TEXT,
            fp.RsvBits(True, False, False),
            len(compressed_payload),
        )
        assert isinstance(result3, fp.RsvBits)
        assert result3.rsv1
        result4 = ext.frame_inbound_payload_data(proto, compressed_payload)
        assert result4 == payload

        result5 = ext.frame_inbound_complete(proto, True)
        assert not isinstance(result5, fp.CloseReason)

    def test_inbound_bad_zlib_payload(self) -> None:
        compressed_payload = b"x" * 23

        ext = wpext.PerMessageDeflate()
        ext._enabled = True
        proto = fp.FrameProtocol(client=True, extensions=[ext])

        result = ext.frame_inbound_header(
            proto,
            fp.Opcode.BINARY,
            fp.RsvBits(True, False, False),
            len(compressed_payload),
        )
        assert isinstance(result, fp.RsvBits)
        assert result.rsv1
        result2 = ext.frame_inbound_payload_data(proto, compressed_payload)
        assert result2 is fp.CloseReason.INVALID_FRAME_PAYLOAD_DATA

    def test_inbound_bad_zlib_decoder_end_state(self) -> None:
        compressed_payload = b"x" * 23

        ext = wpext.PerMessageDeflate()
        ext._enabled = True
        proto = fp.FrameProtocol(client=True, extensions=[ext])

        result = ext.frame_inbound_header(
            proto,
            fp.Opcode.BINARY,
            fp.RsvBits(True, False, False),
            len(compressed_payload),
        )
        assert isinstance(result, fp.RsvBits)
        assert result.rsv1

        class FailDecompressor:
            def decompress(self, data: bytes) -> bytes:
                return b""

            def flush(self) -> None:
                raise zlib.error()

        ext._decompressor = cast("zlib._Decompress", FailDecompressor())
        result2 = ext.frame_inbound_complete(proto, True)

        assert result2 is fp.CloseReason.INVALID_FRAME_PAYLOAD_DATA

    @pytest.mark.parametrize(
        "client,no_context_takeover",
        [(True, True), (True, False), (False, True), (False, False)],
    )
    def test_decompressor_reset(self, client: bool, no_context_takeover: bool) -> None:
        if client:
            args = {"server_no_context_takeover": no_context_takeover}
        else:
            args = {"client_no_context_takeover": no_context_takeover}
        ext = wpext.PerMessageDeflate(**args)
        ext._enabled = True
        proto = fp.FrameProtocol(client=client, extensions=[ext])

        result = ext.frame_inbound_header(
            proto, fp.Opcode.BINARY, fp.RsvBits(True, False, False), 0,
        )
        assert isinstance(result, fp.RsvBits)
        assert result.rsv1

        assert ext._decompressor is not None

        result2 = ext.frame_inbound_complete(proto, True)
        assert not isinstance(result2, fp.CloseReason)

        if no_context_takeover:
            assert ext._decompressor is None
        else:
            assert ext._decompressor is not None

        result3 = ext.frame_inbound_header(
            proto, fp.Opcode.BINARY, fp.RsvBits(True, False, False), 0,
        )
        assert isinstance(result3, fp.RsvBits)
        assert result3.rsv1

        assert ext._decompressor is not None

    def test_outbound_uncompressible_opcode(self) -> None:
        ext = wpext.PerMessageDeflate()
        ext._enabled = True
        proto = fp.FrameProtocol(client=True, extensions=[ext])

        rsv = fp.RsvBits(False, False, False)
        payload = b"x" * 23

        rsv, data = ext.frame_outbound(proto, fp.Opcode.PING, rsv, payload, True)

        assert rsv.rsv1 is False
        assert data == payload

    @pytest.mark.parametrize("client", [True, False])
    def test_outbound_compress_single_frame(self, client: bool) -> None:
        ext = wpext.PerMessageDeflate()
        ext._enabled = True
        proto = fp.FrameProtocol(client=client, extensions=[ext])

        rsv = fp.RsvBits(False, False, False)
        payload = b"x" * 23
        compressed_payload = b"\xaa\xa8\xc0\n\x00\x00"

        rsv, data = ext.frame_outbound(proto, fp.Opcode.BINARY, rsv, payload, True)

        assert rsv.rsv1 is True
        assert data == compressed_payload

    @pytest.mark.parametrize("client", [True, False])
    def test_outbound_compress_multiple_frames(self, client: bool) -> None:
        ext = wpext.PerMessageDeflate()
        ext._enabled = True
        proto = fp.FrameProtocol(client=client, extensions=[ext])

        rsv = fp.RsvBits(False, False, False)
        payload = b"x" * 23
        split = 12
        compressed_payload = b"\xaa\xa8\xc0\n\x00\x00"

        rsv, data = ext.frame_outbound(
            proto, fp.Opcode.BINARY, rsv, payload[:split], False,
        )
        assert rsv.rsv1 is True

        rsv = fp.RsvBits(False, False, False)
        rsv, more_data = ext.frame_outbound(
            proto, fp.Opcode.CONTINUATION, rsv, payload[split:], True,
        )
        assert rsv.rsv1 is False
        assert data + more_data == compressed_payload

    @pytest.mark.parametrize(
        "client,no_context_takeover",
        [(True, True), (True, False), (False, True), (False, False)],
    )
    def test_compressor_reset(self, client: bool, no_context_takeover: bool) -> None:
        if client:
            args = {"client_no_context_takeover": no_context_takeover}
        else:
            args = {"server_no_context_takeover": no_context_takeover}
        ext = wpext.PerMessageDeflate(**args)
        ext._enabled = True
        proto = fp.FrameProtocol(client=client, extensions=[ext])
        rsv = fp.RsvBits(False, False, False)

        rsv, data = ext.frame_outbound(proto, fp.Opcode.BINARY, rsv, b"", False)
        assert rsv.rsv1 is True
        assert ext._compressor is not None

        rsv = fp.RsvBits(False, False, False)
        rsv, data = ext.frame_outbound(proto, fp.Opcode.CONTINUATION, rsv, b"", True)
        assert rsv.rsv1 is False
        if no_context_takeover:
            assert ext._compressor is None
        else:
            assert ext._compressor is not None

        rsv = fp.RsvBits(False, False, False)
        rsv, data = ext.frame_outbound(proto, fp.Opcode.BINARY, rsv, b"", False)
        assert rsv.rsv1 is True
        assert ext._compressor is not None

    @pytest.mark.parametrize("params", parameter_sets)
    def test_repr(self, params: Params) -> None:
        ext = wpext.PerMessageDeflate(**params)
        self.compare_params_to_string(params, ext, repr(ext))


class TestPerMessageDeflateInboundLimits:
    def make_extension(
        self,
        client: bool = True,
        **kwargs: object,
    ) -> tuple[wpext.PerMessageDeflate, fp.FrameProtocol]:
        ext = wpext.PerMessageDeflate(**kwargs)  # type: ignore[arg-type]
        ext._enabled = True
        return ext, fp.FrameProtocol(client=client, extensions=[ext])

    def decode_single(
        self,
        ext: wpext.PerMessageDeflate,
        proto: fp.FrameProtocol,
        compressed: bytes,
        opcode: fp.Opcode = fp.Opcode.BINARY,
    ) -> bytes | fp.CloseReason:
        header = ext.frame_inbound_header(
            proto, opcode, fp.RsvBits(True, False, False), len(compressed),
        )
        assert isinstance(header, fp.RsvBits)
        result = ext.frame_inbound_payload_data(proto, compressed)
        if isinstance(result, fp.CloseReason):
            return result

        completed = ext.frame_inbound_complete(proto, True)
        if isinstance(completed, fp.CloseReason):
            return completed
        return result + (completed or b"")

    def test_default_is_unlimited(self) -> None:
        ext, proto = self.make_extension()
        assert ext.limits is None

        payload = b"x" * 1_000_000
        result = self.decode_single(ext, proto, compress_message(payload))
        assert result == payload

    def test_single_frame_bomb_stops_at_message_limit(self) -> None:
        ext, proto = self.make_extension(max_message_size=1024)
        compressed = compress_message(b"x" * 1_000_000)
        assert len(compressed) < 1024

        result = self.decode_single(ext, proto, compressed)
        assert result is fp.CloseReason.MESSAGE_TOO_BIG
        assert ext._inbound_total_output == 1024
        assert ext._decompressor is None

        # Bytes from the rejected frame must not be decoded as a new message.
        assert ext.frame_inbound_payload_data(proto, b"remaining") is (
            fp.CloseReason.MESSAGE_TOO_BIG
        )

    def test_single_frame_bomb_stops_at_frame_limit(self) -> None:
        ext, proto = self.make_extension(max_frame_size=4096)
        compressed = compress_message(b"x" * 1_000_000)

        result = self.decode_single(ext, proto, compressed)
        assert result is fp.CloseReason.MESSAGE_TOO_BIG
        assert ext._inbound_total_output == 4096
        assert ext._decompressor is None

    def test_message_budget_accumulates_across_continuations(self) -> None:
        ext, proto = self.make_extension(max_message_size=8192)
        payload = b"x" * 100_000
        compressed = compress_message(payload)
        split = split_for_output(compressed, 5000)
        first = compressed[:split]
        second = compressed[split:]

        header = ext.frame_inbound_header(
            proto, fp.Opcode.BINARY, fp.RsvBits(True, False, False), len(first),
        )
        assert isinstance(header, fp.RsvBits)
        first_output = ext.frame_inbound_payload_data(proto, first)
        assert isinstance(first_output, bytes)
        assert ext.frame_inbound_complete(proto, False) is None
        assert ext._inbound_message_output == len(first_output)

        # A control frame in the middle must not reset the message budget.
        assert isinstance(
            ext.frame_inbound_header(
                proto, fp.Opcode.PING, fp.RsvBits(False, False, False), 4,
            ),
            fp.RsvBits,
        )
        assert ext.frame_inbound_payload_data(proto, b"ping") == b"ping"
        assert ext.frame_inbound_complete(proto, True) is None
        assert ext._inbound_message_output == len(first_output)
        assert ext._decompressor is not None

        assert isinstance(
            ext.frame_inbound_header(
                proto,
                fp.Opcode.CONTINUATION,
                fp.RsvBits(False, False, False),
                len(second),
            ),
            fp.RsvBits,
        )
        result = ext.frame_inbound_payload_data(proto, second)
        assert result is fp.CloseReason.MESSAGE_TOO_BIG
        assert ext._inbound_total_output == 8192
        assert ext._decompressor is None

    def test_frame_budget_resets_for_each_frame(self) -> None:
        ext, proto = self.make_extension(max_frame_size=4096)
        payload = b"x" * 100_000
        compressed = compress_message(payload)
        split = split_for_output(compressed, 3000)
        first = compressed[:split]
        second = compressed[split:]

        assert isinstance(
            ext.frame_inbound_header(
                proto, fp.Opcode.BINARY, fp.RsvBits(True, False, False), len(first),
            ),
            fp.RsvBits,
        )
        first_output = ext.frame_inbound_payload_data(proto, first)
        assert isinstance(first_output, bytes)
        assert ext.frame_inbound_complete(proto, False) is None

        assert isinstance(
            ext.frame_inbound_header(
                proto,
                fp.Opcode.CONTINUATION,
                fp.RsvBits(False, False, False),
                len(second),
            ),
            fp.RsvBits,
        )
        result = ext.frame_inbound_payload_data(proto, second)
        assert result is fp.CloseReason.MESSAGE_TOO_BIG
        assert ext._decompressor is None

    def test_total_budget_accumulates_across_messages_and_controls(self) -> None:
        ext, proto = self.make_extension(max_total_size=5000)
        first = compress_message(b"x" * 3000)
        assert self.decode_single(ext, proto, first) == b"x" * 3000
        assert ext._inbound_total_output == 3000

        assert isinstance(
            ext.frame_inbound_header(
                proto, fp.Opcode.PING, fp.RsvBits(False, False, False), 4,
            ),
            fp.RsvBits,
        )
        assert ext.frame_inbound_payload_data(proto, b"ping") == b"ping"
        assert ext.frame_inbound_complete(proto, True) is None
        assert ext._inbound_total_output == 3000

        second = compress_message(b"x" * 3000)
        result = self.decode_single(ext, proto, second)
        assert result is fp.CloseReason.MESSAGE_TOO_BIG
        assert ext._inbound_total_output == 5000
        assert ext._decompressor is None

    def test_empty_compressed_message_with_zero_budgets(self) -> None:
        ext, proto = self.make_extension(
            max_message_size=0, max_total_size=0, max_frame_size=0,
        )
        assert isinstance(
            ext.frame_inbound_header(
                proto, fp.Opcode.BINARY, fp.RsvBits(True, False, False), 0,
            ),
            fp.RsvBits,
        )
        assert ext.frame_inbound_payload_data(proto, b"") == b""
        assert ext.frame_inbound_complete(proto, True) == b""
        assert ext._inbound_error is None

    @pytest.mark.parametrize(
        "no_context_takeover",
        [True, False],
    )
    def test_context_reuse_and_takeover_with_limits(
        self, no_context_takeover: bool,
    ) -> None:
        ext, proto = self.make_extension(
            server_no_context_takeover=no_context_takeover,
            max_message_size=10_000,
        )
        compressor = None
        if not no_context_takeover:
            compressor = zlib.compressobj(
                zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -15,
            )
        first = compress_message(b"first" * 500, compressor)
        second = compress_message(
            b"second" * 500,
            compressor if compressor is not None else zlib.compressobj(
                zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -15,
            ),
        )

        assert self.decode_single(ext, proto, first) == b"first" * 500
        if no_context_takeover:
            assert ext._decompressor is None
        else:
            assert ext._decompressor is not None

        # Whether the receiver reuses the dictionary or starts fresh for each
        # message, both messages must decode successfully with the budget.
        assert self.decode_single(ext, proto, second) == b"second" * 500

    def test_no_context_takeover_waits_for_message_end(self) -> None:
        ext, proto = self.make_extension(server_no_context_takeover=True)
        compressed = compress_message(b"x" * 100)
        split = split_for_output(compressed, 50)

        assert isinstance(
            ext.frame_inbound_header(
                proto,
                fp.Opcode.BINARY,
                fp.RsvBits(True, False, False),
                split,
            ),
            fp.RsvBits,
        )
        output = ext.frame_inbound_payload_data(proto, compressed[:split])
        assert isinstance(output, bytes)
        assert ext.frame_inbound_complete(proto, False) is None
        assert ext._decompressor is not None

        assert isinstance(
            ext.frame_inbound_header(
                proto,
                fp.Opcode.CONTINUATION,
                fp.RsvBits(False, False, False),
                len(compressed) - split,
            ),
            fp.RsvBits,
        )
        more_output = ext.frame_inbound_payload_data(proto, compressed[split:])
        assert isinstance(more_output, bytes)
        output += more_output
        assert ext.frame_inbound_complete(proto, True) == b""
        assert ext._decompressor is None

    @pytest.mark.parametrize(
        "bad_payload",
        [
            b"not a deflate stream",
            zlib.compress(b"x" * 1000),
            gzip.compress(b"x" * 1000),
            compress_message(b"x" * 1000) + gzip.compress(b"trailing"),
        ],
    )
    def test_invalid_or_trailing_stream_is_rejected(self, bad_payload: bytes) -> None:
        ext, proto = self.make_extension(max_message_size=4096)

        result = self.decode_single(ext, proto, bad_payload)
        assert result is fp.CloseReason.INVALID_FRAME_PAYLOAD_DATA
        assert ext._decompressor is None
        assert ext.frame_inbound_payload_data(proto, bad_payload) is (
            fp.CloseReason.INVALID_FRAME_PAYLOAD_DATA
        )

    def test_raw_finished_deflate_stream_is_rejected(self) -> None:
        compressor = zlib.compressobj(
            zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -15,
        )
        bad_payload = compressor.compress(b"x" * 1000)
        bad_payload += compressor.flush(zlib.Z_FINISH)
        bad_payload += b"trailing"

        ext, proto = self.make_extension(max_message_size=4096)
        assert self.decode_single(ext, proto, bad_payload) is (
            fp.CloseReason.INVALID_FRAME_PAYLOAD_DATA
        )
        assert ext._decompressor is None

    def test_frame_protocol_budget_error_is_sticky(self) -> None:
        _ext, proto = self.make_extension(max_message_size=1024)
        compressed = compress_message(b"x" * 1_000_000)
        bomb_frame = make_frame(fp.Opcode.BINARY, compressed, rsv1=True)

        proto.receive_bytes(bomb_frame)
        with pytest.raises(fp.ParseFailed) as excinfo:
            list(proto.received_frames())
        assert excinfo.value.code is fp.CloseReason.MESSAGE_TOO_BIG

        # Re-feeding must repeat the close reason rather than exposing the
        # next frame as a brand new message using a polluted decompressor.
        proto.receive_bytes(
            make_frame(fp.Opcode.BINARY, compress_message(b"ok"), rsv1=True),
        )
        with pytest.raises(fp.ParseFailed) as excinfo:
            list(proto.received_frames())
        assert excinfo.value.code is fp.CloseReason.MESSAGE_TOO_BIG

    def test_frame_protocol_control_interleaving_keeps_budget(self) -> None:
        _ext, proto = self.make_extension(max_message_size=8192)
        payload = b"x" * 100_000
        compressed = compress_message(payload)
        split = split_for_output(compressed, 5000)

        proto.receive_bytes(
            make_frame(fp.Opcode.BINARY, compressed[:split], fin=False, rsv1=True),
        )
        proto.receive_bytes(make_frame(fp.Opcode.PING, b"ping"))
        proto.receive_bytes(
            make_frame(fp.Opcode.CONTINUATION, compressed[split:]),
        )

        with pytest.raises(fp.ParseFailed) as excinfo:
            list(proto.received_frames())
        assert excinfo.value.code is fp.CloseReason.MESSAGE_TOO_BIG

    def test_frame_protocol_control_interleaving_under_budget(self) -> None:
        _ext, proto = self.make_extension(max_message_size=20_000)
        payload = b"x" * 10_000
        compressed = compress_message(payload)
        split = split_for_output(compressed, 5000)

        proto.receive_bytes(
            make_frame(fp.Opcode.BINARY, compressed[:split], fin=False, rsv1=True),
        )
        proto.receive_bytes(make_frame(fp.Opcode.PING, b"ping"))
        proto.receive_bytes(
            make_frame(fp.Opcode.CONTINUATION, compressed[split:]),
        )

        frames = list(proto.received_frames())
        assert [frame.opcode for frame in frames] == [
            fp.Opcode.BINARY,
            fp.Opcode.PING,
            fp.Opcode.BINARY,
        ]
        data = bytearray()
        for frame in frames:
            if not frame.opcode.iscontrol():
                assert isinstance(frame.payload, bytes)
                data += frame.payload
        assert bytes(data) == payload
