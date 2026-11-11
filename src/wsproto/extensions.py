"""
wsproto/extensions
~~~~~~~~~~~~~~~~~~

WebSocket extensions.
"""
from __future__ import annotations

import re
import zlib
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import ClassVar, Optional

from .frame_protocol import CloseReason, FrameDecoder, FrameProtocol, Opcode, RsvBits


class ExtensionParsingError(ValueError):
    """Raised when an extension offer or response cannot be parsed."""


# RFC 7230, Section 3.2.6 - token
_TOKEN_RE = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
# RFC 7692 window bits are a single decimal number without leading zeroes.
_DECIMAL_RE = re.compile(r"(?:0|[1-9][0-9]*)")


class _ValueKind(Enum):
    NONE = "none"
    OPTIONAL = "optional"
    REQUIRED = "required"


@dataclass(frozen=True)
class _ParamSpec:
    value_kind: _ValueKind
    numeric: bool = False
    minimum: int | None = None
    maximum: int | None = None


def _parse_token(value: str) -> str:
    if not value or _TOKEN_RE.fullmatch(value) is None:
        msg = f"Invalid extension token '{value}'"
        raise ExtensionParsingError(msg)
    return value


def _parse_window_bits(name: str, value: str, spec: _ParamSpec) -> int:
    if _DECIMAL_RE.fullmatch(value) is None:
        msg = f"Extension parameter '{name}' must be a decimal integer"
        raise ExtensionParsingError(msg)
    bits = int(value)
    if spec.minimum is not None and bits < spec.minimum:
        msg = f"Extension parameter '{name}' must be at least {spec.minimum}"
        raise ExtensionParsingError(msg)
    if spec.maximum is not None and bits > spec.maximum:
        msg = f"Extension parameter '{name}' must be at most {spec.maximum}"
        raise ExtensionParsingError(msg)
    return bits


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


class PerMessageDeflate(Extension):
    name = "permessage-deflate"

    DEFAULT_CLIENT_MAX_WINDOW_BITS = 15
    DEFAULT_SERVER_MAX_WINDOW_BITS = 15

    # Parameters a client may send in its extension offer, per RFC 7692
    # section 7.1. The window bits may appear without a value, in which case
    # the currently configured value is inherited.
    _OFFER_PARAM_SPECS: ClassVar[dict[str, _ParamSpec]] = {
        "client_no_context_takeover": _ParamSpec(_ValueKind.NONE),
        "server_no_context_takeover": _ParamSpec(_ValueKind.NONE),
        "client_max_window_bits": _ParamSpec(
            _ValueKind.OPTIONAL, numeric=True, minimum=9, maximum=15,
        ),
        "server_max_window_bits": _ParamSpec(
            _ValueKind.OPTIONAL, numeric=True, minimum=9, maximum=15,
        ),
    }

    # Parameters a server may send back in its response. Window bits always
    # carry an explicit value here, so a bare window parameter is invalid.
    _RESPONSE_PARAM_SPECS: ClassVar[dict[str, _ParamSpec]] = {
        "client_no_context_takeover": _ParamSpec(_ValueKind.NONE),
        "server_no_context_takeover": _ParamSpec(_ValueKind.NONE),
        "client_max_window_bits": _ParamSpec(
            _ValueKind.REQUIRED, numeric=True, minimum=9, maximum=15,
        ),
        "server_max_window_bits": _ParamSpec(
            _ValueKind.REQUIRED, numeric=True, minimum=9, maximum=15,
        ),
    }

    def __init__(
        self,
        client_no_context_takeover: bool = False,
        client_max_window_bits: int | None = None,
        server_no_context_takeover: bool = False,
        server_max_window_bits: int | None = None,
    ) -> None:
        self.client_no_context_takeover = client_no_context_takeover
        self.server_no_context_takeover = server_no_context_takeover
        self._client_max_window_bits = self.DEFAULT_CLIENT_MAX_WINDOW_BITS
        self._server_max_window_bits = self.DEFAULT_SERVER_MAX_WINDOW_BITS
        if client_max_window_bits is not None:
            self.client_max_window_bits = client_max_window_bits
        if server_max_window_bits is not None:
            self.server_max_window_bits = server_max_window_bits

        self._compressor: Optional[zlib._Compress] = None  # noqa
        self._decompressor: Optional[zlib._Decompress] = None  # noqa
        # This refers to the current frame
        self._inbound_is_compressible: bool | None = None
        # This refers to the ongoing message (which might span multiple
        # frames). Only the first frame in a fragmented message is flagged for
        # compression, so this carries that bit forward.
        self._inbound_compressed: bool | None = None

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

    @classmethod
    def _parse_extension(
        cls, header_value: str, param_specs: dict[str, _ParamSpec],
    ) -> tuple[str, dict[str, str | None]]:
        """
        Parse an extension header value into a name and ordered parameters.

        The parameters are returned in their on-wire order. Each parameter is
        mapped to its raw string value, or ``None`` for valueless parameters.
        Token casing is normalised to lower case; surrounding OWS is accepted.
        """
        elements = [element.strip() for element in header_value.split(";")]
        if not elements or not elements[0]:
            msg = "Extension header value is missing an extension name"
            raise ExtensionParsingError(msg)

        extension_name = _parse_token(elements[0])
        parameters: dict[str, str | None] = {}
        for element in elements[1:]:
            if not element:
                msg = "Empty extension parameter"
                raise ExtensionParsingError(msg)
            if "=" in element:
                raw_name, raw_value = element.split("=", 1)
                name = _parse_token(raw_name.strip())
                value = _parse_token(raw_value.strip())
            else:
                name = _parse_token(element)
                value = None

            spec = param_specs.get(name.lower())
            if spec is None:
                msg = f"Unknown extension parameter '{name}'"
                raise ExtensionParsingError(msg)
            if name.lower() in parameters:
                msg = f"Duplicate extension parameter '{name}'"
                raise ExtensionParsingError(msg)
            if value is None and spec.value_kind is _ValueKind.REQUIRED:
                msg = f"Extension parameter '{name}' requires a value"
                raise ExtensionParsingError(msg)
            if value is not None and spec.value_kind is _ValueKind.NONE:
                msg = f"Extension parameter '{name}' does not take a value"
                raise ExtensionParsingError(msg)
            if value is not None and spec.numeric:
                _parse_window_bits(name, value, spec)
            parameters[name.lower()] = value

        return extension_name, parameters

    @classmethod
    def validate_offer(cls, offer: str) -> None:
        """Validate a client offer without mutating any extension state."""
        extension_name, _ = cls._parse_extension(offer, cls._OFFER_PARAM_SPECS)
        if extension_name.lower() != cls.name:
            msg = f"Extension name '{extension_name}' is not '{cls.name}'"
            raise ExtensionParsingError(msg)

    def finalize(self, offer: str) -> None:
        extension_name = offer.split(";", 1)[0].strip()
        if extension_name.lower() != self.name:
            # Older versions silently ignored offers for other extensions.
            self._enabled = True
            return

        _, parameters = self._parse_extension(offer, self._RESPONSE_PARAM_SPECS)

        if "client_no_context_takeover" in parameters:
            self.client_no_context_takeover = True
        if "server_no_context_takeover" in parameters:
            self.server_no_context_takeover = True
        if "client_max_window_bits" in parameters:
            value = parameters["client_max_window_bits"]
            assert value is not None
            self.client_max_window_bits = int(value)
        if "server_max_window_bits" in parameters:
            value = parameters["server_max_window_bits"]
            assert value is not None
            self.server_max_window_bits = int(value)

        self._enabled = True

    def accept(self, offer: str) -> bool | None | str:
        extension_name = offer.split(";", 1)[0].strip()
        if extension_name.lower() != self.name:
            # Older versions silently ignored offers for other extensions.
            self._enabled = True
            return ""

        _, parameters = self._parse_extension(offer, self._OFFER_PARAM_SPECS)

        client_no_context_takeover = self.client_no_context_takeover or "client_no_context_takeover" in parameters
        server_no_context_takeover = self.server_no_context_takeover or "server_no_context_takeover" in parameters
        client_max_window_bits = self.client_max_window_bits
        if "client_max_window_bits" in parameters:
            value = parameters["client_max_window_bits"]
            if value is not None:
                client_max_window_bits = int(value)
        server_max_window_bits = self.server_max_window_bits
        if "server_max_window_bits" in parameters:
            value = parameters["server_max_window_bits"]
            if value is not None:
                server_max_window_bits = int(value)

        parameters_to_send: list[str] = []
        if client_no_context_takeover:
            parameters_to_send.append("client_no_context_takeover")
        if server_no_context_takeover:
            parameters_to_send.append("server_no_context_takeover")
        if "client_max_window_bits" in parameters:
            parameters_to_send.append(
                f"client_max_window_bits={client_max_window_bits}",
            )
        if "server_max_window_bits" in parameters:
            parameters_to_send.append(
                f"server_max_window_bits={server_max_window_bits}",
            )

        self.client_no_context_takeover = client_no_context_takeover
        self.server_no_context_takeover = server_no_context_takeover
        self.client_max_window_bits = client_max_window_bits
        self.server_max_window_bits = server_max_window_bits
        self._enabled = True
        return "; ".join(parameters_to_send)

    def frame_inbound_header(
        self,
        proto: FrameDecoder | FrameProtocol,
        opcode: Opcode,
        rsv: RsvBits,
        payload_length: int,
    ) -> CloseReason | RsvBits:
        if rsv.rsv1 and opcode.iscontrol():
            return CloseReason.PROTOCOL_ERROR
        if rsv.rsv1 and opcode is Opcode.CONTINUATION:
            return CloseReason.PROTOCOL_ERROR

        self._inbound_is_compressible = self._compressible_opcode(opcode)

        if self._inbound_compressed is None:
            self._inbound_compressed = rsv.rsv1
            if self._inbound_compressed:
                assert self._inbound_is_compressible
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
        if not self._inbound_compressed or not self._inbound_is_compressible:
            return data
        assert self._decompressor is not None

        try:
            return self._decompressor.decompress(bytes(data))
        except zlib.error:
            return CloseReason.INVALID_FRAME_PAYLOAD_DATA

    def frame_inbound_complete(
        self, proto: FrameDecoder | FrameProtocol, fin: bool,
    ) -> bytes | CloseReason | None:
        if not fin:
            return None
        if not self._inbound_is_compressible:
            self._inbound_compressed = None
            return None
        if not self._inbound_compressed:
            self._inbound_compressed = None
            return None
        assert self._decompressor is not None

        try:
            data = self._decompressor.decompress(b"\x00\x00\xff\xff")
            data += self._decompressor.flush()
        except zlib.error:
            return CloseReason.INVALID_FRAME_PAYLOAD_DATA

        if proto.client:
            no_context_takeover = self.server_no_context_takeover
        else:
            no_context_takeover = self.client_no_context_takeover

        if no_context_takeover:
            self._decompressor = None

        self._inbound_compressed = None

        return data

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
