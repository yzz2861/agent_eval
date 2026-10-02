# Code to read HTTP data
#
# Strategy: each writer takes an event + a write-some-bytes function, which is
# calls.
#
# WRITERS is a dict describing how to pick a reader. It maps states to either:
# - a writer
# - or, for body writers, a dict of framin-dependent writer factories

from typing import Any, Callable, Dict, List, Optional, Tuple, Type, Union

from ._chunk_extensions import ChunkExtensions, render_chunk_extensions
from ._events import Data, EndOfMessage, Event, InformationalResponse, Request, Response
from ._headers import Headers
from ._state import CLIENT, IDLE, SEND_BODY, SEND_RESPONSE, SERVER
from ._util import LocalProtocolError, Sentinel

__all__ = ["WRITERS"]

Writer = Callable[[bytes], Any]


def write_headers(headers: Headers, write: Writer) -> None:
    # "Since the Host field-value is critical information for handling a
    # request, a user agent SHOULD generate Host as the first header field
    # following the request-line." - RFC 7230
    raw_items = headers._full_items
    for raw_name, name, value in raw_items:
        if name == b"host":
            write(b"%s: %s\r\n" % (raw_name, value))
    for raw_name, name, value in raw_items:
        if name != b"host":
            write(b"%s: %s\r\n" % (raw_name, value))
    write(b"\r\n")


def write_request(request: Request, write: Writer) -> None:
    if request.http_version != b"1.1":
        raise LocalProtocolError("I only send HTTP/1.1")
    write(b"%s %s HTTP/1.1\r\n" % (request.method, request.target))
    write_headers(request.headers, write)


# Shared between InformationalResponse and Response
def write_any_response(
    response: Union[InformationalResponse, Response], write: Writer
) -> None:
    if response.http_version != b"1.1":
        raise LocalProtocolError("I only send HTTP/1.1")
    status_bytes = str(response.status_code).encode("ascii")
    # We don't bother sending ascii status messages like "OK"; they're
    # optional and ignored by the protocol. (But the space after the numeric
    # status code is mandatory.)
    #
    # XX FIXME: could at least make an effort to pull out the status message
    # from stdlib's http.HTTPStatus table. Or maybe just steal their enums
    # (either by import or copy/paste). We already accept them as status codes
    # since they're of type IntEnum < int.
    write(b"HTTP/1.1 %s %s\r\n" % (status_bytes, response.reason))
    write_headers(response.headers, write)


class BodyWriter:
    def __call__(self, event: Event, write: Writer) -> None:
        if type(event) is Data:
            self.send_data(
                event.data, write, event.chunk_start, event.chunk_end, event.extensions
            )
        elif type(event) is EndOfMessage:
            self.send_eom(event.headers, write, event.extensions)
        else:  # pragma: no cover
            assert False

    def send_data(
        self,
        data: bytes,
        write: Writer,
        chunk_start: bool = False,
        chunk_end: bool = False,
        extensions: Optional[ChunkExtensions] = None,
    ) -> None:
        pass

    def send_eom(
        self,
        headers: Headers,
        write: Writer,
        extensions: Optional[ChunkExtensions] = None,
    ) -> None:
        pass


#
# These are all careful not to do anything to 'data' except call len(data) and
# write(data). This allows us to transparently pass-through funny objects,
# like placeholder objects referring to files on disk that will be sent via
# sendfile(2).
#
class ContentLengthWriter(BodyWriter):
    def __init__(self, length: int) -> None:
        self._length = length

    def send_data(
        self,
        data: bytes,
        write: Writer,
        chunk_start: bool = False,
        chunk_end: bool = False,
        extensions: Optional[ChunkExtensions] = None,
    ) -> None:
        if extensions:
            raise LocalProtocolError(
                "chunk extensions require chunked transfer encoding"
            )
        self._length -= len(data)
        if self._length < 0:
            raise LocalProtocolError("Too much data for declared Content-Length")
        write(data)

    def send_eom(
        self,
        headers: Headers,
        write: Writer,
        extensions: Optional[ChunkExtensions] = None,
    ) -> None:
        if extensions:
            raise LocalProtocolError(
                "chunk extensions require chunked transfer encoding"
            )
        if self._length != 0:
            raise LocalProtocolError("Too little data for declared Content-Length")
        if headers:
            raise LocalProtocolError("Content-Length and trailers don't mix")


class ChunkedWriter(BodyWriter):
    def __init__(self) -> None:
        self._data: List[bytes] = []
        self._extensions: ChunkExtensions = []

    def _flush(self, write: Writer) -> None:
        write(b"%x" % sum(len(part) for part in self._data))
        write(render_chunk_extensions(self._extensions))
        write(b"\r\n")
        for part in self._data:
            write(part)
        write(b"\r\n")
        self._data = []
        self._extensions = []

    def send_data(
        self,
        data: bytes,
        write: Writer,
        chunk_start: bool = False,
        chunk_end: bool = False,
        extensions: Optional[ChunkExtensions] = None,
    ) -> None:
        extensions = extensions or []
        if self._data:
            if chunk_start:
                raise LocalProtocolError(
                    "cannot start a chunk before ending the previous one"
                )
            if extensions:
                raise LocalProtocolError(
                    "chunk extensions can only be on a chunk start"
                )
            self._data.append(data)
            if chunk_end:
                if sum(len(part) for part in self._data) == 0:
                    raise LocalProtocolError("zero-length chunk marks end of message")
                self._flush(write)
            return

        if chunk_start and chunk_end:
            if not data:
                raise LocalProtocolError("zero-length chunk marks end of message")
            self._data = [data]
            self._extensions = extensions
            self._flush(write)
        elif chunk_start:
            self._data = [data]
            self._extensions = extensions
        elif chunk_end:
            raise LocalProtocolError("chunk end without a chunk start")
        else:
            if not data:
                if extensions:
                    raise LocalProtocolError(
                        "chunk extensions can only be on a chunk start"
                    )
                return
            if extensions:
                self._data = [data]
                self._extensions = extensions
                self._flush(write)
                return
            write(b"%x\r\n" % len(data))
            write(data)
            write(b"\r\n")

    def send_eom(
        self,
        headers: Headers,
        write: Writer,
        extensions: Optional[ChunkExtensions] = None,
    ) -> None:
        if self._data:
            raise LocalProtocolError("EndOfMessage before chunk end")
        write(b"0" + render_chunk_extensions(extensions or []) + b"\r\n")
        write_headers(headers, write)


class Http10Writer(BodyWriter):
    def send_data(
        self,
        data: bytes,
        write: Writer,
        chunk_start: bool = False,
        chunk_end: bool = False,
        extensions: Optional[ChunkExtensions] = None,
    ) -> None:
        if extensions:
            raise LocalProtocolError(
                "chunk extensions require chunked transfer encoding"
            )
        write(data)

    def send_eom(
        self,
        headers: Headers,
        write: Writer,
        extensions: Optional[ChunkExtensions] = None,
    ) -> None:
        if extensions:
            raise LocalProtocolError(
                "chunk extensions require chunked transfer encoding"
            )
        if headers:
            raise LocalProtocolError("can't send trailers to HTTP/1.0 client")
        # no need to close the socket ourselves, that will be taken care of by
        # Connection: close machinery


WritersType = Dict[
    Union[Tuple[Type[Sentinel], Type[Sentinel]], Type[Sentinel]],
    Union[
        Dict[str, Type[BodyWriter]],
        Callable[[Union[InformationalResponse, Response], Writer], None],
        Callable[[Request, Writer], None],
    ],
]

WRITERS: WritersType = {
    (CLIENT, IDLE): write_request,
    (SERVER, IDLE): write_any_response,
    (SERVER, SEND_RESPONSE): write_any_response,
    SEND_BODY: {
        "chunked": ChunkedWriter,
        "content-length": ContentLengthWriter,
        "http/1.0": Http10Writer,
    },
}
