"""
Loopback test servers for the proxy chain tests.

These servers use plain threads and blocking sockets, so that they can be
shared by both the synchronous and asynchronous test suites.
"""

import base64
import socket
import ssl
import threading
import time
import typing
from pathlib import Path

CERTS_DIR = Path(__file__).parent / "certs"
CA_CERT = CERTS_DIR / "ca.crt"
SERVER_CERT = CERTS_DIR / "server.crt"
SERVER_KEY = CERTS_DIR / "server.key"
ROGUE_CERT = CERTS_DIR / "rogue.crt"
ROGUE_KEY = CERTS_DIR / "rogue.key"


def client_ssl_context(cafile: Path = CA_CERT) -> ssl.SSLContext:
    """
    An SSL context for client connections, verifying against the test CA.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=str(cafile))
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    return context


def server_ssl_context(
    certfile: Path = SERVER_CERT, keyfile: Path = SERVER_KEY
) -> ssl.SSLContext:
    """
    An SSL context for server connections, using the test certificates.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(certfile), keyfile=str(keyfile))
    return context


def wait_for(condition: typing.Callable[[], bool], timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.01)
    return condition()


class RecordedRequest(typing.NamedTuple):
    method: bytes
    target: bytes
    headers: typing.List[typing.Tuple[bytes, bytes]]

    def header(self, name: bytes) -> typing.Optional[bytes]:
        for key, value in self.headers:
            if key == name:
                return value
        return None


def read_head(
    conn: socket.socket, buffer: bytes = b""
) -> typing.Tuple[bytes, bytes]:
    while b"\r\n\r\n" not in buffer:
        chunk = conn.recv(65536)
        if not chunk:
            raise ConnectionError("Connection closed by peer.")
        buffer += chunk
    head, _, rest = buffer.partition(b"\r\n\r\n")
    return head, rest


def parse_request(head: bytes) -> RecordedRequest:
    lines = head.split(b"\r\n")
    method, target, _ = lines[0].split(b" ", 2)
    headers = []
    for line in lines[1:]:
        name, _, value = line.partition(b":")
        headers.append((name.strip().lower(), value.strip()))
    return RecordedRequest(method=method, target=target, headers=headers)


class LoopbackServer:
    def __init__(self) -> None:
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen()
        self._listener.settimeout(0.1)
        self.port = self._listener.getsockname()[1]
        self._closing = False
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def _accept_loop(self) -> None:
        while not self._closing:
            try:
                conn, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            thread = threading.Thread(target=self._handle, args=(conn,), daemon=True)
            thread.start()

    def _handle(self, conn: socket.socket) -> None:
        raise NotImplementedError  # pragma: nocover

    def close(self) -> None:
        self._closing = True
        self._listener.close()
        self._thread.join(timeout=5.0)

    def __enter__(self) -> "LoopbackServer":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


class ProxyServer(LoopbackServer):
    """
    A minimal HTTP CONNECT proxy server.

    If "auth" is given then any CONNECT request must include a matching
    "Proxy-Authorization" header, or a 407 response is returned.
    """

    def __init__(
        self,
        ssl_context: typing.Optional[ssl.SSLContext] = None,
        auth: typing.Optional[typing.Tuple[str, str]] = None,
    ) -> None:
        self._ssl_context = ssl_context
        self._auth = auth
        self.requests: typing.List[RecordedRequest] = []
        self.active_tunnels = 0
        self._lock = threading.Lock()
        super().__init__()

    @property
    def url(self) -> str:
        scheme = "https" if self._ssl_context is not None else "http"
        return "%s://127.0.0.1:%d" % (scheme, self.port)

    def _handle(self, conn: socket.socket) -> None:
        try:
            if self._ssl_context is not None:
                conn = self._ssl_context.wrap_socket(conn, server_side=True)
            head, rest = read_head(conn)
            request = parse_request(head)
            with self._lock:
                self.requests.append(request)

            if self._auth is not None:
                userpass = ("%s:%s" % self._auth).encode("ascii")
                expected = b"Basic " + base64.b64encode(userpass)
                if request.header(b"proxy-authorization") != expected:
                    conn.sendall(
                        b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                        b"Proxy-Authenticate: Basic realm=\"proxy\"\r\n"
                        b"Content-Length: 0\r\n"
                        b"\r\n"
                    )
                    conn.close()
                    return

            host, _, port = request.target.partition(b":")
            upstream = socket.create_connection((host.decode("ascii"), int(port)))
            conn.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
            if rest:
                upstream.sendall(rest)

            with self._lock:
                self.active_tunnels += 1
            try:
                self._tunnel(conn, upstream)
            finally:
                with self._lock:
                    self.active_tunnels -= 1
        except (ConnectionError, ssl.SSLError, OSError):
            pass
        finally:
            conn.close()

    def _tunnel(self, client: socket.socket, upstream: socket.socket) -> None:
        thread = threading.Thread(
            target=self._pipe, args=(client, upstream), daemon=True
        )
        thread.start()
        self._pipe(upstream, client)
        thread.join(timeout=5.0)

    def _pipe(self, source: socket.socket, destination: socket.socket) -> None:
        try:
            while True:
                data = source.recv(65536)
                if not data:
                    break
                destination.sendall(data)
        except OSError:
            pass
        finally:
            source.close()
            destination.close()


class OriginServer(LoopbackServer):
    """
    A minimal HTTP/1.1 origin server, optionally using TLS.

    Responds to every request with a fixed body, and supports keep-alive
    so that multiple requests may be sent over a single connection.
    """

    def __init__(
        self,
        ssl_context: typing.Optional[ssl.SSLContext] = None,
        body: bytes = b"Hello, world!",
    ) -> None:
        self._ssl_context = ssl_context
        self._body = body
        self.requests: typing.List[RecordedRequest] = []
        self._lock = threading.Lock()
        super().__init__()

    def _handle(self, conn: socket.socket) -> None:
        try:
            if self._ssl_context is not None:
                conn = self._ssl_context.wrap_socket(conn, server_side=True)
            buffer = b""
            while True:
                head, buffer = read_head(conn, buffer)
                request = parse_request(head)
                with self._lock:
                    self.requests.append(request)
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: text/plain\r\n"
                    + b"Content-Length: %d\r\n" % len(self._body)
                    + b"\r\n"
                    + self._body
                )
        except (ConnectionError, ssl.SSLError, OSError):
            pass
        finally:
            conn.close()
