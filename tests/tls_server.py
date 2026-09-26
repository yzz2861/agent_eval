"""
A local in-process TLS server used to test switching the client
certificate of a connection pool.

Connections are made over `socket.socketpair()` rather than TCP, so that
the tests do not require any network access. The server requires clients
to present a certificate signed by the test CA, and records the client
certificate used on every TLS handshake, so that tests can verify which
SSL context each new connection was established with.
"""

import socket
import ssl
import threading
import time
from pathlib import Path

import h2.config
import h2.connection
import h2.events
import trio

import httpcore
from httpcore._backends.sync import SyncStream
from httpcore._backends.trio import TrioStream

CERTS_DIR = Path(__file__).parent / "certs"

STREAM_BODY = b"stream-part-1|stream-part-2|"
STREAM_BODY_PART_1 = b"stream-part-1|"
STREAM_BODY_PART_2 = b"stream-part-2|"


def client_ssl_context(cert_name: str) -> ssl.SSLContext:
    """
    Return a client SSL context that presents the named client certificate.
    """
    context = ssl.create_default_context(cafile=str(CERTS_DIR / "ca.crt"))
    context.load_cert_chain(str(CERTS_DIR / f"{cert_name}.pem"))
    return context


class AsyncSocketPairBackend(httpcore.AsyncNetworkBackend):
    """
    An async network backend that connects to a `TLSServer` instance
    over `socket.socketpair()`. Requires trio.
    """

    def __init__(self, server: "TLSServer") -> None:
        self._server = server

    async def connect_tcp(
        self, host, port, timeout=None, local_address=None, socket_options=None
    ):
        client_sock, server_sock = socket.socketpair()
        self._server.handle_connection(server_sock)
        trio_socket = trio.socket.from_stdlib_socket(client_sock)
        return TrioStream(trio.SocketStream(trio_socket))

    async def connect_unix_socket(self, path, timeout=None, socket_options=None):
        raise NotImplementedError  # pragma: nocover

    async def sleep(self, seconds):
        await trio.sleep(seconds)


class SocketPairBackend(httpcore.NetworkBackend):
    """
    A sync network backend that connects to a `TLSServer` instance
    over `socket.socketpair()`.
    """

    def __init__(self, server: "TLSServer") -> None:
        self._server = server

    def connect_tcp(
        self, host, port, timeout=None, local_address=None, socket_options=None
    ):
        client_sock, server_sock = socket.socketpair()
        self._server.handle_connection(server_sock)
        return SyncStream(client_sock)

    def connect_unix_socket(self, path, timeout=None, socket_options=None):
        raise NotImplementedError  # pragma: nocover

    def sleep(self, seconds):
        time.sleep(seconds)


class ConnectionRecord:
    def __init__(self, client_cert_cn: str, alpn_protocol: str) -> None:
        self.client_cert_cn = client_cert_cn
        self.alpn_protocol = alpn_protocol
        self.request_count = 0


class TLSServer:
    """
    A threaded TLS server speaking HTTP/1.1, and optionally HTTP/2.

    Records the client certificate CN of every successful handshake in
    `client_cert_cns`, in the order the connections were established.
    """

    def __init__(self, http2: bool = False) -> None:
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._context.load_cert_chain(str(CERTS_DIR / "server.pem"))
        self._context.verify_mode = ssl.CERT_REQUIRED
        self._context.load_verify_locations(cafile=str(CERTS_DIR / "ca.crt"))
        alpn_protocols = ["h2", "http/1.1"] if http2 else ["http/1.1"]
        self._context.set_alpn_protocols(alpn_protocols)

        self._connections: list[ConnectionRecord] = []
        self._failed_handshakes = 0
        self._lock = threading.Lock()
        self._threads: list[threading.Thread] = []

        # Signalling used to coordinate in-flight responses with tests.
        self.stream_requested = threading.Event()
        self.stream_release = threading.Event()
        self.slow_requested = threading.Event()

        self.url = "https://localhost"

    def __enter__(self) -> "TLSServer":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    @property
    def client_cert_cns(self) -> list[str]:
        with self._lock:
            return [record.client_cert_cn for record in self._connections]

    @property
    def connections(self) -> list[ConnectionRecord]:
        with self._lock:
            return list(self._connections)

    @property
    def failed_handshakes(self) -> int:
        with self._lock:
            return self._failed_handshakes

    def handle_connection(self, sock: socket.socket) -> None:
        thread = threading.Thread(target=self._serve, args=(sock,), daemon=True)
        thread.start()
        with self._lock:
            self._threads.append(thread)

    def close(self) -> None:
        self.stream_release.set()
        with self._lock:
            threads = list(self._threads)
        for thread in threads:
            thread.join(timeout=5)

    def _serve(self, sock: socket.socket) -> None:
        try:
            conn = self._context.wrap_socket(sock, server_side=True)
        except OSError:
            # For example a client that does not trust the server
            # certificate, or a missing client certificate.
            with self._lock:
                self._failed_handshakes += 1
            sock.close()
            return

        peer_cert = conn.getpeercert()
        subject = dict(rdn[0] for rdn in peer_cert["subject"])
        record = ConnectionRecord(
            client_cert_cn=subject["commonName"],
            alpn_protocol=conn.selected_alpn_protocol() or "http/1.1",
        )
        with self._lock:
            self._connections.append(record)
        try:
            if record.alpn_protocol == "h2":
                self._serve_http2(conn, record)
            else:
                self._serve_http1(conn, record)
        except OSError:
            # The client went away mid-response.
            pass
        finally:
            conn.close()

    def _serve_http1(self, conn: ssl.SSLSocket, record: ConnectionRecord) -> None:
        buffer = b""
        while True:
            while b"\r\n\r\n" not in buffer:
                data = conn.recv(65536)
                if not data:
                    return
                buffer += data
            headers, buffer = buffer.split(b"\r\n\r\n", 1)
            path = headers.split(b"\r\n")[0].split(b" ")[1].decode("ascii")
            with self._lock:
                record.request_count += 1
            if path == "/stream":
                self.stream_requested.set()
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: plain/text\r\n"
                    b"Content-Length: %d\r\n"
                    b"\r\n" % len(STREAM_BODY)
                    + STREAM_BODY_PART_1
                )
                # Hold the response open until the test releases it.
                self.stream_release.wait(timeout=10)
                conn.sendall(STREAM_BODY_PART_2)
            elif path == "/slow":
                self.slow_requested.set()
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: plain/text\r\n"
                    b"Content-Length: 100\r\n"
                    b"\r\n"
                )
                for _ in range(100):
                    conn.sendall(b"x")
                    time.sleep(0.1)
            else:
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: plain/text\r\n"
                    b"Content-Length: 13\r\n"
                    b"\r\n"
                    b"Hello, world!"
                )

    def _serve_http2(self, conn: ssl.SSLSocket, record: ConnectionRecord) -> None:
        config = h2.config.H2Configuration(client_side=False)
        h2_conn = h2.connection.H2Connection(config=config)
        h2_conn.initiate_connection()
        conn.sendall(h2_conn.data_to_send())
        stream_paths: dict[int, bytes] = {}
        while True:
            data = conn.recv(65535)
            if not data:
                return
            events = h2_conn.receive_data(data)
            for event in events:
                if isinstance(event, h2.events.RequestReceived):
                    with self._lock:
                        record.request_count += 1
                    headers = dict(event.headers)
                    stream_paths[event.stream_id] = headers.get(b":path", b"/")
                elif isinstance(event, h2.events.StreamEnded):
                    path = stream_paths.pop(event.stream_id, b"/")
                    self._respond_http2(h2_conn, conn, event.stream_id, path)
            outgoing = h2_conn.data_to_send()
            if outgoing:
                conn.sendall(outgoing)

    def _respond_http2(
        self,
        h2_conn: "h2.connection.H2Connection",
        conn: ssl.SSLSocket,
        stream_id: int,
        path: bytes,
    ) -> None:
        if path == b"/stream":
            self.stream_requested.set()
            h2_conn.send_headers(
                stream_id,
                [(":status", "200"), ("content-length", str(len(STREAM_BODY)))],
            )
            h2_conn.send_data(stream_id, STREAM_BODY_PART_1, end_stream=False)
            conn.sendall(h2_conn.data_to_send())
            # Hold the response open until the test releases it.
            self.stream_release.wait(timeout=10)
            h2_conn.send_data(stream_id, STREAM_BODY_PART_2, end_stream=True)
            conn.sendall(h2_conn.data_to_send())
        else:
            h2_conn.send_headers(
                stream_id, [(":status", "200"), ("content-length", "13")]
            )
            h2_conn.send_data(stream_id, b"Hello, world!", end_stream=True)
