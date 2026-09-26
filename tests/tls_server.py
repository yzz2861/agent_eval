"""
A local in-process TLS server, used to test client-certificate handling
against both the sync and async connection pools.

Client connections are established over `socket.socketpair()`, so no
listening socket is required. The server requires client certificates,
and records the client certificate presented on each handshake.
"""

from __future__ import annotations

import os
import socket
import ssl
import threading
import time
import typing

import trio

import httpcore
from httpcore._backends.sync import SyncStream
from httpcore._backends.trio import TrioStream

CERTS_DIR = os.path.join(os.path.dirname(__file__), "certs")


class RecordingTLSServer:
    """
    A minimal TLS server that requires client certificates, records which
    client certificate was presented on each handshake, and serves simple
    HTTP/1.1 responses.

    Requests to "/stream" are sent their response headers immediately, with
    the response body held back until `release_stream()` is called, allowing
    tests to keep an in-flight request open across an SSL context update.
    """

    def __init__(self) -> None:
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._context.load_cert_chain(
            certfile=os.path.join(CERTS_DIR, "server.crt"),
            keyfile=os.path.join(CERTS_DIR, "server.key"),
        )
        self._context.verify_mode = ssl.CERT_REQUIRED
        self._context.load_verify_locations(os.path.join(CERTS_DIR, "ca.crt"))

        self.client_cert_names: list[str] = []
        self.handshake_failures = 0
        self.stream_release = threading.Event()
        self._threads: list[threading.Thread] = []

    def release_stream(self) -> None:
        self.stream_release.set()

    def handle_connection(self, conn: socket.socket) -> None:
        thread = threading.Thread(target=self._serve, args=(conn,), daemon=True)
        thread.start()
        self._threads.append(thread)

    def close(self) -> None:
        for thread in self._threads:
            thread.join(timeout=5)

    def _serve(self, conn: socket.socket) -> None:
        try:
            tls_conn = self._context.wrap_socket(conn, server_side=True)
        except (ssl.SSLError, OSError):
            self.handshake_failures += 1
            conn.close()
            return

        try:
            cert = tls_conn.getpeercert()
            assert cert is not None
            subject = dict(rdn[0] for rdn in cert["subject"])
            self.client_cert_names.append(subject["commonName"])

            request = b""
            while b"\r\n\r\n" not in request:
                chunk = tls_conn.recv(4096)
                if not chunk:
                    return
                request += chunk

            if request.startswith(b"GET /stream"):
                tls_conn.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, "
                )
                self.stream_release.wait(timeout=5)
                tls_conn.sendall(b"world!")
            else:
                tls_conn.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, world!"
                )
        except OSError:
            pass
        finally:
            tls_conn.close()


def client_ssl_context(cert_filename: str) -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.load_verify_locations(os.path.join(CERTS_DIR, "ca.crt"))
    context.load_cert_chain(os.path.join(CERTS_DIR, cert_filename))
    context.check_hostname = False
    return context


class AsyncLoopbackBackend(httpcore.AsyncNetworkBackend):
    """
    A network backend that establishes connections to a local
    `RecordingTLSServer` over `socket.socketpair()`.
    """

    def __init__(self, server: RecordingTLSServer) -> None:
        self._server = server

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: typing.Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        client, server = socket.socketpair()
        self._server.handle_connection(server)
        trio_socket = trio.socket.from_stdlib_socket(client)
        return TrioStream(trio.SocketStream(trio_socket))

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: typing.Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        raise NotImplementedError

    async def sleep(self, seconds: float) -> None:
        await trio.sleep(seconds)


class LoopbackBackend(httpcore.NetworkBackend):
    """
    The sync counterpart of `AsyncLoopbackBackend`.
    """

    def __init__(self, server: RecordingTLSServer) -> None:
        self._server = server

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: typing.Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.NetworkStream:
        client, server = socket.socketpair()
        self._server.handle_connection(server)
        return SyncStream(client)

    def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: typing.Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.NetworkStream:
        raise NotImplementedError

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)
