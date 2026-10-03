from __future__ import annotations

import base64
import http.server
import os
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading

import pytest

import httpcore


class ProxyStats:
    def __init__(self) -> None:
        self.connect_count = 0
        self.connects: list[tuple[str, str | None]] = []


class ConnectProxyHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        request = self.request
        if self.server.tls_context is not None:  # type: ignore[attr-defined]
            request = self.server.tls_context.wrap_socket(  # type: ignore[attr-defined]
                self.request, server_side=True
            )

        reader = request.makefile("rb")
        line = reader.readline().decode("ascii", errors="replace")
        method, target, _ = line.split(" ", 2)
        headers: dict[str, str] = {}
        while True:
            header = reader.readline()
            if header in (b"\r\n", b"", b"\n"):
                break
            key, value = header.decode("ascii", errors="replace").split(":", 1)
            headers[key.lower()] = value.strip()

        stats: ProxyStats = self.server.stats  # type: ignore[attr-defined]
        with threading.Lock():
            stats.connect_count += 1
            stats.connects.append((target, headers.get("proxy-authorization")))

        expected_auth = self.server.auth  # type: ignore[attr-defined]
        if expected_auth is not None:
            authorization = "Basic " + base64.b64encode(expected_auth).decode("ascii")
            if headers.get("proxy-authorization") != authorization:
                request.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                return

        if method != "CONNECT":
            request.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            return

        host, port_text = target.rsplit(":", 1)
        with socket.create_connection((host, int(port_text))) as upstream:
            request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self._bridge(request, upstream)

    def _bridge(self, client: socket.socket, upstream: socket.socket) -> None:
        sockets = [client, upstream]
        peers = {client: upstream, upstream: client}

        def relay(source: socket.socket) -> None:
            try:
                while True:
                    data = source.recv(65536)
                    if not data:
                        break
                    peers[source].sendall(data)
            except OSError:
                pass
            finally:
                for sock in sockets:
                    try:
                        sock.close()
                    except OSError:
                        pass

        threads = [
            threading.Thread(target=relay, args=(sock,), daemon=True) for sock in sockets
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()


class ProxyServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        *,
        tls_context: ssl.SSLContext | None,
        auth: bytes | None,
        stats: ProxyStats,
    ) -> None:
        super().__init__(("127.0.0.1", 0), ConnectProxyHandler)
        self.tls_context = tls_context
        self.auth = auth
        self.stats = stats


class FinalHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = b"final response"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        pass


class FinalServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], handler: type[FinalHandler]) -> None:
        super().__init__(address, handler)
        self.tls_context: ssl.SSLContext | None = None

    def get_request(self) -> tuple[socket.socket, tuple[str, int]]:
        sock, address = self.socket.accept()
        if self.tls_context is not None:
            sock = self.tls_context.wrap_socket(sock, server_side=True)
        return sock, address


def _write_certificate(
    tmpdir: str,
    *,
    common_name: str,
    name: str | None = None,
    alt_names: tuple[str, ...] = ("DNS:localhost", "IP:127.0.0.1"),
) -> tuple[str, str]:
    name = common_name if name is None else name
    key_path = os.path.join(tmpdir, f"{name}.key")
    cert_path = os.path.join(tmpdir, f"{name}.crt")
    alt_name = ",".join(alt_names)
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            key_path,
            "-out",
            cert_path,
            "-days",
            "1",
            "-subj",
            f"/CN={common_name}",
            "-addext",
            "subjectAltName=" + alt_name,
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return cert_path, key_path


@pytest.fixture
def proxy_chain_servers():
    with tempfile.TemporaryDirectory() as tmpdir:
        valid_cert, valid_key = _write_certificate(tmpdir, common_name="localhost")
        valid_final_cert, valid_final_key = _write_certificate(
            tmpdir, common_name="localhost", name="final"
        )

        proxy_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        proxy_context.load_cert_chain(valid_cert, valid_key)
        final_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        final_context.load_cert_chain(valid_final_cert, valid_final_key)

        outer_stats = ProxyStats()
        inner_stats = ProxyStats()
        outer_server = ProxyServer(
            tls_context=proxy_context,
            auth=b"outer:secret",
            stats=outer_stats,
        )
        inner_server = ProxyServer(
            tls_context=None,
            auth=b"inner:secret",
            stats=inner_stats,
        )
        final_server = FinalServer(("127.0.0.1", 0), FinalHandler)
        final_server.tls_context = final_context

        servers = [outer_server, inner_server, final_server]
        threads = [
            threading.Thread(target=server.serve_forever, daemon=True) for server in servers
        ]
        for thread in threads:
            thread.start()

        try:
            yield (
                outer_server,
                inner_server,
                final_server,
                outer_stats,
                inner_stats,
                valid_cert,
                valid_final_cert,
            )
        finally:
            for server in servers:
                server.shutdown()
                server.server_close()


def _client_ssl_context(ca_cert: str) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=ca_cert)
    return context


@pytest.mark.anyio
async def test_proxy_chain_tunneling_and_reuse(proxy_chain_servers):
    (
        outer_server,
        inner_server,
        final_server,
        outer_stats,
        inner_stats,
        ca_cert,
        final_ca_cert,
    ) = proxy_chain_servers
    proxy_context = _client_ssl_context(ca_cert)
    final_context = _client_ssl_context(final_ca_cert)
    chain = httpcore.ProxyChain(
        [
            httpcore.Proxy(
                f"https://127.0.0.1:{outer_server.server_address[1]}/",
                auth=("outer", "secret"),
                ssl_context=proxy_context,
            ),
            httpcore.Proxy(
                f"http://127.0.0.1:{inner_server.server_address[1]}/",
                auth=("inner", "secret"),
            ),
        ]
    )
    target = f"https://127.0.0.1:{final_server.server_address[1]}/"

    async with httpcore.AsyncConnectionPool(
        proxy_chain=chain, ssl_context=final_context
    ) as pool:
        response = await pool.request("GET", target)
        assert response.status == 200
        assert response.content == b"final response"

        response = await pool.request("GET", target)
        assert response.status == 200
        assert response.content == b"final response"

        assert len(pool.connections) == 1
        assert outer_stats.connect_count == 1
        assert inner_stats.connect_count == 1
        assert [target_host for target_host, _ in outer_stats.connects] == [
            f"127.0.0.1:{inner_server.server_address[1]}"
        ]
        assert [target_host for target_host, _ in inner_stats.connects] == [
            f"127.0.0.1:{final_server.server_address[1]}"
        ]
        assert outer_stats.connects[0][1] != inner_stats.connects[0][1]


@pytest.mark.anyio
async def test_proxy_chain_inner_407(proxy_chain_servers):
    outer_server, inner_server, final_server, _, _, ca_cert, _ = proxy_chain_servers
    chain = httpcore.ProxyChain(
        [
            httpcore.Proxy(
                f"https://127.0.0.1:{outer_server.server_address[1]}/",
                auth=("outer", "secret"),
                ssl_context=_client_ssl_context(ca_cert),
            ),
            httpcore.Proxy(
                f"http://127.0.0.1:{inner_server.server_address[1]}/",
                auth=("wrong", "credentials"),
            ),
        ]
    )

    async with httpcore.AsyncConnectionPool(proxy_chain=chain) as pool:
        with pytest.raises(httpcore.ProxyError, match=r"hop 2/2.*CONNECT response"):
            await pool.request(
                "GET", f"https://127.0.0.1:{final_server.server_address[1]}/"
            )


@pytest.mark.anyio
async def test_proxy_chain_destination_tls_verification(proxy_chain_servers):
    outer_server, inner_server, final_server, _, _, ca_cert, _ = proxy_chain_servers
    chain = httpcore.ProxyChain(
        [
            httpcore.Proxy(
                f"https://127.0.0.1:{outer_server.server_address[1]}/",
                auth=("outer", "secret"),
                ssl_context=_client_ssl_context(ca_cert),
            ),
            httpcore.Proxy(
                f"http://127.0.0.1:{inner_server.server_address[1]}/",
                auth=("inner", "secret"),
            ),
        ]
    )

    async with httpcore.AsyncConnectionPool(proxy_chain=chain) as pool:
        with pytest.raises(httpcore.ProxyError, match="destination TLS handshake") as exc_info:
            await pool.request(
                "GET", f"https://127.0.0.1:{final_server.server_address[1]}/"
            )
        cause = exc_info.value.__cause__
        assert isinstance(cause, ssl.SSLError) or (
            isinstance(cause, httpcore.ConnectError)
            and isinstance(cause.__cause__, ssl.SSLError)
        )
