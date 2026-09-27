from __future__ import annotations

import functools
import ipaddress

from uvicorn._types import ASGI3Application, ASGIReceiveCallable, ASGISendCallable, Scope


class ProxyHeadersMiddleware:
    """Middleware for handling known proxy headers

    This middleware can be used when a known proxy is fronting the application,
    and is trusted to be properly setting the `X-Forwarded-Proto` and
    `X-Forwarded-For` headers with the connecting client information.

    Modifies the `client` and `scheme` information so that they reference
    the connecting client, rather that the connecting proxy.

    When `forwarded_headers` is enabled, the standardized `Forwarded` header
    (RFC 7239) is also processed. If a request carries both `Forwarded` and
    `X-Forwarded-*` headers, the `Forwarded` header takes precedence and the
    `X-Forwarded-*` headers are ignored for that request; the two header
    families are never combined into a single proxy chain.

    References:
    - <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers#Proxies>
    - <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For>
    - <https://www.rfc-editor.org/rfc/rfc7239>
    """

    def __init__(
        self,
        app: ASGI3Application,
        trusted_hosts: list[str] | str = "127.0.0.1",
        forwarded_headers: bool = False,
    ) -> None:
        self.app = app
        self.trusted_hosts = _TrustedHosts(trusted_hosts)
        self.forwarded_headers = forwarded_headers

    async def __call__(self, scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        if scope["type"] == "lifespan":
            return await self.app(scope, receive, send)

        client_addr = scope.get("client")
        client_host = client_addr[0] if client_addr else None

        if client_host in self.trusted_hosts:
            forwarded_values: list[bytes] = []
            x_forwarded_proto_value: bytes | None = None
            x_forwarded_for_values: list[bytes] = []
            for name, value in scope["headers"]:
                if name == b"forwarded":
                    forwarded_values.append(value)
                elif name == b"x-forwarded-proto":
                    x_forwarded_proto_value = value
                elif name == b"x-forwarded-for":
                    x_forwarded_for_values.append(value)

            if self.forwarded_headers and forwarded_values:
                # The `Forwarded` header is the standardized mechanism and
                # takes precedence over `X-Forwarded-*` headers.
                self._update_scope_from_forwarded(scope, forwarded_values)
            else:
                if x_forwarded_proto_value is not None:
                    x_forwarded_proto = x_forwarded_proto_value.decode("latin1").strip()

                    if x_forwarded_proto in {"http", "https", "ws", "wss"}:
                        if scope["type"] == "websocket":
                            scope["scheme"] = x_forwarded_proto.replace("http", "ws")
                        else:
                            scope["scheme"] = x_forwarded_proto

                if x_forwarded_for_values:
                    x_forwarded_for = b", ".join(x_forwarded_for_values).decode("latin1")
                    host, port = self.trusted_hosts.get_trusted_client_address(x_forwarded_for)

                    if host:
                        # If the x-forwarded-for header is empty then host is an empty string.
                        # Only set the client if we actually got something usable.
                        # See: https://github.com/Kludex/uvicorn/issues/1068
                        scope["client"] = (host, port)

        return await self.app(scope, receive, send)

    def _update_scope_from_forwarded(self, scope: Scope, forwarded_values: list[bytes]) -> None:
        """Update the scope from one or more `Forwarded` header fields (RFC 7239).

        The chain of forwarded elements is walked from the directly connecting
        peer (the last element) towards the client, following the same trust
        boundary as `X-Forwarded-For`: the first untrusted `for=` identifier
        becomes the client. Elements added by the client before the first
        trusted proxy are never reached, so a forged prefix cannot influence
        the result. `for=unknown` and obfuscated identifiers (`_...`) are not
        valid addresses: they terminate the walk and are never exposed as the
        client.
        """
        elements = _parse_forwarded_elements(forwarded_values)
        if not elements:
            return

        selected = elements[0]
        if not self.trusted_hosts.always_trust:
            for element in reversed(elements):
                if element.for_addr is None or element.for_addr[0] not in self.trusted_hosts:
                    selected = element
                    break

        proto = selected.proto
        if proto is not None and proto in {"http", "https", "ws", "wss"}:
            if scope["type"] == "websocket":
                scope["scheme"] = proto.replace("http", "ws")
            else:
                scope["scheme"] = proto

        if selected.for_addr is not None:
            host, port = selected.for_addr
            scope["client"] = (host, port)


def _parse_raw_hosts(value: str) -> list[str]:
    return [item.strip() for item in value.split(",")]


def _parse_host_port(value: str) -> tuple[str, int]:
    """Parse a forwarded host value into host and optional port.

    Accepts bare IPs, IPv4 `host:port`, and bracketed IPv6 `[host]:port`.
    Any unrecognized or malformed value is treated conservatively and returned
    without a port so trust checks do not silently normalize arbitrary input.
    """

    if value.startswith("["):
        bracket_end = value.find("]")
        if bracket_end == -1:
            return value, 0

        host = value[1:bracket_end]
        remainder = value[bracket_end + 1 :]
        if not remainder:
            return host, 0
        if not remainder.startswith(":"):
            return value, 0

        try:
            return host, int(remainder[1:])
        except ValueError:
            return host, 0

    if value.count(":") == 1:
        host, port = value.rsplit(":", 1)
        try:
            return host, int(port)
        except ValueError:
            return value, 0

    return value, 0


def _split_forwarded(value: str, delimiter: str) -> list[str]:
    """Split a `Forwarded` header component on a delimiter.

    Delimiters inside quoted-strings are ignored, and backslash escapes
    (quoted-pairs) are preserved so they can be unquoted afterwards.
    """
    parts: list[str] = []
    current: list[str] = []
    in_quotes = False
    escaped = False
    for char in value:
        if escaped:
            current.append(char)
            escaped = False
        elif in_quotes and char == "\\":
            current.append(char)
            escaped = True
        elif char == '"':
            current.append(char)
            in_quotes = not in_quotes
        elif char == delimiter and not in_quotes:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return parts


def _unquote_forwarded_value(value: str) -> str:
    """Remove quotes and backslash escapes from a quoted-string value."""
    if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
        unescaped: list[str] = []
        escaped = False
        for char in value[1:-1]:
            if escaped:
                unescaped.append(char)
                escaped = False
            elif char == "\\":
                escaped = True
            else:
                unescaped.append(char)
        if escaped:
            unescaped.append("\\")
        return "".join(unescaped)
    return value


def _parse_forwarded_for(value: str) -> tuple[str, int] | None:
    """Parse a `for=` node identifier into a (host, port) pair.

    Returns `None` for `unknown`, obfuscated identifiers (`_...`), and
    anything that is not a valid IP address, so that placeholders can never
    be exposed to the application as a client address.
    """
    if not value or value.lower() == "unknown" or value.startswith("_"):
        return None

    host, port = _parse_host_port(value)
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return None
    return host, port


class _ForwardedElement:
    """A single `forwarded-element` of a `Forwarded` header (RFC 7239)."""

    def __init__(self, for_addr: tuple[str, int] | None, proto: str | None) -> None:
        self.for_addr = for_addr
        self.proto = proto


def _parse_forwarded_elements(values: list[bytes]) -> list[_ForwardedElement]:
    """Parse one or more `Forwarded` header fields into a list of elements.

    Multiple header fields are equivalent to a single comma-separated list
    (RFC 9110, Section 5.3), so they are combined before parsing.
    """
    combined = ", ".join(value.decode("latin1") for value in values)
    elements: list[_ForwardedElement] = []
    for raw_element in _split_forwarded(combined, ","):
        for_value: str | None = None
        proto: str | None = None
        for raw_pair in _split_forwarded(raw_element, ";"):
            name, separator, pair_value = raw_pair.partition("=")
            if not separator:
                continue
            name = name.strip().lower()
            pair_value = _unquote_forwarded_value(pair_value.strip())
            if name == "for" and for_value is None:
                for_value = pair_value
            elif name == "proto" and proto is None:
                proto = pair_value.lower()
        for_addr = _parse_forwarded_for(for_value) if for_value is not None else None
        elements.append(_ForwardedElement(for_addr, proto))
    return elements


class _TrustedHosts:
    """Container for trusted hosts and networks"""

    def __init__(self, trusted_hosts: list[str] | str) -> None:
        self.always_trust: bool = trusted_hosts in ("*", ["*"])

        self.trusted_literals: set[str] = set()
        self.trusted_hosts: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
        self.trusted_networks: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()

        # Notes:
        # - We separate hosts from literals as there are many ways to write
        #   an IPv6 Address so we need to compare by object.
        # - We don't convert IP Address to single host networks (e.g. /32 / 128) as
        #   it more efficient to do an address lookup in a set than check for
        #   membership in each network.
        # - We still allow literals as it might be possible that we receive a
        #   something that isn't an IP Address e.g. a unix socket.

        if not self.always_trust:
            if isinstance(trusted_hosts, str):
                trusted_hosts = _parse_raw_hosts(trusted_hosts)

            for host in trusted_hosts:
                # Note: because we always convert invalid IP types to literals it
                # is not possible for the user to know they provided a malformed IP
                # type - this may lead to unexpected / difficult to debug behaviour.

                if "/" in host:
                    # Looks like a network
                    try:
                        self.trusted_networks.add(ipaddress.ip_network(host))
                    except ValueError:
                        # Was not a valid IP Network
                        self.trusted_literals.add(host)
                else:
                    try:
                        self.trusted_hosts.add(ipaddress.ip_address(host))
                    except ValueError:
                        # Was not a valid IP Address
                        self.trusted_literals.add(host)

        self._trusts = functools.lru_cache(maxsize=4096)(self._compute_trust)

    def __contains__(self, host: str | None) -> bool:
        if self.always_trust:
            return True

        if not host:
            return False

        # Don't cache hosts longer than a DNS name (253); they can't be trusted and would pin huge cache keys.
        if len(host) > 253:
            return self._compute_trust(host)  # pragma: no cover

        return self._trusts(host)

    def _compute_trust(self, host: str) -> bool:
        try:
            ip = ipaddress.ip_address(host)
            return ip in self.trusted_hosts or any(ip in net for net in self.trusted_networks)
        except ValueError:
            return host in self.trusted_literals

    def get_trusted_client_address(self, x_forwarded_for: str) -> tuple[str, int]:
        """Extract the client address from x_forwarded_for header.

        In general this is the first "untrusted" host in the forwarded for list.
        """
        x_forwarded_for_hosts = _parse_raw_hosts(x_forwarded_for)

        if self.always_trust:
            return _parse_host_port(x_forwarded_for_hosts[0])

        # Note: each proxy appends to the header list so check it in reverse order
        for host_port in reversed(x_forwarded_for_hosts):
            host, port = _parse_host_port(host_port)
            if host not in self:
                return host, port

        # All hosts are trusted meaning that the client was also a trusted proxy
        # See https://github.com/Kludex/uvicorn/issues/1068#issuecomment-855371576
        return _parse_host_port(x_forwarded_for_hosts[0])
