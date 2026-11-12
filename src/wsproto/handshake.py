"""
wsproto/handshake
~~~~~~~~~~~~~~~~~~

An implementation of WebSocket handshakes.
"""
from __future__ import annotations

from collections import deque
from typing import (
    TYPE_CHECKING,
    cast,
)
from urllib.parse import urlsplit

import h11

from .connection import Connection, ConnectionState, ConnectionType
from .events import AcceptConnection, Event, RejectConnection, RejectData, Request
from .extensions import Extension
from .utilities import (
    LocalProtocolError,
    RemoteProtocolError,
    generate_accept_token,
    generate_nonce,
    normed_header_dict,
    split_comma_header,
)

if TYPE_CHECKING:
    from collections.abc import Generator, Iterable, Sequence
    from typing import NoReturn

    from .typing import Headers

# RFC6455, Section 4.2.1/6 - Reading the Client's Opening Handshake
WEBSOCKET_VERSION = b"13"

# RFC6455, Section 4.2.1/3 - Value of the Upgrade header
WEBSOCKET_UPGRADE = b"websocket"

# Rejection responses must not disclose proxy internals, so the response only
# carries a stable reason code (never the rejected Host/Origin values).
WEBSOCKET_REJECT_REASON_HEADER = b"x-websocket-reject-reason"


class OriginRejectionReason:
    """Stable reason codes for server origin-policy rejections."""

    DUPLICATE_HOST = "duplicate_host"
    DUPLICATE_ORIGIN = "duplicate_origin"
    DUPLICATE_PROXY_HOST = "duplicate_proxy_host"
    HOST_NOT_ALLOWED = "host_not_allowed"
    INVALID_HOST = "invalid_host"
    INVALID_ORIGIN = "invalid_origin"
    MISSING_ORIGIN = "missing_origin"
    ORIGIN_HOST_MISMATCH = "origin_host_mismatch"
    ORIGIN_NOT_ALLOWED = "origin_not_allowed"
    ORIGIN_SCHEME_NOT_ALLOWED = "origin_scheme_not_allowed"
    ORIGIN_USERINFO_NOT_ALLOWED = "origin_userinfo_not_allowed"


# A shorter alias for callers that already know the codes are origin-related.
RejectionReason = OriginRejectionReason

_DEFAULT_PORTS = {"http": 80, "https": 443}


class _PolicyViolationError(Exception):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _text(value: str | bytes) -> str:
    if isinstance(value, bytes):
        return value.decode("ascii")
    return value


def _normalize_hostname(hostname: str) -> str:
    hostname = hostname.rstrip(".")
    if ":" in hostname:
        return hostname.lower()
    try:
        return hostname.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return hostname.lower()


def _parse_authority(value: str) -> tuple[str, int | None]:
    value = value.strip()
    if not value or "," in value or "@" in value:
        raise _PolicyViolationError(OriginRejectionReason.INVALID_HOST)
    if any(character.isspace() for character in value):
        raise _PolicyViolationError(OriginRejectionReason.INVALID_HOST)
    try:
        parsed = urlsplit("//" + value)
        port = parsed.port
    except ValueError as exc:
        raise _PolicyViolationError(OriginRejectionReason.INVALID_HOST) from exc
    if parsed.scheme or parsed.query or parsed.fragment:
        raise _PolicyViolationError(OriginRejectionReason.INVALID_HOST)
    if parsed.path:
        raise _PolicyViolationError(OriginRejectionReason.INVALID_HOST)
    if parsed.username is not None or parsed.password is not None:
        raise _PolicyViolationError(OriginRejectionReason.INVALID_HOST)
    if parsed.hostname is None:
        raise _PolicyViolationError(OriginRejectionReason.INVALID_HOST)
    return _normalize_hostname(parsed.hostname), port


def _parse_origin(value: str) -> tuple[str, str, int]:
    value = value.strip()
    if not value or any(character.isspace() for character in value):
        raise _PolicyViolationError(OriginRejectionReason.INVALID_ORIGIN)
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise _PolicyViolationError(OriginRejectionReason.INVALID_ORIGIN) from exc
    scheme = parsed.scheme.lower()
    if not scheme or not parsed.netloc:
        raise _PolicyViolationError(OriginRejectionReason.INVALID_ORIGIN)
    if scheme not in _DEFAULT_PORTS:
        raise _PolicyViolationError(OriginRejectionReason.ORIGIN_SCHEME_NOT_ALLOWED)
    if parsed.username is not None or parsed.password is not None:
        raise _PolicyViolationError(OriginRejectionReason.ORIGIN_USERINFO_NOT_ALLOWED)
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise _PolicyViolationError(OriginRejectionReason.INVALID_ORIGIN)
    if parsed.hostname is None:
        raise _PolicyViolationError(OriginRejectionReason.INVALID_ORIGIN)
    return (
        scheme,
        _normalize_hostname(parsed.hostname),
        port if port is not None else _DEFAULT_PORTS[scheme],
    )


def _as_sequence(
    value: str | bytes | Iterable[str | bytes] | None,
) -> tuple[str | bytes, ...]:
    if value is None:
        return ()
    if isinstance(value, (str, bytes)):
        return (value,)
    return tuple(value)


def _is_duplicate_host_error(exc: Exception) -> bool:
    message = str(exc).lower()
    return "multiple host" in message or "more than one host" in message


def _reason_code_from_headers(
    headers: Iterable[tuple[bytes, bytes]],
) -> str | None:
    for name, value in headers:
        if name.lower() != WEBSOCKET_REJECT_REASON_HEADER:
            continue
        try:
            return value.decode("ascii")
        except UnicodeError:
            return None
    return None


class ServerOriginPolicy:
    """
    Explicit server-side Origin and Host trust policy.

    The policy is disabled unless it is passed to :class:`H11Handshake` or
    :class:`~wsproto.WSConnection`. Rejections use HTTP 403 and expose one of
    the stable :class:`OriginRejectionReason` codes. Rejected values are never
    echoed back to the client.

    :param allowed_origins: Exact origins that may be used by browser clients.
    :param allowed_hosts: Host authorities that may serve the WebSocket. When
        omitted, hostnames are derived from ``allowed_origins``.
    :param trust_proxy_host: Use the host from ``proxy_host_header`` instead of
        the ``Host`` header. This is disabled by default.
    :param allow_missing_origin: Permit clients without an ``Origin`` header,
        such as non-browser clients.
    :param proxy_host_header: The only header consulted when
        ``trust_proxy_host`` is enabled. It must be configured explicitly; no
        header (including ``X-Forwarded-Host``) is trusted by default.
    """

    _ALIASES = {
        "allowed_origin": "allowed_origins",
        "allowed_host": "allowed_hosts",
        "origin_allowlist": "allowed_origins",
        "origin_whitelist": "allowed_origins",
        "host_allowlist": "allowed_hosts",
        "host_whitelist": "allowed_hosts",
        "trust_proxy": "trust_proxy_host",
        "trust_proxy_headers": "trust_proxy_host",
        "trust_forwarded_host": "trust_proxy_host",
        "trusted_proxy": "trust_proxy_host",
        "allow_no_origin": "allow_missing_origin",
        "allow_origin_missing": "allow_missing_origin",
        "allow_absent_origin": "allow_missing_origin",
        "allow_non_browser": "allow_missing_origin",
        "allow_non_browser_clients": "allow_missing_origin",
        "forwarded_host_header": "proxy_host_header",
        "proxy_header": "proxy_host_header",
        "proxy_header_name": "proxy_host_header",
        "trusted_host_header": "proxy_host_header",
        "trusted_proxy_header": "proxy_host_header",
    }

    def __init__(
        self,
        allowed_origins: str | bytes | Iterable[str | bytes] | None = (),
        allowed_hosts: str | bytes | Iterable[str | bytes] | None = (),
        trust_proxy_host: bool = False,
        allow_missing_origin: bool = False,
        proxy_host_header: str | bytes | None = None,
        **aliases: object,
    ) -> None:
        arguments: dict[str, object] = {
            "allowed_origins": allowed_origins,
            "allowed_hosts": allowed_hosts,
            "trust_proxy_host": trust_proxy_host,
            "allow_missing_origin": allow_missing_origin,
            "proxy_host_header": proxy_host_header,
        }
        for alias, canonical in self._ALIASES.items():
            if alias in aliases:
                arguments[canonical] = aliases.pop(alias)
        if aliases:
            msg = f"unexpected policy argument(s): {', '.join(sorted(aliases))}"
            raise TypeError(msg)

        allowed_origins = cast(
            "str | bytes | Iterable[str | bytes] | None",
            arguments["allowed_origins"],
        )
        allowed_hosts = cast(
            "str | bytes | Iterable[str | bytes] | None",
            arguments["allowed_hosts"],
        )
        trust_proxy_host = cast("bool", arguments["trust_proxy_host"])
        allow_missing_origin = cast("bool", arguments["allow_missing_origin"])
        proxy_host_header = cast("str | bytes | None", arguments["proxy_host_header"])

        self.allowed_origins = tuple(
            _text(value) for value in _as_sequence(allowed_origins)
        )
        self.allowed_hosts = tuple(
            _text(value) for value in _as_sequence(allowed_hosts)
        )
        self.trust_proxy_host = bool(trust_proxy_host)
        self.allow_missing_origin = bool(allow_missing_origin)

        if proxy_host_header is None:
            self.proxy_host_header = None
        else:
            header = _text(proxy_host_header).strip().lower()
            if not header:
                msg = "proxy_host_header must not be empty"
                raise ValueError(msg)
            self.proxy_host_header = header
        if self.trust_proxy_host and self.proxy_host_header is None:
            msg = "trust_proxy_host requires an explicitly configured proxy_host_header"
            raise ValueError(msg)

        try:
            self._allowed_origin_keys = tuple(
                _parse_origin(origin) for origin in self.allowed_origins
            )
        except _PolicyViolationError as exc:
            msg = f"invalid allowed origin: {exc.reason_code}"
            raise ValueError(msg) from exc
        try:
            self._allowed_host_entries = tuple(
                _parse_authority(host) for host in self.allowed_hosts
            )
        except _PolicyViolationError as exc:
            msg = f"invalid allowed host: {exc.reason_code}"
            raise ValueError(msg) from exc

        if not self._allowed_host_entries and self._allowed_origin_keys:
            self._allowed_host_entries = tuple(
                (origin_host, None)
                for _, origin_host, _ in self._allowed_origin_keys
            )

    @property
    def trust_proxy(self) -> bool:
        return self.trust_proxy_host

    @property
    def allow_no_origin(self) -> bool:
        return self.allow_missing_origin

    def validate(self, origin: str | None, host: str) -> str | None:
        """Return a rejection reason code, or ``None`` when the request passes."""
        try:
            hostname, host_port = _parse_authority(host)
        except _PolicyViolationError as exc:
            return exc.reason_code
        if origin is None:
            return self._validate_without_origin(hostname, host_port)
        try:
            scheme, origin_hostname, origin_port = _parse_origin(origin)
        except _PolicyViolationError as exc:
            return exc.reason_code
        return self._validate_with_origin(
            hostname,
            host_port,
            scheme,
            origin_hostname,
            origin_port,
        )

    def check(self, origin: str | None, host: str) -> str | None:
        """Alias for :meth:`validate`."""
        return self.validate(origin, host)

    def _validate_without_origin(
        self, hostname: str, host_port: int | None,
    ) -> str | None:
        default_ports = frozenset(_DEFAULT_PORTS.values())
        if not self._host_is_allowed(hostname, host_port, default_ports):
            return OriginRejectionReason.HOST_NOT_ALLOWED
        if not self.allow_missing_origin:
            return OriginRejectionReason.MISSING_ORIGIN
        return None

    def _validate_with_origin(
        self,
        hostname: str,
        host_port: int | None,
        scheme: str,
        origin_hostname: str,
        origin_port: int,
    ) -> str | None:
        default_ports = frozenset({_DEFAULT_PORTS[scheme]})
        effective_host_port = (
            host_port if host_port is not None else _DEFAULT_PORTS[scheme]
        )
        if not self._host_is_allowed(hostname, host_port, default_ports):
            return OriginRejectionReason.HOST_NOT_ALLOWED
        if origin_hostname != hostname or origin_port != effective_host_port:
            return OriginRejectionReason.ORIGIN_HOST_MISMATCH
        if (scheme, origin_hostname, origin_port) not in self._allowed_origin_keys:
            return OriginRejectionReason.ORIGIN_NOT_ALLOWED
        return None

    def _host_is_allowed(
        self,
        hostname: str,
        port: int | None,
        default_ports: frozenset[int],
    ) -> bool:
        for allowed_hostname, allowed_port in self._allowed_host_entries:
            if allowed_hostname != hostname:
                continue
            if (
                allowed_port is None
                or allowed_port == port
                or (port is None and allowed_port in default_ports)
            ):
                return True
        return False


# These aliases are intentionally public so callers can use the policy under
# the name that best describes their integration point.
OriginPolicy = ServerOriginPolicy
OriginValidationPolicy = ServerOriginPolicy
WebSocketOriginPolicy = ServerOriginPolicy
REJECTION_REASON_HEADER = WEBSOCKET_REJECT_REASON_HEADER


class H11Handshake:
    """A Handshake implementation for HTTP/1.1 connections."""

    def __init__(
        self,
        connection_type: ConnectionType,
        origin_policy: ServerOriginPolicy | None = None,
    ) -> None:
        self.client = connection_type is ConnectionType.CLIENT
        self._state = ConnectionState.CONNECTING
        self.origin_policy = origin_policy

        if self.client:
            self._h11_connection = h11.Connection(h11.CLIENT)
        else:
            self._h11_connection = h11.Connection(h11.SERVER)

        self._connection: Connection | None = None
        self._events: deque[Event] = deque()
        self._initiating_request: Request | None = None
        self._nonce: bytes | None = None

    @property
    def state(self) -> ConnectionState:
        return self._state

    @property
    def connection(self) -> Connection | None:
        """
        Return the established connection.

        This will either return the connection or raise a
        LocalProtocolError if the connection has not yet been
        established.

        :rtype: h11.Connection
        """
        return self._connection

    def initiate_upgrade_connection(
        self,
        headers: Headers,
        path: bytes | str,
        origin_policy: ServerOriginPolicy | None = None,
    ) -> None:
        """
        Initiate an upgrade connection.

        This should be used if the request has already be received and
        parsed.

        :param list headers: HTTP headers represented as a list of 2-tuples.
        :param str path: A URL path.
        :param origin_policy: Optional explicit server Origin/Host policy for
            this upgrade request, overriding any policy on the handshake.
        """
        if self.client:
            msg = "Cannot initiate an upgrade connection when acting as the client"
            raise LocalProtocolError(
                msg,
            )
        if origin_policy is not None:
            self.origin_policy = origin_policy
        if self.origin_policy is not None:
            self._check_policy_headers(headers)
        upgrade_request = h11.Request(method=b"GET", target=path, headers=headers)
        h11_client = h11.Connection(h11.CLIENT)
        self.receive_data(h11_client.send(upgrade_request))

    def send(self, event: Event) -> bytes:
        """
        Send an event to the remote.

        This will return the bytes to send based on the event or raise
        a LocalProtocolError if the event is not valid given the
        state.

        :returns: Data to send to the WebSocket peer.
        :rtype: bytes
        """
        data = b""
        if isinstance(event, Request):
            data += self._initiate_connection(event)
        elif isinstance(event, AcceptConnection):
            data += self._accept(event)
        elif isinstance(event, RejectConnection):
            data += self._reject(event)
        elif isinstance(event, RejectData):
            data += self._send_reject_data(event)
        else:
            msg = f"Event {event} cannot be sent during the handshake"
            raise LocalProtocolError(
                msg,
            )
        return data

    def receive_data(self, data: bytes | None) -> None:
        """
        Receive data from the remote.

        A list of events that the remote peer triggered by sending
        this data can be retrieved with :meth:`events`.

        :param bytes data: Data received from the WebSocket peer.
        """
        self._h11_connection.receive_data(data or b"")
        while True:
            try:
                event = self._h11_connection.next_event()
            except h11.RemoteProtocolError as exc:
                self._raise_bad_http(exc)
            if (
                isinstance(event, h11.ConnectionClosed)
                or event is h11.NEED_DATA
                or event is h11.PAUSED
            ):
                break

            if self.client:
                if isinstance(event, h11.InformationalResponse):
                    if event.status_code == 101:
                        self._events.append(self._establish_client_connection(event))
                    else:
                        self._events.append(
                            RejectConnection(
                                headers=list(event.headers),
                                status_code=event.status_code,
                                has_body=False,
                                reason_code=_reason_code_from_headers(
                                    event.headers,
                                ),
                            ),
                        )
                        self._state = ConnectionState.CLOSED
                elif isinstance(event, h11.Response):
                    self._state = ConnectionState.REJECTING
                    self._events.append(
                        RejectConnection(
                            headers=list(event.headers),
                            status_code=event.status_code,
                            has_body=True,
                            reason_code=_reason_code_from_headers(
                                event.headers,
                            ),
                        ),
                    )
                elif isinstance(event, h11.Data):
                    self._events.append(
                        RejectData(data=event.data, body_finished=False),
                    )
                elif isinstance(event, h11.EndOfMessage):
                    self._events.append(RejectData(data=b"", body_finished=True))
                    self._state = ConnectionState.CLOSED
            elif isinstance(event, h11.Request):
                self._events.append(self._process_connection_request(event))

    def events(self) -> Generator[Event, None, None]:
        """
        Return a generator that provides any events that have been generated
        by protocol activity.

        :returns: a generator that yields H11 events.
        """
        while self._events:
            yield self._events.popleft()

    # Server mode methods

    def _process_connection_request(
        self, event: h11.Request,
    ) -> Request:
        policy = self.origin_policy
        if policy is not None:
            self._check_policy_headers(event.headers)
        if event.method != b"GET":
            msg = "Request method must be GET"
            raise RemoteProtocolError(
                msg, event_hint=RejectConnection(),
            )
        connection_tokens = None
        extensions: list[str] = []
        host = None
        key = None
        origin_value = None
        proxy_host_value = None
        subprotocols: list[str] = []
        upgrade = b""
        version = None
        headers: Headers = []
        proxy_header_name = (
            policy.proxy_host_header.encode("ascii")
            if policy is not None and policy.proxy_host_header is not None
            else None
        )
        for name, value in event.headers:
            name = name.lower()
            if name == b"connection":
                connection_tokens = split_comma_header(value)
            elif name == b"host":
                try:
                    host = value.decode("idna")
                except UnicodeError:
                    if policy is not None:
                        self._reject_origin_policy(
                            OriginRejectionReason.INVALID_HOST,
                        )
                    raise
                continue  # Skip appending to headers
            elif name == b"sec-websocket-extensions":
                extensions.extend(split_comma_header(value))
                continue  # Skip appending to headers
            elif name == b"sec-websocket-key":
                key = value
            elif name == b"sec-websocket-protocol":
                subprotocols.extend(split_comma_header(value))
                continue  # Skip appending to headers
            elif name == b"sec-websocket-version":
                version = value
            elif name == b"upgrade":
                upgrade = value
            elif name == b"origin":
                origin_value = value
            elif (
                policy is not None
                and policy.trust_proxy_host
                and proxy_header_name is not None
                and name == proxy_header_name
            ):
                proxy_host_value = value
            headers.append((name, value))
        if connection_tokens is None or not any(
            token.lower() == "upgrade" for token in connection_tokens
        ):
            msg = "Missing header, 'Connection: Upgrade'"
            raise RemoteProtocolError(
                msg, event_hint=RejectConnection(),
            )
        if version != WEBSOCKET_VERSION:
            msg = "Missing header, 'Sec-WebSocket-Version'"
            raise RemoteProtocolError(
                msg,
                event_hint=RejectConnection(
                    headers=[(b"Sec-WebSocket-Version", WEBSOCKET_VERSION)],
                    status_code=426 if version else 400,
                ),
            )
        if key is None:
            msg = "Missing header, 'Sec-WebSocket-Key'"
            raise RemoteProtocolError(
                msg, event_hint=RejectConnection(),
            )
        if upgrade.lower() != WEBSOCKET_UPGRADE:
            msg = f"Missing header, 'Upgrade: {WEBSOCKET_UPGRADE.decode()}'"
            raise RemoteProtocolError(
                msg,
                event_hint=RejectConnection(),
            )
        if host is None:
            msg = "Missing header, 'Host'"
            raise RemoteProtocolError(
                msg, event_hint=RejectConnection(),
            )

        if policy is not None:
            host = self._apply_origin_policy(
                host,
                origin_value,
                proxy_host_value,
            )

        self._initiating_request = Request(
            extensions=extensions,
            extra_headers=headers,
            host=host,
            subprotocols=subprotocols,
            target=event.target.decode("ascii"),
        )
        return self._initiating_request

    def _apply_origin_policy(
        self,
        host: str,
        origin_value: bytes | None,
        proxy_host_value: bytes | None,
    ) -> str:
        policy = self.origin_policy
        assert policy is not None
        if policy.trust_proxy_host and proxy_host_value is not None:
            try:
                policy_host = proxy_host_value.decode("idna")
            except UnicodeError:
                self._reject_origin_policy(OriginRejectionReason.INVALID_HOST)
        else:
            policy_host = host

        if origin_value is None:
            origin = None
        else:
            try:
                origin = origin_value.decode("ascii")
            except UnicodeError:
                self._reject_origin_policy(OriginRejectionReason.INVALID_ORIGIN)

        reason_code = policy.validate(origin, policy_host)
        if reason_code is not None:
            self._reject_origin_policy(reason_code)
        return policy_host

    def _raise_bad_http(self, exc: h11.RemoteProtocolError) -> NoReturn:
        if self.origin_policy is not None and _is_duplicate_host_error(exc):
            self._reject_origin_policy(OriginRejectionReason.DUPLICATE_HOST)
        msg = "Bad HTTP message"
        raise RemoteProtocolError(msg, event_hint=RejectConnection()) from exc

    def _check_policy_headers(self, headers: Headers) -> None:
        assert self.origin_policy is not None
        values: dict[bytes, list[bytes]] = {}
        for raw_name, raw_value in headers:
            name = (
                raw_name.encode("latin-1")
                if isinstance(raw_name, str)
                else raw_name
            )
            value = (
                raw_value.encode("latin-1")
                if isinstance(raw_value, str)
                else raw_value
            )
            values.setdefault(name.lower(), []).append(value)

        origins = values.get(b"origin", [])
        if len(origins) > 1 or (origins and b"," in origins[0]):
            self._reject_origin_policy(OriginRejectionReason.DUPLICATE_ORIGIN)
        hosts = values.get(b"host", [])
        if len(hosts) > 1 or (hosts and b"," in hosts[0]):
            self._reject_origin_policy(OriginRejectionReason.DUPLICATE_HOST)
        if self.origin_policy.trust_proxy_host:
            proxy_header = self.origin_policy.proxy_host_header
            assert proxy_header is not None
            proxy_hosts = values.get(proxy_header.encode("ascii"), [])
            if len(proxy_hosts) > 1 or (proxy_hosts and b"," in proxy_hosts[0]):
                self._reject_origin_policy(
                    OriginRejectionReason.DUPLICATE_PROXY_HOST,
                )

    def _reject_origin_policy(self, reason_code: str) -> NoReturn:
        headers = [(WEBSOCKET_REJECT_REASON_HEADER, reason_code.encode("ascii"))]
        msg = f"Handshake rejected by server origin policy ({reason_code})"
        raise RemoteProtocolError(
            msg,
            event_hint=RejectConnection(
                status_code=403,
                headers=headers,
                reason_code=reason_code,
            ),
            reason_code=reason_code,
        )

    def _accept(self, event: AcceptConnection) -> bytes:
        # _accept is always called after _process_connection_request.
        assert self._initiating_request is not None
        request_headers = normed_header_dict(self._initiating_request.extra_headers)

        nonce = request_headers[b"sec-websocket-key"]
        accept_token = generate_accept_token(nonce)

        headers = [
            (b"Upgrade", WEBSOCKET_UPGRADE),
            (b"Connection", b"Upgrade"),
            (b"Sec-WebSocket-Accept", accept_token),
        ]

        if event.subprotocol is not None:
            if event.subprotocol not in self._initiating_request.subprotocols:
                msg = f"unexpected subprotocol {event.subprotocol}"
                raise LocalProtocolError(msg)
            headers.append(
                (b"Sec-WebSocket-Protocol", event.subprotocol.encode("ascii")),
            )

        if event.extensions:
            accepts = server_extensions_handshake(
                cast("Sequence[str]", self._initiating_request.extensions),
                event.extensions,
            )
            if accepts:
                headers.append((b"Sec-WebSocket-Extensions", accepts))

        response = h11.InformationalResponse(
            status_code=101,
            headers=headers + event.extra_headers,
            reason=b"Switching Protocols",
        )
        self._connection = Connection(
            ConnectionType.CLIENT if self.client else ConnectionType.SERVER,
            event.extensions,
        )
        self._state = ConnectionState.OPEN
        return self._h11_connection.send(response) or b""

    def _reject(self, event: RejectConnection) -> bytes:
        if self.state != ConnectionState.CONNECTING:
            msg = f"Connection cannot be rejected in state {self.state}"
            raise LocalProtocolError(
                msg,
            )

        headers = list(event.headers)
        if event.reason_code is not None and not any(
            name.lower() == WEBSOCKET_REJECT_REASON_HEADER
            for name, _ in headers
        ):
            headers.append(
                (WEBSOCKET_REJECT_REASON_HEADER, event.reason_code.encode("ascii")),
            )
        if not event.has_body:
            headers.append((b"content-length", b"0"))
        response = h11.Response(status_code=event.status_code, headers=headers)
        data = self._h11_connection.send(response) or b""
        self._state = ConnectionState.REJECTING
        if not event.has_body:
            data += self._h11_connection.send(h11.EndOfMessage()) or b""
            self._state = ConnectionState.CLOSED
        return data

    def _send_reject_data(self, event: RejectData) -> bytes:
        if self.state != ConnectionState.REJECTING:
            msg = f"Cannot send rejection data in state {self.state}"
            raise LocalProtocolError(
                msg,
            )

        data = self._h11_connection.send(h11.Data(data=event.data)) or b""
        if event.body_finished:
            data += self._h11_connection.send(h11.EndOfMessage()) or b""
            self._state = ConnectionState.CLOSED
        return data

    # Client mode methods

    def _initiate_connection(self, request: Request) -> bytes:
        self._initiating_request = request
        self._nonce = generate_nonce()

        headers = [
            (b"Host", request.host.encode("idna")),
            (b"Upgrade", WEBSOCKET_UPGRADE),
            (b"Connection", b"Upgrade"),
            (b"Sec-WebSocket-Key", self._nonce),
            (b"Sec-WebSocket-Version", WEBSOCKET_VERSION),
        ]

        if request.subprotocols:
            headers.append(
                (
                    b"Sec-WebSocket-Protocol",
                    (", ".join(request.subprotocols)).encode("ascii"),
                ),
            )

        if request.extensions:
            offers: dict[str, str | bool] = {}
            for e in request.extensions:
                assert isinstance(e, Extension)
                offers[e.name] = e.offer()
            extensions = []
            for name, params in offers.items():
                bname = name.encode("ascii")
                if isinstance(params, bool):
                    if params:
                        extensions.append(bname)
                else:
                    extensions.append(b"%s; %s" % (bname, params.encode("ascii")))
            if extensions:
                headers.append((b"Sec-WebSocket-Extensions", b", ".join(extensions)))

        upgrade = h11.Request(
            method=b"GET",
            target=request.target.encode("ascii"),
            headers=headers + request.extra_headers,
        )
        return self._h11_connection.send(upgrade) or b""

    def _establish_client_connection(
        self, event: h11.InformationalResponse,
    ) -> AcceptConnection:
        # _establish_client_connection is always called after _initiate_connection.
        assert self._initiating_request is not None
        assert self._nonce is not None

        accept = None
        connection_tokens = None
        accepts: list[str] = []
        subprotocol = None
        upgrade = b""
        headers: Headers = []
        for name, value in event.headers:
            name = name.lower()
            if name == b"connection":
                connection_tokens = split_comma_header(value)
                continue  # Skip appending to headers
            if name == b"sec-websocket-extensions":
                accepts = split_comma_header(value)
                continue  # Skip appending to headers
            if name == b"sec-websocket-accept":
                accept = value
                continue  # Skip appending to headers
            if name == b"sec-websocket-protocol":
                subprotocol = value.decode("ascii")
                continue  # Skip appending to headers
            if name == b"upgrade":
                upgrade = value
                continue  # Skip appending to headers
            headers.append((name, value))

        if connection_tokens is None or not any(
            token.lower() == "upgrade" for token in connection_tokens
        ):
            msg = "Missing header, 'Connection: Upgrade'"
            raise RemoteProtocolError(
                msg, event_hint=RejectConnection(),
            )
        if upgrade.lower() != WEBSOCKET_UPGRADE:
            msg = f"Missing header, 'Upgrade: {WEBSOCKET_UPGRADE.decode()}'"
            raise RemoteProtocolError(
                msg,
                event_hint=RejectConnection(),
            )
        accept_token = generate_accept_token(self._nonce)
        if accept != accept_token:
            msg = "Bad accept token"
            raise RemoteProtocolError(msg, event_hint=RejectConnection())
        if subprotocol is not None and subprotocol not in self._initiating_request.subprotocols:
            msg = f"unrecognized subprotocol {subprotocol}"
            raise RemoteProtocolError(
                msg,
                event_hint=RejectConnection(),
            )
        extensions = client_extensions_handshake(
            accepts, cast("Sequence[Extension]", self._initiating_request.extensions),
        )

        self._connection = Connection(
            ConnectionType.CLIENT if self.client else ConnectionType.SERVER,
            extensions,
            self._h11_connection.trailing_data[0],
        )
        self._state = ConnectionState.OPEN
        return AcceptConnection(
            extensions=extensions, extra_headers=headers, subprotocol=subprotocol,
        )

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(client={self.client}, state={self.state})"


def server_extensions_handshake(
    requested: Iterable[str], supported: list[Extension],
) -> bytes | None:
    """
    Agree on the extensions to use returning an appropriate header value.

    This returns None if there are no agreed extensions
    """
    accepts: dict[str, bool | bytes] = {}
    for offer in requested:
        name = offer.split(";", 1)[0].strip()
        for extension in supported:
            if extension.name == name:
                accept = extension.accept(offer)
                if isinstance(accept, bool):
                    if accept:
                        accepts[extension.name] = True
                elif accept is not None:
                    accepts[extension.name] = accept.encode("ascii")

    if accepts:
        extensions: list[bytes] = []
        for name, params in accepts.items():
            name_bytes = name.encode("ascii")
            if isinstance(params, bool):
                assert params
                extensions.append(name_bytes)
            elif params == b"":
                extensions.append(b"%s" % (name_bytes))
            else:
                extensions.append(b"%s; %s" % (name_bytes, params))
        return b", ".join(extensions)

    return None


def client_extensions_handshake(
    accepted: Iterable[str], supported: Sequence[Extension],
) -> list[Extension]:
    # This raises RemoteProtocolError is the accepted extension is not
    # supported.
    extensions = []
    for accept in accepted:
        name = accept.split(";", 1)[0].strip()
        for extension in supported:
            if extension.name == name:
                extension.finalize(accept)
                extensions.append(extension)
                break
        else:
            msg = f"unrecognized extension {name}"
            raise RemoteProtocolError(
                msg, event_hint=RejectConnection(),
            )
    return extensions
