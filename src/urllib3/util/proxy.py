from __future__ import annotations

import base64
import dataclasses
import hashlib
import os
import re
import typing

from .url import Url, parse_url

if typing.TYPE_CHECKING:
    from ..connection import ProxyConfig

#: Headers that are only meaningful between the client and the proxy. They
#: must never be forwarded through a CONNECT tunnel to the target origin.
PROXY_ONLY_HEADER_NAMES = frozenset(
    {"proxy-authorization", "proxy-authenticate", "proxy-connection"}
)

#: Headers that carry target-origin credentials. They must never be sent to
#: the proxy, neither in the CONNECT request nor in forwarded requests.
TARGET_AUTH_HEADER_NAMES = frozenset({"authorization"})

_PROXY_AUTH_SCHEMES = ("basic", "digest")

#: Matches the boundary between authentication challenges inside a
#: ``Proxy-Authenticate`` header value, i.e. the start of the value or a
#: comma followed by a scheme token and whitespace.
_AUTH_CHALLENGE_RE = re.compile(r"(?:^|,)\s*([A-Za-z][A-Za-z0-9_-]*)\s+")

_AUTH_PARAM_RE = re.compile(
    r'([A-Za-z][A-Za-z0-9_-]*)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^,\s]+))'
)

_SUPPORTED_DIGEST_ALGORITHMS = {
    "MD5": "md5",
    "SHA-256": "sha256",
    "SHA-512-256": "sha512_256",
}


def connection_requires_http_tunnel(
    proxy_url: Url | None = None,
    proxy_config: ProxyConfig | None = None,
    destination_scheme: str | None = None,
) -> bool:
    """
    Returns True if the connection requires an HTTP CONNECT through the proxy.

    :param URL proxy_url:
        URL of the proxy.
    :param ProxyConfig proxy_config:
        Proxy configuration from poolmanager.py
    :param str destination_scheme:
        The scheme of the destination. (i.e https, http, etc)
    """
    # If we're not using a proxy, no way to use a tunnel.
    if proxy_url is None:
        return False

    # HTTP destinations never require tunneling, we always forward.
    if destination_scheme == "http":
        return False

    # Support for forwarding with HTTPS proxies and HTTPS destinations.
    if (
        proxy_url.scheme == "https"
        and proxy_config
        and proxy_config.use_forwarding_for_https
    ):
        return False

    # Otherwise always use a tunnel.
    return True


def strip_proxy_headers(
    headers: typing.Mapping[str, str],
) -> dict[str, str]:
    """
    Return a copy of ``headers`` without proxy-specific headers.

    Used once a CONNECT tunnel is established so that headers such as
    ``Proxy-Authorization`` are not leaked to the target origin.
    """
    return {
        header: value
        for header, value in headers.items()
        if header.lower() not in PROXY_ONLY_HEADER_NAMES
    }


def strip_target_auth_headers(
    headers: typing.Mapping[str, str],
) -> dict[str, str]:
    """
    Return a copy of ``headers`` without target-origin credential headers.

    Used when building the CONNECT request so that target credentials such
    as an ``Authorization: Bearer ...`` header are never sent to the proxy.
    """
    return {
        header: value
        for header, value in headers.items()
        if header.lower() not in TARGET_AUTH_HEADER_NAMES
    }


def redact_url_userinfo(url: Url | str | None) -> str | None:
    """
    Return ``url`` as a string with any userinfo (``user:password@``) removed.

    Used for URLs that end up in logs, exception messages and redirect
    history so that credentials are never persisted or displayed.
    """
    if url is None:
        return None
    if isinstance(url, Url):
        if url.auth is None:
            return url.url
        return url._replace(auth=None).url
    try:
        parsed = parse_url(url)
    except Exception:
        # If the URL can't be parsed, fall back to scrubbing anything that
        # looks like userinfo rather than risking a credential leak.
        return re.sub(r"(://)[^/@]*@", r"\1", url)
    if parsed.auth is None:
        return url
    return parsed._replace(auth=None).url


def _parse_auth_params(value: str) -> dict[str, str]:
    """Parse the ``key=value`` parameter list of an auth challenge."""
    params: dict[str, str] = {}
    for match in _AUTH_PARAM_RE.finditer(value):
        key = match.group(1).lower()
        quoted, token = match.group(2), match.group(3)
        if quoted is not None:
            params[key] = quoted.replace('\\"', '"').replace("\\\\", "\\")
        else:
            params[key] = token
    return params


def _split_challenges(value: str) -> list[tuple[str, str]]:
    """
    Split a ``Proxy-Authenticate`` header value into individual
    ``(scheme, params)`` challenges.
    """
    stripped = value.strip()
    if re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", stripped):
        # A lone scheme token with no parameters, e.g. "Basic".
        return [(stripped.lower(), "")]
    challenges: list[tuple[str, str]] = []
    matches = list(_AUTH_CHALLENGE_RE.finditer(value))
    for index, match in enumerate(matches):
        scheme = match.group(1).lower()
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(value)
        challenges.append((scheme, value[start:end].strip().rstrip(",")))
    return challenges


def _quote_digest_value(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


@dataclasses.dataclass(frozen=True)
class ProxyAuthStrategy:
    """
    Explicit proxy authentication policy for HTTP CONNECT tunnels.

    The strategy is immutable configuration; per-connection challenge state
    (nonces, nonce counts, attempt counters) is tracked by a dedicated
    session created with :meth:`create_session` when the CONNECT handshake
    starts. ``Proxy-Authorization`` headers are only ever generated from the
    credentials held by this object, never from request headers.

    :param username:
        Decoded proxy username. May contain ``@`` and other special
        characters.
    :param password:
        Decoded proxy password. May contain control characters.
    :param scheme:
        Authentication scheme to use: ``"basic"`` or ``"digest"``. The
        scheme is never negotiated down; a 407 challenge for a different
        scheme is treated as an error.
    :param max_challenge_responses:
        Maximum number of 407 challenges that will be answered while
        establishing a single tunnel. Bounds the CONNECT retry loop.
    """

    username: str
    password: str = ""
    scheme: str = "basic"
    max_challenge_responses: int = 2

    def __post_init__(self) -> None:
        scheme = self.scheme.lower()
        if scheme not in _PROXY_AUTH_SCHEMES:
            raise ValueError(
                f"Unsupported proxy auth scheme: {self.scheme!r}. "
                f"Expected one of {_PROXY_AUTH_SCHEMES}."
            )
        object.__setattr__(self, "scheme", scheme)
        if self.max_challenge_responses < 0:
            raise ValueError("max_challenge_responses must be >= 0")

    def __repr__(self) -> str:
        # Credentials are never included in the repr so that tracebacks and
        # logs don't leak them.
        return (
            f"{type(self).__name__}(scheme={self.scheme!r}, "
            f"username='***', password='***')"
        )

    @classmethod
    def from_url(
        cls,
        proxy_url: Url,
        scheme: str = "basic",
        max_challenge_responses: int = 2,
    ) -> ProxyAuthStrategy | None:
        """
        Build a strategy from the userinfo of a proxy URL, or ``None`` if
        the URL carries no username. Percent-encoded userinfo is decoded.
        """
        username, password = proxy_url.auth_decoded
        if username is None:
            return None
        return cls(
            username=username,
            password=password or "",
            scheme=scheme,
            max_challenge_responses=max_challenge_responses,
        )

    def create_session(self) -> ProxyAuthSession:
        """Create fresh per-connection challenge state for this strategy."""
        return ProxyAuthSession(self)


class ProxyAuthSession:
    """
    Mutable challenge state for a single CONNECT handshake.

    A new session is created for every tunnel establishment so that Digest
    nonces and attempt counters never leak across connections.
    """

    def __init__(self, strategy: ProxyAuthStrategy) -> None:
        self._strategy = strategy
        self._challenges_answered = 0
        self._digest_params: dict[str, str] | None = None
        self._cnonce = ""
        self._nonce_count = 0

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(scheme={self._strategy.scheme!r}, "
            f"challenges_answered={self._challenges_answered})"
        )

    @property
    def challenges_answered(self) -> int:
        return self._challenges_answered

    def proxy_authorization_header(self, method: str, uri: str) -> str | None:
        """
        Generate the ``Proxy-Authorization`` header value for a CONNECT
        request, or ``None`` if a challenge is required first (Digest
        before the first 407).
        """
        strategy = self._strategy
        if strategy.scheme == "basic":
            user_pass = f"{strategy.username}:{strategy.password}".encode("latin-1")
            return "Basic " + base64.b64encode(user_pass).decode("ascii")
        if self._digest_params is None:
            return None
        return self._digest_header(method, uri)

    def handle_challenge(self, authenticate_values: typing.Iterable[str]) -> bool:
        """
        Process the ``Proxy-Authenticate`` headers of a 407 response.

        Returns ``True`` if another CONNECT attempt should be made, i.e. the
        challenge matches the configured scheme, is well-formed, and the
        retry budget hasn't been exhausted. Returns ``False`` for unknown,
        malformed, or repeated-beyond-limit challenges so callers fail
        instead of looping.
        """
        if self._challenges_answered >= self._strategy.max_challenge_responses:
            return False
        challenges: list[tuple[str, str]] = []
        for value in authenticate_values:
            challenges.extend(_split_challenges(value))
        matching = [
            params for scheme, params in challenges if scheme == self._strategy.scheme
        ]
        if not matching:
            # The proxy only offered schemes we didn't configure. Retrying
            # would produce the same 407 forever.
            return False
        if self._strategy.scheme == "digest":
            params = _parse_auth_params(matching[0])
            if not params.get("nonce"):
                # Malformed Digest challenge, can't proceed.
                return False
            algorithm = params.get("algorithm", "MD5").upper()
            if algorithm not in _SUPPORTED_DIGEST_ALGORITHMS:
                return False
            qop_options = [
                qop.strip() for qop in params.get("qop", "").split(",") if qop.strip()
            ]
            if qop_options and "auth" not in qop_options:
                # Only 'auth' is supported; fail instead of looping.
                return False
            self._digest_params = params
            self._cnonce = os.urandom(8).hex()
            self._nonce_count = 0
        self._challenges_answered += 1
        return True

    def _digest_header(self, method: str, uri: str) -> str:
        strategy = self._strategy
        params = self._digest_params or {}
        realm = params.get("realm", "")
        nonce = params["nonce"]
        algorithm = params.get("algorithm", "MD5").upper()
        hash_name = _SUPPORTED_DIGEST_ALGORITHMS[algorithm]

        def hash_hex(value: str) -> str:
            return hashlib.new(hash_name, value.encode("utf-8")).hexdigest()

        ha1 = hash_hex(f"{strategy.username}:{realm}:{strategy.password}")
        ha2 = hash_hex(f"{method}:{uri}")

        qop_options = [
            qop.strip() for qop in params.get("qop", "").split(",") if qop.strip()
        ]
        fields: list[tuple[str, str, bool]] = [
            ("username", strategy.username, True),
            ("realm", realm, True),
            ("nonce", nonce, True),
            ("uri", uri, True),
        ]
        if qop_options:
            if "auth" not in qop_options:
                # Only 'auth' is supported; fail closed rather than sending
                # a response the proxy can't validate.
                raise ValueError(
                    f"Unsupported qop in Digest challenge: {params.get('qop')!r}"
                )
            self._nonce_count += 1
            nonce_count = f"{self._nonce_count:08x}"
            response = hash_hex(
                f"{ha1}:{nonce}:{nonce_count}:{self._cnonce}:auth:{ha2}"
            )
            fields.extend(
                [
                    ("response", response, False),
                    ("algorithm", algorithm, False),
                    ("qop", "auth", False),
                    ("nc", nonce_count, False),
                    ("cnonce", self._cnonce, True),
                ]
            )
        else:
            response = hash_hex(f"{ha1}:{nonce}:{ha2}")
            fields.extend(
                [
                    ("response", response, False),
                    ("algorithm", algorithm, False),
                ]
            )
        if params.get("opaque") is not None:
            fields.append(("opaque", params["opaque"], True))

        rendered = ", ".join(
            f"{key}={_quote_digest_value(value) if quoted else value}"
            for key, value, quoted in fields
        )
        return f"Digest {rendered}"
