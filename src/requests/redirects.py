"""Configurable security policy for HTTP redirects."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast
from urllib.parse import urlparse

from .exceptions import (
    RedirectBodyError,
    RedirectSecurityError,
    UnrewindableBodyError,
)
from .status_codes import codes
from .utils import DEFAULT_PORTS, rewind_body, super_len

if TYPE_CHECKING:
    from .models import PreparedRequest, Response

SENSITIVE_REDIRECT_HEADERS = frozenset(
    (
        "Authorization",
        "Proxy-Authorization",
        "Cookie",
    )
)


def _encode_idna_host(host: str | None) -> str | None:
    if host is None:
        return None

    try:
        host.encode("ascii")
        return host.lower()
    except UnicodeEncodeError:
        import idna

        return idna.encode(host, uts46=True).decode("ascii").lower()


def _default_port(scheme: str, port: int | None) -> int | None:
    return port or DEFAULT_PORTS.get(scheme.lower())


@dataclass
class RedirectPolicy:
    """Controls credentials, origins, and bodies while following redirects."""

    allow_http_downgrade: bool = False
    trusted_hosts: Sequence[str] = ()
    sensitive_headers: Sequence[str] = SENSITIVE_REDIRECT_HEADERS
    max_redirect_body_size: int | None = 1024 * 1024
    allow_body_replay: bool = False

    def __post_init__(self) -> None:
        if isinstance(self.trusted_hosts, str):
            raise TypeError("trusted_hosts must be a sequence of host names")
        if isinstance(self.sensitive_headers, str):
            raise TypeError("sensitive_headers must be a sequence of header names")

        normalized_hosts = []
        for host in self.trusted_hosts:
            try:
                normalized_hosts.append(_encode_idna_host(host.lower()))
            except UnicodeError:
                continue
        self.trusted_hosts = tuple(host for host in normalized_hosts if host)
        self.sensitive_headers = frozenset(
            header.lower() for header in self.sensitive_headers
        )

    def is_trusted_host(self, url: str) -> bool:
        host = _encode_idna_host(urlparse(url).hostname)
        return host is not None and any(
            host == trusted or host.endswith(f".{trusted}")
            for trusted in self.trusted_hosts
        )

    def is_same_origin(self, old_url: str, new_url: str) -> bool:
        old = urlparse(old_url)
        new = urlparse(new_url)
        return (
            old.scheme.lower() == new.scheme.lower()
            and _encode_idna_host(old.hostname) == _encode_idna_host(new.hostname)
            and _default_port(old.scheme, old.port)
            == _default_port(new.scheme, new.port)
        )

    def should_strip_credentials(self, old_url: str, new_url: str) -> bool:
        return not self.is_same_origin(old_url, new_url) and not self.is_trusted_host(
            new_url
        )

    def sensitive_header_names(self) -> frozenset[str]:
        return SENSITIVE_REDIRECT_HEADERS | self.sensitive_headers

    def rewrites_method_to_get(self, status_code: int, method: str) -> bool:
        if method == "HEAD":
            return False
        if status_code == codes.see_other:
            return True
        return status_code in (codes.moved, codes.found) and method == "POST"

    def validate_redirect(
        self,
        status_code: int,
        old_url: str,
        new_url: str,
        prepared_request: PreparedRequest,
        response: Response | None = None,
    ) -> None:
        old = urlparse(old_url)
        new = urlparse(new_url)

        if (
            old.scheme.lower() == "https"
            and new.scheme.lower() == "http"
            and not self.allow_http_downgrade
        ):
            raise RedirectSecurityError(
                f"Refusing to follow HTTPS to HTTP redirect from {old_url!r} "
                f"to {new_url!r}.",
                response=response,
                request=prepared_request,
            )

        if status_code in (
            codes.moved,
            codes.found,
            codes.see_other,
        ) and self.rewrites_method_to_get(
            status_code,
            cast(str, getattr(prepared_request, "method", "")),
        ):
            return

        body = getattr(prepared_request, "body", None)
        if body is None:
            return

        length = super_len(body)
        headers = getattr(prepared_request, "headers", {})
        content_length = headers.get("Content-Length")
        if content_length is not None:
            try:
                length = int(content_length)
            except (TypeError, ValueError):
                length = super_len(body)

        if (
            self.max_redirect_body_size is not None
            and length > self.max_redirect_body_size
        ):
            raise RedirectBodyError(
                f"Refusing to replay a {length}-byte request body for {status_code} "
                f"redirect from {old_url!r} to {new_url!r}; limit is "
                f"{self.max_redirect_body_size} bytes.",
                response=response,
                request=prepared_request,
            )

        if "Transfer-Encoding" in headers:
            if self.allow_body_replay:
                return
            raise RedirectBodyError(
                f"Refusing to replay a chunked request body for {status_code} "
                f"redirect from {old_url!r} to {new_url!r}.",
                response=response,
                request=prepared_request,
            )

        if isinstance(body, (str, bytes, bytearray)):
            return

        if getattr(prepared_request, "_body_position", None) is None:
            raise RedirectBodyError(
                f"Refusing to replay an unrewindable request body for {status_code} "
                f"redirect from {old_url!r} to {new_url!r}.",
                response=response,
                request=prepared_request,
            )

        try:
            rewind_body(prepared_request)  # type: ignore[arg-type]
        except UnrewindableBodyError as exc:
            raise RedirectBodyError(
                f"Refusing to replay an unrewindable request body for {status_code} "
                f"redirect from {old_url!r} to {new_url!r}.",
                response=response,
                request=prepared_request,
            ) from exc
