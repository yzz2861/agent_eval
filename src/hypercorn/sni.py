from __future__ import annotations

import ssl
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

__all__ = ("CertificateGroup", "CertificateSpec")

DEFAULT_CERTIFICATE = "certificate"
DEFAULT_REJECT = "reject"
DEFAULT_POLICIES = (DEFAULT_CERTIFICATE, DEFAULT_REJECT)


@dataclass
class CertificateSpec:
    """A certificate and the key material required to serve it."""

    certfile: str
    keyfile: str | None = None
    password: str | None = None

    @classmethod
    def from_value(cls, value: Any) -> "CertificateSpec":
        if isinstance(value, CertificateSpec):
            return value
        elif isinstance(value, str):
            return cls(certfile=value)
        elif isinstance(value, Mapping):
            try:
                return cls(
                    certfile=value["certfile"],
                    keyfile=value.get("keyfile"),
                    password=value.get("password"),
                )
            except KeyError:
                raise ValueError(f"Invalid certificate specification {value!r}")
        elif isinstance(value, (tuple, list)) and 1 <= len(value) <= 3:
            return cls(*value)
        raise ValueError(f"Invalid certificate specification {value!r}")


def _normalise_domain(domain: Any) -> str:
    if not isinstance(domain, str):
        raise ValueError(f"Invalid domain {domain!r}")
    domain = domain.lower()
    if domain.endswith("."):
        domain = domain[:-1]
    wildcard = domain.startswith("*.")
    host = domain[2:] if wildcard else domain
    if not host or "*" in host:
        raise ValueError(f"Invalid domain {domain!r}")
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError(f"Invalid domain {domain!r}")
    for label in ascii_host.split("."):
        if (
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not all(char.isascii() and (char.isalnum() or char == "-") for char in label)
        ):
            raise ValueError(f"Invalid domain {domain!r}")
    return f"*.{ascii_host}" if wildcard else ascii_host


class CertificateGroup:
    """A group of certificates selected by SNI, reloadable as a unit.

    The group maps domains (exact names such as ``example.com`` or
    single-level wildcards such as ``*.example.com``) to certificates.
    Reloading validates the whole new group before it takes effect, so
    a single invalid certificate, key, or domain rule leaves the
    previous group serving. New handshakes see the reloaded group,
    whilst established connections continue with the certificates they
    negotiated.
    """

    def __init__(
        self,
        certificates: Mapping[str, Any],
        *,
        default: str = DEFAULT_CERTIFICATE,
        context_factory: Callable[[], ssl.SSLContext],
        has_default_certificate: bool,
    ) -> None:
        self._context_factory = context_factory
        self._has_default_certificate = has_default_certificate
        self._certificates: dict[str, CertificateSpec] = {}
        self._default = DEFAULT_CERTIFICATE
        self._contexts: dict[str, ssl.SSLContext] = {}
        self.reload(certificates, default=default)

    @property
    def certificates(self) -> dict[str, CertificateSpec]:
        return dict(self._certificates)

    @property
    def default(self) -> str:
        return self._default

    def reload(
        self,
        certificates: Mapping[str, Any] | None = None,
        *,
        default: str | None = None,
    ) -> None:
        """Atomically replace the whole group of certificates.

        Raises if any certificate, key, or domain rule is invalid, in
        which case the current group is left untouched.
        """
        if certificates is None:
            certificates = self._certificates
        if default is None:
            default = self._default
        if default not in DEFAULT_POLICIES:
            raise ValueError(
                f"Invalid default policy {default!r}, expected one of {DEFAULT_POLICIES}"
            )
        if default == DEFAULT_CERTIFICATE and not self._has_default_certificate:
            raise ValueError(
                'The "certificate" default policy requires certfile and keyfile'
            )

        specs: dict[str, CertificateSpec] = {}
        for domain, value in certificates.items():
            normalised = _normalise_domain(domain)
            if normalised in specs:
                raise ValueError(f"Duplicate domain {normalised!r}")
            specs[normalised] = CertificateSpec.from_value(value)

        contexts: dict[str, ssl.SSLContext] = {}
        for domain, spec in specs.items():
            context = self._context_factory()
            context.load_cert_chain(
                certfile=spec.certfile, keyfile=spec.keyfile, password=spec.password
            )
            contexts[domain] = context

        self._certificates = specs
        self._default = default
        self._contexts = contexts

    def attach(self, context: ssl.SSLContext) -> ssl.SSLContext:
        """Select certificates from this group for handshakes on the context."""
        context.set_servername_callback(self._select_context)
        return context

    def _select_context(
        self,
        sslobj: ssl.SSLObject | ssl.SSLSocket,
        server_name: str | None,
        context: ssl.SSLContext,
    ) -> int | None:
        if server_name is not None:
            name = server_name.lower()
            if name.endswith("."):
                name = name[:-1]
            selected = self._contexts.get(name)
            if selected is None:
                parts = name.split(".", 1)
                if len(parts) == 2:
                    selected = self._contexts.get(f"*.{parts[1]}")
            if selected is not None:
                sslobj.context = selected
                return None
        if self._default == DEFAULT_REJECT:
            return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
        return None
