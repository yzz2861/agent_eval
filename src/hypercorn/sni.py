from __future__ import annotations

import re
import threading
from collections.abc import Iterable
from dataclasses import dataclass
from ssl import SSLContext, SSLError, SSLObject, SSLSocket
from typing import Callable


class CertificateError(ValueError):
    """Raised when a certificate, key, or domain rule is invalid."""


@dataclass
class Certificate:
    """A certificate chain and the key required to serve it."""

    certfile: str
    keyfile: str | None = None
    password: str | None = None


_LABEL_RE = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)\Z")


def _validate_domain(domain: str) -> tuple[str, str]:
    """Validate a domain rule, returning its kind and normalised form.

    Exact domains are returned as ``("exact", name)`` and single level
    wildcards such as ``*.example.com`` as ``("wildcard", "example.com")``.
    """
    if not isinstance(domain, str):
        raise CertificateError(f"Invalid domain rule {domain!r}")
    name = domain.rstrip(".").lower()
    if name.startswith("*."):
        kind, name = "wildcard", name[2:]
    elif "*" in name:
        raise CertificateError(
            f"Invalid domain rule {domain!r}, wildcards must be a complete left-most label"
        )
    else:
        kind = "exact"
    if not name or any(_LABEL_RE.match(label) is None for label in name.split(".")):
        raise CertificateError(f"Invalid domain rule {domain!r}")
    return kind, name


class _CertificateGroup:
    """An immutable set of contexts to select between based on the SNI."""

    def __init__(
        self,
        default: SSLContext,
        exact: dict[str, SSLContext],
        wildcard: dict[str, SSLContext],
    ) -> None:
        self.default = default
        self.exact = exact
        self.wildcard = wildcard

    def select(self, server_name: str | None) -> SSLContext:
        if server_name:
            name = server_name.rstrip(".").lower()
            context = self.exact.get(name)
            if context is not None:
                return context
            if "." in name:
                # Wildcards match a single label only, so strip the
                # left-most label before looking the suffix up.
                context = self.wildcard.get(name.split(".", 1)[1])
                if context is not None:
                    return context
        return self.default


class CertificateStore:
    """A group of certificates selected by SNI, reloadable as a unit.

    The ``context_factory`` must return contexts configured with the
    desired policy (ciphers, ALPN protocols, verification, ...) but
    without a certificate chain. It is used for every certificate so
    that selecting a certificate never alters the TLS policy.
    """

    def __init__(self, context_factory: Callable[[], SSLContext]) -> None:
        self._context_factory = context_factory
        self._lock = threading.Lock()
        # The base context is served by the event loop directly and is
        # used for handshakes that do not send a SNI extension.
        self.context = context_factory()
        self._group: _CertificateGroup | None = None

    def reload(
        self,
        default: Certificate,
        certificates: Iterable[tuple[str, Certificate]] = (),
    ) -> None:
        """Atomically replace the whole group of certificates.

        Every certificate, key, and domain rule is validated before
        anything is applied; if any is invalid a ``CertificateError``
        is raised and the current group keeps serving unchanged.
        """
        group = self._build_group(default, certificates)
        with self._lock:
            # Refresh the base context so that clients not sending a
            # SNI extension also see the new default certificate. This
            # cannot fail as the chain was validated above, and does
            # not affect established connections.
            self.context.load_cert_chain(default.certfile, default.keyfile, default.password)
            self._group = group

    def select(self, server_name: str | None) -> SSLContext:
        """Return the context to serve for the given SNI server name."""
        group = self._group
        if group is None:
            return self.context
        return group.select(server_name)

    def sni_callback(
        self, ssl_object: SSLSocket | SSLObject, server_name: str | None, context: SSLContext
    ) -> None:
        group = self._group
        if group is not None:
            ssl_object.context = group.select(server_name)

    def _build_group(
        self,
        default: Certificate,
        certificates: Iterable[tuple[str, Certificate]],
    ) -> _CertificateGroup:
        default_context = self._load(default)
        exact: dict[str, SSLContext] = {}
        wildcard: dict[str, SSLContext] = {}
        for domain, certificate in certificates:
            kind, name = _validate_domain(domain)
            target = exact if kind == "exact" else wildcard
            if name in target:
                raise CertificateError(f"Duplicate domain rule {domain!r}")
            target[name] = self._load(certificate)
        return _CertificateGroup(default_context, exact, wildcard)

    def _load(self, certificate: Certificate) -> SSLContext:
        context = self._context_factory()
        try:
            context.load_cert_chain(
                certificate.certfile, certificate.keyfile, certificate.password
            )
        except (OSError, SSLError) as error:
            raise CertificateError(
                f"Cannot load certificate {certificate.certfile!r}: {error}"
            ) from error
        return context
