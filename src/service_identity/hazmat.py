"""
Common verification code.
"""

from __future__ import annotations

import ipaddress
import re

from collections.abc import Iterable, Sequence
from typing import Protocol, runtime_checkable

import attr

from .exceptions import (
    CertificateError,
    DNSMismatch,
    IPAddressMismatch,
    Mismatch,
    SRVMismatch,
    URIMismatch,
    VerificationError,
)


try:
    import idna
except ImportError:
    idna = None  # type: ignore[assignment]


@attr.s(slots=True)
class ServiceMatch:
    """
    A match of a service id and a certificate pattern.
    """

    service_id: ServiceID = attr.ib()
    cert_pattern: CertificatePattern = attr.ib()


def verify_service_identity(
    cert_patterns: Sequence[CertificatePattern],
    obligatory_ids: Sequence[ServiceID],
    optional_ids: Sequence[ServiceID],
) -> list[ServiceMatch]:
    """
    Verify whether *cert_patterns* are valid for *obligatory_ids* and
    *optional_ids*.

    *obligatory_ids* must be both present and match.  *optional_ids* must match
    if a pattern of the respective type is present.
    """
    if not cert_patterns:
        msg = "Certificate does not contain any `subjectAltName`s."
        raise CertificateError(msg)

    errors = []
    matches = _find_matches(cert_patterns, obligatory_ids) + _find_matches(
        cert_patterns, optional_ids
    )

    matched_ids = [match.service_id for match in matches]
    for i in obligatory_ids:
        if i not in matched_ids:
            errors.append(i.mismatch(cert_patterns))  # noqa: PERF401

    for i in optional_ids:
        # If an optional ID is not matched by a certificate pattern *but* there
        # is a pattern of the same type , it is an error and the verification
        # fails.  Example: the user passes a SRV-ID for "_mail.domain.com" but
        # the certificate contains an SRV-Pattern for "_xmpp.domain.com".
        if i not in matched_ids and _contains_instance_of(
            cert_patterns, i.pattern_class
        ):
            errors.append(i.mismatch(cert_patterns))  # noqa: PERF401

    if errors:
        raise VerificationError(errors=errors)

    return matches


def _find_matches(
    cert_patterns: Sequence[CertificatePattern],
    service_ids: Sequence[ServiceID],
) -> list[ServiceMatch]:
    """
    Search for matching certificate patterns and service_ids.

    Args:
        service_ids: List of service IDs like DNS_ID.
    """
    matches = []
    for sid in service_ids:
        for cid in cert_patterns:
            if sid.verify(cid):
                matches.append(  # noqa: PERF401
                    ServiceMatch(cert_pattern=cid, service_id=sid)
                )

    return matches


def _contains_instance_of(seq: Sequence[object], cl: type) -> bool:
    return any(isinstance(e, cl) for e in seq)


def _is_ip_address(pattern: str | bytes) -> bool:
    """
    Check whether *pattern* could be/match an IP address.

    Args:
        pattern: A pattern for a host name.

    Returns:
        `True` if *pattern* could be an IP address, else `False`.
    """
    if isinstance(pattern, bytes):
        try:
            pattern = pattern.decode("ascii")
        except UnicodeError:
            return False

    try:
        int(pattern)
    except ValueError:
        pass
    else:
        return True

    try:
        ipaddress.ip_address(pattern.replace("*", "1"))
    except ValueError:
        return False

    return True


@attr.s(slots=True)
class DNSPattern:
    """
    A DNS pattern as extracted from certificates.
    """

    #: The pattern.
    pattern: bytes = attr.ib()

    _RE_LEGAL_CHARS = re.compile(rb"^[a-z0-9\-_.]+$")

    @classmethod
    def from_bytes(cls, pattern: bytes) -> DNSPattern:
        if not isinstance(pattern, bytes):
            msg = "The DNS pattern must be a bytes string."
            raise TypeError(msg)

        pattern = pattern.strip()

        if pattern == b"" or _is_ip_address(pattern) or b"\0" in pattern:
            msg = f"Invalid DNS pattern {pattern!r}."
            raise CertificateError(msg)

        pattern = pattern.translate(_TRANS_TO_LOWER)
        if b"*" in pattern:
            _validate_pattern(pattern)

        return cls(pattern=pattern)


@attr.s(slots=True)
class IPAddressPattern:
    """
    An IP address pattern as extracted from certificates.
    """

    #: The pattern.
    pattern: ipaddress.IPv4Address | ipaddress.IPv6Address = attr.ib()

    @classmethod
    def from_bytes(cls, bs: bytes) -> IPAddressPattern:
        try:
            return cls(pattern=ipaddress.ip_address(bs))
        except ValueError:
            msg = f"Invalid IP address pattern {bs!r}."
            raise CertificateError(msg) from None


@attr.s(slots=True)
class URIPattern:
    """
    An URI pattern as extracted from certificates.
    """

    #: The pattern for the protocol part.
    protocol_pattern: bytes = attr.ib()
    #: The pattern for the DNS part.
    dns_pattern: DNSPattern = attr.ib()
    #: The authority port, or `None` if the certificate omits it.
    port_pattern: int | None = attr.ib(default=None)
    #: The normalized path part, always beginning with a slash.
    path_pattern: bytes = attr.ib(default=b"/")

    @classmethod
    def from_bytes(cls, pattern: bytes) -> URIPattern:
        if not isinstance(pattern, bytes):
            msg = "The URI pattern must be a bytes string."
            raise TypeError(msg)

        pattern = pattern.strip()

        if b":" not in pattern or b"*" in pattern or _is_ip_address(pattern):
            msg = f"Invalid URI pattern {pattern!r}."
            raise CertificateError(msg)

        scheme, remainder = pattern.split(b":", 1)
        protocol_pattern = _normalize_scheme(scheme)
        authority, path = _split_authority_path(remainder)
        hostname, port = _parse_authority(authority)

        return cls(
            protocol_pattern=protocol_pattern,
            dns_pattern=DNSPattern.from_bytes(hostname.lower()),
            port_pattern=port,
            path_pattern=_normalize_cert_path(path),
        )


@attr.s(slots=True)
class SRVPattern:
    """
    An SRV pattern as extracted from certificates.
    """

    #: The pattern for the name part.
    name_pattern: bytes = attr.ib()
    #: The pattern for the DNS part.
    dns_pattern: DNSPattern = attr.ib()
    #: The pattern for the protocol part, or `None` for legacy
    #: single-label SRV-IDs (``_service.domain``).
    protocol_pattern: bytes | None = attr.ib(default=None)

    @classmethod
    def from_bytes(cls, pattern: bytes) -> SRVPattern:
        if not isinstance(pattern, bytes):
            msg = "The SRV pattern must be a bytes string."
            raise TypeError(msg)

        pattern = pattern.strip().translate(_TRANS_TO_LOWER)

        if (
            pattern[0] != b"_"[0]
            or b"." not in pattern
            or b"*" in pattern
            or _is_ip_address(pattern)
        ):
            msg = f"Invalid SRV pattern {pattern!r}."
            raise CertificateError(msg)

        name, hostname = pattern.split(b".", 1)

        service = name[1:]
        protocol = None
        if b"." in hostname:
            first_label, rest = hostname.split(b".", 1)
            if first_label.startswith(b"_"):
                protocol = first_label[1:]
                if not protocol or not _RE_SRV_LABEL.match(protocol):
                    msg = f"Invalid SRV pattern {pattern!r}."
                    raise CertificateError(msg)
                hostname = rest

        if not service or not _RE_SRV_LABEL.match(service):
            msg = f"Invalid SRV pattern {pattern!r}."
            raise CertificateError(msg)

        return cls(
            name_pattern=service,
            dns_pattern=DNSPattern.from_bytes(hostname),
            protocol_pattern=protocol,
        )


CertificatePattern = SRVPattern | URIPattern | DNSPattern | IPAddressPattern
"""
A :class:`Union` of all possible patterns that can be extracted from a
certificate.
"""


@runtime_checkable
class ServiceID(Protocol):
    @property
    def pattern_class(self) -> type[CertificatePattern]: ...

    @property
    def error_on_mismatch(self) -> type[Mismatch]: ...

    def verify(self, pattern: CertificatePattern) -> bool: ...

    def mismatch(
        self, cert_patterns: Sequence[CertificatePattern]
    ) -> Mismatch: ...


@attr.s(init=False, slots=True)
class DNS_ID:
    """
    A DNS service ID, aka hostname.
    """

    hostname: bytes = attr.ib()

    # characters that are legal in a normalized hostname
    _RE_LEGAL_CHARS = re.compile(rb"^[a-z0-9\-_.]+$")
    pattern_class = DNSPattern
    error_on_mismatch = DNSMismatch

    def __init__(self, hostname: str):
        if not isinstance(hostname, str):
            msg = "DNS-ID must be a text string."
            raise TypeError(msg)

        hostname = hostname.strip()
        if not hostname or _is_ip_address(hostname):
            msg = "Invalid DNS-ID."
            raise ValueError(msg)

        if any(ord(c) > 127 for c in hostname):
            if idna:
                ascii_id = idna.encode(hostname)
            else:
                msg = "idna library is required for non-ASCII IDs."
                raise ImportError(msg)
        else:
            ascii_id = hostname.encode("ascii")

        self.hostname = ascii_id.translate(_TRANS_TO_LOWER)
        if self._RE_LEGAL_CHARS.match(self.hostname) is None:
            msg = "Invalid DNS-ID."
            raise ValueError(msg)

    def verify(self, pattern: CertificatePattern) -> bool:
        """
        https://tools.ietf.org/search/rfc6125#section-6.4
        """
        if isinstance(pattern, self.pattern_class):
            return _hostname_matches(pattern.pattern, self.hostname)

        return False

    def mismatch(
        self,
        cert_patterns: Sequence[CertificatePattern],  # noqa: ARG002
    ) -> Mismatch:
        return self.error_on_mismatch(
            mismatched_id=self,
            mismatched_categories=("host",),
            normalized_id=self.hostname.decode("ascii"),
        )


@attr.s(slots=True)
class IPAddress_ID:
    """
    An IP address service ID.
    """

    ip: ipaddress.IPv4Address | ipaddress.IPv6Address = attr.ib(
        converter=ipaddress.ip_address
    )

    pattern_class = IPAddressPattern
    error_on_mismatch = IPAddressMismatch

    def verify(self, pattern: CertificatePattern) -> bool:
        """
        https://tools.ietf.org/search/rfc2818#section-3.1
        """
        if isinstance(pattern, self.pattern_class):
            return self.ip == pattern.pattern

        return False

    def mismatch(
        self,
        cert_patterns: Sequence[CertificatePattern],  # noqa: ARG002
    ) -> Mismatch:
        return self.error_on_mismatch(
            mismatched_id=self,
            mismatched_categories=("ip",),
            normalized_id=str(self.ip),
        )


@attr.s(init=False, slots=True)
class URI_ID:
    """
    An URI service ID.

    The identity is normalized so that comparisons cover the lower-cased
    scheme, the IDNA-encoded host, the explicit port (falling back to the
    scheme's default port) and the normalized path.  Wildcards never cross
    the authority/path boundary and are not allowed at all in a service ID.
    """

    protocol: bytes = attr.ib()
    dns_id: DNS_ID = attr.ib()
    port: int | None = attr.ib()
    path: bytes = attr.ib()

    pattern_class = URIPattern
    error_on_mismatch = URIMismatch

    def __init__(self, uri: str):
        if not isinstance(uri, str):
            msg = "URI-ID must be a text string."
            raise TypeError(msg)

        uri = uri.strip()
        if ":" not in uri:
            msg = "Invalid URI-ID."
            raise ValueError(msg)

        scheme, remainder = uri.split(":", 1)
        try:
            self.protocol = _normalize_scheme(scheme.strip().encode("ascii"))
        except (UnicodeEncodeError, CertificateError) as e:
            msg = "Invalid URI-ID."
            raise ValueError(msg) from e

        try:
            authority_text, path_text = _split_authority_path_text(remainder)
            hostname_text, port = _parse_authority_text(authority_text)
        except CertificateError as e:
            msg = "Invalid URI-ID."
            raise ValueError(msg) from e

        if port is None:
            port = _DEFAULT_PORTS.get(self.protocol)

        self.dns_id = DNS_ID(hostname_text)
        self.port = port
        try:
            self.path = _normalize_client_path(path_text.encode("ascii"))
        except UnicodeEncodeError as e:
            msg = "Invalid URI-ID."
            raise ValueError(msg) from e

    def verify(self, pattern: CertificatePattern) -> bool:
        """
        https://tools.ietf.org/search/rfc6125#section-6.5.2
        """
        if not isinstance(pattern, self.pattern_class):
            return False

        cert_port = pattern.port_pattern
        if cert_port is None:
            cert_port = _DEFAULT_PORTS.get(pattern.protocol_pattern)

        return (
            pattern.protocol_pattern == self.protocol
            and self.dns_id.verify(pattern.dns_pattern)
            and cert_port == self.port
            and pattern.path_pattern == self.path
        )

    def mismatch(
        self, cert_patterns: Sequence[CertificatePattern]
    ) -> Mismatch:
        categories: set[str] = set()
        uri_patterns = [
            p for p in cert_patterns if isinstance(p, self.pattern_class)
        ]
        if not uri_patterns:
            categories.update(("scheme", "host", "port", "path"))
        else:
            for pattern in uri_patterns:
                categories.update(self._failing_categories(pattern))

        return self.error_on_mismatch(
            mismatched_id=self,
            mismatched_categories=tuple(
                category
                for category in ("scheme", "host", "port", "path")
                if category in categories
            ),
            normalized_id=self.normalized_id,
        )

    def _failing_categories(self, pattern: URIPattern) -> tuple[str, ...]:
        categories = []
        if pattern.protocol_pattern != self.protocol:
            categories.append("scheme")
        if not self.dns_id.verify(pattern.dns_pattern):
            categories.append("host")

        cert_port = pattern.port_pattern
        if cert_port is None:
            cert_port = _DEFAULT_PORTS.get(pattern.protocol_pattern)
        if cert_port != self.port:
            categories.append("port")

        if pattern.path_pattern != self.path:
            categories.append("path")

        return tuple(categories)

    @property
    def normalized_id(self) -> str:
        authority = self.dns_id.hostname.decode("ascii")
        if self.port is not None:
            authority = f"{authority}:{self.port}"
        return (
            f"{self.protocol.decode('ascii')}://{authority}"
            f"{self.path.decode('ascii')}"
        )


@attr.s(init=False, slots=True)
class SRV_ID:
    """
    An SRV service ID.
    """

    name: bytes = attr.ib()
    dns_id: DNS_ID = attr.ib()
    #: The protocol label (e.g. ``b"tcp"``), or `None` for legacy
    #: single-label SRV-IDs.
    protocol: bytes | None = attr.ib()
    #: Ports the caller is willing to accept for this service.
    allowed_ports: frozenset[int] = attr.ib()
    #: The concrete port of the connection, or `None` if the caller
    #: provided a policy without selecting a port.
    port: int | None = attr.ib(default=None)

    pattern_class = SRVPattern
    error_on_mismatch = SRVMismatch

    def __init__(
        self,
        srv: str,
        *,
        allowed_ports: Iterable[int] | None = None,
        port: int | None = None,
    ):
        if not isinstance(srv, str):
            msg = "SRV-ID must be a text string."
            raise TypeError(msg)

        srv = srv.strip()
        if "." not in srv or _is_ip_address(srv) or srv[0] != "_":
            msg = "Invalid SRV-ID."
            raise ValueError(msg)

        name, hostname = srv.split(".", 1)

        service = name[1:].encode("ascii").translate(_TRANS_TO_LOWER)
        if not service or not _RE_SRV_LABEL.match(service):
            msg = "Invalid SRV-ID."
            raise ValueError(msg)
        self.name = service
        self.protocol = None
        if hostname.startswith("_") and "." in hostname:
            protocol_label, rest = hostname.split(".", 1)
            protocol = protocol_label[1:]
            protocol_bytes = protocol.encode("ascii").translate(
                _TRANS_TO_LOWER
            )
            if not _RE_SRV_LABEL.match(protocol_bytes):
                msg = "Invalid SRV-ID."
                raise ValueError(msg)
            self.protocol = protocol_bytes
            hostname = rest

        self.dns_id = DNS_ID(hostname)

        if allowed_ports is not None and not isinstance(
            allowed_ports, Iterable
        ):
            msg = "Invalid SRV-ID port policy."
            raise ValueError(msg)
        self.allowed_ports = frozenset(allowed_ports or ())
        if any(
            not isinstance(p, int)
            or isinstance(p, bool)
            or not 0 <= p <= 65535
            for p in self.allowed_ports
        ):
            msg = "Invalid SRV-ID port policy."
            raise ValueError(msg)

        if port is not None and (
            not isinstance(port, int)
            or isinstance(port, bool)
            or not 0 <= port <= 65535
        ):
            msg = "Invalid SRV-ID port."
            raise ValueError(msg)
        if self.allowed_ports and port not in self.allowed_ports:
            msg = "Port is not allowed by the SRV-ID port policy."
            raise ValueError(msg)
        self.port = port

    def verify(self, pattern: CertificatePattern) -> bool:
        """
        https://tools.ietf.org/search/rfc6125#section-6.5.1
        """
        if not isinstance(pattern, self.pattern_class):
            return False

        if self.name != pattern.name_pattern:
            return False
        if pattern.protocol_pattern is not None and (
            self.protocol is None or self.protocol != pattern.protocol_pattern
        ):
            return False
        if not self.dns_id.verify(pattern.dns_pattern):
            return False

        return self.port is None or self.port in self.allowed_ports

    def mismatch(
        self, cert_patterns: Sequence[CertificatePattern]
    ) -> Mismatch:
        categories: set[str] = set()
        srv_patterns = [
            p for p in cert_patterns if isinstance(p, self.pattern_class)
        ]
        if not srv_patterns:
            categories.update(("service", "protocol", "domain"))
        else:
            for pattern in srv_patterns:
                categories.update(self._failing_categories(pattern))

        if self.port is not None and self.port not in self.allowed_ports:
            categories.add("port")

        return self.error_on_mismatch(
            mismatched_id=self,
            mismatched_categories=tuple(
                category
                for category in ("service", "protocol", "domain", "port")
                if category in categories
            ),
            normalized_id=self.normalized_id,
        )

    def _failing_categories(self, pattern: SRVPattern) -> tuple[str, ...]:
        categories = []
        if self.name != pattern.name_pattern:
            categories.append("service")
        if pattern.protocol_pattern is not None and (
            self.protocol is None or self.protocol != pattern.protocol_pattern
        ):
            categories.append("protocol")
        if not self.dns_id.verify(pattern.dns_pattern):
            categories.append("domain")

        return tuple(categories)

    @property
    def normalized_id(self) -> str:
        service = self.name.decode("ascii")
        domain = self.dns_id.hostname.decode("ascii")
        if self.protocol is None:
            identity = f"_{service}.{domain}"
        else:
            identity = f"_{service}._{self.protocol.decode('ascii')}.{domain}"
        if self.port is not None:
            identity = f"{identity}:{self.port}"

        return identity


def _hostname_matches(cert_pattern: bytes, actual_hostname: bytes) -> bool:
    """
    :return: `True` if *cert_pattern* matches *actual_hostname*, else `False`.
    """
    if b"*" in cert_pattern:
        if b"." not in actual_hostname:
            return False
        cert_head, cert_tail = cert_pattern.split(b".", 1)
        actual_head, actual_tail = actual_hostname.split(b".", 1)
        if cert_tail != actual_tail:
            return False
        # No patterns for IDNA
        if actual_head.startswith(b"xn--"):
            return False

        return cert_head in (b"*", actual_head)

    return cert_pattern == actual_hostname


#: Default ports for schemes whose well-known ports are needed to compare a
#: certificate URI without an explicit port with a client URI.
_DEFAULT_PORTS: dict[bytes, int] = {
    b"acap": 674,
    b"afp": 548,
    b"caldav": 80,
    b"carddav": 80,
    b"dict": 2628,
    b"dns": 53,
    b"ftp": 21,
    b"ftps": 990,
    b"git": 9418,
    b"http": 80,
    b"https": 443,
    b"imap": 143,
    b"imaps": 993,
    b"ipp": 631,
    b"ipps": 631,
    b"irc": 194,
    b"ircs": 6697,
    b"ldap": 389,
    b"ldaps": 636,
    b"mssql": 1433,
    b"mysql": 3306,
    b"nfs": 2049,
    b"nntp": 119,
    b"nntps": 563,
    b"pop": 110,
    b"pop3": 110,
    b"pop3s": 995,
    b"postgres": 5432,
    b"postgresql": 5432,
    b"prospero": 1525,
    b"redis": 6379,
    b"rsync": 873,
    b"rtsp": 554,
    b"sip": 5060,
    b"sips": 5061,
    b"smtp": 25,
    b"smtps": 465,
    b"snmp": 161,
    b"ssh": 22,
    b"svn": 3690,
    b"telnet": 23,
    b"tftp": 69,
    b"xmpp": 5222,
    b"xmpp-server": 5269,
}


def _normalize_scheme(scheme: bytes) -> bytes:
    """
    Lower-case and validate an URI scheme.
    """
    scheme = scheme.strip().translate(_TRANS_TO_LOWER)
    if not scheme or not re.fullmatch(rb"[a-z][a-z0-9+\-.]*", scheme):
        msg = f"Invalid URI scheme {scheme!r}."
        raise CertificateError(msg)

    return scheme


def _split_authority_path(remainder: bytes) -> tuple[bytes, bytes]:
    """
    Split the part of an URI following the scheme into authority and path.

    A hierarchical URI starts with ``//``; everything up to the first slash
    is the authority and the rest (including the slash) is the path.  Query
    and fragment components are not part of service identity and are dropped.
    A legacy ``scheme:host`` URI has no path at all.
    """
    if not remainder.startswith(b"//"):
        return remainder, b""

    authority_and_path = remainder[2:]
    slash = authority_and_path.find(b"/")
    if slash == -1:
        authority = authority_and_path
        path = b"/"
    else:
        authority = authority_and_path[:slash]
        path = authority_and_path[slash:]

    for separator in (b"?", b"#"):
        position = authority.find(separator)
        if position != -1:
            authority = authority[:position]
        position = path.find(separator)
        if position != -1:
            path = path[:position]

    return authority, path


def _split_authority_path_text(remainder: str) -> tuple[str, str]:
    """
    Text counterpart of :func:`_split_authority_path`.
    """
    if not remainder.startswith("//"):
        return remainder, ""

    authority_and_path = remainder[2:]
    slash = authority_and_path.find("/")
    if slash == -1:
        authority = authority_and_path
        path = "/"
    else:
        authority = authority_and_path[:slash]
        path = authority_and_path[slash:]

    for separator in ("?", "#"):
        position = authority.find(separator)
        if position != -1:
            authority = authority[:position]
        position = path.find(separator)
        if position != -1:
            path = path[:position]

    return authority, path


def _parse_authority(authority: bytes) -> tuple[bytes, int | None]:
    """
    Split an authority into host and optional port.

    User info and IP literals are rejected and the wildcard character may not
    appear in the authority, so it can never reach the path comparison.
    """
    if b"*" in authority or b"@" in authority or authority.startswith(b"["):
        msg = f"Invalid URI authority {authority!r}."
        raise CertificateError(msg)

    if b":" in authority:
        host, port_text = authority.rsplit(b":", 1)
        try:
            port = int(port_text)
        except ValueError:
            port = -1
        if not 0 <= port <= 65535 or not host:
            msg = f"Invalid URI authority {authority!r}."
            raise CertificateError(msg)

        return host, port

    return authority, None


def _parse_authority_text(authority: str) -> tuple[str, int | None]:
    """
    Text counterpart of :func:`_parse_authority`.
    """
    if "*" in authority or "@" in authority or authority.startswith("["):
        msg = f"Invalid URI authority {authority!r}."
        raise CertificateError(msg)

    if ":" in authority:
        host, port_text = authority.rsplit(":", 1)
        try:
            port = int(port_text)
        except ValueError:
            port = -1
        if not 0 <= port <= 65535 or not host:
            msg = f"Invalid URI authority {authority!r}."
            raise CertificateError(msg)

        return host, port

    return authority, None


def _normalize_cert_path(path: bytes) -> bytes:
    """
    Normalize a certificate URI path for byte-wise comparison.
    """
    if not path:
        return b"/"
    if not path.startswith(b"/"):
        msg = f"Invalid URI path {path!r}."
        raise CertificateError(msg)

    path = _uppercase_percent_encoding(path.translate(_TRANS_TO_LOWER))
    if len(path) > 1:
        path = path.rstrip(b"/") or b"/"

    return path


def _normalize_client_path(path: bytes) -> bytes:
    """
    Normalize a client-supplied URI path.

    Unlike certificate patterns, the client path keeps its case (only
    percent-encoding triplets are upper-cased) but is required to be
    hierarchical.
    """
    if not path:
        return b"/"
    if not path.startswith(b"/"):
        msg = "Invalid URI-ID."
        raise ValueError(msg)

    path = _uppercase_percent_encoding(path)
    if len(path) > 1:
        path = path.rstrip(b"/") or b"/"

    return path


def _uppercase_percent_encoding(path: bytes) -> bytes:
    """
    Upper-case the hex digits of every percent-encoded octet.
    """
    return re.sub(
        rb"%[0-9a-fA-F]{2}",
        lambda match: match.group(0).upper(),
        path,
    )


def _validate_pattern(cert_pattern: bytes) -> None:
    """
    Check whether the usage of wildcards within *cert_pattern* conforms with
    our expectations.
    """
    cnt = cert_pattern.count(b"*")
    if cnt > 1:
        msg = f"Certificate's DNS-ID {cert_pattern!r} contains too many wildcards."
        raise CertificateError(msg)
    parts = cert_pattern.split(b".")
    if len(parts) < 3:
        msg = f"Certificate's DNS-ID {cert_pattern!r} has too few host components for wildcard usage."
        raise CertificateError(msg)
    # We assume there will always be only one wildcard allowed.
    if b"*" not in parts[0]:
        msg = f"Certificate's DNS-ID {cert_pattern!r} has a wildcard outside the left-most part."
        raise CertificateError(msg)
    if any(not len(p) for p in parts):
        msg = f"Certificate's DNS-ID {cert_pattern!r} contains empty parts."
        raise CertificateError(msg)


# Ensure no locale magic interferes.
_TRANS_TO_LOWER = bytes.maketrans(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ", b"abcdefghijklmnopqrstuvwxyz"
)

# RFC 6335 service/protocol labels: 1-15 chars, alphanumeric and hyphens,
# starting and ending alphanumeric.
_RE_SRV_LABEL = re.compile(rb"^[a-z0-9](?:[a-z0-9-]{0,13}[a-z0-9])?$")
