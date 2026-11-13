"""
Common verification code.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata

from collections.abc import Sequence
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


class _InvalidDNSNameError(ValueError):
    """
    A DNS name or pattern that cannot be normalized to A-labels.
    """


# Labels of an ASCII (LDH) name consist of letters, digits and hyphens.
_RE_ASCII_LABEL = re.compile(rb"^[a-z0-9-]+$")

# The maximum length of a single DNS label and of a full domain name.
_MAX_LABEL_LENGTH = 63
_MAX_DOMAIN_LENGTH = 253


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
            errors.append(  # noqa: PERF401
                _mismatch_error(i, cert_patterns)
            )

    for i in optional_ids:
        # If an optional ID is not matched by a certificate pattern *but* there
        # is a pattern of the same type , it is an error and the verification
        # fails.  Example: the user passes a SRV-ID for "_mail.domain.com" but
        # the certificate contains an SRV-Pattern for "_xmpp.domain.com".
        if i not in matched_ids and _contains_instance_of(
            cert_patterns, i.pattern_class
        ):
            errors.append(  # noqa: PERF401
                _mismatch_error(i, cert_patterns)
            )

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


def _mismatch_error(
    service_id: ServiceID, cert_patterns: Sequence[CertificatePattern]
) -> Mismatch:
    """
    Build the mismatch error for *service_id*, attaching the normalized DNS
    pattern that was considered when there is one.
    """
    error = service_id.error_on_mismatch(mismatched_id=service_id)
    if isinstance(error, DNSMismatch):
        for pattern in cert_patterns:
            if isinstance(pattern, DNSPattern):
                error.pattern = pattern.pattern
                break

    return error


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

    @classmethod
    def from_bytes(cls, pattern: bytes) -> DNSPattern:
        if not isinstance(pattern, bytes):
            msg = "The DNS pattern must be a bytes string."
            raise TypeError(msg)

        raw_pattern = pattern.strip()

        if (
            raw_pattern == b""
            or _is_ip_address(raw_pattern)
            or b"\0" in raw_pattern
        ):
            msg = f"Invalid DNS pattern {raw_pattern!r}."
            raise CertificateError(msg, pattern=raw_pattern)

        try:
            normalized = _encode_dns_name(raw_pattern)
        except ImportError as e:
            msg = f"Invalid DNS pattern {raw_pattern!r}: {e}"
            raise CertificateError(msg) from e
        except _InvalidDNSNameError as e:
            msg = f"Invalid DNS pattern {raw_pattern!r}: {e}"
            raise CertificateError(msg) from None

        if b"*" in normalized:
            _validate_pattern(normalized)

        return cls(pattern=normalized)


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

    @classmethod
    def from_bytes(cls, pattern: bytes) -> URIPattern:
        if not isinstance(pattern, bytes):
            msg = "The URI pattern must be a bytes string."
            raise TypeError(msg)

        pattern = pattern.strip().translate(_TRANS_TO_LOWER)

        if b":" not in pattern or b"*" in pattern or _is_ip_address(pattern):
            msg = f"Invalid URI pattern {pattern!r}."
            raise CertificateError(msg)

        protocol_pattern, hostname = pattern.split(b":")

        return cls(
            protocol_pattern=protocol_pattern,
            dns_pattern=DNSPattern.from_bytes(hostname.strip(b"/")),
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
        return cls(
            name_pattern=name[1:], dns_pattern=DNSPattern.from_bytes(hostname)
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


@attr.s(init=False, slots=True)
class DNS_ID:
    """
    A DNS service ID, aka hostname.
    """

    hostname: bytes = attr.ib()

    pattern_class = DNSPattern
    error_on_mismatch = DNSMismatch

    def __init__(self, hostname: str):
        if not isinstance(hostname, str):
            msg = "DNS-ID must be a text string."
            raise TypeError(msg)

        raw_hostname = hostname.strip()
        if not raw_hostname or _is_ip_address(raw_hostname):
            msg = "Invalid DNS-ID."
            raise ValueError(msg)
        if "*" in raw_hostname:
            msg = "DNS-IDs must not contain wildcards."
            raise ValueError(msg)

        try:
            self.hostname = _encode_dns_name(raw_hostname)
        except ImportError:
            raise
        except _InvalidDNSNameError:
            msg = "Invalid DNS-ID."
            raise ValueError(msg) from None

    def verify(self, pattern: CertificatePattern) -> bool:
        """
        https://tools.ietf.org/search/rfc6125#section-6.4
        """
        if isinstance(pattern, self.pattern_class):
            return _hostname_matches(pattern.pattern, self.hostname)

        return False


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


@attr.s(init=False, slots=True)
class URI_ID:
    """
    An URI service ID.
    """

    protocol: bytes = attr.ib()
    dns_id: DNS_ID = attr.ib()

    pattern_class = URIPattern
    error_on_mismatch = URIMismatch

    def __init__(self, uri: str):
        if not isinstance(uri, str):
            msg = "URI-ID must be a text string."
            raise TypeError(msg)

        uri = uri.strip()
        if ":" not in uri or _is_ip_address(uri):
            msg = "Invalid URI-ID."
            raise ValueError(msg)

        prot, hostname = uri.split(":")

        self.protocol = prot.encode("ascii").translate(_TRANS_TO_LOWER)
        self.dns_id = DNS_ID(hostname.strip("/"))

    def verify(self, pattern: CertificatePattern) -> bool:
        """
        https://tools.ietf.org/search/rfc6125#section-6.5.2
        """
        if isinstance(pattern, self.pattern_class):
            return (
                pattern.protocol_pattern == self.protocol
                and self.dns_id.verify(pattern.dns_pattern)
            )

        return False


@attr.s(init=False, slots=True)
class SRV_ID:
    """
    An SRV service ID.
    """

    name: bytes = attr.ib()
    dns_id: DNS_ID = attr.ib()

    pattern_class = SRVPattern
    error_on_mismatch = SRVMismatch

    def __init__(self, srv: str):
        if not isinstance(srv, str):
            msg = "SRV-ID must be a text string."
            raise TypeError(msg)

        srv = srv.strip()
        if "." not in srv or _is_ip_address(srv) or srv[0] != "_":
            msg = "Invalid SRV-ID."
            raise ValueError(msg)

        name, hostname = srv.split(".", 1)

        self.name = name[1:].encode("ascii").translate(_TRANS_TO_LOWER)
        self.dns_id = DNS_ID(hostname)

    def verify(self, pattern: CertificatePattern) -> bool:
        """
        https://tools.ietf.org/search/rfc6125#section-6.5.1
        """
        if isinstance(pattern, self.pattern_class):
            return self.name == pattern.name_pattern and self.dns_id.verify(
                pattern.dns_pattern
            )

        return False


def _hostname_matches(cert_pattern: bytes, actual_hostname: bytes) -> bool:
    """
    :return: `True` if *cert_pattern* matches *actual_hostname*, else `False`.

    Both arguments are normalized A-label names as produced by
    :func:`_encode_dns_name`.  A wildcard is only honored as the complete
    left-most label and matches exactly one label of the hostname.
    """
    cert_labels = cert_pattern.split(b".")
    host_labels = actual_hostname.split(b".")

    if len(cert_labels) != len(host_labels):
        return False

    if cert_labels[0] == b"*":
        # Wildcards never match an A-label (punycode) label.
        if host_labels[0].startswith(b"xn--"):
            return False

        return cert_labels[1:] == host_labels[1:]

    return cert_pattern == actual_hostname


def _validate_pattern(cert_pattern: bytes) -> None:
    """
    Check whether the usage of wildcards within *cert_pattern* conforms with
    our expectations.

    A wildcard must be the only character of the left-most label, the
    pattern needs at least three labels and every label must be non-empty.
    """
    parts = cert_pattern.split(b".")
    if len(parts) < 3:
        msg = f"Certificate's DNS-ID {cert_pattern!r} has too few host components for wildcard usage."
        raise CertificateError(msg, pattern=cert_pattern)
    if any(not len(p) for p in parts):
        msg = f"Certificate's DNS-ID {cert_pattern!r} contains empty parts."
        raise CertificateError(msg, pattern=cert_pattern)
    if cert_pattern.count(b"*") > 1:
        msg = f"Certificate's DNS-ID {cert_pattern!r} contains too many wildcards."
        raise CertificateError(msg, pattern=cert_pattern)
    if parts[0] != b"*":
        msg = f"Certificate's DNS-ID {cert_pattern!r} has a wildcard outside the left-most part."
        raise CertificateError(msg, pattern=cert_pattern)


def _encode_dns_name(name: str | bytes) -> bytes:
    """
    Normalize *name* to ASCII A-labels suitable for byte-wise comparison.

    The name is decoded when necessary, put into Unicode NFC, lower-cased,
    stripped of a single trailing dot and then encoded with IDNA.  Any
    wildcard is only legal as the complete left-most label and is preserved
    while the remaining labels are normalized like an ordinary hostname.

    Raises:
        _InvalidDNSNameError: If *name* contains empty labels, illegal
            characters, a misplaced wildcard or cannot be IDNA-encoded.
        ImportError: If *name* contains non-ASCII data but the optional
            ``idna`` dependency is not installed.
    """
    if isinstance(name, bytes):
        try:
            text_name = name.decode("ascii")
        except UnicodeDecodeError:
            try:
                text_name = name.decode("utf-8")
            except UnicodeDecodeError as e:
                msg = "not valid UTF-8"
                raise _InvalidDNSNameError(msg) from e
    else:
        text_name = name

    # NFC first so that equivalent NFC/NFD inputs get the same A-labels.
    text_name = unicodedata.normalize("NFC", text_name).lower()

    had_trailing_dot = text_name.endswith(".")
    text_name = text_name[:-1] if had_trailing_dot else text_name

    if not text_name:
        msg = "empty DNS name"
        raise _InvalidDNSNameError(msg)

    labels = text_name.split(".")
    if any(label == "" for label in labels):
        msg = "contains empty labels"
        raise _InvalidDNSNameError(msg)

    wildcard = labels[0] == "*"
    wildcard_labels = [
        index for index, label in enumerate(labels) if "*" in label
    ]
    if wildcard_labels and wildcard_labels != [0]:
        msg = "wildcards are only allowed as the complete left-most label"
        raise _InvalidDNSNameError(msg)

    labels_to_encode = labels[1:] if wildcard else labels
    encoded_labels = [_encode_dns_label(label) for label in labels_to_encode]

    if wildcard:
        encoded_labels.insert(0, b"*")

    encoded = b".".join(encoded_labels)
    if len(encoded) > _MAX_DOMAIN_LENGTH:
        msg = "DNS name is too long"
        raise _InvalidDNSNameError(msg)

    return encoded


def _encode_dns_label(label: str) -> bytes:
    """
    Encode a single, already lower-cased DNS label to an A-label.
    """
    if len(label) > _MAX_LABEL_LENGTH:
        msg = f"label {label!r} is too long"
        raise _InvalidDNSNameError(msg)

    try:
        ascii_label = label.encode("ascii")
    except UnicodeEncodeError:
        if idna is None:
            msg = "idna library is required for non-ASCII IDs."
            raise ImportError(msg) from None
        try:
            return idna.encode(label)
        except idna.IDNAError as e:
            raise _InvalidDNSNameError(str(e)) from e

    if _RE_ASCII_LABEL.match(ascii_label) is None:
        msg = f"label {label!r} contains illegal characters"
        raise _InvalidDNSNameError(msg)

    if ascii_label.startswith(b"xn--"):
        # Works without the optional idna dependency; idna adds full
        # punycode/IDNA validation when it is installed.  Valid punycode
        # payloads may themselves contain hyphens.
        if not ascii_label[4:]:
            msg = f"malformed A-label {label!r}"
            raise _InvalidDNSNameError(msg)
        if idna is not None:
            try:
                return idna.encode(label)
            except idna.IDNAError as e:
                raise _InvalidDNSNameError(str(e)) from e

    return ascii_label


# Ensure no locale magic interferes.
_TRANS_TO_LOWER = bytes.maketrans(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ", b"abcdefghijklmnopqrstuvwxyz"
)
