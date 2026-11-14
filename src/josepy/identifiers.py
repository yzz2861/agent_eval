"""ACME identifier and subjectAltName canonicalization.

This module implements uniform validation and canonicalization rules
for ACME identifiers (RFC 8555 and RFC 8738) and for DNS names used in
certificate signing requests:

- DNS names are normalized to A-labels (IDNA/punycode), lowercased and
  stripped of a single trailing root dot. Unicode dot characters
  (U+3002, U+FF0E, U+FF61 and U+2024) are treated as label separators.
- A wildcard marker is only allowed as the complete leftmost label and
  at most once ('*.example.com' is valid, while '*.*.example.com',
  'foo.*.example.com' and a bare '*' are not).
- Empty labels, IP addresses in DNS identifiers, URLs (paths, ports,
  userinfo) and other illegal characters are rejected.

Validated identifiers keep both the original input and the canonical
value. Only the canonical value is serialized and only the canonical
value may be used when issuing certificates.
"""

import ipaddress
import re
from collections.abc import Mapping
from typing import Any, Dict, Iterable, Optional, Tuple, Union

from cryptography import x509

from josepy import errors, interfaces

IDENTIFIER_TYPE_DNS = "dns"
IDENTIFIER_TYPE_IP = "ip"

_WILDCARD_PREFIX = "*."

# Dot-like characters that IDNA2003 (and UTS #46) treat as label
# separators, plus U+2024 ONE DOT LEADER which some stacks fold as well.
_UNICODE_DOTS = "․。．｡"

_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

_MAX_DNS_NAME_LENGTH = 253
_MAX_LABEL_LENGTH = 63


def canonicalize_dns_name(name: str, position: Optional[int] = None) -> str:
    """Validate and canonicalize a DNS name for an ACME identifier or SAN.

    The returned canonical form consists of lowercase A-labels, has no
    trailing dot and keeps at most one wildcard marker as the leftmost
    label.

    :param str name: DNS name to validate, e.g. 'example.com',
        'xn--bcher-kva.de', 'bücher.de' or '*.example.com'.
    :param int position: Optional position of the name in the request,
        reported in raised errors.

    :raises josepy.errors.IdentifierError: if the name is not a valid
        DNS identifier value.
    :rtype: str

    """
    if not isinstance(name, str):
        raise errors.IdentifierError(IDENTIFIER_TYPE_DNS, "DNS name must be a string", position)

    for unicode_dot in _UNICODE_DOTS:
        name = name.replace(unicode_dot, ".")

    if name.endswith("."):
        name = name[: -len(".")]
    if not name:
        raise errors.IdentifierError(IDENTIFIER_TYPE_DNS, "empty DNS name", position)

    wildcard = False
    if name == "*":
        raise errors.IdentifierError(
            IDENTIFIER_TYPE_DNS, "bare wildcard is not a valid DNS name", position
        )
    if name.startswith(_WILDCARD_PREFIX):
        wildcard = True
        name = name[len(_WILDCARD_PREFIX) :]
        if not name:
            raise errors.IdentifierError(
                IDENTIFIER_TYPE_DNS, "empty DNS name after wildcard marker", position
            )
    if "*" in name:
        raise errors.IdentifierError(
            IDENTIFIER_TYPE_DNS,
            "wildcard is only allowed as the entire leftmost label",
            position,
        )

    try:
        ipaddress.ip_address(name)
    except ValueError:
        pass
    else:
        raise errors.IdentifierError(
            IDENTIFIER_TYPE_DNS,
            "IP address is not allowed in a DNS identifier",
            position,
        )

    canonical_labels = []
    for label in name.split("."):
        if not label:
            raise errors.IdentifierError(IDENTIFIER_TYPE_DNS, "empty label", position)
        try:
            alabel = label.encode("idna").decode("ascii").lower()
        except (UnicodeError, ValueError):
            if len(label) > _MAX_LABEL_LENGTH:
                raise errors.IdentifierError(IDENTIFIER_TYPE_DNS, "label too long", position)
            raise errors.IdentifierError(
                IDENTIFIER_TYPE_DNS, "invalid characters in label", position
            )
        if len(alabel) > _MAX_LABEL_LENGTH:
            raise errors.IdentifierError(IDENTIFIER_TYPE_DNS, "label too long", position)
        if not _LABEL_RE.match(alabel):
            raise errors.IdentifierError(
                IDENTIFIER_TYPE_DNS, "invalid characters in label", position
            )
        canonical_labels.append(alabel)

    canonical = ".".join(canonical_labels)
    if len(canonical) > _MAX_DNS_NAME_LENGTH:
        raise errors.IdentifierError(IDENTIFIER_TYPE_DNS, "DNS name too long", position)
    if wildcard:
        canonical = _WILDCARD_PREFIX + canonical
    return canonical


class Identifier(interfaces.JSONDeSerializable):
    """Base class for canonicalized ACME identifiers.

    :ivar str original: The identifier value exactly as provided by the
        caller.
    :ivar str canonical: Canonical identifier value. This is the only
        value serialized to JSON and the only value that may be used
        when issuing certificates.

    """

    type: str = NotImplemented
    """ACME identifier type, e.g. 'dns' or 'ip'."""

    wildcard: bool = False
    """Whether the identifier is a wildcard identifier."""

    __slots__ = ("original", "canonical")

    @property
    def value(self) -> str:
        """Canonical identifier value, safe to use for issuance."""
        return self.canonical

    def to_partial_json(self) -> Dict[str, Any]:
        return {"type": self.type, "value": self.canonical}

    @classmethod
    def from_json(cls, jobj: Mapping[str, Any]) -> "Identifier":
        if not isinstance(jobj, Mapping):
            raise errors.DeserializationError("{0} is not a dictionary object".format(jobj))
        try:
            typ = jobj["type"]
            value = jobj["value"]
        except KeyError as error:
            raise errors.DeserializationError("missing field: {0}".format(error))
        if typ != cls.type:
            raise errors.DeserializationError("expected identifier type '{0}'".format(cls.type))
        return cls(value)

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Identifier):
            return NotImplemented
        return self.type == other.type and self.canonical == other.canonical

    def __hash__(self) -> int:
        return hash((self.type, self.canonical))

    def __repr__(self) -> str:
        return "{0}({1!r})".format(self.__class__.__name__, self.canonical)


class DNSIdentifier(Identifier):
    """Canonicalized ACME 'dns' identifier.

    :ivar bool wildcard: True for wildcard identifiers such as
        '*.example.com'. The wildcard marker is preserved in the
        canonical value.

    """

    type = IDENTIFIER_TYPE_DNS

    __slots__ = ("wildcard",)

    def __init__(self, name: str, position: Optional[int] = None) -> None:
        canonical = canonicalize_dns_name(name, position=position)
        self.original = name
        self.canonical = canonical
        self.wildcard = canonical.startswith(_WILDCARD_PREFIX)

    def to_x509(self) -> x509.DNSName:
        """Get the canonical value as a cryptography DNSName."""
        return x509.DNSName(self.canonical)


class IPIdentifier(Identifier):
    """Canonicalized ACME 'ip' identifier (RFC 8738)."""

    type = IDENTIFIER_TYPE_IP

    __slots__ = ()

    def __init__(
        self,
        address: Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address],
        position: Optional[int] = None,
    ) -> None:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            raise errors.IdentifierError(IDENTIFIER_TYPE_IP, "invalid IP address", position)
        self.original = str(address)
        self.canonical = str(ip)

    def to_x509(self) -> x509.IPAddress:
        """Get the canonical value as a cryptography IPAddress."""
        return x509.IPAddress(ipaddress.ip_address(self.canonical))


def encode_identifier(identifier: Identifier) -> Dict[str, Any]:
    """Serialize an identifier to its JSON form."""
    return identifier.to_partial_json()


def decode_identifier(jobj: Mapping[str, Any]) -> Identifier:
    """Deserialize an ACME identifier from its JSON form.

    :raises josepy.errors.DeserializationError: if the object is not a
        valid identifier.
    :raises josepy.errors.UnrecognizedTypeError: if the identifier type
        is not recognized.

    """
    if not isinstance(jobj, Mapping):
        raise errors.DeserializationError("{0} is not a dictionary object".format(jobj))
    typ = jobj.get("type")
    if typ is None:
        raise errors.DeserializationError("missing type field")
    if typ == IDENTIFIER_TYPE_DNS:
        return DNSIdentifier.from_json(jobj)
    if typ == IDENTIFIER_TYPE_IP:
        return IPIdentifier.from_json(jobj)
    raise errors.UnrecognizedTypeError(typ, jobj)


def dns_identifiers(names: Iterable[str]) -> Tuple[DNSIdentifier, ...]:
    """Validate and canonicalize a list of DNS names, e.g. requested SANs.

    :raises josepy.errors.IdentifierError: if any name is invalid. The
        error reports the position of the offending name.

    """
    return tuple(DNSIdentifier(name, position=index) for index, name in enumerate(names))


def identifier_from_x509(name: x509.GeneralName, position: Optional[int] = None) -> Identifier:
    """Convert a cryptography GeneralName to a canonicalized identifier.

    DNS names stay DNS names (the wildcard marker is preserved) and IP
    addresses stay IP addresses; the two are never conflated.

    :raises josepy.errors.IdentifierError: if the general name type is
        not supported or the value is invalid.

    """
    if isinstance(name, x509.DNSName):
        return DNSIdentifier(name.value, position=position)
    if isinstance(name, x509.IPAddress):
        return IPIdentifier(name.value, position=position)
    raise errors.IdentifierError(
        "unknown",
        "unsupported subjectAltName type: {0}".format(type(name).__name__),
        position,
    )


def identifiers_from_csr(csr: x509.CertificateSigningRequest) -> Tuple[Identifier, ...]:
    """Extract canonicalized identifiers from the SAN extension of a CSR.

    Returns an empty tuple if the CSR carries no subjectAltName
    extension.

    :raises josepy.errors.IdentifierError: if any SAN is invalid. The
        error reports the identifier type and position; the CSR itself
        is never echoed back.

    """
    try:
        ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return ()
    return tuple(identifier_from_x509(name, position=index) for index, name in enumerate(ext.value))
