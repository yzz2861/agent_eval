"""The match_hostname() function from Python 3.5, essential when using SSL."""

# Note: This file is under the PSF license as the code comes from the python
# stdlib.   http://docs.python.org/3/license.html
# It is modified to remove commonName support.

from __future__ import annotations

import ipaddress
import re
import time
import typing
import unicodedata
from ipaddress import IPv4Address, IPv6Address

if typing.TYPE_CHECKING:
    from .ssl_ import _TYPE_PEER_CERT_RET_DICT

__version__ = "3.5.0.1"


class CertificateError(ValueError):
    pass


# DNS names in URLs and certificates are sometimes written using a Unicode
# full stop.  Treat these as ordinary label separators before IDNA encoding.
_DNS_DOT_TRANSLATION = str.maketrans(
    {
        "\u3002": ".",  # IDEOGRAPHIC FULL STOP
        "\uff0e": ".",  # FULLWIDTH FULL STOP
        "\uff61": ".",  # HALFWIDTH IDEOGRAPHIC FULL STOP
    }
)


def _idna_encode_label(label: str) -> str:
    """Return the canonical A-label representation of a DNS label."""
    if label.isascii():
        # ASCII labels are already A-labels.  DNS matching is case-insensitive.
        return label.lower()

    label = unicodedata.normalize("NFC", label.lower())
    try:
        import idna
    except ImportError:
        # The idna package is optional.  Python's built-in codec is a less
        # strict fallback, but still produces comparable A-labels.
        try:
            return label.encode("idna").decode("ascii")
        except UnicodeError as e:
            raise CertificateError(
                f"invalid certificate identity: invalid IDNA label {label!r}"
            ) from e
    else:
        try:
            return idna.encode(label, strict=True, std3_rules=True).decode("ascii")
        except idna.IDNAError as e:
            raise CertificateError(
                f"invalid certificate identity: invalid IDNA label {label!r}"
            ) from e


def _normalize_dns_name(name: str, *, allow_wildcards: bool = False) -> str:
    """Normalize a DNS name for identity comparison.

    This lowercases labels, strips a single trailing root dot, rejects empty
    labels, and converts Unicode labels to their ASCII (punycode) form.  A
    wildcard is only accepted in the left-most label.
    """
    if not isinstance(name, str) or not name:
        raise CertificateError("invalid certificate identity: empty DNS name")

    name = name.translate(_DNS_DOT_TRANSLATION)

    # A single trailing dot denotes the DNS root and is not part of the
    # identity.  Do not use rstrip(): "example.com.." contains an empty label
    # and must not silently become "example.com".
    if name.endswith("."):
        name = name[:-1]

    labels = name.split(".")
    if not labels or any(label == "" for label in labels):
        raise CertificateError(
            f"invalid certificate identity: DNS name {name!r} contains an empty label"
        )

    normalized: list[str] = []
    for index, label in enumerate(labels):
        if "*" in label:
            if not allow_wildcards:
                raise CertificateError(
                    f"invalid certificate identity: DNS name {name!r} contains a wildcard"
                )
            if index != 0:
                raise CertificateError(
                    "invalid certificate: wildcard is only allowed in the "
                    "left-most DNS label"
                )
            if label == "*":
                normalized.append(label)
            else:
                # Wildcards embedded in a U-label/A-label must not be expanded.
                if not label.isascii():
                    raise CertificateError(
                        "invalid certificate: wildcard is embedded in a "
                        "non-ASCII DNS label"
                    )
                normalized.append(label.lower())
        else:
            normalized.append(_idna_encode_label(label))

    return ".".join(normalized)


def _parse_ip_address(hostname: str) -> IPv4Address | IPv6Address | None:
    """Parse an IP literal, accepting brackets and IPv6 zone identifiers."""
    candidate = hostname.strip()
    bracketed = candidate.startswith("[") and candidate.endswith("]")
    if bracketed:
        candidate = candidate[1:-1]
    elif candidate.startswith("[") or candidate.endswith("]"):
        # Brackets are only valid around IP literals, never around DNS names.
        return None

    # A zone identifier scopes an IPv6 address to a local interface and is not
    # part of the certificate identity.  Compare only the address bytes.
    address, separator, _zone = candidate.partition("%")
    if separator and ":" not in address:
        return None

    try:
        return ipaddress.ip_address(address)
    except ValueError:
        return None


def normalize_hostname(hostname: str) -> str:
    """Return the canonical identity used for certificate matching and SNI.

    DNS names are lowercased, have exactly one trailing root dot removed, are
    IDNA-encoded, and must not contain empty labels.  IP literals are returned
    in compressed form without brackets or an IPv6 zone identifier.
    """
    if not isinstance(hostname, str) or not hostname:
        raise CertificateError("invalid certificate identity: empty hostname")

    host_ip = _parse_ip_address(hostname)
    if host_ip is not None:
        return str(host_ip)
    return _normalize_dns_name(hostname)


# Kept as a private alias for callers that used the previous convention of
# keeping normalization helpers private.
_normalize_hostname = normalize_hostname
_normalize_server_hostname = normalize_hostname


def _dnsname_match(
    dn: typing.Any, hostname: str, max_wildcards: int = 1
) -> typing.Match[str] | None | bool:
    """Matching according to RFC 6125, section 6.4.3

    http://tools.ietf.org/html/rfc6125#section-6.4.3
    """
    if not dn or not isinstance(dn, str):
        return False

    parts = dn.split(".")
    leftmost = parts[0]

    wildcards = leftmost.count("*")
    if wildcards > max_wildcards:
        # Issue #17980: avoid denials of service by refusing more
        # than one wildcard per fragment.  A survey of established
        # policy among SSL implementations showed it to be a
        # reasonable choice.
        raise CertificateError(
            "too many wildcards in certificate DNS name: " + repr(dn)
        )

    # RFC 6125, section 6.4.3, subitem 1.
    # The client SHOULD NOT attempt to match a presented identifier in which
    # the wildcard character comprises a label other than the left-most label.
    if any("*" in frag for frag in parts[1:]):
        return False

    normalized_dn = _normalize_dns_name(dn, allow_wildcards=True)
    try:
        normalized_host = _normalize_dns_name(hostname, allow_wildcards=True)
    except CertificateError:
        # An invalid hostname cannot match anything.  In particular, an empty
        # label must never be treated as something a wildcard can match.  An
        # invalid certificate SAN is different: it raises a CertificateError
        # before reaching this branch so callers can report the certificate as
        # invalid instead of merely mismatched.
        return False

    normalized_parts = normalized_dn.split(".")
    leftmost = normalized_parts[0]
    remainder = normalized_parts[1:]

    # speed up common case w/o wildcards
    if not wildcards:
        return bool(normalized_dn == normalized_host)

    pats = []
    if leftmost == "*":
        # When '*' is a fragment by itself, it matches a non-empty dotless
        # fragment.
        pats.append("[^.]+")
    elif leftmost.startswith("xn--") or normalized_host.startswith("xn--"):
        # RFC 6125, section 6.4.3, subitem 3.
        # The client SHOULD NOT attempt to match a presented identifier
        # where the wildcard character is embedded within an A-label or
        # U-label of an internationalized domain name.
        pats.append(re.escape(leftmost))
    else:
        # Otherwise, '*' matches any dotless string, e.g. www*
        pats.append(re.escape(leftmost).replace(r"\*", "[^.]*"))

    # add the remaining fragments, ignore any wildcards
    for frag in remainder:
        pats.append(re.escape(frag))

    pat = re.compile(r"\A" + r"\.".join(pats) + r"\Z")
    return pat.match(normalized_host)


def _ipaddress_match(ipname: str, host_ip: IPv4Address | IPv6Address) -> bool:
    """Exact matching of IP addresses.

    RFC 9110 section 4.3.5: "A reference identity of IP-ID contains the decoded
    bytes of the IP address. An IP version 4 address is 4 octets, and an IP
    version 6 address is 16 octets. [...] A reference identity of type IP-ID
    matches if the address is identical to an iPAddress value of the
    subjectAltName extension of the certificate."
    """
    # OpenSSL may add a trailing newline to a subjectAltName's IP address
    # Divergence from upstream: ipaddress can't handle byte str
    try:
        ip = ipaddress.ip_address(ipname.rstrip())
    except ValueError as e:
        raise CertificateError(
            "invalid certificate: subjectAltName contains an invalid IP Address"
        ) from e
    return bool(ip.packed == host_ip.packed)


def _verify_certificate_validity(cert: _TYPE_PEER_CERT_RET_DICT) -> None:
    """Reject certificates with an invalid validity period.

    OpenSSL normally performs this check during the handshake.  Keeping the
    check here as well ensures callers that provide a decoded certificate
    directly get the same safe default.
    """
    try:
        import ssl
    except ImportError:  # pragma: no cover - urllib3 can be imported without SSL
        return

    now = time.time()
    for field, error in (
        ("notBefore", "certificate is not yet valid"),
        ("notAfter", "certificate is expired"),
    ):
        value = cert.get(field)  # type: ignore[arg-type]
        if not value:
            continue
        if not isinstance(value, str):
            raise CertificateError(
                f"invalid certificate: malformed {field} value"
            )
        try:
            timestamp = ssl.cert_time_to_seconds(value)
        except (ValueError, TypeError, OverflowError) as e:
            raise CertificateError(
                f"invalid certificate: malformed {field} value"
            ) from e

        if field == "notBefore" and now < timestamp:
            raise CertificateError(f"invalid certificate: {error}")
        if field == "notAfter" and now > timestamp:
            raise CertificateError(f"invalid certificate: {error}")


def match_hostname(
    cert: _TYPE_PEER_CERT_RET_DICT | None,
    hostname: str,
    hostname_checks_common_name: bool = False,
) -> None:
    """Verify that *cert* (in decoded format as returned by
    SSLSocket.getpeercert()) matches the *hostname*.  RFC 2818 and RFC 6125
    rules are followed.

    CertificateError is raised on failure. On success, the function
    returns nothing.
    """
    if not cert:
        raise CertificateError(
            "invalid certificate: empty or no certificate, match_hostname needs a "
            "SSL socket or SSL context with either "
            "CERT_OPTIONAL or CERT_REQUIRED"
        )

    _verify_certificate_validity(cert)

    host_ip = _parse_ip_address(hostname)
    if host_ip is None and "*" in hostname:
        # Wildcards are never valid in a real network hostname, but keep the
        # historical behavior for callers that pass a literal certificate-like
        # name to match_hostname() directly.
        normalized_hostname = _normalize_dns_name(hostname, allow_wildcards=True)
    else:
        normalized_hostname = normalize_hostname(hostname)

    dnsnames: list[str] = []
    ipnames: list[str] = []
    san: tuple[tuple[str, str], ...] = cert.get("subjectAltName") or ()
    key: str
    value: str
    for key, value in san:
        if key == "DNS":
            if host_ip is None and _dnsname_match(value, normalized_hostname):
                return
            dnsnames.append(value)
        elif key == "IP Address":
            if host_ip is not None and _ipaddress_match(value, host_ip):
                return
            ipnames.append(value)

    # We only check 'commonName' if it's enabled and we're not verifying
    # an IP address. IP addresses aren't valid within 'commonName'.
    if hostname_checks_common_name and host_ip is None and not dnsnames and not ipnames:
        for sub in cert.get("subject") or ():
            for key, value in sub:
                if key == "commonName":
                    if _dnsname_match(value, normalized_hostname):
                        return
                    dnsnames.append(value)  # Defensive: older PyPy/OpenSSL

    if host_ip is not None:
        if not ipnames:
            if dnsnames:
                raise CertificateError(
                    "certificate SAN mismatch (IP SAN): IP literal "
                    f"{hostname!r} cannot be matched against DNS SANs; "
                    "a matching IP SAN (IP Address subjectAltName) is required"
                )
            raise CertificateError(
                "certificate SAN mismatch (IP SAN): no matching IP SAN "
                "(IP Address subjectAltName) was found"
            )

        host_version = host_ip.version
        san_versions = set()
        for name in ipnames:
            try:
                san_versions.add(ipaddress.ip_address(name.rstrip()).version)
            except ValueError:
                raise CertificateError(
                    "invalid certificate: subjectAltName contains an invalid IP Address"
                ) from None
        if host_version not in san_versions:
            raise CertificateError(
                "certificate IP SAN type mismatch (IP type mismatch): "
                f"hostname {hostname!r} is IPv{host_version} but the certificate "
                f"only contains IPv{', IPv'.join(map(str, sorted(san_versions)))} "
                "Address SANs"
            )
        if len(ipnames) == 1:
            raise CertificateError(
                "certificate SAN mismatch (IP SAN): hostname "
                f"{hostname!r} doesn't match {ipnames[0]!r}"
            )
        raise CertificateError(
            "certificate SAN mismatch (IP SAN): hostname "
            f"{hostname!r} doesn't match either of " + ", ".join(map(repr, ipnames))
        )

    if not dnsnames and ipnames:
        raise CertificateError(
            "certificate SAN mismatch (DNS SAN): certificate only contains "
            "IP SANs (IP Address subjectAltName), which cannot match DNS hostname "
            f"{hostname!r}"
        )
    if dnsnames:
        names = dnsnames + ipnames
        if len(names) == 1:
            raise CertificateError(
                "certificate SAN mismatch (DNS SAN): hostname "
                f"{hostname!r} doesn't match {names[0]!r}"
            )
        raise CertificateError(
            "certificate SAN mismatch (DNS SAN): hostname "
            f"{hostname!r} doesn't match either of " + ", ".join(map(repr, names))
        )
    raise CertificateError(
        "certificate SAN mismatch: no appropriate subjectAltName fields were found"
    )
