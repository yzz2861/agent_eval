"""
Host name normalization and server certificate identity matching.

The checks implemented here follow RFC 6125 (DNS identifiers), RFC 5280 and
RFC 3986 (IP literals) and are independent from the Python interpreter's
``ssl.match_hostname`` version, so the same rules (DNS SAN, IP SAN, IDNA and
IPv6 zone identifiers) apply on every supported interpreter.
"""

import re

from .. import STRING_TYPES
from .log import log, log_enabled, NETWORK

try:
    import ipaddress
except ImportError:  # pragma: no cover - Python 2 without the backport
    ipaddress = None


class HostType(object):
    DNS = 'DNS'
    IP = 'IP'


class NormalizedHost(object):
    """A host identifier split into the part that must be compared with the
    certificate and the part that may be sent as SNI."""

    __slots__ = ('raw', 'host_type', 'is_ipv6', 'zone_id', 'match_value', 'sni_value')

    def __init__(self, raw, host_type, is_ipv6, zone_id, match_value, sni_value):
        self.raw = raw
        self.host_type = host_type
        self.is_ipv6 = is_ipv6
        self.zone_id = zone_id
        # value used when comparing against the certificate SAN entries
        self.match_value = match_value
        # value sent as SNI; None means "do not send SNI"
        self.sni_value = sni_value

    def __str__(self):
        return self.match_value


def _strip_url_wrappers(host):
    # Server() keeps host names without scheme, but defensive code accepts
    # ldap://host and bracketed IPv6 literals too.
    if host.startswith('[') and ']' in host:
        return host[1:host.index(']')]
    return host


def normalize_host(host):
    """Normalize a host name or IP literal.

    * IPv4 and IPv6 literals are parsed with :mod:`ipaddress`; an IPv6 zone
      identifier is remembered for the connection layer but never used when
      matching the certificate (certificates cannot carry zone identifiers).
    * DNS names are lowercased and IDNA encoded (A-label) so unicode names
      match A-label SAN entries and vice versa.
    * SNI uses the normalized DNS name; IP literals do not get a DNS-style SNI.
    """
    if host is None:
        raise ValueError('host cannot be None')
    if isinstance(host, bytes):
        host = host.decode('utf-8')
    if not isinstance(host, STRING_TYPES):
        raise ValueError('host must be a string, got %r' % type(host))

    raw = host
    host = host.strip()
    host = _strip_url_wrappers(host)
    if not host:
        raise ValueError('host cannot be empty')

    zone_id = None
    candidate = host
    if '%' in host:
        candidate, zone_id = host.split('%', 1)

    if ipaddress is not None:
        try:
            ip = ipaddress.ip_address(candidate)
        except ValueError:
            ip = None
    else:  # pragma: no cover - Python 2 without the ipaddress backport
        ip = None

    if ip is not None:
        is_ipv6 = isinstance(ip, ipaddress.IPv6Address)
        match_value = str(ip)
        # RFC 6066: SNI carries DNS names only, never IP literals.
        return NormalizedHost(raw, HostType.IP, is_ipv6, zone_id, match_value, None)

    dns_name = _normalize_dns_name(candidate)
    return NormalizedHost(raw, HostType.DNS, False, None, dns_name, dns_name)


def _normalize_dns_name(name):
    if name.endswith('.'):
        name = name[:-1]
    if not name:
        raise ValueError('invalid empty DNS name')

    labels = name.split('.')
    normalized_labels = []
    for label in labels:
        if not label:
            raise ValueError('invalid DNS name %r' % name)
        try:
            encoded = label.encode('idna')
        except UnicodeError:
            raise ValueError('invalid IDNA label %r' % label)
        normalized_labels.append(encoded.decode('ascii'))
    return '.'.join(normalized_labels).lower()


def dns_name_matches(cert_dns_name, host_name):
    """RFC 6125 DNS name matching with strict wildcard handling.

    A wildcard is accepted only in the left-most label and only matches a
    single, non-empty label, so ``*.example.com`` never matches
    ``a.b.example.com``. Embedded wildcards (``www*.example.com``) are
    supported for a single label as well.
    """
    if not cert_dns_name or not host_name:
        return False

    cert_labels = cert_dns_name.rstrip('.').lower().split('.')
    host_labels = host_name.rstrip('.').lower().split('.')
    if len(cert_labels) != len(host_labels):
        return False

    first = cert_labels[0]
    if '*' in first:
        if first.count('*') > 1:
            return False
        # wildcard must stay in the left-most label
        wildcard_pattern = re.compile(r'\A' + re.escape(first).replace(r'\*', r'[^.]*') + r'\Z')
        if not wildcard_pattern.match(host_labels[0]):
            return False
        cert_labels = cert_labels[1:]
        host_labels = host_labels[1:]

    return cert_labels == host_labels


def ip_name_matches(cert_ip_name, host_ip):
    """Compare an iPAddress SAN (string form from :func:`ssl.getpeercert`)
    with a normalized IP literal."""
    if ipaddress is None:  # pragma: no cover - Python 2 without the backport
        return cert_ip_name == host_ip
    try:
        return ipaddress.ip_address(cert_ip_name) == ipaddress.ip_address(host_ip)
    except ValueError:
        return False


def get_certificate_identities(peer_cert):
    """Return the ``(dns_names, ip_names, has_san, common_names)`` carried by
    a decoded certificate. ``has_san`` is True whenever a subjectAltName
    extension is present, even if it contains no usable DNS/IP entries, because
    RFC 6125 forbids falling back to the commonName in that situation."""
    san = peer_cert.get('subjectAltName', ()) if peer_cert else ()
    has_san = 'subjectAltName' in peer_cert if peer_cert else False
    dns_names = []
    ip_names = []
    for entry_type, entry_value in san:
        if entry_type == 'DNS':
            dns_names.append(entry_value)
        elif entry_type == 'IP Address':
            ip_names.append(entry_value)

    common_names = []
    for rdn in peer_cert.get('subject', ()) if peer_cert else ():
        for attribute_type, attribute_value in rdn:
            if attribute_type == 'commonName':
                common_names.append(attribute_value)

    if log_enabled(NETWORK):
        log(NETWORK, 'certificate identities - DNS SAN: %s - IP SAN: %s - SAN present: %s - CN: %s',
            dns_names, ip_names, has_san, common_names)
    return dns_names, ip_names, has_san, common_names


def match_certificate_identity(peer_cert, normalized_host, allow_common_name_fallback=False):
    """Return the certificate identity that matches the normalized host.

    Raises :class:`ValueError` (with a descriptive message) when no identity
    matches. Matching order:

    1. IP hosts only match ``iPAddress`` SAN entries (never DNS names/CN).
    2. DNS hosts match ``dNSName`` SAN entries, including strict wildcards.
    3. The subject commonName is used only when the certificate has no SAN at
       all, the host is a DNS name and fallback was explicitly enabled.
    """
    dns_names, ip_names, has_san, common_names = get_certificate_identities(peer_cert)
    host_value = normalized_host.match_value

    if normalized_host.host_type == HostType.IP:
        for ip_name in ip_names:
            if ip_name_matches(ip_name, host_value):
                return 'IP Address', ip_name
        raise ValueError('IP address %r not found in certificate IP SAN %r' % (host_value, ip_names))

    for dns_name in dns_names:
        if dns_name_matches(dns_name, host_value):
            return 'DNS', dns_name

    if has_san:
        raise ValueError('host name %r not found in certificate SAN (DNS: %r, IP: %r)'
                         % (host_value, dns_names, ip_names))

    if allow_common_name_fallback:
        for common_name in common_names:
            try:
                normalized_cn = normalize_host(common_name)
            except ValueError:
                continue
            if normalized_cn.host_type == HostType.DNS and dns_name_matches(common_name, host_value):
                return 'CN', common_name
        raise ValueError('host name %r not found in certificate commonName %r (no SAN present)'
                         % (host_value, common_names))

    raise ValueError('host name %r cannot be verified: certificate has no subjectAltName and '
                     'commonName fallback is disabled' % host_value)
