# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import ipaddress
import socket

try:
    from urllib.parse import urlsplit
except (ImportError):
    from urlparse import urlsplit

from asn1crypto import x509

from ._errors import pretty_message
from ._types import byte_cls, str_cls


# GeneralName choices that RFC 5280 section 4.2.1.10 defines matching rules
# for. Names of any other type can not be evaluated against name constraints.
_CHECKED_NAME_TYPES = frozenset([
    'rfc822_name',
    'dns_name',
    'uniform_resource_identifier',
    'ip_address',
    'directory_name',
])


class NameConstraintViolation(Exception):
    """
    Raised when a certificate contains a name that falls outside of the
    permitted subtrees, or inside an excluded subtree, accumulated along the
    validation path.
    """


class NameConstraintIndeterminate(Exception):
    """
    Raised when a name (or a name constraint) can not be normalized and
    evaluated, meaning compliance with the name constraints can not be
    determined instead of being treated as allowed.
    """


class _IpConstraint(object):

    def __init__(self, network):
        self.network = network

    def matches(self, address):
        return address in self.network


class _DnsName(object):

    def __init__(self, labels):
        self.labels = labels


class _EmailName(object):

    def __init__(self, local_part, domain_labels):
        self.local_part = local_part
        self.domain_labels = domain_labels


class _UriName(object):

    def __init__(self, host_labels):
        self.host_labels = host_labels


class _DirectoryName(object):

    def __init__(self, rdns):
        self.rdns = rdns


class _NameConstraintState(object):
    """
    Accumulates the permitted and excluded subtrees defined via the name
    constraints extension of the CA certificates along a validation path,
    following RFC 5280 section 6.1.4.

    An empty permitted-subtree list for a name type means any name of that
    type is permitted; the absence of a nameConstraints extension is never
    treated as permission for arbitrary names.
    """

    def __init__(self):
        # Keys are GeneralName choice names, values are lists of normalized
        # constraint objects accumulated from every CA in the path.
        self._permitted = {}
        self._excluded = {}

    def add_certificate(self, cert):
        """
        Folds the name constraints extension of a CA certificate into the
        accumulated state.

        :param cert:
            An asn1crypto.x509.Certificate object of a CA in the path
        """

        name_constraints = cert.name_constraints_value
        if name_constraints is None:
            return

        permitted = name_constraints['permitted_subtrees']
        if permitted:
            for general_subtree in permitted:
                self._add_subtree(self._permitted, general_subtree['base'])

        excluded = name_constraints['excluded_subtrees']
        if excluded:
            for general_subtree in excluded:
                self._add_subtree(self._excluded, general_subtree['base'])

    def check_certificate(self, cert):
        """
        Checks all subject and subject alternative names of a certificate in
        the path against the accumulated permitted and excluded subtrees.

        :param cert:
            An asn1crypto.x509.Certificate object to check
        """

        general_names = []

        san = cert.subject_alt_name_value
        if san is not None:
            for general_name in san:
                general_names.append(general_name)
        else:
            # When no SAN extension is present, the distinguished name is
            # checked against directory name constraints, and any CN
            # attribute values are treated as DNS names per common name
            # constraint implementations.
            general_names.append(x509.GeneralName(
                name='directory_name',
                value=cert.subject
            ))
            for common_name in _common_names(cert.subject):
                general_names.append(x509.GeneralName(
                    name='dns_name',
                    value=common_name
                ))

        for general_name in general_names:
            self._check_general_name(general_name)

    def _add_subtree(self, bucket, general_name):
        name_type = general_name.name
        if name_type not in _CHECKED_NAME_TYPES:
            raise NameConstraintIndeterminate(pretty_message(
                """
                The path could not be validated because a name constraint uses
                the unsupported GeneralName type %s, so compliance with the
                constraint can not be determined
                """,
                name_type
            ))

        constraint = self._normalize_constraint(general_name)
        bucket.setdefault(name_type, []).append(constraint)

    def _check_general_name(self, general_name):
        name_type = general_name.name
        if name_type not in _CHECKED_NAME_TYPES:
            # RFC 5280 only requires matching for the supported name types;
            # names without matching rules neither violate nor satisfy the
            # accumulated constraints.
            return

        try:
            candidate = self._normalize_name(general_name)
        except (NameConstraintIndeterminate):
            raise
        except (ValueError, socket.error, UnicodeError) as e:
            raise NameConstraintIndeterminate(pretty_message(
                """
                The path could not be validated because the %s name %s could
                not be normalized, so compliance with the name constraints
                can not be determined: %s
                """,
                name_type,
                _display_name(general_name),
                str_cls(e)
            ))

        for constraint in self._excluded.get(name_type, []):
            if _matches(constraint, candidate):
                raise NameConstraintViolation(pretty_message(
                    """
                    The path could not be validated because the name %s is
                    within an excluded subtree
                    """,
                    _display_name(general_name)
                ))

        permitted = self._permitted.get(name_type)
        if permitted and not any(_matches(constraint, candidate) for constraint in permitted):
            raise NameConstraintViolation(pretty_message(
                """
                The path could not be validated because the name %s is not
                within any of the permitted subtrees
                """,
                _display_name(general_name)
            ))

    def _normalize_constraint(self, general_name):
        name_type = general_name.name
        if name_type == 'dns_name':
            return _normalize_dns(_general_name_text(general_name))
        if name_type == 'rfc822_name':
            return _normalize_email(_general_name_text(general_name))
        if name_type == 'uniform_resource_identifier':
            return _normalize_uri(_general_name_text(general_name))
        if name_type == 'ip_address':
            return _normalize_ip_constraint(general_name.contents)
        if name_type == 'directory_name':
            return _normalize_directory(general_name.chosen)
        raise NameConstraintIndeterminate(pretty_message(
            'Unsupported name constraint type %s',
            name_type
        ))

    def _normalize_name(self, general_name):
        name_type = general_name.name
        if name_type == 'dns_name':
            return _normalize_dns(_general_name_text(general_name))
        if name_type == 'rfc822_name':
            return _normalize_email(_general_name_text(general_name))
        if name_type == 'uniform_resource_identifier':
            return _normalize_uri(_general_name_text(general_name))
        if name_type == 'ip_address':
            return _normalize_ip_address(general_name.contents)
        if name_type == 'directory_name':
            return _normalize_directory(general_name.chosen)
        raise NameConstraintIndeterminate(pretty_message(
            'Unsupported GeneralName type %s',
            name_type
        ))


def _common_names(name):
    common_names = []
    for rdn in name.chosen:
        for attribute_type_and_value in rdn:
            if attribute_type_and_value['type'].native == 'common_name':
                common_names.append(attribute_type_and_value['value'].native)
    return common_names


def _general_name_text(general_name):
    """
    Returns the unicode text backing a dnsName, rfc822Name or URI GeneralName.

    asn1crypto eagerly decodes DNS names as IDNA, which raises for certificates
    that store internationalized names as raw U-labels instead of A-labels.
    The raw IA5/UTF-8 bytes are still usable by the normalization routines in
    this module, so fall back to decoding them directly.
    """

    try:
        return general_name.native
    except (UnicodeDecodeError, UnicodeError, ValueError):
        chosen = general_name.chosen
        contents = chosen.contents if hasattr(chosen, 'contents') else chosen
        return contents.decode('utf-8')


def _idna_encode_label(label):
    # encodings.idna operates on individual labels, which matches the IDNA
    # handling of asn1crypto's DNSName type and keeps wildcard labels intact.
    return label.encode('idna').decode('ascii').lower()


def _normalize_dns(value):
    if not isinstance(value, str_cls):
        raise ValueError('DNS names must be unicode strings')

    trailing_dot = value.endswith('.')
    if trailing_dot:
        value = value[:-1]

    if not value:
        raise ValueError('DNS names may not be empty')

    labels = value.split('.')
    return _DnsName([_idna_encode_label(label) for label in labels])


def _matches_dns(constraint, candidate):
    # A constraint beginning with a dot is encoded as an empty first label;
    # such a constraint only matches sub-domains, while a constraint without
    # a leading dot matches the domain and its sub-domains.
    constraint_labels = constraint.labels
    candidate_labels = candidate.labels
    subdomains_only = bool(constraint_labels) and constraint_labels[0] == ''
    constraint_labels = constraint_labels[1:] if subdomains_only else constraint_labels

    if not constraint_labels:
        raise ValueError('DNS name constraints may not be empty')

    # A sub-tree constraint can never match a name that is not strictly longer
    # (sub-domain-only) or at least as long as the constraint.
    if subdomains_only and len(candidate_labels) <= len(constraint_labels):
        return False
    if not subdomains_only and len(candidate_labels) < len(constraint_labels):
        return False
    return candidate_labels[-len(constraint_labels):] == constraint_labels


def _normalize_email(value):
    if not isinstance(value, str_cls) or not value:
        raise ValueError('RFC822 names must be non-empty unicode strings')
    if '@' not in value:
        # Domain-only constraints such as "example.com" apply to any mailbox
        # in the matching domain.
        subdomains_only = value.startswith('.')
        if subdomains_only:
            value = value[1:]
            return _EmailName('', [''] + _normalize_dns(value).labels)
        return _EmailName('', _normalize_dns(value).labels)
    local_part, domain = value.rsplit('@', 1)
    if not local_part or not domain:
        raise ValueError('RFC822 names must contain a local part and a domain')
    return _EmailName(local_part.lower(), _normalize_dns(domain).labels)


def _matches_email(constraint, candidate):
    constraint_local = constraint.local_part
    constraint_domain = constraint.domain_labels
    candidate_local = candidate.local_part
    candidate_domain = candidate.domain_labels
    if constraint_local:
        return constraint_local == candidate_local and tuple(constraint_domain) == tuple(candidate_domain)
    subdomains_only = bool(constraint_domain) and constraint_domain[0] == ''
    domain_labels = tuple(constraint_domain[1:] if subdomains_only else constraint_domain)
    if subdomains_only and len(candidate_domain) <= len(domain_labels):
        return False
    if not subdomains_only and len(candidate_domain) < len(domain_labels):
        return False
    return tuple(candidate_domain[-len(domain_labels):]) == domain_labels


def _normalize_uri(value):
    if not isinstance(value, str_cls):
        raise ValueError('URIs must be unicode strings')
    subdomains_only = value.startswith('.')
    if subdomains_only:
        value = value[1:]
    parseable = value if '://' in value else '//' + value
    parts = urlsplit(parseable)
    host = parts.hostname
    if not host:
        raise ValueError('URIs must include a host component')
    # RFC 5280 allows URI constraints to start with a leading period so that
    # only sub-domains of the host portion match.
    if subdomains_only:
        return _UriName([''] + _normalize_dns(host).labels)
    return _UriName(_normalize_dns(host).labels)


def _matches_uri(constraint, candidate):
    constraint_labels = constraint.host_labels
    candidate_labels = candidate.host_labels
    subdomains_only = bool(constraint_labels) and constraint_labels[0] == ''
    constraint_labels = constraint_labels[1:] if subdomains_only else constraint_labels

    if not constraint_labels:
        raise ValueError('URI name constraints may not be empty')

    if subdomains_only and len(candidate_labels) <= len(constraint_labels):
        return False
    if not subdomains_only and len(candidate_labels) < len(constraint_labels):
        return False
    return candidate_labels[-len(constraint_labels):] == constraint_labels


def _normalize_ip_constraint(raw_bytes):
    if not isinstance(raw_bytes, byte_cls):
        raise ValueError('IP name constraints must be byte strings')

    if len(raw_bytes) == 8:
        address = ipaddress.ip_address(raw_bytes[0:4])
        mask = ipaddress.ip_address(raw_bytes[4:8])
        return _IpConstraint(_network_from_address_mask(address, mask))
    if len(raw_bytes) == 32:
        address = ipaddress.ip_address(raw_bytes[0:16])
        mask = ipaddress.ip_address(raw_bytes[16:32])
        return _IpConstraint(_network_from_address_mask(address, mask))
    if len(raw_bytes) == 4:
        return _IpConstraint(ipaddress.ip_network('%s/32' % ipaddress.ip_address(raw_bytes), strict=False))
    if len(raw_bytes) == 16:
        return _IpConstraint(ipaddress.ip_network('%s/128' % ipaddress.ip_address(raw_bytes), strict=False))

    raise NameConstraintIndeterminate(pretty_message(
        """
        The path could not be validated because an IP name constraint is %d
        bytes long instead of 4, 8, 16 or 32 bytes, so compliance can not be
        determined
        """,
        len(raw_bytes)
    ))


def _network_from_address_mask(address, mask):
    prefix_length = bin(int(mask)).count('1')
    return ipaddress.ip_network('%s/%d' % (address, prefix_length), strict=False)


def _normalize_ip_address(raw_bytes):
    if not isinstance(raw_bytes, byte_cls):
        raise ValueError('IP addresses must be byte strings')
    if len(raw_bytes) not in (4, 16):
        raise ValueError('IP addresses must be 4 bytes for IPv4 or 16 bytes for IPv6')
    return ipaddress.ip_address(raw_bytes)


def _matches_ip(constraint, candidate):
    return constraint.matches(candidate)


def _normalize_directory(name):
    rdns = []
    for rdn in name.chosen:
        attributes = []
        for attribute_type_and_value in rdn:
            oid = attribute_type_and_value['type'].native
            value = attribute_type_and_value['value']
            attributes.append((oid, _directory_value(oid, value.native)))
        rdns.append(tuple(attributes))
    return _DirectoryName(tuple(rdns))


def _directory_value(oid, value):
    # Email addresses and DNS names embedded in distinguished names are name
    # forms that are compared case-insensitively per RFC 5280 section 7.
    if oid in ('email_address', 'domain_component') and isinstance(value, str_cls):
        return value.lower()
    return value


def _matches_directory(constraint, candidate):
    # RFC 5280 section 4.2.1.10: a directory name is within a subtree if the
    # constraint RDN sequence is a prefix of the certificate RDN sequence,
    # where each relative distinguished name is compared in full.
    constraint_rdns = constraint.rdns
    candidate_rdns = candidate.rdns
    if len(constraint_rdns) > len(candidate_rdns):
        return False
    for constraint_rdn, candidate_rdn in zip(constraint_rdns, candidate_rdns):
        if constraint_rdn != candidate_rdn:
            return False
    return True


def _matches(constraint, candidate):
    if isinstance(candidate, _DnsName):
        return _matches_dns(constraint, candidate)
    if isinstance(candidate, _EmailName):
        return _matches_email(constraint, candidate)
    if isinstance(candidate, _UriName):
        return _matches_uri(constraint, candidate)
    if isinstance(candidate, _DirectoryName):
        return _matches_directory(constraint, candidate)
    if isinstance(constraint, _IpConstraint):
        return _matches_ip(constraint, candidate)
    return constraint == candidate


def _display_name(general_name):
    try:
        native = general_name.native
        if isinstance(native, byte_cls):
            return repr(native)
        return str_cls(native)
    except (Exception):
        try:
            return _general_name_text(general_name)
        except (Exception):
            return general_name.name
