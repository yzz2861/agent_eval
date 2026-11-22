# coding: utf-8

"""
Compares an approved certificate signing request (CSR) with an issued X.509
certificate. Exports the following items:

 - ApprovalPolicy()
 - ExtensionComparison()
 - ComparisonView()
 - compare_csr_to_certificate()
 - compare()

The comparison is structural and is intended to be embedded in a certificate
approval/audit backend. It does not verify either signature.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

import binascii
import copy
import hashlib
from datetime import datetime

from . import csr as csr_module
from . import x509
from ._errors import unwrap
from ._ordereddict import OrderedDict
from ._types import byte_cls, int_types, str_cls, type_name
from .core import Void
from .pem import detect as pem_detect
from .pem import unarmor as pem_unarmor


__all__ = [
    'ApprovalPolicy',
    'CSRComparison',
    'CertificateComparison',
    'ComparisonView',
    'ExtensionComparison',
    'compare',
    'compare_certificate_to_csr',
    'compare_csr_to_certificate',
    'build_comparison_view',
    'STATUS_EXACT',
    'STATUS_NARROWED',
    'STATUS_OMITTED',
    'STATUS_WIDENED',
    'STATUS_MISMATCH',
    'STATUS_ISSUER_ADDED',
    'STATUS_UNREQUESTED',
    'SEVERITY_INFO',
    'SEVERITY_WARNING',
    'SEVERITY_ERROR',
    'VERDICT_APPROVED',
    'VERDICT_REVIEW',
    'VERDICT_REJECTED',
]


STATUS_EXACT = 'exact'
STATUS_NARROWED = 'narrowed'
STATUS_OMITTED = 'omitted'
STATUS_WIDENED = 'widened'
STATUS_MISMATCH = 'mismatch'
STATUS_ISSUER_ADDED = 'issuer_added'
STATUS_UNREQUESTED = 'unrequested'
STATUS_CHANGED = 'changed'
STATUS_KEY_REPLACED = 'key_replaced'

SEVERITY_INFO = 'info'
SEVERITY_WARNING = 'warning'
SEVERITY_ERROR = 'error'

VERDICT_APPROVED = 'approved'
VERDICT_REVIEW = 'review_required'
VERDICT_REJECTED = 'rejected'


def _as_bytes(value):
    """
    :param value:
        A byte string or bytearray

    :return:
        A byte string
    """

    if isinstance(value, bytearray):
        return byte_cls(value)
    return value


def _hex(value):
    """
    :param value:
        A byte string

    :return:
        A lower-case hexadecimal unicode string
    """

    return binascii.hexlify(_as_bytes(value)).decode('ascii')


def _sha256_hex(value):
    """
    :param value:
        A byte string

    :return:
        A lower-case SHA-256 hexadecimal unicode string
    """

    return hashlib.sha256(_as_bytes(value)).hexdigest()


def _stable_repr(value):
    """
    Produces a deterministic representation for canonical values. Unlike repr(),
    this sorts sets and dictionaries so semantic fingerprints are stable across
    processes and Python versions.
    """

    if isinstance(value, tuple):
        return '(' + ','.join([_stable_repr(part) for part in value]) + ')'
    if isinstance(value, (set, frozenset)):
        parts = sorted([_stable_repr(part) for part in value])
        return 'set(' + ','.join(parts) + ')'
    if isinstance(value, dict):
        parts = []
        for key in sorted(value.keys(), key=lambda item: str_cls(item)):
            parts.append('%s:%s' % (_stable_repr(key), _stable_repr(value[key])))
        return '{' + ','.join(parts) + '}'
    return repr(value)


def _json_safe(value):
    """
    Converts native ASN.1 values into JSON-safe Python values while preserving
    all information needed by a review UI.
    """

    if isinstance(value, dict):
        output = OrderedDict()
        for key in value.keys():
            output[str_cls(key)] = _json_safe(value[key])
        return output
    if isinstance(value, (list, tuple)):
        return [_json_safe(part) for part in value]
    if isinstance(value, (set, frozenset)):
        return [_json_safe(part) for part in sorted(value, key=_stable_repr)]
    if isinstance(value, bytearray):
        return _hex(byte_cls(value))
    if isinstance(value, byte_cls):
        return _hex(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if value is None or isinstance(value, bool) or isinstance(value, str_cls) or isinstance(value, int_types):
        return value
    if isinstance(value, float):
        return value
    return str_cls(value)


def _canonicalize(value):
    """
    Converts a native ASN.1 value into a hashable, order-insensitive form where
    appropriate. Dictionaries are sorted by key and sets are represented as
    frozensets. Lists and tuples remain ordered.
    """

    if isinstance(value, dict):
        items = []
        for key in value.keys():
            items.append((str_cls(key), _canonicalize(value[key])))
        items.sort(key=lambda part: part[0])
        return ('dict', tuple(items))
    if isinstance(value, (list, tuple)):
        return ('list', tuple([_canonicalize(part) for part in value]))
    if isinstance(value, (set, frozenset)):
        return ('set', frozenset([_canonicalize(part) for part in value]))
    if isinstance(value, bytearray):
        return ('bytes', _hex(byte_cls(value)))
    if isinstance(value, byte_cls):
        return ('bytes', _hex(value))
    if isinstance(value, datetime):
        return ('datetime', value.isoformat())
    if value is None or isinstance(value, bool) or isinstance(value, str_cls) or isinstance(value, int_types):
        return value
    if isinstance(value, float):
        return ('float', repr(value))
    return ('text', str_cls(value))


def _canonical_general_name(value):
    """
    Canonicalizes a GeneralName native value. DNS names are case-insensitive,
    matching RFC 5280 comparison rules, while other name forms are compared by
    their parsed value.
    """

    if isinstance(value, dict) and 'type' in value:
        name_type = str_cls(value.get('type'))
        name_value = value.get('value')
        if name_type == 'dns_name' and isinstance(name_value, str_cls):
            name_value = name_value.lower()
            if name_value.endswith('.'):
                name_value = name_value[:-1]
        elif name_type == 'rfc822_name' and isinstance(name_value, str_cls) and '@' in name_value:
            local_part, domain = name_value.rsplit('@', 1)
            name_value = '%s@%s' % (local_part, domain.lower())
        return ('general_name', name_type, _canonicalize(name_value))
    return ('general_name', _canonicalize(value))


def _canonical_policy(value):
    """
    Canonicalizes a CertificatePolicies entry, retaining qualifiers so a
    changed policy document is visible, not just a changed policy OID.
    """

    if isinstance(value, dict):
        return (
            'policy',
            str_cls(value.get('policy_identifier')),
            _canonicalize(value.get('policy_qualifiers'))
        )
    return ('policy', _canonicalize(value))


def _canonical_name(name):
    """
    Canonicalizes an X.509 Name using its native representation. Different
    string encodings that decode to the same value therefore compare equal.
    """

    if name is None:
        return None
    return _canonicalize(name.native)


def _canonical_spki(spki):
    """
    Canonicalizes a SubjectPublicKeyInfo by algorithm and key bits, retaining
    enough information to distinguish a replaced key from a different encoding
    of the same key.
    """

    if spki is None:
        return None
    algorithm = spki['algorithm']
    try:
        parameters = algorithm['parameters'].native
    except Exception:
        parameters = None
    return (
        'spki',
        str_cls(algorithm['algorithm'].native),
        _canonicalize(parameters),
        _hex(byte_cls(spki['public_key']))
    )


def _semantic_fingerprint(name, semantic):
    """
    :return:
        A hexadecimal SHA-256 of the extension name and canonical value
    """

    payload = (str_cls(name) + '\x00' + _stable_repr(semantic)).encode('utf-8')
    return hashlib.sha256(payload).hexdigest()


def _extension_evidence(extension, path):
    """
    Captures the exact encodings that led to a match or mismatch. Keeping both
    hashes and DER hex allows a reviewer to inspect semantically equivalent
    requests that were encoded differently.
    """

    oid = extension['extn_id']
    value_der = extension['extn_value'].contents
    if value_der is None:
        value_der = b''
    value_der = _as_bytes(value_der)
    extension_der = _as_bytes(extension.dump())
    oid_der = _as_bytes(oid.dump())
    return OrderedDict([
        ('path', path),
        ('oid_der_hex', _hex(oid_der)),
        ('oid_der_sha256', _sha256_hex(oid_der)),
        ('value_der_hex', _hex(value_der)),
        ('value_der_sha256', _sha256_hex(value_der)),
        ('extension_der_sha256', _sha256_hex(extension_der)),
    ])


def _canonical_general_name_object(general_name):
    name_type = general_name.name
    try:
        name_value = general_name.chosen.native
    except Exception:
        name_value = general_name.chosen
    if name_type == 'dns_name' and isinstance(name_value, str_cls):
        name_value = name_value.lower()
        if name_value.endswith('.'):
            name_value = name_value[:-1]
    elif name_type == 'rfc822_name' and isinstance(name_value, str_cls) and '@' in name_value:
        local_part, domain = name_value.rsplit('@', 1)
        name_value = '%s@%s' % (local_part, domain.lower())
    return ('general_name', name_type, _canonicalize(name_value))


def _subset_definitions(name, native, parsed=None):
    """
    Returns the individual items relevant to a subset-style narrowing rule and
    a mapping from canonical item to display value.

    :return:
        A 2-element tuple of (frozenset or None, dict)
    """

    if name == 'key_usage':
        items = native if isinstance(native, (set, frozenset)) else []
        canonical = [_canonicalize(item) for item in items]
        labels = dict((_canonicalize(item), _json_safe(item)) for item in items)
        return frozenset(canonical), labels

    if name == 'extended_key_usage':
        items = native if isinstance(native, list) else []
        canonical = [_canonicalize(item) for item in items]
        labels = dict((_canonicalize(item), _json_safe(item)) for item in items)
        return frozenset(canonical), labels

    if name in ('subject_alt_name', 'issuer_alt_name'):
        if parsed is not None:
            items = list(parsed)
            canonical = [_canonical_general_name_object(item) for item in items]
            labels = dict()
            for index, item in enumerate(items):
                try:
                    value = item.chosen.native
                except Exception:
                    value = None
                labels[canonical[index]] = OrderedDict([
                    ('type', item.name),
                    ('value', _json_safe(value)),
                ])
            return frozenset(canonical), labels
        items = native if isinstance(native, list) else []
        canonical = [_canonical_general_name(item) for item in items]
        labels = dict()
        for index, item in enumerate(items):
            labels[canonical[index]] = _json_safe(item)
        return frozenset(canonical), labels

    if name == 'certificate_policies':
        items = native if isinstance(native, list) else []
        canonical = []
        labels = dict()
        for item in items:
            policy_id = str_cls(item.get('policy_identifier')) if isinstance(item, dict) else str_cls(item)
            canonical.append(_canonicalize(policy_id))
            labels[_canonicalize(policy_id)] = policy_id
        return frozenset(canonical), labels

    if name == 'tls_feature':
        items = native if isinstance(native, list) else []
        canonical = [_canonicalize(item) for item in items]
        labels = dict((_canonicalize(item), _json_safe(item)) for item in items)
        return frozenset(canonical), labels

    if name == 'subject_directory_attributes':
        items = native if isinstance(native, list) else []
        canonical = [_canonicalize(item) for item in items]
        labels = dict((_canonicalize(item), _json_safe(item)) for item in items)
        return frozenset(canonical), labels

    return None, dict()


def _semantic_value(name, native, raw_value_der, parse_error, parsed=None):
    """
    Produces the canonical value used for semantic equality and subset checks.

    Unknown extension OIDs and values that could not be parsed fall back to the
    exact extnValue DER, which prevents unrelated opaque extensions from being
    accidentally treated as equal.
    """

    if parse_error is not None or native is None:
        return ('raw', _hex(raw_value_der))

    if name in x509.Extension._oid_specs:
        if name in (
            'key_usage',
            'extended_key_usage',
            'subject_alt_name',
            'issuer_alt_name',
            'tls_feature',
            'subject_directory_attributes'
        ):
            items, _ = _subset_definitions(name, native, parsed)
            if items is not None:
                return items
        if name == 'certificate_policies':
            if isinstance(native, list):
                return frozenset([_canonical_policy(item) for item in native])
        return _canonicalize(native)

    return ('raw', _hex(raw_value_der))


def _record_from_extension(extension, path, indexes=None):
    """
    Builds the internal representation shared by requested and issued
    extensions.
    """

    indexes = indexes or dict()
    oid_object = extension['extn_id']
    oid = oid_object.dotted
    name = oid_object.native
    critical = bool(extension['critical'].native)
    raw = _extension_evidence(extension, path)

    parsed = None
    native = None
    parse_error = None
    try:
        parsed = extension['extn_value'].parsed
        native = parsed.native
    except Exception as exception:
        parse_error = str_cls(exception)

    raw_value_der = binascii.unhexlify(raw['value_der_hex'].encode('ascii'))
    semantic = _semantic_value(name, native, raw_value_der, parse_error, parsed)
    subset_items, item_labels = _subset_definitions(name, native, parsed)
    if parse_error is not None:
        subset_items = None
        item_labels = dict()

    display = _json_safe(native)
    if parse_error is not None:
        display = OrderedDict([('raw_der_hex', raw['value_der_hex'])])

    record = OrderedDict([
        ('extension', extension),
        ('oid', oid),
        ('extension_name', name),
        ('critical', critical),
        ('raw', raw),
        ('parsed', parsed),
        ('native', native),
        ('parse_error', parse_error),
        ('semantic', semantic),
        ('semantic_fingerprint', _semantic_fingerprint(name, semantic)),
        ('subset_items', subset_items),
        ('item_labels', item_labels),
        ('display', display),
        ('path', path),
    ])
    record.update(indexes)
    return record


def _collect_request_records(certification_request):
    """
    Locates every Extension in every extension_request attribute of a CSR.
    Duplicate attributes and duplicate OIDs are intentionally retained.
    """

    records = []
    errors = []
    info = certification_request['certification_request_info']
    attributes = info['attributes']
    if attributes is None:
        return records, errors

    request_index = 0
    try:
        attribute_list = list(attributes)
    except Exception as exception:
        errors.append(OrderedDict([
            ('code', 'MALFORMED_CSR_ATTRIBUTES'),
            ('severity', SEVERITY_ERROR),
            ('message', 'Unable to parse CSR attributes: %s' % str_cls(exception)),
        ]))
        return records, errors

    for attribute_index, attribute in enumerate(attribute_list):
        try:
            attribute_type = attribute['type'].native
        except Exception as exception:
            errors.append(OrderedDict([
                ('code', 'MALFORMED_CSR_ATTRIBUTE'),
                ('severity', SEVERITY_ERROR),
                ('message', 'Unable to parse CSR attribute %d: %s' % (attribute_index, str_cls(exception))),
            ]))
            continue
        if attribute_type != 'extension_request':
            continue

        try:
            values = list(attribute['values'])
        except Exception as exception:
            errors.append(OrderedDict([
                ('code', 'MALFORMED_EXTENSION_REQUEST'),
                ('severity', SEVERITY_ERROR),
                ('message', 'Unable to parse extension_request values at attributes[%d]: %s' % (
                    attribute_index,
                    str_cls(exception)
                )),
            ]))
            continue

        for value_index, extensions in enumerate(values):
            try:
                extension_list = list(extensions)
            except Exception as exception:
                errors.append(OrderedDict([
                    ('code', 'MALFORMED_EXTENSION_REQUEST'),
                    ('severity', SEVERITY_ERROR),
                    ('message', 'Unable to parse Extensions at attributes[%d].values[%d]: %s' % (
                        attribute_index,
                        value_index,
                        str_cls(exception)
                    )),
                ]))
                continue

            for extension_index, extension in enumerate(extension_list):
                path = 'certification_request_info.attributes[%d].values[%d][%d]' % (
                    attribute_index,
                    value_index,
                    extension_index
                )
                try:
                    record = _record_from_extension(
                        extension,
                        path,
                        OrderedDict([
                            ('index', request_index),
                            ('attribute_index', attribute_index),
                            ('attribute_value_index', value_index),
                            ('extension_index', extension_index),
                        ])
                    )
                    records.append(record)
                    request_index += 1
                except Exception as exception:
                    errors.append(OrderedDict([
                        ('code', 'MALFORMED_REQUEST_EXTENSION'),
                        ('severity', SEVERITY_ERROR),
                        ('message', 'Unable to parse extension at %s: %s' % (path, str_cls(exception))),
                        ('path', path),
                    ]))

    return records, errors


def _collect_certificate_records(certificate):
    """
    Returns all extensions from a certificate in encoded order.
    """

    records = []
    errors = []
    tbs = certificate['tbs_certificate']
    extensions = tbs['extensions']
    if extensions is None or isinstance(extensions, Void):
        return records, errors

    try:
        extension_list = list(extensions)
    except Exception as exception:
        errors.append(OrderedDict([
            ('code', 'MALFORMED_CERTIFICATE_EXTENSIONS'),
            ('severity', SEVERITY_ERROR),
            ('message', 'Unable to parse certificate extensions: %s' % str_cls(exception)),
        ]))
        return records, errors

    for extension_index, extension in enumerate(extension_list):
        path = 'tbs_certificate.extensions[%d]' % extension_index
        try:
            record = _record_from_extension(
                extension,
                path,
                OrderedDict([
                    ('index', extension_index),
                    ('extension_index', extension_index),
                ])
            )
            records.append(record)
        except Exception as exception:
            errors.append(OrderedDict([
                ('code', 'MALFORMED_CERTIFICATE_EXTENSION'),
                ('severity', SEVERITY_ERROR),
                ('message', 'Unable to parse extension at %s: %s' % (path, str_cls(exception))),
                ('path', path),
            ]))

    return records, errors


def _labels(items, record):
    """
    Converts canonical item values back into display values.
    """

    output = []
    for item in items:
        output.append(record['item_labels'].get(item, _json_safe(item)))
    return sorted(output, key=_stable_repr)


def _relation(relation, added=None, removed=None, details=None):
    return OrderedDict([
        ('relation', relation),
        ('added', added or []),
        ('removed', removed or []),
        ('details', details or OrderedDict()),
    ])


def _exact_relation():
    return _relation('exact')


def _subset_relation(request_record, certificate_record):
    """
    Compares two extensions using a set-style subset rule. This covers key
    usage, extended key usage, subject alt names, certificate policies and TLS
    features.
    """

    name = request_record['extension_name']
    request_items = request_record['subset_items']
    certificate_items = certificate_record['subset_items']
    if request_items is None or certificate_items is None:
        return None

    any_name = None
    if name == 'extended_key_usage':
        any_name = 'any_extended_key_usage'
    elif name == 'certificate_policies':
        any_name = 'any_policy'

    if any_name is not None and _canonicalize(any_name) in request_items:
        if _canonicalize(any_name) in certificate_items:
            return _exact_relation()
        if not certificate_items:
            return _relation('mismatch')
        return _relation(
            'narrowed',
            removed=[any_name],
            details=OrderedDict([
                ('requested_any', True),
                ('issued_specific', _labels(certificate_items, certificate_record)),
            ])
        )

    if any_name is not None and _canonicalize(any_name) in certificate_items:
        return _relation(
            'widened',
            added=[any_name],
            details=OrderedDict([
                ('requested_specific', _labels(request_items, request_record)),
                ('issued_any', True),
            ])
        )

    added_items = certificate_items - request_items
    removed_items = request_items - certificate_items
    added = _labels(added_items, certificate_record)
    removed = _labels(removed_items, request_record)

    if not added and not removed:
        if request_record['semantic'] == certificate_record['semantic']:
            return _exact_relation()
        return _relation(
            'mismatch',
            details=OrderedDict([
                ('same_items', True),
                ('different_encoding_or_metadata', True),
            ])
        )
    if added and not removed:
        return _relation('widened', added=added)
    if removed and not added:
        return _relation('narrowed', removed=removed)
    return _relation('mismatch', added=added, removed=removed)


def _basic_constraints_relation(request_record, certificate_record):
    """
    Basic constraints narrow only in the direction of less CA capability.
    """

    req = request_record['native']
    cert = certificate_record['native']
    if not isinstance(req, dict) or not isinstance(cert, dict):
        return None

    req_ca = bool(req.get('ca'))
    cert_ca = bool(cert.get('ca'))
    req_path = req.get('path_len_constraint')
    cert_path = cert.get('path_len_constraint')
    added = []
    removed = []

    if req_ca == cert_ca:
        if not req_ca:
            if req_path == cert_path:
                return _exact_relation()
            return _relation(
                'mismatch',
                details=OrderedDict([
                    ('ca', False),
                    ('requested_path_len', req_path),
                    ('issued_path_len', cert_path),
                ])
            )
        if req_path is None and cert_path is None:
            return _exact_relation()
        if req_path is None:
            removed.append('unlimited_path_len')
            return _relation(
                'narrowed',
                removed=removed,
                details=OrderedDict([
                    ('requested_path_len', None),
                    ('issued_path_len', cert_path),
                ])
            )
        if cert_path is None:
            added.append('unlimited_path_len')
            return _relation(
                'widened',
                added=added,
                details=OrderedDict([
                    ('requested_path_len', req_path),
                    ('issued_path_len', None),
                ])
            )
        if cert_path < req_path:
            removed.append('path_len_constraint')
            return _relation(
                'narrowed',
                removed=removed,
                details=OrderedDict([
                    ('requested_path_len', req_path),
                    ('issued_path_len', cert_path),
                ])
            )
        if cert_path > req_path:
            added.append('path_len_constraint')
            return _relation(
                'widened',
                added=added,
                details=OrderedDict([
                    ('requested_path_len', req_path),
                    ('issued_path_len', cert_path),
                ])
            )
        return _exact_relation()

    if req_ca and not cert_ca:
        removed.append('ca')
        return _relation(
            'narrowed',
            removed=removed,
            details=OrderedDict([
                ('requested_ca', True),
                ('issued_ca', False),
            ])
        )

    added.append('ca')
    return _relation(
        'widened',
        added=added,
        details=OrderedDict([
            ('requested_ca', False),
            ('issued_ca', True),
        ])
    )


def _private_key_usage_period_relation(request_record, certificate_record):
    """
    A certificate private key usage period may only be narrowed.
    """

    req = request_record['native']
    cert = certificate_record['native']
    if not isinstance(req, dict) or not isinstance(cert, dict):
        return None

    req_start = req.get('not_before')
    req_end = req.get('not_after')
    cert_start = cert.get('not_before')
    cert_end = cert.get('not_after')
    widened = []
    narrowed = []

    if req_start is not None:
        if cert_start is None or cert_start < req_start:
            widened.append('not_before')
        elif cert_start > req_start:
            narrowed.append('not_before')
    if req_end is not None:
        if cert_end is None or cert_end > req_end:
            widened.append('not_after')
        elif cert_end < req_end:
            narrowed.append('not_after')

    details = OrderedDict([
        ('requested_not_before', _json_safe(req_start)),
        ('requested_not_after', _json_safe(req_end)),
        ('issued_not_before', _json_safe(cert_start)),
        ('issued_not_after', _json_safe(cert_end)),
    ])
    if widened and narrowed:
        return _relation('mismatch', added=widened, removed=narrowed, details=details)
    if widened:
        return _relation('widened', added=widened, details=details)
    if narrowed:
        return _relation('narrowed', removed=narrowed, details=details)
    return _relation('exact', details=details)


def _apply_rule(request_record, certificate_record, rule):
    """
    Applies either a built-in rule or a caller-provided callable.
    """

    if callable(rule):
        try:
            result = rule(request_record['extension'], certificate_record['extension'])
        except Exception as exception:
            return _relation(
                'mismatch',
                details=OrderedDict([
                    ('custom_rule_error', str_cls(exception)),
                ])
            )
        if isinstance(result, bool):
            if result:
                return _relation('narrowed')
            return _relation('mismatch')
        if isinstance(result, dict):
            relation = result.get('relation')
            if relation is None:
                relation = 'narrowed' if result.get('approved') else 'mismatch'
            return _relation(
                relation,
                added=result.get('added'),
                removed=result.get('removed'),
                details=result.get('details')
            )
        return _relation('mismatch')

    if request_record['semantic'] == certificate_record['semantic']:
        return _exact_relation()

    if rule == 'subset':
        relation = _subset_relation(request_record, certificate_record)
        if relation is not None:
            return relation
    elif rule == 'basic_constraints':
        relation = _basic_constraints_relation(request_record, certificate_record)
        if relation is not None:
            return relation
    elif rule == 'private_key_usage_period':
        relation = _private_key_usage_period_relation(request_record, certificate_record)
        if relation is not None:
            return relation

    return _relation('mismatch')


def _match_basis(relation, request_record, certificate_record):
    """
    Describes why a particular request was selected as the basis.
    """

    if relation == 'exact':
        if request_record['raw']['extension_der_sha256'] == certificate_record['raw']['extension_der_sha256']:
            return 'der_exact'
        if request_record['raw']['value_der_sha256'] == certificate_record['raw']['value_der_sha256']:
            return 'value_der_exact'
        return 'semantic_exact'
    if relation == 'narrowed':
        return 'semantic_narrowed'
    if relation == 'widened':
        return 'semantic_widened'
    return 'semantic_mismatch'


def _rank_match(relation, request_record, certificate_record):
    """
    Ranks candidate requests. Exact encodings win, then exact semantics, then
    the tightest legal narrowing, then the tightest widening for diagnostics.
    """

    relation_name = relation['relation']
    critical_penalty = 0 if request_record['critical'] == certificate_record['critical'] else 5
    if relation_name == 'exact':
        if request_record['raw']['extension_der_sha256'] == certificate_record['raw']['extension_der_sha256']:
            return 100 - critical_penalty
        if request_record['raw']['value_der_sha256'] == certificate_record['raw']['value_der_sha256']:
            return 95 - critical_penalty
        return 90 - critical_penalty
    if relation_name == 'narrowed':
        return 60 - min(len(relation['removed']), 9) - critical_penalty
    if relation_name == 'widened':
        return 30 - min(len(relation['added']), 9) - critical_penalty
    return 10 - critical_penalty


def _request_to_dict(record, match=None):
    """
    Serializes a request extension record, optionally with its match decision.
    """

    output = OrderedDict([
        ('index', record['index']),
        ('path', record['path']),
        ('attribute_index', record.get('attribute_index')),
        ('attribute_value_index', record.get('attribute_value_index')),
        ('extension_index', record.get('extension_index')),
        ('extension', record['extension_name']),
        ('oid', record['oid']),
        ('critical', record['critical']),
        ('value', record['display']),
        ('semantic', _json_safe(record['semantic'])),
        ('semantic_fingerprint', record['semantic_fingerprint']),
        ('parse_error', record['parse_error']),
        ('encoding', OrderedDict([
            ('oid_der_hex', record['raw']['oid_der_hex']),
            ('value_der_hex', record['raw']['value_der_hex']),
            ('value_der_sha256', record['raw']['value_der_sha256']),
            ('extension_der_sha256', record['raw']['extension_der_sha256']),
        ])),
    ])
    if match is not None:
        output['relation'] = match['relation']['relation']
        output['change'] = OrderedDict([
            ('added', match['relation']['added']),
            ('removed', match['relation']['removed']),
            ('details', match['relation']['details']),
        ])
        output['match_basis'] = match['match_basis']
        output['rank'] = match['rank']
        output['selected'] = match['selected']
        output['matched'] = match['matched']
    return output


def _certificate_to_dict(record):
    return OrderedDict([
        ('index', record['index']),
        ('path', record['path']),
        ('extension', record['extension_name']),
        ('oid', record['oid']),
        ('critical', record['critical']),
        ('value', record['display']),
        ('semantic', _json_safe(record['semantic'])),
        ('semantic_fingerprint', record['semantic_fingerprint']),
        ('parse_error', record['parse_error']),
        ('encoding', OrderedDict([
            ('oid_der_hex', record['raw']['oid_der_hex']),
            ('value_der_hex', record['raw']['value_der_hex']),
            ('value_der_sha256', record['raw']['value_der_sha256']),
            ('extension_der_sha256', record['raw']['extension_der_sha256']),
        ])),
    ])


def _issue(code, severity, message, **extra):
    output = OrderedDict([
        ('code', code),
        ('severity', severity),
        ('message', message),
    ])
    for key in extra:
        output[key] = extra[key]
    return output


def _request_variants(candidates):
    """
    Groups requests by semantic value while retaining every encoding path.
    """

    variants = OrderedDict()
    for record in candidates:
        fingerprint = record['semantic_fingerprint']
        if fingerprint not in variants:
            variants[fingerprint] = OrderedDict([
                ('semantic_fingerprint', fingerprint),
                ('value', _json_safe(record['semantic'])),
                ('paths', []),
                ('value_der_sha256s', []),
                ('critical_values', []),
            ])
        variant = variants[fingerprint]
        variant['paths'].append(record['path'])
        if record['critical'] not in variant['critical_values']:
            variant['critical_values'].append(record['critical'])
        if record['raw']['value_der_sha256'] not in variant['value_der_sha256s']:
            variant['value_der_sha256s'].append(record['raw']['value_der_sha256'])
    return list(variants.values())


def _requested_extension_row(certificate_record, candidates, policy):
    """
    Builds the comparison row for an issued extension that has at least one
    requested counterpart with the same extension OID.
    """

    matches = []
    for request_record in candidates:
        rule = policy.rule_for(request_record['extension_name'], request_record['oid'])
        relation = _apply_rule(request_record, certificate_record, rule)
        matches.append(OrderedDict([
            ('record', request_record),
            ('relation', relation),
            ('match_basis', _match_basis(relation['relation'], request_record, certificate_record)),
            ('rank', _rank_match(relation, request_record, certificate_record)),
        ]))

    best = sorted(
        matches,
        key=lambda match: (-match['rank'], match['record']['index'])
    )[0]
    best_fingerprint = best['record']['semantic_fingerprint']
    equivalent_matches = [
        match for match in matches
        if match['record']['semantic_fingerprint'] == best_fingerprint
    ]
    top_rank = best['rank']
    top_matches = [match for match in matches if match['rank'] == top_rank]
    top_fingerprints = set([match['record']['semantic_fingerprint'] for match in top_matches])
    ambiguous = len(top_fingerprints) > 1

    variants = _request_variants(candidates)
    request_conflict = len(set([
        (record['semantic_fingerprint'], record['critical']) for record in candidates
    ])) > 1

    for match in matches:
        match['selected'] = match['record']['semantic_fingerprint'] == best_fingerprint
        match['matched'] = match['selected'] and match['relation']['relation'] in ('exact', 'narrowed')

    relation = best['relation']
    status = relation['relation']
    criticality_changed = best['record']['critical'] != certificate_record['critical']
    criticality_ok = (not criticality_changed) or policy.allow_criticality_change
    conflict_ok = (not request_conflict) or policy.allow_conflicting_requests
    approved = status in ('exact', 'narrowed') and criticality_ok and conflict_ok and not ambiguous

    severity = SEVERITY_INFO
    issues = []
    if status == 'widened':
        severity = SEVERITY_ERROR
        issues.append(_issue(
            'EXTENSION_WIDENED',
            SEVERITY_ERROR,
            'Certificate extension adds values that were not requested',
            extension=certificate_record['extension_name'],
            added=relation['added'],
            request_path=best['record']['path'],
            certificate_path=certificate_record['path']
        ))
    elif status == 'mismatch':
        severity = SEVERITY_ERROR
        issues.append(_issue(
            'EXTENSION_MISMATCH',
            SEVERITY_ERROR,
            'Certificate extension does not match the requested value',
            extension=certificate_record['extension_name'],
            added=relation['added'],
            removed=relation['removed'],
            request_path=best['record']['path'],
            certificate_path=certificate_record['path']
        ))
    elif status == 'narrowed':
        severity = SEVERITY_INFO
    elif status == 'exact':
        severity = SEVERITY_INFO

    if criticality_changed and not criticality_ok:
        severity = SEVERITY_WARNING if severity == SEVERITY_INFO else severity
        issues.append(_issue(
            'CRITICALITY_CHANGED',
            SEVERITY_WARNING,
            'Certificate criticality differs from the request',
            extension=certificate_record['extension_name'],
            requested=best['record']['critical'],
            issued=certificate_record['critical'],
            request_path=best['record']['path'],
            certificate_path=certificate_record['path']
        ))
    if request_conflict and not conflict_ok:
        severity = SEVERITY_WARNING if severity == SEVERITY_INFO else severity
        issues.append(_issue(
            'CONFLICTING_REQUEST_VARIANTS',
            SEVERITY_WARNING,
            'Multiple semantically different requests exist for the same extension OID',
            extension=certificate_record['extension_name'],
            request_paths=[variant['paths'] for variant in variants],
            certificate_path=certificate_record['path']
        ))
    if ambiguous:
        severity = SEVERITY_WARNING if severity == SEVERITY_INFO else severity
        issues.append(_issue(
            'AMBIGUOUS_REQUEST_MATCH',
            SEVERITY_WARNING,
            'Multiple distinct requests match the issued extension equally well',
            extension=certificate_record['extension_name'],
            request_paths=[match['record']['path'] for match in top_matches],
            certificate_path=certificate_record['path']
        ))
    for match in equivalent_matches:
        if match['record']['parse_error'] is not None:
            issues.append(_issue(
                'MALFORMED_REQUEST_EXTENSION',
                SEVERITY_WARNING,
                'Request extension value could not be parsed and was compared as opaque DER',
                extension=certificate_record['extension_name'],
                request_path=match['record']['path'],
                detail=match['record']['parse_error']
            ))
    if certificate_record['parse_error'] is not None:
        severity = SEVERITY_WARNING if severity == SEVERITY_INFO else severity
        issues.append(_issue(
            'MALFORMED_CERTIFICATE_EXTENSION',
            SEVERITY_WARNING,
            'Certificate extension value could not be parsed and was compared as opaque DER',
            extension=certificate_record['extension_name'],
            certificate_path=certificate_record['path'],
            detail=certificate_record['parse_error']
        ))

    if status == 'exact':
        reason = 'requested_extension_preserved'
    elif status == 'narrowed':
        reason = 'requested_extension_narrowed'
    elif status == 'widened':
        reason = 'certificate_adds_requested_scope'
    else:
        reason = 'extension_value_differs'

    equivalent_paths = [match['record']['path'] for match in equivalent_matches]
    selected_request = best['record']
    request_dicts = [_request_to_dict(match['record'], match) for match in matches]
    certificate_dict = _certificate_to_dict(certificate_record)
    provenance = OrderedDict([
        ('kind', 'request'),
        ('source', 'approved_csr'),
        ('verified', True),
        ('request_paths', equivalent_paths),
    ])
    evidence = OrderedDict([
        ('match_basis', best['match_basis']),
        ('request_semantic_fingerprint', selected_request['semantic_fingerprint']),
        ('certificate_semantic_fingerprint', certificate_record['semantic_fingerprint']),
        ('equivalent_request_paths', equivalent_paths),
        ('request_semantic_fingerprints', [variant['semantic_fingerprint'] for variant in variants]),
        ('request_variant_count', len(variants)),
        ('request_encoding_count', len(set([
            record['raw']['value_der_sha256'] for record in candidates
        ]))),
        ('equivalent_request_encoding_count', len(set([
            match['record']['raw']['value_der_sha256'] for match in equivalent_matches
        ]))),
        ('request_encodings', [
            OrderedDict([
                ('path', match['record']['path']),
                ('oid_der_hex', match['record']['raw']['oid_der_hex']),
                ('value_der_hex', match['record']['raw']['value_der_hex']),
                ('value_der_sha256', match['record']['raw']['value_der_sha256']),
                ('extension_der_sha256', match['record']['raw']['extension_der_sha256']),
                ('match_basis', match['match_basis']),
                ('relation', match['relation']['relation']),
                ('selected', match['selected']),
            ]) for match in matches
        ]),
        ('certificate_encoding', certificate_dict['encoding']),
    ])
    trace = OrderedDict([
        ('selected_request_path', selected_request['path']),
        ('selected_request_index', selected_request['index']),
        ('request_paths', [match['record']['path'] for match in matches]),
        ('equivalent_request_paths', equivalent_paths),
        ('certificate_path', certificate_record['path']),
    ])

    return ExtensionComparison(
        OrderedDict([
            ('extension', certificate_record['extension_name']),
            ('oid', certificate_record['oid']),
            ('kind', 'requested'),
            ('status', status),
            ('approved', approved),
            ('legal_narrowing', status == 'narrowed' and approved),
            ('reason', reason),
            ('severity', severity),
            ('request', _request_to_dict(selected_request, best)),
            ('request_path', selected_request['path']),
            ('requests', request_dicts),
            ('request_variants', variants),
            ('request_conflict', request_conflict),
            ('certificate', certificate_dict),
            ('certificate_path', certificate_record['path']),
            ('change', OrderedDict([
                ('added', relation['added']),
                ('removed', relation['removed']),
                ('details', relation['details']),
            ])),
            ('criticality', OrderedDict([
                ('requested', best['record']['critical']),
                ('issued', certificate_record['critical']),
                ('changed', criticality_changed),
                ('allowed', criticality_ok),
            ])),
            ('provenance', provenance),
            ('evidence', evidence),
            ('trace', trace),
            ('issues', issues),
        ]),
        request_extension=selected_request['extension'],
        request_extensions=[match['record']['extension'] for match in matches],
        certificate_extension=certificate_record['extension']
    )


def _issuer_extension_row(certificate_record, policy, certificate=None):
    """
    Builds a row for an issued extension that has no request counterpart.
    """

    source = policy.provenance_for(certificate_record['extension_name'], certificate_record['oid'])
    issues = []
    if source is None:
        if policy.allow_unknown_issuer_extensions:
            status = STATUS_ISSUER_ADDED
            approved = True
            severity = SEVERITY_INFO
            reason = 'issuer_extension_allowed_by_policy'
            source = OrderedDict([
                ('kind', 'policy'),
                ('source', 'allow_unknown_issuer_extensions'),
                ('verified', False),
            ])
        else:
            status = STATUS_UNREQUESTED
            approved = False
            severity = SEVERITY_ERROR
            reason = 'issuer_extension_source_unknown'
            source = OrderedDict([
                ('kind', 'unknown'),
                ('source', None),
                ('verified', False),
            ])
            issues.append(_issue(
                'UNREQUESTED_EXTENSION',
                SEVERITY_ERROR,
                'Certificate contains an extension that was not requested and has no declared provenance',
                extension=certificate_record['extension_name'],
                certificate_path=certificate_record['path']
            ))
    else:
        status = STATUS_ISSUER_ADDED
        approved = True
        severity = SEVERITY_INFO
        reason = 'issuer_extension_with_declared_source'

    if certificate_record['parse_error'] is not None:
        severity = SEVERITY_WARNING if severity == SEVERITY_INFO else severity
        issues.append(_issue(
            'MALFORMED_CERTIFICATE_EXTENSION',
            SEVERITY_WARNING,
            'Certificate extension value could not be parsed and is represented as opaque DER',
            extension=certificate_record['extension_name'],
            certificate_path=certificate_record['path'],
            detail=certificate_record['parse_error']
        ))

    source = copy.deepcopy(source)
    if certificate_record['extension_name'] == 'key_identifier' and certificate is not None:
        try:
            expected = certificate['tbs_certificate']['subject_public_key_info'].sha1
            actual = certificate_record['native']
            if actual == expected:
                source['verified'] = True
                source['verification'] = 'sha1_of_subject_public_key'
            else:
                source['verification'] = 'not_method_1_sha1'
        except Exception as exception:
            source['verification'] = 'unavailable: %s' % str_cls(exception)

    certificate_dict = _certificate_to_dict(certificate_record)
    evidence = OrderedDict([
        ('match_basis', 'none'),
        ('certificate_semantic_fingerprint', certificate_record['semantic_fingerprint']),
        ('certificate_encoding', certificate_dict['encoding']),
    ])
    trace = OrderedDict([
        ('selected_request_path', None),
        ('selected_request_index', None),
        ('request_paths', []),
        ('equivalent_request_paths', []),
        ('certificate_path', certificate_record['path']),
    ])

    return ExtensionComparison(
        OrderedDict([
            ('extension', certificate_record['extension_name']),
            ('oid', certificate_record['oid']),
            ('kind', 'issuer'),
            ('status', status),
            ('approved', approved),
            ('legal_narrowing', False),
            ('reason', reason),
            ('severity', severity),
            ('request', None),
            ('request_path', None),
            ('requests', []),
            ('request_variants', []),
            ('request_conflict', False),
            ('certificate', certificate_dict),
            ('certificate_path', certificate_record['path']),
            ('change', OrderedDict([
                ('added', [certificate_record['display']]),
                ('removed', []),
                ('details', OrderedDict()),
            ])),
            ('criticality', OrderedDict([
                ('requested', None),
                ('issued', certificate_record['critical']),
                ('changed', False),
                ('allowed', True),
            ])),
            ('provenance', source),
            ('evidence', evidence),
            ('trace', trace),
            ('issues', issues),
        ]),
        certificate_extension=certificate_record['extension']
    )


def _omitted_extension_row(oid, candidates, policy):
    """
    Builds a row for a requested extension OID that does not appear in the
    certificate at all.
    """

    first = candidates[0]
    variants = _request_variants(candidates)
    request_conflict = len(set([
        (record['semantic_fingerprint'], record['critical']) for record in candidates
    ])) > 1
    disposition = policy.omission_for(first['extension_name'], oid, candidates)
    issues = []
    added = []
    removed = [record['display'] for record in candidates]
    details = OrderedDict()

    if disposition == 'widened':
        status = STATUS_WIDENED
        approved = False
        legal_narrowing = False
        severity = SEVERITY_ERROR
        reason = 'omitted_extension_widens_scope'
        added = ['absence_of_restriction']
        removed = []
        details['omitted_requested_values'] = [record['display'] for record in candidates]
        issues.append(_issue(
            'EXTENSION_OMITTED_WIDENS_SCOPE',
            SEVERITY_ERROR,
            'Requested restriction was omitted; absence of this extension allows more scope',
            extension=first['extension_name'],
            request_paths=[record['path'] for record in candidates]
        ))
    elif disposition == 'exact':
        status = STATUS_OMITTED
        approved = True
        legal_narrowing = False
        severity = SEVERITY_INFO
        reason = 'omitted_extension_has_no_greater_scope'
    else:
        status = STATUS_OMITTED
        conflict_ok = not request_conflict or policy.allow_conflicting_requests
        if disposition == 'narrowed':
            approved = policy.allow_omission and conflict_ok
        else:
            approved = policy.allow_missing_extensions and conflict_ok
        legal_narrowing = approved and disposition == 'narrowed'
        severity = SEVERITY_INFO if approved else SEVERITY_ERROR
        reason = 'requested_extension_omitted'
        if not approved:
            issues.append(_issue(
                'REQUESTED_EXTENSION_OMITTED',
                SEVERITY_ERROR,
                'Requested extension was not issued and omission is not allowed by policy',
                extension=first['extension_name'],
                request_paths=[record['path'] for record in candidates]
            ))

    if request_conflict and not policy.allow_conflicting_requests:
        severity = SEVERITY_WARNING if severity == SEVERITY_INFO else severity
        issues.append(_issue(
            'CONFLICTING_REQUEST_VARIANTS',
            SEVERITY_WARNING,
            'Multiple semantically different requests exist for the same omitted extension OID',
            extension=first['extension_name'],
            request_paths=[variant['paths'] for variant in variants]
        ))

    request_dicts = [_request_to_dict(record) for record in candidates]
    equivalent_paths = [record['path'] for record in candidates]
    provenance = OrderedDict([
        ('kind', 'request'),
        ('source', 'approved_csr'),
        ('verified', True),
        ('request_paths', equivalent_paths),
    ])
    evidence = OrderedDict([
        ('match_basis', 'none'),
        ('request_semantic_fingerprint', first['semantic_fingerprint']),
        ('certificate_semantic_fingerprint', None),
        ('equivalent_request_paths', equivalent_paths),
        ('request_semantic_fingerprints', [variant['semantic_fingerprint'] for variant in variants]),
        ('request_variant_count', len(variants)),
        ('request_encoding_count', len(set([
            record['raw']['value_der_sha256'] for record in candidates
        ]))),
        ('equivalent_request_encoding_count', len(set([
            record['raw']['value_der_sha256'] for record in candidates
            if record['semantic_fingerprint'] == first['semantic_fingerprint']
        ]))),
        ('request_encodings', [
            OrderedDict([
                ('path', record['path']),
                ('oid_der_hex', record['raw']['oid_der_hex']),
                ('value_der_hex', record['raw']['value_der_hex']),
                ('value_der_sha256', record['raw']['value_der_sha256']),
                ('extension_der_sha256', record['raw']['extension_der_sha256']),
                ('match_basis', 'none'),
                ('relation', 'omitted'),
                ('selected', record['semantic_fingerprint'] == first['semantic_fingerprint']),
            ]) for record in candidates
        ]),
        ('certificate_encoding', None),
    ])
    trace = OrderedDict([
        ('selected_request_path', first['path']),
        ('selected_request_index', first['index']),
        ('request_paths', [record['path'] for record in candidates]),
        ('equivalent_request_paths', equivalent_paths),
        ('certificate_path', None),
    ])

    return ExtensionComparison(
        OrderedDict([
            ('extension', first['extension_name']),
            ('oid', oid),
            ('kind', 'requested'),
            ('status', status),
            ('approved', approved),
            ('legal_narrowing', legal_narrowing),
            ('reason', reason),
            ('severity', severity),
            ('request', _request_to_dict(first)),
            ('request_path', first['path']),
            ('requests', request_dicts),
            ('request_variants', variants),
            ('request_conflict', request_conflict),
            ('certificate', None),
            ('certificate_path', None),
            ('change', OrderedDict([
                ('added', added),
                ('removed', removed),
                ('details', details),
            ])),
            ('criticality', OrderedDict([
                ('requested', first['critical']),
                ('issued', None),
                ('changed', False),
                ('allowed', True),
            ])),
            ('provenance', provenance),
            ('evidence', evidence),
            ('trace', trace),
            ('issues', issues),
        ]),
        request_extension=first['extension'],
        request_extensions=[record['extension'] for record in candidates]
    )


def _subject_row(certification_request, certificate, policy):
    req_info = certification_request['certification_request_info']
    req_name = req_info['subject']
    cert_name = certificate['tbs_certificate']['subject']
    req_canonical = _canonical_name(req_name)
    cert_canonical = _canonical_name(cert_name)
    try:
        exact = req_name == cert_name
    except Exception:
        exact = req_canonical == cert_canonical
    approved = exact or policy.allow_subject_adjustment
    issues = []

    if exact:
        status = STATUS_EXACT
        reason = 'subject_preserved'
        severity = SEVERITY_INFO
        if _as_bytes(req_name.dump()) == _as_bytes(cert_name.dump()):
            basis = 'der_exact'
        else:
            basis = 'semantic_exact'
    else:
        status = STATUS_CHANGED
        if policy.allow_subject_adjustment:
            reason = 'subject_adjusted_by_policy'
            severity = SEVERITY_INFO
        else:
            reason = 'subject_changed'
            severity = SEVERITY_ERROR
            issues.append(_issue(
                'SUBJECT_MISMATCH',
                SEVERITY_ERROR,
                'Certificate subject differs from the approved CSR subject',
                request_path='certification_request_info.subject',
                certificate_path='tbs_certificate.subject'
            ))
        basis = 'different'

    req_native = _json_safe(req_name.native)
    cert_native = _json_safe(cert_name.native)
    added = []
    removed = []
    if isinstance(req_name.native, dict) and isinstance(cert_name.native, dict):
        for key in cert_name.native.keys():
            if key not in req_name.native:
                added.append(key)
        for key in req_name.native.keys():
            if key not in cert_name.native:
                removed.append(key)

    return OrderedDict([
        ('field', 'subject'),
        ('status', status),
        ('approved', approved),
        ('reason', reason),
        ('severity', severity),
        ('match_basis', basis),
        ('request', req_native),
        ('certificate', cert_native),
        ('change', OrderedDict([
            ('added', added),
            ('removed', removed),
        ])),
        ('evidence', OrderedDict([
            ('request_der_sha256', _sha256_hex(req_name.dump())),
            ('certificate_der_sha256', _sha256_hex(cert_name.dump())),
            ('semantic_fingerprint', _semantic_fingerprint('subject', req_canonical)),
        ])),
        ('trace', OrderedDict([
            ('request_path', 'certification_request_info.subject'),
            ('certificate_path', 'tbs_certificate.subject'),
        ])),
        ('issues', issues),
    ])


def _public_key_row(certification_request, certificate):
    req_info = certification_request['certification_request_info']
    req_spki = req_info['subject_pk_info']
    cert_spki = certificate['tbs_certificate']['subject_public_key_info']
    req_canonical = _canonical_spki(req_spki)
    cert_canonical = _canonical_spki(cert_spki)
    exact = req_canonical == cert_canonical
    issues = []

    if exact:
        status = STATUS_EXACT
        reason = 'public_key_preserved'
        approved = True
        severity = SEVERITY_INFO
        if _as_bytes(req_spki.dump()) == _as_bytes(cert_spki.dump()):
            basis = 'der_exact'
        else:
            basis = 'semantic_exact'
    else:
        status = STATUS_KEY_REPLACED
        reason = 'public_key_replaced'
        approved = False
        severity = SEVERITY_ERROR
        basis = 'different'
        issues.append(_issue(
            'PUBLIC_KEY_MISMATCH',
            SEVERITY_ERROR,
            'Certificate public key differs from the approved CSR public key',
            request_path='certification_request_info.subject_pk_info',
            certificate_path='tbs_certificate.subject_public_key_info'
        ))

    return OrderedDict([
        ('field', 'public_key'),
        ('status', status),
        ('approved', approved),
        ('reason', reason),
        ('severity', severity),
        ('match_basis', basis),
        ('request', OrderedDict([
            ('algorithm', _json_safe(req_spki['algorithm']['algorithm'].native)),
            ('sha256', _sha256_hex(byte_cls(req_spki['public_key']))),
        ])),
        ('certificate', OrderedDict([
            ('algorithm', _json_safe(cert_spki['algorithm']['algorithm'].native)),
            ('sha256', _sha256_hex(byte_cls(cert_spki['public_key']))),
        ])),
        ('change', OrderedDict([
            ('added', []),
            ('removed', []),
        ])),
        ('evidence', OrderedDict([
            ('request_der_sha256', _sha256_hex(req_spki.dump())),
            ('certificate_der_sha256', _sha256_hex(cert_spki.dump())),
            ('semantic_fingerprint', _semantic_fingerprint('public_key', req_canonical)),
        ])),
        ('trace', OrderedDict([
            ('request_path', 'certification_request_info.subject_pk_info'),
            ('certificate_path', 'tbs_certificate.subject_public_key_info'),
        ])),
        ('issues', issues),
    ])


class ApprovalPolicy(object):
    """
    Controls which extensions may be narrowed and which issuer-added extensions
    have a declared source.

    :param narrowing:
        A dict mapping extension names or dotted OIDs to a rule. Supported
        string rules are "exact", "subset", "basic_constraints" and
        "private_key_usage_period". A callable may also be supplied; it receives
        (request_extension, certificate_extension) and returns a boolean or a
        dict with keys approved, relation, added, removed and details.

    :param issuer_extension_sources:
        A dict mapping extension names or dotted OIDs to a source label, a
        provenance dict, or None to remove a default source.

    :param omission_rules:
        A dict mapping extension names or dotted OIDs to how omission should be
        interpreted. Supported values are "widened" (absence allows more
        scope), "narrowed" (absence is a legal restriction), "exact" (absence
        has no effect on scope) and "missing" (report but do not infer scope).

    :param allow_omission:
        If True, a requested extension whose omission is classified as
        narrowing may be omitted without forcing rejection.

    :param allow_missing_extensions:
        If True, an omitted extension without an inferred scope effect (usually
        a custom extension) may be omitted without forcing rejection.

    :param allow_criticality_change:
        If True, changing the critical flag does not prevent approval.

    :param allow_unknown_issuer_extensions:
        If True, issuer-added extensions without a declared source are allowed.

    :param allow_conflicting_requests:
        If True, multiple semantically different requests for the same OID do
        not force review. The best-scoring request remains the matching basis.

    :param allow_subject_adjustment:
        If True, a certificate subject may differ from the CSR subject.
    """

    DEFAULT_NARROWING = OrderedDict([
        ('key_usage', 'subset'),
        ('extended_key_usage', 'subset'),
        ('subject_alt_name', 'subset'),
        ('issuer_alt_name', 'subset'),
        ('certificate_policies', 'subset'),
        ('tls_feature', 'subset'),
        ('subject_directory_attributes', 'subset'),
        ('basic_constraints', 'basic_constraints'),
        ('private_key_usage_period', 'private_key_usage_period'),
    ])

    DEFAULT_ISSUER_SOURCES = OrderedDict([
        ('authority_key_identifier', 'issuer_certificate'),
        ('key_identifier', 'derived_from_subject_public_key'),
        ('crl_distribution_points', 'issuer_profile'),
        ('freshest_crl', 'issuer_profile'),
        ('authority_information_access', 'issuer_profile'),
        ('subject_information_access', 'issuer_profile'),
        ('certificate_policies', 'issuer_profile'),
        ('policy_constraints', 'issuer_profile'),
        ('inhibit_any_policy', 'issuer_profile'),
        ('private_key_usage_period', 'issuer_profile'),
        ('netscape_certificate_type', 'issuer_profile'),
        ('entrust_version_extension', 'issuer_profile'),
        ('signed_certificate_timestamp_list', 'issuer_profile'),
        ('tls_feature', 'issuer_profile'),
        ('ocsp_no_check', 'issuer_profile'),
    ])

    DEFAULT_OMISSION_RULES = OrderedDict([
        ('key_usage', 'widened'),
        ('extended_key_usage', 'widened'),
        ('private_key_usage_period', 'widened'),
        ('tls_feature', 'widened'),
        ('certificate_policies', 'widened'),
        ('name_constraints', 'widened'),
        ('policy_constraints', 'widened'),
        ('inhibit_any_policy', 'widened'),
        ('basic_constraints', 'basic_constraints'),
        ('subject_alt_name', 'narrowed'),
        ('issuer_alt_name', 'narrowed'),
        ('subject_directory_attributes', 'narrowed'),
    ])

    def __init__(
            self,
            narrowing=None,
            issuer_extension_sources=None,
            omission_rules=None,
            allow_omission=True,
            allow_missing_extensions=False,
            allow_criticality_change=False,
            allow_unknown_issuer_extensions=False,
            allow_conflicting_requests=False,
            allow_subject_adjustment=False):
        self.narrowing = OrderedDict(self.DEFAULT_NARROWING)
        if narrowing:
            self.narrowing.update(narrowing)
        self.issuer_extension_sources = OrderedDict(self.DEFAULT_ISSUER_SOURCES)
        if issuer_extension_sources:
            for key in issuer_extension_sources:
                self.issuer_extension_sources[key] = issuer_extension_sources[key]
        self.omission_rules = OrderedDict(self.DEFAULT_OMISSION_RULES)
        if omission_rules:
            self.omission_rules.update(omission_rules)
        self.allow_omission = bool(allow_omission)
        self.allow_missing_extensions = bool(allow_missing_extensions)
        self.allow_criticality_change = bool(allow_criticality_change)
        self.allow_unknown_issuer_extensions = bool(allow_unknown_issuer_extensions)
        self.allow_conflicting_requests = bool(allow_conflicting_requests)
        self.allow_subject_adjustment = bool(allow_subject_adjustment)

    def rule_for(self, extension_name, oid):
        """
        Returns the narrowing rule for an extension name or dotted OID.
        """

        if oid in self.narrowing:
            return self.narrowing[oid]
        return self.narrowing.get(extension_name, 'exact')

    def omission_for(self, extension_name, oid, records):
        # Returns widened, narrowed, exact or missing for an omitted request.
        if oid in self.omission_rules:
            rule = self.omission_rules[oid]
        else:
            rule = self.omission_rules.get(extension_name, 'missing')
        if rule == 'basic_constraints':
            for record in records:
                if isinstance(record['native'], dict) and record['native'].get('ca'):
                    return 'narrowed'
            return 'exact'
        if rule == 'widened':
            if extension_name == 'extended_key_usage':
                any_value = _canonicalize('any_extended_key_usage')
                for record in records:
                    if record['subset_items'] and any_value in record['subset_items']:
                        return 'exact'
            elif extension_name == 'certificate_policies':
                any_value = _canonicalize('any_policy')
                for record in records:
                    if record['subset_items'] and any_value in record['subset_items']:
                        return 'exact'
            elif extension_name == 'tls_feature':
                if all([record['subset_items'] == frozenset() for record in records]):
                    return 'exact'
            elif extension_name == 'private_key_usage_period':
                unbounded = True
                for record in records:
                    native = record['native']
                    if not isinstance(native, dict):
                        unbounded = False
                    elif native.get('not_before') is not None or native.get('not_after') is not None:
                        unbounded = False
                if unbounded:
                    return 'exact'
        if rule == 'narrowed':
            if extension_name in (
                    'subject_alt_name',
                    'issuer_alt_name',
                    'subject_directory_attributes'):
                if all([record['subset_items'] == frozenset() for record in records]):
                    return 'exact'
        return rule

    def provenance_for(self, extension_name, oid):
        """
        Returns normalized provenance for an issuer-added extension, or None.
        """

        value = None
        found = False
        if oid in self.issuer_extension_sources:
            value = self.issuer_extension_sources[oid]
            found = True
        elif extension_name in self.issuer_extension_sources:
            value = self.issuer_extension_sources[extension_name]
            found = True
        if not found or value is None:
            return None
        return _normalize_provenance(value)

    def to_dict(self):
        narrowing = OrderedDict()
        for key in self.narrowing:
            value = self.narrowing[key]
            narrowing[key] = value if isinstance(value, str_cls) else 'callable'
        sources = OrderedDict()
        for key in self.issuer_extension_sources:
            value = self.issuer_extension_sources[key]
            sources[key] = _json_safe(value)
        omissions = OrderedDict()
        for key in self.omission_rules:
            value = self.omission_rules[key]
            omissions[key] = value if isinstance(value, str_cls) else 'callable'
        return OrderedDict([
            ('narrowing', narrowing),
            ('issuer_extension_sources', sources),
            ('omission_rules', omissions),
            ('allow_omission', self.allow_omission),
            ('allow_missing_extensions', self.allow_missing_extensions),
            ('allow_criticality_change', self.allow_criticality_change),
            ('allow_unknown_issuer_extensions', self.allow_unknown_issuer_extensions),
            ('allow_conflicting_requests', self.allow_conflicting_requests),
            ('allow_subject_adjustment', self.allow_subject_adjustment),
        ])


def _normalize_provenance(value):
    if isinstance(value, str_cls):
        return OrderedDict([
            ('kind', 'issuer'),
            ('source', value),
            ('verified', False),
        ])
    if isinstance(value, dict):
        output = OrderedDict()
        output['kind'] = value.get('kind', 'issuer')
        output['source'] = value.get('source')
        output['verified'] = bool(value.get('verified', False))
        for key in value.keys():
            if key not in ('kind', 'source', 'verified'):
                output[key] = _json_safe(value[key])
        return output
    return None


class ExtensionComparison(object):
    """
    One row of the certificate/CSR comparison view.
    """

    def __init__(
            self,
            data,
            request_extension=None,
            request_extensions=None,
            certificate_extension=None):
        self._data = data
        self.request_extension = request_extension
        self.request_extensions = request_extensions or []
        self.certificate_extension = certificate_extension

    def __getitem__(self, key):
        return self._data[key]

    def get(self, key, default=None):
        return self._data.get(key, default)

    def __iter__(self):
        return iter(self._data)

    def __contains__(self, key):
        return key in self._data

    def __len__(self):
        return len(self._data)

    def keys(self):
        return list(self._data.keys())

    def values(self):
        return list(self._data.values())

    def items(self):
        return list(self._data.items())

    @property
    def extension(self):
        return self._data['extension']

    @property
    def oid(self):
        return self._data['oid']

    @property
    def status(self):
        return self._data['status']

    @property
    def approved(self):
        return self._data['approved']

    @property
    def is_approved(self):
        return self._data['approved']

    @property
    def legal_narrowing(self):
        return self._data['legal_narrowing']

    @property
    def is_narrowed(self):
        return self._data['status'] == STATUS_NARROWED

    @property
    def is_widened(self):
        return self._data['status'] == STATUS_WIDENED

    @property
    def is_issuer_added(self):
        return self._data['status'] == STATUS_ISSUER_ADDED

    @property
    def severity(self):
        return self._data['severity']

    @property
    def issues(self):
        return self._data['issues']

    @property
    def trace(self):
        return self._data['trace']

    @property
    def provenance(self):
        return self._data['provenance']

    @property
    def request(self):
        return self._data['request']

    @property
    def request_path(self):
        return self._data['request_path']

    @property
    def certificate_path(self):
        return self._data['certificate_path']

    @property
    def requests(self):
        return self._data['requests']

    @property
    def certificate(self):
        return self._data['certificate']

    @property
    def change(self):
        return self._data['change']

    @property
    def evidence(self):
        return self._data['evidence']

    @property
    def criticality(self):
        return self._data['criticality']

    def to_dict(self):
        return copy.deepcopy(self._data)


class ComparisonView(object):
    """
    A serializable comparison view for an approved CSR and an issued
    certificate. Use to_dict() for a JSON-ready structure, or access
    .extensions for ExtensionComparison objects that retain pointers to the
    original ASN.1 request and certificate extension values.
    """

    def __init__(self, certification_request, certificate, policy=None):
        self.csr = certification_request
        self.certificate = certificate
        self.policy = policy if isinstance(policy, ApprovalPolicy) else ApprovalPolicy(**(policy or {}))
        self._build()

    def __getitem__(self, key):
        if key == 'extensions':
            return [row.to_dict() for row in self.extensions]
        return self._data[key]

    def get(self, key, default=None):
        if key == 'extensions':
            return [row.to_dict() for row in self.extensions]
        return self._data.get(key, default)

    def __iter__(self):
        return iter(self.keys())

    def __contains__(self, key):
        return key == 'extensions' or key in self._data

    def __len__(self):
        return len(self._data) + 1

    def keys(self):
        return list(self._data.keys()) + ['extensions']

    def values(self):
        return [self[key] for key in self.keys()]

    def items(self):
        return [(key, self[key]) for key in self.keys()]

    @property
    def verdict(self):
        return self._data['verdict']

    @property
    def approved(self):
        return self._data['approved']

    @property
    def is_approved(self):
        return self._data['approved']

    @property
    def summary(self):
        return self._data['summary']

    @property
    def findings(self):
        return self._data['findings']

    @property
    def subject(self):
        return self._data['subject']

    @property
    def public_key(self):
        return self._data['public_key']

    @property
    def rows(self):
        return self.extensions

    def find(self, extension_name_or_oid):
        """
        Returns the first ExtensionComparison matching an extension name or OID.
        """

        for row in self.extensions:
            if row.extension == extension_name_or_oid or row.oid == extension_name_or_oid:
                return row
        return None

    def request_extension(self, path_or_index):
        """
        Returns the original ASN.1 request Extension selected by path or global
        request index. This is the primary trace-back helper for a review UI.
        """

        if isinstance(path_or_index, int_types):
            for record in self._request_records:
                if record['index'] == path_or_index:
                    return record['extension']
            return None
        for record in self._request_records:
            if record['path'] == path_or_index:
                return record['extension']
        return None

    def certificate_extension(self, path_or_index):
        """
        Returns the original ASN.1 certificate Extension by path or index.
        """

        if isinstance(path_or_index, int_types):
            for record in self._certificate_records:
                if record['index'] == path_or_index:
                    return record['extension']
            return None
        for record in self._certificate_records:
            if record['path'] == path_or_index:
                return record['extension']
        return None

    def to_dict(self):
        output = copy.deepcopy(self._data)
        output['extensions'] = [row.to_dict() for row in self.extensions]
        return output

    def _build(self):
        request_records, request_errors = _collect_request_records(self.csr)
        certificate_records, certificate_errors = _collect_certificate_records(self.certificate)
        self._request_records = request_records
        self._certificate_records = certificate_records
        self.request_extensions = [record['extension'] for record in request_records]
        self.certificate_extensions = [record['extension'] for record in certificate_records]
        self.errors = request_errors + certificate_errors

        request_groups = OrderedDict()
        for record in request_records:
            request_groups.setdefault(record['oid'], []).append(record)
        certificate_groups = OrderedDict()
        for record in certificate_records:
            certificate_groups.setdefault(record['oid'], []).append(record)

        for oid, group in certificate_groups.items():
            if len(group) > 1:
                self.errors.append(_issue(
                    'DUPLICATE_CERTIFICATE_EXTENSION',
                    SEVERITY_ERROR,
                    'Certificate contains the same extension OID more than once',
                    oid=oid,
                    certificate_paths=[record['path'] for record in group]
                ))

        rows = []
        for certificate_record in certificate_records:
            candidates = request_groups.get(certificate_record['oid'], [])
            if candidates:
                row = _requested_extension_row(certificate_record, candidates, self.policy)
            else:
                row = _issuer_extension_row(certificate_record, self.policy, self.certificate)
            rows.append(row)

        for oid, candidates in request_groups.items():
            if oid not in certificate_groups:
                rows.append(_omitted_extension_row(oid, candidates, self.policy))

        subject_row = _subject_row(self.csr, self.certificate, self.policy)
        public_key_row = _public_key_row(self.csr, self.certificate)
        self.extensions = rows

        findings = []
        for row in rows:
            for issue in row.issues:
                item = copy.deepcopy(issue)
                item.setdefault('extension', row.extension)
                findings.append(item)
        for issue in self.errors:
            findings.append(copy.deepcopy(issue))
        for row in (subject_row, public_key_row):
            for issue in row['issues']:
                item = copy.deepcopy(issue)
                item.setdefault('field', row['field'])
                findings.append(item)

        counts = OrderedDict([
            (STATUS_EXACT, 0),
            (STATUS_NARROWED, 0),
            (STATUS_OMITTED, 0),
            (STATUS_ISSUER_ADDED, 0),
            (STATUS_WIDENED, 0),
            (STATUS_MISMATCH, 0),
            (STATUS_UNREQUESTED, 0),
        ])
        for row in rows:
            if row.status in counts:
                counts[row.status] += 1

        has_error = False
        has_warning = False
        for issue in findings:
            if issue.get('severity') == SEVERITY_ERROR:
                has_error = True
            elif issue.get('severity') == SEVERITY_WARNING:
                has_warning = True
        if not subject_row['approved'] or not public_key_row['approved']:
            has_error = True

        if has_error:
            verdict = VERDICT_REJECTED
        elif has_warning:
            verdict = VERDICT_REVIEW
        else:
            verdict = VERDICT_APPROVED

        summary = OrderedDict([
            ('verdict', verdict),
            ('approved', verdict == VERDICT_APPROVED),
            ('requested_extension_count', len(request_records)),
            ('certificate_extension_count', len(certificate_records)),
            ('exact_count', counts[STATUS_EXACT]),
            ('narrowed_count', counts[STATUS_NARROWED]),
            ('omitted_count', counts[STATUS_OMITTED]),
            ('issuer_added_count', counts[STATUS_ISSUER_ADDED]),
            ('widened_count', counts[STATUS_WIDENED]),
            ('mismatch_count', counts[STATUS_MISMATCH]),
            ('unrequested_count', counts[STATUS_UNREQUESTED]),
            ('error_count', len([issue for issue in findings if issue.get('severity') == SEVERITY_ERROR])),
            ('warning_count', len([issue for issue in findings if issue.get('severity') == SEVERITY_WARNING])),
        ])

        self._data = OrderedDict([
            ('verdict', verdict),
            ('approved', verdict == VERDICT_APPROVED),
            ('summary', summary),
            ('subject', subject_row),
            ('public_key', public_key_row),
            ('findings', findings),
            ('errors', copy.deepcopy(self.errors)),
            ('policy', self.policy.to_dict()),
            ('notes', [
                'Signatures are not verified; this view performs structural comparison only.',
                'Request extension order and DER encoding differences are retained as matching evidence.',
                'Only declared provenance allows an issuer-added extension to be approved.',
            ]),
        ])


def _load_csr(value):
    if isinstance(value, csr_module.CertificationRequest):
        return value
    if isinstance(value, bytearray):
        value = byte_cls(value)
    if not isinstance(value, byte_cls):
        raise TypeError(unwrap(
            '''
            approved_csr must be a byte string or
            asn1crypto.csr.CertificationRequest, not %s
            ''',
            type_name(value)
        ))
    if pem_detect(value):
        value = pem_unarmor(value)[2]
    return csr_module.CertificationRequest.load(value)


def _load_certificate(value):
    if isinstance(value, x509.Certificate):
        return value
    if isinstance(value, bytearray):
        value = byte_cls(value)
    if not isinstance(value, byte_cls):
        raise TypeError(unwrap(
            '''
            issued_certificate must be a byte string or
            asn1crypto.x509.Certificate, not %s
            ''',
            type_name(value)
        ))
    if pem_detect(value):
        value = pem_unarmor(value)[2]
    return x509.Certificate.load(value)


def compare_csr_to_certificate(approved_csr, issued_certificate, policy=None):
    """
    Compares an approved CSR to an issued certificate.

    :param approved_csr:
        An asn1crypto.csr.CertificationRequest object, or DER/PEM bytes

    :param issued_certificate:
        An asn1crypto.x509.Certificate object, or DER/PEM bytes

    :param policy:
        An ApprovalPolicy object or a dict of ApprovalPolicy keyword arguments

    :return:
        A ComparisonView
    """

    certification_request = _load_csr(approved_csr)
    certificate = _load_certificate(issued_certificate)
    return ComparisonView(certification_request, certificate, policy=policy)


def compare(approved_csr, issued_certificate, policy=None):
    """
    Alias for compare_csr_to_certificate().
    """

    return compare_csr_to_certificate(approved_csr, issued_certificate, policy=policy)


def compare_certificate_to_csr(issued_certificate, approved_csr, policy=None):
    """
    Argument-order alias for compare_csr_to_certificate().
    """

    return compare_csr_to_certificate(approved_csr, issued_certificate, policy=policy)


def build_comparison_view(approved_csr, issued_certificate, policy=None):
    """
    Alias for compare_csr_to_certificate() that emphasizes the view output.
    """

    return compare_csr_to_certificate(approved_csr, issued_certificate, policy=policy)


CSRComparison = ComparisonView
CertificateComparison = ComparisonView
