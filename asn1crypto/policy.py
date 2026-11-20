# coding: utf-8
"""
Read-only policy evidence views for certificate policy extensions.

The regular x509 parsing path is intentionally left untouched. The views in
this module sit on top of the parsed extension and expose policy qualifiers
with their original ordering and original ASN.1 type, while requiring the
caller to state explicitly which qualifier kinds it knows how to interpret.
Qualifiers that are not implemented, or that the caller did not opt into, are
never treated as an understandable approval basis.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

import re

from . import core
from ._errors import unwrap
from ._ordereddict import OrderedDict
from ._types import str_cls
from .core import Any, CLASS_NUM_TO_NAME_MAP, VOID
from .x509 import (
    CPS_QUALIFIER_OID,
    USER_NOTICE_QUALIFIER_OID,
    IA5String,
    PolicyQualifierId,
    UserNotice,
)


# Qualifier kinds that asn1crypto actually knows how to parse, mapped from
# their dotted OID to the parsed value spec.
IMPLEMENTED_QUALIFIERS = {
    CPS_QUALIFIER_OID: IA5String,
    USER_NOTICE_QUALIFIER_OID: UserNotice,
}

# Names of the universal ASN.1 tags that may appear as qualifier contents, so
# the original type can be reported without forcing an interpretation.
_OID_RE = re.compile(r'^\d+(\.\d+)*$')


_UNIVERSAL_TAG_NAMES = {
    1: 'boolean',
    2: 'integer',
    3: 'bit_string',
    4: 'octet_string',
    5: 'null',
    6: 'object_identifier',
    10: 'enumerated',
    12: 'utf8_string',
    16: 'sequence',
    17: 'set',
    18: 'numeric_string',
    19: 'printable_string',
    20: 'teletex_string',
    21: 'videotex_string',
    22: 'ia5_string',
    23: 'utc_time',
    24: 'generalized_time',
    25: 'graphic_string',
    26: 'visible_string',
    27: 'general_string',
    28: 'universal_string',
    29: 'character_string',
    30: 'bmp_string',
}


def _normalize_qualifier_ids(understood):
    """
    Turns the caller's explicit qualifier selection into a set of dotted OIDs.

    :param understood:
        An iterable of unicode strings, each either a mapped name (e.g.
        "certification_practice_statement") or a dotted OID

    :raises:
        ValueError - when an entry is neither a mapped name nor a dotted OID
        TypeError - when an entry is not a unicode string

    :return:
        A set of dotted OID unicode strings
    """

    selected = set()
    for identifier in understood:
        if not isinstance(identifier, str_cls):
            raise TypeError(unwrap(
                '''
                Qualifier identifiers must be unicode strings, not %s
                ''',
                type(identifier)
            ))
        dotted = PolicyQualifierId.unmap(identifier)
        if not _OID_RE.match(dotted):
            raise ValueError(unwrap(
                '''
                Qualifier identifier "%s" is neither a mapped qualifier name
                nor a dotted OID
                ''',
                identifier
            ))
        selected.add(dotted)
    return selected


def _extract_qualifier(qualifier_info):
    """
    Returns the qualifier contents without applying the qualifier-specific
    syntax.

    Regular parsing eagerly builds known qualifier OIDs into their typed
    classes; malformed contents instead stay as an unbuilt parse tuple. This
    helper returns a generically parsed value and the raw DER bytes in both
    situations, without raising on a malformed qualifier-specific value.

    :return:
        A tuple of a generic core.Asn1Value object and the DER-encoded
        qualifier contents as a byte string
    """
    child = qualifier_info.children[1]
    if isinstance(child, tuple):
        class_, method, tag, header, contents, trailer = child[:6]
        generic = core.load(header + contents + trailer)
        return generic, header + contents + trailer
    if isinstance(child, Any):
        generic = child.parse()
    else:
        generic = child
    return generic, child.dump()


def _tag_description(value):
    """
    Describes the original ASN.1 class and tag of a generically parsed value.

    :param value:
        A generic core.Asn1Value object

    :return:
        An OrderedDict with "class", "tag" and "tag_name" entries
    """

    class_name = CLASS_NUM_TO_NAME_MAP.get(value.class_, str_cls(value.class_))
    tag_name = _UNIVERSAL_TAG_NAMES.get(value.tag)
    if tag_name is None or value.class_ != 0:
        tag_name = str_cls(value.tag)
    return OrderedDict([
        ('class', class_name),
        ('tag', value.tag),
        ('tag_name', tag_name),
    ])


class PolicyQualifierEvidence(object):
    """
    Read-only evidence for a single PolicyQualifierInfo.

    The qualifier is never interpreted on the caller's behalf. A qualifier is
    only marked as understood when asn1crypto implements its syntax AND the
    caller explicitly opted into that qualifier kind.
    """

    def __init__(self, qualifier_info, index, selected):
        """
        :param qualifier_info:
            An x509.PolicyQualifierInfo object
        :param index:
            The zero-based position of the qualifier within its parent policy
        :param selected:
            A set of dotted OIDs the caller explicitly understands
        """

        self._index = index
        oid_field = qualifier_info['policy_qualifier_id']
        self._qualifier_id = oid_field.native
        self._dotted = oid_field.dotted

        generic, raw_bytes = _extract_qualifier(qualifier_info)
        self._tag = _tag_description(generic)
        self._der = raw_bytes

        self._implemented = self._dotted in IMPLEMENTED_QUALIFIERS
        self._selected = self._dotted in selected

        self._understood = self._implemented and self._selected
        self._value = None
        self._error = None

        if self._understood:
            spec = IMPLEMENTED_QUALIFIERS[self._dotted]
            try:
                parsed = spec.load(self._der)
                self._value = parsed.native
            except (ValueError, TypeError) as exc:
                self._understood = False
                self._error = str_cls(exc)

    @property
    def index(self):
        """
        :return:
            The zero-based position of the qualifier in the encoded policy
        """

        return self._index

    @property
    def qualifier_id(self):
        """
        :return:
            The mapped qualifier name, or the dotted OID when not mapped
        """

        return self._qualifier_id

    @property
    def qualifier_id_dotted(self):
        """
        :return:
            The dotted OID of the qualifier
        """

        return self._dotted

    @property
    def implemented(self):
        """
        :return:
            A boolean - True when asn1crypto knows the qualifier syntax
        """

        return self._implemented

    @property
    def explicitly_selected(self):
        """
        :return:
            A boolean - True when the caller opted into this qualifier kind
        """

        return self._selected

    @property
    def understood(self):
        """
        :return:
            A boolean - True only when the syntax is implemented, the caller
            opted in, and the contents parsed successfully
        """

        return self._understood

    @property
    def value(self):
        """
        The native interpretation of the qualifier, using the syntax the
        caller explicitly selected.

        :return:
            The native value, or None when the qualifier is not understood
        """

        return self._value

    @property
    def original_type(self):
        """
        :return:
            An OrderedDict describing the original ASN.1 class and tag
        """

        return self._tag

    @property
    def raw(self):
        """
        :return:
            The DER-encoded qualifier contents, including its ASN.1 header
        """

        return self._der

    @property
    def error(self):
        """
        :return:
            None, or a unicode string describing why an opted-in qualifier
            could not be parsed
        """

        return self._error


class PolicyEvidence(object):
    """
    Read-only evidence for a single PolicyInformation entry.
    """

    def __init__(self, policy_info, index, selected):
        """
        :param policy_info:
            An x509.PolicyInformation object
        :param index:
            The zero-based position of the policy in the extension
        :param selected:
            A set of dotted OIDs the caller explicitly understands
        """

        self._index = index
        identifier = policy_info['policy_identifier']
        self._policy_identifier = identifier.native
        self._policy_dotted = identifier.dotted

        self._qualifiers = []
        qualifier_field = policy_info['policy_qualifiers']
        if qualifier_field is not VOID and qualifier_field is not None:
            for qualifier_index, qualifier_info in enumerate(qualifier_field):
                self._qualifiers.append(
                    PolicyQualifierEvidence(qualifier_info, qualifier_index, selected)
                )

    @property
    def index(self):
        """
        :return:
            The zero-based position of the policy in the encoded extension
        """

        return self._index

    @property
    def policy_identifier(self):
        """
        :return:
            The mapped policy name, or the dotted OID when not mapped
        """

        return self._policy_identifier

    @property
    def policy_identifier_dotted(self):
        """
        :return:
            The dotted OID of the policy
        """

        return self._policy_dotted

    @property
    def qualifiers(self):
        """
        :return:
            A list of PolicyQualifierEvidence objects in encoded order
        """

        return self._qualifiers

    def has_understood_qualifier(self):
        """
        :return:
            A boolean - True when at least one qualifier was understood
        """

        for qualifier in self._qualifiers:
            if qualifier.understood:
                return True
        return False


def policy_evidence(certificate_or_policies, understood=None):
    """
    Builds read-only policy evidence views from a certificate or a parsed
    certificate policies extension.

    Ordering, original ASN.1 types and raw bytes are preserved. The caller must
    pass the qualifier identifiers it is prepared to interpret; qualifiers that
    are not implemented or not selected remain visible but are never marked as
    understood.

    :param certificate_or_policies:
        An x509.Certificate or x509.CertificatePolicies object
    :param understood:
        None, or an iterable of qualifier mapped names and/or dotted OIDs that
        the caller explicitly understands. Defaults to an empty selection, so
        nothing is treated as understandable unless requested.

    :raises:
        ValueError - when an identifier in understood is not a mapped name or dotted OID

    :return:
        A list of PolicyEvidence objects in encoded order, or None when the
        certificate has no certificate policies extension
    """

    from .x509 import Certificate, CertificatePolicies

    if isinstance(certificate_or_policies, Certificate):
        policies = certificate_or_policies.certificate_policies_value
    elif isinstance(certificate_or_policies, CertificatePolicies):
        policies = certificate_or_policies
    else:
        raise TypeError(unwrap(
            '''
            certificate_or_policies must be an x509.Certificate or
            x509.CertificatePolicies object, not %s
            ''',
            type(certificate_or_policies)
        ))

    if policies is None:
        return None

    if understood is None:
        understood = ()
    selected = _normalize_qualifier_ids(understood)

    return [
        PolicyEvidence(policy_info, index, selected)
        for index, policy_info in enumerate(policies)
    ]


def review_policy_basis(certificate_or_policies, understood):
    """
    Reviews whether each policy carries an understandable approval basis.

    This is a fail-closed review: a policy without qualifiers, with only
    unimplemented qualifiers, or with qualifiers the caller did not select, is
    reported as missing an understandable basis. Nothing is approved here -
    the caller remains responsible for the decision.

    :param certificate_or_policies:
        An x509.Certificate or x509.CertificatePolicies object
    :param understood:
        An iterable of qualifier mapped names and/or dotted OIDs the caller
        explicitly understands

    :raises:
        ValueError - when an identifier in understood is not a mapped name or dotted OID

    :return:
        An OrderedDict with:
         - "policies": a list of per-policy OrderedDicts, each with
           "policy_identifier", "has_understood_qualifier" and "reasons"
         - "approved": True only when at least one policy exists and every
           policy has an understood qualifier
    """

    evidence = policy_evidence(certificate_or_policies, understood)
    if evidence is None:
        evidence = []

    reviewed = []
    all_approved = len(evidence) > 0

    for policy in evidence:
        reasons = []
        if not policy.qualifiers:
            reasons.append('policy has no qualifiers')

        for qualifier in policy.qualifiers:
            if qualifier.understood:
                continue
            if qualifier.error is not None:
                reasons.append(
                    'qualifier %s could not be parsed: %s' % (
                        qualifier.qualifier_id_dotted, qualifier.error
                    )
                )
            elif not qualifier.implemented:
                reasons.append(
                    'qualifier %s is not implemented' % qualifier.qualifier_id_dotted
                )
            elif not qualifier.explicitly_selected:
                reasons.append(
                    'qualifier %s was not explicitly selected' % qualifier.qualifier_id_dotted
                )

        has_basis = policy.has_understood_qualifier()
        if not has_basis:
            all_approved = False

        reviewed.append(OrderedDict([
            ('policy_identifier', policy.policy_identifier_dotted),
            ('has_understood_qualifier', has_basis),
            ('reasons', reasons),
        ]))

    return OrderedDict([
        ('policies', reviewed),
        ('approved', all_approved),
    ])
