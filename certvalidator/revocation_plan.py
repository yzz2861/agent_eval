# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import binascii
from datetime import datetime

from asn1crypto import x509

from ._errors import pretty_message
from ._types import str_cls, byte_cls, type_name
from .context import ValidationContext


__all__ = [
    'RevocationEvidencePlan',
    'plan_revocation_evidence',
]


class RevocationEvidencePlan():
    """
    The result of planning offline revocation evidence gathering for a batch
    of certificates. Planning never performs network requests - it only
    inspects the state of a certvalidator.context.ValidationContext object.
    """

    # A datetime.datetime object the plan was created for
    moment = None

    # A list of asn1crypto.x509.Certificate objects that require no query -
    # either already validated in the validation context, or covered by a
    # cached CRL or OCSP response for the plan moment
    covered = None

    # A list of tuples of (asn1crypto.x509.Certificate, list of unicode
    # strings) - certificates that require a query, along with the service
    # URLs the disclosure policy permits the certificate identity to be
    # disclosed to
    to_fetch = None

    # A list of asn1crypto.x509.Certificate objects that require a query but
    # currently have no permitted channel
    suspended = None

    def __init__(self, moment, covered, to_fetch, suspended):
        """
        :param moment:
            A datetime.datetime object the plan was created for

        :param covered:
            A list of asn1crypto.x509.Certificate objects requiring no query

        :param to_fetch:
            A list of tuples of (asn1crypto.x509.Certificate, list of unicode
            strings) of certificates to query and the permitted service URLs

        :param suspended:
            A list of asn1crypto.x509.Certificate objects with no permitted
            channel
        """

        self.moment = moment
        self.covered = covered
        self.to_fetch = to_fetch
        self.suspended = suspended


def plan_revocation_evidence(validation_context, certs, moment=None, disclosure_policy=None):
    """
    Creates an offline plan for gathering revocation evidence for a batch of
    certificates. The plan is based on the certificates already validated in
    the validation context, the certificates and time periods covered by
    cached CRLs and OCSP responses, and a disclosure policy controlling which
    certificate identities may be disclosed to which issuing services. No
    network requests are made.

    :param validation_context:
        A certvalidator.context.ValidationContext object containing the
        validated certificates and cached CRLs and OCSP responses

    :param certs:
        A list of asn1crypto.x509.Certificate objects to plan revocation
        evidence gathering for

    :param moment:
        None or a datetime.datetime object with a tzinfo value to plan for.
        If None, the moment of the validation context is used.

    :param disclosure_policy:
        None or a dict with keys being unicode strings of service URLs (OCSP
        responder or CRL distribution point URLs), and values being lists of
        certificate identities that may be disclosed to that service. Each
        identity may be an asn1crypto.x509.Certificate object, or the SHA-1
        fingerprint of the certificate as a byte string or unicode string of
        hex characters, optionally separated into pairs by spaces or colons.
        If None, no certificate identity may be disclosed to any service.

    :raises:
        TypeError - when any of the parameters are of the wrong type
        ValueError - when moment is a naive datetime object

    :return:
        A RevocationEvidencePlan object
    """

    if not isinstance(validation_context, ValidationContext):
        raise TypeError(pretty_message(
            '''
            validation_context must be an instance of
            certvalidator.context.ValidationContext, not %s
            ''',
            type_name(validation_context)
        ))

    if not isinstance(certs, (list, tuple)):
        raise TypeError(pretty_message(
            '''
            certs must be a list of asn1crypto.x509.Certificate objects, not %s
            ''',
            type_name(certs)
        ))
    for cert in certs:
        if not isinstance(cert, x509.Certificate):
            raise TypeError(pretty_message(
                '''
                certs must be a list of asn1crypto.x509.Certificate objects,
                not %s
                ''',
                type_name(cert)
            ))

    if moment is None:
        moment = validation_context.moment
    else:
        if not isinstance(moment, datetime):
            raise TypeError(pretty_message(
                '''
                moment must be a datetime object, not %s
                ''',
                type_name(moment)
            ))
        if moment.utcoffset() is None:
            raise ValueError(pretty_message(
                '''
                moment is a naive datetime object, meaning the tzinfo
                attribute is not set to a valid timezone
                '''
            ))

    normalized_policy = _normalize_disclosure_policy(disclosure_policy)

    covered = []
    to_fetch = []
    suspended = []

    for cert in certs:
        # Certificates already validated in this context require no query
        if validation_context.check_validation(cert) is not None:
            covered.append(cert)
            continue

        # Certificates covered by a cached CRL or OCSP response for the plan
        # moment require no query
        if _covered_by_cached_crl(validation_context, cert, moment):
            covered.append(cert)
            continue
        if _covered_by_cached_ocsp(validation_context, cert, moment):
            covered.append(cert)
            continue

        permitted_urls = []
        for url in _service_urls(cert):
            if cert.sha1 in normalized_policy.get(url, set()):
                permitted_urls.append(url)

        if permitted_urls:
            to_fetch.append((cert, permitted_urls))
        else:
            suspended.append(cert)

    return RevocationEvidencePlan(moment, covered, to_fetch, suspended)


def _normalize_disclosure_policy(disclosure_policy):
    """
    Normalizes a disclosure policy into a dict of unicode string service URLs
    to sets of SHA-1 fingerprint byte strings of the certificates that may be
    disclosed to the service

    :param disclosure_policy:
        None or a dict as described in plan_revocation_evidence()

    :return:
        A dict with unicode string keys and set-of-byte-string values
    """

    if disclosure_policy is None:
        return {}

    if not isinstance(disclosure_policy, dict):
        raise TypeError(pretty_message(
            '''
            disclosure_policy must be a dict of unicode string service URLs to
            lists of certificate identities, not %s
            ''',
            type_name(disclosure_policy)
        ))

    normalized = {}
    for url, identities in disclosure_policy.items():
        if not isinstance(url, str_cls):
            raise TypeError(pretty_message(
                '''
                disclosure_policy keys must be unicode strings of service
                URLs, not %s
                ''',
                type_name(url)
            ))
        if not isinstance(identities, (list, tuple, set)):
            raise TypeError(pretty_message(
                '''
                disclosure_policy values must be lists of certificate
                identities, not %s
                ''',
                type_name(identities)
            ))
        allowed = set()
        for identity in identities:
            if isinstance(identity, x509.Certificate):
                allowed.add(identity.sha1)
                continue
            if isinstance(identity, byte_cls):
                identity = identity.decode('ascii')
            if not isinstance(identity, str_cls):
                raise TypeError(pretty_message(
                    '''
                    disclosure_policy identities must be
                    asn1crypto.x509.Certificate objects, byte strings or
                    unicode strings, not %s
                    ''',
                    type_name(identity)
                ))
            # Allow users to copy from various OS and browser info dialogs,
            # some of which separate the hex char pairs via spaces or colons
            identity = identity.replace(' ', '').replace(':', '')
            allowed.add(binascii.unhexlify(identity.encode('ascii')))
        normalized[url] = allowed

    return normalized


def _service_urls(cert):
    """
    Lists the URLs of the revocation services a certificate refers to - the
    OCSP responder URLs and the (delta) CRL distribution point URLs

    :param cert:
        An asn1crypto.x509.Certificate object

    :return:
        A list of unicode strings
    """

    urls = list(cert.ocsp_urls)
    for distribution_point in cert.crl_distribution_points:
        urls.append(distribution_point.url)
    for distribution_point in cert.delta_crl_distribution_points:
        urls.append(distribution_point.url)
    return urls


def _covered_by_cached_crl(validation_context, cert, moment):
    """
    Checks if a complete CRL cached in the validation context was issued by
    the issuer of the certificate and is valid for the moment

    :param validation_context:
        A certvalidator.context.ValidationContext object

    :param cert:
        An asn1crypto.x509.Certificate object

    :param moment:
        A datetime.datetime object

    :return:
        A bool - if a cached CRL covers the certificate at the moment
    """

    for certificate_list in validation_context.crls:
        # Delta CRLs do not provide standalone coverage
        if certificate_list.delta_crl_indicator_value is not None:
            continue
        if certificate_list.issuer.hashable != cert.issuer.hashable:
            continue
        tbs_cert_list = certificate_list['tbs_cert_list']
        if moment < tbs_cert_list['this_update'].native:
            continue
        next_update = tbs_cert_list['next_update'].native
        if next_update is not None and moment > next_update:
            continue
        return True

    return False


def _covered_by_cached_ocsp(validation_context, cert, moment):
    """
    Checks if an OCSP response cached in the validation context contains a
    single response for the certificate that is valid for the moment

    :param validation_context:
        A certvalidator.context.ValidationContext object

    :param cert:
        An asn1crypto.x509.Certificate object

    :param moment:
        A datetime.datetime object

    :return:
        A bool - if a cached OCSP response covers the certificate at the
        moment
    """

    for ocsp_response in validation_context.ocsps:
        status = ocsp_response['response_status'].native
        if status != 'successful':
            continue

        response_bytes = ocsp_response['response_bytes']
        if response_bytes['response_type'].native != 'basic_ocsp_response':
            continue

        response = response_bytes['response'].parsed
        for cert_response in response['tbs_response_data']['responses']:
            if _ocsp_single_response_matches(validation_context, cert, cert_response, moment):
                return True

    return False


def _ocsp_single_response_matches(validation_context, cert, cert_response, moment):
    """
    Checks if a single response from an OCSP response is for the certificate
    and valid for the moment

    :param validation_context:
        A certvalidator.context.ValidationContext object

    :param cert:
        An asn1crypto.x509.Certificate object

    :param cert_response:
        An asn1crypto.ocsp.SingleResponse object

    :param moment:
        A datetime.datetime object

    :return:
        A bool - if the single response covers the certificate at the moment
    """

    cert_id = cert_response['cert_id']

    hash_algo = cert_id['hash_algorithm']['algorithm'].native
    try:
        cert_issuer_name_hash = getattr(cert.issuer, hash_algo)
    except AttributeError:
        return False

    if cert_id['issuer_name_hash'].native != cert_issuer_name_hash:
        return False
    if cert_id['serial_number'].native != cert.serial_number:
        return False

    # The issuer key hash can only be confirmed when the issuer certificate
    # is known to the validation context
    issuers = validation_context.certificate_registry.retrieve_by_name(cert.issuer)
    if issuers:
        key_hash_match = False
        for issuer in issuers:
            if getattr(issuer.public_key, hash_algo) == cert_id['issuer_key_hash'].native:
                key_hash_match = True
                break
        if not key_hash_match:
            return False

    if moment < cert_response['this_update'].native:
        return False
    next_update = cert_response['next_update'].native
    if next_update is not None and moment > next_update:
        return False

    return True
