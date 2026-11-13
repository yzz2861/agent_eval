"""
`cryptography.x509 <https://github.com/pyca/cryptography>`_-specific code.
"""

from __future__ import annotations

import warnings

from collections.abc import Sequence
from enum import Enum

from cryptography.hazmat import asn1
from cryptography.x509 import (
    Certificate,
    DNSName,
    ExtensionOID,
    IPAddress,
    NameOID,
    ObjectIdentifier,
    OtherName,
    UniformResourceIdentifier,
)
from cryptography.x509.extensions import ExtensionNotFound

from .exceptions import CertificateError, InvalidSubjectCommonNameError
from .hazmat import (
    DNS_ID,
    CertificatePattern,
    DNSPattern,
    IPAddress_ID,
    IPAddressPattern,
    ServiceMatch,
    SRVPattern,
    URIPattern,
    verify_service_identity,
)


__all__ = [
    "CommonNameFallback",
    "extract_common_name_pattern",
    "extract_patterns",
    "verify_certificate_hostname",
    "verify_certificate_hostname_with_policy",
    "verify_certificate_ip_address",
]


class CommonNameFallback(Enum):
    """
    Policy for whether the subject's ``commonName`` may be used as a
    DNS-ID when verifying a certificate's hostname.

    The policy is only ever consulted if the certificate contains *no*
    ``subjectAltName`` extension at all.  If any ``subjectAltName``
    extension is present -- even one that contains only URI or IP address
    entries -- the ``commonName`` is always ignored.

    .. versionadded:: 26.2.0
    """

    DENY = "deny"
    """
    Never fall back to the ``commonName`` (the default, and the
    historical behavior of *service-identity*).
    """

    ALLOW_IF_NO_SAN = "allow-if-no-san"
    """
    Fall back to a single, strictly validated ``commonName`` if and only
    if the certificate carries no ``subjectAltName`` extension at all.
    """


def verify_certificate_hostname(
    certificate: Certificate, hostname: str
) -> None:
    r"""
    Verify whether *certificate* is valid for *hostname*.

    .. note::
        Nothing is verified about the *authority* of the certificate;
        the caller must verify that the certificate chains to an appropriate
        trust root themselves.

    Args:
        certificate: A *cryptography* X509 certificate object.

        hostname: The hostname that *certificate* should be valid for.

    Raises:
        service_identity.VerificationError:
            If *certificate* is not valid for *hostname*.

        service_identity.CertificateError:
            If *certificate* contains invalid / unexpected data. This includes
            the case where the certificate contains no `subjectAltName`\ s.

    .. versionchanged:: 24.1.0
        :exc:`~service_identity.CertificateError` is raised if the certificate
        contains no ``subjectAltName``\ s instead of
        :exc:`~service_identity.VerificationError`.

    .. versionchanged:: 26.2.0
        The more specific
        :exc:`~service_identity.exceptions.SubjectAltNameMissingError` (a
        subclass of :exc:`~service_identity.CertificateError`) is raised if
        the certificate contains no ``subjectAltName``\ s.
    """
    verify_certificate_hostname_with_policy(certificate, hostname)


def verify_certificate_hostname_with_policy(
    certificate: Certificate,
    hostname: str,
    *,
    common_name_fallback: CommonNameFallback = CommonNameFallback.DENY,
) -> list[ServiceMatch]:
    r"""
    Verify whether *certificate* is valid for *hostname*, with an explicit
    policy for falling back to the subject's ``commonName``.

    Behaves exactly like :func:`verify_certificate_hostname`, except that
    *common_name_fallback* controls whether the subject's ``commonName``
    may be used as a DNS-ID.  The fallback is only consulted if the
    certificate contains no ``subjectAltName`` extension at all; if any
    ``subjectAltName`` extension is present (even one with only URI or
    IP address entries), the ``commonName`` is always ignored.

    The returned matches make the decision auditable: they record exactly
    which certificate patterns (SAN-derived or ``commonName``-derived)
    matched *hostname*.

    Args:
        certificate: A *cryptography* X509 certificate object.

        hostname: The hostname that *certificate* should be valid for.

        common_name_fallback: The :class:`CommonNameFallback` policy to
            apply.  Defaults to :attr:`CommonNameFallback.DENY`, which
            reproduces :func:`verify_certificate_hostname`.

    Returns:
        The list of matches between *hostname* and the certificate's
        patterns.

    Raises:
        service_identity.VerificationError:
            If *certificate* is not valid for *hostname*.  This includes the
            case where the certificate contains ``subjectAltName``\ s,
            but none of them match.

        service_identity.exceptions.SubjectAltNameMissingError:
            If *certificate* contains no ``subjectAltName``\ s and
            *common_name_fallback* is :attr:`CommonNameFallback.DENY`.

        service_identity.exceptions.InvalidSubjectCommonNameError:
            If the ``commonName`` fallback is allowed, but the subject's
            ``commonName`` is structurally invalid.

        service_identity.CertificateError:
            If *certificate* contains other invalid / unexpected data.

    .. versionadded:: 26.2.0
    """
    return verify_service_identity(
        cert_patterns=extract_patterns(
            certificate, common_name_fallback=common_name_fallback
        ),
        obligatory_ids=[DNS_ID(hostname)],
        optional_ids=[],
    )


def verify_certificate_ip_address(
    certificate: Certificate, ip_address: str
) -> None:
    r"""
    Verify whether *certificate* is valid for *ip_address*.

    .. note::
        Nothing is verified about the *authority* of the certificate;
        the caller must verify that the certificate chains to an appropriate
        trust root themselves.

    Args:
        certificate: A *cryptography* X509 certificate object.

        ip_address:
            The IP address that *connection* should be valid for.  Can be an
            IPv4 or IPv6 address.

    Raises:
        service_identity.VerificationError:
            If *certificate* is not valid for *ip_address*.

        service_identity.CertificateError:
            If *certificate* contains invalid / unexpected data. This includes
            the case where the certificate contains no ``subjectAltName``\ s.

    .. versionadded:: 18.1.0

    .. versionchanged:: 24.1.0
        :exc:`~service_identity.CertificateError` is raised if the certificate
        contains no ``subjectAltName``\ s instead of
        :exc:`~service_identity.VerificationError`.
    """
    verify_service_identity(
        cert_patterns=extract_patterns(certificate),
        obligatory_ids=[IPAddress_ID(ip_address)],
        optional_ids=[],
    )


ID_ON_DNS_SRV = ObjectIdentifier("1.3.6.1.5.5.7.8.7")  # id_on_dnsSRV


def extract_common_name_pattern(cert: Certificate) -> DNSPattern:
    """
    Extract the subject's ``commonName`` from *cert* as a
    :class:`~service_identity.hazmat.DNSPattern`, validating it strictly.

    The ``commonName`` is read from the certificate's subject -- never
    from an extension -- and is rejected unless it is unambiguous and
    well-formed:

    - There must be exactly one ``commonName`` attribute, living in its
      own single-valued RDN.
    - It must not be empty or consist only of whitespace.
    - It must not look like a wildcard pattern.
    - It must be a valid (IDNA-encodable) DNS name.

    Args:
        cert: The certificate to extract the ``commonName`` from.

    Returns:
        The ``commonName`` as a DNS pattern.

    Raises:
        service_identity.exceptions.InvalidSubjectCommonNameError:
            If the ``commonName`` is missing or structurally invalid.

    .. versionadded:: 26.2.0
    """
    cn_rdns = [
        rdn
        for rdn in cert.subject.rdns
        if any(attr.oid == NameOID.COMMON_NAME for attr in rdn)
    ]
    if not cn_rdns:
        msg = "Certificate subject contains no commonName."
        raise InvalidSubjectCommonNameError(msg)
    if len(cn_rdns) > 1:
        msg = "Certificate subject contains more than one commonName."
        raise InvalidSubjectCommonNameError(msg)

    (cn_rdn,) = cn_rdns
    if len(cn_rdn) != 1:
        msg = "Certificate commonName is part of a multi-valued RDN."
        raise InvalidSubjectCommonNameError(msg)

    (cn_attr,) = cn_rdn
    common_name = cn_attr.value.strip()
    if not common_name:
        msg = "Certificate commonName is empty."
        raise InvalidSubjectCommonNameError(msg)
    if "*" in common_name:
        msg = f"Certificate commonName {common_name!r} looks like a wildcard pattern."
        raise InvalidSubjectCommonNameError(msg)

    try:
        dns_id = DNS_ID(common_name)
    except (TypeError, ValueError, ImportError) as e:
        msg = (
            f"Certificate commonName {common_name!r} is not a valid DNS name."
        )
        raise InvalidSubjectCommonNameError(msg) from e

    return DNSPattern(pattern=dns_id.hostname)


def extract_patterns(
    cert: Certificate,
    *,
    common_name_fallback: CommonNameFallback = CommonNameFallback.DENY,
) -> Sequence[CertificatePattern]:
    """
    Extract all valid ID patterns from a certificate for service verification.

    Args:
        cert: The certificate to be dissected.

        common_name_fallback:
            Policy for falling back to the subject's ``commonName`` if
            the certificate contains no ``subjectAltName`` extension at
            all.  If any ``subjectAltName`` extension is present (even
            one with only URI or IP address entries), the ``commonName``
            is always ignored.  Defaults to :attr:`CommonNameFallback.DENY`.

    Returns:
        List of IDs.

    .. versionchanged:: 23.1.0
       ``commonName`` is not used as a fallback anymore.

    .. versionchanged:: 26.2.0
       Added the explicit *common_name_fallback* policy.
    """
    ids: list[CertificatePattern] = []
    try:
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
    except ExtensionNotFound:
        if common_name_fallback is CommonNameFallback.ALLOW_IF_NO_SAN:
            ids.append(extract_common_name_pattern(cert))
    else:
        ids.extend(
            [
                DNSPattern.from_bytes(name.encode("utf-8"))
                for name in ext.value.get_values_for_type(DNSName)
            ]
        )
        ids.extend(
            [
                URIPattern.from_bytes(uri.encode("utf-8"))
                for uri in ext.value.get_values_for_type(
                    UniformResourceIdentifier
                )
            ]
        )
        ids.extend(
            [
                IPAddressPattern(ip)
                for ip in ext.value.get_values_for_type(IPAddress)
            ]
        )
        for other in ext.value.get_values_for_type(OtherName):
            if other.type_id == ID_ON_DNS_SRV:
                try:
                    srv = asn1.decode_der(asn1.IA5String, other.value)
                except ValueError as e:
                    msg = "Unexpected certificate content."
                    raise CertificateError(msg) from e

                ids.append(SRVPattern.from_bytes(srv.as_str().encode("ascii")))

    return ids


def extract_ids(cert: Certificate) -> Sequence[CertificatePattern]:
    """
    Deprecated and never public API.  Use :func:`extract_patterns` instead.

    .. deprecated:: 23.1.0
    """
    warnings.warn(
        category=DeprecationWarning,
        message="`extract_ids()` is deprecated, please use `extract_patterns()`.",
        stacklevel=2,
    )
    return extract_patterns(cert)
