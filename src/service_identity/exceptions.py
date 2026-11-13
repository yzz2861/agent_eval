"""
All exceptions and warnings thrown by ``service-identity``.

Separated into an own package for nicer tracebacks, you should still import
them from __init__.py.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from .hazmat import ServiceID

import attr


class SubjectAltNameWarning(DeprecationWarning):
    """
    This warning is not used anymore and will be removed in a future version.

    Formerly:

    Server Certificate does not contain a ``SubjectAltName``.

    Hostname matching is performed on the ``CommonName`` which is deprecated.

    .. deprecated:: 23.1.0
    """


@attr.s(slots=True)
class Mismatch:
    mismatched_id: ServiceID = attr.ib()


class DNSMismatch(Mismatch):
    """
    No matching DNSPattern could be found.
    """


class SRVMismatch(Mismatch):
    """
    No matching SRVPattern could be found.
    """


class URIMismatch(Mismatch):
    """
    No matching URIPattern could be found.
    """


class IPAddressMismatch(Mismatch):
    """
    No matching IPAddressPattern could be found.
    """


@attr.s(auto_exc=True)
class VerificationError(Exception):
    """
    Service identity verification failed.
    """

    errors: Sequence[Mismatch] = attr.ib()

    def __str__(self) -> str:
        return self.__repr__()


class CertificateError(Exception):
    r"""
    Certificate contains invalid or unexpected data.

    This includes the case where s certificate contains no
    ``subjectAltName``\ s.
    """


class SubjectAltNameMissingError(CertificateError):
    r"""
    Certificate contains no ``subjectAltName``\ s and the commonName
    fallback policy does not allow falling back to the subject's
    ``commonName``.

    This is a more specific :class:`CertificateError` so callers can
    distinguish "no usable identity at all" from other certificate
    problems.

    .. versionadded:: 26.2.0
    """


class InvalidSubjectCommonNameError(CertificateError):
    r"""
    The subject's ``commonName`` of a certificate is structurally
    invalid and therefore must not be used for identity verification.

    This includes duplicate ``commonName``\ s, ``commonName``\ s
    within multi-valued RDNs, empty ``commonName``\ s,
    ``commonName``\ s that look like wildcard patterns, and
    ``commonName``\ s that are not valid DNS names (including invalid
    IDNA encoding).

    .. versionadded:: 26.2.0
    """
