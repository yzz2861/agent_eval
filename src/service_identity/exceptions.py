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


@attr.s(slots=True)
class CategoryMismatch(Mismatch):
    """
    A mismatch that records which identity components did not match.

    Only the caller-supplied, normalized identity is recorded; certificate
    contents are never echoed, so unrelated tenants' identities do not leak
    through error messages.
    """

    #: The normalized identity components that failed to match, in a stable
    #: order (e.g. ``("scheme", "host", "port", "path")``).
    mismatched_categories: tuple[str, ...] = attr.ib(factory=tuple)
    #: A canonical, text representation of the caller-supplied identity.
    normalized_id: str | None = attr.ib(default=None)


class DNSMismatch(CategoryMismatch):
    """
    No matching DNSPattern could be found.
    """


class SRVMismatch(CategoryMismatch):
    """
    No matching SRVPattern could be found.
    """


class URIMismatch(CategoryMismatch):
    """
    No matching URIPattern could be found.
    """


class IPAddressMismatch(CategoryMismatch):
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
