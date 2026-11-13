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
class DNSMismatch(Mismatch):
    """
    No matching DNSPattern could be found.
    """

    #: The normalized certificate DNS pattern that was considered, if any.
    pattern: bytes | None = attr.ib(default=None, eq=False)


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


@attr.s(auto_exc=True, slots=True)
class CertificateError(Exception):
    r"""
    Certificate contains invalid or unexpected data.

    This includes the case where s certificate contains no
    ``subjectAltName``\ s.
    """

    #: Human-readable explanation of the problem.
    message: str = attr.ib(default="")

    #: The normalized DNS pattern involved, when one could be determined.
    pattern: bytes | None = attr.ib(default=None)

    #: The normalized DNS hostname involved, when one could be determined.
    hostname: bytes | None = attr.ib(default=None)

    def __str__(self) -> str:
        return self.message
