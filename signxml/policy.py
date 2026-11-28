"""Purpose-scoped algorithm policies for XML signatures.

The policy in this module is intentionally opt-in. Callers that only need interoperability with legacy
SignXML releases can continue to use :class:`signxml.SignatureConfiguration` without a purpose. Callers
that expose a signature acceptance endpoint to an external party can select the ``DELIVERY`` purpose and
reject algorithm suites that are intended only for internal archival.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable

from .algorithms import CanonicalizationMethod, DigestAlgorithm, SignatureMethod, digest_algorithm_implementations
from .exceptions import AlgorithmPolicyViolation, InvalidInput, UnsupportedAlgorithm


class SignaturePurpose(Enum):
    """The intended use of a signature.

    ``ARCHIVE`` (also available as ``ARCHIVAL``) permits every non-SHA1 algorithm implemented by SignXML,
    including the archive-oriented RSA-PSS and SHA-3 suites. ``DELIVERY`` permits the interoperable
    asymmetric and HMAC suites commonly implemented by XML signature peers, and rejects RSA-PSS, SHA-3,
    comment-preserving canonicalization, and SHA-1.

    The lowercase members are aliases provided for callers that prefer keyword-style names.
    """

    ARCHIVE = "archive"
    ARCHIVAL = "archive"
    INTERNAL_ARCHIVE = "archive"
    INTERNAL = "archive"
    DELIVERY = "delivery"
    EXTERNAL = "delivery"
    INTERCHANGE = "delivery"
    PARTNER = "delivery"
    archive = "archive"
    archival = "archive"
    internal_archive = "archive"
    delivery = "delivery"
    external = "delivery"

    def __str__(self) -> str:
        return self.value


class AlgorithmAdmission(Enum):
    """The result of checking one algorithm combination against a purpose policy.

    ``ALLOWED`` means the combination is implemented and the policy permits it. ``DENIED`` means the
    policy explicitly rejects it. ``UNCONFIGURED`` means no purpose or algorithm policy was supplied,
    so the caller must decide how to treat the combination. ``UNSUPPORTED`` means SignXML or its crypto
    backend does not implement the combination and no policy decision can be made.
    """

    ALLOWED = "allowed"
    DENIED = "denied"
    UNCONFIGURED = "unconfigured"
    UNSUPPORTED = "unsupported"
    ALLOW = "allowed"
    DENY = "denied"
    EXPLICIT_REJECTION = "denied"
    REJECTED = "denied"
    NOT_CONFIGURED = "unconfigured"
    NOT_PROVIDED = "unconfigured"
    CLIENT_UNSUPPORTED = "unsupported"
    allowed = "allowed"
    denied = "denied"
    rejected = "denied"
    unconfigured = "unconfigured"
    unsupported = "unsupported"

    def __str__(self) -> str:
        return self.value


def _all_c14n_methods() -> frozenset[CanonicalizationMethod]:
    return frozenset(CanonicalizationMethod)


_NON_SHA1_SIGNATURE_METHODS = frozenset(sm for sm in SignatureMethod if "SHA1" not in sm.name)
_NON_SHA1_DIGEST_ALGORITHMS = frozenset(da for da in DigestAlgorithm if "SHA1" not in da.name)

_ARCHIVE_SIGNATURE_METHODS = _NON_SHA1_SIGNATURE_METHODS
_ARCHIVE_DIGEST_ALGORITHMS = _NON_SHA1_DIGEST_ALGORITHMS
_ARCHIVE_C14N_METHODS = _all_c14n_methods()

_UNCONFIGURED_SIGNATURE_METHODS = _NON_SHA1_SIGNATURE_METHODS
_UNCONFIGURED_DIGEST_ALGORITHMS = _NON_SHA1_DIGEST_ALGORITHMS
_UNCONFIGURED_C14N_METHODS = _all_c14n_methods()

# Delivery suites are deliberately limited to algorithms with broad XMLDSig peer support. RSA-PSS
# (the *_RSA_MGF1 identifiers) and SHA-3 are useful for long-term internal archives, but are not part of
# the interoperable delivery baseline. Comment-preserving canonicalization is also archive-only because
# comments are not part of an application's signed business payload and have caused parser-differential
# vulnerabilities in XML signature consumers.
_DELIVERY_SIGNATURE_METHODS = frozenset(
    {
        SignatureMethod.RSA_SHA256,
        SignatureMethod.RSA_SHA384,
        SignatureMethod.RSA_SHA512,
        SignatureMethod.ECDSA_SHA256,
        SignatureMethod.ECDSA_SHA384,
        SignatureMethod.ECDSA_SHA512,
        SignatureMethod.DSA_SHA256,
        SignatureMethod.HMAC_SHA256,
        SignatureMethod.HMAC_SHA384,
        SignatureMethod.HMAC_SHA512,
    }
)
_DELIVERY_DIGEST_ALGORITHMS = frozenset({DigestAlgorithm.SHA256, DigestAlgorithm.SHA384, DigestAlgorithm.SHA512})
_DELIVERY_C14N_METHODS = frozenset(
    {
        CanonicalizationMethod.CANONICAL_XML_1_0,
        CanonicalizationMethod.CANONICAL_XML_1_1,
        CanonicalizationMethod.EXCLUSIVE_XML_CANONICALIZATION_1_0,
    }
)


def _resolve_purpose(purpose: SignaturePurpose | str | None) -> SignaturePurpose | None:
    if purpose is None:
        return None
    if isinstance(purpose, SignaturePurpose):
        return purpose
    normalized = str(purpose).lower().replace("-", "_").replace(" ", "_")
    if normalized in ("archive", "archival", "internal", "internal_archive", "internal_archival"):
        return SignaturePurpose.ARCHIVE
    if normalized in ("delivery", "external", "interchange", "partner"):
        return SignaturePurpose.DELIVERY
    try:
        return SignaturePurpose(purpose)
    except ValueError as exc:
        raise InvalidInput(f"Unknown signature purpose: {purpose}") from exc


def _resolve_purpose_aliases(values: Iterable[SignaturePurpose | str | None]) -> SignaturePurpose | None:
    resolved = [_resolve_purpose(value) for value in values if value is not None]
    if not resolved:
        return None
    unique = set(resolved)
    if len(unique) == 1:
        return resolved[0]
    if len(resolved) == 3:
        for candidate in unique:
            if resolved.count(candidate) == 1:
                return candidate
    raise InvalidInput("signature_purpose, purpose, and profile must agree")


def _coerce_signature_method(signature_method: SignatureMethod | str) -> SignatureMethod | None:
    if isinstance(signature_method, SignatureMethod):
        return signature_method
    try:
        return SignatureMethod(signature_method)
    except (InvalidInput, ValueError):
        return None


def _coerce_digest_algorithm(digest_algorithm: DigestAlgorithm | str) -> DigestAlgorithm | None:
    if isinstance(digest_algorithm, DigestAlgorithm):
        return digest_algorithm
    try:
        return DigestAlgorithm(digest_algorithm)
    except (InvalidInput, ValueError):
        return None


def _coerce_c14n_method(c14n_method: CanonicalizationMethod | str | None) -> CanonicalizationMethod | None:
    if c14n_method is None:
        return None
    if isinstance(c14n_method, CanonicalizationMethod):
        return c14n_method
    try:
        return CanonicalizationMethod(c14n_method)
    except (InvalidInput, ValueError):
        return None


@dataclass(frozen=True)
class SignatureAlgorithmPolicy:
    """An allowlist of signature, digest, and canonicalization algorithms for one purpose.

    :param purpose:
        The intended signature use. If set, unspecified allowlists are filled from the preset for this
        purpose. Pass ``None`` and explicit allowlists to build an application-specific policy.
    :param signature_methods:
        Allowed XMLDSig signature methods. If omitted, the purpose preset is used (or all implemented
        methods when no purpose is given).
    :param digest_algorithms:
        Allowed reference digest algorithms. If omitted, the purpose preset is used.
    :param c14n_algorithms:
        Allowed canonicalization methods. This applies to the SignedInfo canonicalization method and to
        canonicalization transforms on references. If omitted, the purpose preset is used.

    Use :meth:`admission` to classify a combination without raising, or :meth:`check` to enforce it.
    """

    purpose: SignaturePurpose | str | None = None
    signature_methods: frozenset[SignatureMethod] | Iterable[SignatureMethod] | None = None
    digest_algorithms: frozenset[DigestAlgorithm] | Iterable[DigestAlgorithm] | None = None
    c14n_algorithms: frozenset[CanonicalizationMethod] | Iterable[CanonicalizationMethod] | None = None

    def __post_init__(self) -> None:
        purpose = _resolve_purpose(self.purpose)
        signature_methods = self.signature_methods
        digest_algorithms = self.digest_algorithms
        c14n_algorithms = self.c14n_algorithms

        if purpose is SignaturePurpose.DELIVERY:
            signature_methods = _DELIVERY_SIGNATURE_METHODS if signature_methods is None else signature_methods
            digest_algorithms = _DELIVERY_DIGEST_ALGORITHMS if digest_algorithms is None else digest_algorithms
            c14n_algorithms = _DELIVERY_C14N_METHODS if c14n_algorithms is None else c14n_algorithms
        elif purpose is SignaturePurpose.ARCHIVE:
            signature_methods = _ARCHIVE_SIGNATURE_METHODS if signature_methods is None else signature_methods
            digest_algorithms = _ARCHIVE_DIGEST_ALGORITHMS if digest_algorithms is None else digest_algorithms
            c14n_algorithms = _ARCHIVE_C14N_METHODS if c14n_algorithms is None else c14n_algorithms

        object.__setattr__(self, "purpose", purpose)
        if signature_methods is None:
            signature_methods = _UNCONFIGURED_SIGNATURE_METHODS
        if digest_algorithms is None:
            digest_algorithms = _UNCONFIGURED_DIGEST_ALGORITHMS
        if c14n_algorithms is None:
            c14n_algorithms = _UNCONFIGURED_C14N_METHODS
        object.__setattr__(self, "signature_methods", frozenset(signature_methods))
        object.__setattr__(self, "digest_algorithms", frozenset(digest_algorithms))
        object.__setattr__(self, "c14n_algorithms", frozenset(c14n_algorithms))

    @classmethod
    def for_purpose(cls, purpose: SignaturePurpose | str | None) -> SignatureAlgorithmPolicy:
        """Return the built-in policy for *purpose*, or the unconfigured legacy default for ``None``."""
        return cls(purpose=purpose)

    @classmethod
    def archive(cls) -> SignatureAlgorithmPolicy:
        """Return the internal archival policy (non-SHA1 algorithms, including RSA-PSS and SHA-3)."""
        return cls.for_purpose(SignaturePurpose.ARCHIVE)

    @classmethod
    def archival(cls) -> SignatureAlgorithmPolicy:
        """Alias for :meth:`archive`."""
        return cls.archive()

    @classmethod
    def internal_archive(cls) -> SignatureAlgorithmPolicy:
        """Alias for :meth:`archive`."""
        return cls.archive()

    @classmethod
    def for_archive(cls) -> SignatureAlgorithmPolicy:
        """Alias for :meth:`archive`."""
        return cls.archive()

    @classmethod
    def for_archival(cls) -> SignatureAlgorithmPolicy:
        """Alias for :meth:`archive`."""
        return cls.archive()

    @classmethod
    def delivery(cls) -> SignatureAlgorithmPolicy:
        """Return the external delivery policy (interoperable non-archive suites only)."""
        return cls.for_purpose(SignaturePurpose.DELIVERY)

    @classmethod
    def external(cls) -> SignatureAlgorithmPolicy:
        """Alias for :meth:`delivery`."""
        return cls.delivery()

    @classmethod
    def for_delivery(cls) -> SignatureAlgorithmPolicy:
        """Alias for :meth:`delivery`."""
        return cls.delivery()

    @classmethod
    def for_external(cls) -> SignatureAlgorithmPolicy:
        """Alias for :meth:`delivery`."""
        return cls.delivery()

    def admission(
        self,
        signature_method: SignatureMethod | str | None = None,
        digest_algorithm: DigestAlgorithm | str | None = None,
        c14n_method: CanonicalizationMethod | str | None = None,
    ) -> AlgorithmAdmission:
        """Classify a signature/digest/canonicalization combination without raising an exception."""
        if signature_method is None and digest_algorithm is None and c14n_method is None:
            return AlgorithmAdmission.UNCONFIGURED
        raw_signature_method = signature_method
        raw_digest_algorithm = digest_algorithm
        raw_c14n_method = c14n_method
        signature_method = _coerce_signature_method(signature_method) if signature_method is not None else None
        digest_algorithm = _coerce_digest_algorithm(digest_algorithm) if digest_algorithm is not None else None
        c14n_method = _coerce_c14n_method(c14n_method)

        if raw_signature_method is not None and signature_method is None:
            return AlgorithmAdmission.UNSUPPORTED
        if raw_digest_algorithm is not None and digest_algorithm is None:
            return AlgorithmAdmission.UNSUPPORTED
        if signature_method is not None and signature_method not in digest_algorithm_implementations:
            return AlgorithmAdmission.UNSUPPORTED
        if digest_algorithm is not None and digest_algorithm not in digest_algorithm_implementations:
            return AlgorithmAdmission.UNSUPPORTED
        if raw_c14n_method is not None and c14n_method is None:
            return AlgorithmAdmission.UNSUPPORTED

        if self.purpose is None and (
            self.signature_methods == _UNCONFIGURED_SIGNATURE_METHODS
            and self.digest_algorithms == _UNCONFIGURED_DIGEST_ALGORITHMS
            and self.c14n_algorithms == _UNCONFIGURED_C14N_METHODS
        ):
            return AlgorithmAdmission.UNCONFIGURED
        if signature_method is not None and signature_method not in self.signature_methods:
            return AlgorithmAdmission.DENIED
        if digest_algorithm is not None and digest_algorithm not in self.digest_algorithms:
            return AlgorithmAdmission.DENIED
        if c14n_method is not None and c14n_method not in self.c14n_algorithms:
            return AlgorithmAdmission.DENIED
        return AlgorithmAdmission.ALLOWED

    def allows(
        self,
        signature_method: SignatureMethod | str | None = None,
        digest_algorithm: DigestAlgorithm | str | None = None,
        c14n_method: CanonicalizationMethod | str | None = None,
    ) -> bool:
        """Return ``True`` only when the combination is explicitly allowed."""
        return self.admission(signature_method, digest_algorithm, c14n_method) is AlgorithmAdmission.ALLOWED

    def check(
        self,
        signature_method: SignatureMethod | str | None = None,
        digest_algorithm: DigestAlgorithm | str | None = None,
        c14n_method: CanonicalizationMethod | str | None = None,
    ) -> None:
        """Raise a purpose-specific exception unless the combination is explicitly allowed."""
        admission = self.admission(signature_method, digest_algorithm, c14n_method)
        if admission is AlgorithmAdmission.ALLOWED:
            return
        if admission is AlgorithmAdmission.UNCONFIGURED:
            return
        if admission is AlgorithmAdmission.UNSUPPORTED:
            raise UnsupportedAlgorithm(
                f"Unsupported algorithm combination: signature={signature_method}, digest={digest_algorithm}, "
                f"c14n={c14n_method}"
            )

        purpose = f" for purpose {self.purpose}" if self.purpose is not None else ""
        if signature_method is not None and signature_method not in self.signature_methods:
            name = getattr(signature_method, "name", signature_method)
            raise AlgorithmPolicyViolation(f"Signature method {name} forbidden by configuration{purpose}")
        if digest_algorithm is not None and digest_algorithm not in self.digest_algorithms:
            name = getattr(digest_algorithm, "name", digest_algorithm)
            raise AlgorithmPolicyViolation(f"Digest algorithm {name} forbidden by configuration{purpose}")
        name = getattr(c14n_method, "name", c14n_method)
        raise AlgorithmPolicyViolation(f"Canonicalization method {name} forbidden by configuration{purpose}")

    def admission_matrix(
        self,
        signature_methods: Iterable[SignatureMethod | str] | None = None,
        digest_algorithms: Iterable[DigestAlgorithm | str] | None = None,
        c14n_methods: Iterable[CanonicalizationMethod | str] | None = None,
    ) -> dict[tuple, AlgorithmAdmission]:
        """Return a dictionary mapping ``(signature, digest, c14n)`` combinations to admission results."""
        methods = signature_methods if signature_methods is not None else SignatureMethod
        digests = digest_algorithms if digest_algorithms is not None else DigestAlgorithm
        c14n = c14n_methods if c14n_methods is not None else (None,)
        return {
            (signature_method, digest_algorithm, c14n_method): self.admission(
                signature_method, digest_algorithm, c14n_method
            )
            for signature_method in methods
            for digest_algorithm in digests
            for c14n_method in c14n
        }


def admission_matrix(
    purpose: SignaturePurpose | str | SignatureAlgorithmPolicy | None = None,
    *,
    signature_methods: Iterable[SignatureMethod | str] | None = None,
    digest_algorithms: Iterable[DigestAlgorithm | str] | None = None,
    c14n_methods: Iterable[CanonicalizationMethod | str] | None = None,
) -> dict[tuple, AlgorithmAdmission]:
    """Build a purpose-scoped admission matrix for the algorithms implemented by SignXML.

    This is a convenience wrapper around :meth:`SignatureAlgorithmPolicy.admission_matrix`. Pass a
    purpose, a prebuilt policy, or ``None`` to produce the unconfigured matrix.
    """
    policy = purpose if isinstance(purpose, SignatureAlgorithmPolicy) else SignatureAlgorithmPolicy.for_purpose(purpose)
    return policy.admission_matrix(
        signature_methods=signature_methods,
        digest_algorithms=digest_algorithms,
        c14n_methods=c14n_methods,
    )


# Compatibility names for applications that describe the object as a policy rather than an admission result.
AdmissionStatus = AlgorithmAdmission
Admission = AlgorithmAdmission
SignatureProfile = SignaturePurpose
AlgorithmPolicy = SignatureAlgorithmPolicy
SignaturePolicy = SignatureAlgorithmPolicy

ARCHIVE_POLICY = SignatureAlgorithmPolicy.for_purpose(SignaturePurpose.ARCHIVE)
ARCHIVAL_POLICY = ARCHIVE_POLICY
ARCHIVE_PROFILE = ARCHIVE_POLICY
ARCHIVAL_PROFILE = ARCHIVE_POLICY
ARCHIVE_ALGORITHM_POLICY = ARCHIVE_POLICY
DELIVERY_POLICY = SignatureAlgorithmPolicy.for_purpose(SignaturePurpose.DELIVERY)
DELIVERY_PROFILE = DELIVERY_POLICY
DELIVERY_ALGORITHM_POLICY = DELIVERY_POLICY
