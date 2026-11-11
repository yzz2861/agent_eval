from dataclasses import dataclass, field
from enum import Enum
from typing import List, Mapping, Optional

from cryptography import x509

from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.exceptions import (
    InvalidCertificateChain,
    InvalidRegistrationResponse,
)
from webauthn.helpers.structs import AttestationFormat
from webauthn.helpers.validate_certificate_chain import (
    validate_policy_certificate_chain,
)


class AttestationRejectionReason(str, Enum):
    """Stable audit reason codes emitted when an attestation trust policy rejects a response.

    The values are part of the public API so that audit pipelines can rely on them remaining
    stable even if human-readable messages are reworded.
    """

    FORMAT_UNSUPPORTED = "format_unsupported"
    TRUST_ROOT_MISSING = "trust_root_missing"
    CERTIFICATE_CHAIN_INCOMPLETE = "certificate_chain_incomplete"
    CERTIFICATE_CHAIN_INVALID = "certificate_chain_invalid"
    CERTIFICATE_EXPIRED = "certificate_expired"
    CERTIFICATE_KEY_USAGE = "certificate_key_usage"
    CERTIFICATE_BASIC_CONSTRAINTS = "certificate_basic_constraints"
    SIGNATURE_ALGORITHM_REJECTED = "signature_algorithm_rejected"
    AAGUID_REJECTED = "aaguid_rejected"
    NONE_ATTESTATION_REJECTED = "none_attestation_rejected"
    SELF_ATTESTATION_REJECTED = "self_attestation_rejected"


class AttestationTrustPolicyError(InvalidRegistrationResponse):
    """Raised when an explicitly enabled :class:`AttestationTrustPolicy` rejects a response.

    Subclasses :class:`InvalidRegistrationResponse` so existing callers keep catching the same
    exception, while `reason` exposes a stable code suitable for audit logs. Error messages never
    include full certificate contents.
    """

    def __init__(self, reason: AttestationRejectionReason, message: str) -> None:
        super().__init__(message)
        self.reason = reason


# COSE algorithm IDs whose use on an attestation certificate is accepted when a format policy
# does not configure its own allow-list. EdDSA and ML-DSA certificates are not listed because
# X.509 attestation certificates carrying those key types are not used by the supported formats.
_DEFAULT_ALLOWED_SIGNATURE_ALGS: List[COSEAlgorithmIdentifier] = [
    COSEAlgorithmIdentifier.ECDSA_SHA_256,
    COSEAlgorithmIdentifier.ECDSA_SHA_512,
    COSEAlgorithmIdentifier.RSASSA_PSS_SHA_256,
    COSEAlgorithmIdentifier.RSASSA_PSS_SHA_384,
    COSEAlgorithmIdentifier.RSASSA_PSS_SHA_512,
    COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
    COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_384,
    COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_512,
]

# Maps certificate signature OIDs to the COSE algorithm IDs they may satisfy.
_CERT_SIGNATURE_OID_TO_COSE = {
    x509.SignatureAlgorithmOID.ECDSA_WITH_SHA256: COSEAlgorithmIdentifier.ECDSA_SHA_256,
    x509.SignatureAlgorithmOID.ECDSA_WITH_SHA384: COSEAlgorithmIdentifier.ECDSA_SHA_512,
    x509.SignatureAlgorithmOID.ECDSA_WITH_SHA512: COSEAlgorithmIdentifier.ECDSA_SHA_512,
    x509.SignatureAlgorithmOID.RSASSA_PSS: None,  # Hash determined from the certificate itself
    x509.SignatureAlgorithmOID.RSA_WITH_SHA256: (
        COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256
    ),
    x509.SignatureAlgorithmOID.RSA_WITH_SHA384: (
        COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_384
    ),
    x509.SignatureAlgorithmOID.RSA_WITH_SHA512: (
        COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_512
    ),
}

_RSA_PSS_HASH_TO_COSE = {
    "sha256": COSEAlgorithmIdentifier.RSASSA_PSS_SHA_256,
    "sha384": COSEAlgorithmIdentifier.RSASSA_PSS_SHA_384,
    "sha512": COSEAlgorithmIdentifier.RSASSA_PSS_SHA_512,
}


@dataclass
class FormatAttestationPolicy:
    """Trust settings for a single attestation statement format (`fmt`).

    Attributes:
        `pem_root_certs_bytes`: Trust-anchor root certificates (PEM bytes) allowed for this format.
          A response whose chain does not terminate at one of these roots is rejected.
        `pem_intermediate_certs_bytes`: Additional intermediate certificates (PEM bytes) that may
          be used to complete a chain when the authenticator did not include every intermediate in
          its `x5c`.
        `allowed_aaguids`: When set, only AAGUIDs in this list are accepted. When `None`, every
          AAGUID is allowed unless it appears in `rejected_aaguids`.
        `rejected_aaguids`: AAGUIDs that are always rejected (e.g. recalled device batches).
        `allowed_signature_algs`: COSE algorithm IDs accepted in the attestation statement and on
          the attestation certificate's signature algorithm. Defaults to every supported COSE alg.
        `allow_self_attestation`: Whether self attestation (an attestation statement without an
          `x5c` chain) is accepted for this format.
    """

    pem_root_certs_bytes: List[bytes] = field(default_factory=list)
    pem_intermediate_certs_bytes: List[bytes] = field(default_factory=list)
    allowed_aaguids: Optional[List[str]] = None
    rejected_aaguids: List[str] = field(default_factory=list)
    allowed_signature_algs: Optional[List[COSEAlgorithmIdentifier]] = None
    allow_self_attestation: bool = False


@dataclass
class AttestationTrustPolicy:
    """A reusable, explicitly enabled attestation trust policy.

    Pass an instance as the `attestation_trust_policy` argument of
    `verify_registration_response()` to opt in to policy enforcement. Roots and intermediates are
    scoped per attestation format so that a root trusted for one format can never validate a
    statement claiming another format.

    Attributes:
        `format_policies`: Per-format trust settings keyed by `AttestationFormat`.
        `allow_none_attestation`: Whether `"none"` attestation statements may be accepted.
        `allow_self_attestation`: Default self-attestation setting for formats without an explicit
          `FormatAttestationPolicy`; per-format settings take precedence when a format policy exists.
    """

    format_policies: Mapping[AttestationFormat, FormatAttestationPolicy] = field(
        default_factory=dict
    )
    allow_none_attestation: bool = False
    allow_self_attestation: bool = False

    def format_policy(self, fmt: AttestationFormat) -> Optional[FormatAttestationPolicy]:
        return self.format_policies.get(fmt)


def _raise(reason: AttestationRejectionReason, message: str) -> None:
    raise AttestationTrustPolicyError(reason, message)


def _check_aaguid(
    fmt_policy: FormatAttestationPolicy,
    aaguid: str,
) -> None:
    if aaguid in fmt_policy.rejected_aaguids:
        _raise(
            AttestationRejectionReason.AAGUID_REJECTED,
            f'AAGUID "{aaguid}" is on the attestation rejection list',
        )

    if fmt_policy.allowed_aaguids is not None and aaguid not in fmt_policy.allowed_aaguids:
        _raise(
            AttestationRejectionReason.AAGUID_REJECTED,
            f'AAGUID "{aaguid}" is not on the attestation allow-list',
        )


def _allowed_algs(
    fmt_policy: FormatAttestationPolicy,
) -> List[COSEAlgorithmIdentifier]:
    return fmt_policy.allowed_signature_algs or _DEFAULT_ALLOWED_SIGNATURE_ALGS


def _cert_sig_alg_matches_cose(
    leaf_cert: x509.Certificate,
    allowed_algs: List[COSEAlgorithmIdentifier],
) -> bool:
    oid = leaf_cert.signature_algorithm_oid
    if oid not in _CERT_SIGNATURE_OID_TO_COSE:
        return False

    mapped_alg = _CERT_SIGNATURE_OID_TO_COSE[oid]
    if mapped_alg is not None:
        return mapped_alg in allowed_algs

    # RSASSA-PSS: the OID is shared, so compare the certificate's hash algorithm
    if leaf_cert.signature_hash_algorithm is None:
        return False
    pss_alg = _RSA_PSS_HASH_TO_COSE.get(leaf_cert.signature_hash_algorithm.name)
    return pss_alg is not None and pss_alg in allowed_algs


def _check_signature_algorithm(
    fmt_policy: FormatAttestationPolicy,
    statement_alg: Optional[COSEAlgorithmIdentifier],
    leaf_cert: x509.Certificate,
) -> None:
    allowed_algs = _allowed_algs(fmt_policy)

    if statement_alg not in allowed_algs:
        _raise(
            AttestationRejectionReason.SIGNATURE_ALGORITHM_REJECTED,
            f"Attestation statement signature algorithm {statement_alg} is not permitted "
            "by the trust policy",
        )

    if not _cert_sig_alg_matches_cose(leaf_cert, allowed_algs):
        _raise(
            AttestationRejectionReason.SIGNATURE_ALGORITHM_REJECTED,
            "Attestation certificate signature algorithm is not permitted by the trust policy",
        )


def _classify_chain_failure(exc: InvalidCertificateChain) -> AttestationRejectionReason:
    message = str(exc)
    if "expired" in message or "not yet valid" in message:
        return AttestationRejectionReason.CERTIFICATE_EXPIRED
    if "key usage" in message.lower() or "digital signature" in message.lower():
        return AttestationRejectionReason.CERTIFICATE_KEY_USAGE
    if "basic constraints" in message.lower():
        return AttestationRejectionReason.CERTIFICATE_BASIC_CONSTRAINTS
    if "TRUST_ROOT_MISSING" in message:
        return AttestationRejectionReason.TRUST_ROOT_MISSING
    if "CHAIN_INCOMPLETE" in message:
        return AttestationRejectionReason.CERTIFICATE_CHAIN_INCOMPLETE
    if "No trusted root" in message or "not a configured root" in message:
        return AttestationRejectionReason.TRUST_ROOT_MISSING
    return AttestationRejectionReason.CERTIFICATE_CHAIN_INVALID


def apply_attestation_trust_policy(
    *,
    policy: AttestationTrustPolicy,
    fmt: AttestationFormat,
    aaguid: str,
    x5c: Optional[List[bytes]],
    statement_alg: Optional[COSEAlgorithmIdentifier],
) -> None:
    """Enforce an explicitly enabled :class:`AttestationTrustPolicy` against a response.

    Called by `verify_registration_response()` before the registration result is returned. A
    rejection raises :class:`AttestationTrustPolicyError`, whose `reason` attribute carries a
    stable audit code. Full certificate contents are never included in error messages.
    """
    fmt_policy = policy.format_policy(fmt)
    if fmt_policy is None:
        _raise(
            AttestationRejectionReason.FORMAT_UNSUPPORTED,
            f'Attestation format "{fmt}" is not enabled by the attestation trust policy',
        )

    _check_aaguid(fmt_policy, aaguid)

    if fmt == AttestationFormat.NONE:
        if not policy.allow_none_attestation:
            _raise(
                AttestationRejectionReason.NONE_ATTESTATION_REJECTED,
                '"none" attestation is not enabled by the attestation trust policy',
            )
        # A "none" statement never carries a chain; nothing else to check
        return

    if not x5c:
        # No x5c means the authenticator used self attestation
        allows_self = fmt_policy.allow_self_attestation or policy.allow_self_attestation
        if not allows_self:
            _raise(
                AttestationRejectionReason.SELF_ATTESTATION_REJECTED,
                "Self attestation is not enabled by the attestation trust policy",
            )
        # Self attestation has no certificate chain to validate; the statement signature is
        # still verified independently by the format-specific verifier.
        if statement_alg not in _allowed_algs(fmt_policy):
            _raise(
                AttestationRejectionReason.SIGNATURE_ALGORITHM_REJECTED,
                f"Attestation statement signature algorithm {statement_alg} is not permitted "
                "by the trust policy",
            )
        return

    try:
        leaf_cert = validate_policy_certificate_chain(
            x5c=x5c,
            pem_root_certs_bytes=fmt_policy.pem_root_certs_bytes,
            pem_intermediate_certs_bytes=fmt_policy.pem_intermediate_certs_bytes,
        )
    except InvalidCertificateChain as exc:
        reason = _classify_chain_failure(exc)
        raise AttestationTrustPolicyError(reason, str(exc)) from exc

    _check_signature_algorithm(fmt_policy, statement_alg, leaf_cert)
