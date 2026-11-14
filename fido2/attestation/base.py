# Copyright (c) 2018 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

from __future__ import annotations

import abc
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum, IntEnum, unique
from functools import wraps
from typing import Any, Collection, Mapping, Sequence, cast

from cryptography import x509
from cryptography.exceptions import InvalidSignature as _InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ObjectIdentifier

from ..webauthn import Aaguid, AttestationObject, AuthenticatorData

# Default structural limits for certificate chain validation.
DEFAULT_MAX_CERTIFICATES = 5
DEFAULT_MAX_CHAIN_DEPTH = 4
DEFAULT_MAX_CHAIN_BYTES = 65536


class InvalidAttestation(Exception):
    """Base exception for attestation-related errors."""


class InvalidData(InvalidAttestation):
    """Attestation contains invalid data."""


class InvalidSignature(InvalidAttestation):
    """The signature of the attestation could not be verified."""


class UntrustedAttestation(InvalidAttestation):
    """The CA of the attestation is not trusted."""


@unique
class AttestationFailureStage(str, Enum):
    """Auditable stages of the layered attestation policy.

    Each attestation rejection is tagged with the stage at which the
    decision was made, so that failures can be logged and audited without
    inspecting (or leaking) certificate contents.
    """

    FORMAT = "format"  # Unknown/unsupported attestation format
    STATEMENT = "statement"  # Attestation statement data/signature invalid
    CHAIN = "chain"  # Chain structure, limits or signature verification
    TRUST_ANCHOR = "trust_anchor"  # No anchor in the explicit trust store
    KEY_USAGE = "key_usage"  # Leaf key usage / EKU not acceptable
    VALIDITY = "validity"  # Certificate expired or not yet valid
    AAGUID = "aaguid"  # AAGUID not in the policy whitelist
    POLICY = "policy"  # Attestation type or other policy constraint


class AttestationPolicyError(UntrustedAttestation):
    """Attestation rejected by the layered policy.

    Carries the failure stage for audit purposes. The message never
    includes certificate contents, only positional/structural details.
    """

    def __init__(self, stage: AttestationFailureStage, message: str):
        super().__init__(f"Attestation rejected at stage {stage.value}: {message}")
        self.stage = stage


class UnsupportedType(InvalidAttestation):
    """The attestation format is not supported."""

    def __init__(self, auth_data, fmt=None):
        super().__init__(
            f'Attestation format "{fmt}" is not supported'
            if fmt
            else "This attestation format is not supported!"
        )
        self.auth_data = auth_data
        self.fmt = fmt


@unique
class AttestationType(IntEnum):
    """Supported attestation types."""

    BASIC = 1
    SELF = 2
    ATT_CA = 3
    ANON_CA = 4
    NONE = 0


@unique
class AttestationOutcome(str, Enum):
    """Outcome of a layered attestation policy decision."""

    ACCEPTED = "accepted"  # Trusted attestation, credential accepted
    UNATTESTED = "unattested"  # No attestation provided, allowed by policy


@dataclass(frozen=True)
class AttestationDecision:
    """The auditable decision of the layered attestation policy.

    Contains only fingerprints (SHA-256 of DER) of the involved
    certificates, never the certificates themselves.
    """

    outcome: AttestationOutcome
    attestation_type: AttestationType
    aaguid: Aaguid | None
    chain_length: int
    leaf_fingerprint: str | None = None
    trust_anchor_fingerprint: str | None = None


@dataclass
class AttestationResult:
    """The result of verifying an attestation."""

    attestation_type: AttestationType
    trust_path: list[bytes]


def catch_builtins(f):
    """Utility decoractor to wrap common exceptions related to InvalidData."""

    @wraps(f)
    def inner(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except (ValueError, KeyError, IndexError) as e:
            raise InvalidData(e)

    return inner


@catch_builtins
def verify_x509_chain(
    chain: list[bytes],
    *,
    max_certificates: int = DEFAULT_MAX_CERTIFICATES,
    max_depth: int = DEFAULT_MAX_CHAIN_DEPTH,
    max_bytes: int = DEFAULT_MAX_CHAIN_BYTES,
) -> int:
    """Verifies a chain of certificates.

    Checks that the first item in the chain is issued by the next, and so on.
    The first item is the leaf, the last is the root.
    On cryptography versions older than 40, only RSA and ECDSA signatures are
    supported, and issuer names are not checked.

    Structural checks are performed before any signature verification:
    the chain must be non-empty, contain at least one issuer for the leaf
    (a lone self-signed certificate is rejected), and stay within the given
    limits on certificate count, chain depth and total DER size. Duplicate
    certificates (and therefore loops) are rejected.

    :param chain: The certificate chain, leaf first, trust anchor last.
    :param max_certificates: Maximum number of certificates in the chain.
    :param max_depth: Maximum number of issuer (signature) hops.
    :param max_bytes: Maximum total size of the DER certificates, in bytes.
    :return: The number of signature verifications performed.
    """
    if not chain:
        raise InvalidData("Certificate chain is empty")
    if len(chain) < 2:
        raise InvalidData("Certificate chain has no issuer for the leaf")
    if len(chain) > max_certificates:
        raise InvalidData(
            f"Certificate chain exceeds limit of {max_certificates} certificates"
        )
    if len(chain) - 1 > max_depth:
        raise InvalidData(f"Certificate chain exceeds depth limit of {max_depth}")
    if sum(len(der) for der in chain) > max_bytes:
        raise InvalidData(f"Certificate chain exceeds size limit of {max_bytes} bytes")
    if len(set(chain)) != len(chain):
        raise InvalidData("Certificate chain contains a duplicate certificate")

    certs = [x509.load_der_x509_certificate(der, default_backend()) for der in chain]
    verifications = 0
    cert = certs.pop(0)
    while certs:
        child = cert
        cert = certs.pop(0)
        try:
            if hasattr(child, "verify_directly_issued_by"):
                child.verify_directly_issued_by(cert)
                verifications += 1
                continue

            pub = cert.public_key()
            if isinstance(pub, rsa.RSAPublicKey):
                assert child.signature_hash_algorithm is not None  # noqa: S101
                pub.verify(
                    child.signature,
                    child.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    child.signature_hash_algorithm,
                )
            elif isinstance(pub, ec.EllipticCurvePublicKey):
                assert child.signature_hash_algorithm is not None  # noqa: S101
                pub.verify(
                    child.signature,
                    child.tbs_certificate_bytes,
                    ec.ECDSA(child.signature_hash_algorithm),
                )
            else:
                raise ValueError("Unsupported signature key type")
            verifications += 1
        except _InvalidSignature:
            raise InvalidSignature()
    return verifications


class Attestation(abc.ABC):
    """Implements verification of a specific attestation type."""

    @abc.abstractmethod
    def verify(
        self,
        statement: Mapping[str, Any],
        auth_data: AuthenticatorData,
        client_data_hash: bytes,
    ) -> AttestationResult:
        """Verifies attestation statement.

        :return: An AttestationResult if successful.
        """

    @staticmethod
    def for_type(fmt: str) -> type[Attestation]:
        """Get an Attestation subclass type for the given format."""
        for cls in Attestation.__subclasses__():
            if getattr(cls, "FORMAT", None) == fmt:
                return cls

        class TypedUnsupportedAttestation(UnsupportedAttestation):
            def __init__(self):
                super().__init__(fmt)

        return TypedUnsupportedAttestation


class UnsupportedAttestation(Attestation):
    def __init__(self, fmt=None):
        self.fmt = fmt

    def verify(self, statement, auth_data, client_data_hash):
        raise UnsupportedType(auth_data, self.fmt)


class NoneAttestation(Attestation):
    FORMAT = "none"

    def verify(self, statement, auth_data, client_data_hash):
        if statement != {}:
            raise InvalidData("None Attestation requires empty statement.")
        return AttestationResult(AttestationType.NONE, [])


def _validate_cert_common(cert):
    if cert.version != x509.Version.v3:
        raise InvalidData("Attestation certificate must use version 3!")

    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        if bc.value.ca:
            raise InvalidData("Attestation certificate must have CA=false!")
    except x509.ExtensionNotFound:
        raise InvalidData("Attestation certificate must have Basic Constraints!")


def _cert_validity_bounds(cert) -> tuple[datetime, datetime]:
    nb = getattr(cert, "not_valid_before_utc", None)
    if nb is not None:
        return nb, cert.not_valid_after_utc
    return (
        cert.not_valid_before.replace(tzinfo=timezone.utc),
        cert.not_valid_after.replace(tzinfo=timezone.utc),
    )


def verify_certificate_validity(
    chain: Sequence[bytes], at_time: datetime | None = None
) -> None:
    """Checks that every certificate in a chain is within its validity period.

    :param chain: The certificate chain (DER encoded), leaf first.
    :param at_time: The time to validate against, defaults to now (UTC).
        A naive datetime is interpreted as UTC.
    """
    at = at_time or datetime.now(timezone.utc)
    if at.tzinfo is None:
        at = at.replace(tzinfo=timezone.utc)
    for index, der in enumerate(chain):
        cert = x509.load_der_x509_certificate(der, default_backend())
        not_before, not_after = _cert_validity_bounds(cert)
        if at < not_before or at > not_after:
            raise AttestationPolicyError(
                AttestationFailureStage.VALIDITY,
                f"Certificate at chain index {index} is not within its validity period",
            )


def verify_leaf_key_usage(
    cert,
    required_eku_oids: Sequence[str] = (),
    require_key_usage: bool = True,
) -> None:
    """Checks Basic Constraints, Key Usage and EKU of an attestation leaf.

    The leaf must not be a CA, must (if require_key_usage) carry a Key Usage
    extension including digitalSignature, and must carry at least one of the
    required EKU OIDs, if any are configured.
    """
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        if bc.ca:
            raise AttestationPolicyError(
                AttestationFailureStage.KEY_USAGE,
                "Leaf certificate must not be a CA",
            )
    except x509.ExtensionNotFound:
        raise AttestationPolicyError(
            AttestationFailureStage.KEY_USAGE,
            "Leaf certificate has no Basic Constraints",
        )

    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        if not ku.digital_signature:
            raise AttestationPolicyError(
                AttestationFailureStage.KEY_USAGE,
                "Leaf Key Usage does not include digitalSignature",
            )
    except x509.ExtensionNotFound:
        if require_key_usage:
            raise AttestationPolicyError(
                AttestationFailureStage.KEY_USAGE,
                "Leaf certificate has no Key Usage extension",
            )

    if required_eku_oids:
        try:
            eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        except x509.ExtensionNotFound:
            raise AttestationPolicyError(
                AttestationFailureStage.KEY_USAGE,
                "Leaf certificate has no Extended Key Usage extension",
            )
        if not any(ObjectIdentifier(oid) in eku for oid in required_eku_oids):
            raise AttestationPolicyError(
                AttestationFailureStage.KEY_USAGE,
                "Leaf EKU does not include any of the required usages",
            )


def verify_leaf_san_rp_id(cert, rp_id: str) -> None:
    """Checks that any dNSName SAN of the leaf is related to the RP ID.

    Certificates without a Subject Alternative Name are accepted; any
    dNSName present must be the RP ID itself or a subdomain of it.
    """
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return
    for name in san.get_values_for_type(x509.DNSName):
        if name != rp_id and not name.endswith("." + rp_id):
            raise AttestationPolicyError(
                AttestationFailureStage.POLICY,
                "Leaf SAN dNSName is not related to the RP ID",
            )


def _default_attestations():
    return [
        cast(type[Any], cls)()
        for cls in Attestation.__subclasses__()
        if getattr(cls, "FORMAT", "none") != "none"
    ]


class AttestationVerifier(abc.ABC):
    """Base class for verifying attestation.

    Override the ca_lookup method to provide a trusted root certificate used
    to verify the trust path from the attestation.
    """

    def __init__(self, attestation_types: Sequence[Attestation] | None = None):
        self._attestation_types = attestation_types or _default_attestations()

    @abc.abstractmethod
    def ca_lookup(
        self, attestation_result: AttestationResult, auth_data: AuthenticatorData
    ) -> bytes | None:
        """Lookup a CA certificate to be used to verify a trust path.

        :param attestation_result: The result of the attestation
        :param auth_data: The AuthenticatorData from the registration
        """
        raise NotImplementedError()

    def verify_attestation(
        self, attestation_object: AttestationObject, client_data_hash: bytes
    ) -> None:
        """Verify attestation.

        :param attestation_object: dict containing attestation data.
        :param client_data_hash: SHA256 hash of the ClientData bytes.
        """
        att_verifier: Attestation = UnsupportedAttestation(attestation_object.fmt)
        for at in self._attestation_types:
            if getattr(at, "FORMAT", None) == attestation_object.fmt:
                att_verifier = at
                break
        # An unsupported format causes an exception to be thrown, which
        # includes the auth_data. The caller may choose to handle this case
        # and allow the registration.
        result = att_verifier.verify(
            attestation_object.att_stmt,
            attestation_object.auth_data,
            client_data_hash,
        )

        # "none" and "self" attestation do not establish trust in an
        # Authenticator and must never be treated as equivalent to a
        # trusted attestation.
        if result.attestation_type in (AttestationType.NONE, AttestationType.SELF):
            raise UntrustedAttestation(
                f"Attestation type {result.attestation_type.name} is not trusted"
            )
        if not result.trust_path:
            raise UntrustedAttestation("Attestation has an empty trust path")

        # Lookup CA to use for trust path verification
        ca = self.ca_lookup(result, attestation_object.auth_data)
        if not ca:
            raise UntrustedAttestation("No root found for Authenticator")

        # Validate the trust chain
        try:
            verify_x509_chain(result.trust_path + [ca])
        except InvalidSignature as e:
            raise UntrustedAttestation(e)

    def __call__(self, *args):
        """Allows passing an instance to Fido2Server as verify_attestation"""
        self.verify_attestation(*args)


@dataclass
class AttestationPolicy:
    """Layered attestation policy.

    Combines the trust anchors, AAGUID whitelist, allowed attestation types
    and certificate usage requirements into a single decision, evaluated by
    PolicyAttestationVerifier.

    :param trust_store: Explicit trust anchors (DER encoded certificates).
    :param allowed_aaguids: Whitelist of trusted AAGUIDs, or None to not
        restrict AAGUIDs.
    :param allow_none: Allow "none" attestation, resulting in an UNATTESTED
        decision rather than a trusted one.
    :param allow_self: Allow "self" attestation, resulting in an UNATTESTED
        decision rather than a trusted one.
    :param allowed_types: Trusted attestation types. Defaults to BASIC,
        ATT_CA and ANON_CA.
    :param required_eku_oids: EKU OIDs, one of which the leaf certificate
        must carry, if any are configured.
    :param rp_id: RP ID used to validate leaf SAN dNSNames, if set.
    :param require_key_usage: Require the leaf to carry a Key Usage
        extension including digitalSignature.
    :param max_certificates: Maximum number of certificates in a chain.
    :param max_chain_depth: Maximum number of issuer hops in a chain.
    :param max_chain_bytes: Maximum total DER size of a chain, in bytes.
    :param at_time: Time to validate certificate validity against,
        defaults to the current time.
    """

    trust_store: Sequence[bytes] = ()
    allowed_aaguids: Collection[bytes] | None = None
    allow_none: bool = False
    allow_self: bool = False
    allowed_types: Collection[AttestationType] | None = None
    required_eku_oids: Sequence[str] = ()
    rp_id: str | None = None
    require_key_usage: bool = True
    max_certificates: int = DEFAULT_MAX_CERTIFICATES
    max_chain_depth: int = DEFAULT_MAX_CHAIN_DEPTH
    max_chain_bytes: int = DEFAULT_MAX_CHAIN_BYTES
    at_time: datetime | None = None


class PolicyAttestationVerifier(AttestationVerifier):
    """Layered attestation verifier enforcing an AttestationPolicy.

    Verification proceeds in stages, failing fast on the first rejection:

    1. FORMAT: resolve the attestation format; unknown formats are rejected.
    2. STATEMENT: verify the attestation statement itself.
    3. POLICY: apply the attestation type policy. "none" (and "self", if
       enabled) result in an UNATTESTED decision, never a trusted one.
    4. TRUST_ANCHOR/CHAIN: verify the certificate chain against the
       explicit trust store, enforcing structural limits.
    5. KEY_USAGE/VALIDITY/AAGUID: check the leaf certificate usage, the
       validity of every certificate in the chain, and the AAGUID
       whitelist.
    6. Accept the credential, recording an AttestationDecision.

    Rejections raise AttestationPolicyError, which carries the failure
    stage for auditing and never includes certificate contents.

    :param policy: The AttestationPolicy to enforce.
    :param attestation_types: A list of Attestation types to support.
    :param rp_id: RP ID used for SAN validation, overrides policy.rp_id.
    """

    def __init__(
        self,
        policy: AttestationPolicy,
        attestation_types: Sequence[Attestation] | None = None,
        rp_id: str | None = None,
    ):
        super().__init__(attestation_types)
        if attestation_types is None:
            # The policy entry point must be able to parse "none" in order
            # to classify it as unattested rather than trusted.
            self._attestation_types = [*_default_attestations(), NoneAttestation()]
        self.policy = policy
        self.rp_id = rp_id or policy.rp_id
        self.last_decision: AttestationDecision | None = None
        self.last_verification_count = 0
        self._trust_anchors = [
            (der, x509.load_der_x509_certificate(der, default_backend()))
            for der in policy.trust_store
        ]

    def ca_lookup(
        self, attestation_result: AttestationResult, auth_data: AuthenticatorData
    ) -> bytes | None:
        anchor = self._find_anchor(attestation_result.trust_path)
        return anchor[0] if anchor else None

    def _find_anchor(self, trust_path: Sequence[bytes]) -> tuple[bytes, Any] | None:
        if not trust_path:
            return None
        try:
            issuer = x509.load_der_x509_certificate(
                trust_path[-1], default_backend()
            ).issuer
        except ValueError:
            return None
        for der, cert in self._trust_anchors:
            if der == trust_path[-1] or cert.subject == issuer:
                return der, cert
        return None

    def verify_attestation(
        self, attestation_object: AttestationObject, client_data_hash: bytes
    ) -> AttestationDecision:
        """Verify attestation against the policy.

        :param attestation_object: dict containing attestation data.
        :param client_data_hash: SHA256 hash of the ClientData bytes.
        :return: An AttestationDecision describing the outcome.
        """
        self.last_decision = None
        self.last_verification_count = 0

        # Stage 1: resolve attestation type and format
        fmt = attestation_object.fmt
        att_verifier: Attestation | None = None
        for at in self._attestation_types:
            if getattr(at, "FORMAT", None) == fmt:
                att_verifier = at
                break
        if att_verifier is None:
            raise AttestationPolicyError(
                AttestationFailureStage.FORMAT,
                f"Unsupported attestation format: {fmt}",
            )

        # Stage 2: verify the attestation statement
        try:
            result = att_verifier.verify(
                attestation_object.att_stmt,
                attestation_object.auth_data,
                client_data_hash,
            )
        except InvalidAttestation as e:
            raise AttestationPolicyError(
                AttestationFailureStage.STATEMENT, str(e)
            ) from e

        auth_data = attestation_object.auth_data
        credential_data = auth_data.credential_data
        aaguid = credential_data.aaguid if credential_data else None
        attestation_type = result.attestation_type

        # Stage 3: attestation type policy
        if attestation_type == AttestationType.NONE:
            if not self.policy.allow_none:
                raise AttestationPolicyError(
                    AttestationFailureStage.POLICY,
                    "Attestation of type NONE is not allowed by policy",
                )
            return self._decide(AttestationOutcome.UNATTESTED, attestation_type, aaguid)
        if attestation_type == AttestationType.SELF:
            if not self.policy.allow_self:
                raise AttestationPolicyError(
                    AttestationFailureStage.POLICY,
                    "Attestation of type SELF is not allowed by policy",
                )
            return self._decide(AttestationOutcome.UNATTESTED, attestation_type, aaguid)
        allowed_types = self.policy.allowed_types or {
            AttestationType.BASIC,
            AttestationType.ATT_CA,
            AttestationType.ANON_CA,
        }
        if attestation_type not in allowed_types:
            raise AttestationPolicyError(
                AttestationFailureStage.POLICY,
                f"Attestation type {attestation_type.name} is not allowed by policy",
            )
        if not result.trust_path:
            raise AttestationPolicyError(
                AttestationFailureStage.CHAIN,
                "Attestation has an empty trust path",
            )

        # Stage 4: verify the certificate chain to the explicit trust store
        anchor = self._find_anchor(result.trust_path)
        if anchor is None:
            raise AttestationPolicyError(
                AttestationFailureStage.TRUST_ANCHOR,
                "No trusted root found for the attestation chain",
            )
        chain = list(result.trust_path)
        if chain[-1] != anchor[0]:
            chain.append(anchor[0])
        try:
            self.last_verification_count = verify_x509_chain(
                chain,
                max_certificates=self.policy.max_certificates,
                max_depth=self.policy.max_chain_depth,
                max_bytes=self.policy.max_chain_bytes,
            )
        except InvalidAttestation as e:
            raise AttestationPolicyError(AttestationFailureStage.CHAIN, str(e)) from e

        # Stage 5: leaf usage, validity and AAGUID whitelist
        leaf = x509.load_der_x509_certificate(chain[0], default_backend())
        verify_leaf_key_usage(
            leaf, self.policy.required_eku_oids, self.policy.require_key_usage
        )
        verify_certificate_validity(chain, self.policy.at_time)
        if self.rp_id:
            verify_leaf_san_rp_id(leaf, self.rp_id)
        if self.policy.allowed_aaguids is not None:
            allowed = {bytes(a) for a in self.policy.allowed_aaguids}
            if aaguid is None or bytes(aaguid) not in allowed:
                raise AttestationPolicyError(
                    AttestationFailureStage.AAGUID,
                    "AAGUID is not in the policy whitelist",
                )

        # Stage 6: accept the credential
        return self._decide(
            AttestationOutcome.ACCEPTED,
            attestation_type,
            aaguid,
            chain_length=len(chain),
            leaf_fingerprint=hashlib.sha256(chain[0]).hexdigest(),
            trust_anchor_fingerprint=hashlib.sha256(chain[-1]).hexdigest(),
        )

    def _decide(
        self,
        outcome: AttestationOutcome,
        attestation_type: AttestationType,
        aaguid: Aaguid | None,
        chain_length: int = 0,
        leaf_fingerprint: str | None = None,
        trust_anchor_fingerprint: str | None = None,
    ) -> AttestationDecision:
        decision = AttestationDecision(
            outcome=outcome,
            attestation_type=attestation_type,
            aaguid=aaguid,
            chain_length=chain_length,
            leaf_fingerprint=leaf_fingerprint,
            trust_anchor_fingerprint=trust_anchor_fingerprint,
        )
        self.last_decision = decision
        return decision
