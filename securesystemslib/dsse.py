"""Dead Simple Signing Envelope"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
from collections.abc import Iterable, Mapping
from enum import StrEnum
from typing import Any

from securesystemslib import exceptions
from securesystemslib._internal.utils import b64dec, b64enc, make_hashable
from securesystemslib.signer import Key, Signature, Signer

logger = logging.getLogger(__name__)

APPROVED_CONCLUSIONS = frozenset({"approved", "accepted", "valid", "verified"})
"""Review conclusions that may be carried over when evidence is sufficient."""


class Envelope:
    """DSSE Envelope to provide interface for signing arbitrary data.

    Attributes:
        payload: Arbitrary byte sequence of serialized body.
        payload_type: string that identifies how to interpret payload.
        signatures: dict of Signature key id and Signatures.

    """

    def __init__(
        self,
        payload: bytes,
        payload_type: str,
        signatures: dict[str, Signature],
    ):
        self.payload = payload
        self.payload_type = payload_type
        self.signatures = signatures

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Envelope):
            return False

        return (
            self.payload == other.payload
            and self.payload_type == other.payload_type
            and self.signatures == other.signatures
        )

    def __hash__(self) -> int:
        return hash(
            (
                self.payload,
                self.payload_type,
                make_hashable(self.signatures),
            )
        )

    @classmethod
    def from_dict(cls, data: dict) -> Envelope:
        """Creates a DSSE Envelope from its JSON/dict representation.

        Arguments:
            data: A dict containing a valid payload, payloadType and signatures

        Raises:
            KeyError: If any of the "payload", "payloadType" and "signatures"
                fields are missing from the "data".

            FormatError: If signature in "signatures" is incorrect.

        Returns:
            A "Envelope" instance.
        """

        payload = b64dec(data["payload"])
        payload_type = data["payloadType"]

        signatures = {}
        for signature in data["signatures"]:
            signature["sig"] = b64dec(signature["sig"]).hex()
            sig = Signature.from_dict(signature)
            if sig.keyid in signatures:
                raise ValueError(f"Multiple signatures found for keyid {sig.keyid}")
            signatures[sig.keyid] = sig
        return cls(payload, payload_type, signatures)

    def to_dict(self) -> dict:
        """Returns the JSON-serializable dictionary representation of self."""

        signatures = []
        for signature in self.signatures.values():
            sig_dict = signature.to_dict()
            sig_dict["sig"] = b64enc(bytes.fromhex(sig_dict["sig"]))
            signatures.append(sig_dict)

        return {
            "payload": b64enc(self.payload),
            "payloadType": self.payload_type,
            "signatures": signatures,
        }

    def pae(self) -> bytes:
        """Pre-Auth-Encoding byte sequence of self."""

        payload_type = self.payload_type.encode("utf-8")
        return b"DSSEv1 %d %b %d %b" % (
            len(payload_type),
            payload_type,
            len(self.payload),
            self.payload,
        )

    def digest(self) -> str:
        """Return a SHA-256 hex digest of the canonical envelope.

        The digest binds a review record to the exact payload, payload type
        and signatures it was written about. Signature entries are sorted by
        key id so that the digest does not depend on dict insertion order.

        Returns:
            Hex encoded SHA-256 digest.
        """

        return _canonical_envelope_digest(self)

    def sign(self, signer: Signer) -> Signature:
        """Sign the payload and create the signature.

        Arguments:
            signer: A "Signer" class instance.

        Returns:
            A "Signature" instance.
        """

        signature = signer.sign(self.pae())
        self.signatures[signature.keyid] = signature

        return signature

    def verify(self, keys: list[Key], threshold: int) -> dict[str, Key]:
        """Verify the payload with the provided Keys.

        Arguments:
            keys: A list of public keys to verify the signatures.
            threshold: Number of signatures needed to pass the verification.

        Raises:
            ValueError: If "threshold" is not valid.
            VerificationError: If the enclosed signatures do not pass the
                verification.

        Note:
            Mandating keyid in signatures and matching them with keyid of Key
            in order to consider them for verification, is not DSSE spec
            compliant (Issue #416).

        Returns:
            A dict of the threshold of unique public keys that verified a
            signature.
        """

        accepted_keys = {}
        pae = self.pae()

        # checks for threshold value.
        if threshold <= 0:
            raise ValueError("Threshold must be greater than 0")

        if len(keys) < threshold:
            raise ValueError("Number of keys can't be less than threshold")

        for signature in self.signatures.values():
            for key in keys:
                # If Signature keyid doesn't match with Key, skip.
                if not key.keyid == signature.keyid:
                    continue

                # If a key verifies the signature, we exit and use the result.
                try:
                    key.verify_signature(signature, pae)
                    accepted_keys[key.keyid] = key
                    break
                except exceptions.UnverifiedSignatureError:
                    continue

            # Break, if amount of accepted_keys are more than threshold.
            if len(accepted_keys) >= threshold:
                break

        if threshold > len(accepted_keys):
            raise exceptions.VerificationError(
                "Accepted signatures do not match threshold,"
                f" Found: {len(accepted_keys)}, Expected {threshold}"
            )

        return accepted_keys


class MigrationDecision(StrEnum):
    """Outcome of migrating a historical DSSE review record."""

    REVERIFIED = "reverified"
    """The envelope was cryptographically verified in the new environment."""

    REUSE_APPROVED_EVIDENCE = "reuse_approved_evidence"
    """Re-verification was unavailable, but trusted prior evidence was reused."""

    RECHECK = "recheck"
    """The conclusion does not have enough trusted evidence and must be redone."""


class VerificationFailure(StrEnum):
    """Classification of why a record could not be carried over as-is."""

    MALFORMED_ENVELOPE = "malformed_envelope"
    ENVELOPE_MISMATCH = "envelope_mismatch"
    UNSUPPORTED_CONCLUSION = "unsupported_conclusion"
    MISSING_PUBLIC_KEY = "missing_public_key"
    UNSUPPORTED_ALGORITHM = "unsupported_algorithm"
    ALGORITHM_PARAMETER_MISMATCH = "algorithm_parameter_mismatch"
    UNSUPPORTED_LIBRARY = "unsupported_library"
    KEY_MISMATCH = "key_mismatch"
    INVALID_SIGNATURE = "invalid_signature"
    VERIFICATION_ERROR = "verification_error"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"

    UNTRUSTED_REVIEW_SOURCE = "untrusted_review_source"
    LEGACY_EVIDENCE_DISABLED = "legacy_evidence_disabled"


# Failures caused by the new environment not being able to verify rather than
# by positive evidence that the record itself is bad. Only these failures may
# fall back to approved historical evidence.
_REVERIFICATION_UNAVAILABLE_FAILURES = frozenset(
    {
        VerificationFailure.MISSING_PUBLIC_KEY,
        VerificationFailure.UNSUPPORTED_ALGORITHM,
        VerificationFailure.ALGORITHM_PARAMETER_MISMATCH,
        VerificationFailure.UNSUPPORTED_LIBRARY,
    }
)

# Positive failures that always require a fresh review, even if the new
# environment is also missing capabilities.
_CRYPTOGRAPHIC_FAILURES = frozenset(
    {
        VerificationFailure.MALFORMED_ENVELOPE,
        VerificationFailure.ENVELOPE_MISMATCH,
        VerificationFailure.UNSUPPORTED_CONCLUSION,
        VerificationFailure.KEY_MISMATCH,
        VerificationFailure.INVALID_SIGNATURE,
        VerificationFailure.VERIFICATION_ERROR,
        VerificationFailure.INSUFFICIENT_EVIDENCE,
    }
)

# Most actionable failure first when a result has several classifications.
_FAILURE_PRIORITY = (
    VerificationFailure.MALFORMED_ENVELOPE,
    VerificationFailure.ENVELOPE_MISMATCH,
    VerificationFailure.INVALID_SIGNATURE,
    VerificationFailure.VERIFICATION_ERROR,
    VerificationFailure.KEY_MISMATCH,
    VerificationFailure.INSUFFICIENT_EVIDENCE,
    VerificationFailure.UNSUPPORTED_CONCLUSION,
    VerificationFailure.MISSING_PUBLIC_KEY,
    VerificationFailure.UNSUPPORTED_ALGORITHM,
    VerificationFailure.ALGORITHM_PARAMETER_MISMATCH,
    VerificationFailure.UNSUPPORTED_LIBRARY,
    VerificationFailure.UNTRUSTED_REVIEW_SOURCE,
    VerificationFailure.LEGACY_EVIDENCE_DISABLED,
)

_MISSING = object()


def _get(
    data: Mapping[str, Any],
    *names: str,
    default: Any = _MISSING,
) -> Any:
    """Return the first present alias from data, or default."""

    for name in names:
        if name in data:
            return data[name]
    if default is _MISSING:
        raise KeyError(names[0])
    return default


def _canonical_envelope_digest(envelope: Envelope) -> str:
    """Return a SHA-256 hex digest of a canonicalized envelope."""

    data = envelope.to_dict()
    data["signatures"] = sorted(
        data["signatures"], key=lambda signature: signature["keyid"]
    )
    canonical = json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class SigningAlgorithm:
    """Signing algorithm and scheme parameters.

    Args:
        keytype: Key type, for example ``ed25519`` or ``rsa``.
        scheme: Signature scheme, for example ``ed25519`` or
            ``rsassa-pss-sha256``.
        parameters: Scheme-specific parameters, for example ``{"hash":
            "sha256"}`` or ``{"salt_length": 32}``. An empty mapping means that
            no additional parameters are recorded.
    """

    def __init__(
        self,
        keytype: str,
        scheme: str,
        parameters: Mapping[str, Any] | None = None,
    ):
        if not isinstance(keytype, str) or not isinstance(scheme, str):
            raise TypeError("keytype and scheme must be strings")
        self.keytype = keytype
        self.scheme = scheme
        self.parameters: dict[str, Any] = dict(parameters or {})

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, SigningAlgorithm):
            return False
        return (
            self.keytype == other.keytype
            and self.scheme == other.scheme
            and self.parameters == other.parameters
        )

    def __hash__(self) -> int:
        return hash((self.keytype, self.scheme, make_hashable(self.parameters)))

    def __repr__(self) -> str:
        return (
            f"SigningAlgorithm({self.keytype!r}, {self.scheme!r}, {self.parameters!r})"
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SigningAlgorithm:
        """Create a SigningAlgorithm from its serialized representation."""

        return cls(
            _get(data, "keytype"),
            _get(data, "scheme"),
            _get(data, "parameters", default=None),
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of self."""

        return {
            "keytype": self.keytype,
            "scheme": self.scheme,
            "parameters": dict(self.parameters),
        }


def _coerce_algorithm(
    value: SigningAlgorithm | Mapping[str, Any] | tuple[str, str],
) -> SigningAlgorithm:
    """Return value as a SigningAlgorithm."""

    if isinstance(value, SigningAlgorithm):
        return value
    if isinstance(value, Mapping):
        return SigningAlgorithm.from_dict(value)
    if isinstance(value, tuple) and len(value) == 2:  # noqa: PLR2004
        return SigningAlgorithm(value[0], value[1])
    raise TypeError(f"Unsupported signing algorithm specification: {value!r}")


def _coerce_failure(
    value: VerificationFailure | str | None,
) -> VerificationFailure | None:
    """Return value as a VerificationFailure."""

    if value is None or isinstance(value, VerificationFailure):
        return value
    return VerificationFailure(value)


def _parameters_match(
    required: Mapping[str, Any],
    supported: Mapping[str, Any],
) -> bool:
    """Return True if the supported parameters allow the required ones.

    An empty supported mapping acts as a wildcard. Otherwise every parameter
    recorded with the historical review must be declared with the same value
    by the new environment.
    """

    if not supported:
        return True
    return all(
        name in supported and supported[name] == value
        for name, value in required.items()
    )


class EnvironmentCapabilities:
    """Explicit statement of what a new verification backend can do.

    Args:
        supported_algorithms: Signing algorithms the backend can verify,
            including any scheme parameters it supports.
        public_keys: Public key material available to the backend.
        trusted_review_sources: Identifiers of historical review sources whose
            approvals may be reused.
        allow_legacy_evidence: Whether approved historical evidence may be
            reused when cryptographic re-verification is unavailable.
        threshold: Minimum number of accepted signatures for re-verification.

    Raises:
        TypeError: If an argument has an unexpected type.
        ValueError: If threshold is not positive, or if duplicate, conflicting
            algorithm or key capabilities are declared.
    """

    def __init__(
        self,
        supported_algorithms: Iterable[
            SigningAlgorithm | Mapping[str, Any] | tuple[str, str]
        ],
        public_keys: Iterable[Key] = (),
        trusted_review_sources: Iterable[str] = (),
        allow_legacy_evidence: bool = False,
        threshold: int = 1,
    ):
        if isinstance(threshold, bool) or not isinstance(threshold, int):
            raise TypeError("threshold must be an integer")
        if threshold <= 0:
            raise ValueError("threshold must be greater than 0")

        algorithms: dict[tuple[str, str], dict[str, Any]] = {}
        for value in supported_algorithms:
            spec = _coerce_algorithm(value)
            identifier = (spec.keytype, spec.scheme)
            if identifier in algorithms and algorithms[identifier] != spec.parameters:
                raise ValueError(
                    f"Conflicting capabilities for {spec.keytype}/{spec.scheme}"
                )
            algorithms[identifier] = spec.parameters
        self.supported_algorithms = algorithms

        keys: dict[str, Key] = {}
        for key in public_keys:
            if not isinstance(key, Key):
                raise TypeError("public_keys must contain Key instances")
            if key.keyid in keys and keys[key.keyid] != key:
                raise ValueError(f"Conflicting public keys for {key.keyid}")
            keys[key.keyid] = key
        self.public_keys = keys

        trusted_sources = frozenset(trusted_review_sources)
        if not all(isinstance(source, str) for source in trusted_sources):
            raise TypeError("trusted_review_sources must contain strings")
        self.trusted_review_sources = trusted_sources
        self.allow_legacy_evidence = bool(allow_legacy_evidence)
        self.threshold = threshold

    def supports(self, keytype: str, scheme: str) -> bool:
        """Return True if the backend declares support for the algorithm."""

        return (keytype, scheme) in self.supported_algorithms

    def algorithm_parameters(self, keytype: str, scheme: str) -> dict[str, Any] | None:
        """Return declared parameters for a supported algorithm, if any."""

        return self.supported_algorithms.get((keytype, scheme))

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> EnvironmentCapabilities:
        """Create capabilities from their serialized representation."""

        algorithms = [
            _coerce_algorithm(algorithm)
            for algorithm in _get(
                data,
                "supportedAlgorithms",
                "supported_algorithms",
                default=(),
            )
        ]

        public_keys: list[Key] = []
        for entry in _get(data, "publicKeys", "public_keys", default=()):
            key_data = dict(entry)
            keyid = key_data.pop("keyid")
            public_keys.append(Key.from_dict(keyid, key_data))

        return cls(
            algorithms,
            public_keys,
            trusted_review_sources=_get(
                data,
                "trustedReviewSources",
                "trusted_review_sources",
                default=(),
            ),
            allow_legacy_evidence=bool(
                _get(
                    data,
                    "allowLegacyEvidence",
                    "allow_legacy_evidence",
                    default=False,
                )
            ),
            threshold=int(_get(data, "threshold", default=1)),
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of self."""

        return {
            "supportedAlgorithms": [
                SigningAlgorithm(keytype, scheme, parameters).to_dict()
                for (keytype, scheme), parameters in sorted(
                    self.supported_algorithms.items()
                )
            ],
            "publicKeys": [
                {"keyid": key.keyid, **key.to_dict()}
                for key in self.public_keys.values()
            ],
            "trustedReviewSources": sorted(self.trusted_review_sources),
            "allowLegacyEvidence": self.allow_legacy_evidence,
            "threshold": self.threshold,
        }


class ReviewRecord:
    """A historical review conclusion for a DSSE envelope.

    Args:
        record_id: Identifier of the historical record.
        envelope: Original DSSE envelope, either as an Envelope or as its
            serialized mapping.
        conclusion: Recorded conclusion, for example ``approved``.
        review_source: Identifier of the backend or process that performed the
            original review.
        evidence_keyids: Key ids whose signatures were accepted as evidence for
            the conclusion.
        signing_algorithms: Signing algorithm and parameters recorded per key
            id. Missing entries fall back to the public key itself.
        envelope_digest: Optional digest binding the record to the envelope.
        prior_failure: Optional failure classification recorded by the old
            verifier.

    Raises:
        TypeError: If an argument has an unexpected type.
        ValueError: If a failure classification is unknown.
    """

    def __init__(  # noqa: PLR0913
        self,
        record_id: str,
        envelope: Envelope | Mapping[str, Any],
        conclusion: str,
        review_source: str = "",
        evidence_keyids: Iterable[str] = (),
        signing_algorithms: Mapping[
            str, SigningAlgorithm | Mapping[str, Any] | tuple[str, str]
        ]
        | None = None,
        envelope_digest: str | None = None,
        prior_failure: VerificationFailure | str | None = None,
    ):
        if not isinstance(record_id, str):
            raise TypeError("record_id must be a string")
        if isinstance(envelope, Mapping):
            envelope = Envelope.from_dict(copy.deepcopy(dict(envelope)))
        if not isinstance(envelope, Envelope):
            raise TypeError("envelope must be an Envelope or a mapping")
        if not isinstance(conclusion, str):
            raise TypeError("conclusion must be a string")
        if not isinstance(review_source, str):
            raise TypeError("review_source must be a string")
        if envelope_digest is not None and not isinstance(envelope_digest, str):
            raise TypeError("envelope_digest must be a string or None")

        self.record_id = record_id
        self.envelope = envelope
        self.conclusion = conclusion
        self.review_source = review_source
        evidence = frozenset(evidence_keyids)
        if not all(isinstance(keyid, str) for keyid in evidence):
            raise TypeError("evidence_keyids must contain strings")
        algorithms: dict[str, SigningAlgorithm] = {}
        for keyid, value in (signing_algorithms or {}).items():
            if not isinstance(keyid, str):
                raise TypeError("signing_algorithms key ids must be strings")
            algorithms[keyid] = _coerce_algorithm(value)
        self.evidence_keyids = evidence
        self.signing_algorithms = algorithms
        self.envelope_digest = envelope_digest
        self.prior_failure = _coerce_failure(prior_failure)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ReviewRecord:
        """Create a ReviewRecord from its serialized representation."""

        return cls(
            _get(data, "recordId", "record_id"),
            _get(data, "envelope"),
            _get(data, "conclusion"),
            review_source=_get(data, "reviewSource", "review_source", default=""),
            evidence_keyids=_get(
                data,
                "evidenceKeyids",
                "evidence_keyids",
                default=(),
            ),
            signing_algorithms=_get(
                data,
                "signingAlgorithms",
                "signing_algorithms",
                default=None,
            ),
            envelope_digest=_get(
                data,
                "envelopeDigest",
                "envelope_digest",
                default=None,
            ),
            prior_failure=_get(
                data,
                "priorFailure",
                "prior_failure",
                default=None,
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of self."""

        return {
            "recordId": self.record_id,
            "envelope": self.envelope.to_dict(),
            "conclusion": self.conclusion,
            "reviewSource": self.review_source,
            "evidenceKeyids": sorted(self.evidence_keyids),
            "signingAlgorithms": {
                keyid: algorithm.to_dict()
                for keyid, algorithm in self.signing_algorithms.items()
            },
            "envelopeDigest": self.envelope_digest,
            "priorFailure": (self.prior_failure.value if self.prior_failure else None),
        }


class MigrationAssessment:
    """Assessment of a single historical review record.

    Attributes:
        record_id: Identifier of the assessed record.
        decision: MigrationDecision for the record.
        failures: All observed failure classifications.
        failure: Most actionable failure, if any.
        verified_keyids: Key ids verified in the new environment.
        reused_keyids: Historical key ids whose approved evidence was reused.
        prior_failure: Failure classification recorded by the old verifier.
        reuse_blocked_by: Why legacy evidence was not reused, if applicable.
        reason: Human-readable summary.
    """

    def __init__(  # noqa: PLR0913
        self,
        record_id: str,
        decision: MigrationDecision,
        failures: Iterable[VerificationFailure] = (),
        verified_keyids: Iterable[str] = (),
        reused_keyids: Iterable[str] = (),
        prior_failure: VerificationFailure | None = None,
        reuse_blocked_by: VerificationFailure | None = None,
        reason: str = "",
    ):
        self.record_id = record_id
        self.decision = decision
        unique_failures: list[VerificationFailure] = []
        for failure in failures:
            if failure not in unique_failures:
                unique_failures.append(failure)
        self.failures = tuple(unique_failures)
        self.verified_keyids = frozenset(verified_keyids)
        self.reused_keyids = frozenset(reused_keyids)
        self.prior_failure = prior_failure
        self.reuse_blocked_by = reuse_blocked_by
        self.reason = reason

    @property
    def usable(self) -> bool:
        """Return True if the conclusion can continue to be used."""

        return self.decision is not MigrationDecision.RECHECK

    @property
    def failure(self) -> VerificationFailure | None:
        """Return the most actionable failure classification."""

        for candidate in _FAILURE_PRIORITY:
            if candidate in self.failures:
                return candidate
        return self.failures[0] if self.failures else None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of self."""

        return {
            "recordId": self.record_id,
            "decision": self.decision.value,
            "usable": self.usable,
            "failure": self.failure.value if self.failure else None,
            "failures": [failure.value for failure in self.failures],
            "verifiedKeyids": sorted(self.verified_keyids),
            "reusedKeyids": sorted(self.reused_keyids),
            "priorFailure": (self.prior_failure.value if self.prior_failure else None),
            "reuseBlockedBy": (
                self.reuse_blocked_by.value if self.reuse_blocked_by else None
            ),
            "reason": self.reason,
        }


class MigrationReport:
    """Collection of migration assessments for historical review records."""

    def __init__(self, assessments: Iterable[MigrationAssessment]):
        self.assessments = tuple(assessments)

    @property
    def reusable(self) -> tuple[MigrationAssessment, ...]:
        """Assessments whose conclusions can continue to be used."""

        return tuple(assessment for assessment in self.assessments if assessment.usable)

    @property
    def recheck(self) -> tuple[MigrationAssessment, ...]:
        """Assessments that must be reviewed again."""

        return tuple(
            assessment for assessment in self.assessments if not assessment.usable
        )

    def by_id(self) -> dict[str, MigrationAssessment]:
        """Return assessments keyed by record id."""

        return {assessment.record_id: assessment for assessment in self.assessments}

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of self."""

        return {
            "records": [assessment.to_dict() for assessment in self.assessments],
            "reusable": [assessment.record_id for assessment in self.reusable],
            "recheck": [assessment.record_id for assessment in self.recheck],
        }


def _check_signature(  # noqa: PLR0911
    record: ReviewRecord,
    capabilities: EnvironmentCapabilities,
    keyid: str,
) -> tuple[VerificationFailure | None, bool]:
    """Verify one signature and return (failure, accepted)."""

    signature = record.envelope.signatures[keyid]
    key = capabilities.public_keys.get(keyid)
    if key is None:
        return VerificationFailure.MISSING_PUBLIC_KEY, False

    spec = record.signing_algorithms.get(keyid)
    if spec is None:
        spec = SigningAlgorithm(key.keytype, key.scheme)

    if not capabilities.supports(spec.keytype, spec.scheme):
        return VerificationFailure.UNSUPPORTED_ALGORITHM, False

    supported_parameters = capabilities.algorithm_parameters(spec.keytype, spec.scheme)
    if not _parameters_match(spec.parameters, supported_parameters or {}):
        return VerificationFailure.ALGORITHM_PARAMETER_MISMATCH, False

    if (key.keytype, key.scheme) != (spec.keytype, spec.scheme):
        return VerificationFailure.KEY_MISMATCH, False

    try:
        key.verify_signature(signature, record.envelope.pae())
    except exceptions.VerificationError as error:
        if isinstance(error.__cause__, exceptions.UnsupportedLibraryError):
            return VerificationFailure.UNSUPPORTED_LIBRARY, False
        return VerificationFailure.VERIFICATION_ERROR, False
    except exceptions.UnverifiedSignatureError:
        return VerificationFailure.INVALID_SIGNATURE, False
    except exceptions.UnsupportedLibraryError:
        return VerificationFailure.UNSUPPORTED_LIBRARY, False
    except Exception:
        return VerificationFailure.VERIFICATION_ERROR, False

    return None, True


def _legacy_evidence_blocker(
    record: ReviewRecord,
    capabilities: EnvironmentCapabilities,
) -> VerificationFailure | None:
    """Return why prior evidence may not be reused, or None if it may."""

    if not capabilities.allow_legacy_evidence:
        return VerificationFailure.LEGACY_EVIDENCE_DISABLED
    if record.review_source not in capabilities.trusted_review_sources:
        return VerificationFailure.UNTRUSTED_REVIEW_SOURCE
    return None


def _recheck(
    record: ReviewRecord,
    failures: Iterable[VerificationFailure],
    prior_failure: VerificationFailure | None,
    reuse_blocked_by: VerificationFailure | None = None,
    reason: str = "",
) -> MigrationAssessment:
    """Return a RECHECK assessment."""

    return MigrationAssessment(
        record.record_id,
        MigrationDecision.RECHECK,
        failures=failures,
        prior_failure=prior_failure,
        reuse_blocked_by=reuse_blocked_by,
        reason=reason or "Insufficient trusted evidence for the conclusion.",
    )


def _assess_record(  # noqa: PLR0912
    record: ReviewRecord,
    capabilities: EnvironmentCapabilities,
) -> MigrationAssessment:
    """Assess one historical record against new environment capabilities."""

    prior_failure = record.prior_failure

    if record.envelope_digest is not None:
        actual_digest = record.envelope.digest()
        if actual_digest != record.envelope_digest.lower():
            return _recheck(
                record,
                [VerificationFailure.ENVELOPE_MISMATCH],
                prior_failure,
                reason="Envelope digest does not match the review record.",
            )

    if record.conclusion.strip().lower() not in APPROVED_CONCLUSIONS:
        return _recheck(
            record,
            [VerificationFailure.UNSUPPORTED_CONCLUSION],
            prior_failure,
            reason=f"Conclusion '{record.conclusion}' cannot be carried over.",
        )

    failures: list[VerificationFailure] = []
    verified: set[str] = set()
    signatures = record.envelope.signatures
    required = set(record.evidence_keyids)

    if not signatures:
        failures.append(VerificationFailure.INSUFFICIENT_EVIDENCE)
    if required - set(signatures):
        failures.append(VerificationFailure.INSUFFICIENT_EVIDENCE)

    for keyid in sorted(signatures):
        failure, accepted = _check_signature(record, capabilities, keyid)
        if accepted:
            verified.add(keyid)
        elif failure is not None:
            failures.append(failure)

    enough = required <= verified and len(verified) >= capabilities.threshold
    if not enough and (
        not failures
        or any(
            failure not in _REVERIFICATION_UNAVAILABLE_FAILURES for failure in failures
        )
    ):
        failures.append(VerificationFailure.INSUFFICIENT_EVIDENCE)

    if prior_failure in _CRYPTOGRAPHIC_FAILURES:
        failures.append(prior_failure)

    if not failures:
        return MigrationAssessment(
            record.record_id,
            MigrationDecision.REVERIFIED,
            verified_keyids=verified,
            prior_failure=prior_failure,
            reason="Envelope re-verified with new environment key material.",
        )

    can_reuse = all(
        failure in _REVERIFICATION_UNAVAILABLE_FAILURES for failure in failures
    )
    if can_reuse and required:
        blocked_by = _legacy_evidence_blocker(record, capabilities)
        if blocked_by is None:
            return MigrationAssessment(
                record.record_id,
                MigrationDecision.REUSE_APPROVED_EVIDENCE,
                failures=failures,
                reused_keyids=required,
                prior_failure=prior_failure,
                reason=(
                    "Re-verification unavailable; reusing approved evidence "
                    "from a trusted review source."
                ),
            )
        failures.append(blocked_by)
        return _recheck(
            record,
            failures,
            prior_failure,
            reuse_blocked_by=blocked_by,
            reason="Re-verification unavailable and prior evidence is not trusted.",
        )

    if can_reuse and not required:
        failures.append(VerificationFailure.INSUFFICIENT_EVIDENCE)

    return _recheck(record, failures, prior_failure)


def _assess_mapping(
    data: Mapping[str, Any],
    capabilities: EnvironmentCapabilities,
) -> MigrationAssessment:
    """Assess one serialized record, classifying malformed input."""

    record_id = str(_get(data, "recordId", "record_id", default="<unknown>"))
    try:
        record = ReviewRecord.from_dict(data)
    except (KeyError, TypeError, ValueError, exceptions.FormatError) as error:
        return MigrationAssessment(
            record_id,
            MigrationDecision.RECHECK,
            failures=[VerificationFailure.MALFORMED_ENVELOPE],
            reason=f"Malformed review record: {error}",
        )
    return _assess_record(record, capabilities)


def assess_migration(
    records: (
        ReviewRecord | Mapping[str, Any] | Iterable[ReviewRecord | Mapping[str, Any]]
    ),
    capabilities: EnvironmentCapabilities | Mapping[str, Any],
) -> MigrationReport:
    """Assess historical DSSE review records against new capabilities.

    This is the migration entry point: it accepts old review records and an
    explicit description of what the new backend can verify, then decides per
    record whether the recorded conclusion has enough evidence to be used
    as-is, can only be carried over from trusted approved evidence, or must be
    reviewed again.

    Args:
        records: One review record, or an iterable of records. Records may be
            ReviewRecord instances or their serialized mapping form.
        capabilities: EnvironmentCapabilities or its serialized mapping form.

    Returns:
        MigrationReport with per-record assessments and the reusable and
        recheck subsets.

    Raises:
        TypeError: If records or capabilities have an unsupported type.
    """

    if isinstance(capabilities, Mapping):
        capabilities = EnvironmentCapabilities.from_dict(capabilities)
    if not isinstance(capabilities, EnvironmentCapabilities):
        raise TypeError("capabilities must be EnvironmentCapabilities or a mapping")

    if isinstance(records, (ReviewRecord, Mapping)):
        records = [records]

    assessments = []
    for item in records:
        if isinstance(item, ReviewRecord):
            assessments.append(_assess_record(item, capabilities))
        elif isinstance(item, Mapping):
            assessments.append(_assess_mapping(item, capabilities))
        else:
            raise TypeError("records must contain ReviewRecord or mapping instances")

    return MigrationReport(assessments)
