"""
Offline review entry point for XML signatures made under deprecated algorithm policies.

The workflow implemented here is intentionally fully offline: every key, timestamp and admission rule is
supplied by the caller, and no network access (CRL, OCSP, TSA over HTTP, certificate authority lookup) is
performed. It is built on top of :class:`signxml.XMLSigner` and :class:`signxml.XMLVerifier` and adds three
pieces of machinery around them:

1. :class:`AdmissionPolicy` / :class:`AdmissionPolicyTable` describe which signature and digest algorithms a
   publisher admitted during a given validity interval. Each table is a *versioned* admission table; a
   reviewer can hold several tables side by side.
2. :class:`TrustedTimeEvidence` is a compact, digitally signed token that binds a point in time to the
   fingerprint of a specific document. It stands in for the trusted timestamp a time-stamping authority would
   issue, and is the *only* source of time used by the historical decision. Dates written inside the document
   itself are never consulted, so they cannot be used to mask an old policy.
3. :class:`OfflineReviewer` produces a :class:`ReviewReport` whose checklist records every fact the decision
   rests on, and can issue an :class:`UpgradeReceipt` that re-signs the exact verified material under the
   current policy without rewriting history.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Union
from xml.etree import ElementTree as stdlibElementTree

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)
from lxml import etree

from ..algorithms import DigestAlgorithm, SignatureConstructionMethod, SignatureMethod
from ..exceptions import InvalidInput, InvalidSignature
from ..signer import XMLSigner
from ..util import namespaces
from ..verifier import SignatureConfiguration, VerifyResult, XMLVerifier

# Namespace for the archival-review vocabulary used by time evidence and upgrade receipts.
LEGACY_REVIEW_NAMESPACE = "urn:signxml:legacy-review:1"
_REVIEW_PREFIX = "lr"

# XML namespace map used when building the archival-review vocabulary elements.
_NAMESPACE_MAP = {_REVIEW_PREFIX: LEGACY_REVIEW_NAMESPACE}

PrivateKeyInput = Union[bytes, str, rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]
PublicKeyInput = Union[bytes, str, rsa.RSAPublicKey, ec.EllipticCurvePublicKey]
DocumentInput = Union[bytes, str, etree._Element, stdlibElementTree.Element]
TimestampInput = Union[datetime, str]


def _review_tag(tag: str) -> etree.QName:
    return etree.QName(LEGACY_REVIEW_NAMESPACE, tag)


def _ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ReviewError("Timestamps must carry an explicit timezone; naive datetimes are not accepted")
    return value.astimezone(timezone.utc)


def _parse_timestamp(value: TimestampInput) -> datetime:
    if isinstance(value, datetime):
        return _ensure_utc(value)
    return _ensure_utc(datetime.fromisoformat(value))


def _format_timestamp(value: datetime) -> str:
    return _ensure_utc(value).isoformat().replace("+00:00", "Z")


def _as_bytes(document: DocumentInput) -> bytes:
    if isinstance(document, bytes):
        return document
    if isinstance(document, str):
        return document.encode("utf-8")
    if isinstance(document, stdlibElementTree.Element):
        return stdlibElementTree.tostring(document, encoding="utf-8")
    return etree.tostring(document, encoding="utf-8")


def _as_pem(value: Union[bytes, str]) -> bytes:
    if isinstance(value, str):
        return value.encode("utf-8")
    return value


def _normalize_public_key(public_key: PublicKeyInput) -> rsa.RSAPublicKey | ec.EllipticCurvePublicKey:
    if isinstance(public_key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
        return public_key
    return load_pem_public_key(_as_pem(public_key))


def _private_key_from_input(
    key: PrivateKeyInput, passphrase: bytes | None = None
) -> rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey:
    if isinstance(key, (bytes, str)):
        return load_pem_private_key(_as_pem(key), password=passphrase)
    return key


def document_fingerprint(document: DocumentInput) -> bytes:
    """
    Return the SHA-256 fingerprint of the serialized document.

    The fingerprint is the binding identifier used by :class:`TrustedTimeEvidence` and
    :class:`UpgradeReceipt`. It is computed over the exact bytes handed to the reviewer so that any change to
    the document body, including replacing signed content while keeping a structurally valid signature,
    produces a different fingerprint and breaks the binding.
    """
    return hashlib.sha256(_as_bytes(document)).digest()


class ReviewError(Exception):
    """
    Raised when an offline review cannot be performed at all (for example when the trusted time evidence is
    forged, malformed, or bound to a different document). A cryptographic rejection of the document itself is
    reported on the :class:`ReviewReport` instead of being raised.
    """


class ReviewOutcome(str, Enum):
    """
    The mutually exclusive final conclusions a review can reach.
    """

    ACCEPTED_HISTORIC_CURRENT = "accepted-historic-and-current"
    """The signature is valid, and its algorithms are admitted both at the trusted evidence time and now."""

    ACCEPTED_HISTORIC_REISSUE_NEEDED = "accepted-historic-reissue-needed"
    """The signature was legitimately accepted under the policy in force when it was made, but that algorithm
    policy has since been retired, so the document must be re-signed to remain acceptable now."""

    REJECTED_TAMPERED = "rejected-tampered"
    """Cryptographic verification failed: the digest or signature no longer matches the document content."""

    REJECTED_UNADMITTED_AT_TIME = "rejected-unadmitted-at-time"
    """The signature verifies cryptographically, but its algorithms were not admitted by the policy in force
    at the trusted evidence time, so the document was never legitimately accepted."""

    REJECTED_EVIDENCE = "rejected-evidence"
    """The trusted time evidence itself could not be validated or does not bind this document."""

    REJECTED_NO_EVIDENCE = "rejected-no-evidence"
    """No trusted time evidence was supplied, so no historical decision can be made."""

    @property
    def historically_accepted(self) -> bool:
        return self in (
            ReviewOutcome.ACCEPTED_HISTORIC_CURRENT,
            ReviewOutcome.ACCEPTED_HISTORIC_REISSUE_NEEDED,
        )

    @property
    def reissue_required(self) -> bool:
        return self is ReviewOutcome.ACCEPTED_HISTORIC_REISSUE_NEEDED


@dataclass(frozen=True)
class AdmissionPolicy:
    """
    One version of an algorithm admission table.

    A policy admits a fixed set of XML signature methods and digest algorithms while it is in force. The
    ``effective_from`` instant (inclusive) marks when this table version became active; the most recent
    policy whose ``effective_from`` is not later than the decision time applies.
    """

    version: str
    effective_from: datetime
    signature_methods: frozenset[SignatureMethod]
    digest_algorithms: frozenset[DigestAlgorithm]
    description: str = ""

    def __post_init__(self) -> None:
        if not self.signature_methods:
            raise ReviewError("An admission policy must admit at least one signature method")
        if not self.digest_algorithms:
            raise ReviewError("An admission policy must admit at least one digest algorithm")
        object.__setattr__(self, "effective_from", _ensure_utc(self.effective_from))

    def admits(self, signature_method: SignatureMethod, digest_algorithm: DigestAlgorithm) -> bool:
        return signature_method in self.signature_methods and digest_algorithm in self.digest_algorithms


@dataclass(frozen=True)
class AdmissionPolicyTable:
    """
    A versioned, time-ordered collection of :class:`AdmissionPolicy` entries.

    Historical documents frequently carry acceptance records stamped under different table versions. The
    table resolves the policy that was in force at any given instant so each record can be judged against the
    rules that actually applied then, rather than today's rules.
    """

    name: str
    policies: tuple[AdmissionPolicy, ...]

    def __post_init__(self) -> None:
        ordered = tuple(sorted(self.policies, key=lambda policy: policy.effective_from))
        if len(ordered) != len({policy.version for policy in ordered}):
            raise ReviewError("Admission policy versions must be unique within a table")
        object.__setattr__(self, "policies", ordered)

    def policy_at(self, decision_time: datetime) -> AdmissionPolicy:
        """Return the policy version that was in force at ``decision_time``."""
        moment = _ensure_utc(decision_time)
        applicable = tuple(policy for policy in self.policies if policy.effective_from <= moment)
        if not applicable:
            raise ReviewError(
                f"Policy table {self.name!r} has no admission policy in force at {_format_timestamp(moment)}"
            )
        return applicable[-1]

    def current_policy(self, now: datetime | None = None) -> AdmissionPolicy:
        """Return the policy version currently in force."""
        moment = datetime.now(tz=timezone.utc) if now is None else _ensure_utc(now)
        return self.policy_at(moment)


def build_default_policy_table(
    *,
    retirement_instant: datetime | None = None,
) -> AdmissionPolicyTable:
    """
    Build the two-version admission table used by the shipped test and demo material.

    Version ``v1`` (in force from the Unix epoch) admits every algorithm SignXML can construct, including the
    SHA-1 family kept only for legacy compatibility. Version ``v2`` retires every SHA-1 based signature and
    digest method and admits only the SHA-2/SHA-3 family, matching SignXML's own default
    :class:`SignatureConfiguration`. Override ``retirement_instant`` to pin the policy change to a specific
    date instead of 2024-01-01 UTC.
    """
    if retirement_instant is None:
        retirement_instant = datetime(2024, 1, 1, tzinfo=timezone.utc)
    legacy_policy = AdmissionPolicy(
        version="v1",
        effective_from=datetime(1970, 1, 1, tzinfo=timezone.utc),
        signature_methods=frozenset(SignatureMethod),
        digest_algorithms=frozenset(DigestAlgorithm),
        description="Legacy admission table: SHA-1 based methods admitted for historical signatures",
    )
    modern_policy = AdmissionPolicy(
        version="v2",
        effective_from=_ensure_utc(retirement_instant),
        signature_methods=frozenset(method for method in SignatureMethod if "SHA1" not in method.name),
        digest_algorithms=frozenset(algorithm for algorithm in DigestAlgorithm if "SHA1" not in algorithm.name),
        description="Current admission table: SHA-1 based methods retired",
    )
    return AdmissionPolicyTable(name="default-xmldsig-admission", policies=(legacy_policy, modern_policy))


@dataclass(frozen=True)
class ChecklistItem:
    """
    One entry on the review checklist.

    Every item records the fact that was established (``detail``), the artifact or rule it came from
    (``source``) and whether it passed. Info items describe context and always pass; failed check items are
    what drive a rejection.
    """

    name: str
    passed: bool
    detail: str
    source: str
    informational: bool = False


@dataclass(frozen=True)
class ReviewReport:
    """
    The structured result of an offline review.

    The report deliberately keeps the historical and current decisions separate. ``outcome`` and
    ``historical_accepted`` describe what was true under the policy in force when the document was made;
    ``current_policy_admitted`` and ``reissue_required`` describe what is true under today's policy. A current
    failure never flips a historical acceptance.
    """

    outcome: ReviewOutcome
    document_fingerprint_hex: str
    evidence_id: str | None
    evidence_time: datetime | None
    historical_policy_version: str | None
    historical_policy_admitted: bool | None
    current_policy_version: str | None
    current_policy_admitted: bool | None
    signature_method: SignatureMethod | None
    digest_algorithm: DigestAlgorithm | None
    signed_data: bytes | None
    checklist: tuple[ChecklistItem, ...]
    failure_reason: str | None = None

    @property
    def historical_accepted(self) -> bool:
        return self.outcome.historically_accepted

    @property
    def reissue_required(self) -> bool:
        return self.outcome.reissue_required

    def render_checklist(self) -> str:
        """Render the checklist as a human-readable, line-oriented report."""
        lines = [
            f"review-outcome: {self.outcome.value}",
            f"document-fingerprint: {self.document_fingerprint_hex}",
        ]
        if self.evidence_id is not None:
            lines.append(f"trusted-evidence: {self.evidence_id} at {_format_timestamp(self.evidence_time)}")
        if self.historical_policy_version is not None:
            admitted = "admitted" if self.historical_policy_admitted else "not-admitted"
            lines.append(f"historical-policy: {self.historical_policy_version} ({admitted})")
        if self.current_policy_version is not None:
            admitted = "admitted" if self.current_policy_admitted else "not-admitted"
            lines.append(f"current-policy: {self.current_policy_version} ({admitted})")
        if self.signature_method is not None:
            lines.append(f"signature-method: {self.signature_method.name}")
        if self.digest_algorithm is not None:
            lines.append(f"digest-algorithm: {self.digest_algorithm.name}")
        lines.append(f"reissue-required: {self.reissue_required}")
        for item in self.checklist:
            marker = "INFO" if item.informational else ("PASS" if item.passed else "FAIL")
            lines.append(f"[{marker}] {item.name}: {item.detail} (source: {item.source})")
        return "\n".join(lines)


@dataclass(frozen=True)
class TrustedTimeEvidence:
    """
    A trusted, digitally signed token that attests that a specific document existed at a specific time.

    The token is an enveloping XML Signature produced by :func:`issue_trusted_time_evidence`. It binds an
    ``evidence_id``, an attestation instant and the SHA-256 fingerprint of the document bytes, and is signed
    by a trusted time-keeping key. Unlike a date typed into the document body, this token cannot be backdated
    by the document author, and it is the sole time source consulted by :class:`OfflineReviewer`.
    """

    evidence_id: str
    attestation_time: datetime
    document_fingerprint_hex: str
    signature_xml: bytes

    def serialize(self) -> bytes:
        """Return the canonical XML bytes of the signed evidence token."""
        return self.signature_xml


def _build_evidence_payload(
    *,
    evidence_id: str,
    attestation_time: datetime,
    fingerprint_hex: str,
) -> etree._Element:
    payload = etree.Element(_review_tag("TrustedTimeEvidence"), nsmap=_NAMESPACE_MAP)
    identifier = etree.SubElement(payload, _review_tag("EvidenceId"))
    identifier.text = evidence_id
    timestamp = etree.SubElement(payload, _review_tag("AttestationTime"))
    timestamp.text = _format_timestamp(attestation_time)
    digest = etree.SubElement(payload, _review_tag("DocumentFingerprint"))
    digest.set("algorithm", "sha256")
    digest.text = fingerprint_hex
    return payload


def _unwrap_signed_object(payload: etree._Element) -> etree._Element:
    if payload.tag == f"{{{namespaces.ds}}}Object":
        children = [child for child in payload if not isinstance(child.tag, int)]
        if len(children) != 1:
            raise ReviewError("Signed object must wrap exactly one review payload element")
        return children[0]
    return payload


def _read_evidence_payload(payload: etree._Element) -> tuple[str, datetime, str]:
    payload = _unwrap_signed_object(payload)
    identifier_node = payload.find(f"{_REVIEW_PREFIX}:EvidenceId", namespaces=_NAMESPACE_MAP)
    timestamp_node = payload.find(f"{_REVIEW_PREFIX}:AttestationTime", namespaces=_NAMESPACE_MAP)
    fingerprint_node = payload.find(f"{_REVIEW_PREFIX}:DocumentFingerprint", namespaces=_NAMESPACE_MAP)
    if identifier_node is None or timestamp_node is None or fingerprint_node is None:
        raise ReviewError("Trusted time evidence is missing a required claim element")
    if identifier_node.text is None or timestamp_node.text is None or fingerprint_node.text is None:
        raise ReviewError("Trusted time evidence contains an empty claim element")
    try:
        attestation_time = _parse_timestamp(timestamp_node.text)
    except ValueError as exc:
        raise ReviewError("Trusted time evidence carries an unparseable attestation time") from exc
    return identifier_node.text, attestation_time, fingerprint_node.text.strip()


def _permissive_config() -> SignatureConfiguration:
    return SignatureConfiguration(
        require_x509=False,
        signature_methods=frozenset(SignatureMethod),
        digest_algorithms=frozenset(DigestAlgorithm),
    )


def issue_trusted_time_evidence(
    document: DocumentInput,
    *,
    attestation_key: PrivateKeyInput,
    attestation_time: TimestampInput,
    evidence_id: str | None = None,
    signature_method: SignatureMethod = SignatureMethod.RSA_SHA256,
    digest_algorithm: DigestAlgorithm = DigestAlgorithm.SHA256,
) -> TrustedTimeEvidence:
    """
    Issue a :class:`TrustedTimeEvidence` token binding ``document`` to ``attestation_time``.

    The token is signed with ``attestation_key`` using an enveloping XML Signature. In a real deployment this
    key belongs to a time-stamping authority or another trusted custodian; in the offline test workflow it is
    generated and supplied by the caller. The fingerprint embedded in the token is computed over the exact
    document bytes, so a token cannot be silently replayed against an altered document.
    """
    moment = _parse_timestamp(attestation_time)
    fingerprint = document_fingerprint(document)
    identifier = evidence_id or f"tte-{uuid.uuid4().hex}"
    payload = _build_evidence_payload(
        evidence_id=identifier,
        attestation_time=moment,
        fingerprint_hex=fingerprint.hex(),
    )
    signer = XMLSigner(
        method=SignatureConstructionMethod.enveloping,
        signature_algorithm=signature_method,
        digest_algorithm=digest_algorithm,
    )
    signed = signer.sign(payload, key=_private_key_from_input(attestation_key))
    return TrustedTimeEvidence(
        evidence_id=identifier,
        attestation_time=moment,
        document_fingerprint_hex=fingerprint.hex(),
        signature_xml=etree.tostring(signed, encoding="utf-8", xml_declaration=True),
    )


def load_trusted_time_evidence(
    evidence_data: bytes | str | TrustedTimeEvidence,
    *,
    trusted_evidence_key: PublicKeyInput,
) -> TrustedTimeEvidence:
    """
    Parse and cryptographically validate a trusted time evidence token.

    The enveloping signature is verified against ``trusted_evidence_key`` with every algorithm family
    permitted, because the token itself is the trust anchor for time and must be judged on signature
    validity, not on the document admission policy. Raises :class:`ReviewError` if the token is malformed or
    the signature does not verify.
    """
    if isinstance(evidence_data, TrustedTimeEvidence):
        evidence = evidence_data
        raw = evidence.signature_xml
    else:
        raw = _as_pem(evidence_data)
        evidence = None
    trusted_key = _normalize_public_key(trusted_evidence_key)
    try:
        result = XMLVerifier().verify(raw, require_x509=False, expect_config=_permissive_config())
    except InvalidSignature as exc:
        raise ReviewError(f"Trusted time evidence signature failed verification: {exc}") from exc
    except InvalidInput as exc:
        raise ReviewError(f"Trusted time evidence is malformed: {exc}") from exc
    if not isinstance(result, VerifyResult) or result.signed_xml is None:
        raise ReviewError("Trusted time evidence did not return a signed XML payload")
    if result.signature_key != trusted_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo):
        raise ReviewError("Trusted time evidence was not signed by the configured trusted evidence key")
    identifier, moment, fingerprint_hex = _read_evidence_payload(result.signed_xml)
    if evidence is not None and (
        evidence.evidence_id != identifier
        or evidence.attestation_time != moment
        or evidence.document_fingerprint_hex != fingerprint_hex
    ):
        raise ReviewError("Trusted time evidence claims do not match its parsed token content")
    return TrustedTimeEvidence(
        evidence_id=identifier,
        attestation_time=moment,
        document_fingerprint_hex=fingerprint_hex,
        signature_xml=raw,
    )


class LegacyDocumentSigner(XMLSigner):
    """
    An :class:`~signxml.XMLSigner` subclass that permits legacy SHA-1 based algorithms.

    The base signer refuses SHA-1 in its default configuration because it is insecure for new signatures.
    Historical test material nevertheless has to be reproduced offline, so this subclass opts back in while
    keeping every other safety check. Production code issuing fresh signatures must use the base
    :class:`~signxml.XMLSigner` with a current algorithm.
    """

    def check_deprecated_methods(self) -> None:
        return


def _read_algorithms(signature_node: etree._Element) -> tuple[SignatureMethod, DigestAlgorithm]:
    method_node = signature_node.find("ds:SignedInfo/ds:SignatureMethod", namespaces=namespaces)
    digest_node = signature_node.find("ds:SignedInfo/ds:Reference/ds:DigestMethod", namespaces=namespaces)
    if method_node is None or digest_node is None:
        raise ReviewError("Signature is missing SignatureMethod or DigestMethod elements")
    return (
        SignatureMethod(method_node.get("Algorithm")),
        DigestAlgorithm(digest_node.get("Algorithm")),
    )


class OfflineReviewer:
    """
    Perform offline historical and current admission reviews of signed XML documents.

    A reviewer is constructed once with the trust material it is allowed to use: a *test public key* against
    which document signatures are checked, the trusted key that vouches for time evidence, and one or more
    versioned :class:`AdmissionPolicyTable` objects. All inputs are local; the reviewer performs no network
    access and never consults a clock it owns for the historical decision.

    Two independent questions are answered for every document:

    * Was the document legitimately accepted under the policy in force at the instant attested by the
      trusted time evidence?
    * Is the document still admitted under the policy in force at review time, or must it be re-signed?
    """

    def __init__(
        self,
        *,
        trusted_public_key: PublicKeyInput,
        trusted_evidence_key: PublicKeyInput,
        policy_tables: AdmissionPolicyTable | tuple[AdmissionPolicyTable, ...],
        now: datetime | None = None,
    ) -> None:
        self.trusted_public_key = _normalize_public_key(trusted_public_key)
        self.trusted_evidence_key = _normalize_public_key(trusted_evidence_key)
        if isinstance(policy_tables, AdmissionPolicyTable):
            policy_tables = (policy_tables,)
        if not policy_tables:
            raise ReviewError("At least one admission policy table is required")
        self.policy_tables: tuple[AdmissionPolicyTable, ...] = policy_tables
        self._now = None if now is None else _ensure_utc(now)

    @property
    def now(self) -> datetime:
        return self._now or datetime.now(tz=timezone.utc)

    def _table_at(self, decision_time: datetime) -> AdmissionPolicyTable:
        candidates = []
        for table in self.policy_tables:
            try:
                table.policy_at(decision_time)
            except ReviewError:
                continue
            candidates.append(table)
        if not candidates:
            raise ReviewError(f"No admission table covers the decision time {_format_timestamp(decision_time)}")
        return candidates[0]

    def review(
        self,
        document: DocumentInput,
        *,
        time_evidence: TrustedTimeEvidence | bytes | str | None = None,
    ) -> ReviewReport:
        """
        Review one document and return its :class:`ReviewReport`.

        The report is always returned, even when the document is rejected: the checklist carries the
        evidence behind the conclusion. Only failures that make a review meaningless (missing, forged or
        mismatched time evidence) raise :class:`ReviewError`.
        """
        document_bytes = _as_bytes(document)
        fingerprint = hashlib.sha256(document_bytes).digest()
        fingerprint_hex = fingerprint.hex()
        checklist: list[ChecklistItem] = []

        if time_evidence is None:
            checklist.append(
                ChecklistItem(
                    name="trusted-time-evidence",
                    passed=False,
                    detail="No trusted time evidence was supplied",
                    source="review input",
                )
            )
            return self._build_report(
                outcome=ReviewOutcome.REJECTED_NO_EVIDENCE,
                fingerprint_hex=fingerprint_hex,
                checklist=tuple(checklist),
                failure_reason="Historical acceptance cannot be judged without trusted time evidence",
            )

        try:
            evidence = load_trusted_time_evidence(time_evidence, trusted_evidence_key=self.trusted_evidence_key)
        except ReviewError as exc:
            checklist.append(
                ChecklistItem(
                    name="trusted-time-evidence",
                    passed=False,
                    detail=str(exc),
                    source="trusted evidence token",
                )
            )
            return self._build_report(
                outcome=ReviewOutcome.REJECTED_EVIDENCE,
                fingerprint_hex=fingerprint_hex,
                checklist=tuple(checklist),
                failure_reason=str(exc),
            )

        checklist.append(
            ChecklistItem(
                name="trusted-time-evidence",
                passed=True,
                detail=(
                    f"Evidence {evidence.evidence_id} signed by the trusted evidence key attests "
                    f"{_format_timestamp(evidence.attestation_time)} for document fingerprint "
                    f"{evidence.document_fingerprint_hex}"
                ),
                source=f"trusted evidence {evidence.evidence_id}",
            )
        )

        signature_node = etree.fromstring(document_bytes)
        if signature_node.tag != f"{{{namespaces.ds}}}Signature":
            signature_node = signature_node.find(".//ds:Signature", namespaces=namespaces)
        if signature_node is None:
            checklist.append(
                ChecklistItem(
                    name="xml-signature",
                    passed=False,
                    detail="No XML Signature element was found in the document",
                    source="submitted document",
                )
            )
            return self._build_report(
                outcome=ReviewOutcome.REJECTED_TAMPERED,
                fingerprint_hex=fingerprint_hex,
                evidence=evidence,
                checklist=tuple(checklist),
                failure_reason="Document contains no XML Signature",
            )
        signature_method, digest_algorithm = _read_algorithms(signature_node)
        checklist.append(
            ChecklistItem(
                name="signature-algorithms",
                passed=True,
                detail=(f"Signature declares {signature_method.name} with reference digest {digest_algorithm.name}"),
                source="ds:SignedInfo",
                informational=True,
            )
        )

        try:
            verify_result = XMLVerifier().verify(
                document_bytes,
                require_x509=False,
                expect_config=_permissive_config(),
            )
        except InvalidSignature as exc:
            checklist.append(
                ChecklistItem(
                    name="cryptographic-verification",
                    passed=False,
                    detail=f"Signature or reference digest verification failed: {exc}",
                    source="signxml.XMLVerifier",
                )
            )
            return self._build_report(
                outcome=ReviewOutcome.REJECTED_TAMPERED,
                fingerprint_hex=fingerprint_hex,
                evidence=evidence,
                signature_method=signature_method,
                digest_algorithm=digest_algorithm,
                checklist=tuple(checklist),
                failure_reason=str(exc),
            )

        if not isinstance(verify_result, VerifyResult):
            raise ReviewError("Expected exactly one signed reference in the reviewed document")
        expected_key = self.trusted_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        if verify_result.signature_key != expected_key:
            checklist.append(
                ChecklistItem(
                    name="signing-key-match",
                    passed=False,
                    detail="The signature was made with a key other than the configured trusted test public key",
                    source="VerifyResult.signature_key",
                )
            )
            return self._build_report(
                outcome=ReviewOutcome.REJECTED_TAMPERED,
                fingerprint_hex=fingerprint_hex,
                evidence=evidence,
                signature_method=signature_method,
                digest_algorithm=digest_algorithm,
                checklist=tuple(checklist),
                failure_reason="Signing key does not match the trusted test public key",
            )
        checklist.append(
            ChecklistItem(
                name="cryptographic-verification",
                passed=True,
                detail="Signature value and every reference digest verify against the trusted test public key",
                source="signxml.XMLVerifier",
            )
        )
        checklist.append(
            ChecklistItem(
                name="signing-key-match",
                passed=True,
                detail="The verified signature key equals the configured trusted test public key",
                source="VerifyResult.signature_key",
            )
        )

        binding_matches = evidence.document_fingerprint_hex == fingerprint_hex
        if not binding_matches:
            checklist.append(
                ChecklistItem(
                    name="evidence-document-binding",
                    passed=False,
                    detail=(
                        "Evidence binds document fingerprint "
                        f"{evidence.document_fingerprint_hex} but the submitted document has fingerprint "
                        f"{fingerprint_hex}; the signed body no longer matches the attested material"
                    ),
                    source=f"trusted evidence {evidence.evidence_id}",
                )
            )
            return self._build_report(
                outcome=ReviewOutcome.REJECTED_TAMPERED,
                fingerprint_hex=fingerprint_hex,
                evidence=evidence,
                signature_method=signature_method,
                digest_algorithm=digest_algorithm,
                checklist=tuple(checklist),
                failure_reason="Substituted document body: evidence fingerprint no longer binds the document",
            )
        checklist.append(
            ChecklistItem(
                name="evidence-document-binding",
                passed=True,
                detail="The trusted evidence fingerprint matches the submitted document bytes",
                source=f"trusted evidence {evidence.evidence_id}",
            )
        )

        historical_table = self._table_at(evidence.attestation_time)
        historical_policy = historical_table.policy_at(evidence.attestation_time)
        historical_admitted = historical_policy.admits(signature_method, digest_algorithm)
        checklist.append(
            ChecklistItem(
                name="historical-admission",
                passed=historical_admitted,
                detail=(
                    f"Policy {historical_policy.version} of table {historical_table.name!r} in force at "
                    f"{_format_timestamp(evidence.attestation_time)} "
                    + ("admitted" if historical_admitted else "did not admit")
                    + f" {signature_method.name}/{digest_algorithm.name}"
                ),
                source=f"admission table {historical_table.name!r}",
            )
        )

        current_table = self._table_at(self.now)
        current_policy = current_table.current_policy(self.now)
        current_admitted = current_policy.admits(signature_method, digest_algorithm)
        checklist.append(
            ChecklistItem(
                name="current-admission",
                passed=current_admitted,
                detail=(
                    f"Policy {current_policy.version} of table {current_table.name!r} in force at review time "
                    + ("admits" if current_admitted else "no longer admits")
                    + f" {signature_method.name}/{digest_algorithm.name}"
                ),
                source=f"admission table {current_table.name!r}",
            )
        )

        strict_error = self._strict_verification_error(document_bytes)
        if strict_error is None:
            checklist.append(
                ChecklistItem(
                    name="current-strict-verification",
                    passed=True,
                    detail="The document also verifies under the current strict SignatureConfiguration",
                    source="signxml.XMLVerifier default policy",
                )
            )
        else:
            checklist.append(
                ChecklistItem(
                    name="current-strict-verification",
                    passed=False,
                    detail=(
                        "Verification under the current strict configuration fails: "
                        f"{strict_error}. This does not undo the historical acceptance."
                    ),
                    source="signxml.XMLVerifier default policy",
                )
            )

        if not historical_admitted:
            outcome = ReviewOutcome.REJECTED_UNADMITTED_AT_TIME
            failure_reason = (
                f"Algorithms were not admitted by policy {historical_policy.version} at the trusted evidence time"
            )
        elif current_admitted and strict_error is None:
            outcome = ReviewOutcome.ACCEPTED_HISTORIC_CURRENT
            failure_reason = None
        else:
            outcome = ReviewOutcome.ACCEPTED_HISTORIC_REISSUE_NEEDED
            failure_reason = None

        return self._build_report(
            outcome=outcome,
            fingerprint_hex=fingerprint_hex,
            evidence=evidence,
            historical_table=historical_table,
            historical_policy=historical_policy,
            historical_admitted=historical_admitted,
            current_table=current_table,
            current_policy=current_policy,
            current_admitted=current_admitted,
            signature_method=signature_method,
            digest_algorithm=digest_algorithm,
            signed_data=verify_result.signed_data,
            checklist=tuple(checklist),
            failure_reason=failure_reason,
        )

    def _strict_verification_error(self, document_bytes: bytes) -> str | None:
        try:
            strict_config = SignatureConfiguration(require_x509=False)
            XMLVerifier().verify(document_bytes, expect_config=strict_config)
        except (InvalidSignature, InvalidInput) as exc:
            return str(exc)
        return None

    @staticmethod
    def _build_report(
        *,
        outcome: ReviewOutcome,
        fingerprint_hex: str,
        checklist: tuple[ChecklistItem, ...],
        evidence: TrustedTimeEvidence | None = None,
        historical_table: AdmissionPolicyTable | None = None,
        historical_policy: AdmissionPolicy | None = None,
        historical_admitted: bool | None = None,
        current_table: AdmissionPolicyTable | None = None,
        current_policy: AdmissionPolicy | None = None,
        current_admitted: bool | None = None,
        signature_method: SignatureMethod | None = None,
        digest_algorithm: DigestAlgorithm | None = None,
        signed_data: bytes | None = None,
        failure_reason: str | None = None,
    ) -> ReviewReport:
        return ReviewReport(
            outcome=outcome,
            document_fingerprint_hex=fingerprint_hex,
            evidence_id=evidence.evidence_id if evidence is not None else None,
            evidence_time=evidence.attestation_time if evidence is not None else None,
            historical_policy_version=historical_policy.version if historical_policy is not None else None,
            historical_policy_admitted=historical_admitted,
            current_policy_version=current_policy.version if current_policy is not None else None,
            current_policy_admitted=current_admitted,
            signature_method=signature_method,
            digest_algorithm=digest_algorithm,
            signed_data=signed_data,
            checklist=checklist,
            failure_reason=failure_reason,
        )


@dataclass(frozen=True)
class UpgradeBundle:
    """
    The result of re-signing a historically accepted document.

    reissued_document is the original signed material re-signed under the current policy; its body bytes
    are exactly the previously verified signed_data. receipt is the separately signed
    :class:`UpgradeReceipt` that commits to both the original and the reissued document fingerprints, so the
    two can be proven to cover the same material later.
    """

    reissued_document: bytes
    receipt: "UpgradeReceipt"


@dataclass(frozen=True)
class UpgradeReceipt:
    """
    A signed commitment that a re-signed document covers the exact material of an already verified original.

    The receipt is itself an enveloping XML Signature over a structured claim containing:

    * the fingerprint of the original, historically accepted document;
    * the fingerprint of the reissued document and the current-policy algorithms it now uses;
    * the trusted evidence identifier and attestation time that grounded the historical acceptance;
    * the historical and current policy versions consulted.

    Because every fingerprint is derived from verified bytes, a receipt cannot claim the same material for a
    body-swapped document, and because the historical outcome is recorded rather than re-evaluated, a new
    verification result cannot be used to deny what was historically true.
    """

    receipt_id: str
    original_fingerprint_hex: str
    reissued_fingerprint_hex: str
    evidence_id: str
    attestation_time: datetime
    historical_policy_version: str
    current_policy_version: str
    reissued_signature_method: SignatureMethod
    reissued_digest_algorithm: DigestAlgorithm
    signature_xml: bytes

    def serialize(self) -> bytes:
        """Return the canonical XML bytes of the signed receipt token."""
        return self.signature_xml


def _build_receipt_payload(receipt: UpgradeReceipt) -> etree._Element:
    payload = etree.Element(_review_tag("UpgradeReceipt"), nsmap=_NAMESPACE_MAP)
    fields = (
        ("ReceiptId", receipt.receipt_id),
        ("OriginalDocumentFingerprint", receipt.original_fingerprint_hex),
        ("ReissuedDocumentFingerprint", receipt.reissued_fingerprint_hex),
        ("TrustedEvidenceId", receipt.evidence_id),
        ("AttestationTime", _format_timestamp(receipt.attestation_time)),
        ("HistoricalPolicyVersion", receipt.historical_policy_version),
        ("CurrentPolicyVersion", receipt.current_policy_version),
        ("ReissuedSignatureMethod", receipt.reissued_signature_method.name),
        ("ReissuedDigestAlgorithm", receipt.reissued_digest_algorithm.name),
    )
    for tag, text in fields:
        node = etree.SubElement(payload, _review_tag(tag))
        node.text = text
    return payload


def _read_receipt_payload(payload: etree._Element) -> dict[str, str]:
    wanted = (
        "ReceiptId",
        "OriginalDocumentFingerprint",
        "ReissuedDocumentFingerprint",
        "TrustedEvidenceId",
        "AttestationTime",
        "HistoricalPolicyVersion",
        "CurrentPolicyVersion",
        "ReissuedSignatureMethod",
        "ReissuedDigestAlgorithm",
    )
    payload = _unwrap_signed_object(payload)
    values: dict[str, str] = {}
    for tag in wanted:
        node = payload.find(f"{_REVIEW_PREFIX}:{tag}", namespaces=_NAMESPACE_MAP)
        if node is None or node.text is None:
            raise ReviewError(f"Upgrade receipt is missing the {tag} claim")
        values[tag] = node.text.strip()
    return values


def _check_upgrade_methods_allowed(
    reviewer: OfflineReviewer,
    *,
    signature_method: SignatureMethod,
    digest_algorithm: DigestAlgorithm,
) -> None:
    current_table = reviewer._table_at(reviewer.now)
    current_policy = current_table.current_policy(reviewer.now)
    if not current_policy.admits(signature_method, digest_algorithm):
        raise ReviewError(
            f"Requested upgrade algorithms {signature_method.name}/{digest_algorithm.name} are not admitted by "
            f"current policy {current_policy.version}"
        )


def issue_upgrade(
    reviewer: OfflineReviewer,
    document: DocumentInput,
    *,
    reissue_key: PrivateKeyInput,
    time_evidence: TrustedTimeEvidence | bytes | str,
    signature_method: SignatureMethod = SignatureMethod.RSA_SHA256,
    digest_algorithm: DigestAlgorithm = DigestAlgorithm.SHA256,
    receipt_id: str | None = None,
) -> UpgradeBundle:
    """
    Re-sign a historically accepted document under the current policy and bind the result with a receipt.

    The document is first reviewed. Re-signing is only allowed for a document that was historically
    accepted; documents rejected for tampering or for never having been admitted cannot be upgraded. The
    reissued signature is computed over the exact verified signed_data returned by SignXML, so the
    material cannot drift during the upgrade. Both fingerprints and the historical decision are then
    committed inside the signed :class:`UpgradeReceipt`.
    """
    _check_upgrade_methods_allowed(reviewer, signature_method=signature_method, digest_algorithm=digest_algorithm)
    report = reviewer.review(document, time_evidence=time_evidence)
    if report.outcome is ReviewOutcome.REJECTED_NO_EVIDENCE:
        raise ReviewError("Cannot issue an upgrade without trusted time evidence")
    if not report.historical_accepted:
        raise ReviewError(
            f"Cannot issue an upgrade for a document that was not historically accepted: {report.outcome.value}"
        )
    if report.signed_data is None or report.evidence_time is None or report.historical_policy_version is None:
        raise ReviewError("Review report lacks the verified material required to issue an upgrade")
    if report.outcome is ReviewOutcome.ACCEPTED_HISTORIC_CURRENT:
        raise ReviewError("Document already satisfies the current policy; no re-signature is required")

    signed_root = etree.fromstring(report.signed_data)
    signer = XMLSigner(
        method=SignatureConstructionMethod.enveloped,
        signature_algorithm=signature_method,
        digest_algorithm=digest_algorithm,
    )
    reissued_root = signer.sign(signed_root, key=_private_key_from_input(reissue_key))
    reissued_bytes = etree.tostring(reissued_root, encoding="utf-8", xml_declaration=True)
    reissued_fingerprint = hashlib.sha256(reissued_bytes).digest().hex()

    receipt = UpgradeReceipt(
        receipt_id=receipt_id or f"upg-{uuid.uuid4().hex}",
        original_fingerprint_hex=report.document_fingerprint_hex,
        reissued_fingerprint_hex=reissued_fingerprint,
        evidence_id=report.evidence_id or "",
        attestation_time=report.evidence_time,
        historical_policy_version=report.historical_policy_version,
        current_policy_version=report.current_policy_version or "",
        reissued_signature_method=signature_method,
        reissued_digest_algorithm=digest_algorithm,
        signature_xml=b"",
    )
    receipt_signer = XMLSigner(
        method=SignatureConstructionMethod.enveloping,
        signature_algorithm=signature_method,
        digest_algorithm=digest_algorithm,
    )
    signed_receipt = receipt_signer.sign(_build_receipt_payload(receipt), key=_private_key_from_input(reissue_key))
    object.__setattr__(
        receipt,
        "signature_xml",
        etree.tostring(signed_receipt, encoding="utf-8", xml_declaration=True),
    )
    return UpgradeBundle(reissued_document=reissued_bytes, receipt=receipt)


def verify_upgrade_receipt(
    bundle: UpgradeBundle,
    *,
    original_document: DocumentInput,
    trusted_reissue_key: PublicKeyInput,
) -> tuple[bool, tuple[ChecklistItem, ...]]:
    """
    Verify that an upgrade receipt honestly commits to the same material as the original document.

    The receipt signature is checked against trusted_reissue_key, its claims are parsed, and the
    fingerprints are compared against the supplied original document and the bundle reissued document.
    Returns a boolean together with the detailed checklist so callers can see exactly which commitment
    failed. A body-swapped document fails the original-fingerprint check even if every XML signature is
    otherwise valid.
    """
    trusted_key = _normalize_public_key(trusted_reissue_key)
    checklist: list[ChecklistItem] = []
    try:
        result = XMLVerifier().verify(
            bundle.receipt.signature_xml,
            require_x509=False,
            expect_config=_permissive_config(),
        )
    except InvalidSignature as exc:
        checklist.append(
            ChecklistItem(
                name="receipt-signature",
                passed=False,
                detail=f"Upgrade receipt signature failed verification: {exc}",
                source="signxml.XMLVerifier",
            )
        )
        return False, tuple(checklist)

    if not isinstance(result, VerifyResult) or result.signed_xml is None:
        checklist.append(
            ChecklistItem(
                name="receipt-signature",
                passed=False,
                detail="Upgrade receipt did not return a signed payload",
                source="signxml.XMLVerifier",
            )
        )
        return False, tuple(checklist)
    key_matches = result.signature_key == trusted_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    checklist.append(
        ChecklistItem(
            name="receipt-signature",
            passed=key_matches,
            detail=(
                "Upgrade receipt signature verifies against the trusted reissue key"
                if key_matches
                else "Upgrade receipt was not signed by the trusted reissue key"
            ),
            source="VerifyResult.signature_key",
        )
    )

    claims = _read_receipt_payload(result.signed_xml)
    original_hex = hashlib.sha256(_as_bytes(original_document)).digest().hex()
    reissued_hex = hashlib.sha256(bundle.reissued_document).digest().hex()
    original_matches = claims["OriginalDocumentFingerprint"] == original_hex
    reissued_matches = claims["ReissuedDocumentFingerprint"] == reissued_hex
    checklist.append(
        ChecklistItem(
            name="original-material-binding",
            passed=original_matches,
            detail=(
                "Receipt commits to the submitted original document fingerprint"
                if original_matches
                else "Receipt expects " + claims["OriginalDocumentFingerprint"] + " but original is " + original_hex
            ),
            source="UpgradeReceipt.OriginalDocumentFingerprint",
        )
    )
    checklist.append(
        ChecklistItem(
            name="reissued-material-binding",
            passed=reissued_matches,
            detail=(
                "Receipt commits to the supplied reissued document fingerprint"
                if reissued_matches
                else "Receipt expects " + claims["ReissuedDocumentFingerprint"] + " but reissued is " + reissued_hex
            ),
            source="UpgradeReceipt.ReissuedDocumentFingerprint",
        )
    )
    all_passed = key_matches and original_matches and reissued_matches
    return all_passed, tuple(checklist)


def review_reissued_document(
    reviewer: OfflineReviewer,
    bundle: UpgradeBundle,
    *,
    current_time_evidence: TrustedTimeEvidence | bytes | str,
) -> ReviewReport:
    """
    Review the reissued document produced by :func:`issue_upgrade`.

    The reissued document carries its own fresh trusted time evidence stamped at upgrade time, when the
    current policy is in force. A successful review therefore ends in
    :attr:`ReviewOutcome.ACCEPTED_HISTORIC_CURRENT` with no re-signature required, while the original
    document historical acceptance remains recorded on the receipt and is never overwritten.
    """
    return reviewer.review(bundle.reissued_document, time_evidence=current_time_evidence)
