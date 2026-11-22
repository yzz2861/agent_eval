"""
Read-only selective disclosure review for XAdES signatures.

A complete XAdES signature bundles several independent compliance claims (signing time, signing certificate,
signature policy, signer role, data object format) into a single signed ``xades:SignedProperties`` structure. When an
archive hands a signature to an external reviewer to check a single claim, the rest of the signed properties may be
kept internal, and some supporting evidence (the signing certificate, a standalone signature policy document, or the
trust anchor from the original signing environment) may be disclosed separately or withheld.

This module provides a *disclosure check*: it does not accept or reject a signature outright. Instead, for each
requested claim it enumerates the pre-existing evidence required to recompute that claim, recomputes every piece that
the disclosure actually makes available, and reports what remains unprovable. A claim is only reported as verified
when both layers of evidence hold:

1. The subordinate proof carried inside the signed XAdES structure itself (the digest, identifier or value embedded
   in ``xades:SignedProperties``) can be recomputed from the disclosed material.
2. The original signing environment is preserved: the ``SignedProperties`` reference digest and the
   ``ds:SignatureValue`` both recompute, binding the embedded proof to the signer key.

Anything that cannot be independently recomputed from the disclosed evidence is left in the
:data:`XAdESDisclosureStatus.PENDING_REVIEW` state rather than being treated as a failure. The check never mutates the
signature it examines and never accesses the network; every certificate involved is supplied by the caller from local
fixtures.
"""

from __future__ import annotations

from base64 import b64decode
from dataclasses import dataclass, field
from typing import Any, Iterable

import cryptography.exceptions
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import dsa, ec, padding, rsa, utils as asymmetric_utils
from lxml.etree import _Element

from ..algorithms import (
    SignatureConstructionMethod,
    CanonicalizationMethod,
    DigestAlgorithm,
    SignatureMethod,
    digest_algorithm_implementations,
)
from ..exceptions import InvalidInput
from ..util import add_pem_header, bits_to_bytes_unit, bytes_to_long, ds_tag
from .xades import XAdESProcessor


class XAdESClaim:
    """
    String identifiers for the XAdES compliance claims that can be checked through selective disclosure.
    """

    SIGNING_TIME = "signing_time"
    "The ``xades:SigningTime`` signed property."

    SIGNING_CERTIFICATE = "signing_certificate"
    "The ``xades:SigningCertificate`` / ``xades:SigningCertificateV2`` certificate digest property."

    SIGNATURE_POLICY = "signature_policy"
    "The ``xades:SignaturePolicyIdentifier`` property, including the ``xades:SigPolicyHash``."

    SIGNER_ROLE = "signer_role"
    "The ``xades:SignerRole/xades:ClaimedRoles`` property."

    DATA_OBJECT_FORMAT = "data_object_format"
    "The ``xades:SignedDataObjectProperties/xades:DataObjectFormat`` property."


class XAdESDisclosureStatus:
    """
    Outcomes of a selective disclosure check for a single piece of evidence or claim.
    """

    VERIFIED = "verified"
    "Every required piece of evidence was disclosed and independently recomputed."

    PENDING_REVIEW = "pending_review"
    "Some required evidence was withheld or could not be recomputed; the claim cannot be decided from the disclosure."

    FAILED = "failed"
    "All required evidence was available, but recomputation disproved the claim (a digest or signature mismatch)."


@dataclass(frozen=True)
class DisclosureEvidence:
    """
    A single piece of pre-existing evidence required to recompute a compliance claim.

    :param identifier: Stable name of the evidence item; see the identifiers exposed on
        :class:`XAdESDisclosureChecker`.
    :param description: Human-readable explanation of what this evidence proves and why the claim needs it.
    :param available: Whether the disclosure examined by the check contained everything needed to recompute it.
    :param recomputed: Whether recomputation against the disclosed material succeeded. ``False`` covers both evidence
        that was not available and evidence that failed recomputation; inspect :attr:`available` to tell them apart.
    """

    identifier: str
    description: str
    available: bool
    recomputed: bool


@dataclass(frozen=True)
class XAdESClaimReport:
    """
    The disclosure check result for one compliance claim.

    :param claim: One of the identifiers from :class:`XAdESClaim`.
    :param status: One of the identifiers from :class:`XAdESDisclosureStatus`.
    :param evidence: The evidence items required to independently recompute this claim, each marked with whether it
        was present in the disclosure and whether it recomputed.
    :param detail: Explanation of the first item that prevents independent recomputation, or a success summary.
    """

    claim: str
    status: str
    evidence: tuple[DisclosureEvidence, ...]
    detail: str


@dataclass(frozen=True)
class XAdESDisclosureReport:
    """
    The full result of a selective disclosure check.

    :param claim_reports: One :class:`XAdESClaimReport` per requested claim, in request order.
    :param required_evidence: The de-duplicated union of every evidence item required by any requested claim. This
        describes the complete set of pre-existing materials a reviewer needs to recompute the disclosed claims.
    """

    claim_reports: tuple[XAdESClaimReport, ...]
    required_evidence: tuple[DisclosureEvidence, ...] = field(default_factory=tuple)

    def report_for(self, claim: str) -> XAdESClaimReport:
        """
        Return the :class:`XAdESClaimReport` for the given claim identifier.
        """
        for claim_report in self.claim_reports:
            if claim_report.claim == claim:
                return claim_report
        raise InvalidInput(f"No report was produced for claim {claim}")

    @property
    def verified_claims(self) -> tuple[str, ...]:
        "Identifiers of the claims that were independently recomputed from the disclosed evidence."
        return tuple(report.claim for report in self.claim_reports if report.status == XAdESDisclosureStatus.VERIFIED)

    @property
    def pending_claims(self) -> tuple[str, ...]:
        "Identifiers of the claims that could not be independently recomputed and remain to be reviewed."
        return tuple(
            report.claim for report in self.claim_reports if report.status == XAdESDisclosureStatus.PENDING_REVIEW
        )


class XAdESDisclosureChecker(XAdESProcessor):
    """
    Perform read-only selective disclosure checks on XAdES signatures.

    The checker answers a narrow question: *given the evidence actually disclosed, which compliance claims can an
    external reviewer recompute independently, and which must remain under review?* It does not validate certificate
    chains, revocation, or schema conformance, and it never modifies the signature it is given. Every certificate
    used by the check is supplied by the caller from local fixtures (``trusted_signing_certificate`` or the
    certificates embedded in the signature itself); no network access is performed.

    Two layers of evidence are evaluated for every claim:

    * **Subordinate proof** -- the digest, identifier or value embedded in the signed ``xades:SignedProperties``
      element, recomputed against the material the disclosure provides (e.g. a signing certificate or a standalone
      signature policy document).
    * **Original signing environment** -- the ``xades:SignedProperties`` reference digest and the
      ``ds:SignatureValue``, recomputed to prove that the embedded subordinate proof was actually signed by the
      claimed signer. A ``trusted_signing_certificate`` from a local fixture is used as the trust anchor for this
      layer; if none is supplied, the signing environment cannot be independently recomputed and every claim stays
      pending review.
    """

    EVIDENCE_SIGNED_PROPERTIES_REFERENCE = "signed_properties_reference_digest"
    EVIDENCE_SIGNATURE_VALUE = "signature_value"
    EVIDENCE_SIGNING_CERTIFICATE = "signing_certificate"
    EVIDENCE_SIGNATURE_POLICY_DOCUMENT = "signature_policy_document"

    ALL_CLAIMS = (
        XAdESClaim.SIGNING_TIME,
        XAdESClaim.SIGNING_CERTIFICATE,
        XAdESClaim.SIGNATURE_POLICY,
        XAdESClaim.SIGNER_ROLE,
        XAdESClaim.DATA_OBJECT_FORMAT,
    )

    def check_disclosure(
        self,
        data: Any,
        *,
        claims: Iterable[str] | None = None,
        trusted_signing_certificate: x509.Certificate | str | bytes | None = None,
        signature_policy_documents: dict[str, bytes] | None = None,
    ) -> XAdESDisclosureReport:
        """
        Examine the XAdES signature in ``data`` and report which of the requested claims are independently
        recomputable from the disclosed evidence.

        The check is read-only: the input is parsed into a private working copy and never altered. Claims that cannot
        be recomputed because evidence was withheld are reported as
        :data:`XAdESDisclosureStatus.PENDING_REVIEW`; claims whose evidence is fully present but fails recomputation
        are reported as :data:`XAdESDisclosureStatus.FAILED`.

        :param data: The XAdES signature, as a string, byte string, or parsed lxml element.
        :param claims: Claim identifiers from :class:`XAdESClaim` to check. Defaults to every supported claim.
        :param trusted_signing_certificate: The signer certificate trusted through channels outside the signature
            (a local fixture). It anchors the original-signing-environment recomputation. It may be a parsed
            :class:`cryptography.x509.Certificate`, PEM text, or bare base64 DER as embedded in ``ds:X509Data``.
            When omitted, the signature value cannot be independently recomputed and claims stay pending review.
        :param signature_policy_documents: Mapping of signature policy identifier to the raw bytes of the policy
            document preserved by the archive. When the identifier of a ``xades:SignaturePolicyId`` is present in
            this mapping, its ``xades:SigPolicyHash`` is recomputed; otherwise the policy hash subordinate proof
            cannot be independently recomputed.
        """
        requested_claims = self._normalize_claims(claims)
        policy_documents = dict(signature_policy_documents or {})
        trust_anchor = self._load_certificate(trusted_signing_certificate)

        root = self.get_root(data)
        signature = self._get_signature(root)
        signed_info = self._find(signature, "ds:SignedInfo")
        signed_properties, signed_properties_reference = self._locate_signed_properties(signature, signed_info)

        envelope_evidence = self._evaluate_signing_envelope(
            signature=signature,
            signed_info=signed_info,
            signed_properties=signed_properties,
            signed_properties_reference=signed_properties_reference,
            trust_anchor=trust_anchor,
        )
        embedded_certificates = self._extract_embedded_certificates(signature)

        claim_reports: list[XAdESClaimReport] = []
        for claim in requested_claims:
            claim_reports.append(
                self._evaluate_claim(
                    claim=claim,
                    signed_properties=signed_properties,
                    envelope_evidence=envelope_evidence,
                    embedded_certificates=embedded_certificates,
                    trust_anchor=trust_anchor,
                    policy_documents=policy_documents,
                )
            )

        required_evidence = self._merge_evidence(evidence for report in claim_reports for evidence in report.evidence)
        return XAdESDisclosureReport(
            claim_reports=tuple(claim_reports),
            required_evidence=required_evidence,
        )

    def _get_signature(self, root: _Element) -> _Element:
        if root.tag == ds_tag("Signature"):
            return root
        return self._find(root, "ds:Signature")

    def _normalize_claims(self, claims: Iterable[str] | None) -> tuple[str, ...]:
        if claims is None:
            return self.ALL_CLAIMS
        requested = tuple(claims)
        unknown = [claim for claim in requested if claim not in self.ALL_CLAIMS]
        if unknown:
            raise InvalidInput(f"Unsupported XAdES disclosure claim(s): {unknown}")
        if len(set(requested)) != len(requested):
            raise InvalidInput("Duplicate claims were supplied to the XAdES disclosure check")
        return requested

    def _load_certificate(self, certificate: x509.Certificate | str | bytes | None) -> x509.Certificate | None:
        if certificate is None:
            return None
        if isinstance(certificate, x509.Certificate):
            return certificate
        return x509.load_pem_x509_certificate(add_pem_header(certificate))

    def _merge_evidence(self, evidence_items: Iterable[DisclosureEvidence]) -> tuple[DisclosureEvidence, ...]:
        merged: dict[str, DisclosureEvidence] = {}
        for evidence in evidence_items:
            existing = merged.get(evidence.identifier)
            if existing is None or (evidence.available and not existing.available):
                merged[evidence.identifier] = evidence
        return tuple(merged.values())

    def _evidence(
        self,
        identifier: str,
        description: str,
        *,
        available: bool,
        recomputed: bool,
    ) -> DisclosureEvidence:
        return DisclosureEvidence(
            identifier=identifier,
            description=description,
            available=available,
            recomputed=recomputed,
        )

    def _extract_embedded_certificates(self, signature: _Element) -> list[x509.Certificate]:
        certificates = []
        for certificate_node in self._findall(signature, "ds:KeyInfo/ds:X509Data/ds:X509Certificate"):
            if certificate_node.text:
                certificates.append(x509.load_pem_x509_certificate(add_pem_header(certificate_node.text)))
        return certificates

    def _locate_signed_properties(self, signature: _Element, signed_info: _Element) -> tuple[_Element, _Element]:
        signed_properties_nodes = self._findall(
            signature, "ds:Object/xades:QualifyingProperties/xades:SignedProperties"
        )
        if len(signed_properties_nodes) != 1:
            raise InvalidInput(
                f"Expected exactly one xades:SignedProperties element, found {len(signed_properties_nodes)}"
            )
        signed_properties = signed_properties_nodes[0]
        signed_properties_id = signed_properties.get("Id")
        if not signed_properties_id:
            raise InvalidInput("The xades:SignedProperties element is missing its Id attribute")

        matching_references = []
        for reference in self._findall(signed_info, "ds:Reference"):
            reference_type = reference.get("Type")
            reference_uri = reference.get("URI") or ""
            if (
                reference_type == "http://uri.etsi.org/01903#SignedProperties"
                or reference_uri == f"#{signed_properties_id}"
            ):
                matching_references.append(reference)
        if len(matching_references) != 1:
            raise InvalidInput(
                "Expected exactly one ds:Reference covering the xades:SignedProperties element, "
                f"found {len(matching_references)}"
            )
        return signed_properties, matching_references[0]

    def _evaluate_signing_envelope(
        self,
        *,
        signature: _Element,
        signed_info: _Element,
        signed_properties: _Element,
        signed_properties_reference: _Element,
        trust_anchor: x509.Certificate | None,
    ) -> tuple[DisclosureEvidence, ...]:
        reference_evidence = self._recompute_signed_properties_reference(
            signed_properties=signed_properties,
            reference=signed_properties_reference,
        )
        signature_evidence = self._recompute_signature_value(
            signature=signature,
            signed_info=signed_info,
            trust_anchor=trust_anchor,
        )
        return reference_evidence, signature_evidence

    def _recompute_signed_properties_reference(
        self, *, signed_properties: _Element, reference: _Element
    ) -> DisclosureEvidence:
        description = (
            "Recompute the ds:Reference digest over xades:SignedProperties to prove that the XAdES signed "
            "properties carrying the claim were not altered after signing."
        )
        try:
            digest_algorithm = DigestAlgorithm(self._find(reference, "ds:DigestMethod").get("Algorithm"))
            expected_digest = b64decode(self._find(reference, "ds:DigestValue").text)
            transforms = self._find(reference, "ds:Transforms", require=False)
            canonicalized = self._canonicalize_reference_payload(
                payload=signed_properties,
                transforms=transforms,
            )
            recomputed = self._get_digest(canonicalized, digest_algorithm)
        except (InvalidInput, ValueError):
            return self._evidence(
                self.EVIDENCE_SIGNED_PROPERTIES_REFERENCE, description, available=False, recomputed=False
            )
        return self._evidence(
            self.EVIDENCE_SIGNED_PROPERTIES_REFERENCE,
            description,
            available=True,
            recomputed=recomputed == expected_digest,
        )

    def _canonicalize_reference_payload(self, *, payload: _Element, transforms) -> bytes:
        if transforms is None:
            standalone = self._fromstring(self._tostring(payload, with_tail=False))
            return self._c14n(standalone, algorithm=CanonicalizationMethod.CANONICAL_XML_1_1)
        transform_nodes = self._findall(transforms, "ds:Transform")
        canonicalized = payload
        for transform in transform_nodes:
            algorithm = transform.get("Algorithm")
            if algorithm == SignatureConstructionMethod.enveloped.value:
                continue
            c14n_algorithm = CanonicalizationMethod(algorithm)
            standalone = self._fromstring(self._tostring(canonicalized, with_tail=False))
            canonicalized = self._c14n(standalone, algorithm=c14n_algorithm)
        if isinstance(canonicalized, _Element):
            standalone = self._fromstring(self._tostring(canonicalized, with_tail=False))
            canonicalized = self._c14n(standalone, algorithm=CanonicalizationMethod.CANONICAL_XML_1_1)
        return canonicalized

    def _recompute_signature_value(
        self,
        *,
        signature: _Element,
        signed_info: _Element,
        trust_anchor: x509.Certificate | None,
    ) -> DisclosureEvidence:
        description = (
            "Recompute the ds:SignatureValue over ds:SignedInfo using the trusted signing certificate from the "
            "original signing environment, binding every subordinate XAdES proof to the signer key."
        )
        if trust_anchor is None:
            return self._evidence(self.EVIDENCE_SIGNATURE_VALUE, description, available=False, recomputed=False)
        try:
            c14n_method = CanonicalizationMethod(self._find(signed_info, "ds:CanonicalizationMethod").get("Algorithm"))
            signature_method = SignatureMethod(self._find(signed_info, "ds:SignatureMethod").get("Algorithm"))
            raw_signature = b64decode(self._find(signature, "ds:SignatureValue").text)
            signed_info_c14n = self._c14n(signed_info, algorithm=c14n_method)
            self._verify_with_public_key(
                public_key=trust_anchor.public_key(),
                signature_method=signature_method,
                raw_signature=raw_signature,
                signed_info=signed_info_c14n,
            )
        except (InvalidInput, ValueError, cryptography.exceptions.InvalidSignature):
            return self._evidence(self.EVIDENCE_SIGNATURE_VALUE, description, available=True, recomputed=False)
        return self._evidence(self.EVIDENCE_SIGNATURE_VALUE, description, available=True, recomputed=True)

    def _verify_with_public_key(
        self,
        *,
        public_key,
        signature_method: SignatureMethod,
        raw_signature: bytes,
        signed_info: bytes,
    ) -> None:
        digest = digest_algorithm_implementations[signature_method]()
        if signature_method.name.startswith("ECDSA_"):
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                raise InvalidInput("Trusted signing certificate key does not match the ECDSA signature method")
            der_signature = self._encode_ecdsa_signature(raw_signature, public_key.key_size)
            public_key.verify(der_signature, data=signed_info, signature_algorithm=ec.ECDSA(digest))
        elif signature_method.name.startswith("DSA_"):
            if not isinstance(public_key, dsa.DSAPublicKey):
                raise InvalidInput("Trusted signing certificate key does not match the DSA signature method")
            der_signature = self._encode_dsa_signature(raw_signature)
            public_key.verify(der_signature, data=signed_info, algorithm=digest)
        elif signature_method.name.startswith("RSA_") or signature_method.name.startswith("SHA"):
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise InvalidInput("Trusted signing certificate key does not match the RSA signature method")
            if signature_method.name.startswith("RSA_"):
                asymmetric_padding = padding.PKCS1v15()
            else:
                asymmetric_padding = padding.PSS(mgf=padding.MGF1(digest), salt_length=digest.digest_size)
            public_key.verify(
                raw_signature,
                data=signed_info,
                padding=asymmetric_padding,
                algorithm=digest,
            )
        elif signature_method.name.startswith("HMAC_"):
            raise InvalidInput("HMAC XAdES signatures are not supported by the disclosure check")
        else:
            raise InvalidInput(f"Unsupported signature method: {signature_method}")

    def _encode_ecdsa_signature(self, raw_signature: bytes, key_size_bits: int) -> bytes:
        expected_length = bits_to_bytes_unit(key_size_bits) * 2
        if len(raw_signature) != expected_length:
            raise InvalidInput("Unexpected ECDSA signature length in ds:SignatureValue")
        component_length = len(raw_signature) // 2
        r_value = bytes_to_long(raw_signature[:component_length])
        s_value = bytes_to_long(raw_signature[component_length:])
        return asymmetric_utils.encode_dss_signature(r_value, s_value)

    def _encode_dsa_signature(self, raw_signature: bytes) -> bytes:
        if len(raw_signature) % 2 != 0:
            raise InvalidInput("Unexpected DSA signature length in ds:SignatureValue")
        component_length = len(raw_signature) // 2
        r_value = bytes_to_long(raw_signature[:component_length])
        s_value = bytes_to_long(raw_signature[component_length:])
        return asymmetric_utils.encode_dss_signature(r_value, s_value)

    def _evaluate_claim(
        self,
        *,
        claim: str,
        signed_properties: _Element,
        envelope_evidence: tuple[DisclosureEvidence, ...],
        embedded_certificates: list[x509.Certificate],
        trust_anchor: x509.Certificate | None,
        policy_documents: dict[str, bytes],
    ) -> XAdESClaimReport:
        if claim == XAdESClaim.SIGNING_TIME:
            claim_evidence = self._check_signing_time(signed_properties)
        elif claim == XAdESClaim.SIGNING_CERTIFICATE:
            claim_evidence = self._check_signing_certificate(
                signed_properties=signed_properties,
                embedded_certificates=embedded_certificates,
                trust_anchor=trust_anchor,
            )
        elif claim == XAdESClaim.SIGNATURE_POLICY:
            claim_evidence = self._check_signature_policy(
                signed_properties=signed_properties,
                policy_documents=policy_documents,
            )
        elif claim == XAdESClaim.SIGNER_ROLE:
            claim_evidence = self._check_signer_role(signed_properties)
        else:
            claim_evidence = self._check_data_object_format(signed_properties)

        all_evidence = tuple(envelope_evidence) + tuple(claim_evidence)
        return XAdESClaimReport(
            claim=claim,
            status=self._derive_status(all_evidence),
            evidence=all_evidence,
            detail=self._derive_detail(claim, all_evidence),
        )

    def _derive_status(self, evidence: tuple[DisclosureEvidence, ...]) -> str:
        if any(not item.available for item in evidence):
            return XAdESDisclosureStatus.PENDING_REVIEW
        if all(item.recomputed for item in evidence):
            return XAdESDisclosureStatus.VERIFIED
        return XAdESDisclosureStatus.FAILED

    def _derive_detail(self, claim: str, evidence: tuple[DisclosureEvidence, ...]) -> str:
        for item in evidence:
            if not item.available:
                return f"Claim {claim} remains under review: required evidence {item.identifier} was not disclosed."
            if not item.recomputed:
                return f"Claim {claim} failed recomputation: evidence {item.identifier} does not match the disclosure."
        return f"Claim {claim} was independently recomputed from the disclosed evidence."

    def _signed_signature_properties(self, signed_properties: _Element) -> _Element:
        return self._find(signed_properties, "xades:SignedSignatureProperties")

    def _check_signing_time(self, signed_properties: _Element) -> tuple[DisclosureEvidence, ...]:
        description = (
            "Read the xades:SigningTime value embedded in the signed properties. Its authenticity is established "
            "through the signing-environment evidence; no separate external document is required."
        )
        signing_time = self._find(
            self._signed_signature_properties(signed_properties), "xades:SigningTime", require=False
        )
        if signing_time is None or not (signing_time.text and signing_time.text.strip()):
            return (self._evidence("signing_time_value", description, available=False, recomputed=False),)
        return (self._evidence("signing_time_value", description, available=True, recomputed=True),)

    def _check_signing_certificate(
        self,
        *,
        signed_properties: _Element,
        embedded_certificates: list[x509.Certificate],
        trust_anchor: x509.Certificate | None,
    ) -> tuple[DisclosureEvidence, ...]:
        description = (
            "Recompute every xades:CertDigest under xades:SigningCertificate(V2) against the DER-encoded signing "
            "certificate preserved in ds:KeyInfo/ds:X509Data, and confirm the first digest identifies the trusted "
            "signing certificate from the original signing environment."
        )
        signed_signature_properties = self._signed_signature_properties(signed_properties)
        signing_certificate_node = self._find(signed_signature_properties, "xades:SigningCertificate", require=False)
        signing_certificate_v2_node = self._find(
            signed_signature_properties, "xades:SigningCertificateV2", require=False
        )
        if signing_certificate_node is None and signing_certificate_v2_node is None:
            return (self._evidence(self.EVIDENCE_SIGNING_CERTIFICATE, description, available=False, recomputed=False),)

        candidate_certificates = list(embedded_certificates)
        if trust_anchor is not None and not any(
            certificate.public_bytes(Encoding.DER) == trust_anchor.public_bytes(Encoding.DER)
            for certificate in candidate_certificates
        ):
            candidate_certificates.append(trust_anchor)

        if not candidate_certificates:
            return (self._evidence(self.EVIDENCE_SIGNING_CERTIFICATE, description, available=False, recomputed=False),)

        node = signing_certificate_v2_node if signing_certificate_v2_node is not None else signing_certificate_node
        recomputed = self._recompute_cert_digests(
            signing_certificate_node=node,
            candidate_certificates=candidate_certificates,
            trust_anchor=trust_anchor,
        )
        return (
            self._evidence(
                self.EVIDENCE_SIGNING_CERTIFICATE,
                description,
                available=True,
                recomputed=recomputed,
            ),
        )

    def _recompute_cert_digests(
        self,
        *,
        signing_certificate_node: _Element,
        candidate_certificates: list[x509.Certificate],
        trust_anchor: x509.Certificate | None,
    ) -> bool:
        for cert_index, cert_node in enumerate(self._findall(signing_certificate_node, "xades:Cert")):
            cert_digest_node = self._find(cert_node, "xades:CertDigest")
            digest_algorithm = DigestAlgorithm(self._find(cert_digest_node, "ds:DigestMethod").get("Algorithm"))
            digest_implementation = digest_algorithm_implementations[digest_algorithm]()
            expected_digest = b64decode(self._find(cert_digest_node, "ds:DigestValue").text)
            fingerprints = [certificate.fingerprint(digest_implementation) for certificate in candidate_certificates]
            if expected_digest not in fingerprints:
                return False
            if cert_index == 0 and trust_anchor is not None:
                if expected_digest != trust_anchor.fingerprint(digest_implementation):
                    return False
        return True

    def _check_signature_policy(
        self,
        *,
        signed_properties: _Element,
        policy_documents: dict[str, bytes],
    ) -> tuple[DisclosureEvidence, ...]:
        policy_description = (
            "Read the xades:SignaturePolicyIdentifier embedded in the signed properties. Its presence and "
            "identifier are established through the signing-environment evidence."
        )
        signed_signature_properties = self._signed_signature_properties(signed_properties)
        policy_identifier = self._find(signed_signature_properties, "xades:SignaturePolicyIdentifier", require=False)
        if policy_identifier is None:
            return (
                self._evidence("signature_policy_identifier", policy_description, available=False, recomputed=False),
            )

        evidence = [self._evidence("signature_policy_identifier", policy_description, available=True, recomputed=True)]

        explicit_policy = self._find(policy_identifier, "xades:SignaturePolicyId", require=False)
        if explicit_policy is not None:
            identifier_node = self._find(explicit_policy, "xades:SigPolicyId/xades:Identifier")
            policy_identifier_value = identifier_node.text
            hash_description = (
                "Recompute xades:SigPolicyHash against the standalone signature policy document preserved by the "
                "archive. Without the policy document the hash subordinate proof cannot be independently recomputed."
            )
            sig_policy_hash = self._find(explicit_policy, "xades:SigPolicyHash")
            digest_algorithm = DigestAlgorithm(self._find(sig_policy_hash, "ds:DigestMethod").get("Algorithm"))
            expected_digest = b64decode(self._find(sig_policy_hash, "ds:DigestValue").text)
            policy_document = (
                policy_documents.get(policy_identifier_value) if policy_identifier_value is not None else None
            )
            if policy_document is None:
                evidence.append(
                    self._evidence(
                        self.EVIDENCE_SIGNATURE_POLICY_DOCUMENT,
                        hash_description,
                        available=False,
                        recomputed=False,
                    )
                )
            else:
                recomputed_digest = self._get_digest(policy_document, digest_algorithm)
                evidence.append(
                    self._evidence(
                        self.EVIDENCE_SIGNATURE_POLICY_DOCUMENT,
                        hash_description,
                        available=True,
                        recomputed=recomputed_digest == expected_digest,
                    )
                )
        return tuple(evidence)

    def _check_signer_role(self, signed_properties: _Element) -> tuple[DisclosureEvidence, ...]:
        description = (
            "Read the xades:SignerRole/xades:ClaimedRoles values embedded in the signed properties. Claimed roles "
            "are self-assertions; their authenticity is established through the signing-environment evidence."
        )
        claimed_roles = self._find(
            self._signed_signature_properties(signed_properties),
            "xades:SignerRole/xades:ClaimedRoles",
            require=False,
        )
        if claimed_roles is None or not self._findall(claimed_roles, "xades:ClaimedRole"):
            return (self._evidence("signer_claimed_roles", description, available=False, recomputed=False),)
        return (self._evidence("signer_claimed_roles", description, available=True, recomputed=True),)

    def _check_data_object_format(self, signed_properties: _Element) -> tuple[DisclosureEvidence, ...]:
        description = (
            "Read the xades:DataObjectFormat elements (Description and MimeType) embedded in the signed "
            "properties. Their authenticity is established through the signing-environment evidence."
        )
        signed_data_object_properties = self._find(signed_properties, "xades:SignedDataObjectProperties", require=False)
        if signed_data_object_properties is None or not self._findall(
            signed_data_object_properties, "xades:DataObjectFormat"
        ):
            return (self._evidence("data_object_format", description, available=False, recomputed=False),)
        return (self._evidence("data_object_format", description, available=True, recomputed=True),)
