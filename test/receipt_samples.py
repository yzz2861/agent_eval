"""
Parallel-revision sample group for the offline receipt check.

The sample keeps one original and two revisions that share it as their predecessor. The revisions are reviewed by two
different people. Run this module directly to print how the receipt check reports the correct pairing, a swapped
filing, and an input-order change.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from lxml import etree

from signxml import SignatureConfiguration, XMLSigner, XMLVerifier
from signxml.receipts import (
    ReceiptPolicy,
    ReceiptRole,
    VerifyResult,
    XMLReceiptVerifier,
    content_digest,
)

NS = "urn:example:legal-documents"


def _q(name: str) -> str:
    return f"{{{NS}}}{name}"


def _element(name: str, **attributes: str) -> etree._Element:
    return etree.Element(_q(name), nsmap={None: NS}, **attributes)


@dataclass(frozen=True)
class SampleParty:
    key: rsa.RSAPrivateKey
    certificate: x509.Certificate


@dataclass(frozen=True)
class ParallelRevisionSamples:
    """Signed objects for one original with two independently reviewed revisions."""

    original: VerifyResult
    revision_a: VerifyResult
    revision_b: VerifyResult
    receipt_a: VerifyResult
    receipt_b: VerifyResult
    policy: ReceiptPolicy

    @property
    def results(self) -> tuple[VerifyResult, ...]:
        return (self.original, self.revision_a, self.revision_b, self.receipt_a, self.receipt_b)


def make_party(common_name: str) -> SampleParty:
    """Create a short-lived local RSA key and matching self-signed certificate."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, common_name)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2020, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2035, 1, 1, tzinfo=timezone.utc))
        .sign(key, hashes.SHA256())
    )
    return SampleParty(key=key, certificate=certificate)


def _sign_and_verify(element: etree._Element, party: SampleParty) -> VerifyResult:
    signed = XMLSigner().sign(element, key=party.key, cert=[party.certificate])
    return XMLVerifier().verify(
        signed,
        x509_cert=party.certificate,
        expect_config=SignatureConfiguration(location="./"),
    )


def _add_document(
    kind: str,
    object_id: str,
    body: str,
    *,
    predecessor: etree._Element | None = None,
    sequence: int | None = None,
    scope: str | None = None,
) -> tuple[etree._Element, etree._Element | None]:
    document = _element("Original" if kind == "original" else "Revision", Id=object_id)
    etree.SubElement(document, _q("Body")).text = body
    declaration = etree.SubElement(
        document,
        _q("ContentDeclaration"),
        Kind=kind,
        Object=object_id,
        DigestMethod="sha256",
    )
    if sequence is not None:
        declaration.set("Sequence", str(sequence))
    if scope is not None:
        declaration.set("Scope", scope)
    predecessor_node = None
    if predecessor is not None:
        predecessor_node = etree.SubElement(
            declaration,
            _q("Predecessor"),
            Ref=predecessor.get("Id"),
            DigestMethod="sha256",
        )
        predecessor_node.set("Digest", content_digest(predecessor, "sha256"))
    declaration.set("Digest", content_digest(document, "sha256"))
    return document, predecessor_node


def _add_receipt(
    receipt_id: str,
    target: etree._Element,
    *,
    role: str,
    scope: str,
) -> etree._Element:
    receipt = _element("Receipt", Id=receipt_id)
    etree.SubElement(receipt, _q("Decision")).text = "Approved"
    etree.SubElement(
        receipt,
        _q("ReceiptDeclaration"),
        Role=role,
        Scope=scope,
        Target=target.get("Id"),
        DigestMethod="sha256",
        Digest=content_digest(target, "sha256"),
    )
    return receipt


def build_parallel_revision_samples() -> ParallelRevisionSamples:
    """Build and verify the two-revision sample group used by the regression tests."""
    author = make_party("legal-author")
    editor_a = make_party("editor-a")
    editor_b = make_party("editor-b")
    reviewer_a = make_party("reviewer-a")
    reviewer_b = make_party("reviewer-b")

    original, _ = _add_document("original", "original-1", "Original enforcement notice")
    revision_a, _ = _add_document(
        "revision",
        "revision-a",
        "Revision A: add the payment deadline",
        predecessor=original,
        sequence=2,
        scope="legal-review",
    )
    revision_b, _ = _add_document(
        "revision",
        "revision-b",
        "Revision B: add the appeal address",
        predecessor=original,
        sequence=2,
        scope="legal-review",
    )
    receipt_a = _add_receipt("receipt-a", revision_a, role="reviewer", scope="legal-review")
    receipt_b = _add_receipt("receipt-b", revision_b, role="reviewer", scope="legal-review")

    policy = ReceiptPolicy(
        roles=(
            ReceiptRole(
                "reviewer",
                {"CN=reviewer-a", "CN=reviewer-b"},
                scopes={"legal-review"},
                document_kinds={"revision"},
            ),
        ),
        required_roles={"revision": ("reviewer",)},
    )
    return ParallelRevisionSamples(
        original=_sign_and_verify(original, author),
        revision_a=_sign_and_verify(revision_a, editor_a),
        revision_b=_sign_and_verify(revision_b, editor_b),
        receipt_a=_sign_and_verify(receipt_a, reviewer_a),
        receipt_b=_sign_and_verify(receipt_b, reviewer_b),
        policy=policy,
    )


def demo() -> None:
    """Print the sample group under matching, exchanged, and reordered review materials."""
    samples = build_parallel_revision_samples()
    verifier = XMLReceiptVerifier(samples.policy)

    print("== matching review materials ==")
    print(verifier.verify(samples.results))

    print("\n== receipt-a used as revision-b's review material; receipt-b withheld ==")
    exchanged = (samples.original, samples.revision_a, samples.revision_b, samples.receipt_a)
    print(verifier.verify(exchanged))

    print("\n== both receipts present, but supplied in the opposite order ==")
    reordered = (
        samples.receipt_b,
        samples.revision_b,
        samples.original,
        samples.receipt_a,
        samples.revision_a,
    )
    print(verifier.verify(reordered))


if __name__ == "__main__":
    demo()
