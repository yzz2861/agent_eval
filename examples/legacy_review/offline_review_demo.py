#!/usr/bin/env python
"""
Offline legacy-policy review demonstration.

The script is fully offline: all cryptographic keys, trusted timestamps and admission policy tables are
generated locally, and no network access takes place. It walks through the complete workflow that a
publisher follows when retiring an old XML signature algorithm:

1. A historical document carrying two acceptance records stamped on different dates is signed with the
   retired RSA-SHA1/SHA-1 combination, and a trusted time evidence token binds it to its historical date.
2. The :class:`~signxml.legacy_review.OfflineReviewer` produces a checklist that keeps the historical
   acceptance (valid under the old v1 policy) separate from the current rejection (v2 policy), concluding
   that the document must be re-signed.
3. An upgrade re-signs the exact verified material under RSA-SHA256 and emits a signed receipt committing to
   both document fingerprints; the reissued document now passes the current policy.
4. A second document whose signed body was replaced is reviewed with the same inputs; its checklist shows
   the digest failure and a tampered rejection, demonstrating that the two documents are handled differently.

Run it with the project virtual environment::

    .venv/bin/python examples/legacy_review/offline_review_demo.py
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric import rsa
from lxml import etree

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from signxml import SignatureConstructionMethod
from signxml.algorithms import DigestAlgorithm, SignatureMethod
from signxml.legacy_review import (
    LegacyDocumentSigner,
    OfflineReviewer,
    ReviewOutcome,
    build_default_policy_table,
    issue_trusted_time_evidence,
    issue_upgrade,
    review_reissued_document,
    verify_upgrade_receipt,
)

HISTORICAL_DATE = datetime(2023, 6, 1, tzinfo=timezone.utc)
REVIEW_DATE = datetime(2025, 6, 1, tzinfo=timezone.utc)
UPGRADE_DATE = datetime(2025, 6, 2, tzinfo=timezone.utc)
OUTPUT_DIRECTORY = os.path.join(os.path.dirname(__file__), "output")


def make_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def build_document(body_text):
    return etree.fromstring(
        '<document xmlns="urn:example:acceptance">'
        '<acceptance-record date="2023-05-01">初验通过</acceptance-record>'
        '<acceptance-record date="2023-06-01">复验通过</acceptance-record>'
        f"<body>{body_text}</body>"
        "</document>"
    )


def write_artifact(filename, content):
    path = os.path.join(OUTPUT_DIRECTORY, filename)
    mode = "wb" if isinstance(content, bytes) else "w"
    with open(path, mode) as handle:
        handle.write(content)
    return path


def section(title):
    print()
    print("=" * 78)
    print(title)
    print("=" * 78)


def main():
    os.makedirs(OUTPUT_DIRECTORY, exist_ok=True)
    document_key = make_key()
    evidence_key = make_key()

    section("1. Build the historical document with two dated acceptance records")
    legacy_signer = LegacyDocumentSigner(
        method=SignatureConstructionMethod.enveloped,
        signature_algorithm=SignatureMethod.RSA_SHA1,
        digest_algorithm=DigestAlgorithm.SHA1,
    )
    legacy_root = legacy_signer.sign(build_document("历史验收结论正文"), key=document_key)
    legacy_document = etree.tostring(legacy_root, encoding="utf-8", xml_declaration=True)
    legacy_path = write_artifact("historical-sha1-document.xml", legacy_document)
    print(f"Wrote legacy RSA-SHA1 document: {legacy_path}")

    section("2. Issue trusted time evidence and review under both policy versions")
    evidence = issue_trusted_time_evidence(
        legacy_document, attestation_key=evidence_key, attestation_time=HISTORICAL_DATE
    )
    write_artifact("trusted-time-evidence.xml", evidence.serialize())
    reviewer = OfflineReviewer(
        trusted_public_key=document_key.public_key(),
        trusted_evidence_key=evidence_key.public_key(),
        policy_tables=build_default_policy_table(),
        now=REVIEW_DATE,
    )
    historical_report = reviewer.review(legacy_document, time_evidence=evidence)
    print(historical_report.render_checklist())
    assert historical_report.outcome is ReviewOutcome.ACCEPTED_HISTORIC_REISSUE_NEEDED

    section("3. Re-sign the same verified material and emit the upgrade receipt")
    bundle = issue_upgrade(reviewer, legacy_document, reissue_key=document_key, time_evidence=evidence)
    reissued_path = write_artifact("reissued-sha256-document.xml", bundle.reissued_document)
    receipt_path = write_artifact("upgrade-receipt.xml", bundle.receipt.serialize())
    print(f"Wrote reissued RSA-SHA256 document: {reissued_path}")
    print(f"Wrote signed upgrade receipt: {receipt_path}")
    receipt_ok, receipt_items = verify_upgrade_receipt(
        bundle,
        original_document=legacy_document,
        trusted_reissue_key=document_key.public_key(),
    )
    print(f"Receipt commits to the same verified material: {receipt_ok}")
    assert receipt_ok
    for item in receipt_items:
        print(f"  [PASS] {item.name}: {item.detail}")

    fresh_evidence = issue_trusted_time_evidence(
        bundle.reissued_document, attestation_key=evidence_key, attestation_time=UPGRADE_DATE
    )
    reissued_report = review_reissued_document(reviewer, bundle, current_time_evidence=fresh_evidence)
    print()
    print(reissued_report.render_checklist())
    assert reissued_report.outcome is ReviewOutcome.ACCEPTED_HISTORIC_CURRENT

    section("4. Review a body-swapped document carrying the same old signature structure")
    swapped_document = legacy_document.replace("历史验收结论正文".encode("utf-8"), "被偷换后的另一正文".encode("utf-8"))
    write_artifact("body-swapped-document.xml", swapped_document)
    swapped_report = reviewer.review(swapped_document, time_evidence=evidence)
    print(swapped_report.render_checklist())
    assert swapped_report.outcome is ReviewOutcome.REJECTED_TAMPERED

    section("5. Side-by-side outcome comparison")
    print(f"Re-signed document outcome : {reissued_report.outcome.value}")
    print(f"Body-swapped document outcome: {swapped_report.outcome.value}")
    print(f"Re-signed reissue required : {reissued_report.reissue_required}")
    print(f"Swapped reissue required  : {swapped_report.reissue_required}")
    assert reissued_report.outcome != swapped_report.outcome
    print()
    print("The two checklists make the difference explicit: the re-signed document passes every")
    print("current-policy check, while the body-swapped document fails cryptographic verification.")


if __name__ == "__main__":
    main()
