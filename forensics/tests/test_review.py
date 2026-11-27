import json
import os
from datetime import datetime, timezone

import pytest

import pgpy
from pgpy.constants import (
    CompressionAlgorithm,
    HashAlgorithm,
    KeyFlags,
    PubKeyAlgorithm,
    SymmetricKeyAlgorithm,
)

from forensics.review import (
    ApprovalWindow,
    Assessment,
    EvidenceWindow,
    build_report,
    review_notice,
)

EXAMPLES = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        os.pardir, "examples")

APPROVAL = ApprovalWindow(
    not_before=datetime(2026, 3, 1, tzinfo=timezone.utc),
    not_after=datetime(2026, 3, 31, 23, 59, 59, tzinfo=timezone.utc),
    issued_by="compliance-office",
)

CLAIMED = datetime(2026, 3, 10, 9, 30, 0, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def signing_key():
    key = pgpy.PGPKey.new(
        PubKeyAlgorithm.RSAEncryptOrSign, 2048,
        created=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    uid = pgpy.PGPUID.new("Test Custodian", email="custodian@example.org")
    key.add_uid(
        uid,
        usage={KeyFlags.Sign},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.ZLIB],
    )
    return key


def _detached(key, text, created=CLAIMED):
    return str(key.sign(text.encode("utf-8"), detached=True, created=created))


def test_example_signatures_verify_with_identical_claimed_times():
    key, _ = pgpy.PGPKey.from_file(os.path.join(EXAMPLES, "custodian_pub.asc"))
    claimed = []
    for notice_id in ("notice-a", "notice-b"):
        with open(os.path.join(EXAMPLES, notice_id + ".txt"), "rb") as fh:
            notice = fh.read()
        with open(os.path.join(EXAMPLES, notice_id + ".txt.sig.asc"), "rb") as fh:
            sig = pgpy.PGPSignature.from_blob(fh.read())
        assert key.verify(notice, sig)
        claimed.append(sig.created)
    # the printed signing times of the two notices are identical
    assert str(claimed[0]) == str(claimed[1])
    assert claimed[0] == CLAIMED


def test_archive_report_preserves_distinction():
    with open(os.path.join(EXAMPLES, "archive_report.json"),
              encoding="utf-8") as fh:
        report = json.load(fh)
    notices = {n["notice_id"]: n for n in report["notices"]}
    assert set(notices) == {"notice-a", "notice-b"}

    # identical printed claimed signing times
    assert notices["notice-a"]["claimed_signing_time"] == \
        notices["notice-b"]["claimed_signing_time"]

    # but the archive keeps the two cases clearly apart
    assert notices["notice-a"]["assessment"] == "proven_before_approval"
    assert notices["notice-a"]["external_receipt"]["window"]["start"] < \
        report["approved_window"]["not_before"]
    assert notices["notice-b"]["assessment"] == "self_declared_only"
    assert notices["notice-b"]["external_receipt"] is None
    assert notices["notice-b"]["independent_preservation"] is None


def test_receipt_before_approval_proves_early_signing(signing_key):
    review = review_notice(
        "n1", b"payload", _detached(signing_key, "payload"), signing_key.pubkey,
        APPROVAL,
        external_receipt=EvidenceWindow(
            "external_receipt",
            datetime(2026, 2, 20, 8, 15, tzinfo=timezone.utc),
            source="mail-gateway log",
        ),
    )
    assert review.signature_valid
    assert review.claimed_within_approved_window
    assert review.assessment is Assessment.PROVEN_BEFORE_APPROVAL


def test_self_declared_only_without_external_evidence(signing_key):
    review = review_notice(
        "n2", b"payload", _detached(signing_key, "payload"), signing_key.pubkey,
        APPROVAL,
    )
    assert review.signature_valid
    assert review.claimed_within_approved_window
    assert review.assessment is Assessment.SELF_DECLARED_ONLY


def test_same_claimed_time_yields_distinct_archive_entries(signing_key):
    sig = _detached(signing_key, "payload")
    proven = review_notice(
        "n1", b"payload", sig, signing_key.pubkey, APPROVAL,
        external_receipt=EvidenceWindow(
            "external_receipt",
            datetime(2026, 2, 20, 8, 15, tzinfo=timezone.utc),
        ),
    )
    declared = review_notice(
        "n2", b"payload", sig, signing_key.pubkey, APPROVAL,
    )
    report = build_report([proven, declared], APPROVAL)
    first, second = report["notices"]
    assert first["claimed_signing_time"] == second["claimed_signing_time"]
    assert first["assessment"] == "proven_before_approval"
    assert second["assessment"] == "self_declared_only"


def test_evidence_between_approval_and_claim_contradicts(signing_key):
    review = review_notice(
        "n3", b"payload", _detached(signing_key, "payload"), signing_key.pubkey,
        APPROVAL,
        independent_preservation=EvidenceWindow(
            "independent_preservation",
            datetime(2026, 3, 5, 12, 0, tzinfo=timezone.utc),
        ),
    )
    assert review.assessment is Assessment.CLAIM_CONTRADICTED


def test_evidence_after_claim_corroborates(signing_key):
    review = review_notice(
        "n4", b"payload", _detached(signing_key, "payload"), signing_key.pubkey,
        APPROVAL,
        independent_preservation=EvidenceWindow(
            "independent_preservation",
            datetime(2026, 4, 2, 11, 0, tzinfo=timezone.utc),
        ),
    )
    assert review.assessment is Assessment.CORROBORATED


def test_invalid_signature_is_archived_as_such(signing_key):
    review = review_notice(
        "n5", b"tampered payload", _detached(signing_key, "payload"),
        signing_key.pubkey, APPROVAL,
    )
    assert not review.signature_valid
    assert review.assessment is Assessment.SIGNATURE_INVALID
    assert review.claimed_signing_time == CLAIMED
