# ruff: noqa: PLR2004
import json

import pytest

from securesystemslib.consumption import (
    reconcile_consumption,
    reconcile_signed_archive,
    verify_signed_record,
)
from securesystemslib.dsse import Envelope
from securesystemslib.formats import encode_canonical
from securesystemslib.signer import CryptoSigner


def grant(approval_id="grant-1", quota=2, **extra):
    return {"approval_id": approval_id, "quota": quota, **extra}


def receipt(receipt_id, artifact, repo="repo-a", approval_id="grant-1", **extra):
    return {
        "receipt_id": receipt_id,
        "approval_id": approval_id,
        "repository_id": repo,
        "artifact_id": artifact,
        **extra,
    }


def test_identical_redelivery_is_counted_once():
    repeated = receipt("r1", "sha256:aaa", sequence=1)
    report = reconcile_consumption(
        [grant()],
        [
            repeated,
            dict(repeated),
            receipt("r2", "sha256:bbb", repo="repo-b", sequence=2),
        ],
    )
    ledger = report.ledgers["grant-1"]
    balance = ledger.balance()

    assert balance["observed_uses"] == 2
    assert balance["definite_excess"] == 0
    assert balance["duplicate_deliveries"] == 1
    assert report.status == "within_quota"
    assert report.ok is True


def test_same_artifact_in_different_repos_merges_identity():
    report = reconcile_consumption(
        [grant()],
        [
            receipt("r1", "sha256:aaa", repo="repo-a"),
            receipt("r2", "sha256:aaa", repo="repo-b"),
            receipt("r3", "sha256:bbb", repo="repo-c"),
        ],
    )
    ledger = report.ledgers["grant-1"]
    usage = next(
        item for item in ledger.consumptions if item.artifact_id == "sha256:aaa"
    )

    assert ledger.artifact_count == 2
    assert ledger.definite_excess == 0
    assert usage.repositories == {"repo-a", "repo-b"}


def test_three_distinct_artifacts_show_definite_excess():
    report = reconcile_consumption(
        [grant(quota=2)],
        [
            receipt("r1", "sha256:aaa"),
            receipt("r2", "sha256:bbb", repo="repo-b"),
            receipt("r3", "sha256:ccc", repo="repo-c"),
        ],
    )

    balance = report.ledgers["grant-1"].balance()
    assert balance["observed_uses"] == 3
    assert balance["definite_excess"] == 1
    assert report.status == "definite_excess"
    assert report.ok is False
    assert any(f.code == "definite_excess" for f in report.findings)


def test_event_basis_counts_distinct_uses_of_same_artifact():
    report = reconcile_consumption(
        [grant(quota=2)],
        [
            receipt("r1", "sha256:aaa", event_id="use-1"),
            receipt("r2", "sha256:aaa", repo="repo-b", event_id="use-2"),
            receipt("r3", "sha256:aaa", repo="repo-c", event_id="use-3"),
        ],
        quota_basis="event",
    )

    assert report.ledgers["grant-1"].observed_uses == 3
    assert report.ledgers["grant-1"].definite_excess == 1


def test_revocation_order_separates_after_and_unorderable_uses():
    report = reconcile_consumption(
        [grant(quota=5)],
        [
            receipt("before", "sha256:aaa", sequence=4),
            receipt("after", "sha256:bbb", sequence=11),
            receipt("unknown", "sha256:ccc"),
        ],
        [{"approval_id": "grant-1", "sequence": 10}],
    )
    ledger = report.ledgers["grant-1"]
    states = {item.receipt_ids.copy().pop(): item.state for item in ledger.consumptions}

    assert str(states["before"]) == "pre_revocation"
    assert str(states["after"]) == "post_revocation"
    assert str(states["unknown"]) == "order_indeterminate"
    assert any(f.code == "post_revocation_use" for f in report.findings)
    assert any(f.code == "unorderable_use" for f in report.findings)
    assert report.status == "revocation_violation"


def test_revocation_without_order_makes_uses_indeterminate():
    report = reconcile_consumption(
        [grant(quota=5)],
        [receipt("r1", "sha256:aaa", sequence=2)],
        [{"approval_id": "grant-1", "revoked": True}],
    )

    consumption = report.ledgers["grant-1"].consumptions[0]
    assert str(consumption.state) == "order_indeterminate"
    assert any(f.code == "revocation_without_order" for f in report.findings)


def test_partial_repository_still_allows_definite_excess():
    report = reconcile_consumption(
        [grant(quota=2)],
        [
            receipt("r1", "sha256:aaa"),
            receipt("r2", "sha256:bbb"),
            receipt("r3", "sha256:ccc"),
        ],
        coverage=[{"repository_id": "repo-a", "partial": True, "segment_id": "page-1"}],
    )
    ledger = report.ledgers["grant-1"]

    assert ledger.definite_excess == 1
    assert ledger.unknown_scopes[0].additional_uses_max is None
    assert report.status == "definite_excess"
    assert "unknown scope" in report.explain()


def test_partial_coverage_reports_independent_unknown_range():
    report = reconcile_consumption(
        [grant(quota=2)],
        [receipt("r1", "sha256:aaa")],
        coverage=[
            {
                "repository_id": "repo-a",
                "complete": False,
                "missing_count": 4,
                "segment_id": "segment-2",
            }
        ],
    )
    ledger = report.ledgers["grant-1"]
    balance = ledger.balance()

    assert balance["definite_excess"] == 0
    assert balance["unknown_additional_uses_max"] == 4
    assert balance["worst_case_excess"] == 3
    assert balance["possible_excess"] is True
    assert len(report.unknown_scopes) == 1
    assert report.unknown_scopes[0].segment_id == "segment-2"
    assert any(f.code == "possible_excess" for f in report.findings)


def test_repository_report_segments_can_carry_receipts():
    report = reconcile_consumption(
        {
            "grants": [grant(quota=2)],
            "repository_reports": [
                {
                    "repository_id": "repo-a",
                    "partial": True,
                    "receipts": [
                        receipt("r1", "sha256:aaa"),
                        receipt("r2", "sha256:bbb"),
                        receipt("r3", "sha256:ccc"),
                    ],
                }
            ],
        }
    )

    assert report.ledgers["grant-1"].definite_excess == 1
    assert report.unknown_scopes[0].repository_id == "repo-a"


def test_report_is_json_serializable_and_explainable():
    report = reconcile_consumption(
        [grant()],
        [receipt("r1", "sha256:aaa")],
        coverage=[{"repository_id": "repo-a", "partial": True}],
    )

    encoded = json.dumps(report.to_dict(), ensure_ascii=False)
    assert "unknown_scope" in encoded
    assert "Offline consumption reconciliation" in report.explain()


def sign_record(payload, signer):
    signature = signer.sign(encode_canonical(payload).encode()).to_dict()
    return {"payload": payload, "signature": signature}


def test_securesystemslib_signature_backend_verifies_records():
    signer = CryptoSigner.generate_ed25519()
    approval_payload = grant()
    receipt_payload = receipt("r1", "sha256:aaa")
    signed_approval = sign_record(approval_payload, signer)
    signed_receipt = sign_record(receipt_payload, signer)

    payload, metadata = verify_signed_record(signed_approval, [signer.public_key])
    assert payload["approval_id"] == "grant-1"
    assert metadata["accepted_keyids"] == [signer.public_key.keyid]

    report = reconcile_signed_archive(
        keys=[signer.public_key],
        approvals=[signed_approval],
        receipts=[signed_receipt],
    )
    assert report.verified_records == 2
    assert report.invalid_records == []
    assert report.ok is True


def test_tampered_signed_approval_is_reported_not_trusted():
    signer = CryptoSigner.generate_ed25519()
    signed_approval = sign_record(grant(quota=2), signer)
    signed_approval["payload"]["quota"] = 99

    report = reconcile_signed_archive(
        keys=[signer.public_key],
        approvals=[signed_approval],
        receipts=[],
    )

    assert report.verified_records == 0
    assert len(report.invalid_records) == 1
    assert any(f.code == "invalid_signature" for f in report.findings)
    assert report.ok is False


def test_dsse_envelope_is_supported():
    signer = CryptoSigner.generate_ed25519()
    approval = grant()
    envelope = Envelope(
        payload=json.dumps(approval, separators=(",", ":")).encode(),
        payload_type="application/json",
        signatures={},
    )
    envelope.sign(signer)

    payload, metadata = verify_signed_record(envelope.to_dict(), [signer.public_key])
    assert payload["quota"] == 2
    assert signer.public_key.keyid in metadata["accepted_keyids"]


def test_invalid_quota_is_collected():
    report = reconcile_consumption([{"approval_id": "bad", "quota": -1}])
    assert report.ledgers == {}
    assert len(report.invalid_records) == 1
    assert report.ok is False


@pytest.mark.parametrize("basis", ["artifact", "event"])
def test_supported_quota_basis(basis):
    report = reconcile_consumption([grant()], [], quota_basis=basis)
    assert report.ledgers["grant-1"].basis == basis


def test_unknown_quota_basis_rejected():
    with pytest.raises(ValueError, match="quota_basis"):
        reconcile_consumption([grant()], [], quota_basis="digest")
