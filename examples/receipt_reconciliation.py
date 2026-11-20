"""Offline acceptance example for approval receipt reconciliation.

Run from the repository root::

    PYTHONPATH=. python examples/receipt_reconciliation.py

The first case uses two approvals and three receipts.  A greedy matcher would
give A1 to the flexible release seat and then fail the security seat; the
global matcher moves the release seat to A2 and succeeds.

The second case has no security receipt, so the reviewer-facing result names
the missing signature type explicitly.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from securesystemslib.receipts import (
    Approval,
    Artifact,
    OfflineReceiptVerifier,
    Receipt,
    ReconciliationResult,
    SeatRequirement,
)
from securesystemslib.signer import CryptoSigner, Key

ARTIFACT = Artifact("payments-api", "sha256:" + "a" * 64)
NOW = datetime(2026, 11, 20, 12, 0, tzinfo=UTC)
NOT_BEFORE = NOW - timedelta(hours=1)
NOT_AFTER = NOW + timedelta(hours=1)


def _approval(
    signer: CryptoSigner,
    approval_id: str,
    purposes: set[str],
) -> Approval:
    approval = Approval(
        approval_id=approval_id,
        artifact=ARTIFACT,
        purposes=frozenset(purposes),
        not_before=NOT_BEFORE,
        not_after=NOT_AFTER,
        issuer="release-board",
    )
    approval.sign(signer)
    return approval


def _receipt(  # noqa: PLR0913
    signer: CryptoSigner,
    receipt_id: str,
    approval_id: str,
    seat: str,
    signature_type: str,
    purpose: str = "deploy",
) -> Receipt:
    receipt = Receipt(
        receipt_id=receipt_id,
        approval_id=approval_id,
        seat=seat,
        signature_type=signature_type,
        purpose=purpose,
        artifact=ARTIFACT,
        issued_at=NOW,
    )
    receipt.sign(signer)
    return receipt


def _requirements() -> list[SeatRequirement]:
    return [
        SeatRequirement("release", "release_manager", {"deploy"}, ARTIFACT),
        SeatRequirement("security", "security", {"deploy"}, ARTIFACT),
    ]


def _print_result(title: str, result: ReconciliationResult) -> None:
    print(f"\n=== {title} ===")
    print(result.summary())
    for match in result.matches:
        receipts = ", ".join(match.receipt_ids)
        print(
            f"  {match.seat} [{match.signature_type}] "
            f"<- approval {match.approval_id} via {receipts}"
        )
    if not result.ok:
        print(f"  missing signature types: {', '.join(result.missing_signature_types)}")


def main() -> int:
    board_signer = CryptoSigner.generate_ed25519("approval-key")
    release_signer = CryptoSigner.generate_ed25519("release-key")
    security_signer = CryptoSigner.generate_ed25519("security-key")

    approval_keys: dict[str, Key] = {
        board_signer.public_key.keyid: board_signer.public_key
    }
    receipt_keys: dict[str, dict[str, Key]] = {
        "release_manager": {release_signer.public_key.keyid: release_signer.public_key},
        "security": {security_signer.public_key.keyid: security_signer.public_key},
    }

    approvals = [
        _approval(board_signer, "A1", {"deploy"}),
        _approval(board_signer, "A2", {"deploy"}),
    ]

    passing_receipts = [
        _receipt(release_signer, "release-a1", "A1", "release", "release_manager"),
        _receipt(release_signer, "release-a2", "A2", "release", "release_manager"),
        _receipt(security_signer, "security-a1", "A1", "security", "security"),
    ]
    passing = OfflineReceiptVerifier(
        _requirements(),
        approval_keys=approval_keys,
        receipt_keys=receipt_keys,
    )
    passing.add_approvals(approvals).add_receipts(passing_receipts)
    _print_result("PASS: global matching", passing.reconcile(as_of=NOW))

    failing_receipts = [
        _receipt(release_signer, "release-a1", "A1", "release", "release_manager"),
    ]
    failing = OfflineReceiptVerifier(
        _requirements(),
        approval_keys=approval_keys,
        receipt_keys=receipt_keys,
    )
    failing.add_approvals(approvals).add_receipts(failing_receipts)
    _print_result("FAIL: missing signature category", failing.reconcile(as_of=NOW))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
