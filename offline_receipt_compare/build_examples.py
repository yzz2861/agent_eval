"""Generate the two worked comparator examples under ``examples_store``.

Scenario A is re-verifiable: delegations are re-ordered and versions bumped,
but the same content stays reachable and the retained evidence re-hashes.

Scenario B requires a fresh receipt: the delegated role carrying the target is
removed, so the candidate metadata offers no trusted path to it.
"""

from __future__ import annotations

import hashlib
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from offline_receipt_compare.fixture_io import write_evidence, write_receipts
from offline_receipt_compare.models import Receipt
from offline_receipt_compare.repo_builder import (
    DelegationSpec,
    FixtureRepository,
)

STORE = Path(__file__).resolve().parent.parent / "examples_store"
ISSUED_AT = datetime(2026, 6, 1, 9, 0, tzinfo=UTC)


def _receipt(
    receipt_id: str,
    target_path: str,
    content: bytes,
    delegation_path: list[str],
) -> Receipt:
    return Receipt(
        receipt_id=receipt_id,
        target_path=target_path,
        hashes={"sha256": hashlib.sha256(content).hexdigest()},
        length=len(content),
        issued_at=ISSUED_AT,
        delegation_path=delegation_path,
        evidence_relpath=f"artifacts/{Path(target_path).name}",
    )


def build_scenario_a(base: Path) -> None:
    """Build the re-verifiable example fixtures."""
    # Same download content survives a delegation re-order and version bump.
    target_path = "hardware/pump-7.bin"
    content = b"pump-7 firmware body, identical across metadata versions"
    unreceipted = b"a target that never had an acceptance receipt"

    old = FixtureRepository(expiry_base=ISSUED_AT - timedelta(days=1))
    old.add_delegation(
        "targets",
        DelegationSpec("legacy-hardware", ["hardware/*"], terminating=True),
    )
    old.add_target(target_path, content, role="legacy-hardware")
    old.add_target("misc/internal.log", unreceipted, role="targets")
    old.write(base / "scenario_a_reverifiable" / "old_metadata")

    candidate = FixtureRepository(expiry_base=ISSUED_AT)
    candidate.add_delegation(
        "targets",
        DelegationSpec("hardware", ["hardware/*"], terminating=True),
    )
    candidate.add_target(target_path, content, role="hardware")
    candidate.add_target("misc/internal.log", unreceipted, role="targets")
    candidate.write(base / "scenario_a_reverifiable" / "candidate_metadata")

    receipt = _receipt(
        "R-A-001",
        target_path,
        content,
        ["targets", "legacy-hardware"],
    )
    write_receipts(base / "scenario_a_reverifiable" / "receipts", [receipt])
    write_evidence(
        base / "scenario_a_reverifiable" / "evidence",
        receipt.evidence_relpath,
        content,
    )


def build_scenario_b(base: Path) -> None:
    """Build the reissue-required example fixtures."""
    # The role carrying the target is removed: evidence remains but the new
    # metadata no longer offers any trusted path to the target.
    target_path = "hardware/valve-3.bin"
    content = b"valve-3 firmware body, retained on disk only"

    old = FixtureRepository(expiry_base=ISSUED_AT - timedelta(days=1))
    old.add_delegation(
        "targets",
        DelegationSpec("legacy-hardware", ["hardware/*"], terminating=True),
    )
    old.add_target(target_path, content, role="legacy-hardware")
    old.write(base / "scenario_b_reissue_required" / "old_metadata")

    candidate = FixtureRepository(expiry_base=ISSUED_AT)
    candidate.add_delegation(
        "targets",
        DelegationSpec("hardware", ["hardware/*"], terminating=True),
    )
    candidate.write(base / "scenario_b_reissue_required" / "candidate_metadata")

    receipt = _receipt(
        "R-B-001",
        target_path,
        content,
        ["targets", "legacy-hardware"],
    )
    write_receipts(base / "scenario_b_reissue_required" / "receipts", [receipt])
    write_evidence(
        base / "scenario_b_reissue_required" / "evidence",
        receipt.evidence_relpath,
        content,
    )


def main() -> None:
    """Generate both example scenarios on disk."""
    base = STORE
    build_scenario_a(base)
    build_scenario_b(base)
    sys.stdout.write(f"wrote examples to {base}\n")


if __name__ == "__main__":
    main()
