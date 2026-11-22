"""Compare old and candidate TUF metadata against retained receipts.

Only targets that carry an acceptance receipt are audited: a target that never
had a receipt is part of neither the re-verifiable set nor the risk set.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from offline_receipt_compare.models import (
    EvidenceStore,
    Receipt,
    VerdictCode,
)
from offline_receipt_compare.verifier import (
    MetadataBundle,
    RoleStep,
    TargetResolution,
    verify_chain,
)
from tuf.api.exceptions import RepositoryError
from tuf.api.metadata import Targets


@dataclass
class ReceiptOutcome:
    """Comparison result for a single receipt."""

    # Comparison result for a single receipt.
    receipt_id: str
    target_path: str
    code: str
    detail: str = ""
    historical_path: list[RoleStep] = field(default_factory=list)
    candidate_path: list[RoleStep] = field(default_factory=list)

    @property
    def reverifiable(self) -> bool:
        """True when the historical conclusion still holds."""
        return self.code == VerdictCode.REVERIFIABLE

    def to_dict(self) -> dict:
        """Serialize the outcome for JSON reporting."""
        return {
            "receipt_id": self.receipt_id,
            "target_path": self.target_path,
            "code": self.code,
            "reverifiable": self.reverifiable,
            "detail": self.detail,
            "historical_delegation_path": [
                step.to_dict() for step in self.historical_path
            ],
            "candidate_delegation_path": [
                step.to_dict() for step in self.candidate_path
            ],
        }


@dataclass
class ComparisonReport:
    """Aggregated verdicts and summary counters for one comparison run."""

    outcomes: list[ReceiptOutcome]
    receipts_evaluated: int
    targets_without_receipt_ignored: int

    @property
    def re_verifiable(self) -> list[ReceiptOutcome]:
        """Outcomes whose receipts can still be re-verified."""
        return [item for item in self.outcomes if item.reverifiable]

    @property
    def blocked(self) -> list[ReceiptOutcome]:
        """Outcomes whose receipts can no longer be supported."""
        return [item for item in self.outcomes if not item.reverifiable]

    def to_dict(self) -> dict:
        """Serialize the outcome for JSON reporting."""
        return {
            "summary": {
                "receipts_evaluated": self.receipts_evaluated,
                "re_verifiable": len(self.re_verifiable),
                "blocked": len(self.blocked),
                "targets_without_receipt_ignored": (
                    self.targets_without_receipt_ignored
                ),
            },
            "outcomes": [outcome.to_dict() for outcome in self.outcomes],
        }


class ReceiptComparator:
    """Re-verify a fixed set of receipts against two metadata bundles."""

    # Compare old and candidate metadata for a fixed set of receipts.
    def __init__(
        self,
        old_bundle: MetadataBundle,
        candidate_bundle: MetadataBundle,
        receipts: list[Receipt],
        evidence: EvidenceStore,
    ) -> None:
        """Bind the two bundles, the receipts and the evidence store."""
        self.old_bundle = old_bundle
        self.candidate_bundle = candidate_bundle
        self.receipts = list(receipts)
        self.evidence = evidence

    def run(self) -> ComparisonReport:
        """Evaluate every receipt and assemble the comparison report."""
        outcomes: list[ReceiptOutcome] = []
        for receipt in self.receipts:
            historical = verify_chain(
                self.old_bundle,
                receipt.target_path,
                reference_time=receipt.issued_at,
            )
            if not historical.found:
                outcomes.append(
                    self._outcome(
                        receipt,
                        VerdictCode.NOT_HISTORICALLY_VALID,
                        historical,
                        historical,
                    )
                )
                continue

            candidate = verify_chain(
                self.candidate_bundle,
                receipt.target_path,
                reference_time=receipt.issued_at,
            )
            outcomes.append(self._evaluate(receipt, historical, candidate))

        return ComparisonReport(
            outcomes=outcomes,
            receipts_evaluated=len(self.receipts),
            targets_without_receipt_ignored=self._count_without_receipt(),
        )

    def _evaluate(
        self,
        receipt: Receipt,
        historical: TargetResolution,
        candidate: TargetResolution,
    ) -> ReceiptOutcome:
        """Decide the verdict once both bundles have resolved the target."""
        if not candidate.found:
            return self._outcome(
                receipt, candidate.reason, historical, candidate
            )

        if candidate.target_file is None:
            return self._outcome(
                receipt, candidate.reason, historical, candidate
            )
        if candidate.target_file.hashes != receipt.hashes:
            return self._outcome(
                receipt,
                VerdictCode.CONTENT_DRIFTED,
                historical,
                candidate,
                "candidate target hashes differ from the recorded receipt",
            )

        artifact = self.evidence.read(receipt.evidence_relpath)
        if artifact is None:
            return self._outcome(
                receipt,
                VerdictCode.EVIDENCE_MISSING,
                historical,
                candidate,
            )
        try:
            candidate.target_file.verify_length_and_hashes(artifact)
        except RepositoryError as exc:
            return self._outcome(
                receipt,
                VerdictCode.EVIDENCE_MISMATCH,
                historical,
                candidate,
                f"{type(exc).__name__}: {exc}",
            )

        return self._outcome(
            receipt,
            VerdictCode.REVERIFIABLE,
            historical,
            candidate,
            "candidate path and retained evidence reproduce the receipt",
        )

    def _outcome(
        self,
        receipt: Receipt,
        code: str,
        historical: TargetResolution,
        candidate: TargetResolution,
        detail: str = "",
    ) -> ReceiptOutcome:
        """Build an outcome carrying both reconstructed role paths."""
        return ReceiptOutcome(
            receipt_id=receipt.receipt_id,
            target_path=receipt.target_path,
            code=code,
            detail=detail or candidate.detail or historical.detail,
            historical_path=historical.role_path,
            candidate_path=candidate.role_path,
        )

    def _count_without_receipt(self) -> int:
        """Count listed old targets that have no receipt (not risks)."""
        receipt_paths = {receipt.target_path for receipt in self.receipts}
        listed: set[str] = set()
        for role_name in self.old_bundle.roles():
            metadata = self.old_bundle.get_metadata(role_name)
            if metadata is not None and isinstance(metadata.signed, Targets):
                listed.update(metadata.signed.targets)
        return len(listed - receipt_paths)
