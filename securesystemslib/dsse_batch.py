"""Batch intake of DSSE envelopes with one-time approval tracking.

Several stations may process incoming envelopes in parallel. Each envelope
is presented together with a one-time approval number (e.g. a purchase
approval) that exactly one envelope may consume. This module defines the
batch verification interface:

* "verify_batch" performs the normal DSSE signature verification and
  orchestrates approval occupation and result submission.
* "ApprovalStore" is the persistence layer, implemented by the caller. It
  provides atomic approval occupation ("claim_approval"), idempotent result
  lookup for legitimate retries ("get_result") and atomic result submission
  ("save_results").

Outcomes per envelope ("BatchStatus"):

* VERIFIED: signatures verified and the approval number was consumed.
* REPLAYED: the envelope was processed before; the previously committed
  result is returned and no new approval is consumed.
* INVALID_SIGNATURE: signature verification failed; no approval consumed.
* APPROVAL_CONSUMED: the approval number is already owned by another
  envelope; the item must be resubmitted with a fresh approval number.
"""

from __future__ import annotations

import enum
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from securesystemslib import exceptions
from securesystemslib.dsse import Envelope
from securesystemslib.signer import Key


class BatchStatus(enum.Enum):
    """Outcome of verifying one envelope in a batch."""

    VERIFIED = "verified"
    REPLAYED = "replayed"
    INVALID_SIGNATURE = "invalid_signature"
    APPROVAL_CONSUMED = "approval_consumed"


@dataclass
class BatchItem:
    """One envelope awaiting intake.

    Attributes:
        envelope_id: Caller-assigned unique id for the envelope. Retries of
            the same envelope must reuse the same id.
        envelope: The DSSE envelope to verify.
        approval: One-time approval number presented with the envelope.
    """

    envelope_id: str
    envelope: Envelope
    approval: str


@dataclass
class BatchResult:
    """Outcome for one envelope.

    Attributes:
        envelope_id: Id of the processed envelope.
        status: A "BatchStatus" outcome.
        approval: Approval number consumed by this envelope, if any.
        keyids: Keyids of the keys that verified the envelope, if any.
    """

    envelope_id: str
    status: BatchStatus
    approval: str | None = None
    keyids: list[str] = field(default_factory=list)


class ApprovalStore(ABC):
    """Persistence layer for batch verification, implemented by the caller.

    Implementations must guarantee:

    * "claim_approval" is atomic: an approval number is owned by exactly one
      envelope, even when several stations claim concurrently.
    * "save_results" commits all given results atomically and makes them
      visible to later "get_result" calls, including calls made through a
      new connection after the committing station disconnected.
    """

    @abstractmethod
    def get_result(self, envelope_id: str) -> BatchResult | None:
        """Return the previously committed result for "envelope_id".

        Returns None if the envelope has not been processed yet.
        """

    @abstractmethod
    def claim_approval(self, approval: str, envelope_id: str) -> str:
        """Occupy the one-time "approval" number for "envelope_id".

        Returns the id of the envelope that owns the approval: "envelope_id"
        itself if the claim succeeded, or the id of the envelope that
        claimed the same approval earlier.
        """

    @abstractmethod
    def save_results(self, results: list[BatchResult]) -> None:
        """Atomically commit the given results."""


def verify_batch(
    items: list[BatchItem],
    keys: list[Key],
    threshold: int,
    store: ApprovalStore,
) -> list[BatchResult]:
    """Verify a batch of envelopes, occupying one-time approval numbers.

    Each item is processed as follows:

    1. If "store" holds a committed result for the envelope id, the item is
       a legitimate retry: the stored result is replayed with status
       REPLAYED and no new approval is consumed, even if the retry presents
       a different approval number.
    2. The envelope signatures are verified against "keys" and "threshold".
       Failures yield INVALID_SIGNATURE and consume no approval.
    3. The item's approval number is claimed atomically via the store. If
       another envelope already owns it, the item is rejected with
       APPROVAL_CONSUMED and must be resubmitted with a fresh approval.
    4. Otherwise the item consumes its approval with status VERIFIED.

    Final outcomes (VERIFIED, INVALID_SIGNATURE) are committed through
    "store.save_results" so that later retries replay them. APPROVAL_CONSUMED
    is transient and deliberately not committed: the caller is expected to
    supply a fresh approval number and submit the envelope again.

    Arguments:
        items: The envelopes to process.
        keys: Public keys used for signature verification.
        threshold: Number of signatures needed to pass verification.
        store: Caller-implemented persistence layer.

    Raises:
        ValueError: If "threshold" is not valid for the given keys.

    Returns:
        A list of "BatchResult", one per item, in input order.
    """

    results: list[BatchResult] = []
    committed: list[BatchResult] = []

    for item in items:
        prior = store.get_result(item.envelope_id)
        if prior is not None:
            results.append(
                BatchResult(
                    envelope_id=item.envelope_id,
                    status=BatchStatus.REPLAYED,
                    approval=prior.approval,
                    keyids=prior.keyids,
                )
            )
            continue

        try:
            accepted_keys = item.envelope.verify(keys, threshold)
        except exceptions.VerificationError:
            result = BatchResult(
                envelope_id=item.envelope_id,
                status=BatchStatus.INVALID_SIGNATURE,
            )
            results.append(result)
            committed.append(result)
            continue

        owner = store.claim_approval(item.approval, item.envelope_id)
        if owner != item.envelope_id:
            results.append(
                BatchResult(
                    envelope_id=item.envelope_id,
                    status=BatchStatus.APPROVAL_CONSUMED,
                )
            )
            continue

        result = BatchResult(
            envelope_id=item.envelope_id,
            status=BatchStatus.VERIFIED,
            approval=item.approval,
            keyids=list(accepted_keys),
        )
        results.append(result)
        committed.append(result)

    store.save_results(committed)

    return results
