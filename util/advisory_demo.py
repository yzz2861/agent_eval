"""
End-to-end scenario for collaborative advisory CVSS scoring.

Two responders edit one advisory concurrently:
  * responder A revises the business impact (Integrity metric ``I``),
  * responder B revises an attack premise (Attack Vector metric ``AV``).

Their receipts are external input fed into the CVSS recalculation entry point. The delivery
stream interleaves both submissions and repeats one receipt. After a conflict is rejected and a
revision is withdrawn, a historical release point is recomputed and must match the score and
severity displayed in the report at that point.
"""

from __future__ import print_function, unicode_literals

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cvss import (
    AdvisoryScoring,
    ReceiptConflictError,
    RevisionReceipt,
)

BASE_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"


def print_journal(ledger):
    print("\n--- append-only journal ---")
    for event in ledger.journal():
        payload = event["payload"]
        if event["kind"] == "accepted":
            print(
                "{seq:>2} accepted   {receipt} by {responder} based on v{base} -> v{version} "
                "{fields} score={score} {severity}".format(
                    seq=event["seq"],
                    receipt=payload["receipt_id"],
                    responder=payload["responder"],
                    base=payload["base_version"],
                    version=payload["vector_version"],
                    fields=dict(payload["fields"]),
                    score=payload["base_score"],
                    severity=payload["severity"],
                )
            )
        elif event["kind"] == "rejected":
            print(
                "{seq:>2} rejected   {receipt} by {responder} based on v{base}: {reason} "
                "{conflicts}".format(
                    seq=event["seq"],
                    receipt=payload["receipt_id"],
                    responder=payload["responder"],
                    base=payload["base_version"],
                    reason=payload["reason"],
                    conflicts=[dict(item) for item in payload["conflicts"]],
                )
            )
        elif event["kind"] == "duplicate":
            print(
                "{seq:>2} duplicate  {receipt} (original event {original})".format(
                    seq=event["seq"],
                    receipt=payload["receipt_id"],
                    original=payload["original_seq"],
                )
            )
        elif event["kind"] == "published":
            print(
                "{seq:>2} published  {label} v{version} score={score} {severity}".format(
                    seq=event["seq"],
                    label=payload["label"],
                    version=payload["vector_version"],
                    score=payload["base_score"],
                    severity=payload["severity"],
                )
            )
        elif event["kind"] == "withdrawn":
            print(
                "{seq:>2} withdrawn  {receipt} by {responder}, rollback={rollback}, "
                "last public vector: {vector}".format(
                    seq=event["seq"],
                    receipt=payload["receipt_id"],
                    responder=payload["responder"],
                    rollback=dict(payload["rollback_values"]),
                    vector=payload["last_public_vector"],
                )
            )
        else:
            print(
                "{seq:>2} {kind:<9} {payload}".format(
                    seq=event["seq"], kind=event["kind"], payload=dict(payload)
                )
            )


def main():
    ledger = AdvisoryScoring("RHSA-DEMO-2026", BASE_VECTOR)
    print(
        "advisory {0} starts at vector version 0: {1}".format(
            ledger.advisory_id, ledger.current_result()
        )
    )

    # Both responders read version 0 before composing their receipts concurrently.
    seen_version = ledger.vector_version
    impact_receipt = RevisionReceipt(
        receipt_id="R1",
        responder="responder-a",
        fields={"I": "L"},
        base_version=seen_version,
        seq=1,
    )
    premise_receipt = RevisionReceipt(
        receipt_id="R2",
        responder="responder-b",
        fields={"AV": "A"},
        base_version=seen_version,
        seq=2,
    )

    # Interleaved delivery: A, B, then A's receipt is redelivered by the transport. They are
    # handed over out of order; seq guarantees the transport order is what gets processed.
    redelivery = RevisionReceipt(
        receipt_id="R1",
        responder="responder-a",
        fields={"I": "L"},
        base_version=seen_version,
        seq=3,
    )
    delivered = ledger.deliver(premise_receipt, redelivery, impact_receipt)
    duplicate_event = delivered[2]
    assert duplicate_event["kind"] == "duplicate"
    assert ledger.vector_version == 2

    # A competing receipt tries to overwrite Integrity, which responder A already owns.
    conflicting = RevisionReceipt(
        receipt_id="R3",
        responder="responder-c",
        fields={"I": "H"},
        base_version=ledger.vector_version,
        seq=4,
    )
    try:
        ledger.submit(conflicting)
    except ReceiptConflictError as error:
        print("\nconflict rejected as expected: {0}".format(error))

    # Report the merged state as a named historical release point.
    release = ledger.publish("report-2026-11-28")
    print("\npublished release point: {0}".format(dict(release["payload"])))

    # Responder A withdraws the business-impact revision; its public values stay traceable.
    ledger.withdraw("R1", "responder-a")
    assert "I:L" not in ledger.current_result()["vector"]
    assert "I:L" in ledger.publication("report-2026-11-28")["vector"]

    print_journal(ledger)

    # Recompute any historical release point from the vector displayed in the report.
    recomputed = ledger.recompute_at("report-2026-11-28")
    print("\nhistorical recomputation: {0}".format(dict(recomputed)))
    assert recomputed["matches_display"] is True
    assert recomputed["base_score"] == release["payload"]["base_score"]
    assert recomputed["severity"] == release["payload"]["severity"]
    print(
        "\nOK: recomputed score {0} ({1}) matches the historical report.".format(
            recomputed["base_score"], recomputed["severity"]
        )
    )


if __name__ == "__main__":
    main()
