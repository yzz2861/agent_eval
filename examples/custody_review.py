"""Synthetic custody case using the repository's existing Office fixtures.

The two protected files stand in for the original protected delivery and the
approved re-seal.  Their digests are read from the existing fixture bytes; no
new binary evidence is created.  Run with ``python examples/custody_review.py``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import msoffcrypto
BEFORE = ROOT / "tests" / "inputs" / "example_password.docx"
AFTER = ROOT / "tests" / "inputs" / "ecma376standard_password.docx"


def synthetic_case() -> dict:
    before = msoffcrypto.observe_protection(BEFORE)
    after = msoffcrypto.observe_protection(AFTER)
    events = [
        {
            "event_id": "h1",
            "document_id": "case-01",
            "filename": "case.docx",
            "artifact": str(BEFORE),
            "timestamp": "2026-11-01T00:00:00Z",
            "window_start": "2026-11-01T00:00:00Z",
            "window_end": "2026-11-01T23:59:59Z",
            "claimed_protection": True,
            "evidence_digest": before.digest,
            "delivery_id": "delivery-1",
        },
        {
            "event_id": "h2",
            "document_id": "case-01",
            "filename": "review.docx",
            "artifact": str(BEFORE),
            "timestamp": "2026-11-01T00:01:00Z",
            "window_start": "2026-11-01T00:00:00Z",
            "window_end": "2026-11-01T23:59:59Z",
            "claimed_protection": True,
            "evidence_digest": before.digest,
            "delivery_id": "delivery-1",
        },
        {
            "event_id": "h3",
            "document_id": "case-01",
            "filename": "sealed.docx",
            "artifact": str(AFTER),
            "timestamp": "2026-11-01T01:00:00Z",
            "window_start": "2026-11-01T00:00:00Z",
            "window_end": "2026-11-01T23:59:59Z",
            "claimed_protection": True,
            "evidence_digest": after.digest,
            "delivery_id": "delivery-2",
        },
    ]
    return {
        "events": events,
        "receipts": [
            {
                "receipt_id": "ack-reseal",
                "event_ids": ["h1", "h3"],
                "decision": "approve_reseal",
                "signer": "records-reviewer",
                "signed_at": "2026-11-01T00:30:00Z",
                "evidence_digest": after.digest,
            }
        ],
    }


def main() -> None:
    case = synthetic_case()
    with_receipt = msoffcrypto.review_custody_chain(case, max_gap_seconds=7200)
    without_receipt = msoffcrypto.review_custody_chain(
        {**case, "receipts": []}, max_gap_seconds=7200
    )

    print("No receipt: readings are preserved, with the settling receipts listed.")
    print(json.dumps(without_receipt["solutions"], indent=2, ensure_ascii=False))
    print(json.dumps(without_receipt["required_receipts"], indent=2, ensure_ascii=False))
    print("With approval receipt:")
    print(json.dumps(with_receipt.to_dict(), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
