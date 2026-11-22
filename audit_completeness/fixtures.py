"""Short, hand-built streams used by the demo and the test-suite.

``build_full_stream`` emits ordinary, well-formed records.  ``build_truncated_stream``
keeps every fully-closed batch/record and cuts the *last* batch while its final
record is still open, so completed fields stay reviewable while the tail is
genuinely uncollected rather than missing.
"""

import json


def _record(record_id, risk_level, amount, active, flags, extra=None):
    record = {
        "record_id": record_id,
        "risk_level": risk_level,
        "amount": amount,
        "active": active,
        "flags": list(flags),
    }
    if extra is not None:
        record.update(extra)
    return record


def build_documents():
    return [
        {
            "batch_id": "batch-001",
            "records": [
                _record("r-1", "high", 1250.5, True, ["aml", "pep"]),
                _record("r-2", "low", 80, False, [], extra={"note": "ok"}),
            ],
        },
        {
            "batch_id": "batch-002",
            "records": [
                _record("r-3", "medium", 42, True, ["watch"]),
                _record("r-4", 7, 10, True, ["pep"]),
            ],
        },
    ]


def build_full_stream():
    return json.dumps({"batches": build_documents()}, ensure_ascii=False).encode("utf-8")


def build_truncated_stream():
    """Cut the full stream inside the still-open record of the last batch."""
    full = build_full_stream()
    marker = b"\"record_id\": \"r-4\""
    last_record_field = full.rfind(marker)
    if last_record_field < 0:
        raise RuntimeError("could not locate the last record anchor")
    value_end = full.index(b",", last_record_field)
    return full[:value_end]


def audit_rules():
    return [
        ("batches.item.records.item.risk_level", "string"),
        ("batches.item.records.item.amount", "number"),
        ("batches.item.records.item.active", "boolean"),
        ("batches.item.records.item.flags", "array"),
    ]
