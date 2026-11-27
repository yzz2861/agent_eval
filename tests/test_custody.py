"""Offline custody checks over synthetic handover events and existing fixtures."""

from __future__ import annotations

from pathlib import Path

from msoffcrypto import observe_evidence, review_custody_chain


TEST_DIR = Path(__file__).resolve().parent
INPUT_DIR = TEST_DIR / "inputs"
OUTPUT_DIR = TEST_DIR / "outputs"

PROTECTED_BEFORE = INPUT_DIR / "example_password.docx"
PROTECTED_AFTER = INPUT_DIR / "ecma376standard_password.docx"
PLAIN_DOCUMENT = OUTPUT_DIR / "example.docx"

# Digests of files already carried by the repository.  They are assertions in
# their own right: the fixture bytes must not silently drift.
BEFORE_SHA256 = "0605624697328060fdc75ca9929ea20b9d63ebed9387ff1a97aaf9979757234a"
AFTER_SHA256 = "d265dcf02f7d552486229b8c67a627ef3752fe6802b02fd2d2d485fcfbbac5de"
PLAIN_SHA256 = "8c8212db6e624bfc69286e94d09b7e68c753ee86b6826e51427a33c841f133d1"

START = "2026-11-01T00:00:00Z"
END = "2026-11-01T23:59:59Z"
DOCUMENT_ID = "case-document-01"


def handoff(
    event_id: str,
    filename: str,
    artifact: Path,
    digest: str,
    delivery_id: str,
    timestamp: str,
    *,
    protection: bool = True,
    window_start: str = START,
    window_end: str = END,
) -> dict:
    return {
        "event_id": event_id,
        "document_id": DOCUMENT_ID,
        "filename": filename,
        "artifact": str(artifact),
        "timestamp": timestamp,
        "window_start": window_start,
        "window_end": window_end,
        "claimed_protection": protection,
        "evidence_digest": digest,
        "delivery_id": delivery_id,
    }


def approval_receipt(
    receipt_id: str,
    decision: str,
    event_ids: list[str],
    signed_at: str,
    digest: str,
) -> dict:
    return {
        "receipt_id": receipt_id,
        "event_ids": event_ids,
        "decision": decision,
        "signer": "records-reviewer",
        "signed_at": signed_at,
        "evidence_digest": digest,
        "signature_valid": True,
    }


def reseal_chain(*, with_receipt: bool = True, after_timestamp: str = "2026-11-01T01:00:00Z") -> dict:
    events = [
        handoff("h1", "case.docx", PROTECTED_BEFORE, BEFORE_SHA256, "delivery-1", "2026-11-01T00:00:00Z"),
        # Same delivery token, same bytes and same public protection state.  It
        # is a duplicate delivery, not another protection state and not a link.
        handoff("h2", "review.docx", PROTECTED_BEFORE, BEFORE_SHA256, "delivery-1", "2026-11-01T00:01:00Z"),
        handoff("h3", "sealed.docx", PROTECTED_AFTER, AFTER_SHA256, "delivery-2", after_timestamp),
    ]
    receipts = []
    if with_receipt:
        receipts.append(
            approval_receipt("ack-2", "approve_reseal", ["h1", "h3"], "2026-11-01T00:30:00Z", AFTER_SHA256)
        )
    return {"events": events, "receipts": receipts, "max_gap_seconds": 7200}


def test_public_observation_and_existing_fixture_digests():
    before = observe_evidence(PROTECTED_BEFORE)
    after = observe_evidence(PROTECTED_AFTER)
    plain = observe_evidence(PLAIN_DOCUMENT)

    assert before.digest == BEFORE_SHA256
    assert after.digest == AFTER_SHA256
    assert plain.digest == PLAIN_SHA256
    assert before.protection == "protected" and before.encrypted is True
    assert after.protection == "protected" and after.encrypted is True
    assert plain.protection == "plain" and plain.encrypted is False
    assert before.error is None and after.error is None and plain.error is None


def test_duplicate_delivery_is_not_another_protection_state():
    report = review_custody_chain(reseal_chain())
    data = report.to_dict()

    assert [item["event_id"] for item in data["duplicates"]] == ["h2"]
    duplicate = data["duplicates"][0]
    assert duplicate["canonical_event_id"] == "h1"
    assert duplicate["reason"] == "same_delivery_id"
    assert duplicate["dropped"] is True
    assert duplicate["protection_state_added"] is False

    assert len(data["protection_states"]) == 2
    assert data["protection_states"][0]["duplicate_event_ids"] == ["h2"]
    assert [
        (link["before_event_id"], link["after_event_id"])
        for link in data["links"]
    ] == [("h1", "h3")]


def test_reseal_checks_status_digest_and_time_window():
    report = review_custody_chain(reseal_chain())
    link = report["links"][0]

    assert report.status == "confirmed"
    assert link["status"] == "confirmed"
    assert link["relation"] == "changed_bytes_protected_to_protected"
    for name in ("before_status", "after_status", "before_digest", "after_digest"):
        assert link["checks"][name]["ok"] is True
    assert link["checks"]["before_window"]["ok"] is True
    assert link["checks"]["after_window"]["ok"] is True
    assert link["checks"]["order"]["ok"] is True
    assert link["checks"]["gap"]["ok"] is True
    assert link["checks"]["gap"]["seconds"] == 3600.0

    readings = {item["candidate_id"]: item for item in link["interpretations"]}
    assert readings["approved_reseal_same_document"]["state"] == "supported"
    assert readings["approved_reseal_same_document"]["decisive_receipts"] == ["ack-2"]
    assert readings["replacement_protected_document"]["state"] == "excluded"
    assert link["decisive_receipts"][0]["accepted"] is True


def test_missing_receipt_preserves_both_readings_and_lists_settlers():
    report = review_custody_chain(reseal_chain(with_receipt=False))
    link = report["links"][0]
    readings = {item["candidate_id"]: item for item in link["interpretations"]}

    assert report.status == "ambiguous"
    assert link["status"] == "ambiguous"
    assert readings["approved_reseal_same_document"]["state"] == "possible"
    assert readings["replacement_protected_document"]["state"] == "possible"
    assert {solution["links"]["link-1"] for solution in report["solutions"]} == {
        "approved_reseal_same_document",
        "replacement_protected_document",
    }

    required = {item["candidate_id"]: item for item in link["required_receipts"]}
    assert set(required) == {"approved_reseal_same_document", "replacement_protected_document"}
    assert required["approved_reseal_same_document"]["decision"] == "reseal"
    assert required["approved_reseal_same_document"]["event_ids"] == ["h1", "h3"]
    assert required["approved_reseal_same_document"]["digest"] == AFTER_SHA256


def test_out_of_window_keeps_late_and_clock_reorder_readings():
    report = review_custody_chain(reseal_chain(with_receipt=False, after_timestamp="2026-11-02T01:00:00Z"))
    link = report["links"][0]

    assert link["checks"]["after_window"]["ok"] is False
    assert link["checks"]["after_window"]["reason"] == "after_window_end"
    assert link["checks"]["order"]["ok"] is True
    assert link["checks"]["time"]["ok"] is False
    assert link["status"] == "ambiguous"

    readings = {item["candidate_id"] for item in link["interpretations"]}
    assert {"out_of_window_delivery", "clock_skew_or_reordering"} <= readings
    required = {item["candidate_id"] for item in link["required_receipts"]}
    assert {"out_of_window_delivery", "clock_skew_or_reordering"} <= required


def test_claimed_protection_mismatch_is_a_hard_failure():
    payload = reseal_chain(with_receipt=False)
    payload["events"][0]["claimed_protection"] = False
    report = review_custody_chain(payload)
    link = report["links"][0]

    assert report.status == "invalid"
    assert link["status"] == "invalid"
    assert link["checks"]["before_status"]["ok"] is False
    assert link["checks"]["before_status"]["claimed"] == "plain"
    assert link["checks"]["before_status"]["observed"] == "protected"
    readings = {item["candidate_id"] for item in link["interpretations"]}
    assert "status_claim_error" in readings


def test_conflicting_duplicate_claim_is_reported_without_adding_a_state():
    payload = reseal_chain(with_receipt=False)
    payload["events"][1]["claimed_protection"] = False
    report = review_custody_chain(payload)

    assert report["duplicates"][0]["dropped"] is True
    assert report["duplicates"][0]["claim_conflicts"] == ["claimed_protection"]
    assert len(report["protection_states"]) == 2
    assert report["protection_states"][0]["duplicate_event_ids"] == ["h2"]


def test_identical_name_and_bytes_are_recognized_as_duplicate_without_token():
    payload = reseal_chain(with_receipt=False)
    payload["events"][1]["filename"] = "case.docx"
    payload["events"][1].pop("delivery_id")
    report = review_custody_chain(payload)

    assert report["duplicates"][0]["reason"] == "same_name_same_bytes_same_protection"
    assert report["duplicates"][0]["dropped"] is True
    assert len(report["protection_states"]) == 2


def test_same_delivery_token_with_different_bytes_is_not_silently_dropped():
    payload = reseal_chain(with_receipt=False)
    payload["events"][1] = handoff(
        "h2",
        "review.docx",
        PROTECTED_AFTER,
        AFTER_SHA256,
        "delivery-1",
        "2026-11-01T00:01:00Z",
    )
    report = review_custody_chain(payload)

    duplicate = report["duplicates"][0]
    assert duplicate["event_id"] == "h2"
    assert duplicate["reason"] == "same_delivery_id_but_observation_differs"
    assert duplicate["dropped"] is False
    assert duplicate["protection_state_added"] == "conflict_requires_review"
    events = {item["event_id"]: item for item in report["events"]}
    assert events["h2"]["canonical"] is True
    assert len(report["protection_states"]) == 2


def test_plain_to_protected_receipt_settles_a_seal_link():
    events = [
        handoff("p1", "source.docx", PLAIN_DOCUMENT, PLAIN_SHA256, "plain-delivery", "2026-11-01T00:00:00Z", protection=False),
        handoff("p2", "sealed.docx", PROTECTED_BEFORE, BEFORE_SHA256, "sealed-delivery", "2026-11-01T01:00:00Z"),
    ]
    receipt = approval_receipt("ack-seal", "approve_seal", ["p1", "p2"], "2026-11-01T00:30:00Z", BEFORE_SHA256)
    report = review_custody_chain(
        {"events": events, "receipts": [receipt]},
        max_gap_seconds=3600,
    )

    assert report.status == "confirmed"
    link = report["links"][0]
    readings = {item["candidate_id"]: item for item in link["interpretations"]}
    assert readings["approved_seal_same_document"]["state"] == "supported"
    assert readings["replacement_protected_document"]["state"] == "excluded"


def test_explicit_predecessor_selects_the_legitimate_before_after_link():
    events = [
        handoff("h1", "case.docx", PROTECTED_BEFORE, BEFORE_SHA256, "delivery-1", "2026-11-01T00:00:00Z"),
        handoff("h2", "review.docx", PROTECTED_BEFORE, BEFORE_SHA256, "delivery-side", "2026-11-01T00:10:00Z"),
        handoff("h3", "sealed.docx", PROTECTED_AFTER, AFTER_SHA256, "delivery-2", "2026-11-01T01:00:00Z"),
    ]
    events[2]["previous_event_id"] = "h1"
    report = review_custody_chain({"events": events})

    assert [
        (link["before_event_id"], link["after_event_id"])
        for link in report["links"]
    ] == [("h1", "h3")]
