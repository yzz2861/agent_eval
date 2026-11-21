import os

import pytest

from stix2.datastore.memory import MemoryStore
from stix2.datastore.receipt import (
    BundleReceiver, FileReceiptJournal, content_digest,
)

IND_A = {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--00000000-0000-4000-8000-00000000000a",
    "created": "2017-01-27T13:49:53.935Z",
    "modified": "2017-01-27T13:49:53.935Z",
    "name": "Evidence item A",
    "pattern": "[url:value = 'http://example.com/a']",
    "pattern_type": "stix",
    "valid_from": "2017-01-27T13:49:53.935Z",
}
IND_B = {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--00000000-0000-4000-8000-00000000000b",
    "created": "2017-01-27T13:49:53.935Z",
    "modified": "2017-01-27T13:49:53.935Z",
    "name": "Evidence item B",
    "pattern": "[url:value = 'http://example.com/b']",
    "pattern_type": "stix",
    "valid_from": "2017-01-27T13:49:53.935Z",
}
IND_C = {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--00000000-0000-4000-8000-00000000000c",
    "created": "2017-01-27T13:49:53.935Z",
    "modified": "2017-01-27T13:49:53.935Z",
    "name": "Evidence item C",
    "pattern": "[url:value = 'http://example.com/c']",
    "pattern_type": "stix",
    "valid_from": "2017-01-27T13:49:53.935Z",
}
# Same id and modified as IND_A, but different content.
IND_A_TAMPERED = dict(IND_A, name="Evidence item A (altered)")

BUNDLE_ID = "bundle--11111111-2222-4333-8444-555555555555"


def make_bundle(*objects):
    return {
        "type": "bundle",
        "id": BUNDLE_ID,
        "objects": list(objects),
    }


def make_receiver(tmp_path, store=None):
    store = store or MemoryStore()
    journal = FileReceiptJournal(str(tmp_path / "journal"))
    return BundleReceiver(store, journal), store, journal


def test_handover_missing_supplement_conflict(tmp_path):
    receiver, store, journal = make_receiver(tmp_path)
    checklist = [IND_A["id"], IND_B["id"], IND_C["id"]]

    # Batch 1: two of the three expected items arrive (one missing).
    bundle1 = make_bundle(IND_A, IND_B)
    receipt1 = receiver.receive(
        bundle1, source="team-alpha", expected=checklist,
    )
    assert [item["index"] for item in receipt1.items] == [0, 1]
    assert [item["id"] for item in receipt1.items] == [
        IND_A["id"], IND_B["id"],
    ]
    assert all(item["status"] == "stored" for item in receipt1.items)
    assert all(item["expected"] for item in receipt1.items)
    assert receipt1.source == "team-alpha"
    assert receipt1.missing == [IND_C["id"]]
    assert receipt1.quarantined == []

    # Batch 2: the missing item is supplied later.
    bundle2 = make_bundle(IND_C)
    receipt2 = receiver.receive(bundle2, source="team-alpha")
    assert receipt2.missing == []
    assert receipt2.items[0]["id"] == IND_C["id"]
    assert receipt2.items[0]["expected"]

    # Batch 3: same id/modified as an already stored object, different
    # content -> conflict, quarantined before reaching the store.
    bundle3 = make_bundle(IND_A_TAMPERED)
    receipt3 = receiver.receive(bundle3, source="team-beta")
    assert receipt3.items[0]["status"] == "quarantined"
    assert receipt3.quarantined[0]["id"] == IND_A["id"]
    assert receipt3.quarantined[0]["digest"] != \
        receipt3.quarantined[0]["conflict_digest"]

    # The store still holds the original object, untouched.
    assert store.get(IND_A["id"])["name"] == IND_A["name"]
    quarantine_log = receiver.quarantined()
    assert len(quarantine_log) == 1
    assert quarantine_log[0]["object"]["name"] == IND_A_TAMPERED["name"]
    assert quarantine_log[0]["receipt_id"] == receipt3.receipt_id

    # Three distinct receipts, each verifiable against its own bundle.
    assert len(
        {receipt1.receipt_id, receipt2.receipt_id, receipt3.receipt_id},
    ) == 3
    assert receipt1.verify(bundle1) == []
    assert receipt2.verify(bundle2) == []
    assert receipt3.verify(bundle3) == []

    # A receipt does not verify against a bundle that was tampered with.
    assert receipt1.verify(make_bundle(IND_A_TAMPERED, IND_B)) != []

    # Receipts are persisted and reloadable.
    for receipt in (receipt1, receipt2, receipt3):
        persisted = journal.load_receipt(receipt.batch_digest)
        assert persisted["receipt_id"] == receipt.receipt_id


def test_duplicate_upload_is_not_signed_twice(tmp_path):
    receiver, store, journal = make_receiver(tmp_path)
    bundle = make_bundle(IND_A, IND_B)

    receipt1 = receiver.receive(bundle, source="team-alpha")
    stored_before = dict(store.source._data)

    receipt2 = receiver.receive(bundle, source="team-alpha")
    assert receipt2.duplicate
    assert receipt2.receipt_id == receipt1.receipt_id
    assert receipt2.signed_at == receipt1.signed_at
    assert not receipt1.duplicate

    # The store is untouched and only one receipt exists on disk.
    assert store.source._data == stored_before
    receipts_dir = os.path.join(journal.directory, "receipts")
    assert len(os.listdir(receipts_dir)) == 1


def test_interrupted_intake_is_resumed_not_signed(tmp_path):
    receiver, store, journal = make_receiver(tmp_path)
    bundle = make_bundle(IND_A, IND_B, IND_C)
    checklist = [IND_A["id"], IND_B["id"], IND_C["id"]]

    # Simulate a crash partway through committing the batch.
    original_add = store.sink.add
    calls = {"count": 0}

    def flaky_add(stix_data, *args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 2:
            raise RuntimeError("simulated intake crash")
        return original_add(stix_data, *args, **kwargs)

    store.sink.add = flaky_add
    with pytest.raises(RuntimeError):
        receiver.receive(bundle, source="team-alpha", expected=checklist)

    # Nothing was signed: no receipt, checklist untouched, but the
    # interrupted batch is still in the staging area.
    assert os.listdir(os.path.join(journal.directory, "receipts")) == []
    assert journal.load_checklist()["received"] == {}
    assert os.listdir(os.path.join(journal.directory, "sessions")) != []
    # The first object did reach the store, yet is not signed for.
    assert store.get(IND_A["id"]) is not None

    # A fresh receiver over the same journal (process restart) resumes
    # the interrupted batch instead of signing it blindly.
    receiver2, _, journal2 = make_receiver(tmp_path, store=store)
    receipt = receiver2.receive(bundle, source="team-alpha")
    assert not receipt.duplicate
    assert [item["id"] for item in receipt.items] == [
        IND_A["id"], IND_B["id"], IND_C["id"],
    ]
    assert all(item["status"] == "stored" for item in receipt.items)
    assert receipt.verify(bundle) == []
    assert store.get(IND_B["id"]) is not None
    assert store.get(IND_C["id"]) is not None

    # The staging area is cleared once the batch is fully signed.
    assert os.listdir(os.path.join(journal2.directory, "sessions")) == []
    received = journal2.load_checklist()["received"]
    assert set(received) == set(checklist)


def test_unexpected_items_are_reported(tmp_path):
    receiver, _, _ = make_receiver(tmp_path)
    receipt = receiver.receive(
        make_bundle(IND_A, IND_C), source="team-alpha",
        expected=[IND_A["id"]],
    )
    assert receipt.unexpected == [IND_C["id"]]
    assert receipt.items[0]["expected"]
    assert not receipt.items[1]["expected"]
    assert receipt.missing == []


def test_content_digest_distinguishes_same_id_modified():
    from stix2.parsing import parse
    original = parse(IND_A)
    tampered = parse(IND_A_TAMPERED)
    assert original["id"] == tampered["id"]
    assert original["modified"] == tampered["modified"]
    assert content_digest(original) != content_digest(tampered)
