"""Tests for the file-based signing handoff (handoff package)."""

import json
import subprocess
import sys

import pytest

from handoff.fakesigner import FAKE_SCHEME, FakeKey, FakeSigner
from handoff.form import STATUS_ACTIVE, STATUS_REVOKED, STATUS_SEALED
from handoff.service import HandoffService
from handoff.store import FormStore

PAYLOAD = b"release-artifact\n"


def make_signer(key):
    return FakeSigner.from_priv_key_uri(
        f"{FAKE_SCHEME}:{key.keyval['public']}", key
    )


@pytest.fixture
def env(tmp_path):
    store = FormStore(tmp_path / "store")
    issuer_key = FakeKey.generate()
    alice, bob = FakeKey.generate(), FakeKey.generate()
    reviewer_keys = {k.keyid: k for k in (alice, bob)}
    service = HandoffService(store, issuer_key, reviewer_keys)
    return store, service, issuer_key, alice, bob


def create_form(service, issuer_key, reviewers, policy_rev=1):
    return service.create_form(
        PAYLOAD,
        [k.keyid for k in reviewers],
        policy_rev,
        make_signer(issuer_key),
    )


def sign(form, key):
    return HandoffService.build_submission(form, make_signer(key))


def test_import_valid_submission(env):
    _, service, issuer, alice, bob = env
    form = create_form(service, issuer, [alice, bob])
    result = service.import_submission(sign(form, alice))
    assert result.accepted and not result.duplicate


def test_idempotent_import(env):
    _, service, issuer, alice, bob = env
    form = create_form(service, issuer, [alice, bob])
    submission = sign(form, alice)
    assert service.import_submission(submission).accepted
    again = service.import_submission(submission)
    assert again.accepted and again.duplicate
    tampered = dict(submission, payload_sha256="0" * 64)
    assert not service.import_submission(tampered).accepted


def test_reject_valid_signature_on_revoked_form(env):
    """Acceptance: after the new form exists, an old form's valid
    signature is sent back and must be rejected."""
    _, service, issuer, alice, bob = env
    old_form = create_form(service, issuer, [alice, bob], policy_rev=1)
    old_submission = sign(old_form, alice)

    new_form = service.renew_form(
        old_form.form_id,
        PAYLOAD,
        [alice.keyid, bob.keyid],
        2,
        make_signer(issuer),
    )
    assert new_form.supersedes == old_form.form_id
    assert service.get_form(old_form.form_id).status == STATUS_REVOKED

    result = service.import_submission(old_submission)
    assert not result.accepted
    assert STATUS_REVOKED in result.reason

    assert service.import_submission(sign(new_form, alice)).accepted


def test_reject_replayed_submission_against_new_form(env):
    """A signature made for the old form cannot be replayed under the
    new form id: the signed bytes commit to the form id."""
    _, service, issuer, alice, bob = env
    old_form = create_form(service, issuer, [alice, bob], policy_rev=1)
    new_form = service.renew_form(
        old_form.form_id, PAYLOAD, [alice.keyid, bob.keyid], 2,
        make_signer(issuer),
    )
    replayed = sign(old_form, alice)
    replayed["form_id"] = new_form.form_id
    replayed["policy_revision"] = 2
    assert not service.import_submission(replayed).accepted


def test_reject_unknown_reviewer_and_bad_signature(env):
    _, service, issuer, alice, bob = env
    form = create_form(service, issuer, [alice])
    assert not service.import_submission(sign(form, bob)).accepted
    forged = sign(form, alice)
    forged["signature"]["sig"] = "0" * 64
    assert not service.import_submission(forged).accepted


def test_revoke_blocks_import(env):
    _, service, issuer, alice, bob = env
    form = create_form(service, issuer, [alice, bob])
    service.revoke_form(form.form_id)
    result = service.import_submission(sign(form, alice))
    assert not result.accepted
    assert STATUS_REVOKED in result.reason


def test_crash_mid_renew_recovers(env):
    """Crash after the new form is written but before the old one is
    revoked: recovery replays the journal and finishes the renew."""
    from handoff.form import ApprovalForm

    store, service, issuer, alice, bob = env
    old_form = create_form(service, issuer, [alice, bob], policy_rev=1)

    new_body = ApprovalForm(
        form_id="newform1",
        payload_sha256=old_form.payload_sha256,
        reviewers=old_form.reviewers,
        policy_revision=2,
        created_at=old_form.created_at,
        supersedes=old_form.form_id,
    )
    signed_new = service._issue(new_body, make_signer(issuer))
    # simulate crash: journal persisted, new form written, old form not
    # yet revoked, no done marker; plus a stale temp file
    store.journal_begin(
        "renew",
        {"new_form": signed_new.to_dict(), "revoke_form_id": old_form.form_id},
    )
    store.save_form(signed_new)
    stale = store.root / "forms" / f"{old_form.form_id}.json.tmp-1-abc"
    stale.write_bytes(b"partial")

    reopened = HandoffService(store, service.issuer_key, service.reviewer_keys)
    assert reopened.get_form("newform1").status == STATUS_ACTIVE
    assert reopened.get_form(old_form.form_id).status == STATUS_REVOKED
    assert not stale.exists()
    assert not store.pending_journals()


def test_seal_archives_and_records_location(env, tmp_path):
    store, service, issuer, alice, bob = env
    form = create_form(service, issuer, [alice, bob])
    service.import_submission(sign(form, alice))
    service.import_submission(sign(form, bob))

    manifest = service.seal_form(form.form_id)
    archive_dir = tmp_path / "store" / "archive" / form.form_id
    assert manifest["archived_to"] == str(archive_dir.resolve())
    assert (archive_dir / "form.json").exists()
    assert (archive_dir / "SEAL.json").exists()
    assert len(list((archive_dir / "submissions").glob("*.json"))) == 2
    assert service.get_form(form.form_id).status == STATUS_SEALED

    result = service.import_submission(sign(form, alice))
    assert not result.accepted
    assert STATUS_SEALED in result.reason


def test_crash_mid_seal_recovers(env, tmp_path):
    store, service, issuer, alice, bob = env
    form = create_form(service, issuer, [alice, bob])
    service.import_submission(sign(form, alice))
    store.journal_begin("seal", {"form_id": form.form_id})

    reopened = HandoffService(store, service.issuer_key, service.reviewer_keys)
    assert reopened.get_form(form.form_id).status == STATUS_SEALED
    archive_dir = tmp_path / "store" / "archive" / form.form_id
    assert (archive_dir / "SEAL.json").exists()


def test_cross_process_demo(tmp_path):
    """Two reviewers submit via separate processes and local inboxes."""
    root = tmp_path / "demo-store"
    proc = subprocess.run(
        [sys.executable, "-m", "handoff", "--root", str(root), "demo"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    assert "REJECTED" in out
    assert STATUS_REVOKED in out
    assert "archived_to" in out
    seal_files = list(root.glob("archive/*/SEAL.json"))
    assert len(seal_files) == 1
    manifest = json.loads(seal_files[0].read_text())
    assert manifest["archived_to"] == str(seal_files[0].parent.resolve())
