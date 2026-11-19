"""Handoff service: approval status is enforced, not just signatures.

The old handoff script merged any submission whose signature verified.
This service makes approval status real:

* submissions are bound to a form id and only importable while that form
  is ``active`` -- a valid signature against a revoked （作废） or sealed
  （封存） form is rejected;
* the submission must restate the form's payload digest and policy
  revision, so a signature made for a superseded form cannot be replayed
  against a new one;
* imports are idempotent per (form, reviewer): re-importing the same
  bytes is a no-op, conflicting bytes are rejected;
* renew （续签） and seal （封存） are journaled multi-step operations that
  survive a crash mid-write (see :class:`handoff.store.FormStore`).
"""

from __future__ import annotations

import secrets
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from securesystemslib.exceptions import UnverifiedSignatureError
from securesystemslib.formats import encode_canonical
from securesystemslib.signer import Key, Signature, Signer

from handoff.form import (
    STATUS_ACTIVE,
    STATUS_REVOKED,
    STATUS_SEALED,
    ApprovalForm,
    SignedForm,
    payload_digest,
)
from handoff.store import FormStore


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class ImportResult:
    accepted: bool
    duplicate: bool
    reason: str
    form_id: str | None = None
    reviewer: str | None = None


def submission_signed_bytes(submission: dict[str, Any]) -> bytes:
    """Canonical bytes a reviewer signs: the full commitment of a form."""
    return encode_canonical(
        {
            "form_id": submission["form_id"],
            "payload_sha256": submission["payload_sha256"],
            "policy_revision": submission["policy_revision"],
            "reviewer": submission["reviewer"],
        }
    ).encode("utf-8")


class HandoffService:
    def __init__(
        self,
        store: FormStore,
        issuer_key: Key,
        reviewer_keys: dict[str, Key],
    ):
        self.store = store
        self.issuer_key = issuer_key
        self.reviewer_keys = reviewer_keys
        self.store.recover(
            {
                "renew": lambda p: self._apply_renew(p),
                "seal": lambda p: self._apply_seal(p),
            }
        )

    # -- form lifecycle ------------------------------------------------------

    def _issue(self, form: ApprovalForm, signer: Signer) -> SignedForm:
        sig = signer.sign(form.canonical_bytes())
        return SignedForm(form=form, signatures=[sig.to_dict()])

    def create_form(
        self,
        payload: bytes,
        reviewers: list[str],
        policy_revision: int,
        issuer: Signer,
        supersedes: str | None = None,
    ) -> ApprovalForm:
        unknown = set(reviewers) - set(self.reviewer_keys)
        if unknown:
            raise ValueError(f"Unknown reviewers: {sorted(unknown)}")
        form = ApprovalForm(
            form_id=secrets.token_hex(8),
            payload_sha256=payload_digest(payload),
            reviewers=sorted(reviewers),
            policy_revision=policy_revision,
            created_at=_utcnow(),
            supersedes=supersedes,
        )
        self.store.save_form(self._issue(form, issuer))
        return form

    def renew_form(
        self,
        old_form_id: str,
        payload: bytes,
        reviewers: list[str],
        policy_revision: int,
        issuer: Signer,
    ) -> ApprovalForm:
        """续签: create the successor form and revoke the old one as one
        journaled, crash-safe operation."""
        old = self.store.load_form(old_form_id).form
        if old.status != STATUS_ACTIVE:
            raise ValueError(
                f"Cannot renew form {old_form_id} in status {old.status}"
            )
        new_form = ApprovalForm(
            form_id=secrets.token_hex(8),
            payload_sha256=payload_digest(payload),
            reviewers=sorted(reviewers),
            policy_revision=policy_revision,
            created_at=_utcnow(),
            supersedes=old_form_id,
        )
        signed_new = self._issue(new_form, issuer)
        payload_record = {
            "new_form": signed_new.to_dict(),
            "revoke_form_id": old_form_id,
        }
        journal = self.store.journal_begin("renew", payload_record)
        self._apply_renew(payload_record)
        self.store.journal_done(journal)
        return new_form

    def _apply_renew(self, payload: dict[str, Any]) -> None:
        signed_new = SignedForm.from_dict(payload["new_form"])
        self.store.save_form(signed_new)
        self._set_status(payload["revoke_form_id"], STATUS_REVOKED)

    def revoke_form(self, form_id: str) -> None:
        """作废: a revoked form rejects every further submission."""
        self._set_status(form_id, STATUS_REVOKED)

    def _set_status(self, form_id: str, status: str) -> None:
        signed = self.store.load_form(form_id)
        if signed.form.status == status:
            return
        signed.form.status = status
        self.store.save_form(signed)

    def get_form(self, form_id: str) -> ApprovalForm:
        return self.store.load_form(form_id).form

    # -- reviewer side (offline) ----------------------------------------------

    @staticmethod
    def build_submission(form: ApprovalForm, signer: Signer) -> dict[str, Any]:
        """What a reviewer produces offline and drops into the inbox."""
        submission = {
            "form_id": form.form_id,
            "payload_sha256": form.payload_sha256,
            "policy_revision": form.policy_revision,
            "reviewer": signer.public_key.keyid,
        }
        sig = signer.sign(submission_signed_bytes(submission))
        submission["signature"] = sig.to_dict()
        return submission

    # -- importer side ----------------------------------------------------------

    def import_submission(self, submission: dict[str, Any]) -> ImportResult:
        form_id = submission.get("form_id")
        reviewer = submission.get("reviewer")
        result = ImportResult(
            accepted=False,
            duplicate=False,
            reason="",
            form_id=form_id,
            reviewer=reviewer,
        )

        if not form_id or not self.store.has_form(form_id):
            result.reason = f"unknown form {form_id!r}"
            return result
        form = self.store.load_form(form_id).form

        if form.status != STATUS_ACTIVE:
            result.reason = (
                f"form {form_id} is {form.status}; "
                "signature validity does not matter anymore"
            )
            return result
        if submission.get("payload_sha256") != form.payload_sha256:
            result.reason = "payload digest does not match the form"
            return result
        if submission.get("policy_revision") != form.policy_revision:
            result.reason = "policy revision does not match the form"
            return result
        key = self.reviewer_keys.get(reviewer or "")
        if key is None or reviewer not in form.reviewers:
            result.reason = f"reviewer {reviewer!r} is not on the form"
            return result

        try:
            key.verify_signature(
                Signature.from_dict(dict(submission["signature"])),
                submission_signed_bytes(submission),
            )
        except UnverifiedSignatureError as e:
            result.reason = f"signature verification failed: {e}"
            return result

        if self.store.has_submission(form_id, reviewer):
            existing = self.store.load_submission(form_id, reviewer)
            if existing == submission:
                result.duplicate = True
                result.accepted = True
                result.reason = "already imported (idempotent no-op)"
                return result
            result.reason = "conflicting submission for same reviewer"
            return result

        self.store.save_submission(form_id, submission)
        result.accepted = True
        result.reason = "imported"
        return result

    def import_inbox(self, inbox: str | Path) -> list[ImportResult]:
        results = []
        for path in sorted(Path(inbox).glob("*.json")):
            results.append(self.import_submission(self.store.read_json(path)))
        return results

    # -- sealing -----------------------------------------------------------------

    def seal_form(self, form_id: str) -> dict[str, Any]:
        """封存: archive the form and its submissions, record where they went."""
        form = self.store.load_form(form_id).form
        if form.status == STATUS_REVOKED:
            raise ValueError(f"Cannot seal revoked form {form_id}")
        payload = {"form_id": form_id}
        journal = self.store.journal_begin("seal", payload)
        manifest = self._apply_seal(payload)
        self.store.journal_done(journal)
        return manifest

    def _apply_seal(self, payload: dict[str, Any]) -> dict[str, Any]:
        form_id = payload["form_id"]
        signed = self.store.load_form(form_id)
        archive_dir = (self.store.root / "archive" / form_id).resolve()
        archive_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self.store.form_path(form_id), archive_dir / "form.json")
        submissions = self.store.list_submissions(form_id)
        sub_dir = archive_dir / "submissions"
        sub_dir.mkdir(exist_ok=True)
        for submission in submissions:
            self.store.write_json(
                sub_dir / f"{submission['reviewer']}.json", submission
            )
        self._set_status(form_id, STATUS_SEALED)
        manifest = {
            "form_id": form_id,
            "sealed_at": _utcnow(),
            "status": STATUS_SEALED,
            "archived_to": str(archive_dir),
            "files": ["form.json"]
            + [f"submissions/{s['reviewer']}.json" for s in submissions],
            "note": (
                "Form and all accepted submissions were archived to "
                f"{archive_dir}; the form now rejects further submissions."
            ),
        }
        self.store.write_json(archive_dir / "SEAL.json", manifest)
        return manifest
