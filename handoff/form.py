"""Approval form （单据） model.

A form is the unit of approval: it commits to exactly one payload digest,
a set of reviewer keyids and a policy revision. Its lifecycle is
``active`` -> ``revoked`` (superseded/作废） or ``active`` -> ``sealed``
（封存）. Only submissions bound to an *active* form are importable.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from securesystemslib.formats import encode_canonical

STATUS_ACTIVE = "active"
STATUS_REVOKED = "revoked"
STATUS_SEALED = "sealed"
STATUSES = (STATUS_ACTIVE, STATUS_REVOKED, STATUS_SEALED)


def payload_digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


@dataclass
class ApprovalForm:
    """The committed body of an approval form."""

    form_id: str
    payload_sha256: str
    reviewers: list[str]
    policy_revision: int
    created_at: str
    status: str = STATUS_ACTIVE
    supersedes: str | None = None

    def body_dict(self) -> dict[str, Any]:
        """The fields the form (and issuer signature) commit to."""
        return {
            "form_id": self.form_id,
            "payload_sha256": self.payload_sha256,
            "reviewers": sorted(self.reviewers),
            "policy_revision": self.policy_revision,
            "created_at": self.created_at,
            "status": self.status,
            "supersedes": self.supersedes,
        }

    def canonical_bytes(self) -> bytes:
        return encode_canonical(self.body_dict()).encode("utf-8")

    def to_dict(self) -> dict[str, Any]:
        return self.body_dict()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ApprovalForm":
        form = cls(
            form_id=data["form_id"],
            payload_sha256=data["payload_sha256"],
            reviewers=sorted(data["reviewers"]),
            policy_revision=int(data["policy_revision"]),
            created_at=data["created_at"],
            status=data.get("status", STATUS_ACTIVE),
            supersedes=data.get("supersedes"),
        )
        if form.status not in STATUSES:
            raise ValueError(f"Unknown form status: {form.status}")
        return form


@dataclass
class SignedForm:
    """A form plus the issuer's signatures over its canonical body."""

    form: ApprovalForm
    signatures: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"body": self.form.to_dict(), "signatures": self.signatures}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SignedForm":
        return cls(
            form=ApprovalForm.from_dict(data["body"]),
            signatures=list(data.get("signatures", [])),
        )
