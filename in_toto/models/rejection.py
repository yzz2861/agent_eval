# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Signed offline rejection ticket model.

A rejection ticket is separate from in-toto link metadata.  It records an
approver's explicit refusal for a particular layout version, step and
artifact digest, together with the time window in which the refusal is valid.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import attr

from in_toto.models.common import Signable

REJECTION_TYPE = "rejection"
REJECTION_TYPE_ALIASES = {
    "rejection",
    "rejection_ticket",
    "rejection-ticket",
    "rejectionticket",
    "rejection_vote",
    "rejection-vote",
    "veto",
    "veto_ticket",
}

_FIELD_ALIASES = {
    "layoutVersion": "layout_version",
    "version": "layout_version",
    "layout": "layout_version",
    "layout_id": "layout_version",
    "layout_digest": "layout_version",
    "step": "step_name",
    "stepName": "step_name",
    "step_id": "step_name",
    "name": "step_name",
    "artifact": "artifact_digest",
    "digest": "artifact_digest",
    "artifact_hash": "artifact_digest",
    "artifactDigest": "artifact_digest",
    "rejected_artifact": "artifact_digest",
    "rejected_artifact_digest": "artifact_digest",
    "hash": "artifact_digest",
    "approver_keyid": "approver",
    "approver_id": "approver",
    "approver_key": "approver",
    "reviewer": "approver",
    "reviewer_keyid": "approver",
    "not_before": "valid_from",
    "validFrom": "valid_from",
    "starts_at": "valid_from",
    "start": "valid_from",
    "not_after": "valid_until",
    "valid_to": "valid_until",
    "validTo": "valid_until",
    "validUntil": "valid_until",
    "expires_at": "valid_until",
    "expiration_time": "valid_until",
    "expiration": "valid_until",
    "deadline": "valid_until",
    "ends_at": "valid_until",
    "end": "valid_until",
    "issued_at": "issued_at",
    "signed_at": "issued_at",
    "created_at": "issued_at",
    "timestamp": "issued_at",
    "id": "ticket_id",
    "uuid": "ticket_id",
    "nonce": "ticket_id",
    "corrects": "supersedes",
    "correction_of": "supersedes",
    "replaces": "supersedes",
    "prior": "supersedes",
    "revision_number": "revision",
    "sequence": "revision",
    "seq": "revision",
    "chain": "chain_id",
    "review_id": "chain_id",
    "ballot_id": "chain_id",
    "subject_id": "chain_id",
    "artifact_name": "artifact_name",
    "path": "artifact_name",
}


def _isoformat(value: Any) -> Any:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=datetime.now().astimezone().tzinfo)
        return value.astimezone().isoformat().replace("+00:00", "Z")
    return value


@attr.s(repr=False, init=False)
class RejectionTicket(Signable):
    """Payload of a separately signed offline rejection ticket."""

    _type = attr.ib()
    layout_version = attr.ib()
    step_name = attr.ib()
    artifact_digest = attr.ib()
    approver = attr.ib()
    valid_from = attr.ib()
    valid_until = attr.ib()
    issued_at = attr.ib()
    ticket_id = attr.ib()
    reason = attr.ib()
    decision = attr.ib()
    supersedes = attr.ib()
    revision = attr.ib()
    chain_id = attr.ib()
    artifact_name = attr.ib()

    def __init__(self, **kwargs: Any):
        super().__init__()
        data = {}
        for key, value in kwargs.items():
            normalized_key = _FIELD_ALIASES.get(key, key)
            # Canonical names win over aliases when both are supplied.
            data.setdefault(normalized_key, value)
            if normalized_key not in data or key == normalized_key:
                data[normalized_key] = value

        ticket_type = data.get("_type", REJECTION_TYPE)
        if ticket_type in REJECTION_TYPE_ALIASES:
            ticket_type = REJECTION_TYPE

        self._type = ticket_type
        self.layout_version = data.get("layout_version")
        self.step_name = data.get("step_name")
        self.artifact_digest = data.get("artifact_digest")
        self.approver = data.get("approver")
        self.valid_from = _isoformat(data.get("valid_from"))
        self.valid_until = _isoformat(data.get("valid_until"))
        self.issued_at = _isoformat(data.get("issued_at"))
        self.ticket_id = data.get("ticket_id")
        self.reason = data.get("reason")
        self.decision = data.get("decision", "reject")
        self.supersedes = data.get("supersedes")
        self.revision = data.get("revision")
        self.chain_id = data.get("chain_id")
        self.artifact_name = data.get("artifact_name")
        self.validate()

    @property
    def type_(self) -> str:
        """Metadata payload type."""
        return self._type

    @property
    def step(self) -> Any:
        """Alias for the bound step name."""
        return self.step_name

    @property
    def version(self) -> Any:
        """Alias for the bound layout version."""
        return self.layout_version

    @property
    def expires(self) -> Any:
        """Alias for the end of the validity window."""
        return self.valid_until

    @expires.setter
    def expires(self, value: Any) -> None:
        self.valid_until = value

    @property
    def not_after(self) -> Any:
        """Alias for valid_until."""
        return self.valid_until

    @property
    def not_before(self) -> Any:
        """Alias for valid_from."""
        return self.valid_from

    @property
    def digest(self) -> Any:
        """Alias for artifact_digest."""
        return self.artifact_digest

    @property
    def approver_keyid(self) -> Any:
        """Alias for approver."""
        return self.approver

    @staticmethod
    def read(data: dict) -> "RejectionTicket":
        """Create a ticket from a JSON-compatible dictionary."""
        return RejectionTicket(**data)

    def to_dict(self) -> dict:
        """Return an attrs dictionary representation."""
        return attr.asdict(self)

    def sign(self, signer: Any) -> Any:
        """Sign this ticket and return the traditional in-toto metablock."""
        from in_toto.models.metadata import Metablock

        metadata = Metablock(signed=self, signatures=[])
        metadata.create_signature(signer)
        return metadata

    def _validate_type(self) -> None:
        if self._type not in REJECTION_TYPE_ALIASES:
            raise ValueError(
                f"Invalid rejection ticket _type: {self._type!r}."
            )

    def _validate_decision(self) -> None:
        if self.decision is not None and not isinstance(self.decision, str):
            raise ValueError("Rejection ticket decision must be a string.")


# Common domain-language aliases.
Rejection = RejectionTicket
RejectionReceipt = RejectionTicket
RejectionVote = RejectionTicket
VetoTicket = RejectionTicket
