"""Parsing of the frozen control-domain roster.

The roster is the authoritative statement of who actually holds each key id.
Every key lists the domain(s) that control it; entries are either confirmed
or candidate-only. Candidate ownership never silently upgrades to confirmed:
a key with no confirmed owner makes every reported metric a range and is
called out in the report as pending confirmation.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from securesystemslib.policy_review.models import (
    KeyOwnership,
    PolicyReviewError,
    Roster,
)

_STATUSES = frozenset({"confirmed", "candidate"})


def load_roster(path: str | Path) -> Roster:
    """Load a roster document from a JSON file."""
    try:
        with open(path, "rb") as file:
            data = json.load(file)
    except OSError as error:
        raise PolicyReviewError(f"cannot read roster file {path!s}: {error}") from error
    except json.JSONDecodeError as error:
        raise PolicyReviewError(f"invalid JSON in roster file: {error}") from error
    return parse_roster(data)


def parse_roster(data: Any) -> Roster:
    """Parse a roster document given as a decoded JSON object."""
    if not isinstance(data, dict):
        raise PolicyReviewError("roster document must be a JSON object")
    roster_id = _as_identifier(data.get("roster_id"), "roster_id", required=True)
    frozen_at = data.get("frozen_at")
    if frozen_at is not None and (not isinstance(frozen_at,
        str) or not frozen_at.strip()):
        raise PolicyReviewError(
            "field frozen_at must be a non-empty string when present"
        )

    raw_keys = data.get("keys")
    if not isinstance(raw_keys, list) or not raw_keys:
        raise PolicyReviewError("roster must contain a non-empty keys list")

    ownership: dict[str, KeyOwnership] = {}
    domains: set[str] = set()
    for position, raw_key in enumerate(raw_keys):
        if not isinstance(raw_key, dict):
            raise PolicyReviewError(
                f"key entry at position {position} must be an object"
            )
        keyid = _as_identifier(
            raw_key.get("keyid"), f"keyid at position {position}", required=True
        )
        assert keyid is not None
        if keyid in ownership:
            raise PolicyReviewError(f"duplicate roster entry for key id {keyid!r}")

        raw_owners = raw_key.get("owners")
        if not isinstance(raw_owners, list) or not raw_owners:
            raise PolicyReviewError(f"key {keyid!r}: owners must be a non-empty list")

        confirmed: set[str] = set()
        candidates: set[str] = set()
        for owner in raw_owners:
            domain, status = _parse_owner(owner, keyid)
            domains.add(domain)
            if status == "confirmed":
                confirmed.add(domain)
            else:
                candidates.add(domain)

        # A domain listed as confirmed is not still a pending candidate.
        candidates.difference_update(confirmed)
        ownership[keyid] = KeyOwnership(
            keyid=keyid,
            confirmed=frozenset(confirmed),
            candidates=frozenset(candidates),
        )

    return Roster(
        roster_id=roster_id,
        frozen_at=frozen_at,
        ownership=ownership,
        domains=frozenset(domains),
    )


def _parse_owner(owner: Any, keyid: str) -> tuple[str, str]:
    if not isinstance(owner, dict):
        raise PolicyReviewError(f"key {keyid!r}: every owner must be an object")
    domain = _as_identifier(owner.get("domain"), f"owner domain of key {keyid!r}", True)
    assert domain is not None
    status = owner.get("status", "confirmed")
    if status not in _STATUSES:
        raise PolicyReviewError(
            f"key {keyid!r}: owner status {status!r} must be one of {sorted(_STATUSES)}"
        )
    return domain, status


def _as_identifier(value: Any, what: str, required: bool) -> str | None:
    if value is None:
        if required:
            raise PolicyReviewError(f"missing required field {what!r}")
        return None
    if not isinstance(value, str) or not value.strip():
        raise PolicyReviewError(f"field {what!r} must be a non-empty string")
    return value
