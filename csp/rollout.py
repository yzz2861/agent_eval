"""Audience-scoped decisions for moving from report-only to enforced CSP.

The classes in this module deliberately keep the policy *decision* separate
from the policy *document*.  A deployment can evaluate a request without
touching middleware state, persist the resulting :class:`RuntimeDecision`, and
then use that decision when selecting the enforced or report-only header.

Approvals are the only credentials that can authorize enforcement.  Observations
are useful evidence, but they are intentionally never promoted to an approval:
an observation made for one audience cannot be replayed as permission for a new
audience.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import date, datetime, time, timezone
from enum import Enum
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from django.conf import settings

from csp.constants import HEADER, HEADER_REPORT_ONLY

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponseBase

__all__ = [
    "Approval",
    "ApprovalGrant",
    "ApprovalLedger",
    "ApprovalWindow",
    "Audience",
    "CredentialKind",
    "CSPMode",
    "Decision",
    "DecisionEngine",
    "DecisionRejection",
    "EffectiveWindow",
    "Grant",
    "Observation",
    "PolicyWindow",
    "RejectedApproval",
    "ReleaseDecision",
    "Review",
    "ReviewRecord",
    "ReviewState",
    "ReviewStatus",
    "RolloutDecision",
    "RuntimeDecision",
    "decide",
    "decide_for_request",
    "decide_rollout",
    "evaluate_rollout",
    "get_decision",
    "get_runtime_decision",
    "make_decision",
    "resolve_decision",
]


class CSPMode(str, Enum):
    """The effective CSP mode for a single request."""

    REPORT_ONLY = "report_only"
    ENFORCE = "enforce"


class ReviewStatus(str, Enum):
    """The outcome of a review attached to an approval."""

    APPROVED = "approved"
    PENDING = "pending"
    CHANGES_REQUESTED = "changes_requested"
    REJECTED = "rejected"
    REVOKED = "revoked"


class CredentialKind(str, Enum):
    """What kind of evidence an approval-like record represents."""

    APPROVAL = "approval"
    OBSERVATION = "observation"
    UNKNOWN = "unknown"


_APPROVED_REVIEW_NAMES = {
    "accepted",
    "active",
    "approve",
    "approved",
    "complete",
    "completed",
    "ok",
    "pass",
    "passed",
    "signed_off",
    "signoff",
    "verified",
    "yes",
}
_PENDING_REVIEW_NAMES = {
    "draft",
    "in_review",
    "pending",
    "proposed",
    "requested",
    "review",
    "reviewing",
    "waiting",
}
_CHANGES_REVIEW_NAMES = {
    "changes",
    "changes_requested",
    "needs_changes",
    "rework",
}
_REJECTED_REVIEW_NAMES = {
    "blocked",
    "declined",
    "denied",
    "fail",
    "failed",
    "no",
    "reject",
    "rejected",
    "refused",
}
_REVOKED_REVIEW_NAMES = {
    "cancelled",
    "canceled",
    "expired",
    "revoke",
    "revoked",
    "superseded",
    "withdraw",
    "withdrawn",
}

_APPROVAL_CREDENTIAL_NAMES = {
    "approval",
    "approve",
    "approved",
    "authorization",
    "grant",
    "release",
    "review",
    "signoff",
    "signed_off",
}
_OBSERVATION_CREDENTIAL_NAMES = {
    "monitor",
    "monitoring",
    "observation",
    "observe",
    "observed",
    "report_only",
    "reportonly",
    "telemetry",
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        result = value
    elif isinstance(value, date):
        result = datetime.combine(value, time(0), tzinfo=timezone.utc)
    elif isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = f"{text[:-1]}+00:00"
        result = datetime.fromisoformat(text)
    else:
        raise TypeError(f"Expected a datetime, date, ISO string, or None; got {type(value)!r}.")

    if result.tzinfo is None:
        return result.replace(tzinfo=timezone.utc)
    return result.astimezone(timezone.utc)


def _as_text(value: Any, *, default: str = "") -> str:
    if value is None:
        return default
    return str(value)


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() not in {"", "0", "false", "no", "off"}
    return bool(value)


def _as_name_set(value: Any) -> frozenset[str]:
    if value is None:
        return frozenset()
    if isinstance(value, Audience):
        return frozenset({value.name})
    if isinstance(value, str):
        value = value.split(",")
    if not isinstance(value, Iterable):
        value = (value,)

    names: set[str] = set()
    for item in value:
        if isinstance(item, Audience):
            item = item.name
        name = str(item).strip()
        if name:
            names.add(name)
    return frozenset(names)


def _as_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(str(item) for item in value)


def _coerce_review_status(value: Any, *, default: ReviewStatus | None = None) -> ReviewStatus:
    if value is None:
        return default or ReviewStatus.APPROVED
    if isinstance(value, ReviewStatus):
        return value

    name = str(value).strip().lower().replace("-", "_").replace(" ", "_")
    if name in _APPROVED_REVIEW_NAMES:
        return ReviewStatus.APPROVED
    if name in _PENDING_REVIEW_NAMES:
        return ReviewStatus.PENDING
    if name in _CHANGES_REVIEW_NAMES:
        return ReviewStatus.CHANGES_REQUESTED
    if name in _REJECTED_REVIEW_NAMES:
        return ReviewStatus.REJECTED
    if name in _REVOKED_REVIEW_NAMES:
        return ReviewStatus.REVOKED
    return ReviewStatus.PENDING


def _coerce_credential_kind(value: Any) -> CredentialKind:
    if value is None:
        return CredentialKind.APPROVAL
    if isinstance(value, CredentialKind):
        return value

    name = str(value).strip().lower().replace("-", "_").replace(" ", "_")
    if name in _APPROVAL_CREDENTIAL_NAMES:
        return CredentialKind.APPROVAL
    if name in _OBSERVATION_CREDENTIAL_NAMES:
        return CredentialKind.OBSERVATION
    return CredentialKind.UNKNOWN


def _coerce_mode(value: Any, *, default: CSPMode = CSPMode.REPORT_ONLY) -> CSPMode:
    if value is None:
        return default
    if isinstance(value, CSPMode):
        return value

    name = str(value).strip().lower().replace("-", "_")
    if name in {"enforce", "enforced", "block", "blocking"}:
        return CSPMode.ENFORCE
    if name in {"report", "report_only", "reportonly", "observe", "observation"}:
        return CSPMode.REPORT_ONLY
    return default


@dataclass(frozen=True)
class Audience:
    """A named group that may receive a rollout change."""

    name: str

    def __str__(self) -> str:
        return self.name


@dataclass(frozen=True, init=False)
class PolicyWindow:
    """The half-open time interval in which a policy release is effective."""

    starts_at: datetime | None
    ends_at: datetime | None

    def __init__(self, starts_at: Any = None, ends_at: Any = None, **values: Any) -> None:
        if isinstance(starts_at, Mapping) and ends_at is None:
            values = {**starts_at, **values}
            starts_at = None

        starts_at = _first_present(
            starts_at,
            values,
            "start",
            "starts_at",
            "start_at",
            "effective_from",
            "not_before",
            "valid_from",
            "from",
            "from_",
        )
        ends_at = _first_present(
            ends_at,
            values,
            "end",
            "ends_at",
            "end_at",
            "effective_to",
            "not_after",
            "valid_until",
            "expires_at",
            "to",
            "until",
        )

        start = _as_datetime(starts_at)
        end = _as_datetime(ends_at)
        if start is not None and end is not None and start >= end:
            raise ValueError("Policy window start must be before its end.")

        object.__setattr__(self, "starts_at", start)
        object.__setattr__(self, "ends_at", end)

    @property
    def start(self) -> datetime | None:
        return self.starts_at

    @property
    def end(self) -> datetime | None:
        return self.ends_at

    @property
    def from_(self) -> datetime | None:
        return self.starts_at

    @property
    def to(self) -> datetime | None:
        return self.ends_at

    def contains(self, at: Any = None) -> bool:
        value = _as_datetime(at) or _utcnow()
        if self.starts_at is not None and value < self.starts_at:
            return False
        if self.ends_at is not None and value >= self.ends_at:
            return False
        return True

    @classmethod
    def covering(cls, starts_at: Any = None, ends_at: Any = None) -> PolicyWindow:
        return cls(starts_at=starts_at, ends_at=ends_at)


def _first_present(primary: Any, values: dict[str, Any], *names: str) -> Any:
    if primary is not None:
        return primary
    for name in names:
        if name in values and values[name] is not None:
            return values.pop(name)
    for name in names:
        values.pop(name, None)
    return None


def _coerce_window(value: Any, *, starts_at: Any = None, ends_at: Any = None) -> PolicyWindow:
    if isinstance(value, PolicyWindow):
        window = value
    elif isinstance(value, Mapping):
        window = PolicyWindow(**value)
    elif isinstance(value, (list, tuple)) and len(value) == 2:
        window = PolicyWindow(starts_at=value[0], ends_at=value[1])
    elif value is None:
        window = PolicyWindow()
    else:
        raise TypeError(f"Expected a PolicyWindow or mapping, got {type(value)!r}.")

    start = _as_datetime(starts_at) if starts_at is not None else window.starts_at
    end = _as_datetime(ends_at) if ends_at is not None else window.ends_at
    if start is not None and end is not None and start >= end:
        raise ValueError("Policy window start must be before its end.")
    return PolicyWindow(starts_at=start, ends_at=end)


@dataclass(frozen=True, init=False)
class Review:
    """A review outcome, optionally scoped to one approval."""

    approval_id: str | None
    status: ReviewStatus
    reviewed_by: str
    reviewed_at: datetime | None
    note: str

    def __init__(
        self,
        status: Any = None,
        *,
        approval_id: Any = None,
        reviewed_by: Any = None,
        reviewed_at: Any = None,
        note: Any = None,
        **values: Any,
    ) -> None:
        if isinstance(status, Mapping):
            values = {**status, **values}
            status = None
        status = _first_present(status, values, "review_status", "state", "outcome")
        approval_id = _first_present(approval_id, values, "approval", "grant_id")
        reviewed_by = _first_present(
            reviewed_by,
            values,
            "reviewer",
            "approved_by",
            "approved_by_id",
            "by",
            "actor",
        )
        reviewed_at = _first_present(reviewed_at, values, "at", "when", "created_at", "decided_at")
        note = _first_present(note, values, "reason", "comment", "detail")

        object.__setattr__(self, "approval_id", None if approval_id is None else str(approval_id))
        object.__setattr__(self, "status", _coerce_review_status(status))
        object.__setattr__(self, "reviewed_by", _as_text(reviewed_by))
        object.__setattr__(self, "reviewed_at", _as_datetime(reviewed_at))
        object.__setattr__(self, "note", _as_text(note))

    @property
    def review_status(self) -> ReviewStatus:
        return self.status

    @property
    def reviewer(self) -> str:
        return self.reviewed_by

    @property
    def approved(self) -> bool:
        return self.status is ReviewStatus.APPROVED

    @property
    def is_approved(self) -> bool:
        return self.approved

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> Review:
        return cls(**value)


_MISSING = object()


def _coerce_review(value: Any) -> Review:
    if isinstance(value, Review):
        return value
    if isinstance(value, Mapping):
        return Review.from_mapping(value)
    raise TypeError(f"Expected a Review or mapping, got {type(value)!r}.")


@dataclass(frozen=True, init=False)
class Approval:
    """An auditable authorization to enforce a policy for an audience and path."""

    approval_id: str
    audiences: frozenset[str]
    path: str
    starts_at: datetime | None
    ends_at: datetime | None
    review_status: ReviewStatus
    approved_by: str
    revoked_at: datetime | None
    revoked_by: str
    policy_id: str | None
    source: CredentialKind
    review: Review | None
    observation_ids: tuple[str, ...]
    metadata: Mapping[str, Any] = field(compare=False, repr=False)

    def __init__(
        self,
        approval_id: Any = None,
        audience: Any = None,
        path: Any = None,
        window: Any = None,
        review: Any = None,
        **values: Any,
    ) -> None:
        if isinstance(approval_id, Mapping):
            values = {**approval_id, **values}
            approval_id = values.pop("id", values.pop("approval_id", values.pop("grant_id", None)))
        elif approval_id is None:
            approval_id = values.pop("id", values.pop("approval_id", values.pop("grant_id", None)))
        if approval_id is None:
            raise TypeError("Approval requires an id.")
        if isinstance(audience, Mapping):
            values = {**audience, **values}
            audience = None

        audience = _first_present(audience, values, "audiences", "audience_id", "scope")
        path = _first_present(path, values, "path", "path_prefix", "path_pattern", "scope_path")
        window = _first_present(window, values, "window", "effective_window", "approval_window")

        starts_at = _first_present(
            None,
            values,
            "starts_at",
            "start_at",
            "effective_from",
            "not_before",
            "valid_from",
            "start",
        )
        ends_at = _first_present(
            None,
            values,
            "ends_at",
            "end_at",
            "effective_to",
            "not_after",
            "valid_until",
            "expires_at",
            "expires",
            "end",
        )
        if window is None and (starts_at is not None or ends_at is not None):
            window = PolicyWindow(starts_at=starts_at, ends_at=ends_at)
        else:
            window = _coerce_window(window, starts_at=starts_at, ends_at=ends_at)

        review_status = _first_present(
            None,
            values,
            "review_status",
            "review_state",
            "status",
            "state",
        )
        if review is None and "review" in values:
            review = values.pop("review")
        if review is not None:
            review = _coerce_review(review)
            if review_status is None:
                review_status = review.status
        elif isinstance(review_status, Review):
            review = review_status
            review_status = review.status
        if review_status is None and "approved" in values:
            approved = values.pop("approved")
            review_status = ReviewStatus.APPROVED if _as_bool(approved) else ReviewStatus.REJECTED

        approved_by = _first_present(
            None,
            values,
            "approved_by",
            "approved_by_id",
            "approver",
            "reviewer",
            "reviewed_by",
            "granted_by",
            "actor",
        )
        if approved_by is None and review is not None:
            approved_by = review.reviewed_by

        revoked_at = _first_present(
            None,
            values,
            "revoked_at",
            "withdrawn_at",
            "invalidated_at",
            "revocation_time",
        )
        revoked = values.pop("revoked", values.pop("is_revoked", None))
        if revoked_at is None and revoked:
            revoked_at = revoked if isinstance(revoked, (date, datetime, str)) else datetime.min.replace(tzinfo=timezone.utc)

        policy_id = _first_present(
            None,
            values,
            "policy_id",
            "policy",
            "policy_name",
            "policy_version",
            "policy_revision",
            "release_id",
        )
        source = _first_present(
            None,
            values,
            "source",
            "kind",
            "credential",
            "credential_kind",
            "credential_type",
            "evidence_kind",
            "basis",
        )
        if source is None and values.pop("derived_from_observation", False):
            source = CredentialKind.OBSERVATION

        observation_ids = _as_tuple(_first_present(None, values, "observation_ids", "observations", "based_on_observations"))
        revoked_by = _first_present(None, values, "revoked_by", "withdrawn_by")
        metadata = dict(values.pop("metadata", {}) or {})
        metadata.update(values)

        object.__setattr__(self, "approval_id", str(approval_id))
        object.__setattr__(self, "audiences", _as_name_set(audience))
        object.__setattr__(self, "path", _as_text(path, default="/") or "/")
        object.__setattr__(self, "starts_at", window.starts_at)
        object.__setattr__(self, "ends_at", window.ends_at)
        object.__setattr__(self, "review_status", _coerce_review_status(review_status))
        object.__setattr__(self, "approved_by", _as_text(approved_by))
        object.__setattr__(self, "revoked_at", _as_datetime(revoked_at))
        object.__setattr__(self, "revoked_by", _as_text(revoked_by))
        object.__setattr__(self, "policy_id", None if policy_id is None else str(policy_id))
        object.__setattr__(self, "source", _coerce_credential_kind(source))
        object.__setattr__(self, "review", review)
        object.__setattr__(self, "observation_ids", observation_ids)
        object.__setattr__(self, "metadata", MappingProxyType(metadata))

    @property
    def id(self) -> str:
        return self.approval_id

    @property
    def audience(self) -> str:
        return ", ".join(sorted(self.audiences))

    @property
    def window(self) -> PolicyWindow:
        return PolicyWindow(starts_at=self.starts_at, ends_at=self.ends_at)

    @property
    def reviewer(self) -> str:
        return self.approved_by

    @property
    def approver(self) -> str:
        return self.approved_by

    @property
    def kind(self) -> CredentialKind:
        return self.source

    @property
    def credential(self) -> CredentialKind:
        return self.source

    @property
    def policy(self) -> str | None:
        return self.policy_id

    @property
    def is_approved(self) -> bool:
        return self.review_status is ReviewStatus.APPROVED

    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None

    def is_observation(self) -> bool:
        return self.source is not CredentialKind.APPROVAL

    def revoked(self, at: Any = None, *, by: Any = None, reason: Any = None) -> Approval:
        metadata = dict(self.metadata)
        if reason is not None:
            metadata["revocation_reason"] = str(reason)
        return Approval(
            id=self.id,
            audiences=self.audiences,
            path=self.path,
            starts_at=self.starts_at,
            ends_at=self.ends_at,
            review_status=self.review_status,
            approved_by=self.approved_by,
            revoked_at=at,
            revoked_by=by,
            policy_id=self.policy_id,
            source=self.source,
            review=self.review,
            observation_ids=self.observation_ids,
            metadata=metadata,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "audiences": sorted(self.audiences),
            "path": self.path,
            "starts_at": _isoformat(self.starts_at),
            "ends_at": _isoformat(self.ends_at),
            "review_status": self.review_status.value,
            "approved_by": self.approved_by,
            "revoked_at": _isoformat(self.revoked_at),
            "revoked_by": self.revoked_by,
            "policy_id": self.policy_id,
            "source": self.source.value,
            "observation_ids": list(self.observation_ids),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> Approval:
        return cls(**value)


@dataclass(frozen=True, init=False)
class Observation:
    """Report-only evidence.  This is never a release credential by itself."""

    observation_id: str | None
    audiences: frozenset[str]
    path: str
    observed_at: datetime | None
    policy_id: str | None
    source: CredentialKind
    approval_id: str | None
    metadata: Mapping[str, Any] = field(compare=False, repr=False)

    def __init__(
        self,
        observation_id: Any = None,
        audience: Any = None,
        path: Any = None,
        observed_at: Any = None,
        policy_id: Any = None,
        **values: Any,
    ) -> None:
        if isinstance(observation_id, Mapping):
            values = {**observation_id, **values}
            observation_id = values.pop("id", values.pop("observation_id", None))
        elif observation_id is None:
            observation_id = values.pop("id", values.pop("observation_id", None))

        audience = _first_present(audience, values, "audiences", "audience_id", "scope")
        path = _first_present(path, values, "path", "path_prefix", "path_pattern")
        observed_at = _first_present(observed_at, values, "at", "when", "created_at", "seen_at")
        policy_id = _first_present(policy_id, values, "policy_version", "policy_revision")
        approval_id = _first_present(None, values, "approval_id", "grant_id", "review_id")
        metadata = dict(values.pop("metadata", {}) or {})
        metadata.update(values)

        object.__setattr__(self, "observation_id", None if observation_id is None else str(observation_id))
        object.__setattr__(self, "audiences", _as_name_set(audience))
        object.__setattr__(self, "path", _as_text(path, default="/") or "/")
        object.__setattr__(self, "observed_at", _as_datetime(observed_at))
        object.__setattr__(self, "policy_id", None if policy_id is None else str(policy_id))
        object.__setattr__(self, "source", CredentialKind.OBSERVATION)
        object.__setattr__(self, "approval_id", None if approval_id is None else str(approval_id))
        object.__setattr__(self, "metadata", MappingProxyType(metadata))

    @property
    def id(self) -> str | None:
        return self.observation_id

    @property
    def audience(self) -> str:
        return ", ".join(sorted(self.audiences))

    @property
    def kind(self) -> CredentialKind:
        return self.source

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "audiences": sorted(self.audiences),
            "path": self.path,
            "observed_at": _isoformat(self.observed_at),
            "policy_id": self.policy_id,
            "source": self.source.value,
            "approval_id": self.approval_id,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> Observation:
        return cls(**value)


@dataclass(frozen=True)
class DecisionRejection:
    """Why one candidate approval did not authorize enforcement."""

    approval_id: str
    code: str
    detail: str

    def __str__(self) -> str:
        return f"{self.approval_id}: {self.code} ({self.detail})"


@dataclass(frozen=True)
class RuntimeDecision:
    """An immutable, request-local CSP mode decision.

    ``used_approvals`` contains the approvals that were still effective at
    ``decided_at``.  Revoking one approval later does not mutate a decision
    already returned to a request; a new decision simply observes the new
    ledger state.
    """

    mode: CSPMode
    enforce: bool
    allowed: bool
    path: str
    audiences: tuple[str, ...]
    decided_at: datetime
    policy_id: str | None
    used_approvals: tuple[Approval, ...]
    rejections: tuple[DecisionRejection, ...]
    observations: tuple[Observation, ...]
    reason: str
    reasons: tuple[str, ...]
    policy: Any = None

    @property
    def audience(self) -> str:
        return ", ".join(self.audiences)

    @property
    def report_only(self) -> bool:
        return not self.enforce

    @property
    def header_name(self) -> str:
        return HEADER if self.enforce else HEADER_REPORT_ONLY

    @property
    def approvals(self) -> tuple[Approval, ...]:
        return self.used_approvals

    @property
    def used_approval_ids(self) -> tuple[str, ...]:
        return tuple(approval.id for approval in self.used_approvals)

    @property
    def approval_ids(self) -> tuple[str, ...]:
        return self.used_approval_ids

    @property
    def approvals_used(self) -> tuple[str, ...]:
        return self.used_approval_ids

    @property
    def approved_by(self) -> tuple[str, ...]:
        return tuple(approval.approved_by for approval in self.used_approvals if approval.approved_by)

    @property
    def approvers(self) -> tuple[str, ...]:
        return self.approved_by

    @property
    def used_by(self) -> tuple[str, ...]:
        return self.approved_by

    @property
    def is_enforced(self) -> bool:
        return self.enforce

    @property
    def at(self) -> datetime:
        return self.decided_at

    @property
    def evaluated_at(self) -> datetime:
        return self.decided_at

    @property
    def used_approval(self) -> Approval | None:
        return self.primary_approval

    @property
    def used_approval_id(self) -> str | None:
        return self.primary_approval_id

    @property
    def approval_id(self) -> str | None:
        return self.primary_approval_id

    @property
    def primary_approval(self) -> Approval | None:
        return self.used_approvals[0] if self.used_approvals else None

    @property
    def primary_approval_id(self) -> str | None:
        approval = self.primary_approval
        return None if approval is None else approval.id

    @property
    def approval(self) -> Approval | None:
        return self.primary_approval

    @property
    def rejected_approvals(self) -> tuple[DecisionRejection, ...]:
        return self.rejections

    def rejection_codes(self) -> tuple[str, ...]:
        """Return the distinct rejection codes in evaluation order."""

        return _dedupe(rejection.code for rejection in self.rejections)

    def headers(self, policy: str | None = None) -> dict[str, str]:
        """Return the appropriate CSP header for this decision.

        The caller still owns policy construction.  ``policy`` can also be
        supplied when the decision was created.
        """

        document = self.policy if policy is None else policy
        if document is None:
            return {}
        value = str(document)
        if not value:
            return {}
        return {self.header_name: value}

    def apply(self, response: HttpResponseBase, policy: str | None = None) -> HttpResponseBase:
        for name, value in self.headers(policy).items():
            response[name] = value
        return response

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode.value,
            "enforce": self.enforce,
            "allowed": self.allowed,
            "path": self.path,
            "audiences": list(self.audiences),
            "decided_at": _isoformat(self.decided_at),
            "policy_id": self.policy_id,
            "used_approvals": [approval.to_dict() for approval in self.used_approvals],
            "approval_ids": list(self.approval_ids),
            "approved_by": list(self.approved_by),
            "rejections": [
                {"approval_id": rejection.approval_id, "code": rejection.code, "detail": rejection.detail} for rejection in self.rejections
            ],
            "reason": self.reason,
            "reasons": list(self.reasons),
        }


def _isoformat(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat()


def _path_matches(scope: str, path: str) -> bool:
    scope = scope or "/"
    path = path or "/"
    if scope in {"", "*", "/"}:
        return True
    if any(character in scope for character in "*?["):
        return fnmatch.fnmatchcase(path, scope)
    if scope.endswith("/"):
        base = scope.rstrip("/")
        return path == base or path.startswith(scope)
    return path == scope or path.startswith(f"{scope}/")


def _normalize_approval(value: Any) -> Approval:
    if isinstance(value, Approval):
        return value
    if isinstance(value, Observation):
        return Approval(
            id=value.id or f"observation-{id(value)}",
            audiences=value.audiences,
            path=value.path,
            source=CredentialKind.OBSERVATION,
            policy_id=value.policy_id,
            metadata=dict(value.metadata),
        )
    if isinstance(value, Mapping):
        return Approval.from_mapping(value)
    raise TypeError(f"Expected an Approval or mapping, got {type(value)!r}.")


def _normalize_observation(value: Any) -> Observation:
    if isinstance(value, Observation):
        return value
    if isinstance(value, Mapping):
        return Observation.from_mapping(value)
    raise TypeError(f"Expected an Observation or mapping, got {type(value)!r}.")


def _latest_review(
    approval: Approval,
    reviews: Iterable[Review],
    at: datetime,
) -> tuple[ReviewStatus, str, str, Review | None]:
    candidates: list[Review] = []
    if approval.review is not None:
        candidates.append(approval.review)
    candidates.extend(review for review in reviews if review.approval_id is None or review.approval_id == approval.id)
    candidates = [review for review in candidates if review.reviewed_at is None or review.reviewed_at <= at]
    if not candidates:
        return approval.review_status, approval.approved_by, "", None

    latest = max(
        candidates,
        key=lambda review: review.reviewed_at or datetime.min.replace(tzinfo=timezone.utc),
    )
    return latest.status, latest.reviewed_by or approval.approved_by, latest.note, latest


def _review_rejection_code(status: ReviewStatus, *, require_review: bool) -> str | None:
    if status is ReviewStatus.APPROVED:
        return None
    if status is ReviewStatus.PENDING:
        return "review_pending" if require_review else None
    if status is ReviewStatus.CHANGES_REQUESTED:
        return "review_changes_requested"
    if status is ReviewStatus.REJECTED:
        return "review_rejected"
    if status is ReviewStatus.REVOKED:
        return "review_revoked"
    return "review_pending" if require_review else None


def decide(
    path: str = "/",
    audience: Any = None,
    *,
    at: Any = None,
    policy_id: Any = None,
    approvals: Iterable[Any] = (),
    reviews: Iterable[Any] = (),
    observations: Iterable[Any] = (),
    require_review: bool = True,
    default_mode: Any = CSPMode.REPORT_ONLY,
    policy: Any = None,
) -> RuntimeDecision:
    """Evaluate one request against the current approval ledger.

    An approval authorizes enforcement only when all of these are true at the
    decision time:

    * its credential kind is ``approval`` (never ``observation``),
    * its review status is approved,
    * its audience intersects the request audience,
    * its path scope covers the request path,
    * its policy id matches the requested policy, when both supply one,
    * its effective window contains the decision time, and
    * it has not been revoked at or before the decision time.

    If no approval qualifies, the decision falls back to ``default_mode``
    (report-only by default) and records why each candidate was rejected.
    """

    decided_at = _as_datetime(at) or _utcnow()
    path_value = str(path or "/")
    audiences = _as_name_set(audience)
    requested_policy = None if policy_id is None else str(policy_id)
    fallback_mode = _coerce_mode(default_mode, default=CSPMode.REPORT_ONLY)

    approval_records = [_normalize_approval(item) for item in (approvals or ())]
    review_records = [_coerce_review(item) for item in (reviews or ())]
    observation_records = [_normalize_observation(item) for item in (observations or ())]

    active: list[Approval] = []
    rejections: list[DecisionRejection] = []

    for approval in approval_records:
        status, reviewer, review_note, latest_review = _latest_review(approval, review_records, decided_at)
        detail_suffix = f" ({review_note})" if review_note else ""

        if approval.source is not CredentialKind.APPROVAL:
            code = "observation_credential" if approval.source is CredentialKind.OBSERVATION else "unknown_credential"
            rejections.append(
                DecisionRejection(
                    approval.id,
                    code,
                    "observation and unknown evidence cannot authorize a new audience",
                )
            )
            continue

        if approval.observation_ids and not (reviewer or approval.approved_by):
            rejections.append(
                DecisionRejection(
                    approval.id,
                    "observation_credential",
                    "observation evidence requires a separate approval reviewer",
                )
            )
            continue

        if not audiences:
            rejections.append(DecisionRejection(approval.id, "missing_request_audience", "request has no audience"))
            continue

        if approval.audiences.isdisjoint(audiences):
            rejections.append(
                DecisionRejection(
                    approval.id,
                    "audience_mismatch",
                    f"approved {sorted(approval.audiences)!r}; requested {sorted(audiences)!r}",
                )
            )
            continue

        if not _path_matches(approval.path, path_value):
            rejections.append(
                DecisionRejection(
                    approval.id,
                    "path_mismatch",
                    f"scope {approval.path!r} does not cover {path_value!r}",
                )
            )
            continue

        if requested_policy is not None and approval.policy_id is not None and approval.policy_id != requested_policy:
            rejections.append(
                DecisionRejection(
                    approval.id,
                    "policy_mismatch",
                    f"approval policy {approval.policy_id!r}; requested {requested_policy!r}",
                )
            )
            continue

        if approval.starts_at is not None and decided_at < approval.starts_at:
            rejections.append(
                DecisionRejection(
                    approval.id,
                    "not_yet_effective",
                    f"starts at {_isoformat(approval.starts_at)}",
                )
            )
            continue

        if approval.ends_at is not None and decided_at >= approval.ends_at:
            rejections.append(
                DecisionRejection(
                    approval.id,
                    "expired",
                    f"ended at {_isoformat(approval.ends_at)}",
                )
            )
            continue

        if approval.revoked_at is not None and decided_at >= approval.revoked_at:
            rejections.append(
                DecisionRejection(
                    approval.id,
                    "revoked",
                    f"revoked at {_isoformat(approval.revoked_at)}",
                )
            )
            continue

        review_code = _review_rejection_code(status, require_review=require_review)
        if review_code is not None:
            rejections.append(
                DecisionRejection(
                    approval.id,
                    review_code,
                    f"review status {status.value}{detail_suffix}",
                )
            )
            continue

        if reviewer:
            approval = Approval(
                id=approval.id,
                audiences=approval.audiences,
                path=approval.path,
                starts_at=approval.starts_at,
                ends_at=approval.ends_at,
                review_status=status,
                approved_by=reviewer,
                revoked_at=approval.revoked_at,
                revoked_by=approval.revoked_by,
                policy_id=approval.policy_id,
                source=approval.source,
                review=latest_review,
                observation_ids=approval.observation_ids,
                metadata=dict(approval.metadata),
            )
        active.append(approval)

    active.sort(key=lambda approval: (approval.starts_at or datetime.min.replace(tzinfo=timezone.utc), approval.id))
    enforce = bool(active)

    if enforce:
        reason = "approved"
        reasons: tuple[str, ...] = ()
    elif not audiences:
        reason = "missing_request_audience"
        reasons = ("missing_request_audience",)
    elif any(rejection.code == "observation_credential" for rejection in rejections):
        reason = "observation_is_not_a_release_credential"
        reasons = _dedupe(rejection.code for rejection in rejections)
    elif not approval_records and observation_records:
        reason = "observation_is_not_a_release_credential"
        reasons = ("observation_credential",)
    elif not approval_records:
        reason = "no_approvals"
        reasons = ("no_approvals",)
    else:
        reason = "no_active_approval"
        reasons = _dedupe(rejection.code for rejection in rejections)

    return RuntimeDecision(
        mode=CSPMode.ENFORCE if enforce else fallback_mode,
        enforce=enforce,
        allowed=enforce,
        path=path_value,
        audiences=tuple(sorted(audiences)),
        decided_at=decided_at,
        policy_id=requested_policy,
        used_approvals=tuple(active),
        rejections=tuple(rejections),
        observations=tuple(observation_records),
        reason=reason,
        reasons=reasons,
        policy=policy,
    )


def _dedupe(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


def decide_for_request(
    request: HttpRequest,
    *,
    audience: Any = None,
    at: Any = None,
    approvals: Iterable[Any] | None = None,
    reviews: Iterable[Any] | None = None,
    observations: Iterable[Any] | None = None,
    policy_id: Any = None,
    require_review: bool = True,
    default_mode: Any = CSPMode.REPORT_ONLY,
    policy: Any = None,
    config: Mapping[str, Any] | None = None,
) -> RuntimeDecision:
    """Decision entry point for a Django request.

    The request must expose its audience through ``request.csp_audiences``,
    ``request.csp_audience``, or ``request.audiences``.  Approval data can be
    supplied directly or through a ``CSP_ROLLOUT`` setting.  Audience data is
    never inferred from a user-supplied header.
    """

    path = getattr(request, "path_info", None) or getattr(request, "path", "/")
    if audience is None:
        audience = getattr(request, "csp_audiences", None)
        if audience is None:
            audience = getattr(request, "csp_audience", None)
        if audience is None:
            audience = getattr(request, "audiences", None)

    rollout_config = config
    if rollout_config is None:
        rollout_config = (getattr(settings, "CSP_ROLLOUT", None) if settings.configured else None) or {}

    if approvals is None:
        approvals = rollout_config.get("APPROVALS", rollout_config.get("approvals", ()))
    if reviews is None:
        reviews = rollout_config.get("REVIEWS", rollout_config.get("reviews", ()))
    if observations is None:
        observations = rollout_config.get("OBSERVATIONS", rollout_config.get("observations", ()))
    if policy_id is None:
        policy_id = rollout_config.get("POLICY_ID", rollout_config.get("policy_id"))

    decision = decide(
        path=path,
        audience=audience,
        at=at,
        policy_id=policy_id,
        approvals=approvals,
        reviews=reviews,
        observations=observations,
        require_review=require_review,
        default_mode=default_mode,
        policy=policy,
    )
    setattr(request, "csp_rollout_decision", decision)
    return decision


class ApprovalLedger:
    """A small in-memory ledger used by services and tests.

    Revocation replaces the stored approval with a new immutable record.  A
    :class:`RuntimeDecision` obtained earlier keeps pointing at the previous
    record, which makes historical decisions reproducible.
    """

    def __init__(
        self,
        approvals: Iterable[Any] = (),
        reviews: Iterable[Any] = (),
        observations: Iterable[Any] = (),
        *,
        clock: Any = None,
        require_review: bool = True,
        default_mode: Any = CSPMode.REPORT_ONLY,
    ) -> None:
        self._approvals: dict[str, Approval] = {}
        self._reviews: list[Review] = []
        self._observations: list[Observation] = []
        self.clock = clock or _utcnow
        self.require_review = require_review
        self.default_mode = _coerce_mode(default_mode)

        for approval in approvals or ():
            self.add(approval)
        for review in reviews or ():
            self.add_review(review)
        for observation in observations or ():
            self.add_observation(observation)

    @property
    def approvals(self) -> tuple[Approval, ...]:
        return tuple(self._approvals.values())

    @property
    def reviews(self) -> tuple[Review, ...]:
        return tuple(self._reviews)

    @property
    def observations(self) -> tuple[Observation, ...]:
        return tuple(self._observations)

    def add(self, approval: Any) -> Approval:
        record = _normalize_approval(approval)
        self._approvals[record.id] = record
        return record

    add_approval = add

    def approve(
        self,
        approval_id: str,
        audience: Any,
        path: str = "/",
        *,
        starts_at: Any = None,
        ends_at: Any = None,
        window: Any = None,
        approved_by: Any = None,
        review_status: Any = ReviewStatus.APPROVED,
        policy_id: Any = None,
        source: Any = CredentialKind.APPROVAL,
        **values: Any,
    ) -> Approval:
        record = Approval(
            id=approval_id,
            audience=audience,
            path=path,
            window=window,
            starts_at=starts_at,
            ends_at=ends_at,
            approved_by=approved_by,
            review_status=review_status,
            policy_id=policy_id,
            source=source,
            **values,
        )
        return self.add(record)

    grant = approve

    def get(self, approval_id: str) -> Approval:
        try:
            return self._approvals[str(approval_id)]
        except KeyError as exc:
            raise KeyError(f"Unknown approval {approval_id!r}.") from exc

    def revoke(
        self,
        approval_id: str,
        *,
        at: Any = None,
        by: Any = None,
        reason: Any = None,
    ) -> Approval:
        when = _as_datetime(at) or _as_datetime(self.clock()) or _utcnow()
        revoked = self.get(approval_id).revoked(when, by=by, reason=reason)
        self._approvals[revoked.id] = revoked
        return revoked

    withdraw = revoke

    def add_review(self, review: Any) -> Review:
        record = _coerce_review(review)
        self._reviews.append(record)
        return record

    review = add_review

    def add_observation(self, observation: Any) -> Observation:
        record = _normalize_observation(observation)
        self._observations.append(record)
        return record

    observe = add_observation

    def decide(
        self,
        path: str = "/",
        audience: Any = None,
        *,
        at: Any = None,
        policy_id: Any = None,
        require_review: bool | None = None,
        default_mode: Any = None,
        policy: Any = None,
    ) -> RuntimeDecision:
        return decide(
            path=path,
            audience=audience,
            at=_as_datetime(at) or _as_datetime(self.clock()) or _utcnow(),
            policy_id=policy_id,
            approvals=self._approvals.values(),
            reviews=self._reviews,
            observations=self._observations,
            require_review=self.require_review if require_review is None else require_review,
            default_mode=self.default_mode if default_mode is None else default_mode,
            policy=policy,
        )


class DecisionEngine:
    """Reusable decision engine for callers that do not need a mutable ledger."""

    def __init__(
        self,
        approvals: Iterable[Any] = (),
        reviews: Iterable[Any] = (),
        observations: Iterable[Any] = (),
        *,
        require_review: bool = True,
        default_mode: Any = CSPMode.REPORT_ONLY,
    ) -> None:
        self.approvals = tuple(_normalize_approval(approval) for approval in (approvals or ()))
        self.reviews = tuple(_coerce_review(review) for review in (reviews or ()))
        self.observations = tuple(_normalize_observation(observation) for observation in (observations or ()))
        self.require_review = require_review
        self.default_mode = _coerce_mode(default_mode)

    def decide(
        self,
        path: str = "/",
        audience: Any = None,
        *,
        at: Any = None,
        policy_id: Any = None,
        policy: Any = None,
    ) -> RuntimeDecision:
        return decide(
            path=path,
            audience=audience,
            at=at,
            policy_id=policy_id,
            approvals=self.approvals,
            reviews=self.reviews,
            observations=self.observations,
            require_review=self.require_review,
            default_mode=self.default_mode,
            policy=policy,
        )


# Common spellings used by integrations.  They all resolve to the same
# behavior, which keeps policy decisions consistent across call sites.
ApprovalGrant = Approval
ApprovalWindow = PolicyWindow
Decision = RuntimeDecision
EffectiveWindow = PolicyWindow
Grant = Approval
RejectedApproval = DecisionRejection
ReleaseDecision = RuntimeDecision
ReviewRecord = Review
ReviewState = ReviewStatus
RolloutDecision = RuntimeDecision

decide_rollout = decide
evaluate_rollout = decide
get_decision = decide
get_runtime_decision = decide
make_decision = decide
resolve_decision = decide
