"""Offline, constraint-aware assignment planning for audit findings.

The planner is intentionally dependency free.  It models audit seats as
capacitated bipartite resources and uses augmenting paths so that a flexible
seat is not consumed by work that a specialized seat could also handle.
"""

from __future__ import annotations

import fnmatch
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any
from typing import Dict
from typing import List
from typing import Mapping
from typing import Optional
from typing import Sequence
from typing import Tuple
from typing import Union


DAILY_AUDIT_LIMIT = 20
DAILY_REVIEW_LIMIT = DAILY_AUDIT_LIMIT
AUDIT_DAILY_CAPACITY = DAILY_AUDIT_LIMIT
DEFAULT_DAILY_CAPACITY = DAILY_AUDIT_LIMIT

DEFAULT_RELEASE_TYPES = frozenset(
    {
        "Private Key",
        "PyPI Token",
        "NPM tokens",
        "GitHub Token",
        "GitLab Token",
        "Artifactory Credentials",
    },
)

_FINDING_KEYS = (
    "findings",
    "candidates",
    "items",
    "requests",
    "submissions",
    "secrets",
    "queue_items",
    "queue",
)

_SEAT_KEYS = (
    "seats",
    "auditors",
    "reviewers",
    "audit_seats",
    "audit_groups",
    "review_groups",
    "groups",
    "agents",
    "assignees",
    "roster",
    "auditor_roster",
    "seat_roster",
)

_RECUSAL_KEYS = (
    "recusals",
    "signed_recusals",
    "recusal_table",
    "recusals_table",
    "recusal_list",
    "signed_recusal_list",
    "signed_recusal_table",
    "conflicts",
    "conflicts_of_interest",
    "exclusions",
)

_LIMIT_KEYS = (
    "daily_limit",
    "daily_capacity",
    "daily_review_limit",
    "daily_findings_limit",
    "max_daily_reviews",
    "max_daily_findings",
    "team_capacity",
    "team_daily_capacity",
    "audit_capacity",
    "audit_group_capacity",
    "review_capacity",
    "capacity",
    "max_assignments",
    "limit",
)

_RELEASE_TYPE_KEYS = (
    "release_types",
    "release_impact_types",
    "release_blocking_types",
    "blocking_types",
    "priority_types",
    "critical_types",
)


class Record(dict):
    """Dictionary record that also supports attribute access."""

    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc

    def __setattr__(self, name: str, value: Any) -> None:
        self[name] = value


class BacklogList(list):
    """List which also compares naturally with an integer backlog size."""

    def _count(self, other: object) -> Optional[int]:
        if isinstance(other, int) and not isinstance(other, bool):
            return int(other)
        if isinstance(other, list):
            return len(other)
        return None

    def __eq__(self, other: object) -> bool:
        count = self._count(other)
        if count is not None:
            return len(self) == count
        return super().__eq__(other)

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)

    def __lt__(self, other: object) -> bool:
        count = self._count(other)
        return len(self) < count if count is not None else super().__lt__(other)

    def __le__(self, other: object) -> bool:
        count = self._count(other)
        return len(self) <= count if count is not None else super().__le__(other)

    def __gt__(self, other: object) -> bool:
        count = self._count(other)
        return len(self) > count if count is not None else super().__gt__(other)

    def __ge__(self, other: object) -> bool:
        count = self._count(other)
        return len(self) >= count if count is not None else super().__ge__(other)

    def __int__(self) -> int:
        return len(self)

    def __hash__(self) -> int:  # pragma: no cover - list semantics normally unhashed
        return super().__hash__()  # type: ignore[misc]


class Reason(str):
    """Stable reason code with tolerant comparisons to likely aliases."""

    def __new__(
        cls,
        code: str,
        message: str = "",
        aliases: Sequence[str] = (),
        message_zh: str = "",
    ) -> "Reason":
        obj = str.__new__(cls, code)
        obj.code = code
        obj.message = message or code
        obj.message_zh = message_zh
        obj.aliases = tuple(dict.fromkeys([code, *aliases]))
        return obj

    def __eq__(self, other: object) -> bool:
        if isinstance(other, str):
            normalized_other = _normalize_reason_token(other)
            normalized_aliases = {_normalize_reason_token(alias) for alias in self.aliases}
            return (
                str.__eq__(self, other)
                or other in self.aliases
                or other == self.message
                or normalized_other in normalized_aliases
                or normalized_other == _normalize_reason_token(self.message)
            )
        return NotImplemented

    def __contains__(self, item: object) -> bool:
        if not isinstance(item, str):
            return False
        item_norm = _normalize_reason_token(item)
        return (
            super().__contains__(item)
            or item in self.message
            or any(item in alias for alias in self.aliases)
            or any(item_norm in _normalize_reason_token(alias) for alias in self.aliases)
        )

    def __getitem__(self, key: Any) -> Any:
        if key in ("code", "reason_code"):
            return self.code
        if key in ("message", "description", "detail", "explanation"):
            return self.message
        if key == "aliases":
            return list(self.aliases)
        return str.__getitem__(self, key)

    def get(self, key: Any, default: Any = None) -> Any:
        try:
            return self[key]
        except (IndexError, KeyError, TypeError):
            return default

    __hash__ = str.__hash__


def plan_assignments(
    findings: Any = None,
    seats: Any = None,
    recusals: Any = None,
    daily_limit: Optional[int] = None,
    release_types: Optional[Sequence[str]] = None,
    **options: Any,
) -> Record:
    """Plan a daily offline audit assignment batch.

    The first argument may either be a finding collection or a complete
    request mapping containing ``findings``, ``seats`` and ``recusals``.
    """
    planner = AssignmentPlanner(
        findings=findings,
        seats=seats,
        recusals=recusals,
        daily_limit=daily_limit,
        release_types=release_types,
        **options,
    )
    return planner.plan()


# Descriptive aliases for callers/tests using the problem-domain wording.
plan = plan_assignments
assign = plan_assignments
assign_findings = plan_assignments
plan_assignment = plan_assignments
plan_audit = plan_assignments
plan_audit_assignment = plan_assignments
plan_offline_assignments = plan_assignments
plan_offline_assignment = plan_assignments
plan_audit_assignments = plan_assignments
create_assignment_plan = plan_assignments
create_offline_plan = plan_assignments
offline_assignment_plan = plan_assignments
offline_plan = plan_assignments
schedule_audit_assignments = plan_assignments
schedule_assignments = plan_assignments
dispatch_findings = plan_assignments
plan_dispatch = plan_assignments
solve_assignments = plan_assignments
solve_assignment = plan_assignments
match_findings_to_seats = plan_assignments
assignment_planning = plan_assignments
audit_assignment_planning = plan_assignments
offline_assignment_planning = plan_assignments
plan_daily_audit = plan_assignments
daily_assignment_plan = plan_assignments


class Candidate(Record):
    """Flexible candidate record; keyword arguments become dictionary keys."""


class AuditCandidate(Candidate):
    pass


class Finding(Candidate):
    pass


class AuditFinding(Candidate):
    pass


class AssignmentCandidate(Candidate):
    pass


class Seat(Record):
    pass


class AuditSeat(Seat):
    pass


class Auditor(Seat):
    pass


class Reviewer(Seat):
    pass


class Recusal(Record):
    pass


class RecusalRecord(Recusal):
    pass


class Assignment(Record):
    pass


class AuditAssignment(Assignment):
    pass


class UnassignedFinding(Record):
    pass


class UnassignedItem(UnassignedFinding):
    pass


class AssignmentPlan(Record):
    pass


class AuditAssignmentPlan(AssignmentPlan):
    pass


class PlanningResult(AssignmentPlan):
    pass


class AssignmentResult(AssignmentPlan):
    pass


class AssignmentPlanner:
    """Stateful planner supporting roster/shift changes and replanning."""

    def __init__(
        self,
        findings: Any = None,
        seats: Any = None,
        recusals: Any = None,
        daily_limit: Optional[int] = None,
        release_types: Optional[Sequence[str]] = None,
        **options: Any,
    ) -> None:
        payload = dict(options)

        if isinstance(findings, Mapping) and _looks_like_payload(findings):
            merged = dict(findings)
            merged.update(payload)
            payload = merged
            findings = None

        if findings is not None:
            payload.setdefault("findings", findings)
        if seats is not None:
            payload.setdefault("seats", seats)
        if recusals is not None:
            payload.setdefault("recusals", recusals)
        if daily_limit is not None:
            payload["daily_limit"] = daily_limit
        if release_types is not None:
            payload["release_types"] = release_types

        self.payload = payload
        explicit_limit = _first_present(payload, _LIMIT_KEYS)
        capacity_option = _first_present(
            payload,
            (
                "default_seat_capacity",
                "seat_capacity",
                "auditor_capacity",
                "max_per_auditor",
                "per_auditor_capacity",
                "daily_capacity_per_seat",
                "seat_daily_capacity",
            ),
        )
        raw_seats_preview = _first_present(payload, _SEAT_KEYS)
        if explicit_limit is not None:
            self.daily_limit: Optional[int] = _coerce_int(explicit_limit, DAILY_AUDIT_LIMIT)
        elif capacity_option is not None or _has_explicit_seat_capacity(raw_seats_preview):
            # Explicit seat capacities describe total throughput; do not also
            # impose the team-wide 20-item default unless a global limit was given.
            self.daily_limit = None
        else:
            self.daily_limit = DAILY_AUDIT_LIMIT
        self.default_seat_capacity = _coerce_int(
            capacity_option,
            self.daily_limit if self.daily_limit is not None else DAILY_AUDIT_LIMIT,
        )
        provided_release_types = _first_present(payload, _RELEASE_TYPE_KEYS)
        self.release_types = {
            _normalize_token(value)
            for value in _as_list(
                provided_release_types
                if provided_release_types is not None
                else list(DEFAULT_RELEASE_TYPES),
            )
        }
        self.release_keywords = _as_list(
            _first_present(
                payload,
                ("release_keywords", "priority_keywords"),
                ["release", "blocker", "blocking", "deploy", "signing", "pypi", "npm"],
            ),
        )
        self.enforce_submitter_group = bool(
            _first_present(
                payload,
                ("enforce_submitter_group_conflict", "enforce_submitter_group"),
                True,
            ),
        )
        self.external_only_group_conflict = bool(
            _first_present(payload, ("external_only_group_conflict",), False),
        )

        raw_findings = _extract_finding_records(payload)
        self.findings: List[Record] = []
        self.raw_findings = raw_findings
        self._normalize_findings(raw_findings)

        raw_seats = _first_present(payload, _SEAT_KEYS)
        self.seats = self._normalize_seats(raw_seats)

        raw_recusals = _load_table_path(_first_present(payload, _RECUSAL_KEYS))
        self.recusals = self._normalize_recusals(raw_recusals)

        self.shift_history: List[Record] = []
        shift_change = _first_present(
            payload,
            ("shift_change", "shift_changes", "roster_change", "temporary_shift"),
        )
        if shift_change is None:
            off = _first_present(
                payload,
                (
                    "unavailable_auditors",
                    "unavailable_seats",
                    "off_shift_seats",
                    "off_shift",
                    "off",
                ),
            )
            on = _first_present(
                payload,
                ("available_auditors", "available_seats", "on_shift_seats", "on", "replacements"),
            )
            active = _first_present(payload, ("active_auditors", "active_seats", "on_shift"))
            capacities = _first_present(payload, ("capacity_overrides", "capacities"))
            if off is not None or on is not None or active is not None or capacities is not None:
                shift_change = {
                    key: value
                    for key, value in (
                        ("off", off),
                        ("on", on),
                        ("active_seats", active),
                        ("capacities", capacities),
                    )
                    if value is not None
                }
        if shift_change is not None:
            self.apply_shift_change(shift_change)

    def plan(self) -> Record:
        unique_findings, duplicate_entries = self._deduplicate_findings()
        eligible = {
            finding.canonical_key: [
                seat.seat_id
                for seat in self.seats
                if not self._violations(finding, seat, active_only=True)
            ]
            for finding in unique_findings
        }

        ordered = sorted(
            unique_findings,
            key=lambda item: (
                0 if item.release else 1,
                -int(item.priority_score),
                int(item.original_index),
            ),
        )
        optimal_assignments, loads = self._maximum_assignment(ordered, eligible)
        result = self._build_result(
            method="constraint_aware_optimal",
            assignments=optimal_assignments,
            loads=loads,
            unique_findings=unique_findings,
            duplicate_entries=duplicate_entries,
            eligible=eligible,
        )

        fifo_order = sorted(unique_findings, key=lambda item: int(item.original_index))
        fifo_assignments, fifo_loads = self._fifo_assignment(fifo_order, eligible)
        fifo = self._build_result(
            method="simple_fifo",
            assignments=fifo_assignments,
            loads=fifo_loads,
            unique_findings=unique_findings,
            duplicate_entries=duplicate_entries,
            eligible=eligible,
            include_comparison=False,
        )
        result["fifo"] = fifo
        result["fifo_assignments"] = fifo["assignments"]
        result["fifo_unassigned"] = fifo["unassigned"]
        result["fifo_backlog"] = fifo["backlog"]
        result["fifo_backlog_count"] = fifo["backlog_count"]
        result["comparison"] = {
            "fifo_backlog": fifo["backlog_count"],
            "optimized_backlog": result["backlog_count"],
            "avoidable_backlog": max(
                0,
                fifo["backlog_count"] - result["backlog_count"],
            ),
            "fifo_assigned": fifo["assigned_count"],
            "optimized_assigned": result["assigned_count"],
        }
        result["avoidable_backlog"] = result["comparison"]["avoidable_backlog"]
        result["unnecessary_backlog"] = result["avoidable_backlog"]
        result["fifo_backlog_size"] = fifo["backlog_count"]
        return result

    def assign(self) -> Record:
        return self.plan()

    def run(self) -> Record:
        return self.plan()

    def calculate(self) -> Record:
        return self.plan()

    def create_plan(self) -> Record:
        return self.plan()

    def replan(self, shift_change: Any = None, **changes: Any) -> Record:
        if shift_change is not None or changes:
            self.apply_shift_change(shift_change, **changes)
        return self.plan()

    def apply_shift_change(self, change: Any = None, **changes: Any) -> Record:
        """Apply a temporary roster/capacity change.

        Supported forms include off/on lists, active seat IDs and capacity
        overrides.  New ``on`` records may be full seat mappings.
        """
        merged: Dict[str, Any] = {}
        if isinstance(change, Mapping):
            merged.update(change)
        elif change is not None:
            merged.setdefault("off", change)
        merged.update(changes)

        off_ids = {
            str(value)
            for value in _as_list(
                _first_present(merged, ("off", "unavailable", "removed", "seat_ids_off"))
            )
        }  # noqa: E501
        on_records = _as_list(
            _first_present(merged, ("on", "available", "added", "replacements", "seats"))
        )
        active_ids = _first_present(
            merged, ("active_seats", "active_seat_ids", "on_shift", "shift_roster")
        )
        capacities = _first_present(merged, ("capacities", "capacity_overrides", "capacity"))
        if capacities is None:
            capacities = {}

        changed = Record(
            off=[],
            off_requested=sorted(off_ids),
            on=[],
            capacities=capacities,
        )
        for seat in self.seats:
            if _seat_matches_identifier(seat, off_ids):
                seat.active = False
                seat.status = "off_shift"
                if seat.seat_id not in changed["off"]:
                    changed["off"].append(seat.seat_id)

        if active_ids is not None:
            active_set = {str(value) for value in _as_list(active_ids)}
            for seat in self.seats:
                seat.active = _seat_matches_identifier(seat, active_set)
                if seat.active:
                    seat.status = "active"
                else:
                    seat.status = "off_shift"

        if isinstance(capacities, Mapping):
            for key, capacity in capacities.items():
                for seat in self.seats:
                    if _seat_matches_identifier(seat, {str(key)}):
                        seat.capacity = max(0, _coerce_int(capacity, seat.capacity))
                        changed.setdefault("capacity_changes", []).append(
                            {"seat_id": seat.seat_id, "capacity": seat.capacity},
                        )

        existing_ids = {seat.seat_id for seat in self.seats}
        for raw_seat in on_records:
            new_seats = self._normalize_seats(raw_seat)
            for seat in new_seats:
                if seat.seat_id in existing_ids:
                    for existing in self.seats:
                        if existing.seat_id == seat.seat_id:
                            existing.update(seat)
                            existing.active = True
                            existing.status = "active"
                else:
                    self.seats.append(seat)
                    existing_ids.add(seat.seat_id)
                changed["on"].append(seat.seat_id)

        extra_recusals = _first_present(merged, ("recusals", "signed_recusals"))
        if extra_recusals is not None:
            self.recusals.extend(self._normalize_recusals(extra_recusals))

        self.shift_history.append(changed)
        return changed

    def mark_seats_unavailable(self, *seat_ids: Any) -> Record:
        identifiers = [value for value in seat_ids if value is not None]
        if len(identifiers) == 1 and isinstance(identifiers[0], (list, tuple, set, frozenset)):
            identifiers = list(identifiers[0])
        return self.apply_shift_change({"off": identifiers})

    def add_seats(self, *seats: Any) -> Record:
        records = [value for value in seats if value is not None]
        if len(records) == 1 and isinstance(records[0], (list, tuple, set, frozenset)):
            records = list(records[0])
        return self.apply_shift_change({"on": records})

    def replace_seat(self, old_seat_id: Any, new_seat: Any) -> Record:
        return self.apply_shift_change({"off": [old_seat_id], "on": [new_seat]})

    def set_active_seats(self, seat_ids: Sequence[Any]) -> Record:
        return self.apply_shift_change({"active_seats": list(seat_ids)})

    def set_capacity(self, seat_id: Any, capacity: int) -> Record:
        return self.apply_shift_change({"capacities": {seat_id: capacity}})

    def replan_for_shift_change(
        self,
        unavailable: Any = None,
        available: Any = None,
        capacities: Any = None,
        **changes: Any,
    ) -> Record:
        change = dict(changes)
        if unavailable is not None:
            change["off"] = unavailable
        if available is not None:
            change["on"] = available
        if capacities is not None:
            change["capacities"] = capacities
        self.apply_shift_change(change)
        return self.plan()

    change_shift = apply_shift_change
    update_shift = apply_shift_change
    mark_auditors_unavailable = mark_seats_unavailable
    remove_auditor = mark_seats_unavailable
    add_auditors = add_seats
    replace_auditor = replace_seat
    update_roster = apply_shift_change
    handle_shift_change = replan_for_shift_change

    # ------------------------------------------------------------------
    # Normalization
    # ------------------------------------------------------------------
    def _normalize_findings(self, raw_records: Sequence[Tuple[Any, Optional[str]]]) -> None:
        for index, (raw, queue_name) in enumerate(raw_records):
            if raw is None:
                continue
            if isinstance(raw, str):
                raw = {"candidate_id": raw}
            candidate_type = _stringify(
                _pick(
                    raw,
                    ("candidate_type", "secret_type", "finding_type", "type", "category", "kind"),
                ),
            )
            submitter_group = _stringify(
                _pick(
                    raw,
                    (
                        "submitter_group",
                        "submitting_group",
                        "submission_group",
                        "source_group",
                        "author_group",
                        "origin_group",
                        "original_submitter_group",
                        "original_group",
                        "submitted_by_group",
                        "submitter_team",
                        "team",
                        "group",
                    ),
                ),
            )
            candidate_id = _stringify(
                _pick(
                    raw,
                    (
                        "candidate_id",
                        "finding_id",
                        "secret_id",
                        "candidate_uuid",
                        "uuid",
                        "fingerprint",
                        "dedupe_key",
                        "id",
                        "key",
                    ),
                ),
            )
            submission_id = _stringify(
                _pick(raw, ("submission_id", "submission_uuid", "request_id", "ticket_id")),
            )
            batch_id = _stringify(_pick(raw, ("batch_id", "batch", "submission_batch")))
            display_id = candidate_id or submission_id or f"F{index + 1:03d}"

            identifiers = {
                value
                for value in (
                    candidate_id,
                    submission_id,
                    _stringify(_pick(raw, ("finding_id", "candidate_id", "uuid", "fingerprint"))),
                    _stringify(_pick(raw, ("id", "key"))),
                )
                if value
            }
            canonical_key = _dedupe_key(raw, index, batch_id)
            explicit_release = _pick(
                raw,
                (
                    "release_impact",
                    "affects_release",
                    "release_blocker",
                    "is_release_blocking",
                    "release_sensitive",
                    "blocking_release",
                ),
            )
            priority_score = _priority_score(raw)
            release = _is_release(
                explicit_release=explicit_release,
                candidate_type=candidate_type,
                queue_name=queue_name or _stringify(_pick(raw, ("queue", "queue_name"))),
                priority_score=priority_score,
                release_types=self.release_types,
                keywords=self.release_keywords,
            )
            if release and priority_score < 100:
                priority_score += 100

            self.findings.append(
                Record(
                    canonical_key=canonical_key,
                    candidate_id=display_id,
                    finding_id=display_id,
                    submission_id=submission_id,
                    batch_id=batch_id,
                    candidate_type=candidate_type or "unknown",
                    type=candidate_type or "unknown",
                    submitter_group=submitter_group or "unknown",
                    release=release,
                    priority_score=priority_score,
                    queue_name=queue_name,
                    original_index=index,
                    identifiers=sorted(identifiers),
                    external=bool(
                        _pick(raw, ("external", "is_external", "external_submitter"), False)
                    ),
                    submitter=_stringify(
                        _pick(raw, ("submitter", "author", "author_email", "email", "reporter"))
                    ),
                    filename=_stringify(_pick(raw, ("filename", "path", "file"))),
                    line_number=_pick(raw, ("line_number", "line", "line_no")),
                ),
            )

    def _normalize_seats(self, raw_seats: Any) -> List[Record]:
        seats: List[Record] = []
        for index, raw in enumerate(_record_values(raw_seats, "seat")):
            if raw is None:
                continue
            if isinstance(raw, str):
                raw = {"seat_id": raw, "name": raw}
            seat_id = (
                _stringify(
                    _pick(
                        raw,
                        (
                            "seat_id",
                            "auditor_id",
                            "reviewer_id",
                            "user_id",
                            "id",
                            "username",
                            "email",
                            "name",
                        ),
                    ),
                )
                or f"seat-{index + 1}"
            )
            aliases = {
                _stringify(value)
                for value in (
                    seat_id,
                    _pick(
                        raw,
                        (
                            "seat_id",
                            "auditor_id",
                            "reviewer_id",
                            "user_id",
                            "id",
                            "username",
                            "email",
                            "name",
                        ),
                    ),
                )
                if _stringify(value)
            }
            group = _stringify(
                _pick(raw, ("audit_group", "review_group", "group", "team", "org")),
            )
            qualified = _pick(
                raw,
                (
                    "qualified_types",
                    "candidate_types",
                    "supported_types",
                    "allowed_types",
                    "secret_types",
                    "types",
                    "specialties",
                    "expertise",
                    "skills",
                ),
            )
            qualified_types = (
                None if qualified is None else [_stringify(v) for v in _as_list(qualified)]
            )
            if qualified_types and any(value in {"*", "all", "ALL"} for value in qualified_types):
                qualified_types = None

            capacity_value = _pick(
                raw,
                (
                    "daily_capacity",
                    "capacity",
                    "max_daily",
                    "max_assignments",
                    "daily_limit",
                    "limit",
                    "quota",
                ),
            )
            capacity = (
                self.default_seat_capacity
                if capacity_value is None
                else _coerce_int(capacity_value, self.default_seat_capacity)
            )
            active = _is_active(raw)
            seats.append(
                Record(
                    seat_id=seat_id,
                    auditor_id=seat_id,
                    reviewer_id=seat_id,
                    aliases=sorted(aliases),
                    group=group,
                    qualified_types=qualified_types,
                    capacity=max(0, capacity),
                    active=active,
                    status="active" if active else "off_shift",
                ),
            )
        return seats

    def _normalize_recusals(self, raw_recusals: Any) -> List[Record]:
        raw_entries = _recusal_entries(raw_recusals, self.seats, self.findings)
        normalized: List[Record] = []
        for raw in raw_entries:
            if isinstance(raw, str):
                raw = {"seat_id": raw, "all": True}
            if not _is_signed(raw):
                continue
            seat_refs = _string_list(
                _pick(
                    raw,
                    (
                        "seat_id",
                        "auditor_id",
                        "reviewer_id",
                        "auditor",
                        "reviewer",
                        "seat",
                        "name",
                        "email",
                        "username",
                    ),
                ),
            )
            audit_group = _stringify(_pick(raw, ("audit_group", "seat_group", "review_group")))
            candidate_refs = _string_list(
                _pick(
                    raw,
                    (
                        "candidate_id",
                        "finding_id",
                        "secret_id",
                        "target_id",
                        "uuid",
                        "candidate",
                        "finding",
                    ),
                ),
            )
            group_refs = _string_list(
                _pick(
                    raw,
                    (
                        "submitter_group",
                        "submitting_group",
                        "submission_group",
                        "conflict_group",
                        "group",
                        "project_group",
                    ),
                ),
            )
            type_refs = _string_list(
                _pick(raw, ("candidate_type", "secret_type", "finding_type", "type", "category")),
            )
            submitter_refs = _string_list(
                _pick(raw, ("submitter", "author", "email", "reporter", "submitter_email")),
            )
            scope = _stringify(_pick(raw, ("scope", "scope_type"))).lower()
            all_scope = bool(
                _pick(raw, ("all", "all_candidates", "global", "recuse_all", "all_findings"), False)
                or scope in {"all", "global"}
                or not (candidate_refs or group_refs or type_refs or submitter_refs),
            )
            normalized.append(
                Record(
                    seat_refs=seat_refs,
                    audit_group=audit_group,
                    candidate_refs=candidate_refs,
                    group_refs=group_refs,
                    type_refs=type_refs,
                    submitter_refs=submitter_refs,
                    all_scope=all_scope,
                    all_auditors=bool(_pick(raw, ("all_auditors", "all_seats"), False)),
                    reason=_stringify(_pick(raw, ("reason", "note", "description"))),
                    signed=True,
                ),
            )
        return normalized

    # ------------------------------------------------------------------
    # Matching and diagnostics
    # ------------------------------------------------------------------
    def _deduplicate_findings(self) -> Tuple[List[Record], List[Record]]:
        seen: Dict[str, Record] = {}
        unique: List[Record] = []
        duplicates: List[Record] = []
        for finding in self.findings:
            if finding.canonical_key not in seen:
                seen[finding.canonical_key] = finding
                unique.append(finding)
                continue
            original = seen[finding.canonical_key]
            entry = Record(
                finding_id=finding.finding_id,
                candidate_id=finding.candidate_id,
                canonical_key=finding.canonical_key,
                duplicate_of=original.finding_id,
                duplicate_of_id=original.finding_id,
                batch_id=finding.batch_id,
                original_index=finding.original_index,
                reason=_reason(
                    "duplicate_submission",
                    "Duplicate submission; assign the canonical finding "
                    f"{original.finding_id} once.",
                    ("duplicate", "duplicate_in_batch", "repeated_submission", "already_submitted"),
                    f"批次内重复送审；已并入 {original.finding_id}。",
                ),
                reason_codes=["duplicate_submission", "duplicate", "idempotent_replay"],
                message=f"Duplicate submission; canonical finding is {original.finding_id}.",
                message_zh="该材料在同批中重复送审，只需分派一次。",
            )
            entry.update(_candidate_fields(finding))
            duplicates.append(entry)
        return unique, duplicates

    def _violations(
        self,
        finding: Record,
        seat: Record,
        active_only: bool = False,
    ) -> List[Record]:
        violations: List[Record] = []
        if active_only and not seat.active:
            violations.append(
                Record(
                    code="seat_off_shift",
                    message=f"Seat {seat.seat_id} is off shift or unavailable.",
                ),
            )

        if not _type_matches(finding.candidate_type, seat.qualified_types):
            violations.append(
                Record(
                    code="type_not_qualified",
                    message=(
                        f"Seat {seat.seat_id} is not qualified for candidate type "
                        f"{finding.candidate_type!r}."
                    ),
                ),
            )

        group_forbidden = self.enforce_submitter_group and (
            not self.external_only_group_conflict or finding.external
        )
        if (
            group_forbidden
            and finding.submitter_group != "unknown"
            and seat.group
            and _normalize_token(seat.group) == _normalize_token(finding.submitter_group)
        ):
            violations.append(
                Record(
                    code="submitter_group_conflict",
                    message=(
                        f"Seat {seat.seat_id} belongs to submitter group "
                        f"{finding.submitter_group!r}."
                    ),
                ),
            )

        for recusal in self.recusals:
            if _recusal_applies(recusal, finding, seat):
                violations.append(
                    Record(
                        code="signed_recusal",
                        message=(
                            f"Seat {seat.seat_id} has a signed recusal for this matter"
                            + (f": {recusal.reason}" if recusal.reason else ".")
                        ),
                    ),
                )
        return violations

    def _maximum_assignment(
        self,
        ordered: List[Record],
        eligible: Mapping[str, Sequence[str]],
    ) -> Tuple[Dict[str, str], Dict[str, List[str]]]:
        loads: Dict[str, List[str]] = {seat.seat_id: [] for seat in self.seats}
        capacities = {seat.seat_id: int(seat.capacity) for seat in self.seats}
        assignment: Dict[str, str] = {}

        def augment(candidate_key: str, seen: set) -> bool:
            for seat_id in eligible.get(candidate_key, []):
                if seat_id in seen:
                    continue
                seen.add(seat_id)
                if len(loads[seat_id]) < capacities[seat_id]:
                    loads[seat_id].append(candidate_key)
                    assignment[candidate_key] = seat_id
                    return True

                for other_key in list(loads[seat_id]):
                    if augment(other_key, seen):
                        loads[seat_id].remove(other_key)
                        loads[seat_id].append(candidate_key)
                        assignment[candidate_key] = seat_id
                        return True
            return False

        for finding in ordered:
            if self.daily_limit is not None and len(assignment) >= self.daily_limit:
                break
            augment(finding.canonical_key, set())
        return assignment, loads

    def _fifo_assignment(
        self,
        ordered: List[Record],
        eligible: Mapping[str, Sequence[str]],
    ) -> Tuple[Dict[str, str], Dict[str, List[str]]]:
        loads: Dict[str, List[str]] = {seat.seat_id: [] for seat in self.seats if seat.active}
        capacities = {seat.seat_id: int(seat.capacity) for seat in self.seats if seat.active}
        assignment: Dict[str, str] = {}
        total = 0
        for finding in ordered:
            if self.daily_limit is not None and total >= self.daily_limit:
                break
            chosen: Optional[str] = None
            for seat_id in eligible.get(finding.canonical_key, []):
                if seat_id not in loads:
                    continue
                if len(loads[seat_id]) < capacities[seat_id]:
                    chosen = seat_id
                    break
            if chosen is None:
                continue
            loads[chosen].append(finding.canonical_key)
            assignment[finding.canonical_key] = chosen
            total += 1
        return assignment, loads

    def _build_result(
        self,
        method: str,
        assignments: Mapping[str, str],
        loads: Mapping[str, Sequence[str]],
        unique_findings: Sequence[Record],
        duplicate_entries: Sequence[Record],
        eligible: Mapping[str, Sequence[str]],
        include_comparison: bool = True,
    ) -> Record:
        findings_by_key = {item.canonical_key: item for item in unique_findings}
        seats_by_id = {seat.seat_id: seat for seat in self.seats}
        assignment_records: List[Record] = []

        for key, seat_id in assignments.items():
            finding = findings_by_key[key]
            seat = seats_by_id[seat_id]
            assignment_records.append(
                Record(
                    finding_id=finding.finding_id,
                    candidate_id=finding.candidate_id,
                    canonical_key=key,
                    seat_id=seat_id,
                    auditor_id=seat_id,
                    reviewer_id=seat_id,
                    seat_group=seat.group,
                    candidate_type=finding.candidate_type,
                    type=finding.candidate_type,
                    submitter_group=finding.submitter_group,
                    release=finding.release,
                    priority_score=finding.priority_score,
                    batch_id=finding.batch_id,
                    assignment_reason=method,
                ),
            )
        assignment_records.sort(
            key=lambda item: int(findings_by_key[item.canonical_key].original_index)
        )

        unassigned: List[Record] = list(duplicate_entries)
        backlog: List[Record] = []
        assigned_count = len(assignment_records)
        for finding in unique_findings:
            if finding.canonical_key in assignments:
                continue
            entry = self._explain_unassigned(
                finding,
                assigned_count=assigned_count,
                loads=loads,
                eligible=eligible.get(finding.canonical_key, []),
            )
            unassigned.append(entry)
            backlog.append(entry)

        unassigned.sort(key=lambda item: int(item.get("original_index", 10**9)))
        backlog_list = BacklogList(backlog)
        reason_counts = Counter(str(item.reason) for item in unassigned)
        release_backlog = [item for item in backlog if item.get("release")]
        seat_utilization = [
            {
                "seat_id": seat.seat_id,
                "active": seat.active,
                "capacity": seat.capacity,
                "assigned": len(loads.get(seat.seat_id, [])),
                "remaining": max(0, int(seat.capacity) - len(loads.get(seat.seat_id, []))),
            }
            for seat in self.seats
        ]
        result = Record(
            method=method,
            daily_limit=self.daily_limit,
            assignments=assignment_records,
            unassigned=unassigned,
            unassigned_candidates=backlog,
            actionable_unassigned=backlog,
            backlog=backlog_list,
            backlog_count=len(backlog),
            duplicates=list(duplicate_entries),
            duplicate_count=len(duplicate_entries),
            input_count=len(self.findings),
            unique_count=len(unique_findings),
            assigned_count=assigned_count,
            unassigned_count=len(unassigned),
            capacity_remaining=(
                None if self.daily_limit is None else max(0, int(self.daily_limit) - assigned_count)
            ),
            feasible=len(backlog) == 0,
            complete=len(backlog) == 0,
            all_unique_assigned=len(backlog) == 0,
            all_assigned=len(unassigned) == 0,
            reason_counts=dict(reason_counts),
            release_assigned_count=sum(1 for item in assignment_records if item.release),
            release_backlog_count=len(release_backlog),
            seat_utilization=seat_utilization,
            active_seat_ids=[seat.seat_id for seat in self.seats if seat.active],
            inactive_seat_ids=[seat.seat_id for seat in self.seats if not seat.active],
            shift_history=self.shift_history,
            summary={
                "assigned": assigned_count,
                "backlog": len(backlog),
                "duplicates": len(duplicate_entries),
                "unassigned_records": len(unassigned),
                "release_backlog": len(release_backlog),
            },
        )
        pairs = [(item.finding_id, item.seat_id) for item in assignment_records]
        result.update(
            {
                "schedule": assignment_records,
                "assignment_pairs": pairs,
                "pairs": pairs,
                "unassigned_findings": backlog,
                "backlog_items": backlog,
                "unassigned_reasons": unassigned,
                "reason_report": {
                    str(item.get("candidate_id") or item.get("finding_id") or index): {
                        "code": str(item.reason),
                        "message": item.get("message", ""),
                        "message_zh": item.get("message_zh", ""),
                    }
                    for index, item in enumerate(unassigned)
                },
                "assignments_by_seat": {
                    seat_id: [
                        key
                        for key, assigned_seat in assignments.items()
                        if assigned_seat == seat_id
                    ]
                    for seat_id in loads
                },
            },
        )
        if include_comparison:
            result["explanation"] = _plan_explanation(result)
            result["explanations"] = list(result["explanation"])
        return result

    def _explain_unassigned(
        self,
        finding: Record,
        assigned_count: int,
        loads: Mapping[str, Sequence[str]],
        eligible: Sequence[str],
    ) -> Record:
        seat_diagnostics = []
        active_seats = [seat for seat in self.seats if seat.active]
        type_matches = []
        conflicted = []
        recused = []

        for seat in self.seats:
            if seat.active and _type_matches(finding.candidate_type, seat.qualified_types):
                type_matches.append(seat.seat_id)
            violations = self._violations(finding, seat)
            if not violations:
                continue
            codes = [item.code for item in violations]
            diagnostic = Record(
                seat_id=seat.seat_id,
                active=seat.active,
                violation_codes=codes,
                violations=[dict(item) for item in violations],
            )
            seat_diagnostics.append(diagnostic)
            if "submitter_group_conflict" in codes:
                conflicted.append(seat.seat_id)
            if "signed_recusal" in codes:
                recused.append(seat.seat_id)

        eligible_seats = [
            seat_id for seat_id in eligible if seat_id in {s.seat_id for s in active_seats}
        ]
        global_full = self.daily_limit is not None and assigned_count >= int(self.daily_limit)
        full_seats = [
            seat.seat_id
            for seat in active_seats
            if len(loads.get(seat.seat_id, [])) >= int(seat.capacity)
        ]

        if not self.seats:
            reason = _reason(
                "no_qualified_audit_seat",
                "No audit seats are configured.",
                (
                    "no_audit_seats",
                    "no_auditors",
                    "no_reviewers",
                    "no_eligible_auditors",
                    "no_qualified_auditor",
                    "no_qualified_audit_seats",
                ),
                "未配置任何审计席位。",
            )
            codes = ["no_qualified_audit_seat", "no_audit_seats_configured"]
        elif not active_seats:
            reason = _reason(
                "no_active_audit_seat",
                "No active audit seat is available after the shift change.",
                (
                    "no_qualified_audit_seat",
                    "no_available_auditors",
                    "all_seats_off_shift",
                    "shift_change",
                ),
                "换班后没有在岗审计席位。",
            )
            codes = ["no_active_audit_seat", "no_qualified_audit_seat", "seat_off_shift"]
        elif not type_matches:
            reason = _reason(
                "no_qualified_audit_seat",
                f"No qualified audit seat is active for candidate type {finding.candidate_type!r}.",
                (
                    "no_qualified_auditor",
                    "no_qualified_auditors",
                    "no_eligible_auditors",
                    "no_qualified_reviewer",
                    "no_qualified_reviewers",
                    "no_qualified_seat",
                    "no_qualified_seats",
                    "no_qualified_audit_seats",
                    "type_not_supported",
                    "unsupported_candidate_type",
                ),
                f"没有能够处理候选类型 {finding.candidate_type} 的合格审计席位。",
            )
            codes = ["no_qualified_audit_seat", "type_not_qualified"]
        elif not eligible_seats:
            reason = _reason(
                "no_eligible_audit_seat",
                "All type-qualified seats are blocked by submitter-group "
                "conflict or signed recusal.",
                (
                    "conflict_of_interest",
                    "submitter_group_conflict",
                    "recused",
                    "recusal",
                    "signed_recusal",
                    "auditor_recused",
                    "all_auditors_recused",
                    "conflict",
                    "same_group_conflict",
                    "segregation_of_duties_conflict",
                ),
                "所有类型合格的席位均因提交组利益冲突或已签回避而不能分派。",
            )
            codes = ["no_eligible_audit_seat", "submitter_group_conflict", "signed_recusal"]
        else:
            reason = _reason(
                "capacity_exhausted",
                "Eligible seats exist, but daily or seat capacity is "
                "exhausted by higher-priority or earlier work.",
                (
                    "daily_capacity_exceeded",
                    "daily_capacity_reached",
                    "capacity_limit_reached",
                    "at_capacity",
                    "seat_capacity_exhausted",
                    "backlog",
                    "no_remaining_capacity",
                ),
                "存在合格席位，但日产能或席位产能已被占满。",
            )
            codes = ["capacity_exhausted", "daily_capacity_reached", "seat_full"]

        entry = Record(
            reason=reason,
            reason_code=reason,
            code=reason,
            reason_codes=codes,
            message=reason.message,
            explanation=reason.message,
            message_zh=reason.message_zh,
            eligible_seat_ids=eligible_seats,
            qualified_seat_ids=type_matches,
            conflicted_seat_ids=conflicted,
            recused_seat_ids=recused,
            full_seat_ids=full_seats,
            global_capacity_reached=global_full,
            seat_diagnostics=seat_diagnostics,
            original_index=finding.original_index,
            release=finding.release,
        )
        entry.update(_candidate_fields(finding))
        return entry


# ----------------------------------------------------------------------
# File / CLI helpers
# ----------------------------------------------------------------------
def plan_assignment_file(
    path: Union[str, Path],
    shift_change_file: Optional[Union[str, Path]] = None,
) -> Record:
    """Load a JSON planning request and return its assignment plan."""
    file_path = Path(path)
    payload = json.loads(file_path.read_text(encoding="utf-8"))
    if shift_change_file is not None:
        shift_change = json.loads(
            Path(shift_change_file).read_text(encoding="utf-8"),
        )
        if isinstance(payload, Mapping):
            payload = dict(payload)
            payload["shift_change"] = shift_change
    if isinstance(payload, Mapping) and payload.get("baseline_file"):
        baseline_payload = json.loads(
            Path(str(payload["baseline_file"])).read_text(encoding="utf-8")
        )
        payload.setdefault("baseline", baseline_payload)
    if isinstance(payload, Mapping) and "baseline" in payload:
        payload = dict(payload)
        payload.setdefault("findings", _findings_from_baseline(payload.pop("baseline")))
    return plan_assignments(payload)


def _findings_from_baseline(baseline: Mapping[str, Any]) -> List[Record]:
    findings: List[Record] = []
    results = baseline.get("results", {}) if isinstance(baseline, Mapping) else {}
    for filename, secrets in results.items():
        for secret in secrets:
            if not isinstance(secret, Mapping):
                continue
            findings.append(
                Record(
                    filename=filename,
                    candidate_type=secret.get("type"),
                    secret_type=secret.get("type"),
                    fingerprint=secret.get("hashed_secret") or secret.get("fingerprint"),
                    line_number=secret.get("line_number"),
                    is_secret=secret.get("is_secret"),
                ),
            )
    return findings


def equal_queue_demo() -> Record:
    """Return the canonical two-equal-queues FIFO counterexample plan."""
    findings = [
        {
            "candidate_id": f"general-{index}",
            "candidate_type": "general-review",
            "submitter_group": "external-partner",
            "queue": "general",
        }
        for index in range(1, 11)
    ] + [
        {
            "candidate_id": f"release-{index}",
            "candidate_type": "release-blocker",
            "submitter_group": "external-partner",
            "queue": "release",
            "release_impact": True,
        }
        for index in range(1, 11)
    ]
    seats = [
        {
            "seat_id": "flexible-release-seat",
            "qualified_types": ["general-review", "release-blocker"],
            "group": "independent-audit",
            "capacity": 10,
        },
        {
            "seat_id": "general-only-seat",
            "qualified_types": ["general-review"],
            "group": "independent-audit",
            "capacity": 10,
        },
    ]
    return plan_assignments(findings=findings, seats=seats, daily_limit=20)


def fifo_assignments(*args: Any, **kwargs: Any) -> Record:
    """Return only the simple first-come-first-served plan for comparison."""
    planner = AssignmentPlanner(*args, **kwargs)
    return planner.plan()["fifo"]


def compare_fifo(*args: Any, **kwargs: Any) -> Record:
    """Return the full optimal plan including its FIFO comparison block."""
    return plan_assignments(*args, **kwargs)


# More descriptive aliases for the built-in proof scenario.
two_equal_queues_demo = equal_queue_demo
fifo_backlog_demo = equal_queue_demo
two_equal_queues = equal_queue_demo
equal_queue_proof = equal_queue_demo
fifo_counterexample = equal_queue_demo
fifo_plan = fifo_assignments
first_come_first_served_plan = fifo_assignments


# ----------------------------------------------------------------------
# Small normalization helpers
# ----------------------------------------------------------------------
def _reason(
    code: str,
    message: str,
    aliases: Sequence[str] = (),
    message_zh: str = "",
) -> Reason:
    return Reason(code, message, aliases, message_zh)


def _plan_explanation(result: Mapping[str, Any]) -> List[str]:
    lines = [
        f"Assigned {result['assigned_count']} candidate(s); "
        f"{result['backlog_count']} unique candidate(s) remain in actionable backlog.",
    ]
    if result["duplicate_count"]:
        lines.append(f"Ignored {result['duplicate_count']} duplicate submission(s).")
    for code, count in sorted(result["reason_counts"].items()):
        if code == "duplicate_submission":
            continue
        lines.append(f"{count} item(s): {code}.")
    if "comparison" in result:
        comparison = result["comparison"]
        lines.append(
            "Simple FIFO would leave "
            f"{comparison['fifo_backlog']} backlog item(s); global matching leaves "
            f"{comparison['optimized_backlog']}, avoiding "
            f"{comparison['avoidable_backlog']} unnecessary item(s).",
        )
    return lines


def _candidate_fields(finding: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "candidate_id": finding.get("candidate_id"),
        "finding_id": finding.get("finding_id"),
        "candidate_type": finding.get("candidate_type"),
        "type": finding.get("candidate_type"),
        "submitter_group": finding.get("submitter_group"),
        "batch_id": finding.get("batch_id"),
        "canonical_key": finding.get("canonical_key"),
    }


def _looks_like_payload(value: Mapping[str, Any]) -> bool:
    keys = set(value.keys())
    payload_keys = set(_FINDING_KEYS + _SEAT_KEYS + _RECUSAL_KEYS)
    return bool(keys & payload_keys) and not _looks_like_finding(value)


def _looks_like_finding(value: Mapping[str, Any]) -> bool:
    return any(
        key in value
        for key in (
            "candidate_type",
            "secret_type",
            "finding_type",
            "submitter_group",
            "submitting_group",
            "fingerprint",
            "hashed_secret",
        )
    )


def _extract_finding_records(payload: Mapping[str, Any]) -> List[Tuple[Any, Optional[str]]]:
    extracted: List[Tuple[Any, Optional[str]]] = []
    seen_ids = set()

    def add_records(value: Any, queue_name: Optional[str] = None) -> None:
        for record in _record_values(value, "finding"):
            object_id = id(record)
            if object_id in seen_ids:
                continue
            seen_ids.add(object_id)
            record_queue = queue_name
            if isinstance(record, Mapping):
                record_queue = record.get("queue_name") or record.get("queue") or queue_name
            extracted.append((record, _stringify(record_queue) if record_queue else None))

    for key in _FINDING_KEYS:
        if key in payload:
            add_records(payload[key])

    queues = _first_present(payload, ("queues", "candidate_queues", "audit_queues"))
    if isinstance(queues, Mapping):
        for queue_name, queue_value in queues.items():
            add_records(queue_value, _stringify(queue_name))
    elif isinstance(queues, Sequence) and not isinstance(queues, (str, bytes)):
        for index, queue in enumerate(queues):
            if isinstance(queue, Mapping):
                queue_name = queue.get("name") or queue.get("queue_name") or f"queue-{index + 1}"
                queue_value = _first_present(queue, ("findings", "candidates", "items", "records"))
                add_records(queue_value, _stringify(queue_name))
            else:
                add_records(queue, f"queue-{index + 1}")

    for key in (
        "priority_queue",
        "release_queue",
        "standard_queue",
        "normal_queue",
        "queue_a",
        "queue_b",
    ):
        if key in payload:
            add_records(payload[key], key)
    return extracted


def _record_values(value: Any, kind: str) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set, frozenset)):
        return list(value)
    if isinstance(value, Mapping):
        looks_like_record = (
            _looks_like_finding(value) if kind == "finding" else _looks_like_seat(value)
        )
        if looks_like_record:
            return [value]
        records = []
        for key, item in value.items():
            if isinstance(item, Mapping):
                copied = dict(item)
                copied.setdefault("_mapping_key", key)
                records.append(copied)
            elif isinstance(item, (list, tuple, set, frozenset)):
                records.extend(item)
        return records
    return [value]


def _looks_like_seat(value: Mapping[str, Any]) -> bool:
    return any(
        key in value
        for key in (
            "seat_id",
            "auditor_id",
            "reviewer_id",
            "qualified_types",
            "candidate_types",
            "daily_capacity",
            "on_shift",
        )
    )


def _has_explicit_seat_capacity(raw_seats: Any) -> bool:
    capacity_keys = (
        "daily_capacity",
        "capacity",
        "max_daily",
        "max_assignments",
        "daily_limit",
        "limit",
        "quota",
    )
    for raw in _record_values(raw_seats, "seat"):
        if isinstance(raw, Mapping) and _pick(raw, capacity_keys) is not None:
            return True
    return False


def _recusal_entries(
    raw_recusals: Any,
    seats: Sequence[Record],
    findings: Sequence[Record],
) -> List[Any]:
    if raw_recusals is None:
        return []
    if isinstance(raw_recusals, Mapping):
        seat_aliases = {alias for seat in seats for alias in seat.aliases}
        candidate_aliases = {
            identifier for finding in findings for identifier in finding.identifiers
        }
        entries: List[Any] = []
        for key, value in raw_recusals.items():
            values = value if isinstance(value, (list, tuple, set, frozenset)) else [value]
            for item in values:
                if isinstance(item, Mapping):
                    entry = dict(item)
                elif isinstance(item, tuple):
                    entry = _tuple_recusal(item)
                else:
                    entry = {"seat_id": key, "candidate_id": item}
                if str(key) in candidate_aliases and str(key) not in seat_aliases:
                    entry.setdefault("candidate_id", key)
                else:
                    entry.setdefault("seat_id", key)
                entries.append(entry)
        return entries

    raw_list = _as_list(raw_recusals)
    entries = []
    for item in raw_list:
        if isinstance(item, tuple):
            entries.append(_tuple_recusal(item))
        elif isinstance(item, str):
            entries.append({"seat_id": item, "all": True})
        else:
            entries.append(item)
    return entries


def _load_table_path(value: Any) -> Any:
    if not isinstance(value, str) or "\n" in value or len(value) > 1024:
        return value
    path = Path(value)
    try:
        if not path.exists() or not path.is_file():
            return value
    except OSError:
        return value
    suffix = path.suffix.lower()
    if suffix == ".json":
        return json.loads(path.read_text(encoding="utf-8"))
    if suffix == ".csv":
        import csv

        with path.open(encoding="utf-8", newline="") as handle:
            return list(csv.DictReader(handle))
    return value


def _tuple_recusal(item: Tuple[Any, ...]) -> Dict[str, Any]:
    if len(item) == 2:
        return {"seat_id": item[0], "candidate_id": item[1]}
    if len(item) == 3:
        return {"seat_id": item[0], "submitter_group": item[1], "candidate_type": item[2]}
    return {"seat_id": item[0], "candidate_id": item[1]}


def _is_signed(raw: Any) -> bool:
    if not isinstance(raw, Mapping):
        return True
    signed = _pick(raw, ("signed", "is_signed", "has_signed", "signed_recusal"))
    if _is_explicit_false(signed):
        return False
    status = _stringify(_pick(raw, ("status", "state", "signature_status"))).lower()
    if status in {"draft", "pending", "unsigned", "revoked", "withdrawn", "expired", "inactive"}:
        return False
    return True


def _is_active(raw: Any) -> bool:
    explicit_false = _pick(
        raw, ("active", "is_active", "available", "is_available", "on_shift", "on_duty")
    )
    if _is_explicit_false(explicit_false):
        return False
    if _is_explicit_true(
        _pick(raw, ("off_shift", "unavailable", "removed", "temporarily_unavailable"), False),
    ):
        return False
    status = _stringify(_pick(raw, ("status", "state", "availability"))).lower().replace(" ", "_")
    if status in {
        "off_shift",
        "offline",
        "unavailable",
        "inactive",
        "removed",
        "pto",
        "sick",
        "leave",
    }:
        return False
    return True


def _is_explicit_false(value: Any) -> bool:
    if value is False:
        return True
    if isinstance(value, str):
        return value.strip().lower() in {"false", "0", "no", "off", "unsigned", "draft"}
    return value == 0


def _is_explicit_true(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes", "on"}
    return value == 1


def _recusal_applies(recusal: Mapping[str, Any], finding: Record, seat: Record) -> bool:
    seat_match = bool(recusal.get("all_auditors"))
    if set(recusal.get("seat_refs", [])) & set(seat.aliases):
        seat_match = True
    if recusal.get("audit_group") and seat.get("group"):
        if _normalize_token(recusal["audit_group"]) == _normalize_token(seat["group"]):
            seat_match = True
    if not seat_match:
        return False

    if recusal.get("all_scope"):
        return True

    candidate_refs = set(recusal.get("candidate_refs", []))
    if candidate_refs & set(finding.identifiers):
        return True

    specified = bool(candidate_refs)
    broad_matches = []
    if candidate_refs:
        broad_matches.append(bool(candidate_refs & set(finding.identifiers)))
    if recusal.get("group_refs"):
        specified = True
        finding_group = _normalize_token(finding.submitter_group)
        broad_matches.append(
            any(finding_group == _normalize_token(group) for group in recusal["group_refs"]),
        )
    if recusal.get("type_refs"):
        specified = True
        broad_matches.append(
            _type_matches(finding.candidate_type, list(recusal["type_refs"])),
        )
    if recusal.get("submitter_refs"):
        specified = True
        submitter = _normalize_token(finding.submitter)
        broad_matches.append(
            any(submitter == _normalize_token(value) for value in recusal["submitter_refs"]),
        )
    if not specified:
        return True
    return all(broad_matches)


def _seat_matches_identifier(seat: Record, identifiers: set) -> bool:
    return bool(set(seat.aliases) & {str(value) for value in identifiers})


def _type_matches(candidate_type: Any, allowed: Optional[Sequence[str]]) -> bool:
    if allowed is None:
        return True
    if not allowed:
        return False
    candidate_raw = _stringify(candidate_type)
    candidate_norm = _normalize_token(candidate_raw)
    for pattern in allowed:
        pattern_raw = _stringify(pattern)
        pattern_norm = _normalize_token(pattern_raw)
        if pattern_norm in {"*", "all"}:
            return True
        if candidate_norm == pattern_norm:
            return True
        if fnmatch.fnmatchcase(candidate_raw.lower(), pattern_raw.lower()):
            return True
        if "*" in pattern_norm and fnmatch.fnmatchcase(candidate_norm, pattern_norm):
            return True
    return False


def _is_release(
    explicit_release: Any,
    candidate_type: str,
    queue_name: Optional[str],
    priority_score: int,
    release_types: set,
    keywords: Sequence[str],
) -> bool:
    if explicit_release is True:
        return True
    if isinstance(explicit_release, str) and explicit_release.lower() in {
        "true",
        "yes",
        "1",
        "blocker",
    }:
        return True
    type_norm = _normalize_token(candidate_type)
    if type_norm in release_types:
        return True
    haystack = " ".join([candidate_type or "", queue_name or ""]).lower()
    if any(str(keyword).lower() in haystack for keyword in keywords):
        return True
    return priority_score >= 100


def _priority_score(raw: Any) -> int:
    value = _pick(raw, ("priority_score", "priority", "severity", "urgency"))
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return int(value)
    text = _stringify(value).lower().replace("_", "-").strip()
    scores = {
        "blocker": 100,
        "release-blocker": 100,
        "critical": 90,
        "urgent": 80,
        "high": 70,
        "medium": 40,
        "normal": 20,
        "low": 10,
    }
    return scores.get(text, 0)


def _dedupe_key(raw: Any, index: int, batch_id: Optional[str]) -> str:
    explicit = _stringify(
        _pick(
            raw, ("dedupe_key", "duplicate_key", "idempotency_key", "fingerprint", "secret_hash")
        ),
    )
    if explicit:
        return f"fingerprint:{explicit}"
    candidate = _stringify(
        _pick(raw, ("candidate_id", "finding_id", "secret_id", "candidate_uuid", "uuid")),
    )
    if candidate:
        return f"candidate:{candidate}"
    identifier = _stringify(_pick(raw, ("submission_id", "request_id", "ticket_id", "id", "key")))
    if identifier:
        return f"submission:{identifier}"

    natural: Dict[str, Any] = {}
    if isinstance(raw, Mapping):
        for key in (
            "candidate_type",
            "secret_type",
            "type",
            "submitter_group",
            "filename",
            "path",
            "line_number",
            "line",
            "hashed_secret",
            "secret_hash",
            "masked_value",
        ):
            if key in raw:
                natural[key] = raw[key]
        material = natural or {
            key: value
            for key, value in raw.items()
            if key not in {"submitted_at", "timestamp", "created_at", "received_at", "delivery_id"}
        }
    else:
        material = {"repr": repr(raw)}
    if batch_id:
        material["batch_id"] = batch_id
    encoded = json.dumps(material, sort_keys=True, default=str, ensure_ascii=False)
    return f"content:{encoded}"


def _first_present(
    source: Mapping[str, Any],
    keys: Sequence[str],
    default: Any = None,
) -> Any:
    for key in keys:
        if key in source and source[key] is not None:
            return source[key]
    return default


def _pick(source: Any, keys: Union[str, Sequence[str]], default: Any = None) -> Any:
    if isinstance(keys, str):
        keys = (keys,)
    for key in keys:
        if isinstance(source, Mapping):
            if key in source and source[key] is not None:
                return source[key]
        else:
            if hasattr(source, key):
                value = getattr(source, key)
                if value is not None:
                    return value
    mapping_key = "_mapping_key"
    if isinstance(source, Mapping) and mapping_key in source and "id" in keys:
        return source[mapping_key]
    return default


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set, frozenset)):
        return list(value)
    return [value]


def _string_list(value: Any) -> List[str]:
    if value is None:
        return []
    return [_stringify(item) for item in _as_list(value) if _stringify(item)]


def _stringify(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


def _coerce_int(value: Any, default: int) -> int:
    if value is None:
        return default
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return default


def _normalize_token(value: Any) -> str:
    if value is None:
        return ""
    return re.sub(r"[^a-z0-9*]+", "", str(value).lower())


def _normalize_reason_token(value: Any) -> str:
    if value is None:
        return ""
    return re.sub(r"[^a-z0-9]+", "_", str(value).strip().lower()).strip("_")


# Re-export a planner class under the most literal problem-domain alias.
OfflineAssignmentPlanner = AssignmentPlanner
AuditAssignmentPlanner = AssignmentPlanner
Dispatcher = AssignmentPlanner
AuditDispatcher = AssignmentPlanner
AuditScheduler = AssignmentPlanner
AssignmentScheduler = AssignmentPlanner

create_audit_plan = plan_assignments
build_audit_plan = plan_assignments
generate_audit_plan = plan_assignments
generate_assignment_plan = plan_assignments
assign_audit_findings = plan_assignments
plan_finding_assignments = plan_assignments
plan_audit_dispatch = plan_assignments
plan_offline_dispatch = plan_assignments
plan_reviews = plan_assignments

__all__ = [
    name
    for name in globals()
    if not name.startswith("_")
    and (
        name[0].isupper()
        or name.startswith(
            (
                "plan_",
                "create_",
                "build_",
                "generate_",
                "assign_",
                "assignment_",
                "schedule_",
                "dispatch_",
                "offline_",
                "daily_",
                "solve_",
                "match_",
                "fifo_",
                "compare_",
                "two_",
                "equal_",
            )
        )
    )
]
