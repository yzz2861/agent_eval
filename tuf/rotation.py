"""Offline feasibility checks for signing-window constrained role rotation.

The module describes a transition where the next delegated metadata version
must be acceptable to both sides of a rotation: it needs the old delegation's
signature threshold and the new delegation's signature threshold.  Only
already signed events are considered.  A signature counts when its key is part
of the relevant threshold and the event happened inside the role's approval
window.  No keys are generated, verified or used for signing, and no network or
repository operation is performed.

Approval is modelled as a single sequential lane: for a given order every role
is reviewed after the previous role has finished, after its own signatures are
available, and once its approval window has opened.  The review must finish
before the window closes.  This makes approval order observable: a late slip
can consume the remaining time of a role that is reviewed after it.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Any

from tuf.api.metadata import DelegatedRole, Metadata, Targets

__all__ = [
    "DelegationContract",
    "OrderResult",
    "RoleContractResult",
    "RolePlan",
    "RotationPlan",
    "RotationReport",
    "ScheduleEntry",
    "SignatureEvent",
    "SigningWindow",
    "ThresholdResult",
    "contracts_from_targets",
    "load_rotation_plan",
]


def _require_aware(moment: datetime, label: str) -> None:
    """Raise if ``moment`` has no usable timezone information."""
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware: {moment!r}")


def _parse_time(value: str, label: str) -> datetime:
    moment = datetime.fromisoformat(value)
    _require_aware(moment, label)
    return moment


def _unique_tuple(values: Iterable[str], label: str) -> tuple[str, ...]:
    result = tuple(values)
    if len(set(result)) != len(result):
        raise ValueError(f"{label} contains duplicate entries: {result!r}")
    return result


@dataclass(frozen=True)
class SigningWindow:
    """Inclusive interval in which a role's approval may be completed."""

    not_before: datetime
    not_after: datetime

    def __post_init__(self) -> None:
        _require_aware(self.not_before, "not_before")
        _require_aware(self.not_after, "not_after")
        if self.not_before > self.not_after:
            raise ValueError("not_before must not be after not_after")

    def contains(self, moment: datetime) -> bool:
        """Return whether ``moment`` falls inside the window."""
        _require_aware(moment, "moment")
        return self.not_before <= moment <= self.not_after

    def shift(self, delta: timedelta) -> SigningWindow:
        """Return a copy moved by ``delta``."""
        return SigningWindow(self.not_before + delta, self.not_after + delta)

    def to_dict(self) -> dict[str, str]:
        """Return a JSON-serializable representation."""
        return {
            "not_before": self.not_before.isoformat(),
            "not_after": self.not_after.isoformat(),
        }


@dataclass(frozen=True)
class SignatureEvent:
    """An already produced signature, identified only by a synthetic key id."""

    keyid: str
    signed_at: datetime
    label: str = ""

    def __post_init__(self) -> None:
        if not self.keyid:
            raise ValueError("keyid must not be empty")
        _require_aware(self.signed_at, "signed_at")

    def shift(self, delta: timedelta) -> SignatureEvent:
        """Return a copy whose signature timestamp is moved by ``delta``."""
        return replace(self, signed_at=self.signed_at + delta)

    def to_dict(self) -> dict[str, str]:
        """Return a JSON-serializable representation."""
        result = {"keyid": self.keyid, "signed_at": self.signed_at.isoformat()}
        if self.label:
            result["label"] = self.label
        return result


@dataclass(frozen=True)
class DelegationContract:
    """Old and new signing policy for one delegated role."""

    role: str
    old_keyids: tuple[str, ...]
    old_threshold: int
    new_keyids: tuple[str, ...]
    new_threshold: int

    def __post_init__(self) -> None:
        if not self.role:
            raise ValueError("role must not be empty")
        old_keyids = _unique_tuple(self.old_keyids, "old_keyids")
        new_keyids = _unique_tuple(self.new_keyids, "new_keyids")
        object.__setattr__(self, "old_keyids", old_keyids)
        object.__setattr__(self, "new_keyids", new_keyids)

        for label, keyids, threshold in (
            ("old", old_keyids, self.old_threshold),
            ("new", new_keyids, self.new_threshold),
        ):
            if not keyids:
                raise ValueError(f"{label} keyids for {self.role} are empty")
            if not 1 <= threshold <= len(keyids):
                raise ValueError(
                    f"{label} threshold for {self.role} must be between 1 "
                    f"and {len(keyids)}"
                )


def contracts_from_targets(
    old_targets: Targets, new_targets: Targets
) -> dict[str, DelegationContract]:
    """Read old and new delegated role thresholds from TUF targets metadata.

    Both metadata objects must delegate the same set of role names.  The
    returned mapping follows the old metadata's role order.
    """

    old_roles = _delegated_roles(old_targets, "old")
    new_roles = _delegated_roles(new_targets, "new")
    if set(old_roles) != set(new_roles):
        missing_new = sorted(set(old_roles) - set(new_roles))
        missing_old = sorted(set(new_roles) - set(old_roles))
        raise ValueError(
            "old and new delegations must describe the same roles: "
            f"missing in new={missing_new}, missing in old={missing_old}"
        )

    contracts = {}
    for role_name, old_role in old_roles.items():
        new_role = new_roles[role_name]
        _require_keys(old_targets, old_role, "old")
        _require_keys(new_targets, new_role, "new")
        contracts[role_name] = DelegationContract(
            role=role_name,
            old_keyids=tuple(old_role.keyids),
            old_threshold=old_role.threshold,
            new_keyids=tuple(new_role.keyids),
            new_threshold=new_role.threshold,
        )

    return contracts


def _delegated_roles(
    targets: Targets, label: str
) -> dict[str, DelegatedRole]:
    delegations = targets.delegations
    if delegations is None or delegations.roles is None:
        raise ValueError(f"{label} targets metadata has no delegated roles")
    return delegations.roles


def _require_keys(
    targets: Targets, role: DelegatedRole, label: str
) -> None:
    delegations = targets.delegations
    if delegations is None:
        raise ValueError(f"{label} targets metadata has no delegations")
    unknown = [keyid for keyid in role.keyids if keyid not in delegations.keys]
    if unknown:
        raise ValueError(
            f"{label} role {role.name} references unknown keys: {unknown}"
        )


@dataclass(frozen=True)
class ThresholdResult:
    """Signature count for one side of a role's dual contract."""

    label: str
    threshold: int
    keyids: tuple[str, ...]
    signed: tuple[str, ...]

    @property
    def shortfall(self) -> int:
        """Return the number of additional signatures still required."""
        return max(0, self.threshold - len(set(self.signed)))

    @property
    def ok(self) -> bool:
        """Return whether this side of the contract is satisfied."""
        return self.shortfall == 0

    @property
    def missing(self) -> tuple[str, ...]:
        """Return unsigned key ids when the threshold is not met."""
        if self.ok:
            return ()
        signed = set(self.signed)
        return tuple(keyid for keyid in self.keyids if keyid not in signed)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "threshold": self.threshold,
            "signed": list(self.signed),
            "shortfall": self.shortfall,
            "missing": list(self.missing),
        }


@dataclass(frozen=True)
class RoleContractResult:
    """Dual-contract result and earliest readiness for one role."""

    role: str
    old: ThresholdResult
    new: ThresholdResult
    earliest_ready: datetime | None = None
    accepted_events: tuple[SignatureEvent, ...] = ()
    invalid_events: tuple[SignatureEvent, ...] = ()
    ignored_events: tuple[SignatureEvent, ...] = ()

    @property
    def ok(self) -> bool:
        """Return whether both the old and new thresholds are met."""
        return self.old.ok and self.new.ok

    @property
    def missing_summary(self) -> str:
        """Describe every unmet threshold side."""
        parts = []
        for result in (self.old, self.new):
            if not result.ok:
                parts.append(
                    f"{result.label} threshold {result.threshold} needs "
                    f"{result.shortfall} more signature(s)"
                )
        return "; ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "ok": self.ok,
            "old": self.old.to_dict(),
            "new": self.new.to_dict(),
            "earliest_ready": (
                self.earliest_ready.isoformat()
                if self.earliest_ready is not None
                else None
            ),
            "invalid_events": [
                event.to_dict() for event in self.invalid_events
            ],
            "ignored_events": [
                event.to_dict() for event in self.ignored_events
            ],
        }


@dataclass(frozen=True)
class RolePlan:
    """Dual contract, signature events and window for one delegated role."""

    name: str
    old_keyids: tuple[str, ...]
    old_threshold: int
    new_keyids: tuple[str, ...]
    new_threshold: int
    window: SigningWindow
    duration: timedelta = timedelta(0)
    events: tuple[SignatureEvent, ...] = ()
    requires: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("role name must not be empty")
        object.__setattr__(
            self, "old_keyids", _unique_tuple(self.old_keyids, "old_keyids")
        )
        object.__setattr__(
            self, "new_keyids", _unique_tuple(self.new_keyids, "new_keyids")
        )
        object.__setattr__(self, "events", tuple(self.events))
        object.__setattr__(
            self, "requires", _unique_tuple(self.requires, "requires")
        )
        if self.duration < timedelta(0):
            raise ValueError("duration must not be negative")
        if self.name in self.requires:
            raise ValueError(f"role {self.name} cannot require itself")
        DelegationContract(
            self.name,
            self.old_keyids,
            self.old_threshold,
            self.new_keyids,
            self.new_threshold,
        )

    @classmethod
    def from_contract(
        cls,
        contract: DelegationContract,
        window: SigningWindow,
        duration: timedelta = timedelta(0),
        events: Iterable[SignatureEvent] = (),
        requires: Iterable[str] = (),
    ) -> RolePlan:
        """Build a role plan from a delegation contract and its approvals."""
        return cls(
            name=contract.role,
            old_keyids=contract.old_keyids,
            old_threshold=contract.old_threshold,
            new_keyids=contract.new_keyids,
            new_threshold=contract.new_threshold,
            window=window,
            duration=duration,
            events=tuple(events),
            requires=tuple(requires),
        )

    def contract(self) -> RoleContractResult:
        """Evaluate the old and new thresholds from in-window events."""
        old_keyids = set(self.old_keyids)
        new_keyids = set(self.new_keyids)
        inside = []
        invalid = []
        ignored = []

        for event in self.events:
            if not self.window.contains(event.signed_at):
                invalid.append(event)
            elif (
                event.keyid not in old_keyids
                and event.keyid not in new_keyids
            ):
                ignored.append(event)
            else:
                inside.append(event)

        earliest_by_key: dict[str, SignatureEvent] = {}
        for event in inside:
            current = earliest_by_key.get(event.keyid)
            if current is None or event.signed_at < current.signed_at:
                earliest_by_key[event.keyid] = event

        ordered = sorted(
            earliest_by_key.values(),
            key=lambda item: (item.signed_at, item.keyid),
        )
        old_signed = tuple(
            sorted(
                event.keyid for event in ordered if event.keyid in old_keyids
            )
        )
        new_signed = tuple(
            sorted(
                event.keyid for event in ordered if event.keyid in new_keyids
            )
        )
        old_result = ThresholdResult(
            "old", self.old_threshold, self.old_keyids, old_signed
        )
        new_result = ThresholdResult(
            "new", self.new_threshold, self.new_keyids, new_signed
        )

        old_seen: set[str] = set()
        new_seen: set[str] = set()
        accepted = []
        earliest_ready = None
        for event in ordered:
            if event.keyid in old_keyids:
                old_seen.add(event.keyid)
            if event.keyid in new_keyids:
                new_seen.add(event.keyid)
            accepted.append(event)
            if (
                len(old_seen) >= self.old_threshold
                and len(new_seen) >= self.new_threshold
            ):
                earliest_ready = event.signed_at
                break

        return RoleContractResult(
            role=self.name,
            old=old_result,
            new=new_result,
            earliest_ready=earliest_ready,
            accepted_events=tuple(accepted),
            invalid_events=tuple(invalid),
            ignored_events=tuple(ignored),
        )

    def delayed_slip(self, delta: timedelta) -> RolePlan:
        """Return a copy with this role's signed events moved by ``delta``."""
        return replace(
            self, events=tuple(event.shift(delta) for event in self.events)
        )


@dataclass(frozen=True)
class ScheduleEntry:
    """One role's allocated sequential approval block."""

    role: str
    start: datetime
    end: datetime
    window: SigningWindow
    ready_at: datetime

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "role": self.role,
            "start": self.start.isoformat(),
            "end": self.end.isoformat(),
            "window": self.window.to_dict(),
            "ready_at": self.ready_at.isoformat(),
        }


@dataclass(frozen=True)
class OrderResult:
    """Feasibility of one complete approval order."""

    order: tuple[str, ...]
    feasible: bool
    schedule: tuple[ScheduleEntry, ...]
    blocked_role: str | None
    reason: str | None
    missing_roles: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "order": list(self.order),
            "feasible": self.feasible,
            "schedule": [entry.to_dict() for entry in self.schedule],
            "blocked_role": self.blocked_role,
            "reason": self.reason,
            "missing_roles": list(self.missing_roles),
        }


@dataclass(frozen=True)
class RotationReport:
    """Dual-contract result plus outcome of every approval order."""

    contracts: dict[str, RoleContractResult]
    orders: tuple[OrderResult, ...]

    @property
    def release_contract_ok(self) -> bool:
        """Return whether every role satisfies both thresholds."""
        return all(result.ok for result in self.contracts.values())

    @property
    def feasible_orders(self) -> tuple[tuple[str, ...], ...]:
        """Return the approval orders that can finish inside their windows."""
        return tuple(result.order for result in self.orders if result.feasible)

    @property
    def blocked_orders(self) -> tuple[OrderResult, ...]:
        """Return the approval orders that cannot finish."""
        return tuple(result for result in self.orders if not result.feasible)

    def summary(self) -> str:
        """Return a short human-readable report."""
        lines = [
            "dual release contract: "
            + ("satisfied" if self.release_contract_ok else "not satisfied")
        ]
        for result in self.orders:
            state = "feasible" if result.feasible else "blocked"
            if result.missing_roles:
                state += f" (missing: {', '.join(result.missing_roles)})"
            lines.append(f"{' -> '.join(result.order)}: {state}")
            if result.reason:
                lines.append(f"  {result.reason}")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "release_contract_ok": self.release_contract_ok,
            "contracts": {
                name: result.to_dict()
                for name, result in self.contracts.items()
            },
            "orders": [result.to_dict() for result in self.orders],
            "feasible_orders": [list(order) for order in self.feasible_orders],
        }


@dataclass(frozen=True)
class RotationPlan:
    """Roles, dual contracts and candidate approval orders."""

    roles: tuple[RolePlan, ...]
    orders: tuple[tuple[str, ...], ...]

    def __post_init__(self) -> None:
        roles = tuple(self.roles)
        if not roles:
            raise ValueError("at least one role is required")
        names = tuple(role.name for role in roles)
        if len(set(names)) != len(names):
            raise ValueError("role names must be unique")

        role_map = {role.name: role for role in roles}
        for role in roles:
            missing = [name for name in role.requires if name not in role_map]
            if missing:
                raise ValueError(
                    f"role {role.name} requires unknown roles: {missing}"
                )

        orders = tuple(tuple(order) for order in self.orders)
        if not orders:
            orders = self._topological_orders(roles, role_map)
            if not orders:
                raise ValueError("role requirements contain a cycle")

        object.__setattr__(self, "roles", roles)
        object.__setattr__(self, "orders", orders)

    @staticmethod
    def _topological_orders(
        roles: Sequence[RolePlan], role_map: Mapping[str, RolePlan]
    ) -> tuple[tuple[str, ...], ...]:
        results: list[tuple[str, ...]] = []

        def visit(prefix: tuple[str, ...], done: frozenset[str]) -> None:
            if len(prefix) == len(roles):
                results.append(prefix)
                return
            for role in roles:
                if role.name in done:
                    continue
                if all(name in done for name in role_map[role.name].requires):
                    visit(prefix + (role.name,), done | {role.name})

        visit((), frozenset())
        return tuple(results)

    def topological_orders(self) -> tuple[tuple[str, ...], ...]:
        """Return every order that respects the ``requires`` graph."""
        role_map = {role.name: role for role in self.roles}
        return self._topological_orders(self.roles, role_map)

    def contract_results(self) -> dict[str, RoleContractResult]:
        """Evaluate every role's old and new thresholds."""
        return {role.name: role.contract() for role in self.roles}

    def evaluate(self) -> RotationReport:
        """Evaluate the dual contract and every candidate approval order."""
        contracts = self.contract_results()
        return RotationReport(
            contracts=contracts,
            orders=tuple(
                self._evaluate_order(order, contracts) for order in self.orders
            ),
        )

    def _evaluate_order(
        self,
        order: tuple[str, ...],
        contracts: Mapping[str, RoleContractResult],
    ) -> OrderResult:
        role_map = {role.name: role for role in self.roles}
        if len(order) != len(role_map) or set(order) != set(role_map):
            return OrderResult(
                order=order,
                feasible=False,
                schedule=(),
                blocked_role=None,
                reason="order must contain every role exactly once",
                missing_roles=(),
            )

        for index, role_name in enumerate(order):
            role = role_map[role_name]
            for prerequisite in role.requires:
                if prerequisite not in order[:index]:
                    return OrderResult(
                        order=order,
                        feasible=False,
                        schedule=(),
                        blocked_role=role_name,
                        reason=(
                            f"{role_name} requires {prerequisite} to be "
                            "approved first"
                        ),
                        missing_roles=(role_name,),
                    )

        contract_failures = [
            role_name for role_name in order if not contracts[role_name].ok
        ]
        if contract_failures:
            details = "; ".join(
                f"{name}: {contracts[name].missing_summary}"
                for name in contract_failures
            )
            return OrderResult(
                order=order,
                feasible=False,
                schedule=(),
                blocked_role=contract_failures[0],
                reason=details,
                missing_roles=tuple(contract_failures),
            )

        schedule = []
        previous_end = None
        for role_name in order:
            role = role_map[role_name]
            ready_at = contracts[role_name].earliest_ready
            if ready_at is None:
                return OrderResult(
                    order=order,
                    feasible=False,
                    schedule=tuple(schedule),
                    blocked_role=role_name,
                    reason=f"{role_name}: no complete signature set",
                    missing_roles=(role_name,),
                )

            start = ready_at
            if previous_end is not None and previous_end > start:
                start = previous_end
            if role.window.not_before > start:
                start = role.window.not_before
            end = start + role.duration
            entry = ScheduleEntry(
                role=role_name,
                start=start,
                end=end,
                window=role.window,
                ready_at=ready_at,
            )
            schedule.append(entry)

            if end > role.window.not_after:
                return OrderResult(
                    order=order,
                    feasible=False,
                    schedule=tuple(schedule),
                    blocked_role=role_name,
                    reason=(
                        f"{role_name}: approval would finish at "
                        f"{end.isoformat()} after window closes at "
                        f"{role.window.not_after.isoformat()}"
                    ),
                    missing_roles=(role_name,),
                )
            previous_end = end

        return OrderResult(
            order=order,
            feasible=True,
            schedule=tuple(schedule),
            blocked_role=None,
            reason=None,
            missing_roles=(),
        )

    def with_delayed_slip(
        self, role_name: str, delta: timedelta
    ) -> RotationPlan:
        """Return a plan with one role's already signed events delayed."""
        found = False
        roles = []
        for role in self.roles:
            if role.name == role_name:
                roles.append(role.delayed_slip(delta))
                found = True
            else:
                roles.append(role)
        if not found:
            raise KeyError(f"unknown role: {role_name}")
        return replace(self, roles=tuple(roles))

    @classmethod
    def from_targets(
        cls,
        old_targets: Targets,
        new_targets: Targets,
        approvals: Mapping[str, Mapping[str, Any]],
        orders: Iterable[Iterable[str]],
    ) -> RotationPlan:
        """Build a plan from targets metadata and separate windows."""
        contracts = contracts_from_targets(old_targets, new_targets)
        roles = []
        for role_name, contract in contracts.items():
            try:
                approval = approvals[role_name]
            except KeyError as error:
                raise ValueError(
                    f"no approval window for role {role_name}"
                ) from error

            events = tuple(
                SignatureEvent(
                    keyid=event["keyid"],
                    signed_at=_parse_time(event["signed_at"], "signed_at"),
                    label=event.get("label", ""),
                )
                for event in approval.get("events", ())
            )
            roles.append(
                RolePlan.from_contract(
                    contract,
                    SigningWindow(
                        _parse_time(approval["not_before"], "not_before"),
                        _parse_time(approval["not_after"], "not_after"),
                    ),
                    duration=timedelta(
                        seconds=float(approval.get("duration_seconds", 0))
                    ),
                    events=events,
                    requires=approval.get("requires", ()),
                )
            )

        return cls(tuple(roles), tuple(tuple(order) for order in orders))


def load_rotation_plan(
    old_targets_path: str,
    new_targets_path: str,
    approvals_path: str,
    scenario_path: str,
) -> RotationPlan:
    """Load a plan from two TUF metadata files and two JSON side files."""
    old_metadata = Metadata[Targets].from_file(old_targets_path)
    new_metadata = Metadata[Targets].from_file(new_targets_path)
    if not isinstance(old_metadata.signed, Targets):
        raise TypeError("old metadata is not targets metadata")
    if not isinstance(new_metadata.signed, Targets):
        raise TypeError("new metadata is not targets metadata")

    with open(approvals_path, encoding="utf-8") as approval_file:
        approvals = json.load(approval_file)
    with open(scenario_path, encoding="utf-8") as scenario_file:
        scenario = json.load(scenario_file)

    return RotationPlan.from_targets(
        old_metadata.signed,
        new_metadata.signed,
        approvals,
        scenario["orders"],
    )
