"""
Offline reconciliation of advisory identifiers across two `pip-audit` runs.

Upstream vulnerability sources occasionally merge two advisories into one and
later split a merged advisory back into several separately numbered entries.
A re-run of `pip-audit` only observes the resulting surface change: a batch of
identifiers disappears while another batch appears. This module reconstructs
the advisory lineage offline, using three explicit inputs:

* two audit results in `JsonFormat` shape (the "old" and "new" run),
* the explicit alias changes published by the simulated vulnerability source,
* the previously approved tickets and the evidence attached to each of them.

Historical handling (an approval) is only propagated to a successor branch when
that branch is covered by the evidence's impact scope. A successor whose only
ancestral evidence lacks an impact scope is deliberately left on the new
to-do list instead of being silently closed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from packaging.version import Version

# Reasons a new vulnerability instance remains on the to-do list.
REASON_NEW = "new_without_lineage"
REASON_MISSING_SCOPE = "evidence_missing_scope"
REASON_NOT_COVERED = "evidence_does_not_cover"
REASON_SAME_ID_CONFLICT = "same_id_name_conflict"
REASON_NAME_CONFLICT = "name_conflict"
REASON_NO_APPROVAL = "no_approval"


@dataclass(frozen=True)
class VulnerabilityInstance:
    """
    A single (package, version, advisory) occurrence observed in an audit run.
    """

    name: str
    version: str
    advisory_id: str
    description: str
    aliases: frozenset[str]

    @property
    def identity(self) -> set[str]:
        """Every identifier this instance is known by."""
        return set(self.aliases) | {self.advisory_id}


@dataclass(frozen=True)
class ImpactScope:
    """
    The package version range an approval claim applies to.

    A scope is only trustworthy when both bounds are present. An approval whose
    evidence omits either bound has no impact scope and therefore cannot prove
    coverage of any successor branch.
    """

    name: str
    introduced: str | None
    fixed: str | None

    @property
    def is_complete(self) -> bool:
        """Whether this scope carries both version bounds."""
        return self.introduced is not None and self.fixed is not None

    def covers(self, instance: VulnerabilityInstance) -> bool:
        """Whether the instance's package and version fall within this scope."""
        introduced = self.introduced
        fixed = self.fixed
        if introduced is None or fixed is None or instance.name != self.name:
            return False
        return Version(introduced) <= Version(instance.version) < Version(fixed)


@dataclass(frozen=True)
class ApprovalEvidence:
    """One piece of evidence attached to a historical approval ticket."""

    evidence_id: str
    scope: ImpactScope

    @property
    def has_scope(self) -> bool:
        """Whether this evidence records an impact scope."""
        return self.scope.is_complete


@dataclass(frozen=True)
class Approval:
    """A historical ticket for one advisory, with its supporting evidence."""

    advisory_id: str
    disposition: str
    evidence: list[ApprovalEvidence]


@dataclass(frozen=True)
class AliasEvent:
    """
    An explicit alias change announced by the publication source.

    `merged` maps every predecessor identifier onto the identifiers that now
    represent it. A many-to-one event merges advisories; a one-to-many event
    splits an advisory into several separately numbered entries.
    """

    event_id: str
    merged: dict[str, list[str]]


@dataclass(frozen=True)
class ReconciledItem:
    """The disposition decided for one instance in the new audit."""

    instance: VulnerabilityInstance
    on_todo: bool
    reason: str
    predecessor_ids: list[str]
    propagated_from: list[str]


@dataclass(frozen=True)
class ReconciliationReport:
    """
    The result of reconciling the new audit against the old one.

    `todo` holds every instance that still needs a human decision, including
    successors whose ancestral evidence lacks an impact scope.
    """

    todo: list[ReconciledItem]
    resolved: list[ReconciledItem]

    def to_dict(self) -> dict[str, Any]:
        """Serialize the report to plain JSON-compatible data."""
        return {
            "todo": [_item_to_dict(item) for item in self.todo],
            "resolved": [_item_to_dict(item) for item in self.resolved],
        }


def parse_audit(document: dict[str, Any]) -> list[VulnerabilityInstance]:
    """
    Parse an audit document in `JsonFormat` shape into instances.

    Skipped dependencies carry no vulnerabilities and are ignored.
    """
    instances: list[VulnerabilityInstance] = []
    for dependency in document.get("dependencies", []):
        if "vulns" not in dependency:
            continue
        instances.extend(
            VulnerabilityInstance(
                name=dependency["name"],
                version=dependency["version"],
                advisory_id=vuln["id"],
                description=vuln.get("description", ""),
                aliases=frozenset(vuln.get("aliases", [])),
            )
            for vuln in dependency["vulns"]
        )
    return instances


def parse_approvals(document: dict[str, Any]) -> dict[str, Approval]:
    """Parse the historical approval document into a mapping by advisory id."""
    approvals: dict[str, Approval] = {}
    for entry in document.get("approvals", []):
        evidence = [
            ApprovalEvidence(
                evidence_id=item["id"],
                scope=ImpactScope(
                    name=item["scope"]["name"],
                    introduced=item["scope"].get("introduced"),
                    fixed=item["scope"].get("fixed"),
                ),
            )
            for item in entry.get("evidence", [])
        ]
        approval = Approval(
            advisory_id=entry["advisory_id"],
            disposition=entry["disposition"],
            evidence=evidence,
        )
        approvals[approval.advisory_id] = approval
    return approvals


def parse_alias_events(document: dict[str, Any]) -> list[AliasEvent]:
    """Parse the explicit publication-source alias changes."""
    events: list[AliasEvent] = []
    for entry in document.get("events", []):
        kind = entry["type"]
        if kind == "merge":
            merged = {source: [entry["into"]] for source in entry["sources"]}
        elif kind == "split":
            merged = {entry["from"]: list(entry["into"])}
        elif kind == "alias":
            merged = {entry["from"]: [entry["to"]]}
        else:
            raise ValueError(f"unknown alias event type: {kind}")
        events.append(AliasEvent(event_id=entry["id"], merged=merged))
    return events


def build_lineage(events: list[AliasEvent]) -> dict[str, set[str]]:
    """
    Build the direct successor mapping declared by the publication source.
    """
    successors: dict[str, set[str]] = {}
    for event in events:
        for predecessor, targets in event.merged.items():
            successors.setdefault(predecessor, set()).update(targets)
    return successors


def _ancestors(
    advisory_id: str,
    old_instances: list[VulnerabilityInstance],
    successors: dict[str, set[str]],
) -> list[str]:
    """Return the old-run identifiers whose lineage reaches `advisory_id`."""
    predecessors: list[str] = []
    seen: set[str] = set()
    for instance in old_instances:
        if instance.advisory_id in seen:
            continue
        seen.add(instance.advisory_id)
        reaches_advisory = advisory_id in instance.identity or any(
            advisory_id in _reach(identifier, successors) for identifier in instance.identity
        )
        if reaches_advisory:
            predecessors.append(instance.advisory_id)
    return sorted(set(predecessors))


def _reach(start: str, successors: dict[str, set[str]]) -> set[str]:
    """Transitive closure of successor identifiers starting at `start`."""
    reachable: set[str] = set()
    frontier = [start]
    while frontier:
        current = frontier.pop()
        for target in successors.get(current, set()):
            if target not in reachable:
                reachable.add(target)
                frontier.append(target)
    return reachable


def _same_id_name_conflicts(
    old_instances: list[VulnerabilityInstance],
    new_instances: list[VulnerabilityInstance],
) -> set[str]:
    """Identifiers kept in both runs but renamed, i.e. an identity conflict."""
    old_by_id = {instance.advisory_id: instance for instance in old_instances}
    conflicts: set[str] = set()
    for instance in new_instances:
        previous = old_by_id.get(instance.advisory_id)
        if previous is not None and previous.description != instance.description:
            conflicts.add(instance.advisory_id)
    return conflicts


def _name_conflicts(instances: list[VulnerabilityInstance]) -> set[str]:
    """Advisory ids that share one human-readable name, i.e. an ambiguous name."""
    names_to_primary_ids: dict[str, set[str]] = {}
    for instance in instances:
        if instance.description:
            names_to_primary_ids.setdefault(instance.description, set()).add(instance.advisory_id)
    conflicts: set[str] = set()
    for primary_ids in names_to_primary_ids.values():
        if len(primary_ids) > 1:
            conflicts.update(primary_ids)
    return conflicts


def reconcile(
    old_audit: dict[str, Any],
    new_audit: dict[str, Any],
    alias_document: dict[str, Any],
    approval_document: dict[str, Any],
) -> ReconciliationReport:
    """
    Reconcile the new audit against the old one using explicit lineage.

    Approvals propagate only along branches that the evidence's impact scope
    covers. Same-identifier renames and shared names block propagation so that
    ambiguous advisories are never closed automatically.
    """
    old_instances = parse_audit(old_audit)
    new_instances = parse_audit(new_audit)
    approvals = parse_approvals(approval_document)
    successors = build_lineage(parse_alias_events(alias_document))

    same_id_conflicts = _same_id_name_conflicts(old_instances, new_instances)
    name_conflicts = _name_conflicts(old_instances + new_instances)

    todo: list[ReconciledItem] = []
    resolved: list[ReconciledItem] = []
    for instance in new_instances:
        predecessors = _ancestors(instance.advisory_id, old_instances, successors)
        item = _reconcile_instance(
            instance,
            predecessors,
            approvals,
            same_id_conflicts,
            name_conflicts,
        )
        (todo if item.on_todo else resolved).append(item)

    return ReconciliationReport(todo=todo, resolved=resolved)


def _reconcile_instance(
    instance: VulnerabilityInstance,
    predecessors: list[str],
    approvals: dict[str, Approval],
    same_id_conflicts: set[str],
    name_conflicts: set[str],
) -> ReconciledItem:
    """Decide the to-do status and reason for one new instance."""
    if instance.identity & same_id_conflicts:
        return ReconciledItem(instance, True, REASON_SAME_ID_CONFLICT, predecessors, [])
    if instance.identity & name_conflicts:
        return ReconciledItem(instance, True, REASON_NAME_CONFLICT, predecessors, [])
    if not predecessors:
        return ReconciledItem(instance, True, REASON_NEW, [], [])

    relevant = [approvals[advisory_id] for advisory_id in predecessors if advisory_id in approvals]
    if not relevant:
        return ReconciledItem(instance, True, REASON_NO_APPROVAL, predecessors, [])

    covering: list[str] = []
    saw_missing_scope = False
    saw_non_covering_scope = False
    covering_disposition: str | None = None
    for approval in relevant:
        for evidence in approval.evidence:
            if not evidence.has_scope:
                saw_missing_scope = True
            elif evidence.scope.covers(instance):
                covering.append(approval.advisory_id)
                if covering_disposition is None:
                    covering_disposition = approval.disposition
            else:
                saw_non_covering_scope = True

    if covering:
        return ReconciledItem(
            instance,
            False,
            covering_disposition or relevant[0].disposition,
            predecessors,
            sorted(set(covering)),
        )
    if saw_missing_scope:
        reason = REASON_MISSING_SCOPE
    elif saw_non_covering_scope:
        reason = REASON_NOT_COVERED
    else:
        reason = REASON_NO_APPROVAL
    return ReconciledItem(instance, True, reason, predecessors, [])


def reconcile_files(
    old_audit_path: Path | str,
    new_audit_path: Path | str,
    alias_path: Path | str,
    approval_path: Path | str,
) -> ReconciliationReport:
    """Load the four offline JSON inputs and reconcile them."""
    with Path(old_audit_path).open() as handle:
        old_audit = json.load(handle)
    with Path(new_audit_path).open() as handle:
        new_audit = json.load(handle)
    with Path(alias_path).open() as handle:
        alias_document = json.load(handle)
    with Path(approval_path).open() as handle:
        approval_document = json.load(handle)
    return reconcile(old_audit, new_audit, alias_document, approval_document)


def _item_to_dict(item: ReconciledItem) -> dict[str, Any]:
    return {
        "name": item.instance.name,
        "version": item.instance.version,
        "advisory_id": item.instance.advisory_id,
        "on_todo": item.on_todo,
        "reason": item.reason,
        "predecessor_ids": item.predecessor_ids,
        "propagated_from": item.propagated_from,
    }
