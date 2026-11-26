"""
Offline review of `pip-audit` output against candidate dependency locks.

The normal `pip-audit` flow answers a single question: *which vulnerabilities are
present in this environment?*  This module adds a second, deliberately offline
step.  It takes one or more `pip-audit` JSON reports plus a set of candidate lock
artifacts and answers:

* which candidate artifacts can coexist,
* which deduplicated advisories each artifact and each compatible combination
  would close,
* why incompatible combinations are impossible, and
* which otherwise-attractive alternatives still need an explicit approval.

The engine never performs network I/O and never guesses.  Unknown versions,
missing pins, and contradictory compatibility conditions are reported as
verifiable gaps rather than silently filtered away.

All outputs are canonicalized (stable sorting, alias merging, and deduplication)
so that the order in which reports, dependencies, aliases, pins, or candidates
are supplied cannot change the ticket conclusion.
"""

from __future__ import annotations

import json
import math
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from itertools import combinations
from pathlib import Path
from typing import Any, TypeAlias

import tomli
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

REVIEW_SCHEMA = "pip-audit-review/1"
"""Schema identifier emitted by `ReviewReport.to_dict`."""

VersionLike: TypeAlias = str | Version


class ReviewError(Exception):
    """Raised when an offline review cannot be performed."""


class ReviewParseError(ReviewError):
    """Raised when audit output or a candidate document is malformed."""


def _id_rank(vuln_id: str) -> int:
    """Rank vulnerability identifiers, preferring PYSEC, then CVE."""

    upper_id = vuln_id.upper()
    if upper_id.startswith("PYSEC"):
        return 0
    if upper_id.startswith("CVE"):
        return 1
    if upper_id.startswith("GHSA"):
        return 2
    return 3


def _id_key(vuln_id: str) -> tuple[int, str]:
    return (_id_rank(vuln_id), vuln_id)


def _parse_version(value: Any, *, context: str) -> Version:
    if isinstance(value, Version):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        value = str(value)
    if not isinstance(value, str):
        raise ReviewParseError(f"{context}: expected a version string, got {type(value).__name__}")
    try:
        return Version(value)
    except InvalidVersion as exc:
        raise ReviewParseError(f"{context}: invalid version {value!r}") from exc


def _series(version: Version) -> tuple[int, ...]:
    """Return the release series that a fix must belong to."""

    release = version.release
    if version.major == 0:
        return release[:2]
    return release[:1]


def version_is_fixed(pinned: Version, fix_versions: Sequence[Version]) -> bool:
    """
    Return whether `pinned` includes all known fixes for an advisory.

    A fix version covers a pin when the pin is at or above the fix.  Fixes from
    a different release series do not mask a newer fix in the pin's own series:
    for example, `2.0.0` is not considered fixed by `1.2.3` when `2.0.1` is also
    advertised as a fix.  This mirrors the branch-aware behaviour of package
    maintainers and keeps the offline result checkable from the report alone.
    """

    if not fix_versions:
        return False
    if not any(fix <= pinned for fix in fix_versions):
        return False
    pin_series = _series(pinned)
    return not any(fix > pinned and _series(fix) == pin_series for fix in fix_versions)


class _UnionFind:
    """A small deterministic union-find used to merge advisory aliases."""

    def __init__(self) -> None:
        self._parent: dict[str, str] = {}

    def add(self, item: str) -> None:
        """Add an item if it is not already present."""

        self._parent.setdefault(item, item)

    def find(self, item: str) -> str:
        """Return the canonical root for an item."""

        self.add(item)
        parent = self._parent[item]
        if parent != item:
            parent = self.find(parent)
            self._parent[item] = parent
        return parent

    def union(self, left: str, right: str) -> None:
        """Merge the sets containing two items."""

        left_root = self.find(left)
        right_root = self.find(right)
        if left_root == right_root:
            return
        # Choose by rank/id so the structure itself is order-independent.
        if _id_key(left_root) <= _id_key(right_root):
            self._parent[right_root] = left_root
        else:
            self._parent[left_root] = right_root

    def groups(self) -> dict[str, list[str]]:
        """Return all disjoint sets keyed by their representative."""

        grouped: dict[str, list[str]] = {}
        for item in self._parent:
            grouped.setdefault(self.find(item), []).append(item)
        return grouped


@dataclass(frozen=True)
class AuditVulnerability:
    """A single vulnerability entry from a `pip-audit` JSON report."""

    id: str
    aliases: frozenset[str]
    fix_versions: tuple[Version, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", self.id.strip())
        object.__setattr__(self, "aliases", frozenset(a.strip() for a in self.aliases if a.strip()))
        object.__setattr__(self, "fix_versions", tuple(sorted(set(self.fix_versions))))

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""

        return {
            "id": self.id,
            "aliases": sorted(self.aliases, key=_id_key),
            "fix_versions": [str(version) for version in self.fix_versions],
        }


@dataclass(frozen=True)
class AuditedDependency:
    """A dependency and its vulnerability entries from an audit report."""

    name: str
    version: Version | None
    vulnerabilities: tuple[AuditVulnerability, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", canonicalize_name(self.name))
        object.__setattr__(
            self,
            "vulnerabilities",
            tuple(
                sorted(
                    self.vulnerabilities,
                    key=lambda vuln: (
                        _id_key(vuln.id),
                        tuple(sorted(vuln.aliases, key=_id_key)),
                        tuple(str(v) for v in vuln.fix_versions),
                    ),
                )
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a `pip-audit`-shaped JSON representation."""

        if self.version is None:
            return {"name": self.name, "skip_reason": "no version specified"}
        return {
            "name": self.name,
            "version": str(self.version),
            "vulns": [vuln.to_dict() for vuln in self.vulnerabilities],
        }


@dataclass(frozen=True)
class AuditReport:
    """A normalized `pip-audit` JSON report."""

    dependencies: tuple[AuditedDependency, ...]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "dependencies",
            tuple(
                sorted(
                    self.dependencies,
                    key=lambda dep: (dep.name, str(dep.version) if dep.version is not None else ""),
                )
            ),
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any], *, source: str = "<audit>") -> AuditReport:
        """Build a report from a decoded `pip-audit` JSON object."""

        raw_dependencies = data.get("dependencies")
        if not isinstance(raw_dependencies, list):
            raise ReviewParseError(f"{source}: expected a 'dependencies' array")

        dependencies: list[AuditedDependency] = []
        for dep_index, raw_dep in enumerate(raw_dependencies):
            if not isinstance(raw_dep, Mapping):
                raise ReviewParseError(f"{source}: dependency #{dep_index} is not an object")
            name = raw_dep.get("name")
            if not isinstance(name, str) or not name.strip():
                raise ReviewParseError(f"{source}: dependency #{dep_index} has no name")

            raw_version = raw_dep.get("version")
            version = (
                None
                if raw_version is None
                else _parse_version(raw_version, context=f"{source}: {name}")
            )

            raw_vulns = raw_dep.get("vulns", [])
            if raw_vulns is None:
                raw_vulns = []
            if not isinstance(raw_vulns, list):
                raise ReviewParseError(f"{source}: {name}: expected 'vulns' to be an array")

            vulnerabilities: list[AuditVulnerability] = []
            for vuln_index, raw_vuln in enumerate(raw_vulns):
                if not isinstance(raw_vuln, Mapping):
                    raise ReviewParseError(
                        f"{source}: {name}: vulnerability #{vuln_index} is not an object"
                    )
                vuln_id = raw_vuln.get("id")
                if not isinstance(vuln_id, str) or not vuln_id.strip():
                    raise ReviewParseError(
                        f"{source}: {name}: vulnerability #{vuln_index} has no id"
                    )
                raw_aliases = raw_vuln.get("aliases", [])
                if raw_aliases is None:
                    raw_aliases = []
                if not isinstance(raw_aliases, list) or any(
                    not isinstance(alias, str) for alias in raw_aliases
                ):
                    raise ReviewParseError(
                        f"{source}: {name}: {vuln_id}: expected 'aliases' to be an array of strings"
                    )
                raw_fixes = raw_vuln.get("fix_versions", [])
                if raw_fixes is None:
                    raw_fixes = []
                if not isinstance(raw_fixes, list):
                    raise ReviewParseError(
                        f"{source}: {name}: {vuln_id}: expected 'fix_versions' to be an array"
                    )
                fix_versions = tuple(
                    _parse_version(fix, context=f"{source}: {name}: {vuln_id}") for fix in raw_fixes
                )
                vulnerabilities.append(
                    AuditVulnerability(
                        id=vuln_id,
                        aliases=frozenset(raw_aliases),
                        fix_versions=fix_versions,
                    )
                )

            dependencies.append(
                AuditedDependency(
                    name=name, version=version, vulnerabilities=tuple(vulnerabilities)
                )
            )

        return cls(dependencies=tuple(dependencies))

    @classmethod
    def from_json(cls, text: str | bytes, *, source: str = "<audit>") -> AuditReport:
        """Build a report from JSON text."""

        if isinstance(text, bytes):
            text = text.decode("utf-8-sig")
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ReviewParseError(f"{source}: invalid JSON: {exc.msg}") from exc
        if not isinstance(data, Mapping):
            raise ReviewParseError(f"{source}: expected a JSON object")
        return cls.from_dict(data, source=source)

    @classmethod
    def from_results(cls, results: Mapping[Any, Sequence[Any]]) -> AuditReport:
        """
        Build a report directly from `Auditor.audit` results.

        This accepts the mapping returned by the core auditor without requiring a
        round-trip through the JSON formatter.  Objects are accessed structurally,
        so the review layer stays decoupled from the service implementation.
        """

        dependencies: list[AuditedDependency] = []
        for dep, vulns in results.items():
            name = getattr(dep, "name")
            is_skipped = getattr(dep, "is_skipped", lambda: False)()
            version = None if is_skipped else _parse_version(str(dep.version), context=str(name))
            parsed_vulns = tuple(
                AuditVulnerability(
                    id=str(vuln.id),
                    aliases=frozenset(str(alias) for alias in vuln.aliases),
                    fix_versions=tuple(Version(str(fix)) for fix in vuln.fix_versions),
                )
                for vuln in vulns
            )
            dependencies.append(
                AuditedDependency(name=str(name), version=version, vulnerabilities=parsed_vulns)
            )
        return cls(dependencies=tuple(dependencies))

    def to_dict(self) -> dict[str, Any]:
        """Return a normalized `pip-audit` JSON object."""

        return {"dependencies": [dep.to_dict() for dep in self.dependencies]}


@dataclass(frozen=True, init=False)
class LockCandidate:
    """
    A candidate lock artifact.

    `pins` are exact package versions.  `conditions` are environment
    compatibility assignments such as ``{"platform": "linux", "python":
    "3.11"}``.  Two candidates can coexist only if no pin or condition
    contradicts another candidate (and no explicit `conflicts_with` edge is
    present).
    """

    id: str
    pins: tuple[tuple[str, Version], ...]
    conditions: tuple[tuple[str, str], ...]
    cost: int
    conflicts_with: frozenset[str]
    requires_approval: bool
    approval_note: str

    def __init__(
        self,
        id: str,
        pins: Mapping[str, VersionLike] | Iterable[tuple[str, VersionLike]],
        conditions: Mapping[str, str | int | float] | None = None,
        *,
        cost: int = 1,
        conflicts_with: Iterable[str] = (),
        requires_approval: bool = False,
        approval_note: str = "",
    ) -> None:
        if not isinstance(id, str) or not id.strip():
            raise ReviewParseError("candidate artifact id must be a non-empty string")
        if isinstance(cost, bool) or not isinstance(cost, int) or cost < 0:
            raise ReviewParseError(f"{id}: cost must be a non-negative integer")

        pin_map: dict[str, Version] = {}
        pin_items: Iterable[tuple[str, VersionLike]]
        if isinstance(pins, Mapping):
            pin_items = pins.items()
        else:
            pin_items = pins
        for raw_name, raw_version in pin_items:
            if not isinstance(raw_name, str) or not raw_name.strip():
                raise ReviewParseError(f"{id}: pin name must be a non-empty string")
            name = canonicalize_name(raw_name)
            version = _parse_version(raw_version, context=f"{id}: {raw_name}")
            previous = pin_map.get(name)
            if previous is not None and previous != version:
                raise ReviewParseError(
                    f"{id}: conflicting pins for {name}: {previous} and {version}"
                )
            pin_map[name] = version

        condition_map: dict[str, str] = {}
        for raw_dimension, raw_value in (conditions or {}).items():
            if not isinstance(raw_dimension, str) or not raw_dimension.strip():
                raise ReviewParseError(f"{id}: condition dimension must be a non-empty string")
            if not isinstance(raw_value, (str, int, float)) or isinstance(raw_value, bool):
                raise ReviewParseError(f"{id}: condition {raw_dimension!r} must be a scalar value")
            dimension = raw_dimension.strip().lower()
            value = str(raw_value).strip().lower()
            previous_value = condition_map.get(dimension)
            if previous_value is not None and previous_value != value:
                raise ReviewParseError(
                    f"{id}: conflicting conditions for {dimension}: "
                    f"{previous_value!r} and {value!r}"
                )
            condition_map[dimension] = value

        conflict_values: Iterable[str]
        if isinstance(conflicts_with, str):
            conflict_values = (conflicts_with,)
        else:
            conflict_values = conflicts_with
        conflict_ids = {conflict.strip() for conflict in conflict_values if conflict.strip()}
        conflict_ids.discard(id.strip())

        object.__setattr__(self, "id", id.strip())
        object.__setattr__(self, "pins", tuple(sorted(pin_map.items())))
        object.__setattr__(self, "conditions", tuple(sorted(condition_map.items())))
        object.__setattr__(self, "cost", cost)
        object.__setattr__(self, "conflicts_with", frozenset(conflict_ids))
        object.__setattr__(self, "requires_approval", requires_approval)
        object.__setattr__(self, "approval_note", approval_note.strip())

    @property
    def pin_map(self) -> dict[str, Version]:
        """Return pins as a mapping."""

        return dict(self.pins)

    @property
    def condition_map(self) -> dict[str, str]:
        """Return compatibility conditions as a mapping."""

        return dict(self.conditions)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any], *, source: str = "<candidate>") -> LockCandidate:
        """Build a candidate from a decoded JSON/TOML object."""

        raw_id = data.get("id", data.get("name"))
        if not isinstance(raw_id, str) or not raw_id.strip():
            raise ReviewParseError(f"{source}: candidate has no id")
        raw_pins = data.get("pins", data.get("dependencies"))
        if isinstance(raw_pins, list):
            pin_mapping: dict[str, Any] = {}
            for index, item in enumerate(raw_pins):
                if not isinstance(item, Mapping):
                    raise ReviewParseError(f"{source}: {raw_id}: pin #{index} is not an object")
                name = item.get("name")
                if not isinstance(name, str) or not name.strip():
                    raise ReviewParseError(f"{source}: {raw_id}: pin #{index} has no name")
                if "version" not in item:
                    raise ReviewParseError(f"{source}: {raw_id}: pin #{index} has no version")
                pin_mapping[name] = item["version"]
            raw_pins = pin_mapping
        if not isinstance(raw_pins, Mapping):
            raise ReviewParseError(f"{source}: {raw_id}: expected 'pins' to be an object")
        raw_conditions = data.get("conditions", data.get("constraints", {}))
        if raw_conditions is None:
            raw_conditions = {}
        if not isinstance(raw_conditions, Mapping):
            raise ReviewParseError(f"{source}: {raw_id}: expected 'conditions' to be an object")
        conditions = {str(key): str(value) for key, value in raw_conditions.items()}
        raw_conflicts = data.get("conflicts_with", data.get("conflicts", []))
        if isinstance(raw_conflicts, str):
            raw_conflicts = [raw_conflicts]
        if not isinstance(raw_conflicts, list) or any(
            not isinstance(value, str) for value in raw_conflicts
        ):
            raise ReviewParseError(
                f"{source}: {raw_id}: expected 'conflicts_with' to be an array of strings"
            )
        cost = data.get("cost", 1)
        requires_approval = data.get("requires_approval", False)
        if not isinstance(requires_approval, bool):
            raise ReviewParseError(f"{source}: {raw_id}: 'requires_approval' must be a boolean")
        approval_note = data.get("approval_note", data.get("note", ""))
        if not isinstance(approval_note, str):
            raise ReviewParseError(f"{source}: {raw_id}: 'approval_note' must be a string")

        return cls(
            id=raw_id,
            pins={str(name): str(version) for name, version in raw_pins.items()},
            conditions=conditions,
            cost=cost,
            conflicts_with=raw_conflicts,
            requires_approval=requires_approval,
            approval_note=approval_note,
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""

        result: dict[str, Any] = {
            "id": self.id,
            "pins": {name: str(version) for name, version in self.pins},
            "conditions": dict(self.conditions),
            "cost": self.cost,
            "requires_approval": self.requires_approval,
        }
        if self.conflicts_with:
            result["conflicts_with"] = sorted(self.conflicts_with)
        if self.approval_note:
            result["approval_note"] = self.approval_note
        return result


@dataclass(frozen=True)
class PackageFix:
    """Fix versions for one package affected by an advisory."""

    package: str
    fix_versions: tuple[Version, ...]


@dataclass(frozen=True)
class Advisory:
    """A deduplicated advisory, possibly spanning several packages."""

    id: str
    aliases: tuple[str, ...]
    package_fixes: tuple[PackageFix, ...]

    @property
    def packages(self) -> tuple[str, ...]:
        """Return the affected packages in canonical order."""

        return tuple(package_fix.package for package_fix in self.package_fixes)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""

        return {
            "id": self.id,
            "aliases": list(self.aliases),
            "packages": list(self.packages),
            "fix_versions": {
                package_fix.package: [str(v) for v in package_fix.fix_versions]
                for package_fix in self.package_fixes
            },
        }


@dataclass(frozen=True)
class CoverageGap:
    """A checkable reason why an advisory is not closed."""

    advisory: str
    package: str
    code: str
    pinned: str | None
    fix_versions: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""

        return {
            "advisory": self.advisory,
            "package": self.package,
            "code": self.code,
            "pinned": self.pinned,
            "fix_versions": list(self.fix_versions),
        }


@dataclass(frozen=True)
class InfeasibleReason:
    """A verifiable reason why a lock combination cannot coexist."""

    code: str
    message: str
    artifacts: tuple[str, ...]
    detail: tuple[tuple[str, str], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""

        return {
            "code": self.code,
            "message": self.message,
            "artifacts": list(self.artifacts),
            "detail": dict(self.detail),
        }


@dataclass(frozen=True)
class PackageChange:
    """A package pin that differs from the audited baseline."""

    package: str
    from_versions: tuple[str, ...]
    to_version: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""

        return {
            "package": self.package,
            "from_versions": list(self.from_versions),
            "to_version": self.to_version,
        }


@dataclass(frozen=True)
class Combination:
    """A combination of candidate artifacts and its advisory coverage."""

    artifacts: tuple[str, ...]
    cost: int
    feasible: bool
    pins: tuple[tuple[str, Version], ...]
    conditions: tuple[tuple[str, str], ...]
    covered: tuple[str, ...]
    uncovered: tuple[str, ...]
    gaps: tuple[CoverageGap, ...]
    reasons: tuple[InfeasibleReason, ...]
    requires_approval: bool
    approval_note: str
    changes: tuple[PackageChange, ...] = ()

    @property
    def coverage_scope(self) -> str:
        """Whether coverage was verified from merged pins or is potential only."""

        return "verified" if self.feasible else "potential"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""

        return {
            "artifacts": list(self.artifacts),
            "cost": self.cost,
            "feasible": self.feasible,
            "coverage_scope": self.coverage_scope,
            "pins": {name: str(version) for name, version in self.pins},
            "conditions": dict(self.conditions),
            "covered": list(self.covered),
            "uncovered": list(self.uncovered),
            "coverage_gaps": [gap.to_dict() for gap in self.gaps],
            "reasons": [reason.to_dict() for reason in self.reasons],
            "requires_approval": self.requires_approval,
            "approval_note": self.approval_note,
            "changes": [change.to_dict() for change in self.changes],
        }


@dataclass(frozen=True)
class ArtifactReview:
    """Per-artifact coverage, independent of any combination."""

    artifact: LockCandidate
    covered: tuple[str, ...]
    uncovered: tuple[str, ...]
    gaps: tuple[CoverageGap, ...]
    changes: tuple[PackageChange, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""

        return {
            "id": self.artifact.id,
            "cost": self.artifact.cost,
            "pins": {name: str(version) for name, version in self.artifact.pins},
            "conditions": dict(self.artifact.conditions),
            "requires_approval": self.artifact.requires_approval,
            "covered": list(self.covered),
            "uncovered": list(self.uncovered),
            "coverage_gaps": [gap.to_dict() for gap in self.gaps],
            "changes": [change.to_dict() for change in self.changes],
        }


@dataclass(frozen=True)
class Alternative:
    """A plan that cannot be used as the ticket conclusion yet."""

    artifacts: tuple[str, ...]
    cost: int
    covered: tuple[str, ...]
    uncovered: tuple[str, ...]
    kind: str
    requires_approval: bool
    approval_note: str
    blocked_by: tuple[InfeasibleReason, ...] = ()
    pins: tuple[tuple[str, Version], ...] = ()
    conditions: tuple[tuple[str, str], ...] = ()
    changes: tuple[PackageChange, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""

        return {
            "artifacts": list(self.artifacts),
            "cost": self.cost,
            "covered": list(self.covered),
            "uncovered": list(self.uncovered),
            "kind": self.kind,
            "requires_approval": self.requires_approval,
            "approval_note": self.approval_note,
            "blocked_by": [reason.to_dict() for reason in self.blocked_by],
            "pins": {name: str(version) for name, version in self.pins},
            "conditions": dict(self.conditions),
            "changes": [change.to_dict() for change in self.changes],
        }


@dataclass(frozen=True)
class ReviewOptions:
    """Controls for deterministic combination enumeration."""

    max_artifacts: int | None = None
    max_combinations: int = 65536
    max_alternatives: int = 20

    def __post_init__(self) -> None:
        if self.max_artifacts is not None and self.max_artifacts < 1:
            raise ReviewError("max_artifacts must be at least 1")
        if self.max_combinations < 1:
            raise ReviewError("max_combinations must be at least 1")
        if self.max_alternatives < 0:
            raise ReviewError("max_alternatives must be non-negative")


@dataclass(frozen=True)
class ReviewReport:
    """The complete, deterministic result of an offline review."""

    advisories: tuple[Advisory, ...]
    artifacts: tuple[ArtifactReview, ...]
    combinations: tuple[Combination, ...]
    infeasible: tuple[Combination, ...]
    recommended: tuple[Combination, ...]
    alternatives: tuple[Alternative, ...]
    baseline: tuple[tuple[str, tuple[str, ...]], ...] = ()

    @property
    def complete(self) -> bool:
        """Whether every recommended plan independently closes every advisory."""

        if not self.advisories:
            return True
        return bool(self.recommended) and all(
            not combination.uncovered for combination in self.recommended
        )

    @property
    def summary(self) -> dict[str, Any]:
        """Return a compact, order-independent summary."""

        advisory_ids = {advisory.id for advisory in self.advisories}
        recommended_covers = [set(plan.covered) for plan in self.recommended]
        covered_by_any: set[str] = set()
        for covered in recommended_covers:
            covered_by_any.update(covered)
        if recommended_covers:
            covered_by_all = set(recommended_covers[0])
            for covered in recommended_covers[1:]:
                covered_by_all.intersection_update(covered)
        else:
            covered_by_all = set()
        return {
            "advisory_count": len(self.advisories),
            "artifact_count": len(self.artifacts),
            "combination_count": len(self.combinations),
            "feasible_combination_count": sum(1 for c in self.combinations if c.feasible),
            "infeasible_combination_count": len(self.infeasible),
            "recommended_count": len(self.recommended),
            "alternative_count": len(self.alternatives),
            "covered_by_any_recommended": sorted(covered_by_any, key=_id_key),
            "covered_by_every_recommended": sorted(covered_by_all, key=_id_key),
            "uncovered_by_all_recommended": sorted(advisory_ids - covered_by_all, key=_id_key),
            "closed_advisory_count": len(covered_by_any),
            "closed_by_every_recommended_count": len(covered_by_all),
            "complete": self.complete,
        }

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable report."""

        return {
            "schema": REVIEW_SCHEMA,
            "advisories": [advisory.to_dict() for advisory in self.advisories],
            "baseline": {package: list(versions) for package, versions in self.baseline},
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "combinations": [combination.to_dict() for combination in self.combinations],
            "infeasible": [combination.to_dict() for combination in self.infeasible],
            "recommended": [combination.to_dict() for combination in self.recommended],
            "alternatives": [alternative.to_dict() for alternative in self.alternatives],
            "summary": self.summary,
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        """Return the report as stable JSON."""

        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def to_text(self) -> str:
        """Render a compact human-readable report."""

        lines = [
            f"Advisories: {len(self.advisories)}",
            f"Candidate artifacts: {len(self.artifacts)}",
            f"Combinations: {len(self.combinations)} "
            f"({sum(1 for c in self.combinations if c.feasible)} feasible)",
        ]

        if self.recommended:
            lines.append("Recommended (all equally valid minima):")
            lines.extend(f"  - {_plan_label(plan)}" for plan in self.recommended)
        else:
            lines.append("Recommended: none")

        if self.infeasible:
            lines.append("Infeasible combinations (retained):")
            for plan in self.infeasible:
                reasons = "; ".join(reason.message for reason in plan.reasons)
                lines.append(f"  - {' + '.join(plan.artifacts)}: {reasons}")

        if self.alternatives:
            lines.append("Alternatives requiring approval:")
            lines.extend(
                (
                    f"  - {', '.join(alternative.artifacts)} "
                    f"(covers {len(alternative.covered)}, needs approval: "
                    f"{alternative.approval_note or 'explicit exception'})"
                )
                for alternative in self.alternatives
            )

        lines.append("Complete: " + ("yes" if self.complete else "no"))
        return "\n".join(lines)


def _plan_label(plan: Combination) -> str:
    label = (
        f"{', '.join(plan.artifacts)}: cost {plan.cost}, "
        f"covers {len(plan.covered)}/{len(plan.covered) + len(plan.uncovered)}"
    )
    if plan.changes:
        rendered_changes = ", ".join(
            f"{change.package} {'/'.join(change.from_versions) or 'new'}->{change.to_version}"
            for change in plan.changes
        )
        label += f", changes {rendered_changes}"
    return label


def _parse_document(text: str | bytes, *, source: str) -> Any:
    if isinstance(text, bytes):
        text = text.decode("utf-8-sig")
    try:
        return json.loads(text)
    except json.JSONDecodeError as json_error:
        try:
            return tomli.loads(text)
        except tomli.TOMLDecodeError as toml_error:
            raise ReviewParseError(
                f"{source}: neither valid JSON ({json_error.msg}) nor TOML ({toml_error})"
            ) from toml_error


def parse_audit_reports(value: Any, *, source: str = "<audit>") -> tuple[AuditReport, ...]:
    """Parse one or more audit reports from decoded objects, JSON, or paths."""

    if isinstance(value, AuditReport):
        return (value,)
    if isinstance(value, Path):
        return (AuditReport.from_json(value.read_text(encoding="utf-8-sig"), source=str(value)),)
    if isinstance(value, Mapping):
        return (AuditReport.from_dict(value, source=source),)
    if isinstance(value, (str, bytes)):
        text_value = value.decode("utf-8-sig") if isinstance(value, bytes) else value
        path = _existing_path(text_value)
        if path is not None:
            return (AuditReport.from_json(path.read_text(encoding="utf-8-sig"), source=str(path)),)
        return (AuditReport.from_json(value, source=source),)
    if isinstance(value, Sequence):
        reports: list[AuditReport] = []
        for index, item in enumerate(value):
            reports.extend(parse_audit_reports(item, source=f"{source}[{index}]"))
        if not reports:
            raise ReviewParseError(f"{source}: no audit reports supplied")
        return tuple(reports)
    raise ReviewParseError(f"{source}: unsupported audit report type {type(value).__name__}")


def parse_candidates(value: Any, *, source: str = "<candidates>") -> tuple[LockCandidate, ...]:
    """Parse candidate artifacts from decoded objects, JSON, TOML, or paths."""

    if isinstance(value, LockCandidate):
        return (value,)
    if isinstance(value, Path):
        document = _parse_document(value.read_text(encoding="utf-8-sig"), source=str(value))
        return parse_candidates(document, source=str(value))
    if isinstance(value, (str, bytes)):
        text_value = value.decode("utf-8-sig") if isinstance(value, bytes) else value
        path = _existing_path(text_value)
        if path is not None:
            return parse_candidates(
                _parse_document(path.read_text(encoding="utf-8-sig"), source=str(path)),
                source=str(path),
            )
        return parse_candidates(_parse_document(value, source=source), source=source)
    if isinstance(value, Mapping):
        if "id" in value or "name" in value:
            return (LockCandidate.from_dict(value, source=source),)
        raw_candidates = value.get("artifacts", value.get("candidates", value.get("locks")))
        if raw_candidates is None:
            raise ReviewParseError(
                f"{source}: expected an 'artifacts', 'candidates', or 'locks' array"
            )
        return parse_candidates(raw_candidates, source=source)
    if isinstance(value, Sequence):
        candidates: list[LockCandidate] = []
        seen_ids: set[str] = set()
        for index, item in enumerate(value):
            if isinstance(item, LockCandidate):
                candidate = item
            elif isinstance(item, Mapping):
                candidate = LockCandidate.from_dict(item, source=source)
            else:
                raise ReviewParseError(f"{source}: candidate #{index} is not an object")
            if candidate.id in seen_ids:
                raise ReviewParseError(f"{source}: duplicate candidate id {candidate.id!r}")
            seen_ids.add(candidate.id)
            candidates.append(candidate)
        return tuple(sorted(candidates, key=lambda candidate: candidate.id))
    raise ReviewParseError(f"{source}: unsupported candidate type {type(value).__name__}")


def _existing_path(value: str) -> Path | None:
    """Return a path only when a compact string names an existing file."""

    if not value or "\n" in value or len(value) > 4096:
        return None
    if value.lstrip().startswith(("{", "[", "<", '"')):
        return None
    try:
        path = Path(value)
        return path if path.is_file() else None
    except OSError:
        return None


def load_audit_reports(paths: str | Path | Iterable[str | Path]) -> tuple[AuditReport, ...]:
    """Load one or more `pip-audit` JSON reports from disk."""

    if isinstance(paths, (str, Path)):
        path_list = [Path(paths)]
    else:
        path_list = [Path(path) for path in paths]
    if not path_list:
        raise ReviewParseError("no audit report paths supplied")
    return tuple(
        AuditReport.from_json(path.read_text(encoding="utf-8-sig"), source=str(path))
        for path in path_list
    )


def load_candidates(path: str | Path) -> tuple[LockCandidate, ...]:
    """Load candidate lock artifacts from a JSON or TOML file."""

    candidate_path = Path(path)
    document = _parse_document(
        candidate_path.read_text(encoding="utf-8-sig"), source=str(candidate_path)
    )
    return parse_candidates(document, source=str(candidate_path))


def _build_advisories(reports: Sequence[AuditReport]) -> tuple[Advisory, ...]:
    union_find = _UnionFind()
    occurrences: list[tuple[str, str, tuple[Version, ...]]] = []

    for report in reports:
        for dependency in report.dependencies:
            for vulnerability in dependency.vulnerabilities:
                identifiers = {vulnerability.id, *vulnerability.aliases}
                identifiers.discard("")
                if not identifiers:
                    continue
                sorted_identifiers = sorted(identifiers, key=_id_key)
                for identifier in sorted_identifiers:
                    union_find.add(identifier)
                for identifier in sorted_identifiers[1:]:
                    union_find.union(sorted_identifiers[0], identifier)
                occurrences.append((vulnerability.id, dependency.name, vulnerability.fix_versions))

    grouped_ids = union_find.groups()
    root_for_id = {identifier: root for root, ids in grouped_ids.items() for identifier in ids}

    fixes_by_root: dict[str, dict[str, set[Version]]] = {}
    for vuln_id, package, fix_versions in occurrences:
        root = root_for_id[vuln_id]
        package_fixes = fixes_by_root.setdefault(root, {})
        package_fixes.setdefault(package, set()).update(fix_versions)

    advisories: list[Advisory] = []
    for root, identifiers in grouped_ids.items():
        canonical = min(identifiers, key=_id_key)
        package_fixes = tuple(
            PackageFix(package=package, fix_versions=tuple(sorted(versions)))
            for package, versions in sorted(fixes_by_root.get(root, {}).items())
        )
        advisories.append(
            Advisory(
                id=canonical,
                aliases=tuple(
                    sorted(
                        (identifier for identifier in identifiers if identifier != canonical),
                        key=_id_key,
                    )
                ),
                package_fixes=package_fixes,
            )
        )

    return tuple(sorted(advisories, key=lambda advisory: _id_key(advisory.id)))


def _baseline_versions(reports: Sequence[AuditReport]) -> dict[str, tuple[Version, ...]]:
    versions: dict[str, set[Version]] = {}
    for report in reports:
        for dependency in report.dependencies:
            if dependency.version is not None:
                versions.setdefault(dependency.name, set()).add(dependency.version)
    return {package: tuple(sorted(values)) for package, values in sorted(versions.items())}


def _pin_changes(
    pins: Mapping[str, Version], baseline: Mapping[str, tuple[Version, ...]]
) -> tuple[PackageChange, ...]:
    changes: list[PackageChange] = []
    for package, pinned in sorted(pins.items()):
        previous = baseline.get(package, ())
        if pinned not in previous:
            changes.append(
                PackageChange(
                    package=package,
                    from_versions=tuple(str(version) for version in previous),
                    to_version=str(pinned),
                )
            )
    return tuple(changes)


def _coverage_for_pins(
    advisories: Sequence[Advisory], pins: Mapping[str, Version]
) -> tuple[tuple[str, ...], tuple[CoverageGap, ...]]:
    covered: list[str] = []
    gaps: list[CoverageGap] = []

    for advisory in advisories:
        advisory_gaps: list[CoverageGap] = []
        for package_fix in advisory.package_fixes:
            pinned = pins.get(package_fix.package)
            if pinned is None:
                advisory_gaps.append(
                    CoverageGap(
                        advisory=advisory.id,
                        package=package_fix.package,
                        code="missing_pin",
                        pinned=None,
                        fix_versions=tuple(str(v) for v in package_fix.fix_versions),
                    )
                )
            elif not version_is_fixed(pinned, package_fix.fix_versions):
                advisory_gaps.append(
                    CoverageGap(
                        advisory=advisory.id,
                        package=package_fix.package,
                        code="pin_not_fixed",
                        pinned=str(pinned),
                        fix_versions=tuple(str(v) for v in package_fix.fix_versions),
                    )
                )
        if advisory_gaps:
            gaps.extend(
                sorted(
                    advisory_gaps,
                    key=lambda gap: (gap.advisory, gap.package, gap.code, gap.pinned or ""),
                )
            )
        else:
            covered.append(advisory.id)

    return tuple(covered), tuple(gaps)


def _merge_pins(artifacts: Sequence[LockCandidate]) -> dict[str, Version]:
    merged: dict[str, Version] = {}
    for artifact in artifacts:
        merged.update(artifact.pin_map)
    return merged


def _merge_conditions(artifacts: Sequence[LockCandidate]) -> dict[str, str]:
    merged: dict[str, str] = {}
    for artifact in artifacts:
        merged.update(artifact.condition_map)
    return merged


def _infeasibility_reasons(artifacts: Sequence[LockCandidate]) -> tuple[InfeasibleReason, ...]:
    reasons: list[InfeasibleReason] = []
    ids = {artifact.id for artifact in artifacts}

    for artifact in artifacts:
        reasons.extend(
            (
                InfeasibleReason(
                    code="declared_conflict",
                    message=f"{artifact.id} declares a conflict with {conflict}",
                    artifacts=(artifact.id, conflict),
                    detail=(("artifacts", f"{artifact.id} -> {conflict}"),),
                )
            )
            for conflict in sorted(artifact.conflicts_with & ids)
            if artifact.id < conflict
        )

    condition_values: dict[str, dict[str, list[str]]] = {}
    for artifact in artifacts:
        for dimension, value in artifact.conditions:
            condition_values.setdefault(dimension, {}).setdefault(value, []).append(artifact.id)
    for dimension in sorted(condition_values):
        values = condition_values[dimension]
        if len(values) < 2:
            continue
        rendered = " | ".join(
            f"{value} ({', '.join(sorted(value_ids))})"
            for value, value_ids in sorted(values.items())
        )
        involved = tuple(
            sorted({artifact_id for value_ids in values.values() for artifact_id in value_ids})
        )
        reasons.append(
            InfeasibleReason(
                code="condition_conflict",
                message=f"mutually exclusive {dimension} conditions: {rendered}",
                artifacts=involved,
                detail=(("dimension", dimension), ("values", rendered)),
            )
        )

    pin_values: dict[str, dict[str, list[str]]] = {}
    for artifact in artifacts:
        for package, version in artifact.pins:
            pin_values.setdefault(package, {}).setdefault(str(version), []).append(artifact.id)
    for package in sorted(pin_values):
        versions = pin_values[package]
        if len(versions) < 2:
            continue
        rendered = " | ".join(
            f"{version} ({', '.join(sorted(version_ids))})"
            for version, version_ids in sorted(versions.items())
        )
        involved = tuple(
            sorted(
                {artifact_id for version_ids in versions.values() for artifact_id in version_ids}
            )
        )
        reasons.append(
            InfeasibleReason(
                code="pin_conflict",
                message=f"conflicting pins for {package}: {rendered}",
                artifacts=involved,
                detail=(("package", package), ("versions", rendered)),
            )
        )

    return tuple(
        sorted(reasons, key=lambda reason: (reason.code, reason.message, reason.artifacts))
    )


def _artifact_coverage(
    artifact: LockCandidate, advisories: Sequence[Advisory]
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[CoverageGap, ...]]:
    covered, gaps = _coverage_for_pins(advisories, artifact.pin_map)
    covered_set = set(covered)
    uncovered = tuple(advisory.id for advisory in advisories if advisory.id not in covered_set)
    return covered, uncovered, gaps


def _evaluate_combination(
    artifacts: Sequence[LockCandidate],
    advisories: Sequence[Advisory],
    baseline: Mapping[str, tuple[Version, ...]],
) -> Combination:
    sorted_artifacts = tuple(sorted(artifacts, key=lambda artifact: artifact.id))
    reasons = _infeasibility_reasons(sorted_artifacts)
    feasible = not reasons
    cost = sum(artifact.cost for artifact in sorted_artifacts)
    requires_approval = any(artifact.requires_approval for artifact in sorted_artifacts)
    approval_note = "; ".join(
        sorted(
            artifact.approval_note or f"{artifact.id} requires approval"
            for artifact in sorted_artifacts
            if artifact.requires_approval
        )
    )

    if feasible:
        pins = _merge_pins(sorted_artifacts)
        conditions = _merge_conditions(sorted_artifacts)
        covered, gaps = _coverage_for_pins(advisories, pins)
        pin_entries = tuple(sorted(pins.items()))
        condition_entries = tuple(sorted(conditions.items()))
        changes = _pin_changes(pins, baseline)
    else:
        pin_entries = ()
        condition_entries = ()
        changes = ()
        covered_set: set[str] = set()
        for artifact in sorted_artifacts:
            artifact_covered, _, _ = _artifact_coverage(artifact, advisories)
            covered_set.update(artifact_covered)
        covered = tuple(sorted(covered_set, key=_id_key))
        gaps = ()

    covered_set = set(covered)
    uncovered = tuple(advisory.id for advisory in advisories if advisory.id not in covered_set)

    return Combination(
        artifacts=tuple(artifact.id for artifact in sorted_artifacts),
        cost=cost,
        feasible=feasible,
        pins=pin_entries,
        conditions=condition_entries,
        covered=covered,
        uncovered=uncovered,
        gaps=gaps,
        reasons=reasons,
        requires_approval=requires_approval,
        approval_note=approval_note,
        changes=changes,
    )


def _select_recommended(combinations: Sequence[Combination]) -> tuple[Combination, ...]:
    eligible = [combination for combination in combinations if combination.feasible]
    eligible = [combination for combination in eligible if not combination.requires_approval]
    if not eligible:
        return ()
    max_coverage = max(len(combination.covered) for combination in eligible)
    if max_coverage == 0:
        return ()
    best_coverage = [
        combination for combination in eligible if len(combination.covered) == max_coverage
    ]
    min_cost = min(combination.cost for combination in best_coverage)
    recommended = [combination for combination in best_coverage if combination.cost == min_cost]
    return tuple(
        sorted(
            recommended,
            key=lambda combination: (
                combination.cost,
                -len(combination.covered),
                combination.artifacts,
            ),
        )
    )


def _approval_alternatives(
    combinations: Sequence[Combination], options: ReviewOptions
) -> list[Alternative]:
    approval_plans = [
        combination
        for combination in combinations
        if combination.feasible and combination.requires_approval
    ]
    retained: list[Combination] = []
    for plan in approval_plans:
        plan_cover = set(plan.covered)
        dominated = any(
            other is not plan
            and other.cost <= plan.cost
            and set(other.covered) >= plan_cover
            and (other.cost < plan.cost or set(other.covered) > plan_cover)
            for other in approval_plans
        )
        if not dominated:
            retained.append(plan)

    alternatives = [
        Alternative(
            artifacts=plan.artifacts,
            cost=plan.cost,
            covered=plan.covered,
            uncovered=plan.uncovered,
            kind="declared",
            requires_approval=True,
            approval_note=plan.approval_note or "candidate explicitly requires approval",
            pins=plan.pins,
            conditions=plan.conditions,
            changes=plan.changes,
        )
        for plan in retained
    ]
    alternatives.sort(key=lambda alt: (-len(alt.covered), alt.cost, alt.artifacts, alt.kind))
    return alternatives[: options.max_alternatives]


def _conflict_alternatives(
    combinations: Sequence[Combination],
    recommended: Sequence[Combination],
    options: ReviewOptions,
) -> list[Alternative]:
    if options.max_alternatives == 0:
        return []
    recommended_covers = [set(plan.covered) for plan in recommended]
    infeasible = [combination for combination in combinations if not combination.feasible]

    selected: dict[tuple[str, ...], Alternative] = {}
    for plan in infeasible:
        plan_cover = set(plan.covered)
        if not plan_cover:
            continue
        # Only surface an override when it beats every individual recommended
        # plan. A plan that merely matches the union of several recommended
        # plans is not enough: a ticket needs one usable lock per environment.
        if any(plan_cover <= covered for covered in recommended_covers):
            continue
        note = "requires an approved exception to mutually exclusive runtime constraints"
        alternative = Alternative(
            artifacts=plan.artifacts,
            cost=plan.cost,
            covered=plan.covered,
            uncovered=plan.uncovered,
            kind="conflict_override",
            requires_approval=True,
            approval_note=note,
            blocked_by=plan.reasons,
            pins=plan.pins,
            conditions=plan.conditions,
            changes=plan.changes,
        )
        existing = selected.get(plan.covered)
        if existing is None or (
            alternative.cost,
            len(alternative.artifacts),
            alternative.artifacts,
        ) < (existing.cost, len(existing.artifacts), existing.artifacts):
            selected[plan.covered] = alternative

    alternatives = sorted(
        selected.values(),
        key=lambda alt: (-len(alt.covered), alt.cost, alt.artifacts, alt.kind),
    )
    return alternatives[: options.max_alternatives]


def reconcile(
    audit: Any,
    candidates: Any,
    *,
    options: ReviewOptions | None = None,
) -> ReviewReport:
    """
    Reconcile `pip-audit` output with candidate dependency locks, offline.

    `audit` and `candidates` accept parsed objects, decoded mappings, JSON/TOML
    text, or paths to those documents.  Passing several audit reports is
    supported so that the same advisory observed in multiple candidate
    artifacts is merged exactly once.

    The return value contains every enumerated combination, every retained
    infeasible combination and its reasons, all equally-valid recommended
    minima, and alternatives that require approval.
    """

    review_options = options or ReviewOptions()
    reports = parse_audit_reports(audit)
    parsed_candidates = parse_candidates(candidates)
    advisories = _build_advisories(reports)
    baseline = _baseline_versions(reports)

    artifact_reviews: list[ArtifactReview] = []
    for artifact in parsed_candidates:
        covered, uncovered, gaps = _artifact_coverage(artifact, advisories)
        artifact_reviews.append(
            ArtifactReview(
                artifact=artifact,
                covered=covered,
                uncovered=uncovered,
                gaps=gaps,
                changes=_pin_changes(artifact.pin_map, baseline),
            )
        )

    max_artifacts = (
        len(parsed_candidates)
        if review_options.max_artifacts is None
        else min(review_options.max_artifacts, len(parsed_candidates))
    )
    total = sum(math.comb(len(parsed_candidates), size) for size in range(1, max_artifacts + 1))
    if total > review_options.max_combinations:
        raise ReviewError(
            f"refusing to enumerate {total} combinations (limit "
            f"{review_options.max_combinations}); raise max_combinations or lower "
            "max_artifacts explicitly"
        )

    evaluated: list[Combination] = []
    evaluated.extend(
        _evaluate_combination(artifact_set, advisories, baseline)
        for size in range(1, max_artifacts + 1)
        for artifact_set in combinations(parsed_candidates, size)
    )
    evaluated.sort(
        key=lambda combination: (
            combination.cost,
            -len(combination.covered),
            combination.artifacts,
        )
    )

    feasible = tuple(combination for combination in evaluated if combination.feasible)
    infeasible = tuple(combination for combination in evaluated if not combination.feasible)
    recommended = _select_recommended(feasible)

    alternatives = _approval_alternatives(feasible, review_options)
    alternatives.extend(_conflict_alternatives(evaluated, recommended, review_options))
    alternatives = sorted(
        alternatives,
        key=lambda alt: (-len(alt.covered), alt.cost, alt.kind, alt.artifacts),
    )[: review_options.max_alternatives]

    return ReviewReport(
        advisories=advisories,
        artifacts=tuple(artifact_reviews),
        combinations=tuple(evaluated),
        infeasible=infeasible,
        recommended=recommended,
        alternatives=tuple(alternatives),
        baseline=tuple(
            (package, tuple(str(version) for version in versions))
            for package, versions in baseline.items()
        ),
    )


def review(
    audit: Any,
    candidates: Any,
    *,
    options: ReviewOptions | None = None,
) -> ReviewReport:
    """Alias for `reconcile`."""

    return reconcile(audit, candidates, options=options)


def parse_audit_report(value: Any, *, source: str = "<audit>") -> AuditReport:
    """Parse exactly one audit report."""

    reports = parse_audit_reports(value, source=source)
    if len(reports) != 1:
        raise ReviewParseError(f"{source}: expected exactly one audit report, got {len(reports)}")
    return reports[0]


def load_audit_report(path: str | Path) -> AuditReport:
    """Load exactly one `pip-audit` JSON report from disk."""

    return parse_audit_report(Path(path))


CandidateArtifact = LockCandidate
"""Alias for `LockCandidate`, matching the candidate-artifact terminology."""

LockCombination = Combination
"""Alias for `Combination`."""


__all__ = [
    "REVIEW_SCHEMA",
    "Advisory",
    "Alternative",
    "ArtifactReview",
    "AuditReport",
    "AuditVulnerability",
    "AuditedDependency",
    "CandidateArtifact",
    "Combination",
    "CoverageGap",
    "InfeasibleReason",
    "LockCandidate",
    "LockCombination",
    "PackageChange",
    "PackageFix",
    "ReviewError",
    "ReviewOptions",
    "ReviewParseError",
    "ReviewReport",
    "load_audit_reports",
    "load_audit_report",
    "load_candidates",
    "parse_audit_report",
    "parse_audit_reports",
    "parse_candidates",
    "reconcile",
    "review",
    "version_is_fixed",
]
