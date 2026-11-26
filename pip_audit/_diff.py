"""
Differential audit attribution.

This module compares four audit results in a 2x2 matrix: the old and new
dependency manifests are crossed with the old and new advisory snapshots.  The
four cells make it possible to say whether a finding changed because the
dependency changed, because the advisory data changed, or because both changed
together.  A missing cell, or a freeze snapshot that did not make a judgment
about a package, is never treated as "no finding": it is reported as unknown.
"""

from __future__ import annotations

import argparse
import json
import logging
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from enum import Enum
from pathlib import Path
from typing import Any, TypeAlias, cast

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from pip_audit._dependency_source import DependencySourceError, RequirementSource
from pip_audit._service import Dependency, FreezeFixtureError, FreezeService, VulnerabilityResult
from pip_audit._service.interface import ResolvedDependency, SkippedDependency, VulnerabilityID

logger = logging.getLogger(__name__)

CELLS: tuple[str, ...] = ("old-old", "old-new", "new-old", "new-new")
REFERENCE_FROM = "old-old"
REFERENCE_TO = "new-new"
CANONICAL_CELLS: dict[str, str] = {
    "old-old": "old-old",
    "old_old": "old-old",
    "oldold": "old-old",
    "00": "old-old",
    "old-new": "old-new",
    "old_new": "old-new",
    "oldnew": "old-new",
    "01": "old-new",
    "new-old": "new-old",
    "new_old": "new-old",
    "newold": "new-old",
    "10": "new-old",
    "new-new": "new-new",
    "new_new": "new-new",
    "newnew": "new-new",
    "11": "new-new",
}


class DiffError(ValueError):
    """Raised when audit results cannot be compared."""


class AuditStatus(str, Enum):
    """Whether a package was actually judged by an audit."""

    AUDITED = "audited"
    UNKNOWN = "unknown"
    SKIPPED = "skipped"
    UNJUDGED = "unknown"


class Attribution(str, Enum):
    """The axis or interaction that explains an alert's presence pattern."""

    DEPENDENCY = "dependency"
    DEPENDENCY_ONLY = "dependency"
    ADVISORY = "advisory"
    ADVISORY_ONLY = "advisory"
    BOTH = "both"
    BOTH_CHANGED = "both"
    INTERACTION = "both"
    MIXED = "mixed"
    UNCHANGED = "unchanged"
    UNKNOWN = "unknown"


class Direction(str, Enum):
    """The change between the old-old reference and the new-new reference."""

    ADDED = "added"
    REMOVED = "removed"
    UNCHANGED = "unchanged"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class AuditedPackage:
    """One package record inside a saved audit result."""

    name: str
    version: str | None
    status: AuditStatus = AuditStatus.AUDITED
    vulns: tuple[VulnerabilityResult, ...] = ()
    reason: str | None = None
    queried_version: str | None = None

    @property
    def canonical_name(self) -> str:
        """Return the PEP-503 canonical package name."""
        return canonicalize_name(self.name)

    def to_dict(self) -> dict[str, Any]:
        """Serialize this package record to JSON-compatible data."""
        record: dict[str, Any] = {
            "name": self.canonical_name,
            "version": self.version,
            "status": self.status.value,
            "queried_version": self.queried_version,
            "vulns": [_vuln_to_dict(vuln) for vuln in self.vulns],
        }
        if self.reason is not None:
            record["reason"] = self.reason
        if self.status is AuditStatus.SKIPPED:
            # Match the existing JSON format's spelling for skipped packages.
            record["skip_reason"] = self.reason or "skipped"
        return record


@dataclass(frozen=True)
class AuditResult:
    """A serializable snapshot of one complete audit."""

    packages: Mapping[str, AuditedPackage]
    manifest: str | None = None
    advisory_snapshot: str | None = None
    manifest_packages: frozenset[str] | None = None
    source: str | None = None

    def __post_init__(self) -> None:
        packages: dict[str, AuditedPackage] = {}
        for name, record in self.packages.items():
            key = canonicalize_name(name)
            if record.name != key:
                record = replace(record, name=key)
            packages[key] = record
        object.__setattr__(self, "packages", packages)
        if self.manifest_packages is not None:
            object.__setattr__(
                self,
                "manifest_packages",
                frozenset(canonicalize_name(name) for name in self.manifest_packages),
            )

    def package(self, name: str) -> AuditedPackage | None:
        """Return the record for ``name``, canonicalizing the lookup key."""
        return self.packages.get(canonicalize_name(name))

    def expected_packages(self) -> frozenset[str]:
        """Return the package names that belong to the manifest."""
        if self.manifest_packages is not None:
            return self.manifest_packages
        return frozenset(self.packages)

    def coverage(self) -> dict[str, Any]:
        """Return coverage information, including actual queried versions."""
        expected = sorted(self.expected_packages())
        queried = [
            {
                "name": record.canonical_name,
                "version": record.version,
                "queried_version": record.queried_version,
                "status": record.status.value,
            }
            for record in sorted(self.packages.values(), key=lambda record: record.canonical_name)
        ]
        unknown = [
            {
                "name": record.canonical_name,
                "version": record.version,
                "queried_version": record.queried_version,
                "status": record.status.value,
                "reason": record.reason,
            }
            for record in sorted(self.packages.values(), key=lambda record: record.canonical_name)
            if record.status is AuditStatus.UNKNOWN
        ]
        skipped = [
            {
                "name": record.canonical_name,
                "version": record.version,
                "queried_version": record.queried_version,
                "status": record.status.value,
                "reason": record.reason,
            }
            for record in sorted(self.packages.values(), key=lambda record: record.canonical_name)
            if record.status is AuditStatus.SKIPPED
        ]
        missing = sorted(set(expected) - set(self.packages))
        return {
            "manifest": self.manifest,
            "advisory_snapshot": self.advisory_snapshot,
            "source": self.source,
            "expected": expected,
            "expected_count": len(expected),
            "queried_count": len(queried),
            "audited_count": sum(1 for record in queried if record["status"] == "audited"),
            "queried": queried,
            "unknown": unknown,
            "skipped": skipped,
            "missing": missing,
        }

    def to_dict(self) -> dict[str, Any]:
        """Serialize this audit snapshot.

        The ``dependencies`` and ``fixes`` keys intentionally match the default
        ``pip-audit -f json`` shape.  Extra metadata is additive, so existing
        consumers can keep reading the output while diff mode can preserve
        unknown coverage and actual queried versions.
        """
        return {
            "schema_version": 1,
            "audit": {
                "manifest": self.manifest,
                "advisory_snapshot": self.advisory_snapshot,
                "source": self.source,
            },
            "coverage": self.coverage(),
            "dependencies": [
                record.to_dict()
                for record in sorted(
                    self.packages.values(), key=lambda record: record.canonical_name
                )
            ],
            "fixes": [],
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        """Serialize this audit snapshot to JSON."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_audit(
        cls,
        result: Mapping[Dependency, list[VulnerabilityResult]],
        *,
        manifest: str | None = None,
        advisory_snapshot: str | None = None,
        source: str | None = None,
    ) -> AuditResult:
        """Build a snapshot from the mapping produced by ``Auditor.audit``."""
        packages: dict[str, AuditedPackage] = {}
        for dependency, vulnerabilities in result.items():
            if dependency.is_skipped():
                skipped = cast(SkippedDependency, dependency)
                name = canonicalize_name(skipped.name)
                packages[name] = AuditedPackage(
                    name=name,
                    version=None,
                    status=AuditStatus.SKIPPED,
                    reason=skipped.skip_reason,
                )
                continue

            resolved = cast(ResolvedDependency, dependency)
            name = resolved.canonical_name
            version = str(resolved.version)
            packages[name] = AuditedPackage(
                name=name,
                version=version,
                status=AuditStatus.AUDITED,
                vulns=tuple(vulnerabilities),
                queried_version=version,
            )

        return cls(
            packages=packages,
            manifest=manifest,
            advisory_snapshot=advisory_snapshot,
            manifest_packages=frozenset(packages),
            source=source,
        )


@dataclass(frozen=True)
class AlertAttribution:
    """Attribution detail for one package/vulnerability pair."""

    package: str
    id: str
    aliases: tuple[str, ...]
    attribution: Attribution
    direction: Direction
    presence: Mapping[str, bool | None]
    versions: Mapping[str, str | None]
    fix_versions: tuple[str, ...]
    description: str | None
    reason: str | None = None
    missing_cells: tuple[str, ...] = ()
    unknown_cells: tuple[str, ...] = ()

    @property
    def attributed(self) -> bool:
        """Return whether this alert could be attributed to a known axis."""
        return self.attribution is not Attribution.UNKNOWN

    def to_dict(self) -> dict[str, Any]:
        """Serialize this attribution to JSON-compatible data."""
        return {
            "package": self.package,
            "id": self.id,
            "aliases": list(self.aliases),
            "attribution": self.attribution.value,
            "category": self.attribution.value,
            "direction": self.direction.value,
            "presence": dict(self.presence),
            "versions": dict(self.versions),
            "fix_versions": list(self.fix_versions),
            "description": self.description,
            "reason": self.reason,
            "missing_cells": list(self.missing_cells),
            "unknown_cells": list(self.unknown_cells),
        }


@dataclass(frozen=True)
class CellCoverage:
    """Coverage and query detail for one cell in the matrix."""

    cell: str
    status: str
    manifest: str | None
    advisory_snapshot: str | None
    expected: tuple[str, ...]
    queried: tuple[dict[str, Any], ...]
    unknown: tuple[dict[str, Any], ...]
    skipped: tuple[dict[str, Any], ...]
    missing: tuple[str, ...]
    source: str | None

    def to_dict(self) -> dict[str, Any]:
        """Serialize this coverage record to JSON-compatible data."""
        return {
            "cell": self.cell,
            "status": self.status,
            "manifest": self.manifest,
            "advisory_snapshot": self.advisory_snapshot,
            "source": self.source,
            "expected": list(self.expected),
            "expected_count": len(self.expected),
            "queried_count": len(self.queried),
            "audited_count": sum(
                1 for record in self.queried if record["status"] == "audited"
            ),
            "unknown_count": len(self.unknown),
            "skipped_count": len(self.skipped),
            "missing_count": len(self.missing),
            "queried": list(self.queried),
            "queried_versions": {
                record["name"]: record["queried_version"] for record in self.queried
            },
            "unknown": list(self.unknown),
            "unknown_packages": [record["name"] for record in self.unknown],
            "skipped": list(self.skipped),
            "missing": list(self.missing),
            "missing_packages": list(self.missing),
        }


@dataclass(frozen=True)
class AuditDiff:
    """A complete, reviewable differential audit report."""

    cells: Mapping[str, CellCoverage]
    alerts: tuple[AlertAttribution, ...]

    @property
    def unattributed(self) -> tuple[AlertAttribution, ...]:
        """Return alerts that could not be attributed."""
        return tuple(alert for alert in self.alerts if not alert.attributed)

    @property
    def missing_cells(self) -> tuple[str, ...]:
        """Return the cells for which no audit result was available."""
        return tuple(cell for cell in CELLS if self.cells[cell].status == "missing")

    @property
    def coverage(self) -> Mapping[str, CellCoverage]:
        """Return per-cell coverage information."""
        return self.cells

    @property
    def summary(self) -> dict[str, Any]:
        """Return aggregate counts for the report."""
        categories = Counter(alert.attribution.value for alert in self.alerts)
        directions = Counter(alert.direction.value for alert in self.alerts)
        missing_cells = [
            cell for cell in CELLS if self.cells[cell].status == "missing"
        ]
        unknown_packages = {
            cell: [record["name"] for record in coverage.unknown]
            for cell, coverage in self.cells.items()
            if coverage.unknown
        }
        return {
            "total_alerts": len(self.alerts),
            "attributed": len(self.alerts) - len(self.unattributed),
            "unattributed": len(self.unattributed),
            "dependency": categories.get(Attribution.DEPENDENCY.value, 0),
            "advisory": categories.get(Attribution.ADVISORY.value, 0),
            "both": categories.get(Attribution.BOTH.value, 0),
            "mixed": categories.get(Attribution.MIXED.value, 0),
            "unchanged": categories.get(Attribution.UNCHANGED.value, 0),
            "unknown": categories.get(Attribution.UNKNOWN.value, 0),
            "added": directions.get(Direction.ADDED.value, 0),
            "removed": directions.get(Direction.REMOVED.value, 0),
            "directions_unchanged": directions.get(Direction.UNCHANGED.value, 0),
            "missing_cells": missing_cells,
            "unknown_packages": unknown_packages,
            "by_category": {
                category.value: categories.get(category.value, 0) for category in Attribution
            },
            "by_direction": {
                direction.value: directions.get(direction.value, 0) for direction in Direction
            },
        }

    def to_dict(self) -> dict[str, Any]:
        """Serialize the report to JSON-compatible data."""
        cell_payloads = {cell: coverage.to_dict() for cell, coverage in self.cells.items()}
        return {
            "schema_version": 1,
            "reference": {"from": REFERENCE_FROM, "to": REFERENCE_TO},
            "axes": {
                "dependency": {"old": "old", "new": "new"},
                "advisory": {"old": "old", "new": "new"},
            },
            "summary": self.summary,
            "cells": cell_payloads,
            "coverage": cell_payloads,
            "alerts": [alert.to_dict() for alert in self.alerts],
            "changes": [
                alert.to_dict()
                for alert in self.alerts
                if alert.direction is not Direction.UNCHANGED
            ],
            "unattributed_alerts": [alert.to_dict() for alert in self.unattributed],
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        """Serialize the report to JSON."""
        return json.dumps(self.to_dict(), indent=indent)

    def to_text(self) -> str:
        """Render a compact human-readable report."""
        lines = [
            "pip-audit differential attribution report",
            f"Reference: {REFERENCE_FROM} -> {REFERENCE_TO}",
            "",
            "Coverage (expected packages, actual queried versions):",
        ]
        for cell in CELLS:
            coverage = self.cells[cell]
            lines.append(
                f"  {cell}: {coverage.status}; expected {len(coverage.expected)}; "
                f"queried {len(coverage.queried)}"
            )
            unknown_reasons = {
                record["name"]: record.get("reason") for record in coverage.unknown
            }
            for record in coverage.queried:
                version = record["queried_version"] or record["version"] or "?"
                suffix = "" if record["status"] == "audited" else f" ({record['status']})"
                if record["name"] in unknown_reasons:
                    suffix += f": {unknown_reasons[record['name']]}"
                lines.append(f"    - {record['name']}=={version}{suffix}")
            for name in coverage.missing:
                lines.append(f"    - {name}: no audit record (missing)")
        lines.extend(["", "Alerts:"])
        if not self.alerts:
            lines.append("  (none)")
        for alert in self.alerts:
            presence = " ".join(
                f"{cell}={_presence_text(alert.presence[cell])}" for cell in CELLS
            )
            lines.append(
                f"  [{alert.attribution.value}/{alert.direction.value}] "
                f"{alert.package} {alert.id}: {presence}"
            )
            if alert.reason:
                lines.append(f"    reason: {alert.reason}")
        lines.extend(["", "Unattributed alerts:"])
        if not self.unattributed:
            lines.append("  (none)")
        for alert in self.unattributed:
            lines.append(
                f"  {alert.package} {alert.id}: missing={list(alert.missing_cells)} "
                f"unknown={list(alert.unknown_cells)} reason={alert.reason}"
            )
        return "\n".join(lines)

    def to_markdown(self) -> str:
        """Render a Markdown report."""
        summary = self.summary
        lines = [
            "# pip-audit differential attribution",
            "",
            f"Reference: `{REFERENCE_FROM}` -> `{REFERENCE_TO}`",
            "",
            "## Summary",
            "",
            "| Category | Count |",
            "| --- | ---: |",
        ]
        for category in Attribution:
            lines.append(f"| {category.value} | {summary['by_category'][category.value]} |")
        lines.extend(
            [
                f"| unattributed | {summary['unattributed']} |",
                "",
                "## Coverage",
                "",
                "| Cell | Status | Expected | Queried | Unknown | Missing |",
                "| --- | --- | ---: | ---: | ---: | ---: |",
            ]
        )
        for cell in CELLS:
            coverage = self.cells[cell]
            lines.append(
                f"| {cell} | {coverage.status} | {len(coverage.expected)} | "
                f"{len(coverage.queried)} | {len(coverage.unknown)} | {len(coverage.missing)} |"
            )
        lines.extend(["", "### Queried versions", ""])
        for cell in CELLS:
            coverage = self.cells[cell]
            queried = ", ".join(
                f"`{record['name']}=={record['queried_version'] or record['version'] or '?'}`"
                + ("" if record["status"] == "audited" else f" ({record['status']})")
                for record in coverage.queried
            )
            lines.append(f"- `{cell}`: {queried or '_no queries_'}")
        lines.extend(
            [
                "",
                "## Alerts",
                "",
                "| Package | ID | Attribution | Direction | Presence |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for alert in self.alerts:
            presence = " ".join(
                f"{cell}={_presence_text(alert.presence[cell])}" for cell in CELLS
            )
            lines.append(
                f"| {alert.package} | {alert.id} | {alert.attribution.value} | "
                f"{alert.direction.value} | {presence} |"
            )
        lines.extend(["", "## Unattributed alerts", ""])
        if not self.unattributed:
            lines.append("_None._")
        for alert in self.unattributed:
            lines.append(
                f"- `{alert.package}` `{alert.id}`: missing={list(alert.missing_cells)}, "
                f"unknown={list(alert.unknown_cells)}; {alert.reason}"
            )
        return "\n".join(lines)


SnapshotLike: TypeAlias = AuditResult | Mapping[str, Any] | Sequence[Any] | str | Path | None


def _vuln_to_dict(vuln: VulnerabilityResult) -> dict[str, Any]:
    return {
        "id": vuln.id,
        "aliases": sorted(str(alias) for alias in vuln.aliases),
        "fix_versions": [str(version) for version in vuln.fix_versions],
        "description": vuln.description,
    }


def _vuln_from_dict(raw: Mapping[str, Any]) -> VulnerabilityResult:
    vuln_id = raw.get("id")
    if not isinstance(vuln_id, str) or not vuln_id:
        raise DiffError("saved audit result contains a vulnerability without an id")

    raw_aliases = raw.get("aliases") or []
    if not isinstance(raw_aliases, Sequence) or isinstance(raw_aliases, str):
        raise DiffError(f"vulnerability {vuln_id} has an invalid alias list")

    raw_fix_versions = raw.get("fix_versions") or []
    if not isinstance(raw_fix_versions, Sequence) or isinstance(raw_fix_versions, str):
        raise DiffError(f"vulnerability {vuln_id} has an invalid fix version list")

    fix_versions: list[Version] = []
    for raw_version in raw_fix_versions:
        try:
            fix_versions.append(Version(str(raw_version)))
        except InvalidVersion as exc:
            raise DiffError(
                f"vulnerability {vuln_id} has an invalid fix version: {raw_version!r}"
            ) from exc

    description = raw.get("description")
    return VulnerabilityResult.create(
        ids=cast(list[VulnerabilityID], [vuln_id, *(str(alias) for alias in raw_aliases)]),
        description=str(description) if description is not None else "N/A",
        fix_versions=fix_versions,
        published=None,
    )


def _status_from_dict(raw: Mapping[str, Any]) -> AuditStatus:
    explicit = raw.get("status")
    if explicit is not None:
        if str(explicit).lower() in {"unjudged", "not-judged", "not_judged"}:
            return AuditStatus.UNKNOWN
        try:
            return AuditStatus(str(explicit).lower())
        except ValueError as exc:
            raise DiffError(f"invalid audit status: {explicit!r}") from exc
    if raw.get("skip_reason") is not None:
        return AuditStatus.SKIPPED
    return AuditStatus.AUDITED


def audit_result_from_dict(
    data: Mapping[str, Any] | Sequence[Any], *, source: str | None = None
) -> AuditResult:
    """Load an audit snapshot from saved JSON data.

    Both the default ``pip-audit -f json`` shape (``dependencies`` plus
    ``fixes``) and the richer diff snapshot shape are accepted.
    """
    if isinstance(data, Sequence) and not isinstance(data, (str, bytes, Mapping)):
        data = {"dependencies": data}
    if not isinstance(data, Mapping):
        raise DiffError("saved audit result must be a JSON object or a dependency list")

    raw_dependencies = data.get("dependencies")
    if raw_dependencies is None:
        raise DiffError("saved audit result is missing the 'dependencies' list")

    if isinstance(raw_dependencies, Mapping):
        raw_dependencies = [
            {"name": name, **cast(Mapping[str, Any], value)}
            for name, value in raw_dependencies.items()
        ]
    if not isinstance(raw_dependencies, Sequence) or isinstance(raw_dependencies, str):
        raise DiffError("saved audit result has an invalid 'dependencies' section")

    packages: dict[str, AuditedPackage] = {}
    for raw_dependency in raw_dependencies:
        if not isinstance(raw_dependency, Mapping):
            raise DiffError(f"invalid dependency entry: {raw_dependency!r}")
        raw_name = raw_dependency.get("name")
        if not isinstance(raw_name, str) or not raw_name:
            raise DiffError("saved audit result contains a dependency without a name")
        name = canonicalize_name(raw_name)
        if name in packages:
            raise DiffError(f"saved audit result contains duplicate package: {name}")

        raw_version = raw_dependency.get("version")
        version = str(raw_version) if raw_version is not None else None
        status = _status_from_dict(raw_dependency)
        reason = raw_dependency.get("reason", raw_dependency.get("skip_reason"))
        reason = str(reason) if reason is not None else None
        queried_version = raw_dependency.get("queried_version")
        if queried_version is None:
            queried_version = version
        queried_version = str(queried_version) if queried_version is not None else None

        raw_vulns = raw_dependency.get("vulns") or []
        if not isinstance(raw_vulns, Sequence) or isinstance(raw_vulns, str):
            raise DiffError(f"dependency {name} has an invalid vulnerability list")
        vulns: list[VulnerabilityResult] = []
        for raw_vuln in raw_vulns:
            if not isinstance(raw_vuln, Mapping):
                raise DiffError(f"dependency {name} has an invalid vulnerability entry")
            vulns.append(_vuln_from_dict(raw_vuln))

        packages[name] = AuditedPackage(
            name=name,
            version=version,
            status=status,
            vulns=tuple(vulns),
            reason=reason,
            queried_version=queried_version,
        )

    audit_metadata = data.get("audit", {})
    if not isinstance(audit_metadata, Mapping):
        audit_metadata = {}

    coverage = data.get("coverage", {})
    manifest_packages: frozenset[str] | None = None
    if isinstance(coverage, Mapping):
        expected = coverage.get("expected")
        if isinstance(expected, Sequence) and not isinstance(expected, str):
            manifest_packages = frozenset(canonicalize_name(str(name)) for name in expected)

    manifest = data.get("manifest", audit_metadata.get("manifest"))
    advisory_snapshot = data.get(
        "advisory_snapshot", audit_metadata.get("advisory_snapshot")
    )
    return AuditResult(
        packages=packages,
        manifest=str(manifest) if manifest is not None else None,
        advisory_snapshot=str(advisory_snapshot) if advisory_snapshot is not None else None,
        manifest_packages=manifest_packages,
        source=source,
    )


def load_audit_result(path: Path | str) -> AuditResult:
    """Load one saved audit result from a JSON file."""
    result_path = Path(path)
    try:
        data = json.loads(result_path.read_text())
    except OSError as exc:
        raise DiffError(f"could not read audit result {result_path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise DiffError(f"invalid JSON in audit result {result_path}: {exc}") from exc
    if not isinstance(data, (Mapping, list)):
        raise DiffError(f"audit result {result_path} must contain a JSON object")
    return audit_result_from_dict(data, source=str(result_path))


def _coerce_snapshot(value: SnapshotLike, *, cell: str) -> AuditResult | None:
    if value is None:
        return None
    if isinstance(value, AuditResult):
        return value
    if isinstance(value, Mapping):
        return audit_result_from_dict(value, source=f"<{cell}>")
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return audit_result_from_dict(value, source=f"<{cell}>")
    if isinstance(value, (str, Path)):
        return load_audit_result(value)
    raise DiffError(f"unsupported audit result for cell {cell}: {type(value).__name__}")


def _id_sort_key(identifier: str) -> tuple[int, str]:
    if identifier.startswith("PYSEC"):
        return (1, identifier)
    if identifier.startswith("CVE"):
        return (2, identifier)
    return (3, identifier)


class _DisjointSet:
    def __init__(self) -> None:
        self._parent: dict[str, str] = {}

    def add(self, item: str) -> None:
        self._parent.setdefault(item, item)

    def find(self, item: str) -> str:
        self.add(item)
        parent = self._parent[item]
        if parent != item:
            self._parent[item] = self.find(parent)
        return self._parent[item]

    def union(self, left: str, right: str) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root != right_root:
            self._parent[right_root] = left_root


@dataclass
class _AlertGroup:
    package: str
    root: str = ""
    ids: set[str] = field(default_factory=set)
    results: list[tuple[str, VulnerabilityResult]] = field(default_factory=list)
    roots_by_cell: dict[str, set[str]] = field(default_factory=dict)


def _collect_alert_groups(
    cells: Mapping[str, AuditResult | None],
) -> dict[tuple[str, str], _AlertGroup]:
    """Group vulnerability IDs into per-package alert families across all cells."""
    ids_by_package: dict[str, _DisjointSet] = defaultdict(_DisjointSet)
    vulns_by_package: dict[str, list[tuple[str, VulnerabilityResult]]] = defaultdict(list)

    # First pass: union all IDs and aliases for each package.  Do the unions
    # before assigning cell roots, otherwise an early alias could leave a stale
    # root in ``roots_by_cell`` after a later union.
    for cell, snapshot in cells.items():
        if snapshot is None:
            continue
        for package, record in snapshot.packages.items():
            if record.status is not AuditStatus.AUDITED:
                continue
            for vuln in record.vulns:
                ids = {str(vuln.id), *(str(alias) for alias in vuln.aliases)}
                disjoint = ids_by_package[package]
                identifiers = sorted(ids)
                disjoint.add(identifiers[0])
                for identifier in identifiers[1:]:
                    disjoint.union(identifiers[0], identifier)
                vulns_by_package[package].append((cell, vuln))

    groups: dict[tuple[str, str], _AlertGroup] = {}
    for package, entries in vulns_by_package.items():
        disjoint = ids_by_package[package]
        groups_by_root: dict[str, _AlertGroup] = {}
        for cell, vuln in entries:
            root = disjoint.find(str(vuln.id))
            group = groups_by_root.setdefault(root, _AlertGroup(package=package))
            group.ids.update({str(vuln.id), *(str(alias) for alias in vuln.aliases)})
            group.results.append((cell, vuln))
            group.roots_by_cell.setdefault(cell, set()).add(root)
        for root, group in groups_by_root.items():
            primary = min(group.ids, key=_id_sort_key)
            group.root = root
            groups[(package, primary)] = group
    return groups


def _cell_presence(
    snapshot: AuditResult | None, package: str, group: _AlertGroup, cell: str
) -> bool | None:
    if snapshot is None:
        return None
    record = snapshot.package(package)
    if record is None:
        return None if package in snapshot.expected_packages() else False
    if record.status is not AuditStatus.AUDITED:
        return None
    return group.root in group.roots_by_cell.get(cell, set())


def _classify(
    presence: Mapping[str, bool | None], cells: Mapping[str, AuditResult | None]
) -> tuple[Attribution, Direction, tuple[str, ...], tuple[str, ...], str | None]:
    missing = tuple(cell for cell in CELLS if cells[cell] is None)
    unknown = tuple(
        cell
        for cell in CELLS
        if cells[cell] is not None and presence.get(cell) is None
    )
    if missing or unknown:
        parts: list[str] = []
        if missing:
            parts.append(f"missing cell(s): {', '.join(missing)}")
        if unknown:
            parts.append(f"no judgment for the package in: {', '.join(unknown)}")
        return (
            Attribution.UNKNOWN,
            Direction.UNKNOWN,
            missing,
            unknown,
            "; ".join(parts),
        )

    values = {cell: cast(bool, presence[cell]) for cell in CELLS}
    old_old = values["old-old"]
    old_new = values["old-new"]
    new_old = values["new-old"]
    new_new = values["new-new"]

    if old_old == new_new:
        direction = Direction.UNCHANGED
    elif new_new:
        direction = Direction.ADDED
    else:
        direction = Direction.REMOVED

    if old_old == old_new == new_old == new_new:
        reason = "present in every cell" if old_old else "absent from every cell"
        return Attribution.UNCHANGED, Direction.UNCHANGED, (), (), reason
    if old_old == old_new and new_old == new_new:
        reason = "tracked the dependency change; the advisory change made no difference"
        return Attribution.DEPENDENCY, direction, (), (), reason
    if old_old == new_old and old_new == new_new:
        reason = "tracked the advisory change; the dependency change made no difference"
        return Attribution.ADVISORY, direction, (), (), reason
    # Both single-axis changes must leave the old result untouched; only the
    # combined change may flip it.  Patterns where either change alone flips
    # the result (e.g. only-old or XOR) are reported as mixed.
    both_requires_both = old_new == old_old == new_old and new_new != old_old
    if both_requires_both:
        change = "appear" if direction is Direction.ADDED else "disappear"
        reason = (
            "both the dependency and the advisory had to change before this alert "
            f"could {change}"
        )
        return Attribution.BOTH, direction, (), (), reason

    reason = (
        "presence pattern is not explained by one axis alone; inspect all four cells "
        f"({old_old=}, {old_new=}, {new_old=}, {new_new=})"
    )
    return Attribution.MIXED, direction, (), (), reason


def _build_alert(
    group: _AlertGroup,
    cells: Mapping[str, AuditResult | None],
) -> AlertAttribution:
    package = group.package
    primary = min(group.ids, key=_id_sort_key)
    presence: dict[str, bool | None] = {
        cell: _cell_presence(cells[cell], package, group, cell) for cell in CELLS
    }
    attribution, direction, missing, unknown, reason = _classify(presence, cells)

    versions: dict[str, str | None] = {}
    for cell in CELLS:
        snapshot = cells[cell]
        record = snapshot.package(package) if snapshot is not None else None
        versions[cell] = record.version if record is not None else None

    fix_versions: set[str] = set()
    description: str | None = None
    for cell in ("new-new", "new-old", "old-new", "old-old"):
        for result_cell, vuln in group.results:
            if result_cell != cell:
                continue
            fix_versions.update(str(version) for version in vuln.fix_versions)
            if description is None and vuln.description and vuln.description != "N/A":
                description = vuln.description
    if description is None:
        description = next(
            (vuln.description for _, vuln in group.results if vuln.description), None
        )

    aliases = tuple(sorted(identifier for identifier in group.ids if identifier != primary))
    return AlertAttribution(
        package=package,
        id=primary,
        aliases=aliases,
        attribution=attribution,
        direction=direction,
        presence=presence,
        versions=versions,
        fix_versions=tuple(sorted(fix_versions, key=lambda value: Version(value))),
        description=description,
        reason=reason,
        missing_cells=missing,
        unknown_cells=unknown,
    )


def _cell_coverage(cell: str, snapshot: AuditResult | None) -> CellCoverage:
    if snapshot is None:
        return CellCoverage(
            cell=cell,
            status="missing",
            manifest=None,
            advisory_snapshot=None,
            expected=(),
            queried=(),
            unknown=(),
            skipped=(),
            missing=(),
            source=None,
        )

    coverage = snapshot.coverage()
    unknown = tuple(cast(list[dict[str, Any]], coverage["unknown"]))
    skipped = tuple(cast(list[dict[str, Any]], coverage["skipped"]))
    missing = tuple(cast(list[str], coverage["missing"]))
    status = "incomplete" if unknown or skipped or missing else "complete"
    return CellCoverage(
        cell=cell,
        status=status,
        manifest=snapshot.manifest,
        advisory_snapshot=snapshot.advisory_snapshot,
        expected=tuple(cast(list[str], coverage["expected"])),
        queried=tuple(cast(list[dict[str, Any]], coverage["queried"])),
        unknown=unknown,
        skipped=skipped,
        missing=missing,
        source=snapshot.source,
    )


def diff_audits(
    old_old: SnapshotLike = None,
    old_new: SnapshotLike = None,
    new_old: SnapshotLike = None,
    new_new: SnapshotLike = None,
    *,
    cells: Mapping[str, SnapshotLike] | None = None,
) -> AuditDiff:
    """Compare four saved audit results.

    Positional order is ``old-old``, ``old-new``, ``new-old``, ``new-new``.
    Callers can also pass the mapping form with ``cells={"old-old": ...}``.
    ``None`` for a cell (or a missing file path in the CLI) is a missing cell,
    not an empty audit.
    """
    if (
        cells is None
        and isinstance(old_old, Mapping)
        and "dependencies" not in old_old
        and any(str(key) in CELLS or str(key) in CANONICAL_CELLS for key in old_old)
        and all(value is None for value in (old_new, new_old, new_new))
    ):
        cells = cast(Mapping[str, SnapshotLike], old_old)
        old_old = None

    if cells is not None:
        if any(value is not None for value in (old_old, old_new, new_old, new_new)):
            raise DiffError("pass either four audit results or a cells mapping, not both")
        unknown_keys = set(cells) - set(CELLS)
        if unknown_keys:
            raise DiffError(f"unknown cell(s): {', '.join(sorted(unknown_keys))}")
        raw_cells = {cell: cells.get(cell) for cell in CELLS}
    else:
        raw_cells = {
            "old-old": old_old,
            "old-new": old_new,
            "new-old": new_old,
            "new-new": new_new,
        }

    snapshots = {
        cell: _coerce_snapshot(raw_cells[cell], cell=cell) for cell in CELLS
    }

    groups = _collect_alert_groups(snapshots)
    alerts = [_build_alert(group, snapshots) for group in groups.values()]
    alerts.sort(key=lambda alert: (alert.package, _id_sort_key(alert.id), alert.id))

    coverage = {cell: _cell_coverage(cell, snapshots[cell]) for cell in CELLS}
    return AuditDiff(cells=coverage, alerts=tuple(alerts))


# Explicit aliases for callers that prefer different phrasing.
compute_diff = diff_audits
diff = diff_audits
AttributionReport: TypeAlias = AuditDiff
DiffReport: TypeAlias = AuditDiff
SavedAudit: TypeAlias = AuditResult


def load_audit_results(
    results: Mapping[str, Path | str | None],
) -> dict[str, AuditResult | None]:
    """Load a cell-to-path mapping, preserving omitted or missing cells as ``None``."""
    cells: dict[str, AuditResult | None] = {cell: None for cell in CELLS}
    for raw_cell, path in results.items():
        cell = CANONICAL_CELLS.get(str(raw_cell).strip().lower())
        if cell is None:
            raise DiffError(f"unknown cell {raw_cell!r}; expected one of {', '.join(CELLS)}")
        if path is None:
            continue
        result_path = Path(path)
        if not result_path.exists():
            logger.warning(f"audit result for {cell} is missing: {result_path}")
            continue
        cells[cell] = load_audit_result(result_path)
    return cells


def diff_saved_audits(
    results: Mapping[str, Path | str | None],
) -> AuditDiff:
    """Recompute a differential report directly from saved audit result paths."""
    return diff_audits(cells=load_audit_results(results))


def diff_audit_results(results: Sequence[SnapshotLike]) -> AuditDiff:
    """Compare four audit results supplied in cell order.

    Order is ``old-old``, ``old-new``, ``new-old``, ``new-new``.  Use ``None``
    for a cell that is unavailable.
    """
    if len(results) != 4:
        raise DiffError("expected exactly four audit results")
    return diff_audits(*results)


def audit_results_from_bundle(
    data: Mapping[str, Any] | Sequence[Any],
) -> dict[str, AuditResult | None]:
    """Load a bundle of up to four saved audit results from one JSON object."""
    if isinstance(data, Sequence) and not isinstance(data, (str, bytes, Mapping)):
        if len(data) != 4:
            raise DiffError("audit result bundle list must contain exactly four cells")
        return {
            cell: _coerce_snapshot(value, cell=cell)
            for cell, value in zip(CELLS, data, strict=True)
        }
    if not isinstance(data, Mapping):
        raise DiffError("audit result bundle must be a JSON object")
    raw_cells = data.get("cells", data)
    if not isinstance(raw_cells, Mapping):
        raise DiffError("audit result bundle must contain a 'cells' object")

    cells: dict[str, AuditResult | None] = {cell: None for cell in CELLS}
    for raw_cell, value in raw_cells.items():
        if not isinstance(raw_cell, str):
            continue
        cell = CANONICAL_CELLS.get(raw_cell.strip().lower())
        if cell is None:
            raise DiffError(
                f"unknown cell {raw_cell!r} in result bundle; expected one of {', '.join(CELLS)}"
            )
        if value is None:
            continue
        if isinstance(value, Mapping):
            cells[cell] = audit_result_from_dict(value, source=f"<bundle:{cell}>")
        elif isinstance(value, Sequence) and not isinstance(value, str):
            cells[cell] = audit_result_from_dict(value, source=f"<bundle:{cell}>")
        elif isinstance(value, (str, Path)):
            cells[cell] = load_audit_result(value)
        else:
            raise DiffError(f"invalid audit result for cell {cell} in bundle")
    return cells


def _presence_text(value: bool | None) -> str:
    if value is None:
        return "?"
    return "yes" if value else "no"


def audit_dependencies(
    service: FreezeService,
    dependencies: Iterable[Dependency],
    *,
    manifest: str | None = None,
    advisory_snapshot: str | None = None,
    source: str | None = None,
) -> AuditResult:
    """Audit pre-resolved dependencies against a freeze service, preserving unknowns."""
    packages: dict[str, AuditedPackage] = {}
    for dependency in dependencies:
        if dependency.is_skipped():
            skipped = cast(SkippedDependency, dependency)
            name = canonicalize_name(skipped.name)
            packages[name] = AuditedPackage(
                name=name,
                version=None,
                status=AuditStatus.SKIPPED,
                reason=skipped.skip_reason,
            )
            continue

        resolved = cast(ResolvedDependency, dependency)
        name = resolved.canonical_name
        query = service.query_with_status(resolved)
        version = str(resolved.version)
        packages[name] = AuditedPackage(
            name=name,
            version=version,
            status=(
                AuditStatus.AUDITED if query.status == "audited" else AuditStatus.UNKNOWN
            ),
            vulns=query.vulnerabilities if query.status == "audited" else (),
            reason=query.reason,
            queried_version=version,
        )

    return AuditResult(
        packages=packages,
        manifest=manifest,
        advisory_snapshot=advisory_snapshot or service.snapshot_name,
        manifest_packages=frozenset(packages),
        source=source,
    )


def _collect_requirements(path: Path) -> list[Dependency]:
    source = RequirementSource([path], no_deps=True, disable_pip=True)
    try:
        return list(source.collect())
    except DependencySourceError as exc:
        raise DiffError(str(exc)) from exc


def _diff_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pip-audit diff",
        description=(
            "compare old/new dependency manifests against old/new offline advisory "
            "snapshots, or recompute from four saved audit results"
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--old-old",
        type=Path,
        metavar="FILE",
        help="saved audit result for old dependency + old advisory snapshot",
    )
    parser.add_argument(
        "--old-new",
        type=Path,
        metavar="FILE",
        help="saved audit result for old dependency + new advisory snapshot",
    )
    parser.add_argument(
        "--new-old",
        type=Path,
        metavar="FILE",
        help="saved audit result for new dependency + old advisory snapshot",
    )
    parser.add_argument(
        "--new-new",
        type=Path,
        metavar="FILE",
        help="saved audit result for new dependency + new advisory snapshot",
    )
    parser.add_argument(
        "--result",
        action="append",
        default=[],
        metavar="CELL=FILE",
        help=(
            "saved audit result for a named cell "
            "(old-old, old-new, new-old, new-new, 00, 01, 10, 11)"
        ),
    )
    parser.add_argument(
        "--results",
        type=Path,
        metavar="FILE",
        help="one JSON bundle containing up to four saved audit results, keyed by cell",
    )
    parser.add_argument(
        "--results-dir",
        type=Path,
        metavar="DIR",
        help="directory containing saved results named old-old.json, old-new.json, etc.",
    )
    parser.add_argument(
        "result_files",
        nargs="*",
        type=Path,
        metavar="FILE",
        help=(
            "four saved results in cell order (old-old, old-new, new-old, new-new) "
            "when no other result flags are used"
        ),
    )
    parser.add_argument(
        "--old-requirements",
        "--old-manifest",
        "--old-req",
        "--old",
        dest="old_requirements",
        type=Path,
        metavar="FILE",
        help="old pinned requirements manifest",
    )
    parser.add_argument(
        "--new-requirements",
        "--new-manifest",
        "--new-req",
        "--new",
        dest="new_requirements",
        type=Path,
        metavar="FILE",
        help="new pinned requirements manifest",
    )
    parser.add_argument(
        "--old-advisories",
        "--old-advisory",
        "--old-advisory-file",
        "--advisories-old",
        type=Path,
        metavar="FILE",
        help="old offline advisory snapshot fixture",
    )
    parser.add_argument(
        "--new-advisories",
        "--new-advisory",
        "--new-advisory-file",
        "--advisories-new",
        type=Path,
        metavar="FILE",
        help="new offline advisory snapshot fixture",
    )
    parser.add_argument(
        "--write-results-dir",
        type=Path,
        metavar="DIR",
        help="write the four computed audit results to this directory for later replay",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=("json", "text", "markdown", "columns"),
        default="json",
        help="report format",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("stdout"),
        metavar="FILE",
        help="write the report to this file instead of stdout",
    )
    parser.add_argument(
        "--fail-on-unattributed",
        action="store_true",
        help="exit with status 2 if any alert could not be attributed",
    )
    parser.add_argument("-v", "--verbose", action="count", default=0)
    return parser


def _result_paths(args: argparse.Namespace, parser: argparse.ArgumentParser) -> dict[str, Path]:
    paths: dict[str, Path] = {}
    positional = cast(list[Path], args.result_files)
    if positional:
        if len(positional) != 4:
            parser.error(
                "positional result files must be exactly four: "
                "old-old, old-new, new-old, new-new"
            )
        paths.update(zip(CELLS, positional, strict=True))

    for cell in CELLS:
        value = getattr(args, cell.replace("-", "_"))
        if value is not None:
            if cell in paths:
                parser.error(f"cell {cell} was supplied more than once")
            paths[cell] = value

    for assignment in cast(list[str], args.result):
        if "=" not in assignment:
            parser.error(f"--result expects CELL=FILE, got {assignment!r}")
        raw_cell, raw_path = assignment.split("=", 1)
        cell = CANONICAL_CELLS.get(raw_cell.strip().lower())
        if cell is None:
            parser.error(f"unknown cell {raw_cell!r}; expected one of {', '.join(CELLS)}")
        if cell in paths:
            parser.error(f"cell {cell} was supplied more than once")
        paths[cell] = Path(raw_path)
    return paths


def _load_saved_cells(paths: Mapping[str, Path]) -> dict[str, AuditResult | None]:
    return load_audit_results(paths)


def _load_result_bundle(path: Path) -> dict[str, AuditResult | None]:
    try:
        data = json.loads(path.read_text())
    except OSError as exc:
        raise DiffError(f"could not read audit result bundle {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise DiffError(f"invalid JSON in audit result bundle {path}: {exc}") from exc
    if not isinstance(data, (Mapping, list)):
        raise DiffError(f"audit result bundle {path} must contain a JSON object or list")
    return audit_results_from_bundle(cast(Mapping[str, Any] | Sequence[Any], data))


def _load_results_dir(path: Path) -> dict[str, AuditResult | None]:
    if not path.is_dir():
        raise DiffError(f"audit result directory not found: {path}")
    paths: dict[str, Path] = {}
    for cell in CELLS:
        for name in (f"{cell}.json", f"{cell.replace('-', '_')}.json"):
            candidate = path / name
            if candidate.exists():
                paths[cell] = candidate
                break
    return load_audit_results(paths)


def _compute_freeze_cells(
    args: argparse.Namespace, parser: argparse.ArgumentParser
) -> dict[str, AuditResult]:
    required = {
        "--old-requirements": args.old_requirements,
        "--new-requirements": args.new_requirements,
        "--old-advisories": args.old_advisories,
        "--new-advisories": args.new_advisories,
    }
    missing = [name for name, value in required.items() if value is None]
    if missing:
        parser.error(f"freeze mode requires: {', '.join(missing)}")

    old_requirements = cast(Path, args.old_requirements)
    new_requirements = cast(Path, args.new_requirements)
    old_advisories = cast(Path, args.old_advisories)
    new_advisories = cast(Path, args.new_advisories)

    missing_files = [
        str(path)
        for path in (old_requirements, new_requirements, old_advisories, new_advisories)
        if not path.exists()
    ]
    if missing_files:
        parser.error(f"input file(s) not found: {', '.join(missing_files)}")

    try:
        old_dependencies = _collect_requirements(old_requirements)
        new_dependencies = _collect_requirements(new_requirements)
        old_service = FreezeService(old_advisories)
        new_service = FreezeService(new_advisories)
    except (DiffError, FreezeFixtureError, ValueError) as exc:
        parser.error(str(exc))

    results = {
        "old-old": audit_dependencies(
            old_service,
            old_dependencies,
            manifest=str(old_requirements),
            source=str(old_requirements),
        ),
        "old-new": audit_dependencies(
            new_service,
            old_dependencies,
            manifest=str(old_requirements),
            source=str(old_requirements),
        ),
        "new-old": audit_dependencies(
            old_service,
            new_dependencies,
            manifest=str(new_requirements),
            source=str(new_requirements),
        ),
        "new-new": audit_dependencies(
            new_service,
            new_dependencies,
            manifest=str(new_requirements),
            source=str(new_requirements),
        ),
    }

    if args.write_results_dir is not None:
        output_dir = cast(Path, args.write_results_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        for cell, result in results.items():
            (output_dir / f"{cell}.json").write_text(result.to_json() + "\n")

    return results


def _write_report(report: AuditDiff, *, format_: str, output: Path) -> None:
    if format_ == "json":
        rendered = report.to_json()
    elif format_ in {"text", "columns"}:
        rendered = report.to_text()
    elif format_ == "markdown":
        rendered = report.to_markdown()
    else:  # pragma: no cover - argparse enforces the choices
        raise DiffError(f"unknown report format: {format_}")

    if str(output) in {"stdout", "-"}:
        print(rendered)
    else:
        output.write_text(rendered + "\n")


def diff_main(argv: Sequence[str] | None = None) -> None:
    """Run the ``pip-audit diff`` command."""
    parser = _diff_parser()
    args = parser.parse_args(argv)
    if args.verbose >= 1:
        logging.getLogger("pip_audit").setLevel("DEBUG")

    paths = _result_paths(args, parser)
    freeze_requested = any(
        value is not None
        for value in (
            args.old_requirements,
            args.new_requirements,
            args.old_advisories,
            args.new_advisories,
        )
    )

    saved_inputs = bool(paths) + (args.results is not None) + (args.results_dir is not None)
    if saved_inputs > 1:
        parser.error(
            "use only one of --old-old/--old-new/--new-old/--new-new, --result, "
            "--results, or --results-dir"
        )

    if saved_inputs and freeze_requested:
        parser.error("use either saved audit results or freeze fixtures, not both")
    if args.results is not None:
        try:
            cells = _load_result_bundle(cast(Path, args.results))
        except DiffError as exc:
            parser.error(str(exc))
    elif args.results_dir is not None:
        try:
            cells = _load_results_dir(cast(Path, args.results_dir))
        except DiffError as exc:
            parser.error(str(exc))
    elif paths:
        try:
            cells = _load_saved_cells(paths)
        except DiffError as exc:
            parser.error(str(exc))
    elif freeze_requested:
        cells = _compute_freeze_cells(args, parser)
    else:
        parser.error(
            "provide four saved results (--old-old/--old-new/--new-old/--new-new) "
            "or freeze inputs (--old-requirements/--new-requirements/"
            "--old-advisories/--new-advisories)"
        )

    try:
        report = diff_audits(cells=cells)
    except DiffError as exc:
        parser.error(str(exc))

    _write_report(report, format_=args.format, output=args.output)
    if args.fail_on_unattributed and report.unattributed:
        raise SystemExit(2)


if __name__ == "__main__":  # pragma: no cover
    diff_main()


__all__ = [
    "AuditDiff",
    "AuditResult",
    "AuditStatus",
    "Attribution",
    "AttributionReport",
    "AlertAttribution",
    "CELLS",
    "CellCoverage",
    "DiffError",
    "DiffReport",
    "Direction",
    "SavedAudit",
    "audit_dependencies",
    "audit_result_from_dict",
    "audit_results_from_bundle",
    "compute_diff",
    "diff",
    "diff_audits",
    "diff_audit_results",
    "diff_main",
    "diff_saved_audits",
    "load_audit_result",
    "load_audit_results",
]
