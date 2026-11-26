"""
Offline remediation allocation drills.

This module joins an existing pip-audit JSON result with one or more PEP 751
lockfiles and a local allocation table.  The drill assigns atomic change
combinations to responsible groups while enforcing capacity, scope, cross
environment and shared image version constraints.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import tomli
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version


class AllocationDrillError(Exception):
    """Raised when an offline allocation drill cannot be loaded or executed."""


@dataclass(frozen=True)
class Vulnerability:
    """A vulnerability entry from a pip-audit JSON result."""

    id: str
    aliases: tuple[str, ...] = ()
    fix_versions: tuple[str, ...] = ()


@dataclass(frozen=True)
class AuditedPackage:
    """A dependency entry from a pip-audit JSON result."""

    name: str
    version: str | None
    vulnerabilities: tuple[Vulnerability, ...] = ()
    skip_reason: str | None = None


@dataclass(frozen=True)
class AuditResult:
    """The subset of a pip-audit JSON document needed for allocation."""

    packages: tuple[AuditedPackage, ...]


@dataclass(frozen=True)
class LockEnvironment:
    """A pylock file treated as one deployable environment."""

    name: str
    path: Path
    packages: dict[str, Version]


@dataclass(frozen=True)
class Alert:
    """A vulnerability and the lockfile environments where it is present."""

    vulnerability_id: str
    package: str
    installed_version: str
    environments: tuple[str, ...]
    aliases: tuple[str, ...] = ()
    fix_versions: tuple[str, ...] = ()

    @property
    def key(self) -> str:
        """Stable alert key."""
        return f"{self.vulnerability_id}@{self.package}"

    @property
    def instance_keys(self) -> tuple[str, ...]:
        """Stable keys for each alert/environment occurrence."""
        return tuple(f"{self.key}@{environment}" for environment in self.environments)


@dataclass(frozen=True)
class Scope:
    """A package version line owned by a group."""

    package: str | None
    lines: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class Group:
    """A maintenance group and its allocation constraints."""

    name: str
    capacity: int
    owner: str | None = None
    cross_environment: bool = False
    scopes: tuple[Scope, ...] = ()
    environments: frozenset[str] | None = None


@dataclass(frozen=True)
class Change:
    """One package change inside an atomic combination."""

    package: str
    to_version: str | None = None
    line: str | None = None
    from_version: str | None = None
    environments: frozenset[str] | None = None


@dataclass(frozen=True)
class ImageDecision:
    """A selected version/tag for a shared image."""

    image: str
    version: str


@dataclass(frozen=True)
class Combination:
    """A candidate change combination."""

    id: str
    title: str = ""
    finding_refs: tuple[str, ...] = ()
    environments: frozenset[str] | None = None
    changes: tuple[Change, ...] = ()
    image_decisions: tuple[ImageDecision, ...] = ()
    slot_cost: int = 1
    priority: int = 0
    cross_environment: bool | None = None


@dataclass(frozen=True)
class SharedImage:
    """A shared image whose environments must make one version decision."""

    name: str
    environments: frozenset[str]
    packages: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class PlanTable:
    """Parsed local allocation table."""

    groups: tuple[Group, ...]
    combinations: tuple[Combination, ...]
    shared_images: tuple[SharedImage, ...] = ()
    version: int = 1


@dataclass
class Conflict:
    """An unallocated condition or invalid planning input."""

    code: str
    message: str
    combination_id: str | None = None
    group: str | None = None
    severity: str = "error"
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ResolvedChange:
    """A change after line and environment defaults are resolved."""

    package: str
    environments: frozenset[str]
    line: str | None = None
    to_version: str | None = None
    from_version: str | None = None


@dataclass
class PreparedCombination:
    """A combination joined to audit alerts and lockfile environments."""

    raw: Combination
    finding_ids: frozenset[str]
    environments: frozenset[str]
    cross_environment: bool
    changes: tuple[ResolvedChange, ...]
    covered_instances: frozenset[str]
    valid: bool = True
    issues: tuple[Conflict, ...] = ()


@dataclass(frozen=True)
class Assignment:
    """A selected combination assigned to one group."""

    combination_id: str
    group: str
    slot_cost: int
    covered_instances: tuple[str, ...]


@dataclass(frozen=True)
class GroupLoad:
    """Used and remaining slots for one group."""

    group: str
    owner: str | None
    capacity: int
    used: int
    remaining: int
    combination_ids: tuple[str, ...]


@dataclass
class GreedyClaim:
    """One per-alert slot grab in the explanatory naive simulation."""

    alert_key: str
    vulnerability_id: str
    package: str
    environments: tuple[str, ...]
    group: str | None
    status: str
    reason: str | None = None


@dataclass
class GreedyResult:
    """The predictable failure mode of alert-by-alert scheduling."""

    claims: tuple[GreedyClaim, ...]
    conflicts: tuple[Conflict, ...]
    claimed_alerts: tuple[str, ...]


@dataclass
class DrillResult:
    """Serializable offline allocation drill report."""

    status: str
    audit_result: str
    plan_table: str
    environments: list[dict[str, Any]]
    alerts: list[Alert]
    groups: list[Group]
    shared_images: list[SharedImage]
    combinations: list[PreparedCombination]
    assignments: list[Assignment]
    group_loads: list[GroupLoad]
    conflicts: list[Conflict]
    greedy: GreedyResult
    summary: dict[str, Any]


def _first_key(data: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in data:
            return data[key]
    return None


def _as_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(str(item) for item in value)


def _as_frozenset(value: Any) -> frozenset[str]:
    return frozenset(_as_tuple(value))


def _canonical(name: Any) -> str:
    return canonicalize_name(str(name))


def version_line(version: str | Version) -> str:
    """
    Return the default package version line.

    Candidate tables should set an explicit line for LTS branches such as
    Django's ``4.2``.  The fallback uses ``major.minor`` because that is the
    most specific common branch identifier.
    """

    parsed = version if isinstance(version, Version) else Version(version)
    return f"{parsed.major}.{parsed.minor}"


def load_audit_result(path: Path) -> AuditResult:
    """Load a pip-audit JSON result produced by ``--format=json``."""
    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise AllocationDrillError(f"cannot read audit result {path}: {exc}") from exc

    if isinstance(raw, list):
        dependencies = raw
    elif isinstance(raw, dict):
        dependencies = raw.get("dependencies", [])
    else:
        raise AllocationDrillError(f"invalid audit result {path}: expected JSON object or array")

    if not isinstance(dependencies, list):
        raise AllocationDrillError(f"invalid audit result {path}: 'dependencies' must be a list")

    packages: list[AuditedPackage] = []
    for index, dep in enumerate(dependencies):
        if not isinstance(dep, dict):
            raise AllocationDrillError(
                f"invalid audit result {path}: dependency #{index} is not an object"
            )
        name = dep.get("name")
        if not name:
            raise AllocationDrillError(
                f"invalid audit result {path}: dependency #{index} has no name"
            )

        vulns: list[Vulnerability] = []
        for vuln_index, raw_vuln in enumerate(dep.get("vulns", [])):
            if not isinstance(raw_vuln, dict):
                raise AllocationDrillError(
                    f"invalid audit result {path}: vulnerability #{vuln_index} for {name} is not an object"
                )
            vuln_id = raw_vuln.get("id")
            if not vuln_id:
                raise AllocationDrillError(
                    f"invalid audit result {path}: vulnerability #{vuln_index} for {name} has no id"
                )
            vulns.append(
                Vulnerability(
                    id=str(vuln_id),
                    aliases=_as_tuple(raw_vuln.get("aliases", [])),
                    fix_versions=_as_tuple(raw_vuln.get("fix_versions", [])),
                )
            )

        packages.append(
            AuditedPackage(
                name=_canonical(name),
                version=str(dep["version"]) if dep.get("version") is not None else None,
                vulnerabilities=tuple(vulns),
                skip_reason=dep.get("skip_reason"),
            )
        )

    return AuditResult(packages=tuple(packages))


def environment_name_for_path(path: Path) -> str:
    """Derive a logical environment name from a ``pylock.<env>.toml`` path."""
    name = path.name
    if name == "pylock.toml":
        return "default"
    prefix = "pylock."
    suffix = ".toml"
    if name.startswith(prefix) and name.endswith(suffix):
        return name[len(prefix) : -len(suffix)]
    return path.stem


def load_environments(paths: Sequence[Path]) -> list[LockEnvironment]:
    """Load lockfiles while retaining each file as an affected environment."""
    environments: list[LockEnvironment] = []
    seen_names: dict[str, Path] = {}

    for path in sorted(paths, key=environment_name_for_path):
        try:
            with path.open("rb") as handle:
                raw = tomli.load(handle)
        except (OSError, tomli.TOMLDecodeError) as exc:
            raise AllocationDrillError(f"cannot read pylock input {path}: {exc}") from exc

        lock_version = raw.get("lock-version")
        if not lock_version:
            raise AllocationDrillError(f"{path}: missing lock-version in lockfile")
        try:
            parsed_version = Version(str(lock_version))
        except InvalidVersion as exc:
            raise AllocationDrillError(f"{path}: invalid lock-version {lock_version!r}") from exc
        if parsed_version.major != 1:
            raise AllocationDrillError(
                f"{path}: lockfile version {parsed_version} is not supported"
            )

        raw_packages = raw.get("packages")
        if not isinstance(raw_packages, list) or not raw_packages:
            raise AllocationDrillError(f"{path}: missing packages in lockfile")

        packages: dict[str, Version] = {}
        for index, raw_package in enumerate(raw_packages):
            if not isinstance(raw_package, dict):
                raise AllocationDrillError(f"{path}: package #{index} is not an object")
            name = raw_package.get("name")
            if not name:
                raise AllocationDrillError(f"{path}: invalid package #{index}: no name")
            raw_version = raw_package.get("version")
            if raw_version is None:
                continue
            try:
                version = Version(str(raw_version))
            except InvalidVersion as exc:
                raise AllocationDrillError(f"{path}: invalid version for package {name}") from exc
            canonical = _canonical(name)
            if canonical in packages:
                raise AllocationDrillError(f"{path}: duplicate package {canonical}")
            packages[canonical] = version

        environment_name = environment_name_for_path(path)
        if environment_name in seen_names:
            raise AllocationDrillError(
                f"duplicate pylock environment {environment_name!r}: "
                f"{seen_names[environment_name]} and {path}"
            )
        seen_names[environment_name] = path
        environments.append(LockEnvironment(environment_name, path, packages))

    return environments


def build_alerts(audit: AuditResult, environments: Sequence[LockEnvironment]) -> list[Alert]:
    """Join audit dependencies to exact versions found in lockfile environments."""
    alerts: list[Alert] = []
    for package in audit.packages:
        if package.skip_reason or package.version is None or not package.vulnerabilities:
            continue
        try:
            installed = Version(package.version)
        except InvalidVersion:
            continue

        environment_names = tuple(
            sorted(
                environment.name
                for environment in environments
                if environment.packages.get(package.name) == installed
            )
        )
        alerts.extend(
            Alert(
                vulnerability_id=vulnerability.id,
                package=package.name,
                installed_version=str(installed),
                environments=environment_names,
                aliases=vulnerability.aliases,
                fix_versions=vulnerability.fix_versions,
            )
            for vulnerability in package.vulnerabilities
        )

    return sorted(alerts, key=lambda alert: (alert.vulnerability_id, alert.package))


def _parse_scope(raw: Any) -> Scope:
    if isinstance(raw, str):
        value = raw.strip()
        if value in {"*", "all"}:
            return Scope(package=None)
        for separator in ("@", "==", ":"):
            if separator in value:
                package, line = value.split(separator, 1)
                line = line.strip()
                if separator == "==" and line.endswith(".*"):
                    line = line[:-2]
                return Scope(package=_canonical(package), lines=frozenset({line}))
        return Scope(package=_canonical(value))

    if not isinstance(raw, dict):
        raise AllocationDrillError("invalid scope in allocation table: expected string or object")

    package = _first_key(raw, "package", "name")
    lines = _first_key(raw, "lines", "version_lines", "version_line", "line")
    return Scope(
        package=None if package in (None, "*", "all") else _canonical(package),
        lines=_as_frozenset(lines),
    )


def _parse_group(raw: Any, index: int) -> Group:
    if not isinstance(raw, dict):
        raise AllocationDrillError(f"groups[{index}] must be an object")
    name = raw.get("name") or raw.get("id")
    if not name:
        raise AllocationDrillError(f"groups[{index}] is missing a name")

    capacity = _first_key(raw, "capacity", "slots", "available_slots", "slot_holders")
    if capacity is None:
        raise AllocationDrillError(f"group {name!r} is missing capacity/slots")
    if isinstance(capacity, (list, tuple, set, frozenset)):
        capacity_value = len(capacity)
    elif isinstance(capacity, int) and not isinstance(capacity, bool):
        capacity_value = capacity
    else:
        capacity_value = -1
    if capacity_value < 0:
        raise AllocationDrillError(f"group {name!r} capacity must be a non-negative integer")

    raw_scopes = _first_key(raw, "scopes", "responsibilities", "responsibility", "scope")
    if raw_scopes is None:
        raw_packages = raw.get("packages", [])
        raw_scopes = raw_packages if isinstance(raw_packages, list) else []
    if not isinstance(raw_scopes, list):
        raw_scopes = [raw_scopes]

    environment_scope = raw.get("environments")
    return Group(
        name=str(name),
        owner=raw.get("owner") or raw.get("maintainer"),
        capacity=capacity_value,
        cross_environment=bool(
            _first_key(raw, "cross_environment", "can_handle_cross_environment", "cross_env")
            or False
        ),
        scopes=tuple(_parse_scope(scope) for scope in raw_scopes),
        environments=None if environment_scope is None else _as_frozenset(environment_scope),
    )


def _parse_change(raw: Any, index: int, combination_id: str) -> Change:
    if not isinstance(raw, dict):
        raise AllocationDrillError(
            f"combinations.{combination_id}.changes[{index}] must be an object"
        )
    package = _first_key(raw, "package", "name")
    if not package:
        raise AllocationDrillError(f"combination {combination_id!r} change #{index} has no package")
    environments = raw.get("environments")
    return Change(
        package=_canonical(package),
        to_version=_first_key(raw, "to_version", "new_version", "target_version"),
        line=_first_key(raw, "line", "version_line"),
        from_version=_first_key(raw, "from_version", "old_version", "installed_version"),
        environments=None if environments is None else _as_frozenset(environments),
    )


def _parse_combination(raw: Any, index: int) -> Combination:
    if not isinstance(raw, dict):
        raise AllocationDrillError(f"combinations[{index}] must be an object")
    combination_id = raw.get("id") or raw.get("name")
    if not combination_id:
        raise AllocationDrillError(f"combinations[{index}] is missing an id")

    raw_changes = _first_key(raw, "changes", "change_set", "upgrades") or []
    if not isinstance(raw_changes, list):
        raise AllocationDrillError(f"combination {combination_id!r} changes must be a list")

    raw_image_decisions = _first_key(
        raw, "image_decisions", "shared_image_decisions", "image_versions"
    )
    image_decisions: list[ImageDecision] = []
    if isinstance(raw_image_decisions, dict):
        for image_name, image_version in raw_image_decisions.items():
            image_decisions.append(ImageDecision(image=str(image_name), version=str(image_version)))
    elif raw_image_decisions is not None:
        if not isinstance(raw_image_decisions, list):
            raise AllocationDrillError(
                f"combination {combination_id!r} image_decisions must be a list or table"
            )
        for decision_index, raw_decision in enumerate(raw_image_decisions):
            if not isinstance(raw_decision, dict):
                raise AllocationDrillError(
                    f"combination {combination_id!r} image_decisions[{decision_index}] must be an object"
                )
            image_name = _first_key(raw_decision, "image", "name", "shared_image")
            image_version = _first_key(raw_decision, "version", "to_version", "tag")
            if not image_name or image_version is None:
                raise AllocationDrillError(
                    f"combination {combination_id!r} image_decisions[{decision_index}] needs image and version"
                )
            image_decisions.append(ImageDecision(str(image_name), str(image_version)))

    slot_cost = _first_key(raw, "slot_cost", "cost", "slots") or 1
    if not isinstance(slot_cost, int) or isinstance(slot_cost, bool) or slot_cost < 1:
        raise AllocationDrillError(
            f"combination {combination_id!r} slot_cost must be a positive integer"
        )

    priority = raw.get("priority", 0)
    if not isinstance(priority, int) or isinstance(priority, bool):
        raise AllocationDrillError(f"combination {combination_id!r} priority must be an integer")

    cross = _first_key(raw, "cross_environment", "cross_env")
    environments = raw.get("environments")
    return Combination(
        id=str(combination_id),
        title=str(raw.get("title", raw.get("summary", ""))),
        finding_refs=_as_tuple(
            _first_key(raw, "findings", "vulnerabilities", "vulns", "advisories") or []
        ),
        environments=None if environments is None else _as_frozenset(environments),
        changes=tuple(
            _parse_change(change, change_index, str(combination_id))
            for change_index, change in enumerate(raw_changes)
        ),
        image_decisions=tuple(image_decisions),
        slot_cost=slot_cost,
        priority=priority,
        cross_environment=None if cross is None else bool(cross),
    )


def _parse_shared_image(raw: Any, index: int) -> SharedImage:
    if not isinstance(raw, dict):
        raise AllocationDrillError(f"shared_images[{index}] must be an object")
    name = raw.get("name") or raw.get("id") or f"image-{index}"
    environments = _first_key(raw, "environments", "envs")
    if not environments:
        raise AllocationDrillError(f"shared image {name!r} must declare environments")
    packages = _first_key(raw, "packages", "package")
    return SharedImage(
        name=str(name),
        environments=_as_frozenset(environments),
        packages=_as_frozenset(packages),
    )


def load_plan_table(path: Path) -> PlanTable:
    """Load a TOML or JSON local allocation table."""
    try:
        if path.suffix.lower() == ".json":
            raw = json.loads(path.read_text())
        else:
            with path.open("rb") as handle:
                raw = tomli.load(handle)
    except (OSError, json.JSONDecodeError, tomli.TOMLDecodeError) as exc:
        raise AllocationDrillError(f"cannot read allocation plan {path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise AllocationDrillError(
            f"invalid allocation plan {path}: top-level value must be an object"
        )

    raw_groups = (
        _first_key(raw, "groups", "teams", "maintainers", "owners", "squads", "schedules") or []
    )
    raw_combinations = (
        _first_key(
            raw,
            "combinations",
            "candidate_combinations",
            "candidate_change_combinations",
            "change_combinations",
            "change_sets",
            "candidates",
            "combos",
        )
        or []
    )
    raw_images = _first_key(raw, "shared_images", "images") or []

    if not isinstance(raw_groups, list):
        raise AllocationDrillError("allocation plan 'groups' must be a list")
    if not isinstance(raw_combinations, list):
        raise AllocationDrillError("allocation plan 'combinations' must be a list")
    if not isinstance(raw_images, list):
        raise AllocationDrillError("allocation plan 'shared_images' must be a list")

    version = raw.get("version", 1)
    if not isinstance(version, int) or isinstance(version, bool):
        raise AllocationDrillError("allocation plan 'version' must be an integer")

    return PlanTable(
        groups=tuple(_parse_group(item, index) for index, item in enumerate(raw_groups)),
        combinations=tuple(
            _parse_combination(item, index) for index, item in enumerate(raw_combinations)
        ),
        shared_images=tuple(
            _parse_shared_image(item, index) for index, item in enumerate(raw_images)
        ),
        version=version,
    )


def _ref_index(alerts: Sequence[Alert]) -> dict[str, str]:
    index: dict[str, str] = {}
    for alert in alerts:
        index[alert.vulnerability_id] = alert.vulnerability_id
        for alias in alert.aliases:
            index[alias] = alert.vulnerability_id
    return index


def prepare_combinations(
    table: PlanTable,
    alerts: Sequence[Alert],
    environments: Sequence[LockEnvironment],
) -> tuple[list[PreparedCombination], list[Conflict]]:
    """Join candidate combinations to alert IDs and known environments."""
    env_names = frozenset(environment.name for environment in environments)
    image_names = frozenset(image.name for image in table.shared_images)
    alert_by_id: dict[str, list[Alert]] = {}
    for alert in alerts:
        alert_by_id.setdefault(alert.vulnerability_id, []).append(alert)
    refs = _ref_index(alerts)

    prepared: list[PreparedCombination] = []
    conflicts: list[Conflict] = []

    for combination in table.combinations:
        issues: list[Conflict] = []
        for image_decision in combination.image_decisions:
            if image_decision.image not in image_names:
                issue = Conflict(
                    code="unknown_shared_image",
                    message=(
                        f"combination {combination.id!r} decides version for unknown shared image "
                        f"{image_decision.image!r}"
                    ),
                    combination_id=combination.id,
                    details={"image": image_decision.image},
                )
                issues.append(issue)
                conflicts.append(issue)

        finding_ids: set[str] = set()
        for ref in combination.finding_refs:
            primary = refs.get(ref)
            if primary is None:
                issue = Conflict(
                    code="unknown_finding_reference",
                    message=f"combination {combination.id!r} references unknown audit finding {ref!r}",
                    combination_id=combination.id,
                    details={"reference": ref},
                )
                issues.append(issue)
                conflicts.append(issue)
            else:
                finding_ids.add(primary)

        affected_environments = {
            environment
            for finding_id in finding_ids
            for alert in alert_by_id.get(finding_id, [])
            for environment in alert.environments
        }
        if combination.environments is None:
            combo_environments = set(affected_environments)
        else:
            combo_environments = set(combination.environments)
            unknown = combo_environments - env_names
            if unknown:
                issue = Conflict(
                    code="unknown_environment",
                    message=f"combination {combination.id!r} names unknown environments: {sorted(unknown)}",
                    combination_id=combination.id,
                    details={"environments": sorted(unknown)},
                )
                issues.append(issue)
                conflicts.append(issue)

        resolved_changes: list[ResolvedChange] = []
        for change in combination.changes:
            change_environments = (
                set(change.environments)
                if change.environments is not None
                else set(combo_environments)
            )
            unknown = change_environments - env_names
            if unknown:
                issue = Conflict(
                    code="unknown_environment",
                    message=f"change {change.package!r} in {combination.id!r} names unknown environments: {sorted(unknown)}",
                    combination_id=combination.id,
                    details={"package": change.package, "environments": sorted(unknown)},
                )
                issues.append(issue)
                conflicts.append(issue)

            line = change.line
            if line is None and change.to_version is not None:
                try:
                    line = version_line(change.to_version)
                except InvalidVersion:
                    issue = Conflict(
                        code="invalid_version",
                        message=f"change {change.package!r} in {combination.id!r} has invalid to_version {change.to_version!r}",
                        combination_id=combination.id,
                        severity="warning",
                    )
                    issues.append(issue)
                    conflicts.append(issue)
            elif line is not None:
                line = str(line)

            if change.from_version is not None:
                for environment in environments:
                    if environment.name not in change_environments:
                        continue
                    installed = environment.packages.get(change.package)
                    try:
                        expected = Version(change.from_version)
                    except InvalidVersion:
                        expected = None
                    if installed is not None and expected is not None and installed != expected:
                        issue = Conflict(
                            code="from_version_mismatch",
                            message=(
                                f"{combination.id}: {change.package} is {installed} in "
                                f"{environment.name}, not declared from_version {change.from_version}"
                            ),
                            combination_id=combination.id,
                            severity="warning",
                            details={"environment": environment.name, "installed": str(installed)},
                        )
                        issues.append(issue)
                        conflicts.append(issue)

            resolved_changes.append(
                ResolvedChange(
                    package=change.package,
                    environments=frozenset(change_environments),
                    line=line,
                    to_version=change.to_version,
                    from_version=change.from_version,
                )
            )

        covered_instances = {
            instance
            for alert in alerts
            if alert.vulnerability_id in finding_ids
            for instance in alert.instance_keys
            if instance.rsplit("@", 1)[-1] in combo_environments
        }
        cross_environment = (
            combination.cross_environment
            if combination.cross_environment is not None
            else len(combo_environments) > 1
            or any(len(change.environments) > 1 for change in resolved_changes)
        )
        if not combination.changes:
            issue = Conflict(
                code="combination_without_changes",
                message=f"combination {combination.id!r} does not declare any atomic changes",
                combination_id=combination.id,
            )
            issues.append(issue)
            conflicts.append(issue)
        if not finding_ids:
            issue = Conflict(
                code="combination_without_findings",
                message=f"combination {combination.id!r} does not join to any audit finding",
                combination_id=combination.id,
            )
            issues.append(issue)
            conflicts.append(issue)

        prepared.append(
            PreparedCombination(
                raw=combination,
                finding_ids=frozenset(finding_ids),
                environments=frozenset(combo_environments),
                cross_environment=cross_environment,
                changes=tuple(resolved_changes),
                covered_instances=frozenset(covered_instances),
                valid=not any(issue.severity == "error" for issue in issues),
                issues=tuple(issues),
            )
        )

    for image in table.shared_images:
        unknown = image.environments - env_names
        if unknown:
            conflicts.append(
                Conflict(
                    code="unknown_shared_image_environment",
                    message=f"shared image {image.name!r} names unknown environments: {sorted(unknown)}",
                    details={"image": image.name, "environments": sorted(unknown)},
                )
            )

    return prepared, conflicts


def scope_matches(scope: Scope, package: str, line: str | None) -> bool:
    """Return whether a scope covers a package and optional version line."""
    if scope.package is not None and scope.package != package:
        return False
    if scope.lines and (line is None or line not in scope.lines):
        return False
    return True


def assess_group(combination: PreparedCombination, group: Group) -> list[Conflict]:
    """Return static scope/capability reasons a group cannot take a combination."""
    reasons: list[Conflict] = []
    if group.environments is not None and not combination.environments <= group.environments:
        missing = sorted(combination.environments - group.environments)
        reasons.append(
            Conflict(
                code="environment_scope_mismatch",
                message=f"{group.name!r} is not responsible for environments {missing}",
                combination_id=combination.raw.id,
                group=group.name,
                details={"missing_environments": missing},
            )
        )

    if combination.cross_environment and not group.cross_environment:
        reasons.append(
            Conflict(
                code="cross_environment_not_supported",
                message=f"{group.name!r} cannot coordinate cross-environment upgrades",
                combination_id=combination.raw.id,
                group=group.name,
            )
        )

    reasons.extend(
        Conflict(
            code="version_line_scope_mismatch",
            message=(
                f"{group.name!r} does not own {change.package}"
                + (f" version line {change.line!r}" if change.line else "")
            ),
            combination_id=combination.raw.id,
            group=group.name,
            details={"package": change.package, "line": change.line},
        )
        for change in combination.changes
        if not any(scope_matches(scope, change.package, change.line) for scope in group.scopes)
    )

    if group.capacity < combination.raw.slot_cost:
        reasons.append(
            Conflict(
                code="group_capacity_too_small",
                message=(
                    f"{group.name!r} has capacity {group.capacity}, but combination "
                    f"{combination.raw.id!r} costs {combination.raw.slot_cost}"
                ),
                combination_id=combination.raw.id,
                group=group.name,
                details={"capacity": group.capacity, "slot_cost": combination.raw.slot_cost},
            )
        )

    return reasons


def shared_image_conflicts(
    selected: Sequence[PreparedCombination],
    table: PlanTable,
    environments: Sequence[LockEnvironment],
    *,
    check_coverage: bool,
) -> list[Conflict]:
    """Validate one target version per package across each shared image."""
    env_by_name = {environment.name: environment for environment in environments}
    decisions: dict[tuple[str, str], tuple[str, str, str]] = {}
    image_versions: dict[str, tuple[str, str]] = {}
    conflicts: list[Conflict] = []

    for combination in selected:
        for image_decision in combination.raw.image_decisions:
            current_image = image_versions.get(image_decision.image)
            if current_image is not None and current_image[0] != image_decision.version:
                conflicts.append(
                    Conflict(
                        code="shared_image_version_conflict",
                        message=(
                            f"shared image {image_decision.image!r} received incompatible version "
                            f"decisions {current_image[0]!r} ({current_image[1]}) and "
                            f"{image_decision.version!r} ({combination.raw.id})"
                        ),
                        combination_id=combination.raw.id,
                        details={
                            "kind": "image_version",
                            "image": image_decision.image,
                            "versions": [current_image[0], image_decision.version],
                            "combinations": [current_image[1], combination.raw.id],
                        },
                    )
                )
            image_versions[image_decision.image] = (
                image_decision.version,
                combination.raw.id,
            )

        for change in combination.changes:
            if change.to_version is None:
                conflicts.append(
                    Conflict(
                        code="missing_target_version",
                        message=f"{combination.raw.id}: change for {change.package} has no target version",
                        combination_id=combination.raw.id,
                        details={"package": change.package},
                    )
                )
                continue
            for environment_name in change.environments:
                key = (change.package, environment_name)
                current = decisions.get(key)
                if current is not None and current[0] != change.to_version:
                    conflicts.append(
                        Conflict(
                            code="duplicate_version_decision",
                            message=(
                                f"{change.package} in {environment_name} was told to use both "
                                f"{current[0]} ({current[2]}) and {change.to_version} "
                                f"({combination.raw.id})"
                            ),
                            combination_id=combination.raw.id,
                            details={
                                "package": change.package,
                                "environment": environment_name,
                                "versions": [current[0], change.to_version],
                                "combinations": [current[2], combination.raw.id],
                            },
                        )
                    )
                decisions[key] = (change.to_version, environment_name, combination.raw.id)

    for image in table.shared_images:
        image_environments = sorted(image.environments)
        packages = set(image.packages)
        if not packages:
            packages = {
                package for package, _environment in decisions if _environment in image.environments
            }

        for package in sorted(packages):
            version_sources: dict[str, list[str]] = {}
            covered_environments: set[str] = set()
            for environment_name in image_environments:
                decision = decisions.get((package, environment_name))
                if decision is not None:
                    version, _env, source = decision
                    version_sources.setdefault(version, []).append(source)
                    covered_environments.add(environment_name)

            if not version_sources:
                continue

            if len(version_sources) > 1:
                conflicts.append(
                    Conflict(
                        code="shared_image_version_conflict",
                        message=(
                            f"shared image {image.name!r} requires one {package} version, but "
                            f"candidates choose {sorted(version_sources)}"
                        ),
                        details={
                            "image": image.name,
                            "package": package,
                            "decisions": {
                                version: sorted(set(sources))
                                for version, sources in version_sources.items()
                            },
                        },
                    )
                )

            if check_coverage:
                required_environments = {
                    environment_name
                    for environment_name in image_environments
                    if (
                        environment_name in env_by_name
                        and package in env_by_name[environment_name].packages
                    )
                }
                missing = sorted(required_environments - covered_environments)
                if missing:
                    conflicts.append(
                        Conflict(
                            code="shared_image_coverage_missing",
                            message=(
                                f"shared image {image.name!r} must move {package} consistently, "
                                f"but no target decision covers {missing}"
                            ),
                            details={
                                "image": image.name,
                                "package": package,
                                "environments": missing,
                            },
                        )
                    )

    return conflicts


def _score(
    selected: Sequence[tuple[PreparedCombination, Group]],
) -> tuple[int, int, int, int, int, tuple[str, ...]]:
    covered = {
        instance for combination, _group in selected for instance in combination.covered_instances
    }
    alert_count = len({instance.rsplit("@", 1)[0] for instance in covered})
    cost = sum(combination.raw.slot_cost for combination, _group in selected)
    max_priority = max((combination.raw.priority for combination, _group in selected), default=0)
    tie = tuple(sorted(f"{combination.raw.id}->{group.name}" for combination, group in selected))
    return len(covered), alert_count, -cost, -len(selected), max_priority, tie


def solve_assignments(
    prepared: Sequence[PreparedCombination],
    table: PlanTable,
    environments: Sequence[LockEnvironment],
) -> tuple[list[Assignment], dict[str, int], list[tuple[PreparedCombination, Group]]]:
    """Exhaustively search small local tables for the maximum-coverage plan."""
    groups_by_name = {group.name: group for group in table.groups}
    remaining = {group.name: group.capacity for group in table.groups}
    eligible: dict[str, list[tuple[Group, list[Conflict]]]] = {}
    valid_combinations = [combination for combination in prepared if combination.valid]

    for combination in valid_combinations:
        options: list[tuple[Group, list[Conflict]]] = []
        for group in table.groups:
            reasons = assess_group(combination, group)
            if not reasons:
                options.append((group, []))
        eligible[combination.raw.id] = options

    chosen: list[tuple[PreparedCombination, Group]] = []
    best: list[tuple[PreparedCombination, Group]] | None = None
    best_score: tuple[int, int, int, int, int, tuple[str, ...]] | None = None

    def visit(index: int) -> None:
        nonlocal best, best_score
        if index == len(valid_combinations):
            score = _score(chosen)
            if (
                best_score is None
                or score[:5] > best_score[:5]
                or (score[:5] == best_score[:5] and score[5] < best_score[5])
            ):
                best = list(chosen)
                best_score = score
            return

        combination = valid_combinations[index]

        visit(index + 1)

        for group, _reasons in eligible[combination.raw.id]:
            if remaining[group.name] < combination.raw.slot_cost:
                continue
            tentative = chosen + [(combination, group)]
            version_conflicts = [
                conflict
                for conflict in shared_image_conflicts(
                    [item[0] for item in tentative], table, environments, check_coverage=False
                )
                if conflict.code in {"shared_image_version_conflict", "duplicate_version_decision"}
            ]
            if version_conflicts:
                continue

            remaining[group.name] -= combination.raw.slot_cost
            chosen.append((combination, group))
            visit(index + 1)
            chosen.pop()
            remaining[group.name] += combination.raw.slot_cost

    visit(0)
    assert best is not None

    used = {group.name: 0 for group in table.groups}
    assignments: list[Assignment] = []
    for combination, group in best:
        used[group.name] += combination.raw.slot_cost
        assignments.append(
            Assignment(
                combination_id=combination.raw.id,
                group=group.name,
                slot_cost=combination.raw.slot_cost,
                covered_instances=tuple(sorted(combination.covered_instances)),
            )
        )

    remaining_slots = {name: groups_by_name[name].capacity - used[name] for name in used}
    return assignments, remaining_slots, best


def simulate_alert_grab(
    alerts: Sequence[Alert],
    table: PlanTable,
) -> GreedyResult:
    """
    Simulate naive per-alert slot grabbing.

    The simulation intentionally ignores candidate combinations.  Each
    vulnerability is treated as an independent ticket and consumes one slot,
    even when one atomic combination would cover several alerts/environments.
    """
    remaining = {group.name: group.capacity for group in table.groups}
    claims: list[GreedyClaim] = []
    conflicts: list[Conflict] = []
    claimed: list[str] = []

    for alert in alerts:
        line = version_line(alert.installed_version)
        multi_environment = len(alert.environments) > 1
        chosen_group: Group | None = None
        rejection_details: list[dict[str, Any]] = []

        for group in table.groups:
            reasons: list[str] = []
            if multi_environment and not group.cross_environment:
                reasons.append("cross_environment_not_supported")
            scope_ok = any(scope_matches(scope, alert.package, line) for scope in group.scopes)
            if not scope_ok:
                reasons.append("version_line_scope_mismatch")
            if group.capacity < 1:
                reasons.append("group_capacity_too_small")
            elif remaining[group.name] < 1:
                reasons.append("capacity_exhausted")

            if not reasons and remaining[group.name] >= 1:
                chosen_group = group
                break
            rejection_details.append({"group": group.name, "reasons": reasons})

        if chosen_group is None:
            conflict = Conflict(
                code="alert_grab_failed",
                message=(
                    f"alert {alert.vulnerability_id} for {alert.package} could not grab an "
                    f"eligible slot; affected environments: {list(alert.environments)}"
                ),
                details={
                    "alert_key": alert.key,
                    "package": alert.package,
                    "installed_line": line,
                    "environments": list(alert.environments),
                    "group_assessments": rejection_details,
                },
            )
            conflicts.append(conflict)
            claims.append(
                GreedyClaim(
                    alert_key=alert.key,
                    vulnerability_id=alert.vulnerability_id,
                    package=alert.package,
                    environments=alert.environments,
                    group=None,
                    status="failed",
                    reason="no eligible available slot",
                )
            )
            continue

        remaining[chosen_group.name] -= 1
        claimed.append(alert.key)
        claims.append(
            GreedyClaim(
                alert_key=alert.key,
                vulnerability_id=alert.vulnerability_id,
                package=alert.package,
                environments=alert.environments,
                group=chosen_group.name,
                status="claimed",
            )
        )

    return GreedyResult(
        claims=tuple(claims),
        conflicts=tuple(conflicts),
        claimed_alerts=tuple(claimed),
    )


def diagnose_conflicts(
    prepared: Sequence[PreparedCombination],
    table: PlanTable,
    environments: Sequence[LockEnvironment],
    alerts: Sequence[Alert],
    assignments: Sequence[Assignment],
    remaining_slots: dict[str, int],
    selected: Sequence[tuple[PreparedCombination, Group]],
    preparation_conflicts: Sequence[Conflict],
) -> list[Conflict]:
    """Explain every required alert that the best assignment cannot cover."""
    conflicts = list(preparation_conflicts)
    selected_combinations = [combination for combination, _group in selected]
    conflicts.extend(
        shared_image_conflicts(selected_combinations, table, environments, check_coverage=True)
    )

    assigned_ids = {assignment.combination_id for assignment in assignments}
    assigned = [combination for combination in prepared if combination.raw.id in assigned_ids]
    covered = {instance for combination in assigned for instance in combination.covered_instances}
    required = {instance for alert in alerts for instance in alert.instance_keys}
    uncovered = required - covered

    candidate_by_instance: dict[str, list[PreparedCombination]] = {}
    for combination in prepared:
        if not combination.valid:
            continue
        for instance in combination.covered_instances:
            candidate_by_instance.setdefault(instance, []).append(combination)

    no_candidate = sorted(
        instance for instance in uncovered if instance not in candidate_by_instance
    )
    for instance in no_candidate:
        alert_key, environment = instance.rsplit("@", 1)
        vulnerability_id, package = alert_key.rsplit("@", 1)
        conflicts.append(
            Conflict(
                code="missing_candidate_combination",
                message=(
                    f"no candidate combination covers {vulnerability_id} for {package} "
                    f"in environment {environment}"
                ),
                details={"instance": instance, "environment": environment},
            )
        )

    diagnosed: set[str] = set()
    for instance in sorted(uncovered):
        for combination in candidate_by_instance.get(instance, []):
            if combination.raw.id in diagnosed or combination.raw.id in assigned_ids:
                continue
            diagnosed.add(combination.raw.id)
            group_assessments = [
                {
                    "group": group.name,
                    "reasons": [asdict(reason) for reason in assess_group(combination, group)],
                }
                for group in table.groups
            ]
            eligible = [group for group in table.groups if not assess_group(combination, group)]
            shared_blockers = [
                conflict
                for conflict in shared_image_conflicts(
                    selected_combinations + ([combination] if eligible else []),
                    table,
                    environments,
                    check_coverage=False,
                )
                if conflict.code in {"shared_image_version_conflict", "duplicate_version_decision"}
            ]

            if not eligible:
                conflicts.append(
                    Conflict(
                        code="no_eligible_group",
                        message=(
                            f"combination {combination.raw.id!r} cannot be assigned: no group's "
                            "scope, environment and cross-environment constraints match"
                        ),
                        combination_id=combination.raw.id,
                        details={"group_assessments": group_assessments},
                    )
                )
            else:
                if shared_blockers:
                    conflicts.append(
                        Conflict(
                            code="shared_image_decision_conflict",
                            message=(
                                f"combination {combination.raw.id!r} conflicts with an already selected "
                                "shared image version decision"
                            ),
                            combination_id=combination.raw.id,
                            details={"blockers": [asdict(blocker) for blocker in shared_blockers]},
                        )
                    )
                if all(
                    remaining_slots[group.name] < combination.raw.slot_cost for group in eligible
                ):
                    conflicts.append(
                        Conflict(
                            code="capacity_exhausted",
                            message=(
                                f"combination {combination.raw.id!r} needs "
                                f"{combination.raw.slot_cost} slot(s), but eligible groups have no "
                                "remaining capacity after the selected plan"
                            ),
                            combination_id=combination.raw.id,
                            details={
                                "slot_cost": combination.raw.slot_cost,
                                "eligible_groups": [
                                    {
                                        "group": group.name,
                                        "remaining": remaining_slots[group.name],
                                        "capacity": group.capacity,
                                    }
                                    for group in eligible
                                ],
                                "group_assessments": group_assessments,
                            },
                        )
                    )
                elif not shared_blockers:
                    conflicts.append(
                        Conflict(
                            code="combination_not_selected",
                            message=(
                                f"combination {combination.raw.id!r} was not selected even though an "
                                "eligible slot appears available; inspect solver ordering"
                            ),
                            combination_id=combination.raw.id,
                            details={"group_assessments": group_assessments},
                            severity="warning",
                        )
                    )

    return conflicts


def run_drill(audit_path: Path, pylock_paths: Sequence[Path], plan_path: Path) -> DrillResult:
    """Load all inputs, solve the allocation drill, and return a report."""
    audit = load_audit_result(audit_path)
    environments = load_environments(pylock_paths)
    table = load_plan_table(plan_path)
    alerts = build_alerts(audit, environments)
    prepared, preparation_conflicts = prepare_combinations(table, alerts, environments)

    unlocated = [alert for alert in alerts if not alert.environments]
    for alert in unlocated:
        preparation_conflicts.append(
            Conflict(
                code="unlocated_finding",
                message=(
                    f"{alert.vulnerability_id} for {alert.package} {alert.installed_version} "
                    "was not found at the audited version in any pylock environment"
                ),
                details={"alert_key": alert.key},
            )
        )

    assignments, remaining_slots, selected = solve_assignments(prepared, table, environments)
    greedy = simulate_alert_grab(alerts, table)
    conflicts = diagnose_conflicts(
        prepared,
        table,
        environments,
        alerts,
        assignments,
        remaining_slots,
        selected,
        preparation_conflicts,
    )

    used = {group.name: 0 for group in table.groups}
    assignment_groups: dict[str, list[str]] = {group.name: [] for group in table.groups}
    for assignment in assignments:
        used[assignment.group] += assignment.slot_cost
        assignment_groups[assignment.group].append(assignment.combination_id)

    loads = [
        GroupLoad(
            group=group.name,
            owner=group.owner,
            capacity=group.capacity,
            used=used[group.name],
            remaining=remaining_slots[group.name],
            combination_ids=tuple(assignment_groups[group.name]),
        )
        for group in table.groups
    ]

    required_instances = {instance for alert in alerts for instance in alert.instance_keys}
    covered_instances = {
        instance for assignment in assignments for instance in assignment.covered_instances
    }
    error_conflicts = [conflict for conflict in conflicts if conflict.severity == "error"]
    status = (
        "conflicts"
        if error_conflicts or len(covered_instances) < len(required_instances)
        else "ready"
    )

    environment_summaries = [
        {
            "name": environment.name,
            "lockfile": str(environment.path),
            "packages": {
                name: str(version) for name, version in sorted(environment.packages.items())
            },
        }
        for environment in environments
    ]
    summary = {
        "environment_count": len(environments),
        "alert_count": len(alerts),
        "alert_instance_count": len(required_instances),
        "covered_instance_count": len(covered_instances & required_instances),
        "assigned_combination_count": len(assignments),
        "conflict_count": len(error_conflicts),
        "warning_count": len(conflicts) - len(error_conflicts),
        "greedy_claimed_alert_count": len(greedy.claimed_alerts),
        "greedy_failure_count": len(greedy.conflicts),
    }

    return DrillResult(
        status=status,
        audit_result=str(audit_path),
        plan_table=str(plan_path),
        environments=environment_summaries,
        alerts=alerts,
        groups=list(table.groups),
        shared_images=list(table.shared_images),
        combinations=prepared,
        assignments=assignments,
        group_loads=loads,
        conflicts=conflicts,
        greedy=greedy,
        summary=summary,
    )


def render_json(result: DrillResult) -> str:
    """Render the drill result as JSON."""

    def default(value: Any) -> Any:
        if isinstance(value, (set, frozenset)):
            return sorted(value)
        if isinstance(value, Path):
            return str(value)
        return str(value)

    return json.dumps(asdict(result), ensure_ascii=False, indent=2, default=default)


def render_markdown(result: DrillResult) -> str:
    """Render a reviewer-facing allocation plan in Markdown."""
    lines = [
        "# 离线整改分工预演 / Offline remediation allocation drill",
        "",
        f"- 状态 / Status: `{result.status}`",
        f"- 审计结果 / Audit result: `{result.audit_result}`",
        f"- 方案表 / Plan table: `{result.plan_table}`",
        (
            f"- 覆盖 / Covered: {result.summary['covered_instance_count']}/"
            f"{result.summary['alert_instance_count']} alert environments; "
            f"{len(result.assignments)} combination(s) assigned"
        ),
        f"- 冲突 / Conflicts: {result.summary['conflict_count']} error(s), "
        f"{result.summary['warning_count']} warning(s)",
        "",
        "## 受影响环境 / Affected environments",
        "",
        "| Environment | Lockfile | Vulnerable packages from audit |",
        "| --- | --- | --- |",
    ]

    affected_packages: dict[str, set[str]] = {}
    for alert in result.alerts:
        for environment in alert.environments:
            affected_packages.setdefault(environment, set()).add(
                f"{alert.package} {alert.installed_version} ({alert.vulnerability_id})"
            )
    for environment in result.environments:
        name = environment["name"]
        packages = "; ".join(sorted(affected_packages.get(name, set()))) or "-"
        lines.append(f"| `{name}` | `{environment['lockfile']}` | {packages} |")

    lines.extend(["", "## 每组承接的组合 / Group assignments", ""])
    if result.assignments:
        lines.extend(
            [
                "| Group | Owner | Accepted combinations | Slots used | Remaining |",
                "| --- | --- | --- | ---: | ---: |",
            ]
        )
        for load in result.group_loads:
            combinations = ", ".join(f"`{item}`" for item in load.combination_ids) or "-"
            lines.append(
                f"| `{load.group}` | {load.owner or '-'} | {combinations} | "
                f"{load.used}/{load.capacity} | {load.remaining} |"
            )
    else:
        lines.append("No combination could be assigned.")

    combination_by_id = {combination.raw.id: combination for combination in result.combinations}
    lines.extend(["", "### 组合内容 / Combination scope", ""])
    for assignment in result.assignments:
        combination = combination_by_id[assignment.combination_id]
        raw = combination.raw
        finding_ids = ", ".join(f"`{item}`" for item in sorted(combination.finding_ids)) or "-"
        environments = ", ".join(f"`{item}`" for item in sorted(combination.environments)) or "-"
        changes = "; ".join(
            f"`{change.package}` -> `{change.to_version or 'decision required'}` "
            f"(line `{change.line or 'unspecified'}`)"
            for change in combination.changes
        )
        block = [
            f"#### `{raw.id}` → `{assignment.group}`",
            "",
        ]
        if raw.title:
            block.append(f"- {raw.title}")
        block.extend(
            [
                f"- Findings covered together: {finding_ids}",
                f"- Environments: {environments}",
                f"- Atomic changes: {changes}",
                f"- Slot cost: {assignment.slot_cost}; cross-environment: `{combination.cross_environment}`",
                "",
            ]
        )
        lines.extend(block)

    lines.extend(["## 候选组合可行性 / Candidate feasibility", ""])
    lines.extend(
        [
            "| Combination | Cross-env | Eligible groups | Static blockers |",
            "| --- | --- | --- | --- |",
        ]
    )
    for combination in result.combinations:
        eligible_groups: list[str] = []
        blockers: list[str] = []
        if not combination.valid:
            issue_codes = ", ".join(sorted({issue.code for issue in combination.issues}))
            blockers.append(f"invalid: `{issue_codes}`")
        for group in result.groups:
            reasons = assess_group(combination, group)
            if not reasons:
                eligible_groups.append(f"`{group.name}`")
            else:
                codes = ",".join(reason.code for reason in reasons)
                blockers.append(f"`{group.name}`: {codes}")
        lines.append(
            f"| `{combination.raw.id}` | `{combination.cross_environment}` | "
            f"{', '.join(eligible_groups) or '-'} | {'; '.join(blockers) or '-'} |"
        )

    lines.extend(["", "## 共用镜像一致性 / Shared image consistency", ""])
    if result.shared_images:
        assigned_ids = {item.combination_id for item in result.assignments}
        assigned_combinations = [
            combination for combination in result.combinations if combination.raw.id in assigned_ids
        ]
        for image in result.shared_images:
            environments = ", ".join(f"`{item}`" for item in sorted(image.environments))
            lines.append(f"- **`{image.name}`** environments: {environments}")
            image_decisions = [
                decision
                for combination in assigned_combinations
                for decision in combination.raw.image_decisions
                if decision.image == image.name
            ]
            if image_decisions:
                decision_text = "; ".join(
                    f"image version `{decision.version}`" for decision in image_decisions
                )
                lines.append(f"  - image tag/version: {decision_text}")
            packages = set(image.packages)
            if not packages:
                packages = {
                    change.package
                    for combination in assigned_combinations
                    for change in combination.changes
                }
            for package in sorted(packages):
                decisions: list[str] = []
                for combination in assigned_combinations:
                    for change in combination.changes:
                        if change.package != package or not change.to_version:
                            continue
                        if change.environments & image.environments:
                            decisions.append(
                                f"`{change.to_version}` from `{combination.raw.id}` "
                                "on "
                                + ", ".join(
                                    f"`{environment}`"
                                    for environment in sorted(
                                        change.environments & image.environments
                                    )
                                )
                            )
                decision_text = "; ".join(decisions) or "no selected target decision"
                lines.append(f"  - `{package}`: {decision_text}")
    else:
        lines.append("- No shared image consistency constraints were declared.")

    lines.extend(["", "## 无法分配的冲突条件 / Unassignable conflicts", ""])
    if result.conflicts:
        for conflict in result.conflicts:
            location = ", ".join(
                f"`{value}`" for value in (conflict.combination_id, conflict.group) if value
            )
            prefix = (
                f"- **`{conflict.code}`**{f' [{location}]' if location else ''}: {conflict.message}"
            )
            lines.append(prefix)
    else:
        lines.append("- No allocation conflict.")

    lines.extend(
        [
            "",
            "## 逐告警抢名额预演 / Why alert-by-alert grabbing fails",
            "",
            (
                f"Naive alert grabbing claims {result.summary['greedy_claimed_alert_count']} "
                f"alert(s) and hits {result.summary['greedy_failure_count']} capacity/scope failure(s). "
                "It does not understand that several alerts can be one atomic combination costing one slot."
            ),
            "",
            "| Alert | Environments | Grabbed group | Result | Reason |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    lines.extend(
        f"| `{claim.alert_key}` | {', '.join(f'`{item}`' for item in claim.environments) or '-'} | "
        f"{f'`{claim.group}`' if claim.group else '-'} | `{claim.status}` | {claim.reason or ''} |"
        for claim in result.greedy.claims
    )

    lines.extend(["", "## 排班范围 / Group responsibility scope", ""])
    for group in result.groups:
        scopes = (
            "; ".join(
                "`*`"
                if scope.package is None
                else (
                    f"`{scope.package}`@`{','.join(sorted(scope.lines))}`"
                    if scope.lines
                    else f"`{scope.package}`"
                )
                for scope in group.scopes
            )
            or "no package scope"
        )
        lines.append(
            f"- `{group.name}` ({group.owner or 'unassigned owner'}): capacity `{group.capacity}`, "
            f"cross-environment `{group.cross_environment}`, scope: {scopes}"
        )

    return "\n".join(lines).rstrip() + "\n"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pip-audit-allocation-drill",
        description="Offline pip-audit remediation allocation drill",
    )
    parser.add_argument("--audit-result", type=Path, required=True, help="pip-audit JSON result")
    parser.add_argument(
        "--allocation-plan", type=Path, required=True, help="local TOML/JSON plan table"
    )
    parser.add_argument(
        "--pylock",
        type=Path,
        action="append",
        dest="pylocks",
        default=[],
        help="pylock environment file; repeatable",
    )
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("-o", "--output", type=Path, default=None)
    parser.add_argument(
        "--check", action="store_true", help="exit non-zero when allocation conflicts remain"
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the standalone allocation drill CLI."""
    args = _parser().parse_args(argv)
    if not args.pylocks:
        raise AllocationDrillError("at least one --pylock file is required")
    result = run_drill(args.audit_result, args.pylocks, args.allocation_plan)
    output = render_json(result) if args.format == "json" else render_markdown(result)
    if args.output is None or str(args.output) == "-":
        print(output)
    else:
        args.output.write_text(output)
    if args.check and result.status == "conflicts":
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    try:
        sys.exit(main())
    except AllocationDrillError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(2)
