"""
Offline, snapshot-based vulnerability service.

A freeze fixture is an advisory snapshot with an explicit coverage list.  Unlike a
live service, a freeze fixture can tell the difference between "there are no
advisories for this package" and "this snapshot does not make a judgment about
this package".  The latter is represented as an ``unknown`` query result and is
kept unknown throughout differential attribution.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from pip_audit._service.interface import (
    Dependency,
    ResolvedDependency,
    ServiceError,
    VulnerabilityID,
    VulnerabilityResult,
    VulnerabilityService,
)

logger = logging.getLogger(__name__)


def _version_matches(version: Version, versions: frozenset[str]) -> bool:
    """Compare a parsed version against a fixture's version strings."""
    if str(version) in versions:
        return True
    for raw_version in versions:
        try:
            if Version(raw_version) == version:
                return True
        except InvalidVersion:
            continue
    return False


class FreezeFixtureError(ServiceError):
    """Raised when an offline advisory fixture is invalid."""


@dataclass(frozen=True)
class _VersionRange:
    """A half-open version range, as used by OSV ``ECOSYSTEM`` ranges."""

    introduced: Version | None
    fixed: Version | None
    last_affected: Version | None = None

    def contains(self, version: Version) -> bool:
        """Return whether ``version`` falls inside this range."""
        if self.introduced is not None and version < self.introduced:
            return False
        if self.fixed is not None and version >= self.fixed:
            return False
        if self.last_affected is not None and version > self.last_affected:
            return False
        return True


@dataclass(frozen=True)
class FreezeAdvisory:
    """A single advisory entry from a freeze fixture."""

    id: str
    package: str
    aliases: tuple[str, ...] = ()
    versions: frozenset[str] = frozenset()
    ranges: tuple[_VersionRange, ...] = ()
    fix_versions: tuple[Version, ...] = ()
    description: str = "N/A"

    def affects(self, version: Version) -> bool:
        """Return whether this advisory affects ``version``."""
        if self.versions and _version_matches(version, self.versions):
            return True
        if self.ranges and any(version_range.contains(version) for version_range in self.ranges):
            return True
        # An entry with no version constraint is treated as affecting every
        # version that the snapshot explicitly covers.
        return not self.versions and not self.ranges

    def to_result(self) -> VulnerabilityResult:
        """Convert this advisory into a regular ``VulnerabilityResult``."""
        return VulnerabilityResult.create(
            ids=cast(list[VulnerabilityID], [self.id, *self.aliases]),
            description=self.description,
            fix_versions=list(self.fix_versions),
            published=None,
        )


@dataclass(frozen=True)
class FreezeSnapshot:
    """The parsed contents of an offline advisory snapshot."""

    name: str | None
    coverage: Mapping[str, frozenset[str] | None]
    advisories: Mapping[str, tuple[FreezeAdvisory, ...]]

    def covers(self, package: str, version: str) -> bool:
        """Return whether the snapshot makes a judgment about ``package``/``version``."""
        if "*" in self.coverage:
            return True
        if package not in self.coverage:
            return False
        versions = self.coverage[package]
        # ``None`` means every version of the package is covered.
        if versions is None:
            return True
        try:
            return _version_matches(Version(version), versions)
        except InvalidVersion:
            return version in versions

    def advisories_for(self, package: str, version: Version) -> tuple[FreezeAdvisory, ...]:
        """Return all matching advisories for ``package``/``version``."""
        return tuple(
            advisory
            for advisory in self.advisories.get(package, ())
            if advisory.affects(version)
        )


@dataclass(frozen=True)
class FreezeQuery:
    """The result of a freeze query, including whether a judgment was made."""

    dependency: Dependency
    status: Literal["audited", "unknown"]
    vulnerabilities: tuple[VulnerabilityResult, ...] = ()
    reason: str | None = None

    @property
    def is_unknown(self) -> bool:
        """Return whether the snapshot declined to judge this dependency."""
        return self.status == "unknown"


def _canonical_name(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise FreezeFixtureError("freeze fixture contains a package without a valid name")
    return canonicalize_name(value)


def _parse_version(value: Any) -> Version:
    try:
        return Version(str(value))
    except InvalidVersion as exc:
        raise FreezeFixtureError(f"freeze fixture contains an invalid version: {value!r}") from exc


def _parse_versions(value: Any) -> frozenset[str]:
    if value is None:
        return frozenset()
    if isinstance(value, str):
        if value == "*":
            return frozenset()
        return frozenset({value})
    if not isinstance(value, Sequence):
        raise FreezeFixtureError(f"expected a version list, got: {value!r}")
    return frozenset(str(version) for version in value)


def _parse_ranges(value: Any) -> tuple[_VersionRange, ...]:
    if value is None:
        return ()
    if not isinstance(value, Sequence):
        raise FreezeFixtureError(f"expected a range list, got: {value!r}")

    ranges: list[_VersionRange] = []
    for raw_range in value:
        if not isinstance(raw_range, Mapping):
            raise FreezeFixtureError(f"expected an advisory range object, got: {raw_range!r}")
        events = raw_range.get("events")
        if events is None:
            # A compact range object is also accepted: {"introduced": ..., "fixed": ...}.
            events = [raw_range]
        if not isinstance(events, Sequence):
            raise FreezeFixtureError(f"expected an advisory event list, got: {events!r}")

        introduced: Version | None = None
        for event in events:
            if not isinstance(event, Mapping):
                raise FreezeFixtureError(f"expected an advisory event object, got: {event!r}")
            if "introduced" in event:
                raw_introduced = event["introduced"]
                introduced = None if str(raw_introduced) == "0" else _parse_version(raw_introduced)
            if "fixed" in event:
                ranges.append(
                    _VersionRange(introduced=introduced, fixed=_parse_version(event["fixed"]))
                )
                introduced = None
            if "last_affected" in event:
                ranges.append(
                    _VersionRange(
                        introduced=introduced,
                        fixed=None,
                        last_affected=_parse_version(event["last_affected"]),
                    )
                )
                introduced = None
        if introduced is not None:
            ranges.append(_VersionRange(introduced=introduced, fixed=None))
    return tuple(ranges)


def _parse_fix_versions(raw: Any, ranges: Iterable[_VersionRange]) -> tuple[Version, ...]:
    versions: set[Version] = set()
    if raw is not None:
        if isinstance(raw, str):
            versions.add(_parse_version(raw))
        elif isinstance(raw, Sequence):
            versions.update(_parse_version(version) for version in raw)
        else:
            raise FreezeFixtureError(f"expected a fix version list, got: {raw!r}")
    for version_range in ranges:
        if version_range.fixed is not None:
            versions.add(version_range.fixed)
    return tuple(sorted(versions))


def _parse_advisory(raw: Mapping[str, Any], package: str) -> FreezeAdvisory:
    advisory_id = raw.get("id")
    if not isinstance(advisory_id, str) or not advisory_id:
        raise FreezeFixtureError("freeze fixture contains an advisory without an id")

    raw_aliases = raw.get("aliases") or []
    if not isinstance(raw_aliases, Sequence) or isinstance(raw_aliases, str):
        raise FreezeFixtureError(f"advisory {advisory_id} has an invalid alias list")

    ranges = _parse_ranges(raw.get("ranges"))
    description = raw.get("description")
    if description is None:
        description = raw.get("summary") or raw.get("details") or "N/A"
    description = str(description).replace("\n", " ")

    return FreezeAdvisory(
        id=advisory_id,
        package=package,
        aliases=tuple(sorted(str(alias) for alias in raw_aliases)),
        versions=_parse_versions(raw.get("versions", raw.get("affected_versions"))),
        ranges=ranges,
        fix_versions=_parse_fix_versions(raw.get("fix_versions"), ranges),
        description=description,
    )


def _parse_coverage(raw: Any) -> dict[str, frozenset[str] | None]:
    if raw is None:
        return {}
    if isinstance(raw, str):
        return {_canonical_name(raw): None}
    coverage: dict[str, frozenset[str] | None] = {}

    def add(name: Any, spec: Any) -> None:
        package = _canonical_name(name)
        if spec is None or spec is True or spec == "*":
            coverage[package] = None
            return
        if isinstance(spec, Mapping):
            spec = spec.get("versions", spec.get("affected_versions"))
        if spec is None or spec == "*":
            coverage[package] = None
            return
        versions = _parse_versions(spec)
        coverage[package] = versions

    if isinstance(raw, Mapping):
        for name, spec in raw.items():
            add(name, spec)
        return coverage
    if isinstance(raw, Sequence) and not isinstance(raw, str):
        for entry in raw:
            if isinstance(entry, str):
                add(entry, None)
            elif isinstance(entry, Mapping):
                add(entry.get("name"), entry)
            else:
                raise FreezeFixtureError(f"invalid coverage entry: {entry!r}")
        return coverage
    raise FreezeFixtureError(f"invalid coverage section: {raw!r}")


def _advisories_from_affected(raw: Mapping[str, Any]) -> list[tuple[str, Mapping[str, Any]]]:
    """Expand an OSV-style ``affected`` list into ``(package, advisory)`` pairs."""
    affected = raw.get("affected")
    if affected is None:
        return []
    if not isinstance(affected, Sequence) or isinstance(affected, str):
        raise FreezeFixtureError(f"advisory {raw.get('id')!r} has an invalid affected list")

    pairs: list[tuple[str, Mapping[str, Any]]] = []
    for affected_entry in affected:
        if not isinstance(affected_entry, Mapping):
            continue
        package_spec = affected_entry.get("package")
        if isinstance(package_spec, Mapping):
            name = package_spec.get("name")
        else:
            name = package_spec
        if name is None:
            continue
        entry = dict(raw)
        entry.pop("affected", None)
        entry["versions"] = affected_entry.get("versions", [])
        entry["ranges"] = affected_entry.get("ranges", [])
        pairs.append((_canonical_name(name), entry))
    return pairs


def _parse_advisories(raw: Any) -> dict[str, list[FreezeAdvisory]]:
    advisories: dict[str, list[FreezeAdvisory]] = {}
    if raw is None:
        return advisories
    if isinstance(raw, Mapping):
        raw = [raw]
    if not isinstance(raw, Sequence) or isinstance(raw, str):
        raise FreezeFixtureError("freeze fixture advisories must be a list")

    def add(package: str, advisory: FreezeAdvisory) -> None:
        advisories.setdefault(package, []).append(advisory)

    for entry in raw:
        if not isinstance(entry, Mapping):
            raise FreezeFixtureError(f"invalid advisory entry: {entry!r}")
        if entry.get("withdrawn") is not None:
            logger.debug(f"skipping withdrawn advisory {entry.get('id')!r}")
            continue
        package = entry.get("package")
        if isinstance(package, Mapping):
            package = package.get("name")
        if package is not None:
            add(_canonical_name(package), _parse_advisory(entry, _canonical_name(package)))
            continue
        pairs = _advisories_from_affected(entry)
        if not pairs:
            logger.warning(f"skipping advisory {entry.get('id')!r}: no package information")
            continue
        for pair_package, pair_entry in pairs:
            add(pair_package, _parse_advisory(pair_entry, pair_package))
    return advisories


def _parse_package_section(raw: Any) -> dict[str, list[FreezeAdvisory]]:
    """Parse an optional ``packages`` mapping with nested advisories."""
    advisories: dict[str, list[FreezeAdvisory]] = {}
    if raw is None:
        return advisories
    if not isinstance(raw, Mapping):
        raise FreezeFixtureError("freeze fixture packages section must be an object")
    for name, spec in raw.items():
        if not isinstance(spec, Mapping):
            continue
        package = _canonical_name(name)
        entries = spec.get("advisories") or []
        if not isinstance(entries, Sequence) or isinstance(entries, str):
            raise FreezeFixtureError(f"package {package} has an invalid advisories list")
        for entry in entries:
            if isinstance(entry, Mapping):
                advisories.setdefault(package, []).append(_parse_advisory(entry, package))
    return advisories


def snapshot_from_dict(
    data: Mapping[str, Any] | Sequence[Any], *, name: str | None = None
) -> FreezeSnapshot:
    """Parse a freeze snapshot from a mapping."""
    if isinstance(data, Sequence) and not isinstance(data, (str, bytes, Mapping)):
        data = {"advisories": list(data)}
    if not isinstance(data, Mapping):
        raise FreezeFixtureError("freeze fixture must be a JSON object")

    snapshot_name = data.get("snapshot") or data.get("name") or name

    advisories = _parse_advisories(data.get("advisories", data.get("vulnerabilities")))
    for package, package_advisories in _parse_package_section(data.get("packages")).items():
        advisories.setdefault(package, []).extend(package_advisories)

    raw_coverage = data.get("coverage", data.get("covered", data.get("covered_packages")))
    if raw_coverage is None and isinstance(data.get("packages"), Mapping):
        raw_coverage = data["packages"]
    coverage = _parse_coverage(raw_coverage)

    # If the fixture has no explicit coverage section, only packages that appear
    # in an advisory have a judgment.  Everything else stays unknown instead of
    # silently being treated as clean.
    if not coverage:
        for package in advisories:
            coverage[package] = None

    return FreezeSnapshot(
        name=str(snapshot_name) if snapshot_name is not None else None,
        coverage=coverage,
        advisories={package: tuple(entries) for package, entries in advisories.items()},
    )


def load_freeze_snapshot(
    source: Path | str | Mapping[str, Any] | Sequence[Any], *, name: str | None = None
) -> FreezeSnapshot:
    """Load a freeze snapshot from a JSON file or an already-parsed mapping."""
    if not isinstance(source, (str, Path)):
        return snapshot_from_dict(source, name=name)

    path = Path(source)
    try:
        data = json.loads(path.read_text())
    except OSError as exc:
        raise FreezeFixtureError(f"could not read freeze fixture {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise FreezeFixtureError(f"invalid JSON in freeze fixture {path}: {exc}") from exc
    if isinstance(data, Sequence) and not isinstance(data, (str, bytes, Mapping)):
        data = {"advisories": list(data)}
    if not isinstance(data, Mapping):
        raise FreezeFixtureError(f"freeze fixture {path} must contain a JSON object")
    return snapshot_from_dict(data, name=name or path.stem)


class FreezeService(VulnerabilityService):
    """A vulnerability service backed by an immutable, offline advisory snapshot."""

    def __init__(
        self,
        fixture: Path | str | Mapping[str, Any] | Sequence[Any],
        *,
        name: str | None = None,
    ) -> None:
        """Load a freeze fixture and make it queryable."""
        self.snapshot = load_freeze_snapshot(fixture, name=name)

    @property
    def snapshot_name(self) -> str | None:
        """Return the human-readable snapshot name, if the fixture has one."""
        return self.snapshot.name

    def query_with_status(self, spec: Dependency) -> FreezeQuery:
        """Query the snapshot and preserve whether it actually made a judgment."""
        if spec.is_skipped():
            return FreezeQuery(
                dependency=spec,
                status="unknown",
                reason="dependency was skipped before querying the advisory snapshot",
            )

        dependency = cast(ResolvedDependency, spec)
        if not self.snapshot.covers(dependency.canonical_name, str(dependency.version)):
            snapshot = self.snapshot.name or "freeze snapshot"
            return FreezeQuery(
                dependency=dependency,
                status="unknown",
                reason=(
                    f"{snapshot} has no judgment for "
                    f"{dependency.canonical_name}=={dependency.version}"
                ),
            )

        results = tuple(
            advisory.to_result()
            for advisory in self.snapshot.advisories_for(
                dependency.canonical_name, dependency.version
            )
        )
        return FreezeQuery(dependency=dependency, status="audited", vulnerabilities=results)

    def query(self, spec: Dependency) -> tuple[Dependency, list[VulnerabilityResult]]:
        """Query the snapshot, mapping unknown results to an empty list."""
        result = self.query_with_status(spec)
        return spec, list(result.vulnerabilities)

    def query_status(self, spec: Dependency) -> FreezeQuery:
        """Alias for :meth:`query_with_status`."""
        return self.query_with_status(spec)


# Helpful aliases for callers that use a different noun for a frozen service.
FrozenService = FreezeService
OfflineAdvisoryService = FreezeService
load_freeze_fixture = load_freeze_snapshot

__all__ = [
    "FreezeAdvisory",
    "FreezeFixtureError",
    "FreezeQuery",
    "FreezeService",
    "FreezeSnapshot",
    "FrozenService",
    "OfflineAdvisoryService",
    "load_freeze_fixture",
    "load_freeze_snapshot",
    "snapshot_from_dict",
]
