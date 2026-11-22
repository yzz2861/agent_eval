"""
Offline advisory service for deployment-stage review.

This service implements pip-audit's `VulnerabilityService` interface but
never touches the network: it reads a frozen advisory snapshot (the kind
produced by an air-gapped `pip-audit` run) and answers queries from it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from packaging.utils import canonicalize_name
from packaging.version import Version

from pip_audit._service.interface import (
    Dependency,
    ResolvedDependency,
    SkippedDependency,
    VulnerabilityResult,
    VulnerabilityService,
)


class OfflineAdvisoryServiceError(Exception):
    """Raised when the offline advisory snapshot cannot be loaded."""


@dataclass(frozen=True)
class OfflineAdvisory:
    """A single advisory record from the frozen offline snapshot."""

    id: str
    package: str
    version: Version
    aliases: frozenset[str]
    fix_versions: tuple[Version, ...]
    description: str

    @property
    def canonical_package(self) -> str:
        return canonicalize_name(self.package)


class OfflineAdvisoryService(VulnerabilityService):
    """
    A `VulnerabilityService` backed by an offline advisory snapshot.

    The snapshot is a JSON document with an ``advisories`` array. Each
    advisory pins a package name and version, mirroring the per-package
    results of an offline `pip-audit` audit.
    """

    SCHEMA = "pip-audit-offline-review/v1"

    def __init__(self, snapshot_path: Path) -> None:
        self._snapshot_path = snapshot_path
        self._advisories = self._load(snapshot_path)

    @property
    def advisories(self) -> tuple[OfflineAdvisory, ...]:
        return tuple(self._advisories)

    def _load(self, snapshot_path: Path) -> list[OfflineAdvisory]:
        try:
            with snapshot_path.open(mode="r", encoding="utf-8") as f:
                raw = json.load(f)
        except FileNotFoundError as e:
            raise OfflineAdvisoryServiceError(
                f"{snapshot_path}: advisory snapshot not found"
            ) from e
        except json.JSONDecodeError as e:
            raise OfflineAdvisoryServiceError(
                f"{snapshot_path}: invalid JSON in advisory snapshot"
            ) from e

        schema = raw.get("schema")
        if schema != self.SCHEMA:
            raise OfflineAdvisoryServiceError(
                f"{snapshot_path}: unsupported schema {schema!r}, expected {self.SCHEMA!r}"
            )

        advisories: list[OfflineAdvisory] = []
        for idx, entry in enumerate(raw.get("advisories", [])):
            try:
                advisories.append(
                    OfflineAdvisory(
                        id=entry["id"],
                        package=entry["package"],
                        version=Version(entry["version"]),
                        aliases=frozenset(entry.get("aliases", [])),
                        fix_versions=tuple(
                            Version(v) for v in entry.get("fix_versions", [])
                        ),
                        description=entry.get("description", ""),
                    )
                )
            except KeyError as e:
                raise OfflineAdvisoryServiceError(
                    f"{snapshot_path}: advisory #{idx} missing field {e.args[0]!r}"
                ) from e

        return advisories

    def query(
        self, spec: Dependency
    ) -> tuple[Dependency, list[VulnerabilityResult]]:
        """
        Answer an audit query from the offline snapshot.

        See `VulnerabilityService.query`.
        """

        if spec.is_skipped():
            return spec, []
        spec = ResolvedDependency(
            name=spec.name, version=Version(str(spec.version))
        )

        results: list[VulnerabilityResult] = []
        for advisory in self._advisories:
            if (
                advisory.canonical_package == spec.canonical_name
                and advisory.version == spec.version
            ):
                results.append(
                    VulnerabilityResult(
                        id=advisory.id,
                        description=advisory.description,
                        fix_versions=list(advisory.fix_versions),
                        aliases=set(advisory.aliases),
                    )
                )

        return spec, results

    def advisory_for(
        self, name: str, version: Version
    ) -> tuple[OfflineAdvisory, ...]:
        """Return every raw offline advisory for a package/version pair."""

        canonical = canonicalize_name(name)
        return tuple(
            advisory
            for advisory in self._advisories
            if advisory.canonical_package == canonical
            and advisory.version == version
        )

    def skipped_result(self, spec: SkippedDependency) -> tuple[Dependency, list]:
        """Pass through a pip-audit skipped dependency unchanged."""

        return spec, []
