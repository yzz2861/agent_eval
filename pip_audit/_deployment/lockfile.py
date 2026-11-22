"""
Read PEP 751 lock files for deployment-stage review.

Unlike `pip_audit._dependency_source.pylock.PyLockSource`, which only yields
name/version pairs for auditing, this reader keeps the stage-relevant
evidence attached to each package:

* the dependency groups the package belongs to,
* the per-package environment marker (if any),
* the visible artifacts (wheels/sdists) recorded in the lock file.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import tomli
from packaging.markers import InvalidMarker, Marker
from packaging.utils import canonicalize_name
from packaging.version import Version


class StageLockfileError(Exception):
    """Raised when a stage lock file cannot be parsed or validated."""


@dataclass(frozen=True)
class Artifact:
    """
    A single visible artifact recorded for a locked package.
    """

    filename: str
    url: str | None
    sha256: str | None
    size: int | None


@dataclass(frozen=True)
class LockedPackage:
    """
    A package entry in a stage lock file, together with the evidence that
    determines whether it is selected for a given stage.
    """

    name: str
    version: Version | None
    dependency_groups: tuple[str, ...]
    marker: Marker | None
    marker_raw: str | None
    artifacts: tuple[Artifact, ...]
    skip_reason: str | None

    @property
    def canonical_name(self) -> str:
        return canonicalize_name(self.name)

    @property
    def is_skipped(self) -> bool:
        return self.version is None

    def selected_for(self, environment: dict[str, str] | None) -> bool:
        """
        Return whether the package is selected under `environment`.

        A package without a marker is always selected. A package with a
        marker is selected only when the marker evaluates against the
        supplied environment.
        """

        if self.marker is None:
            return True
        if environment is None:
            return False
        return bool(self.marker.evaluate(environment))


@dataclass(frozen=True)
class StageLockfile:
    """
    A parsed lock file bound to a deployment role.
    """

    role: str
    path: Path
    environments: tuple[str, ...]
    requires_python: str | None
    packages: tuple[LockedPackage, ...] = field(default_factory=tuple)


def _parse_artifacts(package: dict) -> tuple[Artifact, ...]:
    artifacts: list[Artifact] = []
    for wheel in package.get("wheels", []):
        hashes = wheel.get("hashes", {})
        artifacts.append(
            Artifact(
                filename=wheel.get("name", ""),
                url=wheel.get("url"),
                sha256=hashes.get("sha256"),
                size=wheel.get("size"),
            )
        )
    for sdist in package.get("sdists", []):
        hashes = sdist.get("hashes", {})
        artifacts.append(
            Artifact(
                filename=sdist.get("name", ""),
                url=sdist.get("url"),
                sha256=hashes.get("sha256"),
                size=sdist.get("size"),
            )
        )
    return tuple(artifacts)


def _parse_package(idx: int, package: dict) -> LockedPackage:
    name = package.get("name")
    if not name:
        raise StageLockfileError(f"invalid package #{idx}: no name")

    raw_version = package.get("version")
    version: Version | None
    skip_reason: str | None
    if raw_version:
        version = Version(raw_version)
        skip_reason = None
    else:
        # Mirror pip-audit's PEP 751 behavior: source-tree pins without a
        # version cannot be audited and are recorded as skipped.
        version = None
        skip_reason = "no version specified"

    marker_raw = package.get("marker")
    marker: Marker | None = None
    if marker_raw is not None:
        try:
            marker = Marker(marker_raw)
        except InvalidMarker as e:
            raise StageLockfileError(
                f"invalid package #{idx} ({name}): invalid marker {marker_raw!r}"
            ) from e

    groups = tuple(package.get("dependency-groups", []))
    return LockedPackage(
        name=name,
        version=version,
        dependency_groups=groups,
        marker=marker,
        marker_raw=marker_raw,
        artifacts=_parse_artifacts(package),
        skip_reason=skip_reason,
    )


def read_stage_lockfile(role: str, filename: Path) -> StageLockfile:
    """
    Parse a PEP 751 lock file and bind it to the deployment `role`.

    Raises `StageLockfileError` on any parse or validation error.
    """

    try:
        with filename.open(mode="rb") as f:
            pylock = tomli.load(f)
    except FileNotFoundError as e:
        raise StageLockfileError(f"{filename}: lockfile not found") from e
    except tomli.TOMLDecodeError as e:
        raise StageLockfileError(f"{filename}: invalid TOML in lockfile") from e

    lock_version = pylock.get("lock-version")
    if not lock_version:
        raise StageLockfileError(f"{filename}: missing lock-version in lockfile")

    parsed_lock_version = Version(lock_version)
    if parsed_lock_version.major != 1:
        raise StageLockfileError(
            f"{filename}: lockfile version {parsed_lock_version} is not supported"
        )

    packages = pylock.get("packages")
    if not packages:
        raise StageLockfileError(f"{filename}: missing packages in lockfile")

    locked_packages = tuple(_parse_package(idx, package) for idx, package in enumerate(packages))
    return StageLockfile(
        role=role,
        path=filename,
        environments=tuple(pylock.get("environments", [])),
        requires_python=pylock.get("requires-python"),
        packages=locked_packages,
    )
