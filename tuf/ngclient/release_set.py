"""Release-set resolution on top of the TUF client workflow.

This module implements atomic *release-set* validation for updaters that
ship multiple components: individual target files may each be verified by
TUF metadata, yet still form an unusable combination when they originate
from incompatible releases.

A release-set is described by a *manifest*: a JSON document that is itself
distributed as a TUF target. The manifest lists every component of the
release-set together with the target path, the expected sha256 digest and
the compatibility conditions between component versions.

``ReleaseSetResolver`` resolves a manifest inside a single trusted
metadata view: all component target infos are loaded and verified against
the same snapshot, and a complete download plan is produced only if every
component is present, every digest matches the signed targets metadata and
all compatibility conditions hold. If resolution fails -- for example
because the repository published a new snapshot mid-resolution, a
delegation became invalid or a component is missing -- no partial plan is
returned and the previously activated plan (if any) is left untouched.

The manifest is always fetched and verified through the TUF client
workflow: callers only provide the manifest target path and cannot inject
manifest content or hashes that would bypass signature verification.

Manifest format::

    {
      "release_set": "product-2026.11",
      "components": [
        {
          "name": "app",
          "path": "pkgs/app-2.0.tar.gz",
          "sha256": "<64 hex chars>",
          "version": "2.0",
          "requires": {"lib": ">=2.0,<3.0"}
        }
      ]
    }

``requires`` maps the name of another component in the same manifest to a
comma separated list of version clauses. Supported clause operators are
``==``, ``!=``, ``>=``, ``<=``, ``>`` and ``<``. Versions are compared as
dot-separated integers (``2.0`` equals ``2.0.0``).
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from tuf.api import exceptions
from tuf.ngclient.updater import Updater

if TYPE_CHECKING:
    from tuf.api.metadata import TargetFile
    from tuf.ngclient.config import UpdaterConfig
    from tuf.ngclient.fetcher import FetcherInterface

logger = logging.getLogger(__name__)


class ReleaseSetError(exceptions.RepositoryError):
    """Release-set resolution failed: no usable plan was produced."""


def _parse_version(version: str) -> tuple[int, ...]:
    """Parse a dot-separated integer version into a comparable tuple."""
    parts = version.split(".")
    if not parts or any(not part.isdigit() for part in parts):
        raise ReleaseSetError(f"Invalid version string: '{version}'")
    return tuple(int(part) for part in parts)


def _compare_versions(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    """Compare version tuples, padding the shorter one with zeros."""
    length = max(len(left), len(right))
    padded_left = left + (0,) * (length - len(left))
    padded_right = right + (0,) * (length - len(right))
    if padded_left < padded_right:
        return -1
    if padded_left > padded_right:
        return 1
    return 0


_OPERATORS = (">=", "<=", "==", "!=", ">", "<")


def version_satisfies(version: str, specifier: str) -> bool:
    """Return True if ``version`` matches every clause in ``specifier``.

    ``specifier`` is a comma separated list of clauses such as
    ``">=2.0,<3.0"``. Raises ``ReleaseSetError`` on malformed input.
    """
    parsed_version = _parse_version(version)
    for raw_clause in specifier.split(","):
        clause = raw_clause.strip()
        operator = next(
            (op for op in _OPERATORS if clause.startswith(op)), None
        )
        if operator is None:
            raise ReleaseSetError(f"Invalid version clause: '{clause}'")
        bound = _parse_version(clause[len(operator) :])
        comparison = _compare_versions(parsed_version, bound)
        satisfied = {
            "==": comparison == 0,
            "!=": comparison != 0,
            ">=": comparison >= 0,
            "<=": comparison <= 0,
            ">": comparison > 0,
            "<": comparison < 0,
        }[operator]
        if not satisfied:
            return False
    return True


@dataclass(frozen=True)
class ComponentSpec:
    """One component entry of a release-set manifest."""

    name: str
    path: str
    sha256: str
    version: str
    requires: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ReleaseManifest:
    """Parsed and validated release-set manifest."""

    name: str
    components: tuple[ComponentSpec, ...]

    @classmethod
    def from_bytes(cls, data: bytes) -> ReleaseManifest:
        """Parse and validate a manifest, raise ``ReleaseSetError`` if bad."""
        try:
            doc = json.loads(data)
        except ValueError as e:
            raise ReleaseSetError(f"Manifest is not valid JSON: {e}") from e

        if not isinstance(doc, dict):
            raise ReleaseSetError("Manifest must be a JSON object")
        name = doc.get("release_set")
        raw_components = doc.get("components")
        if not isinstance(name, str) or not name:
            raise ReleaseSetError("Manifest 'release_set' must be a string")
        if not isinstance(raw_components, list) or not raw_components:
            raise ReleaseSetError("Manifest 'components' must be a list")

        components = []
        seen_names: set[str] = set()
        for entry in raw_components:
            spec = cls._parse_component(entry)
            if spec.name in seen_names:
                raise ReleaseSetError(f"Duplicate component name '{spec.name}'")
            seen_names.add(spec.name)
            components.append(spec)

        return cls(name, tuple(components))

    @staticmethod
    def _parse_component(entry: object) -> ComponentSpec:
        if not isinstance(entry, dict):
            raise ReleaseSetError("Component entries must be objects")
        name = entry.get("name")
        path = entry.get("path")
        sha256 = entry.get("sha256")
        version = entry.get("version")
        requires = entry.get("requires", {})
        if not isinstance(name, str) or not name:
            raise ReleaseSetError("Component 'name' must be a string")
        if not isinstance(path, str) or not path:
            raise ReleaseSetError(
                f"Component '{name}': 'path' must be a string"
            )
        if (
            not isinstance(sha256, str)
            or len(sha256) != 64
            or any(c not in "0123456789abcdef" for c in sha256)
        ):
            raise ReleaseSetError(
                f"Component '{name}': 'sha256' must be 64 hex chars"
            )
        if not isinstance(version, str):
            raise ReleaseSetError(
                f"Component '{name}': 'version' must be a string"
            )
        _parse_version(version)
        if not isinstance(requires, dict) or not all(
            isinstance(k, str) and isinstance(v, str)
            for k, v in requires.items()
        ):
            raise ReleaseSetError(
                f"Component '{name}': 'requires' must map names to strings"
            )
        return ComponentSpec(name, path, sha256, version, dict(requires))


@dataclass(frozen=True)
class ComponentPlan:
    """A resolved component: manifest spec plus verified target info."""

    spec: ComponentSpec
    targetinfo: TargetFile


@dataclass(frozen=True)
class ReleasePlan:
    """A complete, fully verified download plan for a release-set."""

    manifest_path: str
    release_set: str
    snapshot_version: int
    components: tuple[ComponentPlan, ...]


class ReleaseSetResolver:
    """Resolves release-set manifests into verified download plans.

    The resolver owns the *active plan*: the last release-set that was
    resolved successfully. A failed ``resolve()`` never modifies the
    active plan, so a previously activated release-set remains usable.

    Every ``resolve()`` builds a fresh ``Updater`` on the shared local
    cache, so each resolution happens inside one consistent trusted
    metadata view while still observing newly published repository state.

    Args are passed through to ``Updater``: see its documentation.
    """

    def __init__(
        self,
        metadata_dir: str,
        metadata_base_url: str,
        target_dir: str | None = None,
        target_base_url: str | None = None,
        fetcher: FetcherInterface | None = None,
        config: UpdaterConfig | None = None,
        *,
        bootstrap: bytes | None,
    ):
        self._metadata_dir = metadata_dir
        self._metadata_base_url = metadata_base_url
        self._target_dir = target_dir
        self._target_base_url = target_base_url
        self._fetcher = fetcher
        self._config = config
        self._bootstrap = bootstrap
        self._active_plan: ReleasePlan | None = None

    @property
    def active_plan(self) -> ReleasePlan | None:
        """The last successfully resolved plan, or None."""
        return self._active_plan

    def _new_updater(self) -> Updater:
        return Updater(
            self._metadata_dir,
            self._metadata_base_url,
            self._target_dir,
            self._target_base_url,
            self._fetcher,
            self._config,
            bootstrap=self._bootstrap,
        )

    def resolve(self, manifest_path: str) -> ReleasePlan:
        """Resolve ``manifest_path`` into a complete download plan.

        The manifest is downloaded and verified as a regular TUF target:
        its integrity is anchored in signed targets metadata. All
        components are resolved inside the same trusted metadata view.

        On success the returned plan becomes the active plan. On any
        failure ``ReleaseSetError`` is raised, no plan is returned and
        the previously active plan is left unchanged.

        Args:
            manifest_path: Target path of the release-set manifest.

        Raises:
            ReleaseSetError: Resolution failed for any reason.
            OSError: Local metadata or target cache could not be written.
        """
        updater = self._new_updater()
        try:
            plan = self._resolve_with(updater, manifest_path)
        except ReleaseSetError:
            raise
        except (exceptions.RepositoryError, exceptions.DownloadError) as e:
            raise ReleaseSetError(
                f"Failed to resolve release-set '{manifest_path}': {e}"
            ) from e

        self._active_plan = plan
        logger.info(
            "Activated release-set '%s' (%d components)",
            plan.release_set,
            len(plan.components),
        )
        return plan

    def _resolve_with(
        self, updater: Updater, manifest_path: str
    ) -> ReleasePlan:
        updater.refresh()
        trusted = updater._trusted_set  # noqa: SLF001
        snapshot_version = trusted.snapshot.version
        timestamp_version = trusted.timestamp.version

        manifest_info = updater.get_targetinfo(manifest_path)
        if manifest_info is None:
            raise ReleaseSetError(
                f"Manifest '{manifest_path}' is not a TUF-authorized target"
            )

        with tempfile.TemporaryDirectory() as tmp_dir:
            manifest_file = updater.download_target(
                manifest_info, os.path.join(tmp_dir, "manifest.json")
            )
            with open(manifest_file, "rb") as f:
                manifest_data = f.read()

        manifest = ReleaseManifest.from_bytes(manifest_data)

        plans = []
        for spec in manifest.components:
            plans.append(self._resolve_component(updater, spec))

        self._check_compatibility(manifest)

        # The trusted view must not have changed while resolving: a new
        # snapshot or timestamp mid-resolution means the plan could mix
        # metadata from two repository states.
        if (
            trusted.snapshot.version != snapshot_version
            or trusted.timestamp.version != timestamp_version
        ):
            raise ReleaseSetError(
                "Repository metadata changed during release-set resolution"
            )

        return ReleasePlan(
            manifest_path,
            manifest.name,
            snapshot_version,
            tuple(plans),
        )

    @staticmethod
    def _resolve_component(
        updater: Updater, spec: ComponentSpec
    ) -> ComponentPlan:
        targetinfo = updater.get_targetinfo(spec.path)
        if targetinfo is None:
            raise ReleaseSetError(
                f"Component '{spec.name}' target '{spec.path}' "
                "is missing from trusted metadata"
            )
        if targetinfo.hashes.get("sha256") != spec.sha256:
            raise ReleaseSetError(
                f"Component '{spec.name}' digest does not match "
                "signed targets metadata"
            )
        return ComponentPlan(spec, targetinfo)

    @staticmethod
    def _check_compatibility(manifest: ReleaseManifest) -> None:
        versions = {spec.name: spec.version for spec in manifest.components}
        for spec in manifest.components:
            for dependency, specifier in spec.requires.items():
                dependency_version = versions.get(dependency)
                if dependency_version is None:
                    raise ReleaseSetError(
                        f"Component '{spec.name}' requires "
                        f"'{dependency}' which is not in the release-set"
                    )
                if not version_satisfies(dependency_version, specifier):
                    raise ReleaseSetError(
                        f"Component '{spec.name}' {spec.version} requires "
                        f"'{dependency}' {specifier}, but release-set "
                        f"contains {dependency_version}"
                    )

    def download_all(
        self,
        plan: ReleasePlan | None = None,
        target_dir: str | None = None,
    ) -> dict[str, str]:
        """Download (or reuse cached) files for every component of a plan.

        Args:
            plan: Plan to download. Default is the active plan.
            target_dir: Download directory. Default is the resolver
                target directory.

        Raises:
            ValueError: No plan is active and none was given.
            DownloadError: A component download failed.
            RepositoryError: A downloaded component failed verification.

        Returns:
            Dict mapping component names to local file paths.
        """
        if plan is None:
            plan = self._active_plan
        if plan is None:
            raise ValueError("No release-set plan to download")

        updater = self._new_updater()
        if target_dir is not None:
            updater.target_dir = target_dir

        paths = {}
        for component in plan.components:
            targetinfo = component.targetinfo
            filepath = updater.find_cached_target(targetinfo)
            if filepath is None:
                filepath = updater.download_target(targetinfo)
            paths[component.spec.name] = filepath
        return paths
