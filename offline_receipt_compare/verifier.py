"""Offline TUF chain verification and delegation path resolution.

The verifier reuses python-tuf TrustedMetadataSet so signature, hash, length
and version checks match a real TUF client exactly. On top of that it runs
the same pre-order depth-first delegation walk as ngclient.Updater to decide
which role is authoritative for a target and to record the path.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from offline_receipt_compare.models import VerdictCode
from tuf.api.exceptions import RepositoryError
from tuf.api.metadata import Metadata, TargetFile, Targets
from tuf.ngclient._internal.trusted_metadata_set import TrustedMetadataSet
from tuf.ngclient.config import EnvelopeType

ROOT = "root"
TIMESTAMP = "timestamp"
SNAPSHOT = "snapshot"
TARGETS = "targets"
TOP_LEVEL = (ROOT, TIMESTAMP, SNAPSHOT, TARGETS)


@dataclass(frozen=True)
class RoleStep:
    """One role entry in a reconstructed delegation path."""

    # One role in a reconstructed delegation path.
    role: str
    version: int

    def to_dict(self) -> dict:
        """Serialize the role step for JSON reporting."""
        return {"role": self.role, "version": self.version}


@dataclass
class TargetResolution:
    """Outcome of resolving one target path inside a metadata bundle."""

    # Outcome of resolving one target path inside one metadata bundle.
    found: bool = False
    target_file: TargetFile | None = None
    role_path: list[RoleStep] = field(default_factory=list)
    reason: str = ""
    detail: str = ""

    @classmethod
    def failure(cls, reason: str, detail: str = "") -> TargetResolution:
        """Build a resolution that did not find a trusted target."""
        return cls(found=False, reason=reason, detail=detail)


class MetadataBundle:
    """A fully offline, immutable set of TUF metadata for one repository."""

    # An immutable, fully offline set of TUF metadata for one repository.
    #
    # Holds role JSON files named root.json, timestamp.json, snapshot.json,
    # targets.json and one <role>.json per delegated role.
    def __init__(
        self,
        metadata_dir: str | Path,
        envelope_type: EnvelopeType = EnvelopeType.METADATA,
    ) -> None:
        """Load every role JSON file from an offline metadata directory."""
        self.metadata_dir = Path(metadata_dir)
        self.envelope_type = envelope_type
        self._raw: dict[str, bytes] = {}
        for path in sorted(self.metadata_dir.glob("*.json")):
            self._raw[path.stem] = path.read_bytes()

    def roles(self) -> list[str]:
        """Return role names with top-level roles first."""
        # Role names with top-level roles first, then delegated roles.
        ordered = [role for role in TOP_LEVEL if role in self._raw]
        ordered.extend(
            role for role in sorted(self._raw) if role not in TOP_LEVEL
        )
        return ordered

    def raw(self, role: str) -> bytes | None:
        """Return raw role JSON bytes, or ``None`` when absent."""
        return self._raw.get(role)

    def get_metadata(self, role: str) -> Metadata | None:
        """Deserialize one role, or return ``None`` when it is absent."""
        data = self._raw.get(role)
        if data is None:
            return None
        return Metadata.from_bytes(data)


def verify_chain(
    bundle: MetadataBundle,
    target_path: str,
    reference_time: datetime | None = None,
) -> TargetResolution:
    """Verify the full TUF chain offline and resolve ``target_path``."""
    root_data = bundle.raw(ROOT)
    if root_data is None:
        return TargetResolution.failure(
            VerdictCode.METADATA_UNTRUSTED,
            "bundle is missing root.json",
        )

    try:
        trusted = TrustedMetadataSet(root_data, bundle.envelope_type)
        if reference_time is not None:
            trusted.reference_time = _as_utc(reference_time)
        trusted.update_timestamp(_require(bundle, TIMESTAMP))
        trusted.update_snapshot(_require(bundle, SNAPSHOT))
        trusted.update_targets(_require(bundle, TARGETS))
    except RepositoryError as exc:
        return TargetResolution.failure(
            VerdictCode.METADATA_UNTRUSTED,
            f"{type(exc).__name__}: {exc}",
        )
    except KeyError:
        return TargetResolution.failure(
            VerdictCode.METADATA_UNTRUSTED,
            "bundle is missing a required top-level role",
        )

    return _walk_delegations(bundle, trusted, target_path)


def _as_utc(value: datetime) -> datetime:
    """Normalize a datetime to timezone-aware UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _require(bundle: MetadataBundle, role: str) -> bytes:
    """Fetch a required role and raise ``KeyError`` when it is missing."""
    data = bundle.raw(role)
    if data is None:
        raise KeyError(role)
    return data


def _walk_delegations(
    bundle: MetadataBundle,
    trusted: TrustedMetadataSet,
    target_path: str,
) -> TargetResolution:
    # Mirror ngclient.Updater pre-order DFS, including terminating roles and
    # backtracking after a role whose metadata cannot be loaded.
    to_visit: list[tuple[str, str]] = [(TARGETS, ROOT)]
    visited: set[str] = set()
    path_by_role: dict[str, list[str]] = {TARGETS: [TARGETS]}
    first_error: TargetResolution | None = None

    while to_visit:
        role_name, parent_role = to_visit.pop()
        if role_name in visited:
            continue

        try:
            targets = _load_role(bundle, trusted, role_name, parent_role)
        except (RepositoryError, KeyError) as exc:
            visited.add(role_name)
            if first_error is None:
                reason = (
                    VerdictCode.DELEGATED_ROLE_REMOVED
                    if isinstance(exc, KeyError)
                    else VerdictCode.METADATA_UNTRUSTED
                )
                first_error = TargetResolution.failure(
                    reason, f"role {role_name!r}: {exc}"
                )
            continue

        target_file = targets.targets.get(target_path)
        if target_file is not None:
            steps = [
                RoleStep(role, trusted[role].version)
                for role in path_by_role[role_name]
            ]
            return TargetResolution(
                found=True,
                target_file=target_file,
                role_path=steps,
            )

        visited.add(role_name)
        children = _children_for(targets, target_path)
        next_roles: list[tuple[str, str]] = []
        for child_name, terminating in children:
            next_roles.append((child_name, role_name))
            path_by_role[child_name] = [*path_by_role[role_name], child_name]
            if terminating:
                break
        next_roles.reverse()
        to_visit.extend(next_roles)

    if first_error is not None:
        return first_error
    return TargetResolution.failure(
        VerdictCode.PATH_BROKEN,
        "no delegated role serves the target path in the candidate metadata",
    )


def _load_role(
    bundle: MetadataBundle,
    trusted: TrustedMetadataSet,
    role_name: str,
    parent_role: str,
) -> Targets:
    """Load and verify one delegated role through its parent role."""
    if role_name == TARGETS:
        return trusted.targets
    if trusted.contains(role_name, parent_role):
        return trusted[role_name]  # type: ignore[return-value]
    data = _require(bundle, role_name)
    return trusted.update_delegated_targets(data, role_name, parent_role)


def _children_for(targets: Targets, target_path: str) -> list[tuple[str, bool]]:
    """Return delegated child roles responsible for ``target_path``."""
    if targets.delegations is None:
        return []
    return list(targets.delegations.get_roles_for_target(target_path))
