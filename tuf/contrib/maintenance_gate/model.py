"""Data model shared by the offline maintenance admission gate.
XTEST

An authorization slip ("pause update" or "resume update") is represented as
signed TUF delegated targets metadata.  Every target entry in such metadata
carries a maintenance action in its TUF ``custom`` field, while the target
paths themselves are the *target set* the statement points at.  The
authorization version is not a separate counter: it is the TUF metadata
``version`` of the delegated role, which snapshot pins and the trusted
metadata reader refuses to roll back.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from tuf.api.metadata import TargetFile, Targets

#: Maintenance actions carried in a target file's ``custom`` field.
PAUSE = "pause"
RESUME = "resume"

#: Name of the custom field that stores the maintenance action.
ACTION_FIELD = "maintenance_action"


class GateStatus(StrEnum):
    """Lifecycle of an authorization document fed to the gate.

    Attributes:
        TRUSTED: The document was verified through the TUF chain and became
            part of the trusted view.
        STAGED: The document could not be verified yet because another role
            of the same release is missing (a "half set"). It is held and
            retried automatically.
        REJECTED: The document failed verification (bad signature, rollback,
            hash mismatch, ...). It can never influence an admission.
    """

    TRUSTED = "trusted"
    STAGED = "staged"
    REJECTED = "rejected"


class AdmissionVerdict(StrEnum):
    """Per-package admission verdict returned by the gate.

    Attributes:
        PROCEED: A verified resume statement, or no pause in effect, allows
            the package.
        PAUSED: A verified pause statement covering the package is in effect.
        PENDING: The authoritative metadata could not be verified, so the
            gate fails closed and asks for an operator check.
    """

    PROCEED = "proceed"
    PAUSED = "paused"
    PENDING = "pending"


@dataclass(frozen=True)
class AuthorizationStatement:
    """A single verified pause/resume statement.

    Attributes:
        action: One of :data:`PAUSE` / :data:`RESUME`.
        role: Delegated TUF role that signed the statement.
        version: Authorization version, equal to the role's TUF metadata
            version (and therefore rollback protected by snapshot).
        targets: Target set the statement points at, as target paths.

    Whether the signing role is *terminating* for a lookup is a property of
    the delegation graph (stored on the parent role), not of the statement,
    so it is resolved by the gate rather than stored here.
    """

    action: str
    role: str
    version: int
    targets: frozenset[str]

    def covers(self, target_path: str) -> bool:
        """Return whether ``target_path`` belongs to this statement's set."""
        return target_path in self.targets


def target_action(target_file: TargetFile) -> str | None:
    """Read the maintenance action stored on a target file, if any."""
    custom = target_file.unrecognized_fields.get("custom")
    if not isinstance(custom, dict):
        return None
    action = custom.get(ACTION_FIELD)
    if action in (PAUSE, RESUME):
        return action
    return None


def statements_from_targets(
    role: str, targets: Targets
) -> list[AuthorizationStatement]:
    """Extract maintenance statements from a verified targets role.

    A delegated role documents one authorization release, so all target
    entries carrying an action share the role's authorization version.
    Entries without an action are ordinary target descriptions and ignored.
    """

    by_action: dict[str, set[str]] = {}
    for path, target_file in targets.targets.items():
        action = target_action(target_file)
        if action is not None:
            by_action.setdefault(action, set()).add(path)

    return [
        AuthorizationStatement(
            action=action,
            role=role,
            version=targets.version,
            targets=frozenset(paths),
        )
        for action, paths in by_action.items()
    ]


@dataclass
class IngestResult:
    """Outcome of feeding one authorization document to the gate."""

    role: str
    status: GateStatus
    reason: str
    promoted_epoch: int | None = None
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def trusted(self) -> bool:
        """Return whether the document became part of the trusted view."""
        return self.status is GateStatus.TRUSTED


@dataclass(frozen=True)
class AdmissionDecision:
    """The admission verdict for one target package.

    Attributes:
        target: Target path of the package under evaluation.
        verdict: One of :class:`AdmissionVerdict`.
        basis: Human readable justification, naming the verified statement
            and authorization version (or the missing metadata that forces a
            fail-closed pending verdict).
        statement: The verified statement that decided the verdict, when one
            was available.
    """

    target: str
    verdict: AdmissionVerdict
    basis: str
    statement: AuthorizationStatement | None = None
