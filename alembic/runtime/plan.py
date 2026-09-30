from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass
from typing import Any
from typing import Literal
from typing import TYPE_CHECKING
from typing import cast

from .. import util
from ..script import revision
from .migration import HeadMaintainer
from .migration import MigrationStep

if TYPE_CHECKING:
    from ..script.base import ScriptDirectory

Direction = Literal["upgrade", "downgrade"]
StepKind = Literal[
    "move",
    "create_branch",
    "delete_branch",
    "merge_branches",
    "unmerge_branches",
]
TableActionOp = Literal["insert", "update", "delete"]
CurrentRevisions = str | Collection[str | None] | None


@dataclass(frozen=True)
class VersionTableAction:
    """Describe one insert, update, or delete against the version table."""

    operation: TableActionOp
    from_revision: str | None = None
    to_revision: str | None = None

    @property
    def revision(self) -> str | None:
        if self.operation == "insert":
            return self.to_revision
        elif self.operation == "delete":
            return self.from_revision
        else:
            return None

    def to_dict(self) -> dict[str, str | None]:
        if self.operation == "update":
            return {
                "operation": "update",
                "from_revision": self.from_revision,
                "to_revision": self.to_revision,
            }
        elif self.operation == "insert":
            return {
                "operation": "insert",
                "revision": self.to_revision,
            }
        else:
            return {
                "operation": "delete",
                "revision": self.from_revision,
            }


@dataclass(frozen=True)
class PlanStep:
    """Describe one migration and the version table transition."""

    direction: Direction
    revision_id: str
    from_revision_ids: tuple[str, ...]
    to_revision_ids: tuple[str, ...]
    source_revisions: tuple[str, ...]
    destination_revisions: tuple[str, ...]
    version_table_actions: tuple[VersionTableAction, ...]
    kind: StepKind

    def to_dict(self) -> dict[str, Any]:
        return {
            "direction": self.direction,
            "revision_id": self.revision_id,
            "kind": self.kind,
            "from_revision_ids": list(self.from_revision_ids),
            "to_revision_ids": list(self.to_revision_ids),
            "source_revisions": list(self.source_revisions),
            "destination_revisions": list(self.destination_revisions),
            "version_table_actions": [
                action.to_dict() for action in self.version_table_actions
            ],
        }


@dataclass(frozen=True)
class MigrationPlan:
    """Ordered migration plan and simulated version-table states."""

    direction: Direction
    target: str | None
    current_revisions: tuple[str, ...]
    steps: tuple[PlanStep, ...]

    @property
    def final_revisions(self) -> tuple[str, ...]:
        if self.steps:
            return self.steps[-1].destination_revisions
        return self.current_revisions

    def to_dict(self) -> dict[str, Any]:
        return {
            "direction": self.direction,
            "target": self.target,
            "current_revisions": list(self.current_revisions),
            "final_revisions": list(self.final_revisions),
            "steps": [step.to_dict() for step in self.steps],
        }


def _normalize_current(
    current: CurrentRevisions,
) -> tuple[str, ...] | None:
    if current is None:
        return None
    if isinstance(current, str):
        values = (current,)
    else:
        values = tuple(current)

    normalized = tuple(
        value for value in values if value is not None and value != "base"
    )
    if len(normalized) != len(set(normalized)):
        raise util.InvalidPlanStateError(
            "Current revisions must be unique: %s" % (", ".join(normalized),)
        )
    return normalized


def _raise_plan_error(error: Exception, scope: str = "target") -> None:
    if isinstance(error, revision.MultipleHeads):
        raise util.AmbiguousPlanTargetError(str(error)) from error
    if isinstance(error, revision.RangeNotAncestorError):
        raise util.UnreachablePlanTargetError(str(error)) from error
    if isinstance(error, revision.ResolutionError):
        argument = error.argument
        if str(error).startswith("Multiple revisions "):
            if scope == "target":
                raise util.AmbiguousPlanTargetError(str(error)) from error
            raise util.InvalidPlanStateError(str(error)) from error
        raise util.UnknownPlanRevisionError(
            str(error), revision=argument, scope=scope
        ) from error
    if isinstance(error, revision.RevisionError):
        message = str(error)
        if "ambiguous" in message.lower():
            raise util.AmbiguousPlanTargetError(message) from error
        lower_message = message.lower()
        if any(
            text in lower_message
            for text in (
                "not a valid",
                "didn't produce",
                "walked too far",
            )
        ):
            raise util.UnreachablePlanTargetError(message) from error
        raise util.PlanError(message) from error
    if isinstance(error, util.CommandError):
        raise error
    raise util.PlanError(str(error)) from error


def _resolve_current(
    script: ScriptDirectory, current: tuple[str, ...]
) -> tuple[str, ...]:
    try:
        revisions = script.revision_map.get_revisions(current)
        current_set = {rev.revision for rev in revisions if rev is not None}
        tips = {
            rev.revision
            for rev in script.revision_map._get_all_current(current)
        }
    except Exception as error:
        if isinstance(error, revision.RevisionError):
            _raise_plan_error(error, scope="current")
        raise

    if current_set != tips:
        raise util.InvalidPlanStateError(
            "Current revisions must be active heads: %s"
            % (", ".join(sorted(current)),)
        )
    return tuple(sorted(current_set))


def _migration_steps(
    script: ScriptDirectory,
    direction: Direction,
    target: str | None,
    current: tuple[str, ...],
) -> list[MigrationStep]:
    try:
        if direction == "upgrade":
            revisions = script.iterate_revisions(
                target, current, implicit_base=True
            )
            return [
                MigrationStep.upgrade_from_script(script.revision_map, rev)
                for rev in reversed(list(revisions))
            ]
        else:
            revisions = script.iterate_revisions(
                current, target, select_for_downgrade=True
            )
            return [
                MigrationStep.downgrade_from_script(script.revision_map, rev)
                for rev in revisions
            ]
    except Exception as error:
        if isinstance(error, revision.RevisionError):
            _raise_plan_error(error)
        raise


def _action(
    operation: TableActionOp,
    from_revision: str | None = None,
    to_revision: str | None = None,
) -> VersionTableAction:
    return VersionTableAction(
        operation=operation,
        from_revision=from_revision,
        to_revision=to_revision,
    )


class _PlanningHeadMaintainer(HeadMaintainer):
    def __init__(self, heads: Collection[str]) -> None:
        super().__init__(cast(Any, None), heads)
        self.actions: list[VersionTableAction] = []

    def _insert_version(self, version: str) -> None:
        self.actions.append(_action("insert", to_revision=version))
        self.heads.add(version)

    def _delete_version(self, version: str) -> None:
        self.actions.append(_action("delete", from_revision=version))
        self.heads.remove(version)

    def _update_version(self, from_: str, to_: str) -> None:
        self.actions.append(_action("update", from_, to_))
        self.heads.remove(from_)
        self.heads.add(to_)


def _step_kind(step: MigrationStep, heads: set[str]) -> StepKind:
    if step.should_delete_branch(heads):
        return "delete_branch"
    if step.should_create_branch(heads):
        return "create_branch"
    if step.should_merge_branches(heads):
        return "merge_branches"
    if step.should_unmerge_branches(heads):
        return "unmerge_branches"
    return "move"


def _step_actions(
    step: MigrationStep, heads: set[str]
) -> tuple[StepKind, tuple[VersionTableAction, ...], set[str]]:
    kind = _step_kind(step, heads)
    maintainer = _PlanningHeadMaintainer(heads)
    maintainer.update_to_step(step)
    return kind, tuple(maintainer.actions), set(maintainer.heads)


def build_migration_plan(
    script: ScriptDirectory,
    target: str | None,
    current: CurrentRevisions = None,
    direction: Direction = "upgrade",
) -> MigrationPlan:
    """Build an ordered migration plan without invoking migration functions.

    The same revision resolution, relative-target, branch-label, dependency,
    merge, and topological-ordering logic used by upgrade and downgrade is
    used to construct the steps. Version-table changes are simulated in
    memory.
    """

    normalized_current = _normalize_current(current)
    if normalized_current is not None:
        current_revisions = _resolve_current(script, normalized_current)
    else:
        current_revisions = ()

    steps = _migration_steps(script, direction, target, current_revisions)
    heads = set(current_revisions)
    planned_steps = []

    for step in steps:
        source = tuple(sorted(heads))
        kind, actions, heads = _step_actions(step, heads)
        destination = tuple(sorted(heads))
        planned_steps.append(
            PlanStep(
                direction=direction,
                revision_id=step.revision.revision,
                from_revision_ids=step.from_revisions,
                to_revision_ids=step.to_revisions,
                source_revisions=source,
                destination_revisions=destination,
                version_table_actions=actions,
                kind=kind,
            )
        )

    return MigrationPlan(
        direction=direction,
        target=target,
        current_revisions=current_revisions,
        steps=tuple(planned_steps),
    )
