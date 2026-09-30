"""Structured migration planning.

This module implements a "dry run" facility that computes which
migration scripts Alembic would run, in which order, and how the
version table would change, when moving a database from a given set of
current heads to a target revision.  No ``upgrade()`` or
``downgrade()`` functions are executed, and no connection to the
database is required when the current heads are given explicitly.

Revision resolution and ordering are exactly those used by the real
:func:`.command.upgrade` and :func:`.command.downgrade`
commands, so branch labels, relative targets (e.g. ``+2`` /
``-1``), merge points and ``depends_on``
dependencies are all supported.

.. versionadded:: 1.21.0

"""

from __future__ import annotations

import dataclasses
from typing import Iterable
from typing import TYPE_CHECKING

from . import util
from .runtime import migration
from .script import revision as _revision

if TYPE_CHECKING:
    from .runtime.migration import VersionTableMutation
    from .script.base import ScriptDirectory


@dataclasses.dataclass(frozen=True)
class PlanStep:
    """A single step within a :class:`.MigrationPlan`.

    Corresponds to the invocation of one revision script's
    ``upgrade()`` or ``downgrade()``
    function, along with the mutations the step would apply to the
    version table.

    .. versionadded:: 1.21.0

    """

    direction: str
    """``"upgrade"`` or ``"downgrade"``."""

    revision: str
    """The revision whose ``upgrade()`` or
    ``downgrade()`` would run."""

    source_revisions: tuple[str, ...]
    """Revisions this step moves away from, including any revisions
    implied by ``depends_on`` dependencies."""

    destination_revisions: tuple[str, ...]
    """Revisions this step moves towards, including any revisions
    implied by ``depends_on`` dependencies."""

    branch_action: str
    """The version table action category for this step; one of
    ``"create_branch"``, ``"delete_branch"``,
    ``"merge_branches"``, ``"unmerge_branches"``
    or ``"update"``."""

    version_table_mutations: tuple[VersionTableMutation, ...]
    """Ordered version table mutations (insert/update/delete of rows)
    this step would perform."""

    heads_before: tuple[str, ...]
    """Contents of the version table before this step, sorted."""

    heads_after: tuple[str, ...]
    """Contents of the version table after this step, sorted."""

    doc: str | None
    """The docstring/message of the underlying revision script."""


@dataclasses.dataclass(frozen=True)
class MigrationPlan:
    """A structured, ordered plan of migration steps.

    Produced by :func:`.build_plan`.

    .. versionadded:: 1.21.0

    """

    direction: str
    """``"upgrade"`` or ``"downgrade"``."""

    target: str
    """The target revision expression the plan was built for."""

    initial_heads: tuple[str, ...]
    """Current heads the plan starts from, sorted.  Empty means the
    database is at "base" (no version table rows)."""

    final_heads: tuple[str, ...]
    """Contents of the version table once all steps are applied."""

    steps: tuple[PlanStep, ...]
    """The ordered migration steps."""

    @property
    def is_empty(self) -> bool:
        """True if no migrations are required to reach the target."""
        return not self.steps

    def render(self, verbose: bool = False) -> str:
        """Render the plan as human-readable text.

        :param verbose: if True, include the version table contents
         after every step.

        """
        lines = [
            "Current heads: %s" % _format_heads(self.initial_heads),
            "Target: %s (%s)" % (self.target, self.direction),
        ]
        if not self.steps:
            lines.append("No migrations to run; already at target.")
        for index, step in enumerate(self.steps, 1):
            header = "Step %d: %s %s -> %s" % (
                index,
                step.direction,
                _format_heads(step.source_revisions),
                _format_heads(step.destination_revisions),
            )
            if step.doc:
                header = "%s, %s" % (header, step.doc)
            lines.append(header)
            lines.append("  version table: %s" % step.branch_action)
            for mut in step.version_table_mutations:
                if mut.action == "insert":
                    lines.append("    INSERT %s" % mut.to_revision)
                elif mut.action == "delete":
                    lines.append("    DELETE %s" % mut.from_revision)
                else:
                    lines.append(
                        "    UPDATE %s -> %s"
                        % (mut.from_revision, mut.to_revision)
                    )
            if verbose:
                lines.append(
                    "  heads after step: %s" % _format_heads(step.heads_after)
                )
        lines.append("Final heads: %s" % _format_heads(self.final_heads))
        return "\n".join(lines)


def _format_heads(heads: tuple[str, ...]) -> str:
    return ", ".join(heads) if heads else "(base)"


def build_plan(
    script_directory: ScriptDirectory,
    target: str,
    current_heads: Iterable[str] = (),
    direction: str = "upgrade",
) -> MigrationPlan:
    """Compute the migration plan from current heads to a target.

    Uses the same revision resolution and ordering as the real
    :func:`.command.upgrade` and :func:`.command.downgrade`
    commands, but does not execute any migration functions and does
    not require a database connection.

    :param script_directory: the :class:`.ScriptDirectory` to
     plan against.

    :param target: the target revision expression; may be a revision
     id or partial id, ``"head"`` /
     ``"heads"`` / ``"base"``, a
     branch label such as ``mybranch@head``, or a
     relative target such as ``+2`` or
     ``-1``.

    :param current_heads: the revision identifiers currently present
     in the database's version table.  Pass an empty iterable for a
     database at "base".  This allows planning entirely offline;
     alternatively, the current heads may be read from the database
     using :meth:`.MigrationContext.get_current_heads`.

    :param direction: ``"upgrade"`` (default) or
     ``"downgrade"``.

    :return: a :class:`.MigrationPlan`.

    :raises .AmbiguousTargetError: if the target resolves to more
     than one revision.

    :raises .RevisionNotFoundError: if the target or one of the
     current heads cannot be resolved to a known revision.

    :raises .UnreachableRangeError: if the target is not reachable
     from the current heads.

    :raises .PlanError: for any other revision resolution problem.

    """
    if direction not in ("upgrade", "downgrade"):
        raise util.PlanError(
            "Unknown plan direction %r; expected 'upgrade' or 'downgrade'"
            % direction
        )

    heads = tuple(current_heads)

    try:
        if direction == "upgrade":
            scripts = list(
                script_directory.iterate_revisions(
                    target, heads, implicit_base=True
                )
            )
            steps = [
                migration.MigrationStep.upgrade_from_script(
                    script_directory.revision_map, script
                )
                for script in reversed(scripts)
            ]
        else:
            scripts = list(
                script_directory.iterate_revisions(
                    heads, target, select_for_downgrade=True
                )
            )
            steps = [
                migration.MigrationStep.downgrade_from_script(
                    script_directory.revision_map, script
                )
                for script in scripts
            ]
    except _revision.MultipleHeads as mh:
        raise util.AmbiguousTargetError(
            "Multiple head revisions are present for given argument "
            "'%s'; please specify a specific target revision, "
            "'<branchname>@head' to narrow to a specific head, or "
            "'heads' for all heads" % (mh.argument or target)
        ) from mh
    except _revision.ResolutionError as re:
        raise util.RevisionNotFoundError(
            "Can't locate revision identified by '%s'" % re.argument
        ) from re
    except _revision.RangeNotAncestorError as rna:
        raise util.UnreachableRangeError(
            "Destination %s is not a valid %s target from current "
            "head(s) %s"
            % (target, direction, _format_heads(tuple(sorted(heads))))
        ) from rna
    except _revision.RevisionError as err:
        raise util.PlanError(err.args[0]) from err

    simulated_heads = set(heads)
    plan_steps = []
    for step in steps:
        heads_before = tuple(sorted(simulated_heads))
        branch_action, mutations = migration._step_version_table_mutations(
            step, simulated_heads
        )
        for mut in mutations:
            if mut.action == "insert":
                assert mut.to_revision is not None
                simulated_heads.add(mut.to_revision)
            elif mut.action == "delete":
                assert mut.from_revision is not None
                simulated_heads.remove(mut.from_revision)
            else:
                assert mut.from_revision is not None
                assert mut.to_revision is not None
                simulated_heads.remove(mut.from_revision)
                simulated_heads.add(mut.to_revision)
        plan_steps.append(
            PlanStep(
                direction=direction,
                revision=step.revision.revision,
                source_revisions=step.from_revisions,
                destination_revisions=step.to_revisions,
                branch_action=branch_action,
                version_table_mutations=tuple(mutations),
                heads_before=heads_before,
                heads_after=tuple(sorted(simulated_heads)),
                doc=step.doc,
            )
        )

    return MigrationPlan(
        direction=direction,
        target=target,
        initial_heads=tuple(sorted(heads)),
        final_heads=tuple(sorted(simulated_heads)),
        steps=tuple(plan_steps),
    )
