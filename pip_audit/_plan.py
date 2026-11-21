"""
Functionality for planning dependency fixes without applying them.

This module implements a read-only planner that sits in front of the
existing fix flow (`pip_audit._fix` and `DependencySource.fix`). It reuses
the project's current constraints, parsed directly from the requirements
files, and never invokes an installer (no `pip`, no virtual environments).

Fix suggestions are scoped to named groups (e.g. "runtime" and "test"),
where each group owns one or more requirements files. A suggestion is only
ever validated against the constraints of its own group, so a suggestion
that is only suitable for a test group cannot affect the runtime group.

Multiple suggestions (typically carried by separate release lines) can be
merged into a single plan. The merged plan is re-validated against each
group's approved risk bounds: the lower bound is the currently pinned
version (fixes must not downgrade) and the upper bounds are the group's
existing version specifiers. Every finding is reported with the exact
source (file and line) of the constraint that produced it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import Version
from pip_requirements_parser import InstallRequirement, RequirementsFile


class PlanError(Exception):
    """
    Raised when the planner cannot interpret its inputs, e.g. when a
    requirements file contains an invalid line or a suggestion references
    an unknown group.
    """

    pass


@dataclass(frozen=True)
class PlanConstraint:
    """
    A version constraint on a package, lifted from a requirements file.

    `source` and `line` identify exactly where the constraint comes from,
    so that plan output can trace every decision back to its origin.
    """

    package: str
    specifier: SpecifierSet
    source: Path
    line: int

    def allows(self, version: Version) -> bool:
        """
        Check whether `version` satisfies this constraint.
        """
        return self.specifier.contains(version)

    def describe(self) -> str:
        """
        Render this constraint with its provenance as `source:line: specifier`.
        """
        return f"{self.source}:{self.line}: {self.package}{self.specifier}"


@dataclass(frozen=True)
class PlanGroup:
    """
    A named group of requirements files whose constraints are planned together.

    Groups are isolated from each other: a suggestion scoped to one group is
    never validated against, or applied to, another group's constraints.
    """

    name: str
    requirement_files: tuple[Path, ...]


@dataclass(frozen=True)
class FixSuggestion:
    """
    A single proposed upgrade, typically produced on one release line.

    `group` scopes the suggestion: it is only checked against that group's
    constraints. `current` is the currently approved (pinned) version and
    `target` is the proposed fix version. `origin` labels where the
    suggestion came from (e.g. a branch or release line) for reporting.
    """

    group: str
    package: str
    current: Version
    target: Version
    origin: str = ""


@dataclass(frozen=True)
class ApprovedWindow:
    """
    The approved risk bounds for a package within a group.

    `lower` is the currently pinned version: planned targets must not go
    below it. `constraints` are the group's existing specifiers, which act
    as the approved upper bounds.
    """

    group: str
    package: str
    lower: Version
    constraints: tuple[PlanConstraint, ...]

    def rejected_by(self, target: Version) -> list[str]:
        """
        Return the reasons (with constraint provenance) for which `target`
        falls outside the approved window, or an empty list if it is inside.
        """
        reasons = []
        if target < self.lower:
            reasons.append(
                f"target {target} is below the approved lower bound {self.lower} "
                f"for group {self.group!r}"
            )
        reasons.extend(
            f"target {target} is outside the approved bounds set by {constraint.describe()}"
            for constraint in self.constraints
            if not constraint.allows(target)
        )
        return reasons


@dataclass(frozen=True)
class PlannedFix:
    """
    A fix that survived validation and merging, and is ready to apply.
    """

    group: str
    package: str
    current: Version
    target: Version
    origins: tuple[str, ...]
    constraints: tuple[PlanConstraint, ...]


@dataclass(frozen=True)
class PlanViolation:
    """
    A suggestion that falls outside its group's approved risk bounds.
    """

    suggestion: FixSuggestion
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class MergeConflict:
    """
    Two or more individually valid suggestions that cannot be merged because
    they propose different targets for the same package in the same group.
    """

    group: str
    package: str
    suggestions: tuple[FixSuggestion, ...]
    constraints: tuple[PlanConstraint, ...]


@dataclass
class FixPlan:
    """
    The outcome of planning: applicable fixes, bound violations, and merge
    conflicts, plus the re-validated view of the merged plan.
    """

    planned: list[PlannedFix] = field(default_factory=list)
    violations: list[PlanViolation] = field(default_factory=list)
    conflicts: list[MergeConflict] = field(default_factory=list)
    revalidated: list[PlannedFix] = field(default_factory=list)

    def ok(self) -> bool:
        """
        Check whether the plan is clean, i.e. free of violations and conflicts.
        """
        return not self.violations and not self.conflicts

    def render(self) -> str:
        """
        Render the plan as human-readable text, citing the source of every
        constraint that informed a decision.
        """
        lines = [
            f"Fix plan: {len(self.planned)} planned, "
            f"{len(self.conflicts)} conflict(s), "
            f"{len(self.violations)} violation(s)"
        ]
        if self.revalidated:
            lines.append("Planned fixes (re-validated against approved risk bounds):")
            for fix in self.revalidated:
                origins = ", ".join(fix.origins) if fix.origins else "unknown origin"
                lines.append(
                    f"  [{fix.group}] {fix.package} {fix.current} -> {fix.target} (from {origins})"
                )
                lines.extend(
                    f"    within approved bounds: {constraint.describe()}"
                    for constraint in fix.constraints
                )
        if self.conflicts:
            lines.append("Merge conflicts:")
            for conflict in self.conflicts:
                proposals = ", ".join(
                    f"{s.target} ({s.origin or 'unknown origin'})" for s in conflict.suggestions
                )
                lines.append(
                    f"  [{conflict.group}] {conflict.package}: conflicting targets {proposals}"
                )
                lines.extend(
                    f"    each satisfies: {constraint.describe()}"
                    for constraint in conflict.constraints
                )
        if self.violations:
            lines.append("Bound violations:")
            for violation in self.violations:
                s = violation.suggestion
                lines.append(
                    f"  [{s.group}] {s.package} {s.current} -> {s.target} "
                    f"({s.origin or 'unknown origin'})"
                )
                lines.extend(f"    {reason}" for reason in violation.reasons)
        return "\n".join(lines)


def collect_constraints(group: PlanGroup) -> dict[str, tuple[PlanConstraint, ...]]:
    """
    Parse a group's requirements files read-only and return its constraints,
    indexed by canonicalized package name.

    This never invokes an installer: the files are parsed directly with
    `pip-requirements-parser`, mirroring the pre-resolved path of
    `RequirementSource`.
    """
    constraints: dict[str, list[PlanConstraint]] = {}
    for filename in group.requirement_files:
        rf = RequirementsFile.from_file(filename)
        if rf.invalid_lines:
            invalid = rf.invalid_lines[0]
            raise PlanError(
                f"requirement file {filename} contains invalid specifier at "
                f"line {invalid.line_number}: {invalid.error_message}"
            )
        for req in rf.requirements:
            if not isinstance(req, InstallRequirement):
                continue
            if req.req is None or req.is_editable:
                continue
            if req.marker is not None and not req.marker.evaluate():
                continue
            if not req.specifier:
                continue
            name = canonicalize_name(req.name)
            constraint = PlanConstraint(
                package=name,
                specifier=req.specifier,
                source=filename,
                line=req.requirement_line.line_number,
            )
            constraints.setdefault(name, []).append(constraint)
    return {name: tuple(entries) for name, entries in constraints.items()}


def _approved_window(
    group: PlanGroup,
    package: str,
    current: Version,
    constraints: dict[str, tuple[PlanConstraint, ...]],
) -> ApprovedWindow:
    return ApprovedWindow(
        group=group.name,
        package=package,
        lower=current,
        constraints=constraints.get(package, ()),
    )


def plan_fixes(groups: list[PlanGroup], suggestions: list[FixSuggestion]) -> FixPlan:
    """
    Validate and merge fix suggestions into a read-only plan.

    Each suggestion is first validated on its own, against only its own
    group's approved risk bounds. Surviving suggestions are then merged by
    (group, package): identical targets are deduplicated, while diverging
    targets are reported as merge conflicts. Finally, the merged plan is
    re-validated against each group's approved risk bounds.
    """
    plan = FixPlan()
    groups_by_name = {group.name: group for group in groups}
    constraints_by_group = {group.name: collect_constraints(group) for group in groups}

    # Individual validation, scoped to each suggestion's own group.
    valid: dict[tuple[str, str], list[FixSuggestion]] = {}
    windows: dict[tuple[str, str], ApprovedWindow] = {}
    for suggestion in suggestions:
        group = groups_by_name.get(suggestion.group)
        if group is None:
            raise PlanError(
                f"suggestion for {suggestion.package} references unknown group {suggestion.group!r}"
            )
        package = canonicalize_name(suggestion.package)
        constraints = constraints_by_group[group.name]
        window = _approved_window(group, package, suggestion.current, constraints)
        windows[(group.name, package)] = window

        reasons = window.rejected_by(suggestion.target)
        if reasons:
            plan.violations.append(PlanViolation(suggestion=suggestion, reasons=tuple(reasons)))
            continue
        valid.setdefault((group.name, package), []).append(suggestion)

    # Merge suggestions per (group, package).
    for (group_name, package), grouped in valid.items():
        window = windows[(group_name, package)]
        targets = {suggestion.target for suggestion in grouped}
        if len(targets) > 1:
            plan.conflicts.append(
                MergeConflict(
                    group=group_name,
                    package=package,
                    suggestions=tuple(grouped),
                    constraints=window.constraints,
                )
            )
            continue
        plan.planned.append(
            PlannedFix(
                group=group_name,
                package=package,
                current=grouped[0].current,
                target=grouped[0].target,
                origins=tuple(s.origin for s in grouped if s.origin),
                constraints=window.constraints,
            )
        )

    # Re-validate the merged plan against each group's approved risk bounds.
    for fix in plan.planned:
        window = windows[(fix.group, fix.package)]
        reasons = window.rejected_by(fix.target)
        if reasons:  # pragma: no cover
            suggestion = FixSuggestion(
                group=fix.group,
                package=fix.package,
                current=fix.current,
                target=fix.target,
                origin=", ".join(fix.origins),
            )
            plan.violations.append(PlanViolation(suggestion=suggestion, reasons=tuple(reasons)))
        else:
            plan.revalidated.append(fix)
    return plan
