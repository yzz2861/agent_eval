from __future__ import annotations

import pytest
from packaging.version import Version

from pip_audit._plan import (
    FixSuggestion,
    PlanError,
    PlanGroup,
    collect_constraints,
    plan_fixes,
)


@pytest.fixture
def req_files(tmp_path):
    runtime = tmp_path / "runtime.txt"
    runtime.write_text("foo==1.0.0\nbar>=2.0,<3.0\n")
    test = tmp_path / "test.txt"
    test.write_text("foo>=1.0.0,<4.0.0\n")
    return runtime, test


@pytest.fixture
def groups(req_files):
    runtime, test = req_files
    return [
        PlanGroup(name="runtime", requirement_files=(runtime,)),
        PlanGroup(name="test", requirement_files=(test,)),
    ]


def suggestion(group, package, current, target, origin=""):
    return FixSuggestion(
        group=group,
        package=package,
        current=Version(current),
        target=Version(target),
        origin=origin,
    )


def test_collect_constraints_records_provenance(req_files):
    runtime, _ = req_files
    constraints = collect_constraints(PlanGroup(name="runtime", requirement_files=(runtime,)))

    assert set(constraints) == {"foo", "bar"}
    (foo,) = constraints["foo"]
    assert foo.source == runtime
    assert foo.line == 1
    assert foo.describe() == f"{runtime}:1: foo==1.0.0"
    (bar,) = constraints["bar"]
    assert bar.line == 2
    assert bar.allows(Version("2.5"))
    assert not bar.allows(Version("3.0"))


def test_collect_constraints_invalid_line(req_files):
    runtime, _ = req_files
    runtime.write_text("not a requirement===\n")
    with pytest.raises(PlanError, match="invalid specifier at line 1"):
        collect_constraints(PlanGroup(name="runtime", requirement_files=(runtime,)))


def test_plan_single_valid_suggestion(groups):
    plan = plan_fixes(groups, [suggestion("test", "foo", "1.0.0", "2.0.0", "release-1")])

    assert plan.ok()
    assert len(plan.planned) == 1
    fix = plan.planned[0]
    assert fix.group == "test"
    assert fix.target == Version("2.0.0")
    # The merged plan is re-validated against the group's approved bounds.
    assert plan.revalidated == plan.planned


def test_plan_violation_cites_constraint_source(groups, req_files):
    runtime, _ = req_files
    # `bar` is constrained to <3.0 by the runtime group.
    plan = plan_fixes(groups, [suggestion("runtime", "bar", "2.1", "3.2", "release-1")])

    assert not plan.ok()
    assert not plan.planned
    assert len(plan.violations) == 1
    (reason,) = plan.violations[0].reasons
    assert f"{runtime}:2: bar<3.0,>=2.0" in reason
    rendered = plan.render()
    assert f"{runtime}:2" in rendered


def test_plan_rejects_downgrade_below_lower_bound(groups):
    plan = plan_fixes(groups, [suggestion("test", "foo", "2.0.0", "1.5.0", "release-1")])

    assert not plan.ok()
    (reason,) = plan.violations[0].reasons
    assert "below the approved lower bound 2.0.0" in reason


def test_plan_group_isolation(groups):
    # `foo==1.0.0` is pinned in the runtime group, but the test group allows
    # anything in [1.0.0, 4.0.0). A test-only suggestion must not leak into
    # the runtime group.
    plan = plan_fixes(groups, [suggestion("test", "foo", "1.0.0", "3.5.0", "release-1")])

    assert plan.ok()
    assert len(plan.planned) == 1
    assert plan.planned[0].group == "test"

    # The same target in the runtime group is outside the approved bounds.
    plan = plan_fixes(groups, [suggestion("runtime", "foo", "1.0.0", "3.5.0", "release-1")])
    assert not plan.ok()
    assert len(plan.violations) == 1


def test_plan_merge_conflict_for_diverging_targets(groups, req_files):
    runtime, _ = req_files
    # Each suggestion is individually valid against the runtime constraints,
    # but merged they propose two different pins for the same package.
    suggestions = [
        suggestion("runtime", "bar", "2.1", "2.5", "release-1.1"),
        suggestion("runtime", "bar", "2.1", "2.9", "release-1.2"),
    ]
    for individual in suggestions:
        assert plan_fixes(groups, [individual]).ok()

    plan = plan_fixes(groups, suggestions)

    assert not plan.ok()
    assert not plan.planned
    assert len(plan.conflicts) == 1
    conflict = plan.conflicts[0]
    assert conflict.group == "runtime"
    assert conflict.package == "bar"
    assert {s.target for s in conflict.suggestions} == {Version("2.5"), Version("2.9")}
    # The conflict output traces back to the constraint both targets satisfy.
    rendered = plan.render()
    assert f"{runtime}:2: bar<3.0,>=2.0" in rendered
    assert "release-1.1" in rendered
    assert "release-1.2" in rendered


def test_plan_merge_deduplicates_identical_targets(groups):
    suggestions = [
        suggestion("test", "foo", "1.0.0", "2.0.0", "release-1.1"),
        suggestion("test", "foo", "1.0.0", "2.0.0", "release-1.2"),
    ]
    plan = plan_fixes(groups, suggestions)

    assert plan.ok()
    assert len(plan.planned) == 1
    assert plan.planned[0].origins == ("release-1.1", "release-1.2")


def test_plan_merge_isolated_across_groups(groups):
    # The same package may legitimately receive different targets in
    # different groups; only same-group divergence conflicts.
    suggestions = [
        suggestion("runtime", "foo", "1.0.0", "1.0.0", "release-1.1"),
        suggestion("test", "foo", "1.0.0", "3.0.0", "release-1.2"),
    ]
    plan = plan_fixes(groups, suggestions)

    assert plan.ok()
    assert len(plan.planned) == 2
    assert {fix.group for fix in plan.planned} == {"runtime", "test"}


def test_plan_unknown_group(groups):
    with pytest.raises(PlanError, match="unknown group"):
        plan_fixes(groups, [suggestion("staging", "foo", "1.0.0", "2.0.0")])
