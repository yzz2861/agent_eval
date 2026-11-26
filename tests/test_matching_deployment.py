"""Tests for coverage-driven Sigma rule deployment planning."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from sigma.matching import DeploymentPlanner, DeploymentScenario, RuleCandidate
from sigma.rule.rule import SigmaRule

SCENARIO_PATH = (
    Path(__file__).resolve().parents[1] / "examples" / "rule_deployment" / "scenario.yml"
)


@pytest.fixture(scope="module")
def scenario() -> DeploymentScenario:
    return DeploymentScenario.from_yaml(SCENARIO_PATH)


@pytest.fixture(scope="module")
def planner(scenario: DeploymentScenario) -> DeploymentPlanner:
    return DeploymentPlanner(scenario)


@pytest.fixture(scope="module")
def plans(planner: DeploymentPlanner):
    return planner.select_plans()


def test_coverage_matrix_is_built_from_local_matcher(planner: DeploymentPlanner):
    matrix = planner.coverage_matrix

    assert matrix.covers("P", "A0")
    assert not matrix.covers("P", "A1")
    assert matrix.covers("A", "A1")
    assert matrix.covers("A", "A2")
    assert matrix.covers("A", "A4")
    assert not matrix.covers("A", "A3")
    assert matrix.covers("B", "A1")
    assert matrix.covers("B", "A3")
    assert matrix.covers("B", "A4")
    assert not matrix.covers("B", "A2")
    assert matrix.covers("C", "A5")
    assert matrix.covers("D", "A6")
    assert matrix.covers("E", "A7")

    assert matrix.covers("baseline:old_ps_encoded", "A1")
    assert matrix.covers("baseline:old_ps_download", "A4")
    assert set(planner.old_hit_ids()) == {"A1", "A4"}
    assert all(
        not matrix.covers(candidate, benign_id)
        for candidate in matrix.candidate_columns
        for benign_id in ("B1", "B2", "B3", "B4", "B5", "B6")
    )


def test_coverage_matrix_serializes(planner: DeploymentPlanner):
    matrix = planner.coverage_matrix
    payload = matrix.to_dict()

    assert payload["columns"] == list(matrix.columns)
    assert payload["matrix"]["A1"]["A"] is True
    assert payload["matrix"]["A1"]["B"] is True
    assert payload["matrix"]["A2"]["B"] is False
    assert "`A1`" in matrix.to_markdown()
    assert matrix.to_csv().splitlines()[0].startswith("case,label,severity,")


def test_two_equally_feasible_plans_are_returned(plans):
    assert len(plans) == 2
    selected = {plan.selected_ids for plan in plans}
    assert selected == {("P", "A", "C"), ("P", "B", "C")}
    assert all(plan.feasible for plan in plans)
    assert all(plan.cost == 4 for plan in plans)
    assert all(plan.score == (3, 2, 0, 0) for plan in plans)
    assert all(not plan.false_positive_case_ids for plan in plans)
    assert all(set(plan.retained_old_hit_ids) == {"A1", "A4"} for plan in plans)
    assert all(not plan.missing_old_hit_ids for plan in plans)


def test_each_plan_can_recompute_its_alerts(plans):
    plan_a, plan_b = plans
    assert plan_a.replay() == plan_a.alert_rows()
    assert plan_b.replay() == plan_b.alert_rows()

    alerts_a = {row["case_id"]: row["rule_ids"] for row in plan_a.replay() if row["alerted"]}
    alerts_b = {row["case_id"]: row["rule_ids"] for row in plan_b.replay() if row["alerted"]}
    assert alerts_a == {
        "A0": ["P"],
        "A1": ["A"],
        "A2": ["A"],
        "A4": ["A"],
        "A5": ["C"],
    }
    assert alerts_b == {
        "A0": ["P"],
        "A1": ["B"],
        "A3": ["B"],
        "A4": ["B"],
        "A5": ["C"],
    }
    assert alerts_a != alerts_b


def test_replayed_results_survive_json_roundtrip(plans):
    payload = [plan.to_dict(include_replay=True) for plan in plans]
    decoded = json.loads(json.dumps(payload))
    for plan_payload in decoded:
        assert plan_payload["replay"] == plan_payload["alerts"]
        assert plan_payload["feasible"] is True


def test_uncovered_cases_name_capability_or_constraint(plans):
    plan_a, plan_b = plans
    uncovered_a = {case.case_id: case for case in plan_a.uncovered}
    uncovered_b = {case.case_id: case for case in plan_b.uncovered}

    assert uncovered_a["A3"].kind == "constraint"
    assert uncovered_a["A3"].reason == "mutual_exclusion"
    assert uncovered_a["A3"].capable_rule_ids == ("B",)
    assert uncovered_a["A6"].kind == "constraint"
    assert uncovered_a["A6"].reason == "retention"
    assert uncovered_a["A7"].kind == "constraint"
    assert uncovered_a["A7"].reason == "capacity"
    assert uncovered_a["A8"].kind == "capability"
    assert uncovered_a["A8"].reason == "no_rule_capability"
    assert uncovered_a["A9"].kind == "capability"

    assert uncovered_b["A2"].kind == "constraint"
    assert uncovered_b["A2"].reason == "mutual_exclusion"
    assert uncovered_b["A6"].reason == "retention"
    assert uncovered_b["A7"].reason == "capacity"
    assert {"A8", "A9"}.issubset(
        {case_id for case_id, case in uncovered_b.items() if case.kind == "capability"}
    )


def test_capacity_and_rule_slots_are_hard_constraints(planner: DeploymentPlanner):
    over_capacity = planner.evaluate(["P", "A", "D"])
    assert not over_capacity.feasible
    assert any(v.code == "capacity" for v in over_capacity.violations)

    over_slots = planner.evaluate(["P", "A", "C", "E"])
    assert not over_slots.feasible
    assert any(v.code == "capacity" for v in over_slots.violations)
    assert any(v.code == "rule_limit" for v in over_slots.violations)


def test_mutual_exclusion_and_prerequisite_are_enforced(planner: DeploymentPlanner):
    both_variants = planner.evaluate(["P", "A", "B"])
    assert any(v.code == "mutual_exclusion" for v in both_variants.violations)

    missing_prerequisite = planner.evaluate(["A", "C"])
    assert any(v.code == "prerequisite" for v in missing_prerequisite.violations)


def test_retention_rejects_plans_that_drop_old_hits(planner: DeploymentPlanner):
    plan = planner.evaluate(["P", "C"])
    assert any(v.code == "retention" for v in plan.violations)
    assert set(plan.missing_old_hit_ids) == {"A1", "A4"}


def test_false_positive_label_blocks_broad_rule(scenario: DeploymentScenario):
    broad_rule = SigmaRule.from_yaml("""
title: Broad PowerShell Inventory
name: F
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\powershell.exe'
    condition: selection
""")
    candidate = RuleCandidate(id="F", rule=broad_rule, cost=1)
    relaxed = replace(scenario.constraints, capacity=5, max_rules=4)
    extended = replace(
        scenario,
        candidates=(*scenario.candidates, candidate),
        constraints=relaxed,
    )
    plan = DeploymentPlanner(extended).evaluate(["P", "A", "C", "F"])
    assert not plan.feasible
    assert any(v.code == "false_positive" for v in plan.violations)
    assert "B1" in plan.false_positive_case_ids


def test_rule_slot_limit_is_reported_with_unlimited_capacity(scenario: DeploymentScenario):
    constrained = replace(scenario.constraints, capacity=100, max_rules=1)
    plan = DeploymentPlanner(replace(scenario, constraints=constrained)).evaluate(["P", "C"])
    assert any(v.code == "rule_limit" for v in plan.violations)


def test_explicit_required_cases_are_enforced_without_old_hit_retention(
    scenario: DeploymentScenario,
):
    constrained = replace(
        scenario.constraints,
        retain_old_hits=False,
        required_cases=frozenset({"A6"}),
    )
    plan = DeploymentPlanner(replace(scenario, constraints=constrained)).evaluate(["P", "A", "C"])
    assert any(v.code == "retention" for v in plan.violations)
    assert any(case.case_id == "A6" for case in plan.uncovered)


def test_nested_event_scenario_loader():
    scenario = DeploymentScenario.from_dict(
        {
            "title": "inline",
            "constraints": {"capacity": 1, "max_rules": 1},
            "cases": [
                {
                    "id": "C1",
                    "label": "malicious",
                    "severity": "high",
                    "event": {
                        "timestamp": "2026-11-20T12:00:00Z",
                        "logsource": {
                            "category": "process_creation",
                            "product": "windows",
                        },
                        "data": {"CommandLine": "mimikatz.exe"},
                    },
                }
            ],
            "candidates": [
                {
                    "id": "R",
                    "rule": """
title: Inline
name: R
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: mimikatz
    condition: selection
""",
                }
            ],
        }
    )
    plans = DeploymentPlanner(scenario).select_plans()
    assert len(plans) == 1
    assert plans[0].selected_ids == ("R",)
    assert plans[0].replay() == plans[0].alert_rows()
