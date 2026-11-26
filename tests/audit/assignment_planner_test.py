import json

import pytest

from detect_secrets.audit.assignment import AssignmentPlanner
from detect_secrets.audit.assignment import equal_queue_demo
from detect_secrets.audit.assignment import plan_assignment_file
from detect_secrets.audit.assignment import plan_assignments
from detect_secrets.main import main


def test_release_priority_and_submitter_group_constraint():
    plan = plan_assignments(
        findings=[
            {
                "candidate_id": "normal-1",
                "candidate_type": "Secret Keyword",
                "submitter_group": "team-a",
            },
            {
                "candidate_id": "release-1",
                "candidate_type": "PyPI Token",
                "submitter_group": "team-b",
            },
        ],
        seats=[
            {
                "seat_id": "same-group",
                "group": "team-a",
                "qualified_types": ["Secret Keyword", "PyPI Token"],
            },
            {
                "seat_id": "independent",
                "group": "audit",
                "qualified_types": ["PyPI Token"],
            },
        ],
    )

    assignments = {item.candidate_id: item.seat_id for item in plan.assignments}
    assert assignments["release-1"] in {"same-group", "independent"}
    assert "normal-1" not in assignments
    unassigned = {
        item.candidate_id: item for item in plan.unassigned if item.candidate_id == "normal-1"
    }
    assert "normal-1" in unassigned
    assert unassigned["normal-1"].reason == "submitter_group_conflict"
    assert "submitter_group_conflict" in unassigned["normal-1"].reason_codes


def test_signed_recusal_blocks_specific_seat():
    plan = plan_assignments(
        findings=[
            {
                "candidate_id": "finding-1",
                "candidate_type": "AWS Access Key",
                "submitter_group": "partner",
            },
        ],
        seats=[
            {"seat_id": "auditor-1", "qualified_types": ["AWS Access Key"]},
            {"seat_id": "auditor-2", "qualified_types": ["AWS Access Key"]},
        ],
        recusals=[
            {
                "auditor_id": "auditor-1",
                "finding_id": "finding-1",
                "signed": True,
            },
            {
                "auditor_id": "auditor-2",
                "finding_id": "finding-1",
                "signed": False,
            },
        ],
    )

    assert len(plan.assignments) == 1
    assert plan.assignments[0].seat_id == "auditor-2"


def test_recusal_for_other_candidate_does_not_expand_scope():
    plan = plan_assignments(
        candidates=[
            {"id": "candidate-1", "candidate_type": "Slack Token", "submitter_group": "g"},
            {"id": "candidate-2", "candidate_type": "Slack Token", "submitter_group": "g"},
        ],
        auditors=[
            {"id": "auditor-1", "types": ["Slack Token"], "capacity": 1},
            {"id": "auditor-2", "types": ["Slack Token"], "capacity": 1},
        ],
        recusal_list={"auditor-1": ["candidate-2"]},
    )

    assignments = {item.candidate_id: item.seat_id for item in plan.assignments}
    assert assignments == {
        "candidate-1": "auditor-1",
        "candidate-2": "auditor-2",
    }


def test_no_qualified_audit_seat_has_explainable_reason():
    plan = plan_assignments(
        findings=[
            {
                "candidate_id": "finding-1",
                "candidate_type": "Future Quantum Token",
                "submitter_group": "partner",
            },
        ],
        seats=[
            {"seat_id": "auditor-1", "qualified_types": ["AWS Access Key"]},
        ],
    )

    assert plan.assigned_count == 0
    assert plan.backlog_count == 1
    reason = plan.unassigned[0].reason
    assert reason == "no_qualified_auditor"
    assert "qualified audit seat" in plan.unassigned[0].message
    assert plan.unassigned[0].seat_diagnostics[0].violation_codes == [
        "type_not_qualified",
    ]


def test_duplicate_batch_submission_is_assigned_once_and_explained():
    finding = {
        "candidate_id": "shared-finding",
        "candidate_type": "Private Key",
        "submitter_group": "partner",
        "fingerprint": "same-fingerprint",
    }
    plan = plan_assignments(
        findings=[
            finding,
            {
                **finding,
                "submission_id": "second-delivery",
            },
        ],
        seats=[{"seat_id": "auditor-1", "qualified_types": ["Private Key"]}],
    )

    assert plan.assigned_count == 1
    assert plan.duplicate_count == 1
    assert plan.duplicates[0].duplicate_of == "shared-finding"
    assert plan.duplicates[0].reason == "duplicate"
    assert any(item.reason == "duplicate_submission" for item in plan.unassigned)


def test_temporary_shift_change_replans_work():
    planner = AssignmentPlanner(
        findings=[
            {
                "candidate_id": "finding-1",
                "candidate_type": "GitHub Token",
                "submitter_group": "partner",
            },
        ],
        seats=[
            {"seat_id": "first-shift", "qualified_types": ["GitHub Token"]},
        ],
    )
    first_plan = planner.plan()
    assert first_plan.assignments[0].seat_id == "first-shift"

    changed = planner.apply_shift_change(
        {
            "off": ["first-shift"],
            "on": [
                {
                    "seat_id": "replacement",
                    "qualified_types": ["GitHub Token"],
                    "capacity": 20,
                },
            ],
        },
    )
    second_plan = planner.plan()

    assert changed["off"] == ["first-shift"]
    assert second_plan.active_seat_ids == ["replacement"]
    assert second_plan.assignments[0].seat_id == "replacement"


def test_daily_limit_explains_capacity_backlog():
    findings = [
        {
            "candidate_id": f"finding-{index}",
            "candidate_type": "Secret Keyword",
            "submitter_group": "partner",
        }
        for index in range(21)
    ]
    plan = plan_assignments(
        findings=findings,
        seats=[{"seat_id": "auditor-1", "qualified_types": ["Secret Keyword"]}],
        daily_limit=20,
    )

    assert plan.assigned_count == 20
    assert plan.backlog_count == 1
    assert plan.capacity_remaining == 0
    assert plan.backlog[0].reason == "daily_capacity_exceeded"


def test_two_equal_queues_show_avoidable_fifo_backlog():
    plan = equal_queue_demo()

    assert len(plan.assignments) == 20
    assert plan.backlog_count == 0
    assert plan.fifo_backlog_count == 10
    assert plan.avoidable_backlog == 10
    assert plan.backlog == 0
    assert plan.fifo_backlog == 10

    release_assignments = {
        item.candidate_id: item.seat_id for item in plan.assignments if item.release
    }
    assert all(seat_id == "flexible-release-seat" for seat_id in release_assignments.values())
    assert len(release_assignments) == 10


def test_plan_is_json_serializable_and_file_entrypoint(tmp_path):
    request_file = tmp_path / "plan.json"
    request_file.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "candidate_id": "finding-1",
                        "candidate_type": "Slack Token",
                        "submitter_group": "partner",
                    },
                ],
                "seats": [
                    {"seat_id": "seat-1", "qualified_types": ["Slack Token"]},
                ],
            },
        ),
        encoding="utf-8",
    )

    plan = plan_assignment_file(request_file)
    json.dumps(plan)
    assert plan.assigned_count == 1


def test_audit_cli_accepts_offline_plan_without_baseline(tmp_path, printer):
    request_file = tmp_path / "plan.json"
    request_file.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "candidate_id": "finding-1",
                        "candidate_type": "Slack Token",
                        "submitter_group": "partner",
                    },
                ],
                "seats": [
                    {"seat_id": "seat-1", "qualified_types": ["Slack Token"]},
                ],
            },
        ),
        encoding="utf-8",
    )

    exit_code = main(["audit", "--plan-assignments", str(request_file)])
    output = json.loads(printer.message)

    assert exit_code == 0
    assert output["assigned_count"] == 1


@pytest.mark.parametrize(
    "keyword",
    [
        "candidates",
        "auditors",
        "signed_recusals",
        "daily_capacity",
    ],
)
def test_common_keyword_aliases(keyword):
    kwargs = {
        keyword: 20 if keyword == "daily_capacity" else None,
    }
    if keyword == "candidates":
        kwargs[keyword] = [
            {"id": "f1", "candidate_type": "Slack Token", "submitter_group": "g"},
        ]
    elif keyword == "auditors":
        kwargs["findings"] = [
            {"id": "f1", "candidate_type": "Slack Token", "submitter_group": "g"},
        ]
        kwargs[keyword] = [{"id": "a1", "types": ["Slack Token"]}]
    elif keyword == "signed_recusals":
        kwargs["findings"] = [
            {"id": "f1", "candidate_type": "Slack Token", "submitter_group": "g"},
        ]
        kwargs["auditors"] = [{"id": "a1", "types": ["Slack Token"]}]
        kwargs[keyword] = []
    else:
        kwargs["findings"] = []
        kwargs["seats"] = []

    plan = plan_assignments(**kwargs)
    assert "assignments" in plan
