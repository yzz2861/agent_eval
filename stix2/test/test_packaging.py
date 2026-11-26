import pytest

from stix2 import plan_stix_packages


def test_four_object_two_sender_package_plan():
    assertions = {
        "relationship--1": ["relationship--1"],
        "relationship--2": ["relationship--2"],
    }
    dependencies = {
        "relationship--1": ["identity--1", "identity--2"],
        "relationship--2": ["identity--1", "identity--2"],
    }
    sender_permissions = {
        "bob": [
            "identity--1",
            "identity--2",
            "relationship--2",
        ],
        "alice": [
            "identity--1",
            "identity--2",
            "relationship--1",
        ],
    }

    result = plan_stix_packages(
        assertions,
        dependencies,
        sender_permissions,
        forbidden_together=[
            {"relationship--1", "relationship--2"},
        ],
    )

    assert result.proof_requirements == (
        (
            "relationship--1",
            (
                "identity--1",
                "identity--2",
                "relationship--1",
            ),
            ("alice",),
        ),
        (
            "relationship--2",
            (
                "identity--1",
                "identity--2",
                "relationship--2",
            ),
            ("bob",),
        ),
    )
    assert result.minimum_proof_sets == (
        (
            "identity--1",
            "identity--2",
            "relationship--1",
        ),
        (
            "identity--1",
            "identity--2",
            "relationship--2",
        ),
    )
    assert result.packages == (
        (
            "P0001",
            "alice",
            ("relationship--1",),
            (
                "identity--1",
                "identity--2",
                "relationship--1",
            ),
        ),
        (
            "P0002",
            "bob",
            ("relationship--2",),
            (
                "identity--1",
                "identity--2",
                "relationship--2",
            ),
        ),
    )
    assert result.single_sender_packages == {
        "alice": ("P0001",),
        "bob": ("P0002",),
    }
    assert result.minimum_single_sender_plans == ()
    assert result.minimum_joint_receipt_plans == (
        (
            "D0001",
            ("P0001", "P0002"),
            ("alice", "bob"),
        ),
    )
    assert result.minimum_complete_plans == result.minimum_joint_receipt_plans
    assert result.mandatory_assertion_groups == ()


def test_dependency_closure_and_mandatory_assertion_group():
    result = plan_stix_packages(
        assertions={
            "relationship--1": ["relationship--1"],
            "relationship--2": ["relationship--2"],
        },
        dependencies={
            "relationship--1": ["identity--1", "identity--2"],
            "relationship--2": ["identity--1", "identity--2"],
        },
        sender_permissions={
            "alice": [
                "identity--1",
                "identity--2",
                "relationship--1",
                "relationship--2",
            ],
        },
    )

    assert result.minimum_complete_plans == (
        (
            "D0001",
            ("P0003",),
            ("alice",),
        ),
    )
    assert result.mandatory_assertion_groups == (
        ("relationship--1", "relationship--2"),
    )
    assert result.minimum_single_sender_plans == result.minimum_complete_plans


def test_stix_relationship_mapping_input():
    relationships = [
        {
            "type": "relationship",
            "id": "relationship--1",
            "source_ref": "identity--1",
            "target_ref": "identity--2",
        },
        {
            "type": "relationship",
            "id": "relationship--2",
            "source_ref": "identity--2",
            "target_ref": "identity--3",
        },
    ]

    result = plan_stix_packages(
        relationships,
        dependencies={},
        sender_permissions={
            "alice": [
                "identity--1",
                "identity--2",
                "relationship--1",
            ],
            "bob": [
                "identity--2",
                "identity--3",
                "relationship--2",
            ],
        },
        forbidden_together=[
            {"relationship--1", "relationship--2"},
        ],
    )

    assert [
        requirement.object_ids for requirement in result.proof_requirements
    ] == [
        ("identity--1", "identity--2", "relationship--1"),
        ("identity--2", "identity--3", "relationship--2"),
    ]
    assert result.minimum_joint_receipt_plans == (
        ("D0001", ("P0001", "P0002"), ("alice", "bob")),
    )


def test_unavailable_object_is_rejected():
    with pytest.raises(ValueError, match="not available through any sender"):
        plan_stix_packages(
            assertions={"relationship--1": ["relationship--1"]},
            dependencies={
                "relationship--1": ["identity--1", "identity--2"],
            },
            sender_permissions={
                "alice": ["identity--1", "relationship--1"],
            },
        )


def test_insufficient_proof_permission_is_rejected():
    with pytest.raises(ValueError, match="No sender can provide"):
        plan_stix_packages(
            assertions={"relationship--1": ["relationship--1"]},
            dependencies={
                "relationship--1": ["identity--1", "identity--2"],
            },
            sender_permissions={
                "alice": ["identity--1", "relationship--1"],
                "bob": ["identity--2"],
            },
        )


def test_dependency_cycle_is_rejected():
    with pytest.raises(ValueError, match="Dependency cycle"):
        plan_stix_packages(
            assertions={"relationship--1": ["relationship--1"]},
            dependencies={
                "relationship--1": ["identity--1"],
                "identity--1": ["identity--2"],
                "identity--2": ["identity--1"],
            },
            sender_permissions={
                "alice": [
                    "identity--1",
                    "identity--2",
                    "relationship--1",
                ],
            },
        )
