"""Tests for entity merge reconciliation."""

import json

from stix2.equivalence import merge


def test_transitive_merge_closure():
    report = merge.reconcile_entity_merges(
        positive=[("A", "B"), ("B", "C")],
    )

    assert report["status"] == "consistent"
    assert report["groups"] == [["A", "B", "C"]]
    assert report["certain_merges"] == [
        ["A", "B"],
        ["A", "C"],
        ["B", "C"],
    ]
    assert report["undetermined_pairs"] == []
    assert report["minimal_conflicts"] == []


def test_minimal_conflict_on_chain_plus_separation():
    report = merge.reconcile_entity_merges(
        positive=[("A", "B"), ("B", "C")],
        negative=[("A", "C")],
    )

    assert report["status"] == "ambiguous"
    assert report["consistent"] is False
    assert report["groups"] is None
    assert report["partition"] is None
    assert len(report["minimal_conflicts"]) == 1

    conflict = report["minimal_conflicts"][0]
    assert conflict["pairs"] == [
        ["A", "B"],
        ["B", "C"],
        ["A", "C"],
    ]
    assert conflict["relations"] == ["merge", "merge", "separate"]
    assert conflict["size"] == 3
    assert conflict["minimal"] is True


def test_chain_plus_separation_keeps_both_edges_possible():
    report = merge.reconcile_entity_merges(
        positive=[("A", "B"), ("B", "C")],
        negative=[("A", "C")],
    )

    assert report["certain_merges"] == []
    assert report["possible_merges"] == [["A", "B"], ["B", "C"]]
    assert report["still_valid_merges"] == [["A", "B"], ["B", "C"]]
    assert report["impossible_merges"] == [["A", "C"]]
    assert report["certain_separations"] == [["A", "C"]]
    assert report["undetermined_pairs"] == [["A", "B"], ["B", "C"]]

    assert report["partitions"] == [
        [["A"], ["B", "C"]],
        [["A", "B"], ["C"]],
    ]


def test_derived_separation_propagates_through_merge():
    report = merge.reconcile_entity_merges(
        positive=[("A", "B")],
        negative=[("A", "C")],
    )

    assert report["status"] == "consistent"
    assert report["groups"] == [["A", "B"]]
    assert report["certain_separations"] == [["A", "C"], ["B", "C"]]
    assert report["undetermined_pairs"] == []


def test_insufficient_evidence_does_not_force_grouping():
    report = merge.reconcile_entity_merges(entities=["A", "B", "C"])

    assert report["status"] == "insufficient"
    assert report["groups"] == []
    assert report["evidence_sufficient"] is False
    assert report["fully_determined"] is False
    assert report["undetermined_pairs"] == [
        ["A", "B"],
        ["A", "C"],
        ["B", "C"],
    ]


def test_direct_positive_and_negative_is_minimal_conflict():
    report = merge.reconcile_entity_merges(
        positive=[("A", "B")],
        negative=[("A", "B")],
    )

    assert report["status"] == "resolved"
    assert report["minimal_conflicts"][0]["pairs"] == [
        ["A", "B"],
        ["A", "B"],
    ]
    assert report["minimal_conflicts"][0]["size"] == 2
    assert report["groups"] == []


def test_self_separation_is_unsatisfiable():
    report = merge.reconcile_entity_merges(negative=[("A", "A")])

    assert report["status"] == "unsatisfiable"
    assert report["resolvable"] is False
    assert report["groups"] is None
    assert report["minimal_conflicts"][0]["positive_edges"] == []


def test_all_simple_paths_are_minimal_conflicts():
    report = merge.reconcile_entity_merges(
        positive=[
            ("A", "B"),
            ("B", "C"),
            ("C", "D"),
            ("A", "C"),
        ],
        negative=[("A", "D")],
    )

    pairs = [conflict["pairs"] for conflict in report["minimal_conflicts"]]
    assert [["A", "C"], ["C", "D"], ["A", "D"]] in pairs
    assert [["A", "B"], ["B", "C"], ["C", "D"], ["A", "D"]] in pairs
    assert len(pairs) == 2


def test_purpose_specific_reports_and_combined_conflict():
    report = merge.reconcile_entity_merges(
        [
            {
                "left": "A",
                "right": "B",
                "relation": "merge",
                "purpose": "analysis",
            },
            {
                "left": "B",
                "right": "C",
                "relation": "merge",
                "purpose": "analysis",
            },
            {
                "left": "A",
                "right": "C",
                "relation": "separate",
                "purpose": "legal",
            },
        ],
    )

    assert report["purposes"] == ["analysis", "legal"]
    assert report["purposes_compatible"] is True
    assert report["combined_consistent"] is False
    assert report["by_purpose"]["analysis"]["groups"] == [["A", "B", "C"]]
    assert report["by_purpose"]["legal"]["groups"] == []


def test_query_purpose_does_not_scope_global_evidence():
    report = merge.reconcile_entity_merges(
        positive=[("A", "B")],
        purpose="analysis",
    )

    assert report["groups"] == [["A", "B"]]
    assert report["by_purpose"]["analysis"]["groups"] == [["A", "B"]]


def test_weight_selects_preferred_but_keeps_ambiguity():
    report = merge.reconcile_entity_merges(
        evidence=[
            {"left": "A", "right": "B", "relation": "merge", "weight": 5},
            {"left": "B", "right": "C", "relation": "merge", "weight": 1},
            {"left": "A", "right": "C", "relation": "separate", "weight": 100},
        ],
    )

    assert report["status"] == "ambiguous"
    assert report["groups"] is None
    assert report["preferred_groups"] == [["A", "B"]]
    assert len(report["partitions"]) == 2


def test_required_positive_mode_rejects_conflicts():
    report = merge.reconcile_entity_merges(
        positive=[("A", "B"), ("B", "C")],
        negative=[("A", "C")],
        positive_mode="required",
    )

    assert report["status"] == "unsatisfiable"
    assert report["resolvable"] is False
    assert report["minimal_conflicts"]


def test_stix_relationships_are_read():
    bundle = {
        "type": "bundle",
        "id": "bundle--00000000-0000-4000-8000-000000000001",
        "objects": [
            {
                "type": "identity",
                "id": "identity--00000000-0000-4000-8000-000000000002",
                "name": "ACME",
                "identity_class": "organization",
            },
            {
                "type": "identity",
                "id": "identity--00000000-0000-4000-8000-000000000003",
                "name": "ACME Corporation",
                "identity_class": "organization",
            },
            {
                "type": "relationship",
                "id": "relationship--00000000-0000-4000-8000-000000000004",
                "relationship_type": "same-as",
                "source_ref": "identity--00000000-0000-4000-8000-000000000002",
                "target_ref": "identity--00000000-0000-4000-8000-000000000003",
            },
        ],
    }

    assertions = merge.assertions_from_stix(bundle)
    assert len(assertions) == 1
    assert assertions[0].positive is True

    report = merge.reconcile_entity_merges(objects=bundle)
    assert report["groups"] == [
        [
            "identity--00000000-0000-4000-8000-000000000002",
            "identity--00000000-0000-4000-8000-000000000003",
        ],
    ]


def test_load_evidence_from_json(tmp_path):
    path = tmp_path / "evidence.json"
    path.write_text(
        json.dumps(
            {
                "merges": [["A", "B"]],
                "separations": [["B", "C"]],
            },
        ),
    )

    assertions = merge.load_evidence(str(path))
    report = merge.reconcile_entity_merges(assertions)

    assert report["groups"] == [["A", "B"]]
    assert report["certain_separations"] == [["A", "C"], ["B", "C"]]


def test_aliases_and_reconciler():
    assert merge.check_merge_consistency(positive=[("A", "B")]) is True
    assert merge.check_merge_consistency(
        positive=[("A", "B")],
        negative=[("A", "B")],
    ) is False
    assert merge.find_minimal_conflicts(
        positive=[("A", "B"), ("B", "C")],
        negative=[("A", "C")],
    )[0]["size"] == 3
    assert merge.compatible_groups(positive=[("A", "B")]) == [["A", "B"]]
    assert merge.compatible_groups(
        positive=[("A", "B"), ("B", "C")],
        negative=[("A", "C")],
    ) is None

    reconciler = merge.EntityMergeReconciler(positive=[("A", "B")])
    assert reconciler.check() is True
    assert reconciler.compatible_groups() == [["A", "B"]]


def test_string_assertions():
    report = merge.reconcile_entity_merges(
        evidence=["A~B", "B!=C"],
    )
    assert report["groups"] == [["A", "B"]]
    assert report["certain_separations"] == [["A", "C"], ["B", "C"]]
