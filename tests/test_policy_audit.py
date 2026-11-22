"""Tests for the CVSS policy pre-check toolkit (run from repository root)."""

import unittest

from cvss.exceptions import CVSSError
from policy_audit.compare import compare_versions
from policy_audit.graph import build_band_graph
from policy_audit.policy import PolicyError, load_policy
from policy_audit.report import audit_version, build_report
from policy_audit.universe import VERSIONS, build_universe, find_vector, score_vector


def full_allow(version):
    return {
        metric: list(VERSIONS[version].domains[metric])
        for metric in VERSIONS[version].mandatory
    }


V31_BANDS = [
    {"name": "None", "lower": 0.0, "upper": 0.1, "disposition": "triage"},
    {"name": "Low", "lower": 0.1, "upper": 4.0, "disposition": "routine-ticket"},
    {"name": "Medium", "lower": 4.0, "upper": 7.0, "disposition": "routine-ticket"},
    {"name": "High", "lower": 7.0, "upper": 9.0, "disposition": "expedite"},
    {"name": "Critical", "lower": 9.0, "upper": None, "disposition": "emergency"},
]

V2_BANDS = [
    {"name": "Low", "lower": 0.0, "upper": 4.0, "disposition": "routine-ticket"},
    {"name": "Medium", "lower": 4.0, "upper": 7.0, "disposition": "routine-ticket"},
    {"name": "High", "lower": 7.0, "upper": None, "disposition": "emergency"},
]


def make_policy():
    return load_policy(
        {
            "name": "test",
            "versions": {
                "3.1": {"allowed_values": full_allow("3.1"), "bands": V31_BANDS},
                "2.0": {"allowed_values": full_allow("2.0"), "bands": V2_BANDS},
            },
        }
    )


class UniverseTests(unittest.TestCase):
    def test_universe_sizes_match_cartesian_space(self):
        self.assertEqual(2592, len(build_universe("3.1")))
        self.assertEqual(729, len(build_universe("2.0")))
        self.assertEqual(104976, len(build_universe("4.0")))

    def test_known_anchor_scores(self):
        self.assertEqual(
            9.8,
            score_vector(
                "3.1",
                dict(
                    zip(
                        VERSIONS["3.1"].mandatory,
                        ["N", "L", "N", "N", "U", "H", "H", "H"],
                    )
                ),
            ),
        )
        self.assertEqual(
            0.0,
            score_vector(
                "3.1",
                dict(
                    zip(
                        VERSIONS["3.1"].mandatory,
                        ["N", "L", "N", "N", "U", "N", "N", "N"],
                    )
                ),
            ),
        )

    def test_invalid_combination_is_never_synthesised(self):
        with self.assertRaises(CVSSError):
            score_vector("3.1", {"AV": "X"})
        self.assertIsNone(find_vector("3.1", {"AV": "N"}))


class PolicyTests(unittest.TestCase):
    def test_band_partition_and_severity_counts(self):
        policy = make_policy()
        audit = audit_version("3.1", policy)
        self.assertEqual(2592, audit.covered_size)
        self.assertEqual(0, audit.uncovered_size)
        population = {band["name"]: band["vectors"] for band in audit.as_dict()["bands"]}
        self.assertEqual(96, population["None"])
        self.assertEqual(61, population["Critical"])

    def test_restricted_policy_flags_missing_candidates(self):
        policy = load_policy(
            {
                "name": "restricted",
                "versions": {
                    "3.1": {
                        "allowed_values": {
                            "AV": ["N"],
                            "AC": ["L"],
                            "PR": ["N"],
                            "UI": ["N"],
                            "S": ["U"],
                            "C": ["N", "L", "H"],
                            "I": ["N", "L", "H"],
                            "A": ["N", "L", "H"],
                        },
                        "bands": V31_BANDS,
                    }
                },
            }
        )
        audit = audit_version("3.1", policy)
        self.assertEqual(27, audit.covered_size)
        self.assertEqual(2592 - 27, audit.uncovered_size)
        self.assertGreater(len(audit.blocked), 0)
        verdict = build_report(policy, ["3.1"])["verdicts"][0]
        self.assertEqual("needs-review", verdict["status"])

    def test_policy_rejects_unknown_value_and_band_gap(self):
        with self.assertRaises(PolicyError):
            load_policy(
                {
                    "name": "bad",
                    "versions": {
                        "3.1": {
                            "allowed_values": {
                                "AV": ["N", "ZZZ"],
                                "AC": ["L"],
                                "PR": ["N"],
                                "UI": ["N"],
                                "S": ["U"],
                                "C": ["N"],
                                "I": ["N"],
                                "A": ["N"],
                            },
                            "bands": V31_BANDS,
                        }
                    },
                }
            )
        gap_bands = [
            {"name": "Low", "lower": 0.0, "upper": 4.0, "disposition": "x"},
            {"name": "High", "lower": 5.0, "upper": None, "disposition": "y"},
        ]
        with self.assertRaises(PolicyError):
            load_policy(
                {
                    "name": "gap",
                    "versions": {
                        "3.1": {
                            "allowed_values": full_allow("3.1"),
                            "bands": gap_bands,
                        }
                    },
                }
            )


class GraphTests(unittest.TestCase):
    def setUp(self):
        self.policy = make_policy()
        universe = build_universe("3.1")
        covered, _ = self.policy.partition_universe(universe)
        self.graph = build_band_graph("3.1", self.policy, covered)

    def test_every_edge_changes_exactly_one_metric(self):
        for edge in self.graph.edges:
            differing = [
                metric
                for metric in VERSIONS["3.1"].mandatory
                if edge.source.value_map[metric] != edge.target.value_map[metric]
            ]
            self.assertEqual([edge.metric], differing)

    def test_full_space_is_one_cross_band_component(self):
        self.assertEqual(1, len(self.graph.components))
        self.assertEqual(1, len(self.graph.cross_band_components()))

    def test_band_skipping_edges_exist(self):
        self.assertGreater(len(self.graph.band_skipping_edges), 0)
        order = [band.name for band in self.policy.version_policy("3.1").bands]
        for edge in self.graph.band_skipping_edges:
            source_band = self.graph.band_of_vector[edge.source.vector]
            target_band = self.graph.band_of_vector[edge.target.vector]
            self.assertGreater(abs(order.index(source_band) - order.index(target_band)), 1)

    def test_shortest_witness_is_reproducible_and_minimal(self):
        start = find_vector(
            "3.1",
            dict(
                zip(
                    VERSIONS["3.1"].mandatory,
                    ["N", "L", "N", "N", "U", "N", "N", "N"],
                )
            ),
        )
        goal = find_vector(
            "3.1",
            dict(
                zip(
                    VERSIONS["3.1"].mandatory,
                    ["N", "L", "N", "N", "U", "H", "H", "H"],
                )
            ),
        )
        witness = self.graph.shortest_witness(start, goal)
        self.assertEqual(3, witness.distance)
        chain = witness.as_dict()["chain"]
        self.assertEqual(start.vector, chain[0]["vector"])
        self.assertEqual(goal.vector, chain[-1]["vector"])
        for step in chain[1:]:
            self.assertIsNotNone(step["fact"])


class CompareTests(unittest.TestCase):
    def _spec(self):
        metric_mapping = {
            "AV": {"2.0": "AV", "3.1": "AV"},
            "AC": {"2.0": "AC", "3.1": "AC"},
            "C": {"2.0": "C", "3.1": "C"},
            "I": {"2.0": "I", "3.1": "I"},
            "A": {"2.0": "A", "3.1": "A"},
        }
        value_mapping = {
            "AV": {
                "N": {"2.0": "N", "3.1": "N"},
                "A": {"2.0": "A", "3.1": "A"},
                "L": {"2.0": "L", "3.1": "L"},
            },
            "AC": {
                "L": {"2.0": "L", "3.1": "L"},
                "H": {"2.0": "H", "3.1": "H"},
            },
            "C": {"N": {"2.0": "N", "3.1": "N"}, "H": {"2.0": "C", "3.1": "H"}},
            "I": {"N": {"2.0": "N", "3.1": "N"}, "H": {"2.0": "C", "3.1": "H"}},
            "A": {"N": {"2.0": "N", "3.1": "N"}, "H": {"2.0": "C", "3.1": "H"}},
        }
        canonical_domains = {
            "AV": ("N", "A", "L"),
            "AC": ("L", "H"),
            "C": ("N", "H"),
            "I": ("N", "H"),
            "A": ("N", "H"),
        }
        baseline = {
            "2.0": {"AV": "N", "AC": "L", "Au": "N", "C": "N", "I": "N", "A": "N"},
            "3.1": {
                "AV": "N",
                "AC": "L",
                "PR": "N",
                "UI": "N",
                "S": "U",
                "C": "N",
                "I": "N",
                "A": "N",
            },
        }
        return metric_mapping, value_mapping, canonical_domains, baseline

    def test_surprise_jump_between_versions(self):
        policy = make_policy()
        metric_mapping, value_mapping, domains, baseline = self._spec()
        report = compare_versions(
            ["2.0", "3.1"],
            ["AV", "AC", "C", "I", "A"],
            metric_mapping,
            value_mapping,
            domains,
            policy,
            baseline,
        )
        self.assertEqual(48, len(report.shared_vectors))
        self.assertEqual(0, len(report.unavailable))
        surprises = report.surprise_edges()
        self.assertGreater(len(surprises), 0)
        av_surprise = next(edge for edge in surprises if edge.fact == "AV:N->A")
        self.assertEqual(["High", "High"], av_surprise.bands["2.0"])
        self.assertEqual(["Critical", "High"], av_surprise.bands["3.1"])


if __name__ == "__main__":
    unittest.main()
