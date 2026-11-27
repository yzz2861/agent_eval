import sys
import unittest
from os import path

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))

from cvss import CVSSJointCheckError, joint_check


LOW_VECTOR = (
    "CVSS:4.0/AV:L/AC:H/AT:P/PR:N/UI:P/VC:H/VI:N/VA:N/"
    "SC:N/SI:N/AU:N/SA:N/S:P/R:A/V:D/RE:L/U:Red/MAV:L/MAC:L/MAT:N/"
    "MPR:L/MUI:A/MVC:L/MVI:N/MVA:H/MSC:H/MSI:L/MSA:N/CR:H/IR:L/AR:L/E:P"
)
MEDIUM_VECTOR = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L"
HIGH_VECTOR = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"


class TestJointCheck(unittest.TestCase):
    def test_returns_combinations_allowed_by_shared_observation(self):
        result = joint_check(
            {
                "announcement-a": {
                    "candidates": [
                        {
                            "vector": LOW_VECTOR,
                            "observations": {"deployment": "current", "access": "local"},
                        },
                        {
                            "vector": MEDIUM_VECTOR,
                            "observations": {"deployment": "current", "access": "network"},
                        },
                    ]
                },
                "announcement-b": {
                    "candidates": [
                        {
                            "vector": LOW_VECTOR,
                            "observations": {"deployment": "current", "access": "local"},
                        },
                        {
                            "vector": MEDIUM_VECTOR,
                            "observations": {"deployment": "current", "access": "network"},
                        },
                    ]
                },
            },
            [
                {
                    "relation": "equal",
                    "left": {
                        "announcement": "announcement-a",
                        "observation": "deployment",
                    },
                    "right": {
                        "announcement": "announcement-b",
                        "observation": "deployment",
                    },
                }
            ],
            threshold="Medium",
        )

        self.assertTrue(result.is_feasible)
        self.assertTrue(result.is_determined)
        self.assertEqual(4, len(result.combinations))
        self.assertEqual(
            [
                {"announcement-a": "Low", "announcement-b": "Low"},
                {"announcement-a": "Low", "announcement-b": "Medium"},
                {"announcement-a": "Medium", "announcement-b": "Low"},
                {"announcement-a": "Medium", "announcement-b": "Medium"},
            ],
            result.severity_combinations,
        )
        self.assertEqual(
            "Low", result.combinations[0]["announcement-a"]["severity"]
        )
        self.assertEqual(
            "Low", result.combinations[0]["announcement-b"]["severity"]
        )
        self.assertEqual(
            "current",
            result.combinations[0]["announcement-a"]["observations"]["deployment"],
        )

    def test_undetermined_when_no_candidate_satisfies_threshold(self):
        result = joint_check(
            {
                "announcement-a": {
                    "candidates": [
                        {
                            "vector": HIGH_VECTOR,
                            "observations": {"deployment": "current"},
                        }
                    ]
                },
                "announcement-b": {
                    "candidates": [
                        {
                            "vector": MEDIUM_VECTOR,
                            "observations": {"deployment": "current"},
                        }
                    ]
                },
            },
            threshold="Medium",
        )

        self.assertFalse(result.is_feasible)
        self.assertEqual(["announcement-a"], result.undetermined_announcements)
        self.assertEqual([], result.combinations)
        self.assertEqual([], result.conflicts)
        rejected = result.rejected_candidates["announcement-a"][0]
        self.assertEqual("High", rejected["severity"])
        self.assertEqual(
            "severity High is above threshold Medium", rejected["rejection_reason"]
        )

    def test_reports_bound_observations_and_tier_conflict(self):
        result = joint_check(
            {
                "announcement-a": {
                    "candidates": [
                        {
                            "vector": LOW_VECTOR,
                            "observations": {"deployment": "current", "access": "local"},
                        },
                        {
                            "vector": MEDIUM_VECTOR,
                            "observations": {"deployment": "current", "access": "network"},
                        },
                    ]
                },
                "announcement-b": {
                    "candidates": [
                        {
                            "vector": LOW_VECTOR,
                            "observations": {"deployment": "current", "access": "local"},
                        },
                        {
                            "vector": MEDIUM_VECTOR,
                            "observations": {"deployment": "current", "access": "network"},
                        },
                    ]
                },
            },
            [
                {
                    "relation": "mutually_exclusive",
                    "left": {
                        "announcement": "announcement-a",
                        "observation": "access",
                    },
                    "right": {
                        "announcement": "announcement-b",
                        "observation": "access",
                    },
                }
            ],
            threshold="Medium",
        )

        self.assertTrue(result.is_feasible)
        self.assertFalse(result.is_determined)
        self.assertEqual(2, len(result.combinations))
        self.assertEqual(2, len(result.conflicts))
        conflict = result.conflicts[0]
        self.assertEqual("mutually_exclusive", conflict["relation"])
        self.assertEqual("access", conflict["observations"][0]["observation"])
        self.assertEqual("local", conflict["observations"][0]["value"])
        self.assertEqual("local", conflict["observations"][1]["value"])
        self.assertEqual({"announcement-a": "Low", "announcement-b": "Low"}, conflict["severities"])

    def test_equal_relation_can_eliminate_all_combinations(self):
        result = joint_check(
            {
                "announcement-a": {
                    "candidates": [
                        {
                            "vector": LOW_VECTOR,
                            "observations": {"access": "local"},
                        }
                    ]
                },
                "announcement-b": {
                    "candidates": [
                        {
                            "vector": MEDIUM_VECTOR,
                            "observations": {"access": "network"},
                        }
                    ]
                },
            },
            [
                {
                    "relation": "equal",
                    "left": {
                        "announcement": "announcement-a",
                        "observation": "access",
                    },
                    "right": {
                        "announcement": "announcement-b",
                        "observation": "access",
                    },
                }
            ],
            threshold="Medium",
        )

        self.assertFalse(result.is_feasible)
        self.assertEqual([], result.undetermined_announcements)
        self.assertEqual(1, len(result.conflicts))
        self.assertEqual("equal", result.conflicts[0]["relation"])
        self.assertEqual(
            ["local", "network"],
            [item["value"] for item in result.conflicts[0]["observations"]],
        )

    def test_numeric_threshold_uses_cvss_score(self):
        result = joint_check(
            {
                "announcement-a": {
                    "candidates": [
                        {"vector": MEDIUM_VECTOR, "observations": {"access": "network"}},
                        {"vector": HIGH_VECTOR, "observations": {"access": "local"}},
                    ]
                }
            },
            threshold=6.0,
        )

        self.assertEqual(["announcement-a"], result.undetermined_announcements)
        self.assertEqual([], result.candidates["announcement-a"])
        self.assertEqual(
            "score 8.7 is above threshold 6.0",
            result.rejected_candidates["announcement-a"][1]["rejection_reason"],
        )

    def test_accepts_caller_supplied_candidate_without_vector(self):
        result = joint_check(
            {
                "announcement-a": {
                    "candidates": [
                        {
                            "severity": "Medium",
                            "score": 6.5,
                            "observations": {"access": "network"},
                        }
                    ]
                },
                "announcement-b": {
                    "candidates": [
                        {
                            "severity": "Low",
                            "score": 3.5,
                            "observations": {"access": "network"},
                        }
                    ]
                },
            },
            [
                {
                    "relation": "equal",
                    "left": {
                        "announcement": "announcement-a",
                        "observation": "access",
                    },
                    "right": {
                        "announcement": "announcement-b",
                        "observation": "access",
                    },
                }
            ],
        )

        self.assertTrue(result.is_feasible)
        self.assertEqual(6.5, result.combinations[0]["announcement-a"]["score"])
        self.assertIsNone(result.combinations[0]["announcement-a"]["vector"])

    def test_per_announcement_threshold_overrides_global_threshold(self):
        result = joint_check(
            {
                "announcement-a": {
                    "threshold": 9.0,
                    "candidates": [
                        {"vector": HIGH_VECTOR, "observations": {"access": "local"}}
                    ],
                },
                "announcement-b": {
                    "threshold": "Low",
                    "candidates": [
                        {"vector": MEDIUM_VECTOR, "observations": {"access": "network"}}
                    ],
                },
            }
        )

        self.assertEqual(["announcement-b"], result.undetermined_announcements)
        self.assertEqual("High", result.candidates["announcement-a"][0]["severity"])

    def test_invalid_vector_raises_joint_check_error(self):
        with self.assertRaises(CVSSJointCheckError):
            joint_check(
                {
                    "announcement-a": {
                        "candidates": [{"vector": "CVSS:4.0/AV:bad"}]
                    }
                }
            )

    def test_invalid_threshold_raises_joint_check_error(self):
        with self.assertRaises(CVSSJointCheckError):
            joint_check(
                {
                    "announcement-a": {
                        "candidates": [
                            {
                                "severity": "Low",
                                "score": 3.5,
                                "observations": {"access": "local"},
                            }
                        ]
                    }
                },
                threshold="Unknown",
            )

    def test_accepts_cvss2_and_cvss3_vectors(self):
        result = joint_check(
            {
                "announcement-a": {
                    "candidates": [
                        {
                            "vector": (
                                "AV:L/AC:L/Au:M/C:N/I:P/A:C/E:U/RL:W/RC:ND/"
                                "CDP:L/TD:H/CR:ND/IR:ND/AR:M"
                            ),
                            "observations": {"deployment": "current"},
                        }
                    ]
                },
                "announcement-b": {
                    "candidates": [
                        {
                            "vector": (
                                "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:N/"
                                "E:H/RL:O/RC:R/CR:H/MAC:H/MC:L"
                            ),
                            "observations": {"deployment": "current"},
                        }
                    ]
                },
            },
            [
                {
                    "relation": "equal",
                    "left": {
                        "announcement": "announcement-a",
                        "observation": "deployment",
                    },
                    "right": {
                        "announcement": "announcement-b",
                        "observation": "deployment",
                    },
                }
            ],
        )

        self.assertTrue(result.is_feasible)
        self.assertEqual("Medium", result.combinations[0]["announcement-a"]["severity"])
        self.assertEqual("Medium", result.combinations[0]["announcement-b"]["severity"])


if __name__ == "__main__":
    unittest.main()
