import itertools
import sys
import unittest
from os import path

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))

from cvss.cvss4 import CVSS4
from cvss.exceptions import CVSS4MalformedError, CVSS4UnsatisfiableError
from cvss.range4 import score_range


class TestCVSS4Range(unittest.TestCase):
    def assert_endpoints_rescorable(self, result):
        """
        The existing scoring API must be able to independently recompute both
        endpoints from the returned complete vectors.
        """
        self.assertEqual(result.min_score, CVSS4(result.min_vector).base_score)
        self.assertEqual(result.max_score, CVSS4(result.max_vector).base_score)

    def assert_matches_brute_force(self, vector, constraints, varied_metrics):
        """
        Cross-checks the range endpoints against a small-scale exhaustive
        enumeration of the candidate combinations scored one by one.
        """
        result = score_range(vector, constraints)
        fixed = {}
        if vector:
            for field in vector.split("/")[1:]:
                metric, value = field.split(":")
                fixed[metric] = value
        for metric, constraint in constraints.items():
            if metric not in varied_metrics:
                value = constraint if isinstance(constraint, str) else constraint[0]
                fixed[metric] = value
        scores = []
        for combination in itertools.product(*(constraints[m] for m in varied_metrics)):
            metrics = dict(fixed)
            metrics.update(zip(varied_metrics, combination))
            full_vector = "CVSS:4.0/" + "/".join(
                "{0}:{1}".format(metric, metrics[metric]) for metric in sorted(metrics)
            )
            scores.append(CVSS4(full_vector).base_score)
        self.assertEqual(min(scores), result.min_score)
        self.assertEqual(max(scores), result.max_score)
        self.assert_endpoints_rescorable(result)

    def test_fixed_vector_degenerates(self):
        """
        A fully specified vector has a single reachable score.
        """
        vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
        result = score_range(vector)
        self.assertEqual(CVSS4(vector).base_score, result.min_score)
        self.assertEqual(CVSS4(vector).base_score, result.max_score)
        self.assert_endpoints_rescorable(result)

    def test_fix_and_narrow(self):
        """
        Constraints may fix a metric to a single value or only narrow its
        candidate set; known threat and environmental metrics are taken from
        the vector.
        """
        vector = "CVSS:4.0/AV:N/AC:L/PR:N/UI:N/E:P/CR:H/IR:M"
        constraints = {
            "AT": ["N", "P"],
            "VC": "H",
            "VI": ["H", "L"],
            "VA": ["L", "N"],
            "SC": ["H", "N"],
            "SI": ["L", "N"],
            "SA": ["H", "L", "N"],
        }
        result = score_range(vector, constraints)
        self.assertEqual(6.9, result.min_score)
        self.assertEqual(9.3, result.max_score)
        self.assert_endpoints_rescorable(result)

    def test_small_exhaustive_crosscheck(self):
        """
        Small fixture cross-checked against brute-force enumeration, including
        a known modified environmental metric.
        """
        vector = "CVSS:4.0/AV:A/AC:H/AT:N/PR:L/E:A/MAV:N"
        constraints = {
            "UI": ["N", "P", "A"],
            "VC": ["H", "L", "N"],
            "VI": ["H", "N"],
            "VA": "L",
            "SC": ["H", "L", "N"],
            "SI": ["H", "L", "N"],
            "SA": ["H", "L", "N"],
        }
        varied = ["UI", "VC", "VI", "SC", "SI", "SA"]
        self.assert_matches_brute_force(vector, constraints, varied)

    def test_threat_environmental_exhaustive_crosscheck(self):
        """
        Ranging over threat and environmental candidates follows the official
        scoring rules, verified by brute-force enumeration.
        """
        vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
        constraints = {
            "E": ["X", "A", "P", "U"],
            "CR": ["X", "H", "M", "L"],
            "IR": ["X", "H", "M", "L"],
            "AR": ["X", "H", "M", "L"],
        }
        varied = ["E", "CR", "IR", "AR"]
        self.assert_matches_brute_force(vector, constraints, varied)

    def test_naive_per_metric_lowest_misses_lower_bound(self):
        """
        Picking the apparently lowest value per metric misses the true lower
        bound: "X" (not defined) looks like "no impact" but the official rules
        score it as the worst-case default (E:X as A, CR/IR/AR:X as H).
        """
        vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
        constraints = {
            "E": ["X", "A", "P", "U"],
            "CR": ["X", "H", "M", "L"],
            "IR": ["X", "H", "M", "L"],
            "AR": ["X", "H", "M", "L"],
        }
        naive_vector = vector + "/E:X/CR:X/IR:X/AR:X"
        naive_score = CVSS4(naive_vector).base_score
        result = score_range(vector, constraints)
        self.assertEqual(10.0, naive_score)
        self.assertEqual(7.9, result.min_score)
        self.assertLess(result.min_score, naive_score)
        self.assertEqual(10.0, result.max_score)
        self.assert_endpoints_rescorable(result)

    def test_supplemental_metrics_do_not_change_score(self):
        """
        Supplemental metrics never influence the score, so constraining them
        keeps the endpoints of the unconstrained range.
        """
        vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
        plain = score_range(vector)
        constrained = score_range(vector, {"AU": ["N", "Y"], "S": ["N", "P"]})
        self.assertEqual(plain.min_score, constrained.min_score)
        self.assertEqual(plain.max_score, constrained.max_score)
        self.assert_endpoints_rescorable(constrained)

    def test_unsatisfiable_constraints(self):
        vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
        # Empty candidate set
        self.assertRaises(
            CVSS4UnsatisfiableError, score_range, vector, {"E": []}
        )
        # Constraint contradicts the value fixed in the vector
        self.assertRaises(
            CVSS4UnsatisfiableError, score_range, vector, {"AV": ["A", "L"]}
        )

    def test_malformed_input(self):
        vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
        # Unknown metric in constraints
        self.assertRaises(CVSS4MalformedError, score_range, vector, {"XX": "N"})
        # Unknown value in constraints
        self.assertRaises(CVSS4MalformedError, score_range, vector, {"AV": "Q"})
        # Missing prefix
        self.assertRaises(CVSS4MalformedError, score_range, "AV:N/AC:L")
        # Trailing slash
        self.assertRaises(CVSS4MalformedError, score_range, vector + "/")
        # Duplicate metric
        self.assertRaises(
            CVSS4MalformedError,
            score_range,
            "CVSS:4.0/AV:N/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
        )
        # Invalid value in vector
        self.assertRaises(
            CVSS4MalformedError,
            score_range,
            "CVSS:4.0/AV:Q/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
        )


if __name__ == "__main__":
    unittest.main()
