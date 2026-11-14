import ast
import sys
import unittest
from os import path

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))

from cvss.cvss4 import CVSS4
from cvss.exceptions import (
    CVSS4DependencyError,
    CVSS4MalformedError,
    CVSS4MandatoryError,
    CVSS4RHMalformedError,
    CVSS4RHScoreDoesNotMatch,
)

WD = path.dirname(path.abspath(sys.argv[0]))  # Manage to run script anywhere in the path


class TestCVSS4(unittest.TestCase):
    def run_tests_from_file(self, test_name):
        with open(path.join(WD, test_name)) as f:
            for line in f:
                vector, expected_score = line.split(" - ")
                expected_score = expected_score.replace("(", "").replace(")", "")
                expected_score = float(expected_score)
                result = CVSS4(vector)
                results_score = result.base_score
                self.assertEqual(expected_score, results_score, test_name + " - " + vector)
                results_json_score = result.as_json()["baseScore"]
                self.assertEqual(
                    expected_score, results_json_score, test_name + " - " + vector + " - JSON"
                )

    def run_rh_tests_from_file(self, test_name):
        with open(path.join(WD, test_name)) as f:
            for line in f:
                vector, expected_scores = line.strip().split(" - ")
                expected_scores = ast.literal_eval(expected_scores)
                tested_rh_vector = str(expected_scores[0]) + "/" + vector
                result = CVSS4.from_rh_vector(tested_rh_vector)
                results_scores = result.scores()
                self.assertEqual(expected_scores, results_scores, test_name + " - " + vector)

    def test_base(self):
        """
        All vector combinations with only mandatory fields, 104,976 bn vectors.
        """
        self.run_tests_from_file("vectors_base4")

    def test_modified(self):
        """
        All vector combinations of modified environmental fields, 373,248 vectors.
        """
        self.run_tests_from_file("vectors_modified4")

    def test_supplemental(self):
        """
        All vector combinations of supplemental fields, 576 vectors.
        """
        self.run_tests_from_file("vectors_supplemental4")

    def test_security(self):
        """
        All vector combinations of security fields, 54 vectors.
        """
        self.run_tests_from_file("vectors_security4")

    def test_threat(self):
        """
        All vector combinations of threat fields, 6 vectors.
        """
        self.run_tests_from_file("vectors_threat4")

    def test_random(self):
        """
        Random vector combinations across all fields, 10,000 bn vectors.
        """
        self.run_tests_from_file("vectors_random4")

    def test_severity(self):
        """
        Tests for computing severities.
        """

        v = (
            "CVSS:4.0/AV:L/AC:H/AT:P/PR:N/UI:P/VC:H/VI:N/VA:N/"
            "SC:N/SI:N/AU:N/SA:N/S:P/R:A/V:D/RE:L/U:Red/MAV:L/MAC:L/MAT:N/"
            "MPR:L/MUI:A/MVC:L/MVI:N/MVA:H/MSC:H/MSI:L/MSA:N/CR:H/IR:L/AR:L/E:P"
        )
        self.assertEqual(("Low"), CVSS4(v).severity, v)
        self.assertEqual(("Low"), CVSS4(v).as_json()["baseSeverity"], v)

        v = (
            "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:P/VC:N/VI:L/VA:L/"
            "SC:H/SI:N/AU:Y/SA:N/S:N/R:I/V:C/RE:M/U:Amber/MAV:L/MAC:H/MAT:P"
            "/MPR:N/MUI:P/MVC:L/MVI:N/MVA:H/MSC:H/MSI:H/MSA:S/CR:M/IR:M/AR:M/E:A"
        )
        self.assertEqual(("High"), CVSS4(v).severity, v)
        self.assertEqual(("High"), CVSS4(v).as_json()["baseSeverity"], v)

        v = (
            "CVSS:4.0/AV:N/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/"
            "SC:L/SI:N/AU:Y/SA:L/S:P/R:U/V:D/RE:M/U:Red/MAV:N/MAC:H/MAT:P"
            "/MPR:H/MUI:P/MVC:L/MVI:H/MVA:L/MSC:N/MSI:H/MSA:H/CR:L/IR:H/AR:M/E:U"
        )
        self.assertEqual(("Low"), CVSS4(v).severity, v)
        self.assertEqual(("Low"), CVSS4(v).as_json()["baseSeverity"], v)

        v = (
            "CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/"
            "SC:N/SI:H/AU:N/SA:L/S:P/R:U/V:D/RE:H/U:Clear/MAV:A/MAC:L/MAT:N"
            "/MPR:N/MUI:P/MVC:N/MVI:L/MVA:L/MSC:H/MSI:N/MSA:L/CR:M/IR:M/AR:L/E:U"
        )
        self.assertEqual(("Low"), CVSS4(v).severity, v)
        self.assertEqual(("Low"), CVSS4(v).as_json()["baseSeverity"], v)

        v = (
            "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:A/VC:H/VI:H/VA:N/"
            "SC:H/SI:N/AU:Y/SA:N/S:N/R:I/V:C/RE:L/U:Green/MAV:L/MAC:L/MAT:N"
            "/MPR:H/MUI:P/MVC:L/MVI:L/MVA:N/MSC:H/MSI:H/MSA:S/CR:H/IR:H/AR:H/E:P"
        )
        self.assertEqual(("Medium"), CVSS4(v).severity, v)
        self.assertEqual(("Medium"), CVSS4(v).as_json()["baseSeverity"], v)

        v = (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:H/"
            "SC:H/SI:L/AU:Y/SA:H/S:N/R:U/V:C/RE:M/U:Amber/MAV:L/MAC:H/MAT:N"
            "/MPR:H/MUI:N/MVC:N/MVI:L/MVA:N/MSC:L/MSI:S/MSA:H/CR:H/IR:M/AR:M/E:A"
        )
        self.assertEqual(("Medium"), CVSS4(v).severity, v)
        self.assertEqual(("Medium"), CVSS4(v).as_json()["baseSeverity"], v)

        v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L"
        self.assertEqual(("Medium"), CVSS4(v).severity, v)
        self.assertEqual(("Medium"), CVSS4(v).as_json()["baseSeverity"], v)

        v = (
            "CVSS:4.0/AV:A/AC:H/AT:P/PR:N/UI:P/VC:N/VI:L/VA:N/"
            "SC:H/SI:H/AU:N/SA:N/S:N/R:A/V:C/RE:M/U:Green/MAV:L/MAC:L/MAT:P"
            "/MPR:L/MUI:A/MVC:N/MVI:L/MVA:H/MSC:L/MSI:N/MSA:S/CR:L/IR:L/AR:M/E:P"
        )
        self.assertEqual(("Low"), CVSS4(v).severity, v)
        self.assertEqual(("Low"), CVSS4(v).as_json()["baseSeverity"], v)

        v = (
            "CVSS:4.0/AV:A/AC:H/AT:N/PR:H/UI:A/VC:H/VI:N/VA:H/"
            "SC:L/SI:N/AU:N/SA:H/S:P/R:I/V:D/RE:M/U:Red/MAV:N/MAC:L/MAT:N"
            "/MPR:N/MUI:N/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/CR:H/IR:H/AR:H/E:U"
        )
        self.assertEqual(("Critical"), CVSS4(v).severity, v)
        self.assertEqual(("Critical"), CVSS4(v).as_json()["baseSeverity"], v)

        v = (
            "CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:P/VC:L/VI:N/VA:H/"
            "SC:L/SI:N/AU:Y/SA:H/S:P/R:I/V:D/RE:H/U:Green/MAV:A/MAC:L/MAT:N"
            "/MPR:N/MUI:A/MVC:L/MVI:H/MVA:H/MSC:N/MSI:H/MSA:L/CR:L/IR:H/AR:L/E:U"
        )
        self.assertEqual(("Medium"), CVSS4(v).severity, v)
        self.assertEqual(("Medium"), CVSS4(v).as_json()["baseSeverity"], v)

        v = (
            "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:N/VC:L/VI:N/VA:H/"
            "SC:L/SI:H/AU:N/SA:H/S:P/R:U/V:C/RE:H/U:Red/MAV:L/MAC:L/MAT:P"
            "/MPR:L/MUI:P/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/CR:H/IR:H/AR:H/E:P"
        )
        self.assertEqual(("None"), CVSS4(v).severity, v)
        self.assertEqual(("None"), CVSS4(v).as_json()["baseSeverity"], v)

    def test_json_schema_no_impact_metrics(self):
        v = "CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"
        json_data = CVSS4(v).as_json(minimal=True)
        # Selectively test some values
        self.assertEqual(json_data["baseScore"], 0.0)
        self.assertEqual(json_data["vectorString"], v)
        self.assertIn("attackVector", json_data)

    def test_json_schema_high_va(self):
        v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"
        json_data = CVSS4(v).as_json(minimal=True)
        # Selectively test some values
        self.assertEqual(json_data["baseScore"], 8.7)
        self.assertEqual(json_data["vectorString"], v)

    def test_json_schema_high_va_low_ar(self):
        v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N/AR:L"
        json_data = CVSS4(v).as_json(minimal=True)
        # Selectively test some values
        self.assertEqual(json_data["baseScore"], 7.9)
        self.assertEqual(json_data["vectorString"], v)
        self.assertIn("availabilityRequirements", json_data)

    def test_json_schema_high_msi(self):
        v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/MSI:H"
        json_data = CVSS4(v).as_json(minimal=True)
        # Selectively test some values
        self.assertEqual(json_data["baseScore"], 7.7)
        self.assertEqual(json_data["vectorString"], v)
        self.assertIn("modifiedSubsequentSystemImpactIntegrity", json_data)
        self.assertIn("subsequentSystemImpactIntegrity", json_data)

    def test_invalid_metric_key(self):
        v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/JJ:H"
        error = ""
        try:
            CVSS4(v)
        except CVSS4MalformedError as e:
            error = str(e)
        self.assertEqual(error, 'Invalid metric key in CVSS4 vector "JJ:H"')

    def test_invalid_metric_value(self):
        v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:J"
        error = ""
        try:
            CVSS4(v)
        except CVSS4MalformedError as e:
            error = str(e)
        self.assertEqual(error, 'Invalid metric value in CVSS4 vector "SA:J"')

    def test_duplicate_metric_key(self):
        v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SI:H"
        error = ""
        try:
            CVSS4(v)
        except CVSS4MalformedError as e:
            error = str(e)
        self.assertEqual(error, 'Duplicate metric "SI"')

    def test_rh_vector(self):
        """
        Test for parsing Red Hat style of CVSS vectors, e.g. containing score.
        """
        self.run_rh_tests_from_file("vectors_simple4")

        # Bad values
        v = "8.3/CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:N/SC:L/SI:L/SA:N"
        self.assertRaises(CVSS4RHScoreDoesNotMatch, CVSS4.from_rh_vector, v)

        v = "7.0/CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:N/VA:N/SC:N/SI:L/SA:N"
        self.assertRaises(CVSS4RHScoreDoesNotMatch, CVSS4.from_rh_vector, v)

        # Vector cannot be split to score/vector
        v = ""
        self.assertRaises(CVSS4RHMalformedError, CVSS4.from_rh_vector, v)

        v = "8.3|AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:H/SI:N/SA:L"
        self.assertRaises(CVSS4RHMalformedError, CVSS4.from_rh_vector, v)

        # Score is not float
        v = "ABC|AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:H/SI:N/SA:L"
        self.assertRaises(CVSS4RHMalformedError, CVSS4.from_rh_vector, v)

    def test_clean_vector_field_order(self):
        # This vector is sorted following the specification requirement and
        # should match the clean_vector.
        v = (
            "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/"
            "E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:N/MVI:N/"
            "MVA:N/MSC:N/MSI:N/MSA:N/S:P/AU:Y/R:I/V:C/RE:H/U:Red"
        )
        self.assertEqual(CVSS4(v).clean_vector(), v, "Invalid CVSS4 metric field order")
    def test_modified_metric_dependencies(self):
        """
        Modified (environmental) metrics depend on their base counterparts. Setting a
        modified metric without the metric it depends on must raise an error which
        names both metrics, instead of silently falling back to default values.
        """
        # MSI depends on SI
        v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SA:N/MSI:H"
        error = ""
        try:
            CVSS4(v)
        except CVSS4DependencyError as e:
            error = str(e)
        self.assertIn("MSI", error)
        self.assertIn("SI", error)

        # MSC depends on SC
        v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SI:N/SA:N/MSC:H"
        error = ""
        try:
            CVSS4(v)
        except CVSS4DependencyError as e:
            error = str(e)
        self.assertIn("MSC", error)
        self.assertIn("SC", error)

        # MSA depends on SA
        v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/MSA:S"
        error = ""
        try:
            CVSS4(v)
        except CVSS4DependencyError as e:
            error = str(e)
        self.assertIn("MSA", error)
        self.assertIn("SA", error)

        # MAV depends on AV
        v = "CVSS:4.0/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/MAV:N"
        error = ""
        try:
            CVSS4(v)
        except CVSS4DependencyError as e:
            error = str(e)
        self.assertIn("MAV", error)
        self.assertIn("AV", error)

        # Dependency errors are malformed vectors
        v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SA:N/MSI:H"
        self.assertRaises(CVSS4MalformedError, CVSS4, v)

        # Modified metric explicitly set to X is not defined, so it does not
        # require its dependency and falls back to the mandatory check
        v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SA:N/MSI:X"
        self.assertRaises(CVSS4MandatoryError, CVSS4, v)

    def test_modified_metric_inheritance(self):
        """
        Modified metrics which are not set inherit the defined value of the metric
        they depend on, so the score is the same whether the modified metric is
        missing, set to X, or set to the same value as its dependency.
        """
        base = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
        inherited = CVSS4(base)
        explicit_x = CVSS4(base + "/MSI:X")
        explicit_same = CVSS4(base + "/MSI:H")
        explicit_other = CVSS4(base + "/MAV:P")
        self.assertEqual(inherited.base_score, explicit_x.base_score)
        self.assertEqual(inherited.base_score, explicit_same.base_score)
        self.assertNotEqual(inherited.base_score, explicit_other.base_score)

    def test_scoring_order_stable(self):
        """
        The score and the cleaned vector must not depend on the order of fields in
        the input vector.
        """
        v_ordered = (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/"
            "E:P/MSI:S"
        )
        v_shuffled = (
            "CVSS:4.0/MSI:S/E:P/SA:H/SI:H/SC:H/VA:H/VI:H/VC:H/UI:N/PR:N/AT:N/"
            "AC:L/AV:N"
        )
        ordered = CVSS4(v_ordered)
        shuffled = CVSS4(v_shuffled)
        self.assertEqual(ordered.base_score, shuffled.base_score)
        self.assertEqual(ordered.clean_vector(), shuffled.clean_vector())
        self.assertEqual(ordered, shuffled)

    def test_base_threat_environmental_combinations(self):
        """
        Scores and JSON output for base, base+threat, base+environmental, and
        base+threat+environmental metric combinations.
        """
        base = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"

        # Base metrics only
        c = CVSS4(base)
        self.assertEqual(c.base_score, 10.0)
        self.assertEqual(c.severity, "Critical")
        json_data = c.as_json(minimal=True)
        self.assertIn("attackVector", json_data)
        self.assertNotIn("exploitMaturity", json_data)
        self.assertNotIn("modifiedAttackVector", json_data)
        self.assertNotIn("safety", json_data)

        # Base + threat
        c = CVSS4(base + "/E:U")
        self.assertEqual(c.base_score, 9.1)
        json_data = c.as_json(minimal=True)
        self.assertEqual(json_data["exploitMaturity"], "UNREPORTED")
        self.assertNotIn("modifiedAttackVector", json_data)

        # Base + environmental
        c = CVSS4(base + "/CR:L/IR:L/AR:L/MVC:L/MVI:L/MVA:L")
        self.assertEqual(c.base_score, 7.9)
        json_data = c.as_json(minimal=True)
        self.assertEqual(json_data["confidentialityRequirements"], "LOW")
        self.assertEqual(json_data["modifiedVulnerableSystemImpactConfidentiality"], "LOW")
        self.assertNotIn("exploitMaturity", json_data)

        # Base + threat + environmental (+ supplemental, which does not score)
        v = base + "/E:U/CR:L/IR:L/AR:L/MVC:L/MVI:L/MVA:L"
        c = CVSS4(v)
        self.assertEqual(c.base_score, 5.0)
        self.assertEqual(c.severity, "Medium")
        c_supplemental = CVSS4(v + "/S:P/AU:Y/R:A/V:C/RE:H/U:Red")
        self.assertEqual(c_supplemental.base_score, 5.0)
        json_data = c_supplemental.as_json(minimal=True)
        self.assertEqual(json_data["exploitMaturity"], "UNREPORTED")
        self.assertEqual(json_data["safety"], "PRESENT")

    def test_json_round_trip_preserves_original_selection(self):
        """
        as_json() reports the original selections (unset optional metrics are
        NOT_DEFINED, not the values they inherited for scoring) and a round-trip
        through the JSON vector string preserves the original vector.
        """
        v = (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/"
            "E:P/MSI:S"
        )
        c = CVSS4(v)
        json_data = c.as_json()
        self.assertEqual(json_data["vectorString"], v)
        self.assertEqual(json_data["modifiedSubsequentSystemImpactIntegrity"], "SAFETY")
        self.assertEqual(json_data["modifiedSubsequentSystemImpactConfidentiality"], "NOT_DEFINED")
        self.assertEqual(json_data["modifiedAttackVector"], "NOT_DEFINED")
        self.assertEqual(json_data["exploitMaturity"], "POC")

        restored = CVSS4(json_data["vectorString"])
        self.assertEqual(c, restored)
        self.assertEqual(c.base_score, restored.base_score)
        self.assertEqual(c.as_json(), restored.as_json())

        # Round-trip through the cleaned (minimal) vector is also stable
        cleaned = CVSS4(c.clean_vector())
        self.assertEqual(c, cleaned)
        self.assertEqual(c.base_score, cleaned.base_score)


if __name__ == "__main__":
    unittest.main()
