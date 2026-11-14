import ast
import json
import sys
import unittest
from os import path

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))

from cvss.cvss4 import CVSS4
from cvss.exceptions import (
    CVSS4MalformedError,
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
        self.assertEqual(("LOW"), CVSS4(v).as_json()["baseSeverity"], v)

        v = (
            "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:P/VC:N/VI:L/VA:L/"
            "SC:H/SI:N/AU:Y/SA:N/S:N/R:I/V:C/RE:M/U:Amber/MAV:L/MAC:H/MAT:P"
            "/MPR:N/MUI:P/MVC:L/MVI:N/MVA:H/MSC:H/MSI:H/MSA:S/CR:M/IR:M/AR:M/E:A"
        )
        self.assertEqual(("High"), CVSS4(v).severity, v)
        self.assertEqual(("HIGH"), CVSS4(v).as_json()["baseSeverity"], v)

        v = (
            "CVSS:4.0/AV:N/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/"
            "SC:L/SI:N/AU:Y/SA:L/S:P/R:U/V:D/RE:M/U:Red/MAV:N/MAC:H/MAT:P"
            "/MPR:H/MUI:P/MVC:L/MVI:H/MVA:L/MSC:N/MSI:H/MSA:H/CR:L/IR:H/AR:M/E:U"
        )
        self.assertEqual(("Low"), CVSS4(v).severity, v)
        self.assertEqual(("LOW"), CVSS4(v).as_json()["baseSeverity"], v)

        v = (
            "CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/"
            "SC:N/SI:H/AU:N/SA:L/S:P/R:U/V:D/RE:H/U:Clear/MAV:A/MAC:L/MAT:N"
            "/MPR:N/MUI:P/MVC:N/MVI:L/MVA:L/MSC:H/MSI:N/MSA:L/CR:M/IR:M/AR:L/E:U"
        )
        self.assertEqual(("Low"), CVSS4(v).severity, v)
        self.assertEqual(("LOW"), CVSS4(v).as_json()["baseSeverity"], v)

        v = (
            "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:A/VC:H/VI:H/VA:N/"
            "SC:H/SI:N/AU:Y/SA:N/S:N/R:I/V:C/RE:L/U:Green/MAV:L/MAC:L/MAT:N"
            "/MPR:H/MUI:P/MVC:L/MVI:L/MVA:N/MSC:H/MSI:H/MSA:S/CR:H/IR:H/AR:H/E:P"
        )
        self.assertEqual(("Medium"), CVSS4(v).severity, v)
        self.assertEqual(("MEDIUM"), CVSS4(v).as_json()["baseSeverity"], v)

        v = (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:H/"
            "SC:H/SI:L/AU:Y/SA:H/S:N/R:U/V:C/RE:M/U:Amber/MAV:L/MAC:H/MAT:N"
            "/MPR:H/MUI:N/MVC:N/MVI:L/MVA:N/MSC:L/MSI:S/MSA:H/CR:H/IR:M/AR:M/E:A"
        )
        self.assertEqual(("Medium"), CVSS4(v).severity, v)
        self.assertEqual(("MEDIUM"), CVSS4(v).as_json()["baseSeverity"], v)

        v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L"
        self.assertEqual(("Medium"), CVSS4(v).severity, v)
        self.assertEqual(("MEDIUM"), CVSS4(v).as_json()["baseSeverity"], v)

        v = (
            "CVSS:4.0/AV:A/AC:H/AT:P/PR:N/UI:P/VC:N/VI:L/VA:N/"
            "SC:H/SI:H/AU:N/SA:N/S:N/R:A/V:C/RE:M/U:Green/MAV:L/MAC:L/MAT:P"
            "/MPR:L/MUI:A/MVC:N/MVI:L/MVA:H/MSC:L/MSI:N/MSA:S/CR:L/IR:L/AR:M/E:P"
        )
        self.assertEqual(("Low"), CVSS4(v).severity, v)
        self.assertEqual(("LOW"), CVSS4(v).as_json()["baseSeverity"], v)

        v = (
            "CVSS:4.0/AV:A/AC:H/AT:N/PR:H/UI:A/VC:H/VI:N/VA:H/"
            "SC:L/SI:N/AU:N/SA:H/S:P/R:I/V:D/RE:M/U:Red/MAV:N/MAC:L/MAT:N"
            "/MPR:N/MUI:N/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/CR:H/IR:H/AR:H/E:U"
        )
        self.assertEqual(("Critical"), CVSS4(v).severity, v)
        self.assertEqual(("CRITICAL"), CVSS4(v).as_json()["baseSeverity"], v)

        v = (
            "CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:P/VC:L/VI:N/VA:H/"
            "SC:L/SI:N/AU:Y/SA:H/S:P/R:I/V:D/RE:H/U:Green/MAV:A/MAC:L/MAT:N"
            "/MPR:N/MUI:A/MVC:L/MVI:H/MVA:H/MSC:N/MSI:H/MSA:L/CR:L/IR:H/AR:L/E:U"
        )
        self.assertEqual(("Medium"), CVSS4(v).severity, v)
        self.assertEqual(("MEDIUM"), CVSS4(v).as_json()["baseSeverity"], v)

        v = (
            "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:N/VC:L/VI:N/VA:H/"
            "SC:L/SI:H/AU:N/SA:H/S:P/R:U/V:C/RE:H/U:Red/MAV:L/MAC:L/MAT:P"
            "/MPR:L/MUI:P/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/CR:H/IR:H/AR:H/E:P"
        )
        self.assertEqual(("None"), CVSS4(v).severity, v)
        self.assertEqual(("NONE"), CVSS4(v).as_json()["baseSeverity"], v)

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
        self.assertIn("availabilityRequirement", json_data)

    def test_json_schema_high_msi(self):
        v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/MSI:H"
        json_data = CVSS4(v).as_json(minimal=True)
        # Selectively test some values
        self.assertEqual(json_data["baseScore"], 7.7)
        self.assertEqual(json_data["vectorString"], v)
        self.assertIn("modifiedSubIntegrityImpact", json_data)
        self.assertIn("subIntegrityImpact", json_data)

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


    def test_json_severity_boundaries(self):
        doc = (
            "Severity buckets follow the CVSS v4.0 rating scale with half-up rounding "
            "(None 0.0, Low 0.1-3.9, Medium 4.0-6.9, High 7.0-8.9, Critical 9.0-10.0)."
        )
        boundaries = {
            "CVSS:4.0/AV:P/AC:H/AT:N/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N": "NONE",
            "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:H/SA:H/S:N/"
            "AU:Y/R:U/V:D/RE:L/U:Green/MAV:L/MAC:H/MAT:P/MPR:N/MUI:P/MVC:H/"
            "MVI:L/MVA:H/MSC:H/MSI:H/MSA:L/CR:H/IR:M/AR:M/E:U": "LOW",
            "CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:H/SA:N": "MEDIUM",
            "CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:A/VC:N/VI:H/VA:N/SC:N/SI:N/SA:L/S:N/"
            "AU:N/R:A/V:D/RE:L/U:Red/MAV:N/MAC:H/MAT:P/MPR:N/MUI:N/MVC:N/"
            "MVI:H/MVA:L/MSC:N/MSI:S/MSA:H/CR:L/IR:H/AR:M/E:P": "HIGH",
            "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:L/SI:L/SA:H": "CRITICAL",
        }
        for vector, expected_severity in boundaries.items():
            cvss = CVSS4(vector)
            data = cvss.as_json()
            self.assertEqual(cvss.scores()[0], data["baseScore"], vector)
            self.assertEqual(expected_severity, data["baseSeverity"], vector)
            self.assertNotIn("None", data.values())

    def test_json_minimal_base_only_structure(self):
        doc = "Minimal JSON contains only required base metrics and the version prefix."
        v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L"
        data = CVSS4(v).as_json(minimal=True)
        self.assertEqual("4.0", data["version"])
        self.assertEqual(v, data["vectorString"])
        for key in (
            "exploitMaturity",
            "confidentialityRequirement",
            "modifiedAttackVector",
            "Safety",
            "providerUrgency",
        ):
            self.assertNotIn(key, data)
        # 11 mandatory metrics plus version, vectorString, baseScore and baseSeverity.
        self.assertEqual(15, len(data))

    def test_json_minimal_includes_only_present_optional_metrics(self):
        doc = "Minimal output keeps explicitly supplied optional metrics only."
        v = (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N/"
            "AR:L"
        )
        data = CVSS4(v).as_json(minimal=True)
        self.assertIn("availabilityRequirement", data)
        self.assertEqual("LOW", data["availabilityRequirement"])
        self.assertNotIn("confidentialityRequirement", data)
        self.assertNotIn("modifiedAttackVector", data)

    def test_json_unset_optional_metrics_not_faked_as_defaults(self):
        doc = "Unset optional metrics serialize to NOT_DEFINED, not computation defaults."
        v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L"
        data = CVSS4(v).as_json()
        self.assertEqual("NOT_DEFINED", data["exploitMaturity"])
        self.assertEqual("NOT_DEFINED", data["modifiedAttackVector"])
        self.assertEqual("NOT_DEFINED", data["modifiedVulnConfidentialityImpact"])
        self.assertEqual("NOT_DEFINED", data["Safety"])
        self.assertEqual("NOT_DEFINED", data["providerUrgency"])
        # Mandatory base metrics remain concrete enum values.
        self.assertEqual("NETWORK", data["attackVector"])
        self.assertEqual("LOW", data["vulnConfidentialityImpact"])

    def test_json_schema_enum_spelling(self):
        doc = "Schema-specific enum spellings are emitted correctly."
        v = (
            "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/"
            "E:P/R:U/MSC:N/MSI:N/MSA:N/S:N"
        )
        data = CVSS4(v).as_json()
        self.assertEqual("ADJACENT", data["attackVector"])
        self.assertEqual("PROOF_OF_CONCEPT", data["exploitMaturity"])
        self.assertEqual("USER", data["Recovery"])
        self.assertEqual("NONE", data["modifiedSubConfidentialityImpact"])
        self.assertEqual("NONE", data["modifiedSubIntegrityImpact"])
        self.assertEqual("NEGLIGIBLE", data["Safety"])

    def test_json_round_trip_preserves_scores(self):
        doc = "JSON dump/load round-trip preserves score, severity and vector rebuild."
        vectors = [
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
            "CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:H/SA:N",
            "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:L/SI:L/SA:H",
            "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/"
            "S:P/AU:Y/R:A/V:D/RE:L/U:Red/MAV:L/MAC:L/MAT:N/MPR:L/MUI:A/"
            "MVC:L/MVI:N/MVA:H/MSC:H/MSI:L/MSA:N/CR:H/IR:L/AR:L/E:P",
        ]
        for vector in vectors:
            original = CVSS4(vector)
            decoded = json.loads(json.dumps(original.as_json()))
            self.assertEqual(original.scores()[0], decoded["baseScore"], vector)
            self.assertEqual(original.as_json()["baseSeverity"], decoded["baseSeverity"], vector)
            rebuilt = CVSS4(decoded["vectorString"])
            self.assertEqual(original.scores(), rebuilt.scores(), vector)
            self.assertEqual(original.as_json(), rebuilt.as_json(), vector)

    def test_json_round_trip_minimal_and_sorted(self):
        v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L"
        for kwargs in ({"minimal": True}, {"sort": True}, {"sort": True, "minimal": True}):
            data = CVSS4(v).as_json(**kwargs)
            decoded = json.loads(json.dumps(data))
            self.assertEqual(data, decoded)
            self.assertEqual(6.9, decoded["baseScore"])

    def test_json_contains_only_serializable_primitives(self):
        v = (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/"
            "E:P/CR:H/MAV:N/S:P/U:Red"
        )
        data = CVSS4(v).as_json()
        json.dumps(data)
        for value in data.values():
            self.assertIsInstance(value, (str, float, int, bool, type(None)))

    def test_json_serialization_errors_are_library_exceptions(self):
        doc = "Serialization failures raise CVSS library exceptions, not raw KeyError."
        cvss = CVSS4("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L")
        cvss.original_metrics["E"] = "BOGUS"
        self.assertRaises(CVSS4MalformedError, cvss.as_json)
        self.assertTrue(cvss.clean_vector().startswith("CVSS:4.0/"))


if __name__ == "__main__":
    unittest.main()
