import json

from detect_secrets.derivation import analyze_observations
from detect_secrets.derivation import assert_no_plaintext
from detect_secrets.derivation import build_observations
from detect_secrets.derivation import build_report
from detect_secrets.derivation import load_report
from detect_secrets.derivation import save_report


SECRET = "AKIA/TEST+123=456_secret"
LOOKALIKE = "AKIA/TEST+123=456_secreX"


def _analysis():
    from urllib.parse import quote
    return analyze_observations(build_observations([
        ("acme", "AWS Access Key", "plain.txt", 1, SECRET),
        ("acme", "AWS Access Key", "url.txt", 2, quote(SECRET, safe="")),
        ("acme", "AWS Access Key", "other.txt", 3, LOOKALIKE),
    ]))


class TestReportPersistence:
    @staticmethod
    def test_report_contains_no_plaintext():
        report = build_report(_analysis())
        serialized = json.dumps(report)
        assert SECRET not in serialized
        assert LOOKALIKE not in serialized
        assert_no_plaintext(report, [SECRET, LOOKALIKE])

    @staticmethod
    def test_assert_no_plaintext_detects_leaks():
        import pytest
        with pytest.raises(AssertionError):
            assert_no_plaintext({"leak": SECRET}, [SECRET])

    @staticmethod
    def test_saved_file_contains_no_plaintext(tmp_path):
        filename = str(tmp_path / "derivation.json")
        report = save_report(_analysis(), filename)
        with open(filename) as f:
            on_disk = f.read()
        assert SECRET not in on_disk
        assert LOOKALIKE not in on_disk
        assert load_report(filename) == report


    @staticmethod
    def test_report_is_deterministic_across_scans(tmp_path):
        first = save_report(_analysis(), str(tmp_path / "one.json"))
        second = save_report(_analysis(), str(tmp_path / "two.json"))
        assert first == second

    @staticmethod
    def test_report_carries_verified_groups_and_unverifiable_list():
        report = build_report(_analysis())
        assert len(report["groups"]) == 1
        member_files = {
            member["location"]["filename"]
            for group in report["groups"]
            for member in group["members"]
        }
        assert member_files == {"plain.txt", "url.txt"}
        assert len(report["unverifiable_relationships"]) >= 1
        for candidate in report["unverifiable_relationships"]:
            assert "*" in candidate["masked_left"]
            assert candidate["reason"] == "no_verifiable_decode_chain"

    @staticmethod
    def test_unverified_section_can_be_omitted():
        report = build_report(_analysis(), include_unverified=False)
        assert "unverifiable_relationships" not in report
        assert report["groups"]


class TestSecretsCollectionIntegration:
    @staticmethod
    def test_runs_over_scan_results_without_changing_plugins(tmp_path):
        from detect_secrets.core.secrets_collection import SecretsCollection
        from detect_secrets.derivation import analyze_secrets_collection
        from detect_secrets.settings import transient_settings

        secret_file = tmp_path / "credentials.txt"
        secret_file.write_text("aws_access_key = AKIAZZZZZZZZZZZZZZZZ\n")

        with transient_settings({"plugins_used": [{"name": "AWSKeyDetector"}]}):
            collection = SecretsCollection()
            collection.scan_file(str(secret_file))
            analysis = analyze_secrets_collection(collection, tenant="acme")

        assert len(analysis.observations) == 1
        report = analysis.to_report().to_dict()
        assert_no_plaintext(report, [
            observation.raw_value for observation in analysis.observations
        ])

    @staticmethod
    def test_baseline_loaded_collection_has_no_plaintext(tmp_path):
        from detect_secrets.core import baseline
        from detect_secrets.core.secrets_collection import SecretsCollection
        from detect_secrets.derivation import analyze_secrets_collection
        from detect_secrets.settings import transient_settings

        secret_file = tmp_path / "credentials.txt"
        secret_file.write_text("aws_access_key = AKIAZZZZZZZZZZZZZZZZ\n")

        with transient_settings({"plugins_used": [{"name": "AWSKeyDetector"}]}):
            scanned = SecretsCollection()
            scanned.scan_file(str(secret_file))
            payload = baseline.format_for_output(scanned)
            reloaded = SecretsCollection.load_from_baseline(payload)
            analysis = analyze_secrets_collection(reloaded, tenant="acme")

        # Baselines carry hashes only, so there is no plaintext to analyze.
        assert analysis.observations == []
