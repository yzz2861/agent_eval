import json

from detect_secrets import main as main_module


class TestDerivationCli:
    @staticmethod
    def test_scan_writes_plaintext_free_derivation_report(tmp_path):
        secret = "AKIAZZZZZZZZZZZZZZZZ"
        lookalike = "AKIAZZZZZZZZZZZZZZZA"
        source = tmp_path / "credentials.txt"
        source.write_text(
            f"aws_access_key = {secret}\\n"
            f"other_key = {lookalike}\\n"
        )
        report_path = tmp_path / "derivation.json"

        main_module.main([
            "-C",
            str(tmp_path),
            "scan",
            ".",
            "--all-files",
            "--no-verify",
            "--derivation-report",
            str(report_path),
            "--derivation-tenant",
            "acme",
        ])

        report = json.loads(report_path.read_text())
        assert report["tenant"] == "acme"
        serialized = json.dumps(report)
        assert secret not in serialized
        assert lookalike not in serialized
        # Masking, not raw values, is what reaches the unverifiable list.
        for candidate in report["unverifiable_relationships"]:
            assert secret not in candidate["masked_left"]
            assert "*" in candidate["masked_left"]

    @staticmethod
    def test_derivation_report_is_stable_across_repeated_scans(tmp_path):
        secret = "AKIAZZZZZZZZZZZZZZZZ"
        source = tmp_path / "credentials.txt"
        source.write_text(f"aws_access_key = {secret}\\n")

        scan_dir = tmp_path / "repo"
        scan_dir.mkdir()
        (scan_dir / "credentials.txt").write_text(
            "aws_access_key = " + secret + chr(10),
        )
        first_path = tmp_path / "one.json"
        second_path = tmp_path / "two.json"
        for path in (first_path, second_path):
            main_module.main([
                "-C",
                str(scan_dir),
                "scan",
                ".",
                "--all-files",
                "--no-verify",
                "--derivation-report",
                str(path),
            ])

        assert json.loads(first_path.read_text()) == json.loads(second_path.read_text())
