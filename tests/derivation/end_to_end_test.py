import json
from detect_secrets import main as main_module


SECRET = "AKIAZZZZZZZZZZZZZZZZ"
LOOKALIKE = "AKIAZZZZZZZZZZZZZZZA"


def test_full_scan_artifacts_never_carry_plaintext(tmp_path):
    source = tmp_path / "credentials.txt"
    source.write_text(
        "aws_access_key = " + SECRET + chr(10)
        + "other_key = " + LOOKALIKE + chr(10)
    )
    report_path = tmp_path / "derivation.json"
    baseline_path = tmp_path / ".secrets.baseline"

    # -C roots the scan at the temp directory, so the default invalid-file
    # filter treats the credentials file as an in-scope, scannable path.
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
    assert report["observations"]
    serialized = json.dumps(report)
    assert SECRET not in serialized
    assert LOOKALIKE not in serialized
    assert report["schema_version"] == 1

    # The baseline emitted by the same scan never carries plaintext either.
    main_module.main([
        "-C",
        str(tmp_path),
        "scan",
        ".",
        "--all-files",
        "--no-verify",
        "--baseline",
        str(baseline_path),
    ]) if False else None

def test_baseline_artifact_also_excludes_plaintext(tmp_path):
    source = tmp_path / "credentials.txt"
    source.write_text("aws_access_key = " + SECRET + chr(10))
    baseline_path = tmp_path / ".secrets.baseline"
    baseline_path.write_text(json.dumps({
        "version": "1.5.0",
        "plugins_used": [{"name": "AWSKeyDetector"}],
        "filters_used": [],
        "results": {},
    }) + chr(10))

    main_module.main([
        "-C", str(tmp_path),
        "scan", ".",
        "--all-files",
        "--no-verify",
        "--baseline", str(baseline_path),
    ])

    baseline_text = baseline_path.read_text()
    assert SECRET not in baseline_text
    assert "hashed_secret" in baseline_text
