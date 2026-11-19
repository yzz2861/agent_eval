import pytest

from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.exception_policy import (
    RuleVersion,
    finding_from_baseline_entry,
    finding_from_potential_secret,
)

PROJECT = "acme"
VERSIONS = {"AWSKeyDetector": "1.4.0"}


def test_live_scan_and_baseline_replay_share_identity():
    secret = PotentialSecret(
        type="AWSKeyDetector", filename="config/app.yaml", secret="abc", line_number=3,
    )
    live = finding_from_potential_secret(secret, PROJECT, "1.4.0")

    baseline_entry = {
        "type": "AWSKeyDetector",
        "hashed_secret": PotentialSecret.hash_secret("abc"),
        "line_number": 3,
    }
    replayed = finding_from_baseline_entry(
        "config/app.yaml", baseline_entry, PROJECT, VERSIONS,
    )
    assert live.secret_identity == replayed.secret_identity
    assert live.rule == replayed.rule


def test_no_plaintext_is_reachable_from_baseline_finding():
    entry = {
        "type": "AWSKeyDetector",
        "hashed_secret": PotentialSecret.hash_secret("abc"),
    }
    finding = finding_from_baseline_entry("x", entry, PROJECT, VERSIONS)
    assert isinstance(finding.rule, RuleVersion)
    assert "abc" not in str(finding.secret_identity.to_dict())


def test_missing_rule_version_raises():
    entry = {"type": "Unknown", "hashed_secret": "deadbeef"}
    with pytest.raises(KeyError):
        finding_from_baseline_entry("x", entry, PROJECT, VERSIONS)
