import json

from detect_secrets.core import baseline
from detect_secrets.core.migration import LinkageManifest
from detect_secrets.core.migration import LinkageRecord
from detect_secrets.core.migration import MigrationStatus
from detect_secrets.core.migration import prepare_comparison_inputs
from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.core.secrets_collection import SecretsCollection

PROJECT = "proj-integration"
RULE = "AWSKeyDetector"
START = "2026-01-01T00:00:00Z"
END = "2026-07-01T00:00:00Z"
NOW = "2026-03-01T00:00:00Z"


def _write(path, collection):
    data = {
        "version": "1.5.0",
        "plugins_used": [{"name": RULE}],
        "filters_used": [],
        "results": collection.json(),
        "generated_at": NOW,
    }
    path.write_text(json.dumps(data))


def test_migration_sits_between_baseline_load_and_audit_compare(tmp_path):
    old_id = PotentialSecret.hash_secret("legacy-secret")
    new_id = PotentialSecret.hash_secret("rotated-secret")

    old = SecretsCollection()
    old["config/aws.py"].add(
        PotentialSecret(RULE, "config/aws.py", "legacy-secret", 4,
                         is_secret=False, is_verified=True),
    )
    new = SecretsCollection()
    new["config/aws.py"].add(
        PotentialSecret(RULE, "config/aws.py", "rotated-secret", 4),
    )
    old_path = tmp_path / "old.baseline"
    new_path = tmp_path / "new.baseline"
    _write(old_path, old)
    _write(new_path, new)

    material = LinkageManifest(
        PROJECT, START, END,
        [
            LinkageRecord(
                record_id="r1", project_id=PROJECT, rule_id=RULE,
                old_secret_id=old_id, new_secret_id=new_id,
                not_before=START, not_after=END,
                filename="config/aws.py",
            ),
        ],
    )

    # This mirrors audit.compare._get_baseline_from_file on both sides.
    old_loaded = baseline.load(baseline.load_from_file(str(old_path)))
    new_loaded = baseline.load(baseline.load_from_file(str(new_path)))

    result = prepare_comparison_inputs(
        old_loaded, new_loaded, material, PROJECT, evaluated_at=NOW,
    )

    assert result.report.entries[0].status == MigrationStatus.MIGRATED
    migrated_secret = list(result.migrated_baseline)[0][1]
    assert migrated_secret.secret_hash == new_id
    assert migrated_secret.is_secret is False
    assert migrated_secret.is_verified is True

    # The migrated collection still serializes as a valid baseline.
    serialized = result.migrated_baseline.json()
    assert serialized["config/aws.py"][0]["is_secret"] is False
