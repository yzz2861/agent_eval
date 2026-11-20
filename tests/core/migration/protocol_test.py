import json

import pytest

from detect_secrets.core.migration import LinkageManifest
from detect_secrets.core.migration import LinkageProjectMismatchError
from detect_secrets.core.migration import LinkageRecord
from detect_secrets.core.migration import MigrationStatus
from detect_secrets.core.migration import UnsafeMigrationReportError
from detect_secrets.core.migration import migrate_baseline
from detect_secrets.core.migration import prepare_comparison_inputs
from detect_secrets.core.migration import assert_report_is_sanitized
from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.core.secrets_collection import SecretsCollection

PROJECT = "proj-alpha"
OTHER_PROJECT = "proj-beta"
RULE = "AWSKeyDetector"
OTHER_RULE = "KeywordDetector"
WINDOW_START = "2026-01-01T00:00:00Z"
WINDOW_END = "2026-07-01T00:00:00Z"
DURING_WINDOW = "2026-03-01T00:00:00Z"
AFTER_WINDOW = "2026-08-01T00:00:00Z"

# Deterministic, per-run record_ref generator instead of random uuids.
REFS = ["ref-{:02d}".format(index) for index in range(100)]


def hashed(value: str) -> str:
    return PotentialSecret.hash_secret(value)


def collection(rule_id: str, filename: str, secret: str,
              is_secret=None, is_verified: bool = False) -> SecretsCollection:
    output = SecretsCollection()
    output[filename].add(
        PotentialSecret(
            type=rule_id,
            filename=filename,
            secret=secret,
            line_number=4,
            is_secret=is_secret,
            is_verified=is_verified,
        ),
    )
    return output


def record(record_id: str, rule_id: str = RULE, old_id: str = "old-hash",
           new_id: str = "new-hash", filename: str = "config/aws.py",
           project_id: str = PROJECT, not_before: str = WINDOW_START,
           not_after: str = WINDOW_END) -> LinkageRecord:
    return LinkageRecord(
        record_id=record_id,
        project_id=project_id,
        rule_id=rule_id,
        old_secret_id=old_id,
        new_secret_id=new_id,
        not_before=not_before,
        not_after=not_after,
        filename=filename,
        attestation="virtual candidate for migration tests",
    )


def manifest(records, start: str = WINDOW_START,
             end: str = WINDOW_END) -> LinkageManifest:
    return LinkageManifest(PROJECT, start, end, list(records))


@pytest.fixture
def fixed_refs(monkeypatch):
    stream = iter(REFS)
    monkeypatch.setattr(
        "detect_secrets.core.migration.protocol.uuid.uuid4",
        lambda: type("U", (), {"hex": next(stream)})(),
    )


def test_migrated_decision_and_verification_are_carried_forward(fixed_refs):
    old_id, new_id = hashed("legacy-secret"), hashed("rotated-secret")
    old = collection(RULE, "config/aws.py", "legacy-secret",
                     is_secret=True, is_verified=True)
    new = collection(RULE, "config/aws.py", "rotated-secret")
    material = manifest([record("r1", old_id=old_id, new_id=new_id)])

    result = prepare_comparison_inputs(
        old, new, material, PROJECT, evaluated_at=DURING_WINDOW,
    )

    entry = result.report.entries[0]
    assert entry.status == MigrationStatus.MIGRATED
    target = list(result.migrated_baseline)[0][1]
    assert target.secret_hash == new_id
    assert target.is_secret is True
    assert target.is_verified is True
    assert entry.decision is True
    assert entry.evidence_count == 1


def test_original_review_record_remains_in_old_baseline(fixed_refs):
    old_id, new_id = hashed("legacy-secret"), hashed("rotated-secret")
    old = collection(RULE, "config/aws.py", "legacy-secret", is_secret=False)
    new = collection(RULE, "config/aws.py", "rotated-secret")
    material = manifest([record("r1", old_id=old_id, new_id=new_id)])

    result = migrate_baseline(old, new, material, evaluated_at=DURING_WINDOW)

    original = list(old)[0][1]
    assert original.secret_hash == old_id
    assert original.is_secret is False
    migrated = list(result.migrated_baseline)[0][1]
    assert migrated.is_secret is False
    assert migrated.secret_hash != original.secret_hash


def test_equal_old_id_under_different_rule_is_not_merged(fixed_refs):
    shared_hash = hashed("shared-looking-value")
    old = collection(OTHER_RULE, "config/aws.py", "shared-looking-value",
                     is_secret=True)
    new = collection(OTHER_RULE, "config/aws.py", "rotated-secret")
    # Evidence exists, but only for a different rule with the same old hash.
    material = manifest([
        record("r1", rule_id=RULE, old_id=shared_hash, new_id=hashed("x")),
    ])

    result = migrate_baseline(old, new, material, evaluated_at=DURING_WINDOW)

    entry = result.report.entries[0]
    assert entry.rule_id == OTHER_RULE
    assert entry.status == MigrationStatus.UNMIGRATED
    target = list(result.migrated_baseline)[0][1]
    assert target.is_secret is None


def test_linkage_material_from_another_project_is_rejected(fixed_refs):
    old = collection(RULE, "config/aws.py", "legacy", is_secret=True)
    new = collection(RULE, "config/aws.py", "rotated")
    foreign = LinkageManifest(
        OTHER_PROJECT, WINDOW_START, WINDOW_END,
        [record("r1", project_id=OTHER_PROJECT)],
    )

    with pytest.raises(LinkageProjectMismatchError):
        prepare_comparison_inputs(
            old, new, foreign, PROJECT, evaluated_at=DURING_WINDOW,
        )


def test_foreign_manifest_scope_is_rejected_at_load_boundary(fixed_refs):
    old = collection(RULE, "config/aws.py", "legacy", is_secret=True)
    new = collection(RULE, "config/aws.py", "rotated")
    material = LinkageManifest(
        OTHER_PROJECT, WINDOW_START, WINDOW_END,
        [record("r1", project_id=OTHER_PROJECT)],
    )
    with pytest.raises(LinkageProjectMismatchError):
        material.require_project(PROJECT)


def test_duplicate_evidence_blocks_migration(fixed_refs):
    old_id, new_id = hashed("legacy"), hashed("rotated")
    old = collection(RULE, "config/aws.py", "legacy", is_secret=True)
    new = collection(RULE, "config/aws.py", "rotated")
    material = manifest([
        record("r1", old_id=old_id, new_id=new_id),
        record("r2", old_id=old_id, new_id=new_id),
    ])

    result = migrate_baseline(old, new, material, evaluated_at=DURING_WINDOW)

    entry = result.report.entries[0]
    assert entry.status == MigrationStatus.DUPLICATE
    assert entry.evidence_count == 2
    assert result.pending_record_refs() == [entry.record_ref]
    assert list(result.migrated_baseline)[0][1].is_secret is None


def test_conflicting_evidence_blocks_migration(fixed_refs):
    old_id = hashed("legacy")
    old = collection(RULE, "config/aws.py", "legacy", is_secret=True)
    new = collection(RULE, "config/aws.py", "rotated")
    material = manifest([
        record("r1", old_id=old_id, new_id=hashed("rotated-a")),
        record("r2", old_id=old_id, new_id=hashed("rotated-b")),
    ])

    result = migrate_baseline(old, new, material, evaluated_at=DURING_WINDOW)

    entry = result.report.entries[0]
    assert entry.status == MigrationStatus.CONFLICT
    assert result.pending_record_refs() == [entry.record_ref]


def test_filename_conflict_is_reported(fixed_refs):
    old_id, new_id = hashed("legacy"), hashed("rotated")
    old = collection(RULE, "config/aws.py", "legacy", is_secret=True)
    new = collection(RULE, "config/aws.py", "rotated")
    material = manifest([
        record("r1", old_id=old_id, new_id=new_id, filename="elsewhere/x.py"),
    ])

    result = migrate_baseline(old, new, material, evaluated_at=DURING_WINDOW)

    assert result.report.entries[0].status == MigrationStatus.CONFLICT


def test_expired_evidence_is_reported(fixed_refs):
    old_id = hashed("legacy")
    old = collection(RULE, "config/aws.py", "legacy", is_secret=True)
    new = collection(RULE, "config/aws.py", "rotated")
    material = manifest([
        record(
            "r1", old_id=old_id, new_id=hashed("rotated"),
            not_before="2025-01-01T00:00:00Z",
            not_after="2025-12-31T00:00:00Z",
        ),
    ])

    result = migrate_baseline(old, new, material, evaluated_at=DURING_WINDOW)

    entry = result.report.entries[0]
    assert entry.status == MigrationStatus.EXPIRED
    assert entry.evidence_count == 1


def test_no_evidence_leaves_item_unmigrated(fixed_refs):
    old = collection(RULE, "config/aws.py", "legacy", is_secret=True)
    new = collection(RULE, "config/aws.py", "rotated")
    material = manifest([])

    result = migrate_baseline(old, new, material, evaluated_at=DURING_WINDOW)

    entry = result.report.entries[0]
    assert entry.status == MigrationStatus.UNMIGRATED
    assert entry.evidence_count == 0
    assert result.pending_record_refs() == [entry.record_ref]


def test_target_missing_when_new_baseline_lacks_candidate(fixed_refs):
    old_id = hashed("legacy")
    old = collection(RULE, "config/aws.py", "legacy", is_secret=True)
    new = collection(RULE, "config/aws.py", "totally-different")
    material = manifest([
        record("r1", old_id=old_id, new_id=hashed("rotated")),
    ])

    result = migrate_baseline(old, new, material, evaluated_at=DURING_WINDOW)

    assert result.report.entries[0].status == MigrationStatus.TARGET_MISSING


def test_early_window_close_keeps_valid_items_queryable(fixed_refs):
    old_id, new_id = hashed("legacy"), hashed("rotated")
    old = collection(RULE, "config/aws.py", "legacy", is_secret=True)
    new = collection(RULE, "config/aws.py", "rotated")
    # Evidence itself is still fresh; only the transition window was closed.
    fresh = record(
        "r1", old_id=old_id, new_id=new_id,
        not_before=WINDOW_START, not_after="2026-12-31T00:00:00Z",
    )
    material = manifest([fresh])

    result = migrate_baseline(old, new, material, evaluated_at=AFTER_WINDOW)

    assert result.report.window_open is False
    entry = result.report.entries[0]
    assert entry.status == MigrationStatus.UNMIGRATED
    assert "window is closed" in entry.reason
    assert result.pending_record_refs() == [entry.record_ref]
    assert list(result.migrated_baseline)[0][1].is_secret is None


def test_summary_counts_each_outcome(fixed_refs):
    migrated_id = hashed("migrated-secret")
    old = SecretsCollection()
    new = SecretsCollection()
    old["config/a.py"].add(
        PotentialSecret(RULE, "config/a.py", "migrated-secret", 1, is_secret=True),
    )
    old["config/b.py"].add(
        PotentialSecret(RULE, "config/b.py", "orphan-secret", 2, is_secret=False),
    )
    new["config/a.py"].add(
        PotentialSecret(RULE, "config/a.py", "new-migrated", 1),
    )
    new["config/b.py"].add(
        PotentialSecret(RULE, "config/b.py", "new-orphan", 2),
    )
    material = manifest([
        record("r1", old_id=migrated_id, new_id=hashed("new-migrated"),
               filename="config/a.py"),
    ])

    result = migrate_baseline(old, new, material, evaluated_at=DURING_WINDOW)
    summary = result.report.json()["summary"]

    assert summary["migrated"] == 1
    assert summary["unmigrated"] == 1


def test_report_has_no_plaintext_or_correlatable_identifier(fixed_refs):
    old_id, new_id = hashed("legacy-secret"), hashed("rotated-secret")
    old = collection(RULE, "config/aws.py", "legacy-secret", is_secret=True)
    new = collection(RULE, "config/aws.py", "rotated-secret")
    material = manifest([record("r1", old_id=old_id, new_id=new_id)])

    result = migrate_baseline(old, new, material, evaluated_at=DURING_WINDOW)
    payload = json.loads(result.report.to_json_string())
    serialized = json.dumps(payload)

    assert "legacy-secret" not in serialized
    assert "rotated-secret" not in serialized
    assert old_id not in serialized
    assert new_id not in serialized
    assert_report_is_sanitized(
        payload,
        forbidden_values=[
            "legacy-secret", "rotated-secret", old_id, new_id,
        ],
    )


def test_sanitizer_rejects_correlatable_key(fixed_refs):
    with pytest.raises(UnsafeMigrationReportError):
        assert_report_is_sanitized(
            {"entry": {"hashed_secret": "whatever"}},
        )


def test_sanitizer_rejects_plaintext_value(fixed_refs):
    with pytest.raises(UnsafeMigrationReportError):
        assert_report_is_sanitized(
            {"entry": {"reason": "x"}},
            forbidden_values=["x"],
        )


def test_record_refs_are_per_run_and_uncorrelatable(fixed_refs):
    old_id, new_id = hashed("legacy"), hashed("rotated")
    old = collection(RULE, "config/aws.py", "legacy", is_secret=True)
    new = collection(RULE, "config/aws.py", "rotated")
    material = manifest([record("r1", old_id=old_id, new_id=new_id)])

    first = migrate_baseline(old, new, material, evaluated_at=DURING_WINDOW)
    second = migrate_baseline(old, new, material, evaluated_at=DURING_WINDOW)
    refs_a = [entry.record_ref for entry in first.report.entries]
    refs_b = [entry.record_ref for entry in second.report.entries]
    assert refs_a == ["ref-00"]
    assert refs_b == ["ref-01"]
    assert refs_a != refs_b
    assert all(ref not in json.dumps(material.json()) for ref in refs_a + refs_b)


def test_entries_with_status_helper(fixed_refs):
    old_id, new_id = hashed("legacy"), hashed("rotated")
    old = collection(RULE, "config/aws.py", "legacy", is_secret=True)
    new = collection(RULE, "config/aws.py", "rotated")
    material = manifest([])

    result = migrate_baseline(old, new, material, evaluated_at=DURING_WINDOW)
    report = result.report

    assert len(report.entries_with_status(MigrationStatus.UNMIGRATED)) == 1
    assert report.entries_with_status(MigrationStatus.MIGRATED) == []
    assert len(report.pending_entries) == 1


def test_sanitizer_walks_nested_lists_and_scalars(fixed_refs):
    payload = {"entries": [{"reason": "clean"}, {"reason": "also clean"}]}
    assert_report_is_sanitized(payload, forbidden_values=["nope"])

    with pytest.raises(UnsafeMigrationReportError):
        assert_report_is_sanitized(
            {"entries": [{"reason": "contains nope inside"}]},
            forbidden_values=["nope"],
        )


def test_default_evaluation_time_uses_current_moment(monkeypatch):
    import detect_secrets.core.migration.protocol as protocol_module
    from datetime import timezone
    from datetime import datetime

    frozen = datetime(2026, 3, 1, tzinfo=timezone.utc)
    monkeypatch.setattr(protocol_module, "utcnow", lambda: frozen)

    old_id, new_id = hashed("legacy"), hashed("rotated")
    old = collection(RULE, "config/aws.py", "legacy", is_secret=True)
    new = collection(RULE, "config/aws.py", "rotated")
    material = manifest([record("r1", old_id=old_id, new_id=new_id)])

    result = migrate_baseline(old, new, material)

    assert result.report.evaluated_at == "2026-03-01T00:00:00Z"
    assert result.report.window_open is True
    assert result.report.entries[0].status == MigrationStatus.MIGRATED
