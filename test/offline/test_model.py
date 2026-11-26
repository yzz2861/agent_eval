from dataclasses import replace

import pytest
from packaging.version import Version

from pip_audit._offline.model import (
    AdvisoryRecord,
    AdvisoryStatus,
    DeploymentRecord,
    DispositionAction,
    DispositionRecord,
    Snapshot,
    package_key,
    parse_rfc3339,
    to_rfc3339,
)


def _roundtrip_advisory(record):
    return AdvisoryRecord.from_dict(record.to_dict())


def test_rfc3339_roundtrip():
    raw = "2026-11-01T08:00:00Z"
    assert to_rfc3339(parse_rfc3339(raw)) == raw


def test_rfc3339_accepts_fractional_and_offset():
    assert parse_rfc3339("2026-11-01T08:00:00.123456Z").second == 0
    assert parse_rfc3339("2026-11-01T16:00:00+08:00").hour == 8


def test_package_key_normalizes_separators_and_case():
    assert package_key("Foo.Bar_Baz Qux") == "foo-bar-baz-qux"


def test_advisory_was_known_requires_receipt_and_authority(late_advisory, timestamps):
    assert late_advisory.was_known(timestamps["nov2"]) is False
    assert late_advisory.was_known(timestamps["nov3"]) is True


def test_corrected_advisory_is_inactive_after_correction(corrected_late, timestamps):
    assert corrected_late.is_active(timestamps["nov3"]) is True
    assert corrected_late.is_active(timestamps["nov5"]) is False
    assert corrected_late.was_known(timestamps["nov5"]) is False


def test_withdrawn_advisory_becomes_inactive(late_advisory, timestamps):
    withdrawn = replace(
        late_advisory,
        status=AdvisoryStatus.Withdrawn,
        withdrawn_at=timestamps["nov5"],
    )
    assert withdrawn.is_active(timestamps["nov3"]) is True
    assert withdrawn.is_active(timestamps["nov5"]) is False


def test_advisory_dict_roundtrip(old_advisory):
    assert _roundtrip_advisory(old_advisory) == old_advisory


def test_deployment_placeholder_roundtrip():
    placeholder = DeploymentRecord(name="ghost", version=None, deployed=False)
    restored = DeploymentRecord.from_dict(placeholder.to_dict())
    assert restored == placeholder
    assert restored.key == "ghost"
    assert restored.deployed is False


def test_disposition_roundtrip():
    disposition = DispositionRecord(
        advisory_id="PYSEC-1",
        package="foo",
        action=DispositionAction.Upgrade,
        rule_version="rules-1",
        target_version=Version("1.2.0"),
    )
    assert DispositionRecord.from_dict(disposition.to_dict()) == disposition


def test_snapshot_roundtrip_and_indexes(second_snapshot):
    restored = Snapshot.from_dict(second_snapshot.to_dict())
    assert restored == second_snapshot
    assert set(restored.advisory_index()) == {"PYSEC-OLD", "PYSEC-LATE"}
    assert restored.disposition_index() == {}


def test_snapshot_rejects_unknown_schema(second_snapshot):
    payload = second_snapshot.to_dict()
    payload["schema_version"] = 999
    with pytest.raises(ValueError, match="schema version"):
        Snapshot.from_dict(payload)


def test_with_corrections_supersedes_record(first_snapshot, corrected_late, timestamps):
    successor = first_snapshot.with_corrections(
        [corrected_late], new_id="snap-3", created_at=timestamps["nov5"]
    )
    assert successor.id == "snap-3"
    assert len(successor.advisories) == 2
    corrected = successor.advisory_index()["PYSEC-LATE"]
    assert corrected.status is AdvisoryStatus.Corrected
    # The original snapshot is not mutated and keeps its identity.
    assert first_snapshot.id == "snap-1"
    assert successor.deployments == first_snapshot.deployments
