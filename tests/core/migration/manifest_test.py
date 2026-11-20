import json

import pytest

from detect_secrets.core.migration import InvalidLinkageMaterialError
from detect_secrets.core.migration import LinkageManifest
from detect_secrets.core.migration import LinkageRecord
from detect_secrets.exceptions import UnableToReadBaselineError

PROJECT = "proj-alpha"
START = "2026-01-01T00:00:00Z"
END = "2026-07-01T00:00:00Z"


def payload(**overrides):
    data = {
        "project_id": PROJECT,
        "transition_starts_at": START,
        "transition_ends_at": END,
        "records": [
            {
                "record_id": "r1",
                "project_id": PROJECT,
                "rule_id": "AWSKeyDetector",
                "old_secret_id": "aaa111",
                "new_secret_id": "bbb222",
                "not_before": START,
                "not_after": END,
                "filename": "config/aws.py",
            },
        ],
    }
    data.update(overrides)
    return data


def test_manifest_json_roundtrip_preserves_identifiers():
    material = LinkageManifest.from_dict(payload())
    restored = LinkageManifest.from_dict(json.loads(json.dumps(material.json())))

    assert restored.project_id == PROJECT
    record = restored.records[0]
    assert isinstance(record, LinkageRecord)
    assert record.old_secret_id == "aaa111"
    assert record.new_secret_id == "bbb222"
    assert record.filename == "config/aws.py"


def test_window_open_checks_both_bounds():
    material = LinkageManifest.from_dict(payload())
    assert material.is_window_open("2026-01-01T00:00:00Z") is True
    assert material.is_window_open("2026-06-30T23:59:59Z") is True
    assert material.is_window_open(END) is False
    assert material.is_window_open("2025-12-31T23:59:59Z") is False


def test_missing_top_level_field_is_rejected(tmp_path):
    broken = payload()
    del broken["records"]
    path = tmp_path / "linkage.json"
    path.write_text(json.dumps(broken))

    with pytest.raises(InvalidLinkageMaterialError):
        LinkageManifest.load(str(path))


def test_missing_record_field_is_rejected():
    broken = payload()
    del broken["records"][0]["new_secret_id"]
    with pytest.raises(InvalidLinkageMaterialError):
        LinkageManifest.from_dict(broken)


def test_inverted_record_validity_is_rejected():
    broken = payload()
    broken["records"][0]["not_after"] = START
    broken["records"][0]["not_before"] = END
    with pytest.raises(InvalidLinkageMaterialError):
        LinkageManifest.from_dict(broken)


def test_inverted_window_is_rejected():
    with pytest.raises(InvalidLinkageMaterialError):
        LinkageManifest(PROJECT, END, START, [])


def test_missing_file_raises_readable_error(tmp_path):
    with pytest.raises(UnableToReadBaselineError):
        LinkageManifest.load(str(tmp_path / "does-not-exist.json"))


def test_non_object_payload_is_rejected(tmp_path):
    path = tmp_path / "linkage.json"
    path.write_text(json.dumps(["not", "an", "object"]))
    with pytest.raises(InvalidLinkageMaterialError):
        LinkageManifest.load(str(path))


def test_bad_timestamp_is_rejected():
    with pytest.raises(ValueError):
        LinkageManifest.from_dict(payload(transition_starts_at="not-a-time"))


def test_manifest_never_contains_secret_plaintext():
    material = LinkageManifest.from_dict(payload())
    serialized = json.dumps(material.json())
    assert "hashed_secret" not in serialized
    assert "secret_value" not in serialized
    assert "plaintext" not in serialized
    # Only pseudonymous id fields are allowed to carry secret-derived data.
    record = material.json()["records"][0]
    assert set(record) >= {"old_secret_id", "new_secret_id"}
