"""Finding de-duplication and queue assignment tests."""

import pytest

from detect_secrets.sampling.loader import load_findings
from detect_secrets.sampling.loader import load_queue_map
from detect_secrets.sampling.models import make_finding_id


def test_multi_plugin_hit_collapses_into_one_finding(baseline_file, queue_map_file):
    findings = load_findings(str(baseline_file), load_queue_map(str(queue_map_file)))

    merged = next(
        finding
        for finding in findings
        if finding.finding_id == "src/payments/api.py:10:hash-aaa"
    )
    assert merged.plugin_hit_count == 2
    assert merged.detector_types == ["AWS Access Key", "Secret Keyword"]
    # Primary detector is deterministic and independent of plugin ordering.
    assert merged.primary_detector == "AWS Access Key"


def test_each_distinct_location_is_one_finding(baseline_file, queue_map_file):
    findings = load_findings(str(baseline_file), load_queue_map(str(queue_map_file)))
    assert len(findings) == 7
    assert len({finding.finding_id for finding in findings}) == 7


def test_queue_map_uses_longest_prefix(tmp_path):
    baseline = {
        "results": {
            "src/payments/api.py": [
                {
                    "type": "AWS Access Key",
                    "filename": "src/payments/api.py",
                    "hashed_secret": "h",
                    "line_number": 1,
                },
            ],
        },
    }
    path = tmp_path / "baseline.json"
    path.write_text(__import__("json").dumps(baseline))
    queue_map = {"src/": "broad", "src/payments/": "narrow"}

    findings = load_findings(str(path), queue_map)

    assert findings[0].source_queue == "narrow"


def test_unmatched_files_go_to_default_queue(tmp_path):
    baseline = {
        "results": {
            "misc.py": [
                {
                    "type": "Private Key",
                    "filename": "misc.py",
                    "hashed_secret": "h",
                    "line_number": 1,
                },
            ],
        },
    }
    path = tmp_path / "baseline.json"
    path.write_text(__import__("json").dumps(baseline))

    findings = load_findings(str(path), {"src/": "payments"})

    assert findings[0].source_queue == "unclassified"


def test_findings_export_with_explicit_queue(tmp_path):
    export = {
        "findings": [
            {
                "finding_id": "custom-id",
                "type": "Private Key",
                "filename": "a.py",
                "hashed_secret": "h",
                "line_number": 3,
                "source_queue": "imported",
            },
        ],
    }
    path = tmp_path / "export.json"
    path.write_text(__import__("json").dumps(export))

    findings = load_findings(str(path))

    assert findings[0].finding_id == "custom-id"
    assert findings[0].source_queue == "imported"


def test_make_finding_id_is_stable():
    assert make_finding_id("a.py", 4, "deadbeef") == "a.py:4:deadbeef"


def test_unknown_input_shape_raises(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{}")
    with pytest.raises(ValueError):
        load_findings(str(path))
