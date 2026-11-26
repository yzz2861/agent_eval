import json

import pytest

from pip_audit._offline.cli import main


def _write_payload(path, payload):
    path.write_text(json.dumps(payload), encoding="utf-8")


@pytest.fixture()
def review_dir(tmp_path):
    return tmp_path / "review"


@pytest.fixture()
def payload_path(tmp_path):
    return tmp_path / "input.json"


@pytest.fixture()
def snapshot_payload():
    return {
        "id": "snap-1",
        "created_at": "2026-11-01T08:00:00Z",
        "rule_version": "rules-1",
        "advisories": [
            {
                "id": "PYSEC-LATE",
                "package": "foo",
                "affected_range": ">=1.0,<1.2",
                "description": "late",
                "fix_versions": ["1.2.0"],
                "aliases": [],
                "effective_at": "2026-11-01T00:00:00Z",
                "received_at": "2026-11-03T00:00:00Z",
            }
        ],
        "deployments": [
            {"name": "foo", "version": "1.0.1", "deployed": True},
            {"name": "ghost", "version": "3.0.0", "deployed": False},
        ],
    }


def _run_json(argv, capsys):
    assert main(argv) == 0
    return json.loads(capsys.readouterr().out)


def test_snapshot_then_review_and_trace(review_dir, payload_path, snapshot_payload, capsys):
    _write_payload(payload_path, snapshot_payload)
    saved = _run_json(["--review-dir", str(review_dir), "snapshot", str(payload_path)], capsys)
    assert saved["snapshot_id"] == "snap-1"

    listed = _run_json(["--review-dir", str(review_dir), "list"], capsys)
    assert listed[0]["dispositions"] == 1

    as_of_known = _run_json(
        [
            "--review-dir",
            str(review_dir),
            "review",
            "--cutoff",
            "2026-11-02T00:00:00Z",
            "--view",
            "as-of-known",
        ],
        capsys,
    )
    assert as_of_known["summary"]["vulnerability_count"] == 0
    hidden = as_of_known["findings"][0]
    assert hidden["visible"] is False
    assert hidden["reasons"] == ["not-yet-received-at-cutoff"]

    today = _run_json(
        [
            "--review-dir",
            str(review_dir),
            "review",
            "--cutoff",
            "2026-11-02T00:00:00Z",
            "--view",
            "today",
        ],
        capsys,
    )
    assert today["summary"]["vulnerability_count"] == 1
    assert today["summary"]["late_count"] == 1
    assert today["findings"][0]["disposition"]["action"] == "upgrade"

    trace = _run_json(
        [
            "--review-dir",
            str(review_dir),
            "trace",
            "--cutoff",
            "2026-11-02T00:00:00Z",
            "--view",
            "today",
        ],
        capsys,
    )
    assert trace["first_snapshot_changing_report"] == "snap-1"


def test_review_defaults_to_latest_snapshot(review_dir, payload_path, snapshot_payload, capsys):
    _write_payload(payload_path, snapshot_payload)
    main(["--review-dir", str(review_dir), "snapshot", str(payload_path)])
    capsys.readouterr()

    second = dict(snapshot_payload, id="snap-2", created_at="2026-11-04T08:00:00Z")
    _write_payload(payload_path, second)
    main(["--review-dir", str(review_dir), "snapshot", str(payload_path)])
    capsys.readouterr()

    report = _run_json(
        [
            "--review-dir",
            str(review_dir),
            "review",
            "--cutoff",
            "2026-11-02T00:00:00Z",
            "--view",
            "today",
        ],
        capsys,
    )
    assert report["summary"]["snapshot_id"] == "snap-2"


def test_invalid_cutoff_exits_nonzero(review_dir):
    with pytest.raises(SystemExit):
        main(
            [
                "--review-dir",
                str(review_dir),
                "review",
                "--cutoff",
                "november-second",
            ]
        )


def test_review_without_snapshots_fails(review_dir):
    with pytest.raises(SystemExit):
        main(
            [
                "--review-dir",
                str(review_dir),
                "review",
                "--cutoff",
                "2026-11-02T00:00:00Z",
            ]
        )
