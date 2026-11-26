import json
import sys

import pytest

from pip_audit._diff import (
    AuditStatus,
    Attribution,
    DiffError,
    audit_result_from_dict,
    audit_results_from_bundle,
    diff_audit_results,
    diff_audits,
    diff_main,
    load_audit_result,
)


CELLS = ("old-old", "old-new", "new-old", "new-new")


def _cells(asset):
    return {
        cell: load_audit_result(asset(f"diff/cells/{cell}.json")) for cell in CELLS
    }


def _by_package(report):
    return {alert.package: alert for alert in report.alerts}


def test_four_fixture_attribution(asset):
    report = diff_audits(cells=_cells(asset))
    alerts = _by_package(report)

    assert alerts["alpha"].attribution is Attribution.DEPENDENCY
    assert alerts["alpha"].direction.value == "removed"
    assert dict(alerts["alpha"].presence) == {
        "old-old": True,
        "old-new": True,
        "new-old": False,
        "new-new": False,
    }

    assert alerts["beta"].attribution is Attribution.ADVISORY
    assert alerts["beta"].direction.value == "removed"

    assert alerts["gamma"].attribution is Attribution.BOTH
    assert alerts["gamma"].direction.value == "added"
    assert dict(alerts["gamma"].presence) == {
        "old-old": False,
        "old-new": False,
        "new-old": False,
        "new-new": True,
    }

    assert alerts["delta"].attribution is Attribution.UNCHANGED
    assert report.unattributed == ()
    assert report.summary["by_category"] == {
        "dependency": 1,
        "advisory": 1,
        "both": 1,
        "mixed": 0,
        "unchanged": 1,
        "unknown": 0,
    }


def test_report_has_coverage_and_queried_versions(asset):
    report = diff_audits(cells=_cells(asset))

    # zeta is never judged, but it remains visible in every cell's coverage.
    for cell in CELLS:
        coverage = report.cells[cell]
        assert coverage.status == "incomplete"
        zeta = next(record for record in coverage.queried if record["name"] == "zeta")
        assert zeta["queried_version"] == "6.0"
        assert zeta["status"] == "unknown"
        assert coverage.unknown[0]["name"] == "zeta"

    assert report.cells["old-old"].queried[0]["queried_version"] == "1.0"
    assert report.cells["new-new"].queried[0]["queried_version"] == "1.1"

    payload = report.to_dict()
    assert payload["schema_version"] == 1
    assert payload["summary"]["total_alerts"] == 4
    assert payload["unattributed_alerts"] == []
    assert json.loads(report.to_json())["cells"]["old-old"]["expected_count"] == 5


def test_missing_cell_makes_alerts_unattributable(asset):
    cells = _cells(asset)
    del cells["new-old"]

    report = diff_audits(cells=cells)
    assert report.cells["new-old"].status == "missing"
    assert report.summary["missing_cells"] == ["new-old"]
    assert len(report.unattributed) == 4
    for alert in report.alerts:
        assert alert.attribution is Attribution.UNKNOWN
        assert alert.direction.value == "unknown"
        assert alert.missing_cells == ("new-old",)


def test_unknown_package_blocks_attribution(asset):
    cells = _cells(asset)
    old_new = cells["old-new"]
    beta = old_new.package("beta")
    assert beta is not None
    cells["old-new"] = type(old_new)(
        packages={
            **old_new.packages,
            "beta": type(beta)(
                name=beta.name,
                version=beta.version,
                status=AuditStatus.UNKNOWN,
                vulns=(),
                queried_version=beta.queried_version,
                reason="test snapshot has no judgment for beta",
            ),
        },
        manifest=old_new.manifest,
        advisory_snapshot=old_new.advisory_snapshot,
        manifest_packages=old_new.manifest_packages,
        source=old_new.source,
    )

    report = diff_audits(cells=cells)
    beta_alert = _by_package(report)["beta"]
    assert beta_alert.attribution is Attribution.UNKNOWN
    assert beta_alert.unknown_cells == ("old-new",)
    assert beta_alert in report.unattributed
    assert report.cells["old-new"].status == "incomplete"


def test_default_json_output_is_accepted():
    default_json = {
        "dependencies": [
            {
                "name": "alpha",
                "version": "1.0",
                "vulns": [
                    {
                        "id": "PYSEC-2025-1",
                        "fix_versions": ["1.1"],
                        "aliases": ["CVE-2025-0001"],
                        "description": "alpha 1.0 issue",
                    }
                ],
            },
            {"name": "gamma", "version": "3.0", "vulns": []},
        ],
        "fixes": [],
    }

    snapshot = audit_result_from_dict(default_json)
    assert snapshot.package("alpha") is not None
    assert snapshot.package("alpha").version == "1.0"  # type: ignore[union-attr]
    assert snapshot.expected_packages() == frozenset({"alpha", "gamma"})

    report = diff_audits(snapshot, snapshot, snapshot, snapshot)
    alpha = _by_package(report)["alpha"]
    assert alpha.attribution is Attribution.UNCHANGED
    assert alpha.direction.value == "unchanged"

    # The richer snapshot keeps the existing dependencies/fixes keys while
    # adding coverage metadata.
    serialized = snapshot.to_dict()
    assert set(serialized) >= {"dependencies", "fixes", "coverage"}
    assert serialized["dependencies"][0]["name"] == "alpha"


def test_cli_saved_results_and_missing_cell(asset, capsys):
    paths = {cell: asset(f"diff/cells/{cell}.json") for cell in CELLS}
    diff_main(
        [
            "--old-old",
            str(paths["old-old"]),
            "--old-new",
            str(paths["old-new"]),
            "--new-old",
            str(paths["new-old"]),
            "--new-new",
            str(paths["new-new"]),
            "--format",
            "json",
        ]
    )
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["both"] == 1

    diff_main(
        [
            "--result",
            f"00={paths['old-old']}",
            "--result",
            f"01={paths['old-new']}",
            "--result",
            f"11={paths['new-new']}",
            "--format",
            "json",
        ]
    )
    report = json.loads(capsys.readouterr().out)
    assert report["cells"]["new-old"]["status"] == "missing"
    assert len(report["unattributed_alerts"]) == 4


def test_cli_freeze_mode_writes_replayable_results(asset, tmp_path, capsys):
    diff_main(
        [
            "--old-requirements",
            str(asset("diff/old-requirements.txt")),
            "--new-requirements",
            str(asset("diff/new-requirements.txt")),
            "--old-advisories",
            str(asset("diff/advisories-old.json")),
            "--new-advisories",
            str(asset("diff/advisories-new.json")),
            "--write-results-dir",
            str(tmp_path),
            "--format",
            "json",
        ]
    )
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["by_category"]["both"] == 1

    for cell in CELLS:
        saved = tmp_path / f"{cell}.json"
        assert saved.exists()
        loaded = load_audit_result(saved)
        assert loaded.package("zeta").status is AuditStatus.UNKNOWN  # type: ignore[union-attr]


def test_bundle_and_four_result_api(asset):
    bundle = {
        "cells": {
            cell: json.loads(asset(f"diff/cells/{cell}.json").read_text()) for cell in CELLS
        }
    }
    cells = audit_results_from_bundle(bundle)
    assert set(cells) == set(CELLS)
    assert all(value is not None for value in cells.values())
    assert diff_audits(cells).summary["both"] == 1

    report = diff_audit_results([cells[cell] for cell in CELLS])
    assert report.summary["dependency"] == 1


def test_cli_bundle_input(asset, tmp_path, capsys):
    bundle = {
        cell: json.loads(asset(f"diff/cells/{cell}.json").read_text()) for cell in CELLS
    }
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(bundle))
    diff_main(["--results", str(bundle_path), "--format", "json"])
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["by_category"]["both"] == 1


def test_cli_results_dir_with_one_cell_deleted(asset, tmp_path, capsys):
    for cell in CELLS:
        if cell == "new-old":
            continue
        (tmp_path / f"{cell}.json").write_text(asset(f"diff/cells/{cell}.json").read_text())

    diff_main(["--results-dir", str(tmp_path), "--format", "json"])
    report = json.loads(capsys.readouterr().out)
    assert report["cells"]["new-old"]["status"] == "missing"
    assert report["summary"]["missing_cells"] == ["new-old"]
    assert {alert["package"] for alert in report["unattributed_alerts"]} == {
        "alpha",
        "beta",
        "delta",
        "gamma",
    }


def test_cli_diff_entrypoint(asset, monkeypatch, capsys):
    import pip_audit._cli as cli

    paths = {cell: asset(f"diff/cells/{cell}.json") for cell in CELLS}
    argv = [
        "pip-audit",
        "diff",
        "--old-old",
        str(paths["old-old"]),
        "--old-new",
        str(paths["old-new"]),
        "--new-old",
        str(paths["new-old"]),
        "--new-new",
        str(paths["new-new"]),
    ]
    monkeypatch.setattr(sys, "argv", argv)
    cli.audit()
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["unattributed"] == 0


def test_diff_requires_dependencies():
    with pytest.raises(DiffError):
        audit_result_from_dict({"fixes": []})


def test_cli_rejects_mixed_modes(asset):
    with pytest.raises(SystemExit):
        diff_main(
            [
                "--old-old",
                str(asset("diff/cells/old-old.json")),
                "--old-requirements",
                str(asset("diff/old-requirements.txt")),
            ]
        )
