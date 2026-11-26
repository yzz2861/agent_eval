"""Tests for offline remediation allocation drills."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

import pip_audit._cli
from pip_audit._allocation import (
    AllocationDrillError,
    assess_group,
    build_alerts,
    load_audit_result,
    load_environments,
    load_plan_table,
    main,
    prepare_combinations,
    render_json,
    run_drill,
    shared_image_conflicts,
)

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEMO = _REPO_ROOT / "examples" / "allocation-drill"


def _demo_result():
    return run_drill(
        _DEMO / "audit-result.json",
        [_DEMO / "pylock.web.toml", _DEMO / "pylock.worker.toml"],
        _DEMO / "allocation-plan.toml",
    )


def test_demo_inputs_join_vulnerabilities_to_both_environments():
    result = _demo_result()

    assert [environment["name"] for environment in result.environments] == ["web", "worker"]
    assert {alert.vulnerability_id: alert.environments for alert in result.alerts} == {
        "ADV-2026-5101": ("web", "worker"),
        "ADV-2026-5102": ("web", "worker"),
        "ADV-2026-5103": ("web", "worker"),
    }


def test_demo_assigns_atomic_django_batch_to_only_cross_env_owner():
    result = _demo_result()

    assert [(item.combination_id, item.group) for item in result.assignments] == [
        ("django-4.2.27-shared-batch", "cross-env-release")
    ]
    load = next(load for load in result.group_loads if load.group == "cross-env-release")
    assert (load.used, load.capacity, load.remaining) == (1, 1, 0)

    django = next(
        combo for combo in result.combinations if combo.raw.id == "django-4.2.27-shared-batch"
    )
    assert django.finding_ids == {"ADV-2026-5101", "ADV-2026-5102"}
    assert django.covered_instances == {
        "ADV-2026-5101@django@web",
        "ADV-2026-5101@django@worker",
        "ADV-2026-5102@django@web",
        "ADV-2026-5102@django@worker",
    }


def test_demo_reports_exact_unallocatable_capacity_condition():
    result = _demo_result()
    conflict = next(
        conflict for conflict in result.conflicts if conflict.code == "capacity_exhausted"
    )

    assert conflict.combination_id == "cryptography-44.0.3-shared-batch"
    eligible = conflict.details["eligible_groups"]
    assert eligible == [{"group": "cross-env-release", "remaining": 0, "capacity": 1}]

    assessments = {item["group"]: item["reasons"] for item in conflict.details["group_assessments"]}
    crypto_reasons = [reason["code"] for reason in assessments["crypto-line"]]
    assert "cross_environment_not_supported" in crypto_reasons
    django_reasons = [reason["code"] for reason in assessments["django-4.2-line"]]
    assert "version_line_scope_mismatch" in django_reasons


def test_demo_greedy_alert_grabbing_fails_after_first_claim():
    result = _demo_result()

    assert result.greedy.claimed_alerts == ("ADV-2026-5101@django",)
    assert [claim.status for claim in result.greedy.claims] == ["claimed", "failed", "failed"]
    assert [claim.group for claim in result.greedy.claims] == [
        "cross-env-release",
        None,
        None,
    ]
    assert {conflict.code for conflict in result.greedy.conflicts} == {"alert_grab_failed"}


def test_json_report_is_serializable():
    result = _demo_result()
    payload = json.loads(render_json(result))

    assert payload["status"] == "conflicts"
    assert payload["summary"]["covered_instance_count"] == 4


def _write_ready_fixture(tmp_path: Path) -> tuple[Path, list[Path], Path]:
    audit = tmp_path / "audit.json"
    audit.write_text(
        json.dumps(
            {
                "dependencies": [
                    {
                        "name": "django",
                        "version": "4.2.26",
                        "vulns": [
                            {"id": "VULN-1", "aliases": ["CVE-1"], "fix_versions": ["4.2.27"]},
                            {"id": "VULN-2", "aliases": ["CVE-2"], "fix_versions": ["4.2.27"]},
                        ],
                    }
                ]
            }
        )
    )
    web = tmp_path / "pylock.web.toml"
    worker = tmp_path / "pylock.worker.toml"
    web.write_text('lock-version = "1.0"\n[[packages]]\nname="django"\nversion="4.2.26"\n')
    worker.write_text('lock-version = "1.0"\n[[packages]]\nname="django"\nversion="4.2.26"\n')
    plan = tmp_path / "plan.toml"
    plan.write_text(
        """
version = 1

[[shared_images]]
name = "image"
environments = ["web", "worker"]
packages = ["django"]

[[groups]]
name = "line"
capacity = 2
cross_environment = false
scopes = ["django@4.2"]

[[groups]]
name = "solo-cross-env"
capacity = 1
cross_environment = true
scopes = ["*"]

[[combinations]]
id = "atomic-batch"
findings = ["VULN-1", "VULN-2"]
environments = ["web", "worker"]

[[combinations.changes]]
package = "django"
line = "4.2"
to_version = "4.2.27"
"""
    )
    return audit, [web, worker], plan


def test_atomic_batch_succeeds_with_one_cross_environment_slot(tmp_path):
    audit, pylocks, plan = _write_ready_fixture(tmp_path)
    result = run_drill(audit, pylocks, plan)

    assert result.status == "ready"
    assert [item.combination_id for item in result.assignments] == ["atomic-batch"]
    assert result.assignments[0].group == "solo-cross-env"
    assert result.greedy.claimed_alerts == ("VULN-1@django",)
    assert len(result.greedy.conflicts) == 1


def test_allocation_cli_check_returns_one_for_conflicting_demo(capsys):
    exit_code = main(
        [
            "--audit-result",
            str(_DEMO / "audit-result.json"),
            "--allocation-plan",
            str(_DEMO / "allocation-plan.toml"),
            "--pylock",
            str(_DEMO / "pylock.web.toml"),
            "--pylock",
            str(_DEMO / "pylock.worker.toml"),
            "--format",
            "json",
            "--check",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert json.loads(captured.out)["status"] == "conflicts"


def test_pip_audit_cli_infers_json_from_global_format(monkeypatch, capsys):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "pip-audit",
            "--audit-result",
            str(_DEMO / "audit-result.json"),
            "--allocation-plan",
            str(_DEMO / "allocation-plan.toml"),
            "--pylock",
            str(_DEMO / "pylock.web.toml"),
            "--pylock",
            str(_DEMO / "pylock.worker.toml"),
            "--format",
            "json",
        ],
    )

    pip_audit._cli.audit()

    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["alert_count"] == 3


def test_missing_pylock_argument_is_an_error():
    with pytest.raises(AllocationDrillError, match="at least one --pylock"):
        main(["--audit-result", "audit.json", "--allocation-plan", "plan.toml"])


def test_version_line_scope_is_enforced():
    audit = load_audit_result(_DEMO / "audit-result.json")
    environments = load_environments([_DEMO / "pylock.web.toml", _DEMO / "pylock.worker.toml"])
    alerts = build_alerts(audit, environments)
    table = load_plan_table(_DEMO / "allocation-plan.toml")
    combinations, _ = prepare_combinations(table, alerts, environments)
    django = next(item for item in combinations if item.raw.id == "django-4.2.27-shared-batch")
    django_line = next(group for group in table.groups if group.name == "django-4.2-line")
    reasons = assess_group(django, django_line)

    assert [reason.code for reason in reasons] == ["cross_environment_not_supported"]


def test_shared_image_rejects_inconsistent_versions(tmp_path):
    audit_path = tmp_path / "audit.json"
    audit_path.write_text(json.dumps({"dependencies": []}))
    plan_path = tmp_path / "plan.toml"
    plan_path.write_text(
        """
version = 1
[[shared_images]]
name = "base"
environments = ["web", "worker"]
packages = ["django"]

[[groups]]
name = "g"
capacity = 2
cross_environment = true
scopes = ["*"]

[[combinations]]
id = "split-versions"
findings = []
environments = ["web", "worker"]

[[combinations.changes]]
package = "django"
to_version = "4.2.27"
environments = ["web"]

[[combinations.changes]]
package = "django"
to_version = "4.2.28"
environments = ["worker"]
"""
    )
    web = tmp_path / "pylock.web.toml"
    worker = tmp_path / "pylock.worker.toml"
    web.write_text('lock-version = "1.0"\n[[packages]]\nname="django"\nversion="4.2.26"\n')
    worker.write_text('lock-version = "1.0"\n[[packages]]\nname="django"\nversion="4.2.26"\n')

    table = load_plan_table(plan_path)
    environments = load_environments([web, worker])
    combinations, prep_conflicts = prepare_combinations(table, [], environments)
    conflict = shared_image_conflicts(combinations, table, environments, check_coverage=False)

    assert prep_conflicts  # finding-less candidate is also flagged
    assert any(item.code == "shared_image_version_conflict" for item in conflict)


def test_invalid_audit_json_raises_named_error(tmp_path):
    audit = tmp_path / "audit.json"
    audit.write_text("not json")
    with pytest.raises(AllocationDrillError, match="cannot read audit result"):
        load_audit_result(audit)
