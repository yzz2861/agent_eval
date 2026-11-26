import copy
import itertools
import json
from pathlib import Path

import pytest
from packaging.version import Version

from pip_audit._audit import Auditor
from pip_audit._review import (
    REVIEW_SCHEMA,
    AuditReport,
    LockCandidate,
    PackageChange,
    ReviewError,
    ReviewOptions,
    ReviewParseError,
    load_candidates,
    parse_candidates,
    reconcile,
    version_is_fixed,
)
from pip_audit._review_cli import main as review_main


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _fixture_review(asset) -> object:
    audit = _read_json(asset("review/audit.json"))
    candidates = _read_json(asset("review/candidates.json"))
    return reconcile(audit, candidates)


def test_advisory_aliases_merge_across_reports(asset):
    first = AuditReport.from_json(
        asset("review/audit.json").read_text(encoding="utf-8"), source="first"
    )
    second = AuditReport.from_json(
        asset("review/audit-duplicate.json").read_text(encoding="utf-8"), source="second"
    )

    report = reconcile((first, second), asset("review/candidates.json"))

    assert [advisory.id for advisory in report.advisories] == [
        "PYSEC-2026-0001",
        "CVE-2026-0002",
        "CVE-2026-0003",
        "CVE-2026-0004",
    ]
    assert report.advisories[0].aliases == (
        "CVE-2026-0001",
        "GHSA-aaaa-bbbb-0001",
    )
    assert report.summary["advisory_count"] == 4


def test_equal_cost_candidates_are_both_recommended(asset):
    report = _fixture_review(asset)

    assert [plan.artifacts for plan in report.recommended] == [
        ("linux-runtime",),
        ("windows-runtime",),
    ]
    assert {plan.cost for plan in report.recommended} == {1}
    assert all(len(plan.covered) == 4 for plan in report.recommended)
    assert all(not plan.uncovered for plan in report.recommended)
    assert report.complete is True


def test_recommended_plans_show_the_single_dependency_upgrade(asset):
    report = _fixture_review(asset)

    assert [plan.changes for plan in report.recommended] == [
        (PackageChange(package="webcore", from_versions=("1.8.0",), to_version="2.0.0"),),
        (PackageChange(package="webcore", from_versions=("1.8.0",), to_version="2.0.0"),),
    ]


def test_same_advisory_is_closed_only_once(asset):
    report = _fixture_review(asset)

    linux = next(
        artifact for artifact in report.artifacts if artifact.artifact.id == "linux-runtime"
    )
    windows = next(
        artifact for artifact in report.artifacts if artifact.artifact.id == "windows-runtime"
    )
    assert linux.covered == windows.covered
    assert len(linux.covered) == 4

    both = next(
        combination
        for combination in report.infeasible
        if combination.artifacts == ("linux-runtime", "windows-runtime")
    )
    assert len(both.covered) == 4
    assert both.coverage_scope == "potential"
    assert report.summary["closed_advisory_count"] == 4


def test_infeasible_reasons_are_verifiable(asset):
    report = _fixture_review(asset)
    both = next(
        combination
        for combination in report.infeasible
        if combination.artifacts == ("linux-runtime", "windows-runtime")
    )

    condition_reasons = [reason for reason in both.reasons if reason.code == "condition_conflict"]
    platform_reason = next(
        reason for reason in condition_reasons if dict(reason.detail)["dimension"] == "platform"
    )
    assert "linux-runtime" in platform_reason.artifacts
    assert "windows-runtime" in platform_reason.artifacts
    assert "linux" in dict(platform_reason.detail)["values"]
    assert "windows" in dict(platform_reason.detail)["values"]

    pin_conflict = next(
        combination
        for combination in report.infeasible
        if combination.artifacts == ("legacy-linux", "linux-runtime")
    )
    pin_reason = next(reason for reason in pin_conflict.reasons if reason.code == "pin_conflict")
    pin_detail = dict(pin_reason.detail)
    assert pin_detail["package"] == "webcore"
    assert "1.9.5" in pin_detail["versions"]
    assert "2.0.0" in pin_detail["versions"]
    assert both.pins == ()


def test_approval_required_alternative_is_retained(asset):
    report = _fixture_review(asset)

    alternative = next(
        alternative
        for alternative in report.alternatives
        if alternative.artifacts == ("windows-rc",)
    )
    assert alternative.kind == "declared"
    assert alternative.requires_approval is True
    assert "FIPS" in alternative.approval_note
    assert not any("windows-rc" in plan.artifacts for plan in report.recommended)


def test_conflict_override_alternative_when_no_single_plan_closes_all():
    audit = {
        "dependencies": [
            {
                "name": "alpha",
                "version": "1.0.0",
                "vulns": [{"id": "CVE-2026-3001", "fix_versions": ["2.0.0"]}],
            },
            {
                "name": "beta",
                "version": "1.0.0",
                "vulns": [{"id": "CVE-2026-3002", "fix_versions": ["2.0.0"]}],
            },
        ]
    }
    candidates = [
        LockCandidate(
            id="linux-alpha",
            pins={"alpha": "2.0.0", "beta": "1.0.0"},
            conditions={"platform": "linux"},
        ),
        LockCandidate(
            id="windows-beta",
            pins={"alpha": "1.0.0", "beta": "2.0.0"},
            conditions={"platform": "windows"},
        ),
    ]

    report = reconcile(audit, candidates)

    assert report.complete is False
    assert [plan.artifacts for plan in report.recommended] == [
        ("linux-alpha",),
        ("windows-beta",),
    ]
    alternative = next(alt for alt in report.alternatives if alt.kind == "conflict_override")
    assert alternative.artifacts == ("linux-alpha", "windows-beta")
    assert alternative.covered == ("CVE-2026-3001", "CVE-2026-3002")
    assert alternative.requires_approval is True
    assert any(reason.code == "condition_conflict" for reason in alternative.blocked_by)
    assert any(reason.code == "pin_conflict" for reason in alternative.blocked_by)


def test_duplicate_candidate_ids_are_rejected():
    with pytest.raises(ReviewParseError, match="duplicate candidate id"):
        parse_candidates(
            [
                {"id": "same", "pins": {"webcore": "1.0.0"}},
                {"id": "same", "pins": {"webcore": "2.0.0"}},
            ]
        )


def test_invalid_pin_version_is_rejected():
    with pytest.raises(ReviewParseError, match="invalid version"):
        LockCandidate(id="bad", pins={"webcore": "not-a-version"})


def test_candidate_pins_may_be_named_objects():
    candidates = parse_candidates(
        [{"id": "named", "pins": [{"name": "WebCore", "version": "2.0.0"}]}]
    )

    assert candidates[0].pins == (("webcore", Version("2.0.0")),)


def test_candidate_names_and_conditions_are_canonicalized():
    candidate = LockCandidate(
        id="  artifact  ",
        pins={"Web_Core": "2.0.0", "django": "4.2.0"},
        conditions={"Platform": "Linux", "Python": 3.11},
    )
    assert candidate.id == "artifact"
    assert candidate.pins == (("django", Version("4.2.0")), ("web-core", Version("2.0.0")))
    assert candidate.conditions == (("platform", "linux"), ("python", "3.11"))


def test_toml_candidates_and_path_inputs(asset):
    candidates = load_candidates(asset("review/candidates.toml"))
    assert [candidate.id for candidate in candidates] == ["linux-runtime", "windows-runtime"]

    report = reconcile(asset("review/audit.json"), asset("review/candidates.toml"))
    assert report.complete is True
    assert [plan.artifacts for plan in report.recommended] == [
        ("linux-runtime",),
        ("windows-runtime",),
    ]


def test_input_order_cannot_change_the_report(asset):
    audit = _read_json(asset("review/audit.json"))
    candidates = _read_json(asset("review/candidates.json"))
    baseline = reconcile(copy.deepcopy(audit), copy.deepcopy(candidates)).to_dict()

    audit_variants = []
    for dependency_order in (audit["dependencies"], list(reversed(audit["dependencies"]))):
        variant = copy.deepcopy(audit)
        variant["dependencies"] = copy.deepcopy(dependency_order)
        for dependency in variant["dependencies"]:
            dependency["vulns"] = list(reversed(dependency["vulns"]))
            for vulnerability in dependency["vulns"]:
                vulnerability["aliases"] = list(reversed(vulnerability["aliases"]))
        audit_variants.append(variant)

    for permutation in itertools.permutations(candidates["artifacts"]):
        candidate_variant = {"artifacts": []}
        for candidate in permutation:
            candidate = copy.deepcopy(candidate)
            candidate["pins"] = dict(reversed(list(candidate["pins"].items())))
            candidate["conditions"] = dict(reversed(list(candidate["conditions"].items())))
            candidate_variant["artifacts"].append(candidate)
        for audit_variant in audit_variants:
            report = reconcile(audit_variant, candidate_variant)
            assert report.to_dict() == baseline


def test_recommendation_does_not_depend_on_filter_order(asset):
    audit = _read_json(asset("review/audit.json"))
    candidates = _read_json(asset("review/candidates.json"))

    baseline = reconcile(audit, candidates)
    reordered = reconcile(audit, {"artifacts": list(reversed(candidates["artifacts"]))})

    assert [plan.artifacts for plan in baseline.recommended] == [
        plan.artifacts for plan in reordered.recommended
    ]
    assert len(reordered.recommended) == 2


def test_uncovered_advisory_reports_checkable_gaps(asset):
    audit = _read_json(asset("review/audit.json"))
    for dependency in audit["dependencies"]:
        for vulnerability in dependency["vulns"]:
            vulnerability["fix_versions"] = ["3.0.0"]
    candidates = _read_json(asset("review/candidates.json"))

    report = reconcile(audit, candidates)

    assert report.complete is False
    assert report.recommended == ()
    assert len(report.summary["uncovered_by_all_recommended"]) == 4
    gaps = [gap for plan in report.combinations if plan.feasible for gap in plan.gaps]
    assert any(
        gap.code == "pin_not_fixed"
        and gap.package == "webcore"
        and gap.pinned == "2.0.0"
        and gap.fix_versions == ("3.0.0",)
        for gap in gaps
    )


def test_missing_pin_is_a_checkable_gap():
    audit = {
        "dependencies": [
            {
                "name": "webcore",
                "version": "1.8.0",
                "vulns": [{"id": "CVE-2026-9999", "fix_versions": ["2.0.0"]}],
            }
        ]
    }
    candidates = [LockCandidate(id="django-only", pins={"django": "4.2.0"})]

    report = reconcile(audit, candidates)

    assert report.complete is False
    assert report.recommended == ()
    assert report.artifacts[0].gaps[0].code == "missing_pin"
    assert report.artifacts[0].gaps[0].package == "webcore"


def test_advisory_spanning_two_packages_needs_both_fixes_but_counts_once():
    audit = {
        "dependencies": [
            {
                "name": "webcore",
                "version": "1.8.0",
                "vulns": [{"id": "CVE-2026-7777", "fix_versions": ["2.0.0"]}],
            },
            {
                "name": "gateway",
                "version": "1.0.0",
                "vulns": [
                    {
                        "id": "GHSA-cccc-dddd-7777",
                        "aliases": ["CVE-2026-7777"],
                        "fix_versions": ["1.1.0"],
                    }
                ],
            },
        ]
    }
    partial = LockCandidate(id="partial", pins={"webcore": "2.0.0"})
    full = LockCandidate(id="full", pins={"webcore": "2.0.0", "gateway": "1.1.0"}, cost=2)

    report = reconcile(audit, [partial, full])

    assert report.summary["advisory_count"] == 1
    assert report.summary["closed_advisory_count"] == 1
    partial_review = next(item for item in report.artifacts if item.artifact.id == "partial")
    assert partial_review.covered == ()
    assert partial_review.gaps[0].code == "missing_pin"
    assert partial_review.gaps[0].package == "gateway"
    assert report.recommended[0].artifacts == ("full",)


def test_empty_audit_is_complete():
    report = reconcile({"dependencies": []}, [LockCandidate(id="lock", pins={})])

    assert report.advisories == ()
    assert report.recommended == ()
    assert report.complete is True


def test_combination_limit_is_explicit():
    audit = {"dependencies": []}
    candidates = [
        LockCandidate(id=f"artifact-{index}", pins={"webcore": "2.0.0"}) for index in range(4)
    ]

    with pytest.raises(ReviewError, match="refusing to enumerate"):
        reconcile(audit, candidates, options=ReviewOptions(max_combinations=10))

    report = reconcile(
        audit, candidates, options=ReviewOptions(max_combinations=10, max_artifacts=2)
    )
    assert len(report.combinations) == 10


@pytest.mark.parametrize(
    "pinned,fixes,expected",
    [
        ("1.5.0", ["1.2.3", "2.0.1"], True),
        ("2.0.0", ["1.2.3", "2.0.1"], False),
        ("2.0.1", ["1.2.3", "2.0.1"], True),
        ("3.0.0", ["2.0.0"], True),
        ("1.2.2", ["1.2.3"], False),
        ("1.0.0", [], False),
    ],
)
def test_version_is_fixed_handles_release_series(pinned, fixes, expected):
    assert version_is_fixed(Version(pinned), [Version(fix) for fix in fixes]) is expected


def test_audit_results_can_be_reviewed_without_json_roundtrip(dep_source, vuln_service):
    results = dict(Auditor(vuln_service()).audit(dep_source()))
    audit = AuditReport.from_results(results)
    candidates = [LockCandidate(id="fixed", pins={"foo": "1.1.0"})]

    report = reconcile(audit, candidates)

    assert [advisory.id for advisory in report.advisories] == ["fake-id"]
    assert report.complete is True


def test_report_json_roundtrip(asset):
    report = _fixture_review(asset)
    payload = json.loads(report.to_json())

    assert payload["schema"] == REVIEW_SCHEMA
    assert payload["summary"]["closed_advisory_count"] == 4
    assert [plan["artifacts"] for plan in payload["recommended"]] == [
        ["linux-runtime"],
        ["windows-runtime"],
    ]


def test_cli_json_output(asset, tmp_path):
    output = tmp_path / "report.json"
    status = review_main(
        [
            "--audit",
            str(asset("review/audit.json")),
            "--candidates",
            str(asset("review/candidates.json")),
            "--format",
            "json",
            "--output",
            str(output),
        ]
    )

    assert status == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["schema"] == REVIEW_SCHEMA
    assert payload["summary"]["complete"] is True


def test_cli_text_output_mentions_ties_and_approval(asset, capsys):
    status = review_main(
        [
            "--audit",
            str(asset("review/audit.json")),
            "--candidates",
            str(asset("review/candidates.json")),
        ]
    )

    captured = capsys.readouterr()
    assert status == 0
    assert "Recommended" in captured.out
    assert "linux-runtime" in captured.out
    assert "windows-runtime" in captured.out
    assert "windows-rc" in captured.out


def test_cli_incomplete_exit_status(asset, tmp_path):
    audit = _read_json(asset("review/audit.json"))
    for dependency in audit["dependencies"]:
        for vulnerability in dependency["vulns"]:
            vulnerability["fix_versions"] = ["3.0.0"]
    audit_path = tmp_path / "audit.json"
    audit_path.write_text(json.dumps(audit), encoding="utf-8")

    args = [
        "--audit",
        str(audit_path),
        "--candidates",
        str(asset("review/candidates.json")),
    ]
    assert review_main(args) == 1
    assert review_main([*args, "--allow-incomplete"]) == 0


def test_cli_missing_input_is_an_error(tmp_path, capsys):
    status = review_main(
        [
            "--audit",
            str(tmp_path / "missing.json"),
            "--candidates",
            str(tmp_path / "missing-candidates.json"),
        ]
    )

    captured = capsys.readouterr()
    assert status == 2
    assert "pip-audit-review: error:" in captured.err
