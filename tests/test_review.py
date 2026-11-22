import json

from pip_audit._deployment import (
    FindingStatus,
    build_report,
    read_exemption_catalog,
    read_stage_lockfile,
    render_json,
    review_stage,
    review_stages,
)
from pip_audit._deployment.offline import OfflineAdvisoryService


def _review(lock, role, advisory_snapshot, exemption_file, environment):
    stage = read_stage_lockfile(role, lock)
    service = OfflineAdvisoryService(advisory_snapshot)
    catalog = read_exemption_catalog(exemption_file)
    return review_stage(stage, service, catalog, environment)


def _by_name(stage_review):
    return {review.canonical_name: review for review in stage_review.reviews}


def test_build_host_findings_are_exempt(build_lock, advisory_snapshot, exemption_file, linux_env):
    stage = _review(build_lock, "build-host", advisory_snapshot, exemption_file, linux_env)
    packages = _by_name(stage)

    assert packages["wheel"].status is FindingStatus.Exempt
    assert packages["setuptools"].status is FindingStatus.Exempt
    assert packages["requests"].status is FindingStatus.Exempt
    assert packages["requests"].applied_exemption.role == "build-host"
    assert stage.runtime_warnings == ()


def test_marker_gated_package_is_not_selected(build_lock, advisory_snapshot, exemption_file, linux_env):
    stage = _review(build_lock, "build-host", advisory_snapshot, exemption_file, linux_env)
    pywin32 = _by_name(stage)["pywin32"]

    assert pywin32.selected is False
    assert pywin32.status is FindingStatus.NotSelected
    assert pywin32.findings  # advisory evidence still recorded
    assert pywin32.is_runtime_warning is False


def test_runtime_requests_not_cancelled_by_build_exemption(
    runtime_lock, advisory_snapshot, exemption_file, linux_env
):
    stage = _review(runtime_lock, "runtime-image", advisory_snapshot, exemption_file, linux_env)
    requests_review = _by_name(stage)["requests"]

    assert requests_review.status is FindingStatus.Open
    assert requests_review.is_runtime_warning is True
    assert requests_review.applied_exemption is None
    mismatch = requests_review.role_mismatch_exemption
    assert mismatch is not None
    assert mismatch.role == "build-host"
    assert mismatch.advisory == "PYSEC-2024-REQUESTS"
    assert requests_review.findings[0].advisory_id == "PYSEC-2024-REQUESTS"


def test_same_archive_keeps_separate_basis_per_role(
    build_lock, runtime_lock, advisory_snapshot, exemption_file, linux_env
):
    build_stage = _review(build_lock, "build-host", advisory_snapshot, exemption_file, linux_env)
    runtime_stage = _review(
        runtime_lock, "runtime-image", advisory_snapshot, exemption_file, linux_env
    )

    build_requests = _by_name(build_stage)["requests"]
    runtime_requests = _by_name(runtime_stage)["requests"]

    # Same visible archive (identical wheel hash) in both stages.
    assert build_requests.artifacts[0].sha256 == runtime_requests.artifacts[0].sha256
    assert build_requests.version == runtime_requests.version == "2.32.2"

    # Each stage keeps its own advisory basis.
    assert build_requests.findings == runtime_requests.findings
    assert len(build_requests.findings) == 1

    # But only the runtime side retains an un-cancelled warning.
    assert build_requests.is_runtime_warning is False
    assert runtime_requests.is_runtime_warning is True
    assert runtime_requests.role_mismatch_exemption is not None


def test_unregistered_role_entry_is_retained_as_warning(
    runtime_lock, advisory_snapshot, exemption_file, linux_env
):
    stage = _review(runtime_lock, "runtime-image", advisory_snapshot, exemption_file, linux_env)
    jinja2 = _by_name(stage)["jinja2"]

    assert jinja2.status is FindingStatus.RoleNotRegistered
    assert jinja2.is_runtime_warning is True
    retained = jinja2.retained_exemption
    assert retained.role == "legacy-ci"
    assert retained.advisory == "PYSEC-2025-JINJA2"
    assert jinja2.applied_exemption is None


def test_correctly_scoped_runtime_exemption(
    runtime_lock, advisory_snapshot, exemption_file, linux_env
):
    stage = _review(runtime_lock, "runtime-image", advisory_snapshot, exemption_file, linux_env)
    urllib3 = _by_name(stage)["urllib3"]

    assert urllib3.status is FindingStatus.Exempt
    assert urllib3.is_runtime_warning is False
    assert urllib3.applied_exemption.role == "runtime-image"


def test_clean_and_skipped_packages(runtime_lock, advisory_snapshot, exemption_file, linux_env):
    stage = _review(runtime_lock, "runtime-image", advisory_snapshot, exemption_file, linux_env)
    packages = _by_name(stage)

    assert packages["certifi"].status is FindingStatus.Open
    assert packages["certifi"].findings == ()
    assert packages["certifi"].is_runtime_warning is False

    assert packages["internal-utils"].status is FindingStatus.Skipped
    assert packages["internal-utils"].skip_reason == "no version specified"
    assert packages["internal-utils"].is_runtime_warning is False


def test_review_stages_and_report_roundtrip(
    build_lock, runtime_lock, advisory_snapshot, exemption_file, linux_env, tmp_path
):
    stage_reviews, _service, _catalog = review_stages(
        stages=[("build-host", build_lock), ("runtime-image", runtime_lock)],
        advisory_snapshot=advisory_snapshot,
        exemption_file=exemption_file,
        environments={"build-host": linux_env, "runtime-image": linux_env},
    )

    report = build_report(stage_reviews)
    assert report["schema"] == "deployment-stage-review/v1"
    assert report["stage_count"] == 2
    assert report["runtime_warning_count"] == 2

    roles = {stage["role"]: stage for stage in report["stages"]}
    assert roles["build-host"]["runtime_warning_count"] == 0
    assert roles["runtime-image"]["runtime_warning_count"] == 2

    rendered = render_json(stage_reviews)
    reparsed = json.loads(rendered)
    assert reparsed["runtime_warning_count"] == 2

    warning_names = {
        pkg["name"] for pkg in roles["runtime-image"]["runtime_warnings"]
    }
    assert warning_names == {"requests", "jinja2"}

    output = tmp_path / "report.json"
    output.write_text(rendered, encoding="utf-8")
    assert json.loads(output.read_text())["schema"] == "deployment-stage-review/v1"
