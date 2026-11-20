import hashlib

from elev_audit import (
    ApprovedException,
    DeploymentConditions,
    VERDICT_APPROVED,
    VERDICT_INCONCLUSIVE,
    VERDICT_REJECTED,
    attach_external_manifest,
    audit_artifact,
    build_empty_pe,
    build_pe_with_manifests,
    extract_embedded_evidence,
    make_manifest,
)
from elev_audit.policy import (
    REASON_ARCHITECTURE_MISMATCH,
    REASON_ARTIFACT_MISMATCH,
    REASON_MANIFEST_HASH_MISMATCH,
)

ARTIFACT = "tool.exe"


def _evidence(manifest_bytes, machine="i386", artifact=ARTIFACT, languages=None):
    languages = languages or {0x409: manifest_bytes}
    return extract_embedded_evidence(
        build_pe_with_manifests(languages, machine=machine), artifact
    )


def _approval(manifest_bytes, evidence, **overrides):
    params = dict(
        exception_id="EXC-1",
        artifact_ids=[ARTIFACT],
        architectures=[evidence.machine],
        approved_levels=["requireAdministrator"],
        allow_auto_elevate=False,
        approved_manifest_sha256=[hashlib.sha256(manifest_bytes).hexdigest()],
        approved_pe_sha256=[evidence.pe_sha256],
        approved_languages=[0x409],
        required_conditions={"channel": "internal"},
    )
    params.update(overrides)
    return ApprovedException(**params)


def test_baseline_approval_covers_exact_build():
    manifest = make_manifest("requireAdministrator")
    evidence = _evidence(manifest)
    approval = _approval(manifest, evidence)
    conditions = DeploymentConditions({"channel": "internal"})
    report = audit_artifact(evidence, [approval], conditions)
    assert report["verdict"] == VERDICT_APPROVED
    assert report["matched_exception_ids"] == ["EXC-1"]


def test_architecture_retarget_makes_approval_inapplicable():
    manifest = make_manifest("requireAdministrator")
    x86 = _evidence(manifest, machine="i386")
    approval = _approval(manifest, x86)
    x64 = _evidence(manifest, machine="amd64")
    report = audit_artifact(x64, [approval], DeploymentConditions({"channel": "internal"}))
    assert report["verdict"] == VERDICT_REJECTED
    reasons = report["evaluations"][0]["reasons"]
    assert REASON_ARCHITECTURE_MISMATCH in reasons


def test_manifest_change_pins_hash_and_blocks_unapproved_auto_elevate():
    manifest = make_manifest("requireAdministrator")
    evidence = _evidence(manifest)
    approval = _approval(manifest, evidence)
    rebuilt = make_manifest("requireAdministrator", auto_elevate=True)
    rebuilt_evidence = _evidence(rebuilt)
    report = audit_artifact(
        rebuilt_evidence, [approval], DeploymentConditions({"channel": "internal"})
    )
    assert report["verdict"] == VERDICT_REJECTED
    reasons = report["evaluations"][0]["reasons"]
    assert REASON_MANIFEST_HASH_MISMATCH in reasons
    assert "auto_elevate_not_approved" in reasons
    assert "pe_hash_not_approved" in reasons


def test_exception_never_crosses_artifact_boundary():
    manifest = make_manifest("requireAdministrator")
    evidence = _evidence(manifest, artifact="other.exe")
    approval = _approval(manifest, _evidence(manifest))
    report = audit_artifact(evidence, [approval], DeploymentConditions({"channel": "internal"}))
    reasons = report["evaluations"][0]["reasons"]
    assert REASON_ARTIFACT_MISMATCH in reasons


def test_missing_evidence_is_inconclusive_not_approved():
    manifest = make_manifest("requireAdministrator")
    baseline = _evidence(manifest)
    approval = _approval(manifest, baseline)
    empty = extract_embedded_evidence(build_empty_pe("i386"), ARTIFACT)
    report = audit_artifact(empty, [approval], DeploymentConditions({"channel": "internal"}))
    assert report["verdict"] == VERDICT_INCONCLUSIVE
    assert report["matched_exception_ids"] == []


def test_caller_supplied_standalone_manifest_is_accepted_as_evidence():
    manifest = make_manifest("highestAvailable")
    empty = extract_embedded_evidence(build_empty_pe("i386"), ARTIFACT)
    attached = attach_external_manifest(empty, manifest, source="caller:deploy/tool.manifest")
    assert attached.requested_level.level == "highestAvailable"
    approval = ApprovedException(
        exception_id="EXC-EXT",
        artifact_ids=[ARTIFACT],
        architectures=[empty.machine],
        approved_levels=["highestAvailable"],
    )
    report = audit_artifact(empty, [approval])
    assert report["verdict"] == VERDICT_APPROVED


def test_deployment_condition_mismatch_blocks_coverage():
    manifest = make_manifest("requireAdministrator")
    evidence = _evidence(manifest)
    approval = _approval(manifest, evidence)
    report = audit_artifact(
        evidence, [approval], DeploymentConditions({"channel": "public-store"})
    )
    assert report["verdict"] == VERDICT_REJECTED
    assert any(
        "deployment_condition_unmet:channel" in reason
        for reason in report["evaluations"][0]["reasons"]
    )


def test_unapproved_language_branch_is_not_covered():
    english = make_manifest("requireAdministrator")
    chinese = make_manifest("asInvoker")
    evidence = _evidence(english, languages={0x409: english, 0x804: chinese})
    approval = _approval(english, _evidence(english))
    report = audit_artifact(evidence, [approval], DeploymentConditions({"channel": "internal"}))
    assert report["language_branch_conflict"] is True
    assert report["verdict"] == VERDICT_REJECTED
    assert "language_branch_not_approved" in report["evaluations"][0]["reasons"]


def test_no_workstation_default_is_substituted_for_no_declaration():
    silent = make_manifest(level=None)
    evidence = _evidence(silent)
    approval = ApprovedException(
        exception_id="EXC-ND",
        artifact_ids=[ARTIFACT],
        architectures=[evidence.machine],
        approved_levels=["asInvoker"],
    )
    report = audit_artifact(evidence, [approval])
    assert report["verdict"] == VERDICT_INCONCLUSIVE
    assert "no_declaration" in report["findings"]
