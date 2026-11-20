"""End-to-end demonstration with pure-byte fixtures.

Scenario: an internal artifact "contoso-admintool.exe" ships an embedded
RT_MANIFEST. An approved exception EXC-2026-0417 covers the x86 build with
requireAdministrator and a pinned manifest hash. Two independent build
changes then make that same approval record inapplicable:

  1. the build is retargeted from x86 (i386) to x64 (amd64);
  2. the rebuilt manifest content no longer matches the pinned hash and adds
     an autoElevate=true element that the approval never granted.

Everything here is generated in memory as bytes; no Windows toolchain or
scanning-workstation default execution level is consulted.
"""
from __future__ import annotations

import hashlib
import json

from elev_audit import (
    ApprovedException,
    DeploymentConditions,
    audit_artifact,
    build_pe_with_manifests,
    evaluate_exception,
    extract_embedded_evidence,
    make_manifest,
)

ARTIFACT_ID = "contoso-admintool.exe"
DEPLOYMENT = DeploymentConditions(
    conditions={"channel": "internal-ltsc", "user_consent_required": True},
    source="caller:build-pipeline/run-4417",
)


def _print_header(title):
    print()
    print("=" * 78)
    print(title)
    print("=" * 78)


def main():
    original_manifest = make_manifest(level="requireAdministrator")
    original_manifest_hash = hashlib.sha256(original_manifest).hexdigest()
    original_pe = build_pe_with_manifests({0x409: original_manifest}, machine="i386")
    original_pe_hash = hashlib.sha256(original_pe).hexdigest()
    approval = ApprovedException(
        exception_id="EXC-2026-0417",
        artifact_ids=[ARTIFACT_ID],
        architectures=["IMAGE_FILE_MACHINE_I386"],
        approved_levels=["requireAdministrator"],
        allow_auto_elevate=False,
        approved_manifest_sha256=[original_manifest_hash],
        approved_pe_sha256=[original_pe_hash],
        approved_languages=[0x409],
        required_conditions={
            "channel": "internal-ltsc",
            "user_consent_required": True,
        },
        justification="Legacy admin tool requires elevation for driver cleanup.",
    )
    _print_header("Baseline build: the approved x86 artifact")
    baseline = extract_embedded_evidence(original_pe, ARTIFACT_ID)
    baseline_report = audit_artifact(baseline, [approval], DEPLOYMENT)
    print(json.dumps(baseline_report, indent=2, default=str))
    assert baseline_report["verdict"] == "approved"

    _print_header("Build change 1: retargeted from x86 to x64")
    retargeted_pe = build_pe_with_manifests({0x409: original_manifest}, machine="amd64")
    retargeted = extract_embedded_evidence(retargeted_pe, ARTIFACT_ID)
    retargeted_eval = evaluate_exception(approval, retargeted, DEPLOYMENT)
    print(json.dumps(retargeted_eval, indent=2, default=str))
    assert retargeted_eval["covered"] is False
    assert "architecture_not_approved" in retargeted_eval["reasons"]
    assert "pe_hash_not_approved" in retargeted_eval["reasons"]

    _print_header("Build change 2: rebuilt manifest + autoElevate on x86")
    rebuilt_manifest = make_manifest(
        level="requireAdministrator", auto_elevate=True
    )
    rebuilt_pe = build_pe_with_manifests({0x409: rebuilt_manifest}, machine="i386")
    rebuilt = extract_embedded_evidence(rebuilt_pe, ARTIFACT_ID)
    rebuilt_eval = evaluate_exception(approval, rebuilt, DEPLOYMENT)
    print(json.dumps(rebuilt_eval, indent=2, default=str))
    assert rebuilt_eval["covered"] is False
    assert "manifest_hash_not_approved" in rebuilt_eval["reasons"]
    assert "auto_elevate_not_approved" in rebuilt_eval["reasons"]
    rebuilt_report = audit_artifact(rebuilt, [approval], DEPLOYMENT)
    assert rebuilt_report["verdict"] == "rejected"

    _print_header("Build change 3: second language branch added")
    branched_pe = build_pe_with_manifests(
        {0x409: original_manifest, 0x804: make_manifest(level="asInvoker")},
        machine="i386",
    )
    branched = extract_embedded_evidence(branched_pe, ARTIFACT_ID)
    branched_report = audit_artifact(branched, [approval], DEPLOYMENT)
    print(json.dumps(branched_report["evaluations"][0], indent=2, default=str))
    print("artifact findings:", branched_report["findings"])
    assert branched_report["language_branch_conflict"] is True
    assert branched_report["verdict"] == "rejected"

    _print_header("Build change 4: deployment condition no longer met")
    wrong_channel = DeploymentConditions(
        conditions={"channel": "public-store", "user_consent_required": True},
        source="caller:release-ops",
    )
    condition_eval = evaluate_exception(approval, baseline, wrong_channel)
    print(json.dumps(condition_eval, indent=2, default=str))
    assert any("deployment_condition_unmet:channel" in r for r in condition_eval["reasons"])
    print()
    print("All drift scenarios demonstrated successfully.")


if __name__ == "__main__":
    main()
