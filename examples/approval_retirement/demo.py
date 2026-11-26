#!/usr/bin/env python3
"""Demonstrate one approved retirement and one shared-reference refusal.

Run from the repository root::

    python examples/approval_retirement/demo.py

The script creates self-contained evidence bundles under
``examples/approval_retirement/evidence``.  Each bundle contains the signed
approval index, the request, public verification keys, and the result report.
The successful bundle additionally contains the signed retirement manifest and
the retained digest/authorization record.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from securesystemslib.retirement import (  # noqa: E402
    INDEX_PAYLOAD_TYPE,
    INDEX_SCHEMA_VERSION,
    ApprovalAttachment,
    ApprovalCase,
    ApprovalIndex,
    AuthorizationRecord,
    RetirementRequest,
    RetirementService,
    write_signed_document,
)
from securesystemslib.signer import CryptoSigner  # noqa: E402

DEFAULT_OUTPUT = Path(__file__).parent / "evidence"


def sha256_digest(data: bytes) -> dict[str, str]:
    return {"sha256": hashlib.sha256(data).hexdigest()}


def write_attachment(
    scenario: Path, attachment_id: str, body: str
) -> ApprovalAttachment:
    relative_path = f"attachments/{attachment_id}.txt"
    path = scenario / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    data = body.encode("utf-8")
    path.write_bytes(data)
    return ApprovalAttachment(
        attachment_id=attachment_id,
        path=relative_path,
        digest=sha256_digest(data),
        size=len(data),
    )


def authorization(
    *,
    case_id: str,
    attachments: dict[str, ApprovalAttachment],
    approver: CryptoSigner,
    approved_at: str,
) -> AuthorizationRecord:
    return AuthorizationRecord.create(
        record_id=f"authz-{case_id}",
        case_id=case_id,
        attachment_ids=attachments,
        approved_at=approved_at,
        authorized_digests={
            attachment_id: dict(attachment.digest or {})
            for attachment_id, attachment in attachments.items()
        },
        approver=approver,
    )


def write_index(
    scenario: Path,
    *,
    attachments: dict[str, ApprovalAttachment],
    cases: dict[str, tuple[str, ...]],
    approver: CryptoSigner,
    archivist: CryptoSigner,
) -> Path:
    index = ApprovalIndex(
        schema_version=INDEX_SCHEMA_VERSION,
        created_at="2026-11-27T00:00:00+00:00",
        attachments=attachments,
        cases={
            case_id: ApprovalCase(
                case_id=case_id,
                attachment_ids=attachment_ids,
                authorization=authorization(
                    case_id=case_id,
                    attachments={
                        attachment_id: attachments[attachment_id]
                        for attachment_id in attachment_ids
                    },
                    approver=approver,
                    approved_at="2021-06-01T09:30:00+00:00",
                ),
            )
            for case_id, attachment_ids in cases.items()
        },
    )
    index_path = scenario / "index.dsse.json"
    write_signed_document(index_path, index.to_dict(), INDEX_PAYLOAD_TYPE, archivist)
    return index_path


def write_public_keys(directory: Path, *signers: CryptoSigner) -> None:
    keys = {signer.public_key.keyid: signer.public_key.to_dict() for signer in signers}
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "public-keys.json").write_text(
        json.dumps(keys, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def write_summary(path: Path, summary: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def run_success(output: Path) -> dict[str, Any]:
    scenario = output / "success"
    if scenario.exists():
        shutil.rmtree(scenario)
    scenario.mkdir(parents=True)

    approver = CryptoSigner.generate_ed25519()
    archivist = CryptoSigner.generate_ed25519()

    old_attachment = write_attachment(
        scenario,
        "att-2020-approval",
        "2020 approval memo: release approved by the records board\n",
    )
    new_attachment = write_attachment(
        scenario,
        "att-2025-approval",
        "2025 approval memo: still-current case material\n",
    )
    index_path = write_index(
        scenario,
        attachments={
            old_attachment.attachment_id: old_attachment,
            new_attachment.attachment_id: new_attachment,
        },
        cases={
            "case-2020-17": (old_attachment.attachment_id,),
            "case-2025-04": (new_attachment.attachment_id,),
        },
        approver=approver,
        archivist=archivist,
    )

    service = RetirementService(
        [archivist.public_key],
        [approver.public_key],
        signer=archivist,
    )
    result = service.retire(
        index_path,
        RetirementRequest(
            request_id="retire-2020-approval",
            case_id="case-2020-17",
            attachment_id=old_attachment.attachment_id,
        ),
        manifest_path=scenario / "retirement-manifest.dsse.json",
        evidence_dir=scenario / "evidence",
    )
    write_public_keys(scenario / "evidence", approver, archivist)

    return {
        "scenario": "successful-retirement",
        "status": result.status.value,
        "reason": result.reason,
        "retired_attachment": result.attachment_id,
        "retired_attachment_exists": (scenario / old_attachment.path).exists(),
        "retained_digest": dict(result.digest or {}),
        "authorization_record": (
            result.authorization.get("record_id")
            if result.authorization is not None
            else None
        ),
        "verification": result.verification["status"]
        if result.verification is not None
        else None,
        "evidence": "success/evidence",
    }


def run_shared_reference(output: Path) -> dict[str, Any]:
    scenario = output / "shared-reference"
    if scenario.exists():
        shutil.rmtree(scenario)
    scenario.mkdir(parents=True)

    approver = CryptoSigner.generate_ed25519()
    archivist = CryptoSigner.generate_ed25519()

    shared_attachment = write_attachment(
        scenario,
        "att-shared-evidence",
        "Approval evidence used by two case files; it must not be removed.\n",
    )
    index_path = write_index(
        scenario,
        attachments={shared_attachment.attachment_id: shared_attachment},
        cases={
            "case-2020-17": (shared_attachment.attachment_id,),
            "case-2021-09": (shared_attachment.attachment_id,),
        },
        approver=approver,
        archivist=archivist,
    )

    service = RetirementService(
        [archivist.public_key],
        [approver.public_key],
        signer=archivist,
    )
    result = service.retire(
        index_path,
        RetirementRequest(
            request_id="retire-shared-attempt",
            case_id="case-2020-17",
            attachment_id=shared_attachment.attachment_id,
        ),
        manifest_path=scenario / "retirement-manifest.dsse.json",
        evidence_dir=scenario / "evidence",
    )
    write_public_keys(scenario / "evidence", approver, archivist)

    rejection = json.loads(
        (scenario / "evidence/rejection.json").read_text(encoding="utf-8")
    )
    return {
        "scenario": "shared-reference-rejection",
        "status": result.status.value,
        "reason": result.reason,
        "referencing_cases": list(result.referencing_cases),
        "attachment_exists": (scenario / shared_attachment.path).exists(),
        "attachment_digest_matches": rejection["verification"]["attachment"][
            "digest_matches_index"
        ],
        "verification": rejection["verification"]["status"],
        "evidence": "shared-reference/evidence",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"evidence output directory (default: {DEFAULT_OUTPUT})",
    )
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)

    summary = [run_success(output), run_shared_reference(output)]
    write_summary(output / "acceptance-summary.json", {"results": summary})
    print(json.dumps({"results": summary}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
