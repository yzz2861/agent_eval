"""Runnable shared-substitute sample for the independence audit.

Run 'python -m securesystemslib.independence_sample' to print reports.
The sample uses real securesystemslib Ed25519 signatures; all identity, key,
roster, alias, substitution, and overlap facts carry offline source records.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from typing import Any

from securesystemslib.independence_check import (
    audit_independence,
    canonical_json,
    sha256_digest,
    verify_offline_attestation,
)
from securesystemslib.signer import CryptoSigner

SIGNED_AT = "2026-11-27T10:00:00+08:00"
SHIFT_START = "2026-11-27T09:00:00+08:00"
SHIFT_END = "2026-11-27T18:00:00+08:00"
PAYLOAD = (
    b"approval-case: DATA-COMPLIANCE-2026-1127\n"
    b"decision: approve-release\n"
    b"artifact-digest: sha256:sample-only\n"
)


def _source(source_id: str, kind: str, locator: str, excerpt: str) -> dict[str, Any]:
    return {
        "id": source_id,
        "kind": kind,
        "locator": locator,
        "excerpt": excerpt,
        "content_sha256": sha256_digest(excerpt),
    }


@dataclass
class SharedSubstituteSample:
    """A sample whose missing independent signoff can be added once."""

    bundle: dict[str, Any]
    signers: dict[str, CryptoSigner]
    payload: bytes = PAYLOAD
    signed_at: str = SIGNED_AT
    signoff_added: bool = False

    def add_independent_signoff(self) -> dict[str, Any]:
        """Add Zhao's independent compliance signoff to this same sample."""
        if self.signoff_added:
            raise RuntimeError("independent signoff has already been added")
        signer = self.signers["key-zhao-2026"]
        receipt_payload = (
            "independent-signoff-receipt/v1\n"
            f"case_id={self.bundle['case_id']}\n"
            f"approval_payload_sha256={sha256_digest(self.payload)}\n"
            "receipt_id=RECEIPT-ZHAO-20261127-01\n"
        ).encode()
        signature = signer.sign(receipt_payload)
        candidate = {
            "keyid": signer.public_key.keyid,
            "sig": signature.signature,
            "payload": receipt_payload.decode("utf-8"),
            "payload_encoding": "utf-8",
            "signed_at": self.signed_at,
            "signature_kind": "independent_signoff",
            "signoff_type": "independent_delivery_receipt",
            "receipt_id": "RECEIPT-ZHAO-20261127-01",
            "source": "SRC-INDEPENDENT-SIGNOFF",
        }
        for group in self.bundle["approval_groups"]:
            if group["id"] == "compliance":
                group["signatures"].append(candidate)
                break
        self.signoff_added = True
        return candidate

    def audit(self) -> Any:
        return audit_independence(self.bundle)


def create_shared_substitute_sample() -> SharedSubstituteSample:
    """Create the shared-substitute case with real Ed25519 signatures."""
    key_ids = [
        "key-lin-2026",
        "key-zhou-2026",
        "key-chen-2025-old",
        "key-chen-2026-new",
        "key-zhao-2026",
    ]
    signers = {keyid: CryptoSigner.generate_ed25519(keyid=keyid) for keyid in key_ids}
    public_keys = {
        keyid: signer.public_key.to_dict() for keyid, signer in signers.items()
    }

    def signed_candidate(keyid: str, source_id: str, kind: str) -> dict[str, Any]:
        signature = signers[keyid].sign(PAYLOAD)
        return {
            "keyid": keyid,
            "sig": signature.signature,
            "signed_at": SIGNED_AT,
            "signature_kind": kind,
            "source": source_id,
        }

    bundle: dict[str, Any] = {
        "schema_version": "independence-sample/v1",
        "case_id": "shared-substitute-data-compliance",
        "payload": PAYLOAD.decode("utf-8"),
        "payload_encoding": "utf-8",
        "signed_at": SIGNED_AT,
        "sources": {
            "SRC-HR-ALIAS": _source(
                "SRC-HR-ALIAS",
                "hr_identity_export",
                "offline://records/2026/hr-aliases.yaml",
                "chen.che = Chen Che = CC-oncall => person.chen",
            ),
            "SRC-KEY-HISTORY": _source(
                "SRC-KEY-HISTORY",
                "key_rotation_record",
                "offline://records/2026/key-history.yaml",
                "Chen old key overlaps new key during rotation acceptance window.",
            ),
            "SRC-SHARED-ONCALL": _source(
                "SRC-SHARED-ONCALL",
                "shared_roster_publication",
                "offline://records/2026/W48/shared-oncall.yaml",
                "Data and compliance use one on-call pool from 2026-W47 onward.",
            ),
            "SRC-DATA-ROSTER": _source(
                "SRC-DATA-ROSTER",
                "data_roster",
                "offline://records/2026/W48/data-roster.yaml",
                "Lin Lan data primary; Chen Che approved substitute for Wang Meng.",
            ),
            "SRC-DATA-SUBSTITUTE": _source(
                "SRC-DATA-SUBSTITUTE",
                "leave_and_substitute_approval",
                "offline://records/2026/W48/data-substitute.yaml",
                "Wang Meng leave approved; Chen Che acts as data approver.",
            ),
            "SRC-COMPLIANCE-ROSTER": _source(
                "SRC-COMPLIANCE-ROSTER",
                "compliance_roster",
                "offline://records/2026/W48/compliance-roster.yaml",
                "Zhou Yu primary; Chen Che and Zhao Ning scheduled compliance staff.",
            ),
            "SRC-TIME-OVERLAP-REVIEW": _source(
                "SRC-TIME-OVERLAP-REVIEW",
                "dual_hat_overlap_review",
                "offline://records/2026/W48/overlap-review.yaml",
                "Chen Che data substitute and compliance shift overlap all day.",
            ),
            "SRC-INDEPENDENT-SIGNOFF": _source(
                "SRC-INDEPENDENT-SIGNOFF",
                "independent_delivery_receipt",
                "offline://records/2026/W48/zhao-signoff.yaml",
                "Zhao Ning signs independent compliance receipt after conflict review.",
            ),
        },
        "principals": [
            {
                "id": "person.lin",
                "display_name": "Lin Lan",
                "aliases": [{"alias": "lin.lan", "source": "SRC-HR-ALIAS"}],
            },
            {
                "id": "person.zhou",
                "display_name": "Zhou Yu",
                "aliases": [{"alias": "zhou.yu", "source": "SRC-HR-ALIAS"}],
            },
            {
                "id": "person.chen",
                "display_name": "Chen Che",
                "aliases": [
                    {"alias": "chen.che", "source": "SRC-HR-ALIAS"},
                    {"alias": "CC-oncall", "source": "SRC-HR-ALIAS"},
                ],
            },
            {
                "id": "person.zhao",
                "display_name": "Zhao Ning",
                "aliases": [{"alias": "zhao.ning", "source": "SRC-HR-ALIAS"}],
            },
            {"id": "person.wang", "display_name": "Wang Meng"},
        ],
        "aliases": [
            {"alias": "陈澈", "principal_id": "person.chen", "source": "SRC-HR-ALIAS"},
        ],
        "public_keys": public_keys,
        "key_history": [
            {
                "keyid": "key-lin-2026",
                "principal_id": "person.lin",
                "valid_from": "2026-01-01T00:00:00+08:00",
                "source": "SRC-KEY-HISTORY",
            },
            {
                "keyid": "key-zhou-2026",
                "principal_id": "person.zhou",
                "valid_from": "2026-01-01T00:00:00+08:00",
                "source": "SRC-KEY-HISTORY",
            },
            {
                "keyid": "key-chen-2025-old",
                "holder": "chen.che",
                "valid_from": "2025-01-01T00:00:00+08:00",
                "valid_to": "2027-01-01T00:00:00+08:00",
                "successor_keyid": "key-chen-2026-new",
                "source": "SRC-KEY-HISTORY",
            },
            {
                "keyid": "key-chen-2026-new",
                "holder": "陈澈",
                "valid_from": "2026-11-01T00:00:00+08:00",
                "predecessor_keyid": "key-chen-2025-old",
                "source": "SRC-KEY-HISTORY",
            },
            {
                "keyid": "key-zhao-2026",
                "principal_id": "person.zhao",
                "valid_from": "2026-01-01T00:00:00+08:00",
                "source": "SRC-KEY-HISTORY",
            },
        ],
        "shifts": [
            {
                "group_id": "data",
                "principal_id": "person.lin",
                "start": SHIFT_START,
                "end": SHIFT_END,
                "kind": "primary",
                "source": "SRC-DATA-ROSTER",
            },
            {
                "group_id": "data",
                "principal_id": "person.chen",
                "start": SHIFT_START,
                "end": SHIFT_END,
                "kind": "substitute",
                "substitute_for": "person.wang",
                "source": "SRC-DATA-SUBSTITUTE",
            },
            {
                "group_id": "compliance",
                "principal_id": "person.zhou",
                "start": SHIFT_START,
                "end": SHIFT_END,
                "kind": "primary",
                "source": "SRC-COMPLIANCE-ROSTER",
            },
            {
                "group_id": "compliance",
                "principal_id": "person.chen",
                "start": SHIFT_START,
                "end": SHIFT_END,
                "kind": "shared_on_call",
                "source": "SRC-SHARED-ONCALL",
            },
            {
                "group_id": "compliance",
                "principal_id": "person.zhao",
                "start": SHIFT_START,
                "end": SHIFT_END,
                "kind": "primary",
                "source": "SRC-COMPLIANCE-ROSTER",
            },
        ],
        "time_overlap_attestations": [
            {
                "principal_id": "person.chen",
                "group_ids": ["data", "compliance"],
                "start": SHIFT_START,
                "end": SHIFT_END,
                "source": "SRC-TIME-OVERLAP-REVIEW",
            }
        ],
        "approval_groups": [
            {
                "id": "data",
                "threshold": 2,
                "signatures": [
                    signed_candidate("key-lin-2026", "SRC-DATA-ROSTER", "approval"),
                    signed_candidate(
                        "key-chen-2025-old",
                        "SRC-DATA-SUBSTITUTE",
                        "substitute_approval",
                    ),
                ],
            },
            {
                "id": "compliance",
                "threshold": 2,
                "signatures": [
                    signed_candidate(
                        "key-zhou-2026", "SRC-COMPLIANCE-ROSTER", "approval"
                    ),
                    signed_candidate(
                        "key-chen-2026-new",
                        "SRC-SHARED-ONCALL",
                        "shared_oncall_approval",
                    ),
                ],
            },
        ],
    }
    return SharedSubstituteSample(bundle=bundle, signers=signers)


def build_shared_substitute_sample(
    include_independent_signoff: bool = False,
) -> dict[str, Any]:
    """Build a bundle dict; optionally include the independent signoff."""
    sample = create_shared_substitute_sample()
    if include_independent_signoff:
        sample.add_independent_signoff()
    return sample.bundle


def _print_summary(title: str, bundle: dict[str, Any]) -> None:
    result = audit_independence(bundle)
    summary = {
        "ok": result.ok,
        "feasible": result.feasible,
        "shortfall": result.shortfall,
        "absence": result.to_dict().get("absence"),
        "assignment": result.assignment,
        "shared_principals": result.shared_principals,
        "inputs_digest": result.inputs_digest,
        "report_digest": result.report_digest,
    }
    print(f"== {title} ==")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", nargs="?", help="offline bundle JSON to recompute")
    parser.add_argument("--full", action="store_true", help="print full report")
    args = parser.parse_args(argv)

    if args.bundle:
        with open(args.bundle, encoding="utf-8") as handle:
            bundle = json.load(handle)
        result = audit_independence(bundle)
        if args.full:
            report = result.to_dict()
        else:
            report = {
                key: result.to_dict()[key]
                for key in ("ok", "feasible", "shortfall", "assignment", "attestation")
            }
        print(canonical_json(report))
        attestation = verify_offline_attestation(bundle, result)
        if not attestation["valid"]:
            return 2
        return 0 if result.ok else 1

    sample = create_shared_substitute_sample()
    _print_summary("Before independent signoff", sample.bundle)
    sample.add_independent_signoff()
    _print_summary("After independent signoff", sample.bundle)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
