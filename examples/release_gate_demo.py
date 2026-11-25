#!/usr/bin/env python3
"""End-to-end demo of the DSSE release gate.

The script generates a small set of signing keys, signs build, approval and
dependency attestations as DSSE envelopes, writes a versionable policy and
runs the release gate twice:

1. against the genuine attestations  -> release allowed
2. after swapping one envelope for a different artifact, keeping every
   signature cryptographically valid -> release blocked at the subject/role
   gate

Run it with the repository virtualenv, e.g.
``.venv/bin/python examples/release_gate_demo.py``.
"""

from __future__ import annotations

import json
from pathlib import Path

from securesystemslib.dsse import Envelope
from securesystemslib.gate import (
    IN_TOTO_PAYLOAD_TYPE,
    ReleaseGate,
    ReleasePolicy,
)
from securesystemslib.signer import CryptoSigner

BUILD = "https://example.com/predicate/build"
APPROVAL = "https://example.com/predicate/approval"
DEPENDENCY = "https://example.com/predicate/dependency"
ARTIFACT = "release/app-1.0.0.tar.gz"
DIGEST = "a" * 64
SWAPPED_DIGEST = "f" * 64


def statement(digest: str, predicate_type: str) -> dict:
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": ARTIFACT, "digest": {"sha256": digest}}],
        "predicateType": predicate_type,
        "predicate": {},
    }


def sign(signer: CryptoSigner, predicate_type: str, digest: str) -> dict:
    payload = json.dumps(
        statement(digest, predicate_type),
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    envelope = Envelope(payload, IN_TOTO_PAYLOAD_TYPE, {})
    envelope.sign(signer)
    return envelope.to_dict()


def build_policy(signers: dict[str, CryptoSigner]) -> ReleasePolicy:
    keyring = {
        signer.public_key.keyid: signer.public_key.to_dict()
        for signer in signers.values()
    }
    return ReleasePolicy.from_dict(
        {
            "schema_version": 1,
            "policy_id": "demo-release-policy",
            "policy_version": "2026.11.0",
            "expected_payload_types": [IN_TOTO_PAYLOAD_TYPE],
            "expected_subjects": [{"name": ARTIFACT, "digest": {"sha256": DIGEST}}],
            "keyring": keyring,
            "roles": [
                {
                    "predicate_type": BUILD,
                    "allowed_keyids": ["builder-1", "builder-2"],
                    "threshold": 2,
                },
                {
                    "predicate_type": APPROVAL,
                    "allowed_keyids": ["approver-1"],
                    "threshold": 1,
                    "separation_from": [BUILD],
                },
                {
                    "predicate_type": DEPENDENCY,
                    "allowed_keyids": ["scanner-1"],
                    "threshold": 1,
                },
            ],
            "principals": {
                "builder-a": ["builder-1"],
                "builder-b": ["builder-2"],
                "approver": ["approver-1"],
                "scanner": ["scanner-1"],
            },
        }
    )


def print_report(title: str, result) -> None:
    print(f"== {title} ==")
    print(f"allowed: {result.allowed}")
    if result.blocking_gates:
        print(f"blocking gates: {list(result.blocking_gates)}")
    for finding in result.findings:
        print(f"  [{finding.status.value:4}] {finding.gate}: {finding.message}")
    print()


def main() -> None:
    signers = {
        keyid: CryptoSigner.generate_ed25519(keyid)
        for keyid in ("builder-1", "builder-2", "approver-1", "scanner-1")
    }
    policy = build_policy(signers)
    gate = ReleaseGate(policy)

    out_dir = Path("examples/out")
    out_dir.mkdir(exist_ok=True)
    (out_dir / "policy.json").write_text(json.dumps(policy.to_dict(), indent=2))

    genuine = [
        sign(signers["builder-1"], BUILD, DIGEST),
        sign(signers["builder-2"], BUILD, DIGEST),
        sign(signers["approver-1"], APPROVAL, DIGEST),
        sign(signers["scanner-1"], DEPENDENCY, DIGEST),
    ]
    (out_dir / "envelopes.json").write_text(json.dumps(genuine, indent=2))
    print_report("genuine attestations", gate.evaluate(genuine))

    swapped = list(genuine)
    swapped[0] = sign(signers["builder-1"], BUILD, SWAPPED_DIGEST)
    swapped_result = gate.evaluate(swapped)
    print_report("swapped artifact (all signatures still valid)", swapped_result)


if __name__ == "__main__":
    main()
