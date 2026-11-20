"""Verify the two offline DSSE evidence interchange samples."""

from __future__ import annotations

import json
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_public_key

from securesystemslib.dsse import verify_evidence
from securesystemslib.signer import SSlibKey

ROOT = Path(__file__).parent


def public_key(sample: Path) -> SSlibKey:
    key = load_pem_public_key((sample / "public_key.pem").read_bytes())
    evidence = json.loads((sample / "evidence.json").read_text(encoding="utf-8"))
    signer = evidence["signatures"][0]
    return SSlibKey.from_crypto(
        key,
        keyid=signer["keyid"],
        scheme=signer["algorithm"]["scheme"],
    )


def main() -> int:
    sample1 = ROOT / "sample1"
    evidence1 = json.loads((sample1 / "evidence.json").read_text(encoding="utf-8"))
    reformatted = json.dumps(evidence1, indent=4, sort_keys=True)
    report1 = verify_evidence(
        reformatted,
        keys=[public_key(sample1)],
        artifact=(sample1 / "artifact.txt").read_bytes(),
    )
    print("sample1:", report1.status, report1.message or "")

    sample2 = ROOT / "sample2"
    report2 = verify_evidence(
        sample2 / "evidence.json",
        keys=[public_key(sample2)],
        artifact=(sample2 / "artifact.txt").read_bytes(),
    )
    print("sample2:", report2.status, report2.message or "")

    if report1.status != "verified":
        return 1
    if report2.status != "rejected":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
