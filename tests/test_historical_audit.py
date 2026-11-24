from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from securesystemslib.signer import CryptoSigner

from tuf.api.history import (
    AuditRequest,
    CollectedMetadata,
    TargetSpec,
    audit_dict,
    request_to_dict,
)
from tuf.api.history_codec import replay_bundle
from tuf.api.metadata import (
    Metadata,
    MetaFile,
    Role,
    Root,
    Snapshot,
    TargetFile,
    Targets,
    Timestamp,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
TARGET_PATH = "demo/file.txt"
TARGET_DATA = b"historical target bytes\n"
AS_OF = datetime(2025, 3, 2, tzinfo=UTC)
CURRENT_TIME = datetime(2026, 11, 25, tzinfo=UTC)
METADATA_EXPIRES = datetime(2025, 4, 1, tzinfo=UTC)
ROOT_EXPIRES = datetime(2030, 1, 1, tzinfo=UTC)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def new_signer() -> CryptoSigner:
    return CryptoSigner.generate_ed25519()


def sign_metadata(inner: object, signer: CryptoSigner) -> bytes:
    md = Metadata(inner)
    md.sign(signer)
    return md.to_bytes()


def root_bytes(
    version: int,
    root_signer: CryptoSigner,
    role_signer: CryptoSigner,
    signing_signers: list[CryptoSigner],
    expires: datetime = ROOT_EXPIRES,
) -> bytes:
    root_key = root_signer.public_key
    role_key = role_signer.public_key
    root = Root(
        version=version,
        expires=expires,
        keys={root_key.keyid: root_key, role_key.keyid: role_key},
        roles={
            Root.type: Role([root_key.keyid], 1),
            Timestamp.type: Role([role_key.keyid], 1),
            Snapshot.type: Role([role_key.keyid], 1),
            Targets.type: Role([role_key.keyid], 1),
        },
    )
    md = Metadata(root)
    for signer in signing_signers:
        md.sign(signer, append=True)
    return md.to_bytes()


def target_chain(role_signer: CryptoSigner, expires: datetime = METADATA_EXPIRES):
    target_file = TargetFile.from_data(TARGET_PATH, TARGET_DATA)
    targets = Targets(
        version=1,
        expires=expires,
        targets={TARGET_PATH: target_file},
    )
    targets_bytes = sign_metadata(targets, role_signer)

    targets_meta = MetaFile(
        version=1,
        length=len(targets_bytes),
        hashes={"sha256": sha256_hex(targets_bytes)},
    )
    snapshot = Snapshot(
        version=1,
        expires=expires,
        meta={"targets.json": targets_meta},
    )
    snapshot_bytes = sign_metadata(snapshot, role_signer)

    snapshot_meta = MetaFile(
        version=1,
        length=len(snapshot_bytes),
        hashes={"sha256": sha256_hex(snapshot_bytes)},
    )
    timestamp = Timestamp(
        version=1,
        expires=expires,
        snapshot_meta=snapshot_meta,
    )
    timestamp_bytes = sign_metadata(timestamp, role_signer)
    return targets_bytes, snapshot_bytes, timestamp_bytes


class RotationFixture:
    def __init__(self) -> None:
        self.root1 = new_signer()
        self.root2 = new_signer()
        self.root2_alt = new_signer()
        self.role1 = new_signer()
        self.role2 = new_signer()
        self.root1_bytes = root_bytes(
            1, self.root1, self.role1, [self.root1]
        )
        self.root2_bytes = root_bytes(
            2,
            self.root2,
            self.role1,
            [self.root1, self.root2],
        )
        self.root2_alt_bytes = root_bytes(
            2,
            self.root2_alt,
            self.role1,
            [self.root1, self.root2_alt],
        )
        self.root3_bytes = root_bytes(
            3, self.root2, self.role2, [self.root2]
        )
        targets, snapshot, timestamp = target_chain(self.role1)
        self.targets_bytes = targets
        self.snapshot_bytes = snapshot
        self.timestamp_bytes = timestamp

    def record(
        self,
        data: bytes,
        collected_at: datetime,
        sequence: int,
        name: str,
        record_id: str | None = None,
    ) -> CollectedMetadata:
        return CollectedMetadata(
            data=data,
            collected_at=collected_at,
            sequence=sequence,
            name=name,
            record_id=record_id or name,
        )

    def happy_records(self) -> list[CollectedMetadata]:
        return [
            self.record(
                self.root2_bytes,
                datetime(2025, 2, 1, tzinfo=UTC),
                2,
                "2.root.json",
            ),
            self.record(
                self.targets_bytes,
                datetime(2025, 3, 1, tzinfo=UTC),
                3,
                "targets.json",
            ),
            self.record(
                self.snapshot_bytes,
                datetime(2025, 3, 1, tzinfo=UTC),
                4,
                "snapshot.json",
            ),
            self.record(
                self.timestamp_bytes,
                datetime(2025, 3, 1, tzinfo=UTC),
                5,
                "timestamp.json",
            ),
            self.record(
                self.root3_bytes,
                datetime(2025, 6, 1, tzinfo=UTC),
                6,
                "3.root.json",
            ),
        ]

    def request(
        self,
        records: list[CollectedMetadata] | None = None,
        *,
        as_of: datetime = AS_OF,
        current_time: datetime = CURRENT_TIME,
    ) -> AuditRequest:
        return AuditRequest(
            trust_anchor=self.root1_bytes,
            records=tuple(self.happy_records() if records is None else records),
            target=TargetSpec(TARGET_PATH, TARGET_DATA),
            as_of=as_of,
            current_time=current_time,
        )


def codes(view: dict[str, object]) -> set[str]:
    result: set[str] = set()
    for key in ("accepted_reasons", "rejection_reasons", "unprovable_reasons"):
        for reason in view.get(key, []):  # type: ignore[union-attr]
            result.add(reason["code"])  # type: ignore[index]
    for step in view.get("steps", []):  # type: ignore[union-attr]
        for reason in step.get("reasons", []):
            result.add(reason["code"])
    return result


def step_named(report: dict[str, object], mode: str, name: str) -> dict[str, object]:
    view = report[mode]
    for step in view["steps"]:  # type: ignore[index]
        if step["name"] == name:
            return step
    raise AssertionError(f"missing step {name}")


class HistoricalAuditTest(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = RotationFixture()

    def test_historical_acceptance_and_current_revocation(self) -> None:
        report = audit_dict(self.fixture.request())
        historical = report["historical"]
        current = report["current"]

        self.assertEqual("accepted", historical["verdict"])
        self.assertEqual("rejected", current["verdict"])
        historical_codes = codes(historical)
        current_codes = codes(current)
        self.assertIn("trust_anchor_self_signed", historical_codes)
        self.assertIn("root_version_verified", historical_codes)
        self.assertIn("timestamp_verified", historical_codes)
        self.assertIn("snapshot_verified", historical_codes)
        self.assertIn("target_hash_verified", historical_codes)
        self.assertIn("key_revoked_under_current_root", current_codes)

        root_step = step_named(report, "historical", "root_v2")
        self.assertEqual("passed", root_step["status"])
        self.assertIn(sha256_hex(self.fixture.root2_bytes), root_step["evidence_hashes"])

        evidence_hashes = {item["sha256"] for item in report["evidence"]}
        for raw in (
            self.fixture.root1_bytes,
            self.fixture.root2_bytes,
            self.fixture.root3_bytes,
            self.fixture.timestamp_bytes,
            self.fixture.snapshot_bytes,
            self.fixture.targets_bytes,
            TARGET_DATA,
        ):
            self.assertIn(sha256_hex(raw), evidence_hashes)

    def test_collection_time_does_not_replace_expiry(self) -> None:
        as_of = datetime(2025, 5, 1, tzinfo=UTC)
        report = audit_dict(self.fixture.request(as_of=as_of))
        historical = report["historical"]
        self.assertEqual("rejected", historical["verdict"])
        self.assertIn("metadata_expired", codes(historical))
        timestamp_step = step_named(report, "historical", "timestamp")
        self.assertEqual("failed", timestamp_step["status"])
        self.assertIn(sha256_hex(self.fixture.timestamp_bytes), timestamp_step["evidence_hashes"])

    def test_missing_intermediate_root_is_unprovable(self) -> None:
        missing_records = [
            self.fixture.record(
                self.fixture.root3_bytes,
                datetime(2025, 2, 15, tzinfo=UTC),
                2,
                "3.root.json",
            )
        ]
        report = audit_dict(self.fixture.request(missing_records))
        for mode in ("historical", "current"):
            view = report[mode]
            self.assertEqual("unprovable", view["verdict"])
            self.assertIn("missing_intermediate_root", codes(view))
            self.assertIn("discontinuous_root_chain", codes(view))

    def test_conflicting_root_records_are_not_chosen(self) -> None:
        conflict_records = [
            self.fixture.record(
                self.fixture.root2_bytes,
                datetime(2025, 2, 1, tzinfo=UTC),
                2,
                "2a.root.json",
                "root-2a",
            ),
            self.fixture.record(
                self.fixture.root2_alt_bytes,
                datetime(2025, 2, 1, tzinfo=UTC),
                3,
                "2b.root.json",
                "root-2b",
            ),
        ]
        report = audit_dict(self.fixture.request(conflict_records))
        historical = report["historical"]
        self.assertEqual("unprovable", historical["verdict"])
        conflict_codes = codes(historical)
        self.assertIn("conflicting_root_records", conflict_codes)
        step = step_named(report, "historical", "root_v2")
        self.assertEqual("conflict", step["status"])
        self.assertIn(sha256_hex(self.fixture.root2_bytes), step["evidence_hashes"])
        self.assertIn(sha256_hex(self.fixture.root2_alt_bytes), step["evidence_hashes"])

    def test_collection_log_gap_is_unprovable_but_reasons_remain(self) -> None:
        records = self.fixture.happy_records()
        records[1] = self.fixture.record(
            self.fixture.targets_bytes,
            datetime(2025, 3, 1, tzinfo=UTC),
            4,
            "targets.json",
        )
        report = audit_dict(self.fixture.request(records))
        historical = report["historical"]
        self.assertEqual("unprovable", historical["verdict"])
        self.assertIn("collection_log_gap", codes(historical))
        self.assertTrue(historical["accepted_reasons"])

    def test_bundle_replays_in_another_process(self) -> None:
        request = self.fixture.request()
        report = audit_dict(request)
        bundle = {
            "schema": "tuf-historical-casebook/v1",
            "cases": [
                {
                    "name": "rotation",
                    "request": request_to_dict(request),
                    "expected_report": report,
                }
            ],
        }
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as tmp:
            path = Path(tmp) / "casebook.json"
            path.write_text(json.dumps(bundle), encoding="utf-8")
            env = dict(os.environ)
            env["PYTHONPATH"] = str(REPO_ROOT)
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tuf.api.history",
                    str(path),
                    "--check",
                ],
                cwd=REPO_ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        self.assertEqual(0, result.returncode, result.stderr + result.stdout)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["all_match"])


if __name__ == "__main__":
    unittest.main()
