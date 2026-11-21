"""Tests for batch DSSE verification with a caller-implemented store.

A temporary SQLite database stands in for the caller's persistence layer.
Each "station" gets its own connection to the same database file, which
simulates parallel intake stations sharing one persistent store.
"""

import os
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_private_key

from securesystemslib.dsse import Envelope
from securesystemslib.dsse_batch import (
    ApprovalStore,
    BatchItem,
    BatchResult,
    BatchStatus,
    verify_batch,
)
from securesystemslib.signer import CryptoSigner

PEMS_DIR = Path(__file__).parent / "data" / "pems"


class SQLiteApprovalStore(ApprovalStore):
    """ApprovalStore backed by a SQLite database file.

    One instance (one connection) simulates one intake station.
    """

    def __init__(self, db_path: str):
        self.conn = sqlite3.connect(db_path)
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS approvals ("
            "  approval TEXT PRIMARY KEY,"
            "  envelope_id TEXT NOT NULL"
            ")"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS results ("
            "  envelope_id TEXT PRIMARY KEY,"
            "  status TEXT NOT NULL,"
            "  approval TEXT,"
            "  keyids TEXT NOT NULL"
            ")"
        )
        self.conn.commit()

    def close(self):
        self.conn.close()

    def get_result(self, envelope_id: str) -> BatchResult | None:
        row = self.conn.execute(
            "SELECT status, approval, keyids FROM results WHERE envelope_id = ?",
            (envelope_id,),
        ).fetchone()
        if row is None:
            return None
        status, approval, keyids = row
        return BatchResult(
            envelope_id=envelope_id,
            status=BatchStatus(status),
            approval=approval,
            keyids=keyids.split(",") if keyids else [],
        )

    def claim_approval(self, approval: str, envelope_id: str) -> str:
        # The primary key makes the occupation atomic across connections.
        with self.conn:
            cursor = self.conn.execute(
                "INSERT OR IGNORE INTO approvals (approval, envelope_id) VALUES (?, ?)",
                (approval, envelope_id),
            )
            if cursor.rowcount == 1:
                return envelope_id
            row = self.conn.execute(
                "SELECT envelope_id FROM approvals WHERE approval = ?",
                (approval,),
            ).fetchone()
            return row[0]

    def save_results(self, results: list[BatchResult]) -> None:
        with self.conn:
            self.conn.executemany(
                "INSERT INTO results (envelope_id, status, approval, keyids)"
                " VALUES (?, ?, ?, ?)",
                [
                    (
                        result.envelope_id,
                        result.status.value,
                        result.approval,
                        ",".join(result.keyids),
                    )
                    for result in results
                ],
            )

    def approval_owner(self, approval: str) -> str | None:
        row = self.conn.execute(
            "SELECT envelope_id FROM approvals WHERE approval = ?",
            (approval,),
        ).fetchone()
        return row[0] if row else None


class TestVerifyBatch(unittest.TestCase):
    """Batch verification over parallel stations sharing one SQLite store."""

    @classmethod
    def setUpClass(cls):
        cls.signers: list[CryptoSigner] = []
        for keytype in ["rsa", "ed25519"]:
            with open(PEMS_DIR / f"{keytype}_private.pem", "rb") as f:
                private_key = load_pem_private_key(f.read(), None)
            cls.signers.append(CryptoSigner(private_key))
        cls.keys = [signer.public_key for signer in cls.signers]

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.temp_dir)
        self.db_path = os.path.join(self.temp_dir, "approvals.db")
        self.stations: list[SQLiteApprovalStore] = []
        self.addCleanup(self.close_stations)

    def close_stations(self):
        for station in self.stations:
            station.close()

    def open_station(self) -> SQLiteApprovalStore:
        station = SQLiteApprovalStore(self.db_path)
        self.stations.append(station)
        return station

    def make_envelope(self, payload: bytes) -> Envelope:
        envelope = Envelope(payload, "application/vnd.test.purchase", {})
        for signer in self.signers:
            envelope.sign(signer)
        return envelope

    def test_parallel_stations_single_approval_consumed_once(self):
        """Two stations race on one approval: exactly one envelope wins."""
        station_a = self.open_station()
        station_b = self.open_station()

        result_a = verify_batch(
            [BatchItem("env-1", self.make_envelope(b"order-1"), "PA-001")],
            self.keys,
            1,
            station_a,
        )[0]
        result_b = verify_batch(
            [BatchItem("env-2", self.make_envelope(b"order-2"), "PA-001")],
            self.keys,
            1,
            station_b,
        )[0]

        # env-1 consumed the approval; env-2 must ask for a fresh one.
        self.assertEqual(result_a.status, BatchStatus.VERIFIED)
        self.assertEqual(result_a.approval, "PA-001")
        self.assertEqual(result_b.status, BatchStatus.APPROVAL_CONSUMED)
        self.assertIsNone(result_b.approval)
        self.assertEqual(station_b.approval_owner("PA-001"), "env-1")

    def test_retry_after_commit_and_disconnect_replays_result(self):
        """A retry after the committing station went away gets the old result."""
        station_a = self.open_station()
        envelope = self.make_envelope(b"order-1")
        verify_batch([BatchItem("env-1", envelope, "PA-001")], self.keys, 1, station_a)
        # The station commits, then disconnects.
        station_a.close()
        self.stations.remove(station_a)

        # A retry arrives at another station, presenting a new approval
        # number that must not be consumed.
        station_b = self.open_station()
        result = verify_batch(
            [BatchItem("env-1", envelope, "PA-777")], self.keys, 1, station_b
        )[0]

        self.assertEqual(result.status, BatchStatus.REPLAYED)
        self.assertEqual(result.approval, "PA-001")
        self.assertEqual(station_b.approval_owner("PA-001"), "env-1")
        self.assertIsNone(station_b.approval_owner("PA-777"))

    def test_rejected_envelope_resubmitted_with_fresh_approval(self):
        """The loser of the approval race can be resubmitted with a new one."""
        station_a = self.open_station()
        station_b = self.open_station()
        envelope_2 = self.make_envelope(b"order-2")

        verify_batch(
            [BatchItem("env-1", self.make_envelope(b"order-1"), "PA-001")],
            self.keys,
            1,
            station_a,
        )
        rejected = verify_batch(
            [BatchItem("env-2", envelope_2, "PA-001")], self.keys, 1, station_b
        )[0]
        self.assertEqual(rejected.status, BatchStatus.APPROVAL_CONSUMED)

        # The transient rejection is not committed: a fresh approval lets
        # the same envelope id through.
        resubmitted = verify_batch(
            [BatchItem("env-2", envelope_2, "PA-002")], self.keys, 1, station_b
        )[0]
        self.assertEqual(resubmitted.status, BatchStatus.VERIFIED)
        self.assertEqual(resubmitted.approval, "PA-002")
        self.assertEqual(station_a.approval_owner("PA-002"), "env-2")

    def test_invalid_signature_consumes_no_approval_and_is_replayed(self):
        """Bad signatures are committed, consume nothing, and replay."""
        station_a = self.open_station()
        envelope = self.make_envelope(b"order-1")
        envelope.signatures = {}  # no signature can verify now

        result = verify_batch(
            [BatchItem("env-1", envelope, "PA-001")], self.keys, 1, station_a
        )[0]
        self.assertEqual(result.status, BatchStatus.INVALID_SIGNATURE)
        self.assertIsNone(station_a.approval_owner("PA-001"))

        station_b = self.open_station()
        retry = verify_batch(
            [BatchItem("env-1", envelope, "PA-001")], self.keys, 1, station_b
        )[0]
        self.assertEqual(retry.status, BatchStatus.REPLAYED)
        self.assertIsNone(retry.approval)
        self.assertIsNone(station_b.approval_owner("PA-001"))

    def test_mixed_batch_in_one_call(self):
        """One batch may contain fresh, replayed and rejected items."""
        station_a = self.open_station()
        verify_batch(
            [BatchItem("env-1", self.make_envelope(b"order-1"), "PA-001")],
            self.keys,
            1,
            station_a,
        )

        station_b = self.open_station()
        results = verify_batch(
            [
                BatchItem("env-1", self.make_envelope(b"order-1"), "PA-001"),
                BatchItem("env-2", self.make_envelope(b"order-2"), "PA-001"),
                BatchItem("env-3", self.make_envelope(b"order-3"), "PA-003"),
            ],
            self.keys,
            1,
            station_b,
        )

        self.assertEqual(
            [r.status for r in results],
            [
                BatchStatus.REPLAYED,
                BatchStatus.APPROVAL_CONSUMED,
                BatchStatus.VERIFIED,
            ],
        )
        self.assertEqual(results[0].approval, "PA-001")
        self.assertIsNone(results[1].approval)
        self.assertEqual(results[2].approval, "PA-003")
        self.assertEqual(station_b.approval_owner("PA-003"), "env-3")


if __name__ == "__main__":
    unittest.main()
