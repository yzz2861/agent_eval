"""Walkthrough test for the edge-device claim-and-confirm interface.

Scenario: a repair station serves TUF-trusted artifacts to edge devices
via offline media. Two simulated devices claim deliveries from a
temporary repository; one device re-claims after a version change and
sends its installation receipt the next day. The final report confirms
only the artifact that was actually installed.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from datetime import UTC, datetime, timedelta

from edge_delivery import (
    ClaimService,
    ClaimTicket,
    ConflictKind,
    DeliveryDeprecatedError,
    ReceiptMismatchError,
    TicketStatus,
)
from tests.repository_simulator import RepositorySimulator
from tuf.ngclient import Updater


class EdgeDevice:
    """Simulated edge device carrying offline media."""

    def __init__(self, device_id: str, service: ClaimService):
        self.device_id = device_id
        self.service = service
        self.installed: dict[str, dict[str, str]] = {}

    def claim(self, target_path: str) -> ClaimTicket:
        return self.service.claim(self.device_id, target_path)

    def install(self, ticket: ClaimTicket, media: bytes) -> None:
        """Install media only if it matches the sealed claim ticket."""
        digest = hashlib.sha256(media).hexdigest()
        if ticket.hashes.get("sha256") != digest:
            raise ValueError("offline media does not match sealed ticket")
        self.installed[ticket.target_path] = dict(ticket.hashes)

    def send_receipt(
        self, target_path: str, received_at: datetime | None = None
    ) -> ClaimTicket:
        return self.service.confirm(
            self.device_id,
            target_path,
            self.installed[target_path],
            received_at,
        )


class TestEdgeDeliveryWalkthrough(unittest.TestCase):
    """Two devices, one temporary repository, full claim lifecycle."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.metadata_dir = os.path.join(self.temp_dir.name, "metadata")
        self.targets_dir = os.path.join(self.temp_dir.name, "targets")

        self.sim = RepositorySimulator()
        self.sim.add_target("targets", b"firmware-v1", "firmware.bin")
        self.sim.targets.targets["firmware.bin"].unrecognized_fields[
            "custom"
        ] = {"version": 1}
        self.sim.add_target("targets", b"diag-v1", "diag-tool.bin")
        self.sim.targets.version += 1
        self.sim.update_snapshot()

        self.service = ClaimService(self._make_updater)
        self.device_a = EdgeDevice("device-a", self.service)
        self.device_b = EdgeDevice("device-b", self.service)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _make_updater(self) -> Updater:
        return Updater(
            self.metadata_dir,
            "https://example.com/metadata/",
            self.targets_dir,
            "https://example.com/targets/",
            self.sim,
            bootstrap=self.sim.signed_roots[0],
        )

    def _publish(self, firmware: bytes, version: int) -> None:
        """Publish a new firmware version and deprecate the diag tool."""
        self.sim.add_target("targets", firmware, "firmware.bin")
        self.sim.targets.targets["firmware.bin"].unrecognized_fields[
            "custom"
        ] = {"version": version}
        del self.sim.targets.targets["diag-tool.bin"]
        self.sim.targets.version += 1
        self.sim.update_snapshot()

    def test_claim_reclaim_and_late_receipt(self) -> None:
        # Both devices claim the firmware; device B also claims the tool.
        ticket_a1 = self.device_a.claim("firmware.bin")
        ticket_b1 = self.device_b.claim("firmware.bin")
        ticket_b_diag = self.device_b.claim("diag-tool.bin")

        # Re-claiming an unchanged delivery is idempotent.
        reclaim = self.device_a.claim("firmware.bin")
        self.assertEqual(reclaim.claim_id, ticket_a1.claim_id)
        self.assertEqual(reclaim, ticket_a1)

        # The repository publishes firmware v2 and deprecates the tool;
        # the station refreshes its trust view.
        self._publish(b"firmware-v2", 2)
        self.service.refresh_remote()

        # The remote refresh must not change any already-sealed ticket.
        self.assertIs(self.service.get_ticket(ticket_a1.claim_id), ticket_a1)
        self.assertIs(
            self.service.get_ticket(ticket_b_diag.claim_id), ticket_b_diag
        )

        # Device A re-claims: the version change is recorded as an
        # explicit conflict and a new ticket is sealed for v2.
        ticket_a2 = self.device_a.claim("firmware.bin")
        self.assertNotEqual(ticket_a2.claim_id, ticket_a1.claim_id)
        self.assertNotEqual(ticket_a2.hashes, ticket_a1.hashes)
        self.assertEqual(ticket_a2.custom, {"version": 2})
        self.assertEqual(
            self.service.get_ticket(ticket_a1.claim_id).status,
            TicketStatus.SUPERSEDED,
        )

        # Device B re-claims the deprecated tool: explicit conflict,
        # no new ticket, and its sealed ticket stays untouched.
        with self.assertRaises(DeliveryDeprecatedError):
            self.device_b.claim("diag-tool.bin")
        self.assertIs(
            self.service.get_ticket(ticket_b_diag.claim_id), ticket_b_diag
        )

        # Device A installs v2 from offline media; the receipt reaches
        # the station the next day and confirms the sealed v2 ticket.
        media = self.sim.fetch_target(
            "firmware.bin", ticket_a2.hashes["sha256"]
        )
        self.device_a.install(ticket_a2, media)
        next_day = datetime.now(UTC) + timedelta(days=1)
        confirmed = self.device_a.send_receipt(
            "firmware.bin", received_at=next_day
        )
        self.assertEqual(confirmed.claim_id, ticket_a2.claim_id)
        self.assertEqual(confirmed.status, TicketStatus.CONFIRMED)

        # Device B reports an artifact it was never handed: mismatch.
        with self.assertRaises(ReceiptMismatchError):
            self.service.confirm(
                self.device_b.device_id,
                "firmware.bin",
                ticket_a2.hashes,
            )

        # The report confirms only the artifact actually installed.
        report = self.service.report()
        self.assertEqual(
            [t.claim_id for t in report.confirmed], [ticket_a2.claim_id]
        )
        self.assertEqual(report.confirmed[0].device_id, "device-a")
        self.assertEqual(report.confirmed[0].hashes, ticket_a2.hashes)

        self.assertEqual(
            {t.claim_id for t in report.pending},
            {ticket_b1.claim_id, ticket_b_diag.claim_id},
        )
        self.assertEqual(
            [c.kind for c in report.conflicts],
            [
                ConflictKind.VERSION_CHANGED,
                ConflictKind.DELIVERY_DEPRECATED,
                ConflictKind.RECEIPT_MISMATCH,
            ],
        )
        version_conflict = report.conflicts[0]
        self.assertEqual(version_conflict.device_id, "device-a")
        self.assertEqual(version_conflict.sealed_hashes, ticket_a1.hashes)
        self.assertEqual(version_conflict.observed_hashes, ticket_a2.hashes)


if __name__ == "__main__":
    unittest.main()
