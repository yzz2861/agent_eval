"""Acceptance tests for the offline maintenance-station planner.

The scenario uses a fixed clock, so every verdict is deterministic and
reproducible without network access.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from maintenance.engine import (
    OfflineVerifier,
    evaluate_fleet,
    load_inventory,
    load_release_directories,
    parse_iso,
)
from maintenance.scenario.build_scenario import build_scenario


class MaintenancePlannerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.scenario_dir = Path(cls.tmp.name)
        build_scenario(cls.scenario_dir)
        cls.inventory = load_inventory(
            cls.scenario_dir / "devices" / "inventory.json"
        )
        cls.releases = load_release_directories(cls.scenario_dir)
        cls.root = cls.scenario_dir / "devices" / "root.json"
        cls.window_open = "2026-11-21T06:00:00+00:00"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def _group(self, decisions: list[dict], name: str) -> dict:
        return next(item for item in decisions if item["device_group"] == name)

    def test_three_release_directories_are_considered(self) -> None:
        self.assertEqual(
            [path.name for path in self.releases],
            ["release-a", "release-b", "release-c"],
        )

    def test_south_picks_earlier_release_when_later_one_too_new(self) -> None:
        decisions = evaluate_fleet(self.inventory, self.releases, self.root)
        south = self._group(decisions, "fleet-south")

        # South only trusts metadata v2: the earlier 1.4.0 bundle verifies
        # while the later bundles advance metadata beyond its trust state.
        self.assertEqual(south["decision_status"], "install-update")
        self.assertEqual(south["selected_version"], "1.4.0")
        self.assertEqual(south["source_release"], "release-a")
        statuses = {item["release"]: item["status"] for item in south["candidates"]}
        self.assertEqual(statuses["release-b"], "metadata-version-ahead")
        self.assertEqual(statuses["release-a"], "verified")

    def test_bundle_b_verifies_but_cannot_finish_within_window(self) -> None:
        # release-b signs correctly and is unexpired at window open, yet its
        # 10:00Z expiry leaves a 08:00Z install deadline inside the window.
        verifier = OfflineVerifier(self.root, self.releases[1], self.window_open)
        verdict = verifier.verify(self.inventory["target"], 3)
        self.assertTrue(verdict.verified)
        self.assertEqual(verdict.status, "verified")
        deadline = verifier.install_deadline(
            verdict.verifiable_until, timedelta(hours=2)
        )
        self.assertEqual(
            deadline.isoformat(), "2026-11-21T08:00:00+00:00"
        )
        window_close = "2026-11-21T12:00:00+00:00"
        self.assertLess(deadline, parse_iso(window_close))

    def test_north_keeps_inventory_when_metadata_advanced_too_far(self) -> None:
        decisions = evaluate_fleet(self.inventory, self.releases, self.root)
        north = self._group(decisions, "fleet-north")
        self.assertEqual(north["decision_status"], "keep-inventory")
        self.assertEqual(north["selected_version"], "1.3.0")
        self.assertIsNone(north["source_release"])
        ahead = [
            item for item in north["candidates"]
            if item["status"] == "metadata-version-ahead"
        ]
        self.assertEqual(len(ahead), 3)

    def test_east_picks_newest_verifiable_bundle(self) -> None:
        decisions = evaluate_fleet(self.inventory, self.releases, self.root)
        east = self._group(decisions, "fleet-east")
        self.assertEqual(east["decision_status"], "install-update")
        self.assertEqual(east["selected_version"], "1.6.0")
        self.assertEqual(east["source_release"], "release-c")

    def test_conclusion_expiry_uses_window_close_for_installable(self) -> None:
        decisions = evaluate_fleet(self.inventory, self.releases, self.root)
        south = self._group(decisions, "fleet-south")
        self.assertEqual(
            south["conclusion_expires_at"], "2026-11-21T12:00:00+00:00"
        )
        self.assertEqual(
            south["install_deadline"], "2026-12-20T06:00:00+00:00"
        )

    def test_tampered_timestamp_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            target_dir = Path(scratch) / "release-a"
            shutil.copytree(self.releases[0], target_dir)
            tampered = target_dir / "metadata" / "timestamp.json"
            payload = json.loads(tampered.read_text())
            payload["signed"]["version"] = 99
            tampered.write_text(json.dumps(payload))

            verdict = OfflineVerifier(
                self.root, target_dir, self.window_open
            ).verify(self.inventory["target"])
            self.assertFalse(verdict.verified)
            self.assertEqual(verdict.status, "signature-invalid")

    def test_tampered_payload_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            target_dir = Path(scratch) / "release-a"
            shutil.copytree(self.releases[0], target_dir)
            payload = target_dir / "targets" / "firmware.bin"
            payload.write_bytes(b"tampered firmware content")

            verdict = OfflineVerifier(
                self.root, target_dir, self.window_open
            ).verify(self.inventory["target"])
            self.assertFalse(verdict.verified)
            self.assertEqual(verdict.status, "payload-mismatch")


    def test_west_keeps_earlier_bundle_when_later_lacks_install_time(self) -> None:
        decisions = evaluate_fleet(self.inventory, self.releases, self.root)
        west = self._group(decisions, "fleet-west")

        # Both A and B verify, but B expires mid-window so it cannot finish:
        # the station keeps the earlier, fully-valid 1.4.0 bundle.
        self.assertEqual(west["decision_status"], "keep-current")
        self.assertEqual(west["selected_version"], "1.4.0")
        self.assertEqual(west["source_release"], "release-a")
        candidates = {item["release"]: item for item in west["candidates"]}
        self.assertEqual(candidates["release-b"]["status"], "verified")
        self.assertFalse(candidates["release-b"]["has_time_to_install"])
        self.assertTrue(candidates["release-a"]["has_time_to_install"])
        self.assertEqual(
            candidates["release-b"]["install_deadline"],
            "2026-11-21T08:00:00+00:00",
        )


if __name__ == "__main__":
    unittest.main()
