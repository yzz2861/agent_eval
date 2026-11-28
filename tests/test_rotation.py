from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from tuf.api.metadata import DelegatedRole, Delegations, Key, Targets
from tuf.rotation import (
    RolePlan,
    SignatureEvent,
    SigningWindow,
    contracts_from_targets,
    load_rotation_plan,
)

SAMPLE_DIR = (
    Path(__file__).resolve().parents[1] / "examples" / "rotation_windows"
)
START = datetime(2026, 12, 1, 9, 0, tzinfo=UTC)


def make_targets(policy: dict[str, tuple[tuple[str, ...], int]]) -> Targets:
    keys = {}
    roles = {}
    for role_name, (keyids, threshold) in policy.items():
        for keyid in keyids:
            keys[keyid] = Key.from_dict(
                keyid,
                {
                    "keytype": "ed25519",
                    "scheme": "ed25519",
                    "keyval": {"public": "00" * 32},
                },
            )
        roles[role_name] = DelegatedRole(
            role_name, list(keyids), threshold, False, ["*"]
        )
    return Targets(delegations=Delegations(keys, roles))


def sample_plan():
    return load_rotation_plan(
        str(SAMPLE_DIR / "old_targets.json"),
        str(SAMPLE_DIR / "new_targets.json"),
        str(SAMPLE_DIR / "approvals.json"),
        str(SAMPLE_DIR / "scenario.json"),
    )


class RotationContractTests(unittest.TestCase):
    def test_thresholds_come_from_old_and_new_targets(self) -> None:
        old = make_targets(
            {"role-a": (("old-a-1", "old-a-2"), 2)}
        )
        new = make_targets({"role-a": (("new-a-1",), 1)})

        contract = contracts_from_targets(old, new)["role-a"]

        self.assertEqual(contract.old_keyids, ("old-a-1", "old-a-2"))
        self.assertEqual(contract.old_threshold, 2)
        self.assertEqual(contract.new_keyids, ("new-a-1",))
        self.assertEqual(contract.new_threshold, 1)

    def test_old_acceptance_alone_does_not_satisfy_new_contract(self) -> None:
        role = RolePlan(
            name="role-a",
            old_keyids=("old-a-1", "old-a-2"),
            old_threshold=2,
            new_keyids=("new-a-1", "new-a-2"),
            new_threshold=2,
            window=SigningWindow(START, START + timedelta(hours=2)),
            events=(
                SignatureEvent("old-a-1", START + timedelta(minutes=1)),
                SignatureEvent("old-a-2", START + timedelta(minutes=2)),
                SignatureEvent("new-a-1", START + timedelta(minutes=3)),
            ),
        )

        result = role.contract()

        self.assertTrue(result.old.ok)
        self.assertFalse(result.new.ok)
        self.assertFalse(result.ok)
        self.assertEqual(result.new.missing, ("new-a-2",))

    def test_signature_outside_window_is_not_counted(self) -> None:
        role = RolePlan(
            name="role-a",
            old_keyids=("old-a-1", "old-a-2"),
            old_threshold=2,
            new_keyids=("new-a-1",),
            new_threshold=1,
            window=SigningWindow(START, START + timedelta(hours=1)),
            events=(
                SignatureEvent("old-a-1", START - timedelta(seconds=1)),
                SignatureEvent("old-a-2", START + timedelta(minutes=1)),
                SignatureEvent("new-a-1", START + timedelta(minutes=2)),
            ),
        )

        result = role.contract()

        self.assertFalse(result.ok)
        self.assertEqual(result.old.missing, ("old-a-1",))
        self.assertEqual(len(result.invalid_events), 1)

    def test_retained_key_counts_for_old_and_new_thresholds(self) -> None:
        role = RolePlan(
            name="role-a",
            old_keyids=("shared",),
            old_threshold=1,
            new_keyids=("shared", "new-a-1"),
            new_threshold=2,
            window=SigningWindow(START, START + timedelta(hours=1)),
            events=(
                SignatureEvent("shared", START + timedelta(minutes=1)),
                SignatureEvent("new-a-1", START + timedelta(minutes=2)),
            ),
        )

        result = role.contract()

        self.assertTrue(result.ok)
        self.assertEqual(result.old.signed, ("shared",))
        self.assertEqual(result.new.signed, ("new-a-1", "shared"))


class RotationScheduleTests(unittest.TestCase):
    def test_both_approval_orders_finish_on_baseline(self) -> None:
        report = sample_plan().evaluate()

        self.assertTrue(report.release_contract_ok)
        self.assertEqual(
            report.feasible_orders,
            (
                (
                    "delegated-alpha",
                    "delegated-beta",
                    "delegated-gamma",
                ),
                (
                    "delegated-alpha",
                    "delegated-gamma",
                    "delegated-beta",
                ),
            ),
        )
        self.assertEqual(report.blocked_orders, ())

    def test_delayed_beta_slip_rejects_only_beta_before_gamma(self) -> None:
        plan = sample_plan().with_delayed_slip(
            "delegated-beta", timedelta(minutes=15)
        )
        report = plan.evaluate()

        self.assertTrue(report.release_contract_ok)
        self.assertEqual(
            report.feasible_orders,
            (
                (
                    "delegated-alpha",
                    "delegated-gamma",
                    "delegated-beta",
                ),
            ),
        )
        self.assertEqual(len(report.blocked_orders), 1)
        blocked = report.blocked_orders[0]
        self.assertEqual(
            blocked.order,
            (
                "delegated-alpha",
                "delegated-beta",
                "delegated-gamma",
            ),
        )
        self.assertEqual(blocked.blocked_role, "delegated-gamma")
        self.assertEqual(blocked.missing_roles, ("delegated-gamma",))
        self.assertIn("window closes", blocked.reason or "")

    def test_delay_past_role_window_reports_that_role(self) -> None:
        plan = sample_plan().with_delayed_slip(
            "delegated-gamma", timedelta(hours=2)
        )
        report = plan.evaluate()

        self.assertFalse(report.release_contract_ok)
        self.assertFalse(report.contracts["delegated-gamma"].ok)
        for result in report.blocked_orders:
            self.assertIn("delegated-gamma", result.missing_roles)


if __name__ == "__main__":
    unittest.main()
