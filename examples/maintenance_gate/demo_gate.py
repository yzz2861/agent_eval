"""Runnable demonstration of the offline maintenance admission gate.

The scenario mirrors a real offline device:

* an authorization authority signs pause/resume slips as TUF delegated targets
  metadata and publishes coherent releases (epochs);
* the slips reach the device over different channels, so they can arrive in any
  order, only half complete, or with an older resume slip showing up last;
* the device admits packages purely from the verified TUF view, which makes the
  final verdict independent of arrival order.

Run it with the repository virtual environment::

    .venv/bin/python examples/maintenance_gate/demo_gate.py
"""

from __future__ import annotations

from tuf.contrib.maintenance_gate import (
    AdmissionVerdict,
    AuthorizationRepository,
    DelegationSpec,
    GateStatus,
    MaintenanceGate,
    Statement,
)

ROLES = ["timestamp", "snapshot", "targets", "channel-a", "channel-b"]
DELEGATED = ["channel-a", "channel-b"]

# Target paths used throughout the scenario.
PKG_A = "pkg/device-a/firmware.bin"
PKG_B = "pkg/device-b/firmware.bin"
PKG_SHARED = "pkg/shared/driver.bin"


def banner(title: str) -> None:
    print()
    print("=" * 72)
    print(title)
    print("=" * 72)


def show_verdicts(gate: MaintenanceGate, packages: list[str]) -> None:
    for package in packages:
        decision = gate.admit(package)
        print(
            f"  {package:28s} -> {decision.verdict.value:8s} | {decision.basis}"
        )


def main() -> None:
    # Two maintenance channels with overlapping responsibility. channel-b is
    # terminating, so a target lookup stops there once it matches.
    repo = AuthorizationRepository(
        [
            DelegationSpec("channel-a", ["pkg/device-a/*", "pkg/shared/*"]),
            DelegationSpec(
                "channel-b",
                ["pkg/device-b/*", "pkg/shared/*"],
                terminating=True,
            ),
        ]
    )

    banner("1. Publish two coherent authorization releases")
    epoch1 = repo.publish(
        [
            Statement.pause("channel-a", PKG_A),
            Statement.pause("channel-b", PKG_B, PKG_SHARED),
        ]
    )
    epoch2 = repo.publish(
        [
            Statement.resume("channel-a", PKG_A),
            Statement.pause("channel-b", PKG_B, PKG_SHARED),
        ]
    )
    print("epoch 1: pause A, pause B, pause shared")
    print("epoch 2: resume A, pause B, pause shared")

    banner("2. Same release, two arrival orders -> identical admission")
    packages = [PKG_A, PKG_B, PKG_SHARED]
    gate_forward = MaintenanceGate(repo.root_bytes, delegated_roles=DELEGATED)
    gate_reverse = MaintenanceGate(repo.root_bytes, delegated_roles=DELEGATED)
    for role in ROLES:
        gate_forward.ingest(role, epoch2[role])
    for role in reversed(ROLES):
        gate_reverse.ingest(role, epoch2[role])
    print("forward order:")
    show_verdicts(gate_forward, packages)
    print("reverse order:")
    show_verdicts(gate_reverse, packages)

    banner("3. Only half a release arrives -> held, decisions fail closed")
    half_gate = MaintenanceGate(repo.root_bytes, delegated_roles=DELEGATED)
    for role in ("channel-a", "timestamp", "snapshot"):
        result = half_gate.ingest(role, epoch2[role])
        print(
            f"  ingest {role:10s} -> {result.status.value:7s} | {result.reason}"
        )
    print("  admission while incomplete:")
    show_verdicts(half_gate, packages)

    banner("4. An old resume slip arrives last -> rollback is rejected")
    gate = MaintenanceGate(repo.root_bytes, delegated_roles=DELEGATED)
    for role in ROLES:
        gate.ingest(role, epoch2[role])
    print(f"  trusted epoch before late material: {gate.trusted_epoch}")
    late = gate.ingest("timestamp", epoch1["timestamp"])
    print(f"  late epoch-1 timestamp -> {late.status.value}: {late.reason}")
    print("  admission unchanged:")
    show_verdicts(gate, packages)

    banner("5. A new pause on top of the trusted view")
    epoch3 = repo.publish([Statement.pause("channel-a", PKG_A)])
    for role in ROLES:
        gate.ingest(role, epoch3[role])
    print(f"  trusted epoch is now {gate.trusted_epoch}")
    show_verdicts(gate, packages)

    banner("6. Already cached package is re-evaluated, never auto-admitted")
    intact = f"authorization::{PKG_A}".encode()
    tampered = b"stale-or-tampered-bytes"
    print(
        "  intact cached A:",
        gate.admit_cached(PKG_A, intact).verdict.value,
    )
    tampered_decision = gate.admit_cached(PKG_A, tampered)
    print(
        "  tampered cached A:",
        tampered_decision.verdict.value,
        "|",
        tampered_decision.basis,
    )

    banner("Summary of gate states")
    print("  verdict values:", [v.value for v in AdmissionVerdict])
    print("  ingest statuses:", [s.value for s in GateStatus])


if __name__ == "__main__":
    main()
