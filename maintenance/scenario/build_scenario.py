#!/usr/bin/env python3
"""Build the offline maintenance-station scenario.

The scenario models a vendor that publishes firmware update bundles into
copyable release directories over time.  Every directory is a self-contained
TUF repository (metadata plus target payloads) that the maintenance station
can mirror onto local media before the network is disconnected.

The fixed clock (see ``maintenance/engine/clock.py``) makes every timestamp
deterministic so that acceptance can be reproduced without a live network.

Timeline (all instants are ISO-8601, timezone aware)::

    2026-11-20T00:00Z  inventory time: devices report their trusted metadata
                       and the firmware version they currently run
    2026-11-20T08:00Z  release A is published (firmware 1.4.0, long validity)
    2026-11-21T00:00Z  release B is published (firmware 1.5.0, expires 10:00Z)
    2026-11-21T02:00Z  release C is published (firmware 1.6.0, metadata v4)
    2026-11-21T06:00Z  maintenance window opens
    2026-11-21T12:00Z  maintenance window closes / network is disconnected

Release B is signed correctly and unexpired when the window opens, but its
metadata expires at 10:00Z: with a two hour install duration the 08:00Z
install deadline falls inside the window, so verification passes yet a 1.5.0
install cannot be guaranteed to finish.  Release A stays valid throughout
the window.  Release C is fully valid but advances metadata to v4, beyond
the version every group pinned at inventory time, so it never replaces the
trusted stock state.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from securesystemslib.signer import CryptoSigner

from tuf.api.metadata import (
    Metadata,
    MetaFile,
    Root,
    Snapshot,
    TargetFile,
    Targets,
    Timestamp,
)

# ---------------------------------------------------------------------------
# Fixed timeline
# ---------------------------------------------------------------------------

INVENTORY_TIME = datetime(2026, 11, 20, 0, 0, tzinfo=UTC)
RELEASE_A_TIME = datetime(2026, 11, 20, 8, 0, tzinfo=UTC)
RELEASE_B_TIME = datetime(2026, 11, 21, 0, 0, tzinfo=UTC)
RELEASE_C_TIME = datetime(2026, 11, 21, 2, 0, tzinfo=UTC)
WINDOW_OPEN = datetime(2026, 11, 21, 6, 0, tzinfo=UTC)
WINDOW_CLOSE = datetime(2026, 11, 21, 12, 0, tzinfo=UTC)

# Every install is assumed to need this much remaining metadata validity.
INSTALL_DURATION = timedelta(hours=2)

# Metadata validity periods chosen per release.  Release B is published late
# and still signed-valid when the window opens, but expires at 10:00Z: with a
# 2 hour install duration its install deadline (08:00Z) is inside the window,
# so verification passes yet the install cannot be finished before expiry.
RELEASE_A_VALIDITY = timedelta(days=30)
RELEASE_B_VALIDITY = timedelta(hours=10)  # expires 2026-11-21T10:00Z
# Release C is signed correctly and valid for the whole window, but its
# metadata version is ahead of what every device group has trusted: it must
# never be allowed to replace the inventory state.
RELEASE_C_VALIDITY = timedelta(days=7)

FIRMWARE_TARGET = "firmware/firmware.bin"


def iso(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Release:
    """One copyable release directory."""

    name: str
    published_at: datetime
    firmware_version: str
    metadata_version: int
    expiry: datetime


RELEASES = [
    Release(
        name="release-a",
        published_at=RELEASE_A_TIME,
        firmware_version="1.4.0",
        metadata_version=2,
        expiry=RELEASE_A_TIME + RELEASE_A_VALIDITY,
    ),
    Release(
        name="release-b",
        published_at=RELEASE_B_TIME,
        firmware_version="1.5.0",
        metadata_version=3,
        expiry=RELEASE_B_TIME + RELEASE_B_VALIDITY,
    ),
    Release(
        name="release-c",
        published_at=RELEASE_C_TIME,
        firmware_version="1.6.0",
        metadata_version=4,
        expiry=RELEASE_C_TIME + RELEASE_C_VALIDITY,
    ),
]


def _firmware_payload(version: str) -> bytes:
    return (
        f"firmware {version}\n"
        "deterministic payload for offline maintenance verification\n"
    ).encode()


def _build_release(
    out_dir: Path,
    release: Release,
    root_signer: CryptoSigner,
    timestamp_signer: CryptoSigner,
    snapshot_signer: CryptoSigner,
    targets_signer: CryptoSigner,
) -> None:
    """Write a fully signed TUF repository for one release."""

    metadata_dir = out_dir / "metadata"
    targets_dir = out_dir / "targets"
    metadata_dir.mkdir(parents=True, exist_ok=True)
    targets_dir.mkdir(parents=True, exist_ok=True)

    payload = _firmware_payload(release.firmware_version)
    target_path = targets_dir / Path(FIRMWARE_TARGET).name
    target_path.write_bytes(payload)

    targets = Targets(
        version=release.metadata_version,
        expires=release.expiry,
        targets={
            FIRMWARE_TARGET: TargetFile.from_data(
                FIRMWARE_TARGET, payload
            )
        },
    )
    targets_meta = Metadata(targets)
    targets_meta.sign(targets_signer)

    snapshot = Snapshot(
        version=release.metadata_version,
        expires=release.expiry,
        meta={
            "targets.json": MetaFile(release.metadata_version),
        },
    )
    snapshot_meta = Metadata(snapshot)
    snapshot_meta.sign(snapshot_signer)

    timestamp = Timestamp(
        version=release.metadata_version,
        expires=release.expiry,
        snapshot_meta=MetaFile(release.metadata_version),
    )
    timestamp_meta = Metadata(timestamp)
    timestamp_meta.sign(timestamp_signer)

    root = Root(
        version=1,
        expires=INVENTORY_TIME + timedelta(days=365),
    )
    for role, signer in (
        ("root", root_signer),
        ("timestamp", timestamp_signer),
        ("snapshot", snapshot_signer),
        ("targets", targets_signer),
    ):
        root.add_key(signer.public_key, role)
    root_meta = Metadata(root)
    root_meta.sign(root_signer)

    (metadata_dir / "root.json").write_bytes(root_meta.to_bytes())
    (metadata_dir / "timestamp.json").write_bytes(timestamp_meta.to_bytes())
    (metadata_dir / "snapshot.json").write_bytes(snapshot_meta.to_bytes())
    (metadata_dir / "targets.json").write_bytes(targets_meta.to_bytes())

    manifest = {
        "release": release.name,
        "published_at": iso(release.published_at),
        "metadata_expires": iso(release.expiry),
        "metadata_version": release.metadata_version,
        "firmware_version": release.firmware_version,
        "target": FIRMWARE_TARGET,
    }
    (out_dir / "release.json").write_text(
        json.dumps(manifest, indent=2) + "\n"
    )


def build_scenario(root: Path) -> dict[str, object]:
    """Create release directories, device inventory and the window config."""

    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)

    # One stable set of vendor keys across both releases: the devices pinned
    # the root at inventory time and every release must verify against it.
    root_signer = CryptoSigner.generate_ecdsa()
    timestamp_signer = CryptoSigner.generate_ecdsa()
    snapshot_signer = CryptoSigner.generate_ecdsa()
    targets_signer = CryptoSigner.generate_ecdsa()

    releases_dir = root / "releases"
    for release in RELEASES:
        _build_release(
            releases_dir / release.name,
            release,
            root_signer,
            timestamp_signer,
            snapshot_signer,
            targets_signer,
        )

    # The trusted root is the anchor each device holds from inventory time.
    trusted_root = Metadata(
        Root(version=1, expires=INVENTORY_TIME + timedelta(days=365))
    )
    for role, signer in (
        ("root", root_signer),
        ("timestamp", timestamp_signer),
        ("snapshot", snapshot_signer),
        ("targets", targets_signer),
    ):
        trusted_root.signed.add_key(signer.public_key, role)
    trusted_root.sign(root_signer)

    inventory_dir = root / "devices"
    inventory_dir.mkdir(parents=True, exist_ok=True)
    (inventory_dir / "root.json").write_bytes(trusted_root.to_bytes())

    inventory = {
        "inventory_time": iso(INVENTORY_TIME),
        "window_open": iso(WINDOW_OPEN),
        "window_close": iso(WINDOW_CLOSE),
        "install_duration_hours": int(INSTALL_DURATION.total_seconds() // 3600),
        "target": FIRMWARE_TARGET,
        "device_groups": [
            {
                "group": "fleet-north",
                "devices": 12,
                "installed_firmware": "1.3.0",
                "trusted_metadata_version": 1,
            },
            {
                "group": "fleet-south",
                "devices": 7,
                "installed_firmware": "1.3.0",
                "trusted_metadata_version": 2,
            },
            {
                "group": "fleet-east",
                "devices": 5,
                "installed_firmware": "1.4.0",
                "trusted_metadata_version": 4,
            },
            {
                "group": "fleet-west",
                "devices": 3,
                "installed_firmware": "1.4.0",
                "trusted_metadata_version": 3,
            },
        ],
    }
    (inventory_dir / "inventory.json").write_text(
        json.dumps(inventory, indent=2) + "\n"
    )

    return inventory


def main() -> None:
    scenario_root = Path(__file__).resolve().parents[1] / "scenario_data"
    inventory = build_scenario(scenario_root)
    print(f"Scenario written to {scenario_root}")
    print(json.dumps(inventory, indent=2))


if __name__ == "__main__":
    main()
