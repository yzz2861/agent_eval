"""Plan the last verifiable install version per device group.

The planner combines offline TUF verdicts with the maintenance window and
each device group inventory. It never lets an unverified update replace
the trusted inventory state: when no release can be verified at the fixed
evaluation time, the group keeps its inventory firmware version.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from maintenance.engine.clock import parse_iso
from maintenance.engine.verifier import OfflineVerifier, ReleaseVerdict


def load_inventory(inventory_path: str | Path) -> dict:
    """Load the device inventory taken at the fixed inventory time."""
    return json.loads(Path(inventory_path).read_text())


def load_release_directories(scenario_dir: str | Path) -> list[Path]:
    """Return copyable release directories in filesystem order."""
    releases_root = Path(scenario_dir) / "releases"
    return sorted(
        path
        for path in releases_root.iterdir()
        if path.is_dir() and (path / "release.json").is_file()
    )


@dataclass
class GroupDecision:
    """Final maintenance decision for one device group."""

    device_group: str
    devices: int
    target: str
    inventory_version: str
    trusted_metadata_version: int
    selected_version: str
    source_release: str | None
    decision_status: str
    failure_reason: str | None
    installed_by: datetime
    verifiable_until: datetime | None
    install_deadline: datetime | None
    conclusion_expires_at: datetime
    candidates: list[ReleaseVerdict] = field(default_factory=list)

    def to_dict(self) -> dict:
        def stamp(value: datetime | None) -> str | None:
            return value.isoformat() if value is not None else None

        return {
            "device_group": self.device_group,
            "devices": self.devices,
            "target": self.target,
            "inventory_version": self.inventory_version,
            "trusted_metadata_version": self.trusted_metadata_version,
            "selected_version": self.selected_version,
            "source_release": self.source_release,
            "decision_status": self.decision_status,
            "failure_reason": self.failure_reason,
            "installed_by": self.installed_by.isoformat(),
            "verifiable_until": stamp(self.verifiable_until),
            "install_deadline": stamp(self.install_deadline),
            "conclusion_expires_at": self.conclusion_expires_at.isoformat(),
            "candidates": [verdict.to_dict() for verdict in self.candidates],
        }


def evaluate_fleet(
    inventory: dict,
    release_dirs: list[str | Path],
    trusted_root_path: str | Path | None = None,
) -> list[dict]:
    """Evaluate every device group against all releases at a fixed clock.

    The fixed clock is the maintenance window open: that is the earliest
    time the station can start an install, so all metadata must still be
    valid then and every conclusion is reproducible offline.
    """
    window_open = parse_iso(inventory["window_open"])
    window_close = parse_iso(inventory["window_close"])
    install_duration = timedelta(
        hours=inventory["install_duration_hours"]
    )

    root_path = trusted_root_path
    if root_path is None:
        root_path = Path("maintenance/scenario/generated/devices/root.json")

    verifiers = [
        OfflineVerifier(root_path, release_dir, window_open)
        for release_dir in release_dirs
    ]

    decisions: list[dict] = []
    for group in inventory["device_groups"]:
        decisions.append(
            _evaluate_group(
                group,
                inventory["target"],
                verifiers,
                window_open,
                window_close,
                install_duration,
            ).to_dict()
        )
    return decisions


def _evaluate_group(
    group: dict,
    target: str,
    verifiers: list[OfflineVerifier],
    window_open: datetime,
    window_close: datetime,
    install_duration: timedelta,
) -> GroupDecision:
    inventory_version = group["installed_firmware"]
    trusted_metadata_version = group["trusted_metadata_version"]

    candidates: list[ReleaseVerdict] = []
    for verifier in verifiers:
        verdict = verifier.verify(
            target, trusted_metadata_version
        )
        if verdict.verified:
            verdict.install_deadline = verifier.install_deadline(
                verdict.verifiable_until, install_duration
            )
            # An install started anywhere in the window must still finish
            # before the metadata expires, so the deadline must cover the
            # full window, not just its opening moment.
            verdict.has_time_to_install = (
                verdict.install_deadline >= window_close
            )
        candidates.append(verdict)
    candidates.sort(key=lambda item: item.published_at)

    usable = [
        verdict
        for verdict in candidates
        if verdict.verified and verdict.has_time_to_install
    ]

    if usable:
        chosen = max(usable, key=lambda item: item.published_at)
        source_release = chosen.release_name
        selected_version = chosen.target_version
        failure_reason = None
        verifiable_until = chosen.verifiable_until
        install_deadline = chosen.install_deadline
        conclusion_expires_at = min(install_deadline, window_close)
        if _version_key(selected_version) > _version_key(inventory_version):
            decision_status = "install-update"
        else:
            decision_status = "keep-current"
            failure_reason = "already on the newest verifiable installable version"
    else:
        decision_status, failure_reason = _fallback(candidates)
        source_release = None
        selected_version = inventory_version
        verifiable_until = None
        install_deadline = None
        conclusion_expires_at = window_close

    return GroupDecision(
        device_group=group["group"],
        devices=group["devices"],
        target=target,
        inventory_version=inventory_version,
        trusted_metadata_version=trusted_metadata_version,
        selected_version=selected_version,
        source_release=source_release,
        decision_status=decision_status,
        failure_reason=failure_reason,
        installed_by=window_close,
        verifiable_until=verifiable_until,
        install_deadline=install_deadline,
        conclusion_expires_at=conclusion_expires_at,
        candidates=candidates,
    )


def _version_key(version: str) -> tuple[int, ...]:
    """Parse a dotted numeric firmware version for ordering."""
    return tuple(int(part) for part in version.split("."))


def _fallback(candidates: list[ReleaseVerdict]) -> tuple[str, str]:
    """Explain why the inventory state must be kept."""
    if not candidates:
        return "keep-inventory", "no release directories available"
    if any(verdict.verified for verdict in candidates):
        msg = "verified but remaining validity shorter than install duration"
        return "keep-inventory", msg
    statuses = sorted({verdict.status for verdict in candidates})
    return "keep-inventory", "; ".join(statuses)
