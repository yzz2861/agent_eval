# Copyright 2026, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Tests for offline remediation planning."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from securesystemslib.signer import CryptoSigner, Signer

from tuf.api import exceptions
from tuf.api.metadata import (
    TOP_LEVEL_ROLE_NAMES,
    DelegatedRole,
    Delegations,
    MetaFile,
    Metadata,
    Root,
    Snapshot,
    TargetFile,
    Targets,
    Timestamp,
)
from tuf.api.serialization.json import JSONSerializer
from tuf.ngclient.remediation import (
    APPROVED,
    INSTALL,
    PENDING,
    ROLLBACK,
    CompatibilityTable,
    Device,
    RemediationError,
    RemediationPlanner,
    VerifiedTargetView,
)

_EXPIRES = datetime.now(UTC) + timedelta(days=3650)


@dataclass
class _BuiltView:
    metadata: dict[str, bytes]
    signers: dict[str, Signer]


def _target(path: str, custom: dict[str, Any] | None = None) -> TargetFile:
    target = TargetFile.from_data(
        path, b"firmware:" + path.encode(), ["sha256"]
    )
    if custom is not None:
        target.unrecognized_fields["custom"] = custom
    return target


def _build_view(
    *,
    top_targets: dict[str, dict[str, Any]] | None = None,
    delegated_targets: dict[str, dict[str, Any]] | None = None,
    snapshot_version: int = 1,
    role_version: int = 1,
    top_version: int = 1,
    delegate: bool = True,
    delegation_paths: list[str] | None = None,
    pin_delegated: bool = True,
) -> _BuiltView:
    signers: dict[str, Signer] = {
        role: CryptoSigner.generate_ed25519()
        for role in [*TOP_LEVEL_ROLE_NAMES, "firmware"]
    }

    root = Root(expires=_EXPIRES)
    for role in TOP_LEVEL_ROLE_NAMES:
        root.add_key(signers[role].public_key, role)
    root_md = Metadata(root)
    root_md.sign(signers[Root.type])

    delegations = None
    if delegated_targets is not None and delegate:
        key = signers["firmware"].public_key
        delegated_role = DelegatedRole(
            "firmware",
            [key.keyid],
            1,
            False,
            paths=delegation_paths or ["firmware/*"],
        )
        delegations = Delegations(
            {key.keyid: key}, {"firmware": delegated_role}
        )

    top = Targets(
        version=top_version,
        expires=_EXPIRES,
        targets={
            path: _target(path, custom)
            for path, custom in (top_targets or {}).items()
        },
        delegations=delegations,
    )
    top_md = Metadata(top)
    top_md.sign(signers[Targets.type])
    top_bytes = top_md.to_bytes(JSONSerializer())

    files = {
        Root.type: root_md.to_bytes(JSONSerializer()),
        Targets.type: top_bytes,
    }
    snapshot_meta = {
        f"{Targets.type}.json": MetaFile.from_data(
            top_version, top_bytes, ["sha256"]
        )
    }

    if delegated_targets is not None:
        delegated = Targets(
            version=role_version,
            expires=_EXPIRES,
            targets={
                path: _target(path, custom)
                for path, custom in delegated_targets.items()
            },
        )
        role_md = Metadata(delegated)
        role_md.sign(signers["firmware"])
        role_bytes = role_md.to_bytes(JSONSerializer())
        files["firmware"] = role_bytes
        if pin_delegated:
            snapshot_meta["firmware.json"] = MetaFile.from_data(
                role_version, role_bytes, ["sha256"]
            )
        else:
            snapshot_meta["firmware.json"] = MetaFile(role_version)

    snapshot = Snapshot(
        version=snapshot_version, expires=_EXPIRES, meta=snapshot_meta
    )
    snapshot_md = Metadata(snapshot)
    snapshot_md.sign(signers[Snapshot.type])
    snapshot_bytes = snapshot_md.to_bytes(JSONSerializer())
    files[Snapshot.type] = snapshot_bytes

    timestamp = Timestamp(
        expires=_EXPIRES,
        snapshot_meta=MetaFile.from_data(
            snapshot_version, snapshot_bytes, ["sha256"]
        ),
    )
    timestamp_md = Metadata(timestamp)
    timestamp_md.sign(signers[Timestamp.type])
    files[Timestamp.type] = timestamp_md.to_bytes(JSONSerializer())

    return _BuiltView(files, signers)


def _compatibility(
    *, spare_rules: dict[str, dict[str, Any]], allow_pending: bool = True
) -> CompatibilityTable:
    return CompatibilityTable.from_dict(
        {
            "schema_version": 1,
            "allow_pending": allow_pending,
            "device_groups": {
                "monitoring": {
                    "firmware/common-1.0.0.bin": {
                        "from": ["1.0.0"],
                        "uses": ["install", "rollback"],
                    },
                    "firmware/monitor-1.1.0.bin": {
                        "from": ["1.0.0"],
                        "uses": ["install"],
                    },
                },
                "spare": spare_rules,
            },
        }
    )


def _firmware_views() -> tuple[VerifiedTargetView, VerifiedTargetView]:
    archive = _build_view(
        top_targets={
            "firmware/common-1.0.0.bin": {
                "version": "1.0.0",
                "uses": ["install", "rollback"],
                "withdrawn": True,
            }
        },
        delegated_targets={
            "firmware/spare-0.9.0.bin": {
                "version": "0.9.0",
                "uses": ["rollback"],
                "review_status": PENDING,
            }
        },
        snapshot_version=4,
        role_version=2,
    )
    current = _build_view(
        top_targets={
            "firmware/monitor-1.1.0.bin": {
                "version": "1.1.0",
                "uses": ["install"],
            }
        },
        snapshot_version=9,
        role_version=3,
    )
    return (
        VerifiedTargetView.load("archive", archive.metadata, kind="archive"),
        VerifiedTargetView.load("current", current.metadata),
    )


def _spare_rules() -> dict[str, dict[str, Any]]:
    return {
        "firmware/common-1.0.0.bin": {
            "from": ["1.0.0"],
            "uses": ["rollback"],
        },
        "firmware/spare-0.9.0.bin": {
            "from": ["1.0.0"],
            "uses": ["rollback"],
            "review_status": PENDING,
        },
    }


def test_same_installed_version_gets_group_specific_routes() -> None:
    archive, current = _firmware_views()
    planner = RemediationPlanner(
        [current, archive],
        _compatibility(spare_rules=_spare_rules()),
    )

    plan = planner.plan(
        [
            Device("mon-01", "monitoring", "1.0.0"),
            Device("spare-01", "spare", "1.0.0"),
        ]
    )

    monitoring, spare = plan.plans
    assert monitoring.recommended is not None
    assert monitoring.recommended.use == INSTALL
    assert monitoring.recommended.source.path == "firmware/monitor-1.1.0.bin"
    assert monitoring.recommended.review_status == APPROVED
    assert monitoring.recommended.controlled is False
    assert any("withdrawn target" in note for note in monitoring.notes)

    assert spare.recommended is not None
    assert spare.recommended.use == ROLLBACK
    assert spare.recommended.source.path == "firmware/spare-0.9.0.bin"
    assert spare.recommended.source.view == "archive"
    assert spare.recommended.source.snapshot_version == 4
    assert spare.recommended.review_status == PENDING
    assert spare.recommended.controlled is True
    assert spare.recommended.requires_approval is True

    rendered = plan.render()
    assert "firmware/common-1.0.0.bin" in rendered
    assert "monitoring/mon-01" in rendered
    assert "INSTALL" in rendered
    assert "spare/spare-01" in rendered
    assert "ROLLBACK" in rendered
    assert "pending-review" in rendered


def test_pending_material_can_be_disabled() -> None:
    archive, current = _firmware_views()
    planner = RemediationPlanner(
        [current, archive],
        _compatibility(spare_rules=_spare_rules(), allow_pending=False),
    )

    plan = planner.plan([Device("spare-01", "spare", "1.0.0")])
    device_plan = plan.plans[0]

    assert device_plan.available == ()
    assert any("pending-review" in note for note in device_plan.notes)


def test_signed_target_uses_cannot_be_widened_by_compatibility_table() -> None:
    view = _build_view(
        top_targets={
            "firmware/monitor-1.1.0.bin": {
                "version": "1.1.0",
                "uses": ["rollback"],
            }
        }
    )
    verified = VerifiedTargetView.load("current", view.metadata)
    table = CompatibilityTable.from_dict(
        {
            "device_groups": {
                "monitoring": {
                    "firmware/monitor-1.1.0.bin": {
                        "from": ["1.0.0"],
                        "uses": ["install", "rollback"],
                    }
                }
            }
        }
    )

    plan = RemediationPlanner([verified], table).plan(
        [Device("mon-01", "monitoring", "1.0.0")]
    )

    assert plan.plans[0].available == ()


def test_withdrawn_target_is_not_installable() -> None:
    view = _build_view(
        top_targets={
            "firmware/old-2.0.0.bin": {
                "version": "2.0.0",
                "uses": ["install"],
                "withdrawn": True,
            }
        }
    )
    verified = VerifiedTargetView.load("archive", view.metadata, kind="archive")
    table = CompatibilityTable.from_dict(
        {
            "device_groups": {
                "monitoring": {
                    "firmware/old-2.0.0.bin": {
                        "from": ["1.0.0"],
                        "uses": ["install"],
                    }
                }
            }
        }
    )

    plan = RemediationPlanner([verified], table).plan(
        [Device("mon-01", "monitoring", "1.0.0")]
    )

    assert plan.plans[0].available == ()
    assert plan.withdrawn_targets == ("firmware/old-2.0.0.bin",)


def test_old_snapshot_rejects_new_delegated_metadata() -> None:
    built = _build_view(
        delegated_targets={
            "firmware/spare-0.9.0.bin": {
                "version": "0.9.0",
                "uses": ["rollback"],
            }
        }
    )
    role_md = Metadata[Targets].from_bytes(built.metadata["firmware"])
    role_md.signed.version = 2
    role_md.signed.targets["firmware/new.bin"] = _target(
        "firmware/new.bin", {"version": "2.0.0", "uses": ["install"]}
    )
    role_md.signatures.clear()
    role_md.sign(built.signers["firmware"])
    built.metadata["firmware"] = role_md.to_bytes(JSONSerializer())

    with pytest.raises(exceptions.RepositoryError):
        VerifiedTargetView.load("archive", built.metadata, kind="archive")


def test_new_snapshot_rejects_old_delegated_metadata() -> None:
    built = _build_view(
        delegated_targets={
            "firmware/spare-2.0.0.bin": {
                "version": "2.0.0",
                "uses": ["install"],
            }
        },
        role_version=2,
        snapshot_version=2,
    )
    role_md = Metadata[Targets].from_bytes(built.metadata["firmware"])
    role_md.signed.version = 1
    role_md.signed.targets["firmware/spare-1.0.0.bin"] = _target(
        "firmware/spare-1.0.0.bin", {"version": "1.0.0", "uses": ["install"]}
    )
    role_md.signatures.clear()
    role_md.sign(built.signers["firmware"])
    built.metadata["firmware"] = role_md.to_bytes(JSONSerializer())

    with pytest.raises(exceptions.RepositoryError):
        VerifiedTargetView.load("current", built.metadata)


def test_unpinned_delegated_metadata_is_rejected() -> None:
    built = _build_view(
        delegated_targets={
            "firmware/spare-0.9.0.bin": {
                "version": "0.9.0",
                "uses": ["rollback"],
            }
        },
        pin_delegated=False,
    )

    with pytest.raises(RemediationError, match="does not pin hashes"):
        VerifiedTargetView.load("archive", built.metadata, kind="archive")


def test_unreachable_delegated_role_is_ignored() -> None:
    built = _build_view(
        delegated_targets={
            "firmware/spare-0.9.0.bin": {
                "version": "0.9.0",
                "uses": ["rollback"],
            }
        },
        delegate=False,
    )
    view = VerifiedTargetView.load("archive", built.metadata, kind="archive")

    assert all(
        source.path != "firmware/spare-0.9.0.bin" for source in view.targets
    )


def test_delegated_target_outside_delegated_path_is_ignored() -> None:
    built = _build_view(
        delegated_targets={
            "firmware/other/spare-0.9.0.bin": {
                "version": "0.9.0",
                "uses": ["rollback"],
            }
        },
        delegation_paths=["firmware/spare/*"],
    )
    view = VerifiedTargetView.load("archive", built.metadata, kind="archive")

    assert all(
        source.path != "firmware/other/spare-0.9.0.bin"
        for source in view.targets
    )


def test_empty_plan_renders_header() -> None:
    archive, current = _firmware_views()
    planner = RemediationPlanner(
        [current, archive], _compatibility(spare_rules=_spare_rules())
    )

    plan = planner.plan([])

    assert "group/device" in plan.render()
    assert plan.to_dict()["devices"] == []


def test_expired_view_is_rejected_unless_explicitly_allowed() -> None:
    built = _build_view(
        top_targets={
            "firmware/monitor-1.1.0.bin": {
                "version": "1.1.0",
                "uses": ["install"],
            }
        }
    )
    later = datetime.now(UTC) + timedelta(days=365 * 20)

    with pytest.raises(exceptions.ExpiredMetadataError):
        VerifiedTargetView.load(
            "current", built.metadata, reference_time=later
        )

    view = VerifiedTargetView.load(
        "archive", built.metadata, kind="archive", allow_expired=True
    )
    assert view.stale is True


def test_unknown_device_group_has_explicit_note() -> None:
    archive, current = _firmware_views()
    planner = RemediationPlanner(
        [current, archive],
        CompatibilityTable.from_dict(
            {
                "device_groups": {
                    "monitoring": {
                        "firmware/monitor-1.1.0.bin": {
                            "from": ["1.0.0"],
                            "uses": ["install"],
                        }
                    }
                }
            }
        ),
    )

    plan = planner.plan([Device("lab-01", "lab", "1.0.0")])

    assert plan.plans[0].available == ()
    assert "no compatibility rules" in plan.plans[0].notes[0]
