from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING

from dissect.eventlog.wevt import (
    FallbackReason,
    LookupPolicy,
    OfflineResourceCatalog,
    ResourceKind,
    ResourceManifest,
    ResourceRecord,
)

if TYPE_CHECKING:
    from pathlib import Path

PROVIDER_ID = "7b9a43c1-0f6a-4a5d-9e8b-1c2d3e4f5a6b"


def test_manifest_only_accepts_signed_copy(tmp_path: Path) -> None:
    unsigned = tmp_path / "a-unsigned.wevt"
    signed = tmp_path / "z-signed.wevt"
    unsigned.write_bytes(b"unsigned WEVT")
    signed.write_bytes(b"signed WEVT")

    catalog = OfflineResourceCatalog(
        (
            ResourceRecord(unsigned, ResourceKind.WEVT, PROVIDER_ID, "1.0.0", sha256=None, signed=False),
            ResourceRecord(
                signed,
                ResourceKind.WEVT,
                PROVIDER_ID,
                "1.0.0",
                sha256=hashlib.sha256(signed.read_bytes()).hexdigest(),
            ),
        )
    )
    result = catalog.lookup_wevt(PROVIDER_ID, "1.0.0")

    assert result.source is not None
    assert result.source.path == signed
    assert result.source.signed is True
    assert result.source.digest == hashlib.sha256(signed.read_bytes()).hexdigest()
    assert [attempt.reason for attempt in result.attempts] == [
        FallbackReason.UNSIGNED_SOURCE,
        FallbackReason.EXACT,
    ]


def test_manifest_digest_mismatch_is_rejected(tmp_path: Path) -> None:
    resource = tmp_path / "tampered.wevt"
    resource.write_bytes(b"changed after acquisition")
    catalog = OfflineResourceCatalog(
        (ResourceRecord(resource, ResourceKind.WEVT, PROVIDER_ID, "1.0.0", sha256="0" * 64),)
    )

    result = catalog.lookup_wevt(PROVIDER_ID, "1.0.0")

    assert result.found is False
    assert result.attempts[0].reason == FallbackReason.DIGEST_MISMATCH
    assert "expected sha256" in result.attempts[0].detail


def test_lookup_falls_back_to_neighbor_version_and_records_reasons(tmp_path: Path) -> None:
    neighbor = tmp_path / "zh-CN-0.9.0.json"
    neighbor.write_text("{}", encoding="utf-8")
    catalog = OfflineResourceCatalog(
        (
            ResourceRecord(
                neighbor,
                ResourceKind.MESSAGES,
                PROVIDER_ID,
                "0.9.0",
                "zh-CN",
                sha256=hashlib.sha256(neighbor.read_bytes()).hexdigest(),
            ),
        )
    )

    result = catalog.lookup_messages(
        PROVIDER_ID,
        "1.0.0",
        "zh-CN",
        LookupPolicy(version_fallbacks=("0.9.0",)),
    )

    assert result.source is not None
    assert result.source.version == "0.9.0"
    assert result.source.locale == "zh-CN"
    assert result.fallback_reasons == (FallbackReason.VERSION_FALLBACK,)
    assert [attempt.reason for attempt in result.attempts] == [
        FallbackReason.MISSING_RESOURCE,
        FallbackReason.VERSION_FALLBACK,
    ]


def test_manifest_loading_keeps_relative_paths_local(tmp_path: Path) -> None:
    resource = tmp_path / "labels.json"
    resource.write_text('{"fields": []}', encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "resources": [
                    {
                        "path": "labels.json",
                        "kind": "messages",
                        "provider_id": PROVIDER_ID,
                        "version": "1.0.0",
                        "locale": "zh-CN",
                        "sha256": hashlib.sha256(resource.read_bytes()).hexdigest(),
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    loaded = ResourceManifest.load(manifest)

    assert loaded.resources[0].path == resource
    assert loaded.catalog.lookup_messages(PROVIDER_ID, "1.0.0", "zh-CN").found
