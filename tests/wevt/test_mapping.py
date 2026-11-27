from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING

import pytest

from dissect.eventlog.wevt import (
    EventDefinition,
    EventDefinitionCatalog,
    EventField,
    EventIdentity,
    EventLocalizer,
    FallbackReason,
    FieldIdentity,
    LookupPolicy,
    OfflineResourceCatalog,
    ResourceKind,
    ResourceRecord,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

PROVIDER_ID = "7b9a43c1-0f6a-4a5d-9e8b-1c2d3e4f5a6b"
V1_DEFINITION = "aaaaaaaa-1111-5111-8111-aaaaaaaaaaaa"
V2_DEFINITION = "bbbbbbbb-2222-5222-8222-bbbbbbbbbbbb"


def make_definition(version: int, definition_id: str, paths: tuple[str, ...]) -> EventDefinition:
    event = EventIdentity(PROVIDER_ID, 100, version, definition_id)
    return EventDefinition(event, tuple(EventField(FieldIdentity(event, path)) for path in paths))


def make_resource(path: Path, version: str, fields: list[dict[str, object]], *, signed: bool = True) -> ResourceRecord:
    path.write_text(
        json.dumps(
            {
                "provider_id": PROVIDER_ID,
                "version": version,
                "locale": "zh-CN",
                "fields": fields,
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    return ResourceRecord(
        path,
        ResourceKind.MESSAGES,
        PROVIDER_ID,
        version,
        "zh-CN",
        hashlib.sha256(path.read_bytes()).hexdigest(),
        signed=signed,
    )


def test_missing_exact_pack_uses_signed_neighbor_version(tmp_path: Path) -> None:
    untrusted = make_resource(
        tmp_path / "zh-CN-1.0.0.json",
        "1.0.0",
        [
            {
                "event_id": 100,
                "event_version": 1,
                "definition_id": V1_DEFINITION,
                "path": "EventData.ServiceName",
                "label": "未签收译文",
            }
        ],
        signed=False,
    )
    signed = make_resource(
        tmp_path / "zh-CN-0.9.0.json",
        "0.9.0",
        [
            {
                "event_id": 100,
                "event_version": 1,
                "definition_id": V1_DEFINITION,
                "path": "EventData.ServiceName",
                "label": "服务名",
            },
            {
                "event_id": 100,
                "event_version": 1,
                "definition_id": V1_DEFINITION,
                "path": "EventData.DisplayName",
                "label": "服务名",
            },
        ],
    )
    catalog = OfflineResourceCatalog((untrusted, signed))
    localizer = EventLocalizer(catalog)
    definition = make_definition(
        1,
        V1_DEFINITION,
        ("EventData.ServiceName", "EventData.DisplayName", "EventData.PID"),
    )
    values = {
        "EventData.ServiceName": "Spooler",
        "EventData.DisplayName": "Print Spooler",
        "EventData.PID": 42,
    }

    result = localizer.map_event(
        definition,
        values,
        version="1.0.0",
        locale="zh-CN",
        policy=LookupPolicy(version_fallbacks=("0.9.0",)),
    )

    assert result.values_by_path == values
    assert result.labels["EventData.ServiceName"] == "服务名"
    assert result.labels["EventData.DisplayName"] == "服务名"
    assert result.labels["EventData.PID"] == "EventData.PID"
    assert result.fields[0].source is not None
    assert result.fields[0].source.path == signed.path
    assert result.fields[0].source.signed is True
    assert result.fields[0].fallback_reasons == (FallbackReason.VERSION_FALLBACK,)
    assert [attempt.reason for attempt in result.fields[0].attempts] == [
        FallbackReason.UNSIGNED_SOURCE,
        FallbackReason.VERSION_FALLBACK,
    ]
    assert result.fields[2].translated is False
    assert result.fields[2].fallback_reasons == (FallbackReason.UNTRANSLATED,)


def test_field_identity_binds_version_and_definition(tmp_path: Path) -> None:
    signed = make_resource(
        tmp_path / "zh-CN-0.9.0.json",
        "0.9.0",
        [
            {
                "event_id": 100,
                "event_version": 1,
                "definition_id": V1_DEFINITION,
                "path": "EventData.ServiceName",
                "label": "服务名",
            }
        ],
    )
    localizer = EventLocalizer(OfflineResourceCatalog((signed,)))
    policy = LookupPolicy(version_fallbacks=("0.9.0",))
    v2 = make_definition(2, V2_DEFINITION, ("EventData.ServiceName",))

    result = localizer.map_event(
        v2,
        {"EventData.ServiceName": "Spooler"},
        version="1.0.0",
        locale="zh-CN",
        policy=policy,
    )

    assert result.labels == {"EventData.ServiceName": "EventData.ServiceName"}
    assert result.fields[0].attempts[-1].reason == FallbackReason.FIELD_NOT_FOUND


def test_labels_cannot_be_used_as_field_paths(tmp_path: Path) -> None:
    signed = make_resource(
        tmp_path / "zh-CN-1.0.0.json",
        "1.0.0",
        [
            {
                "event_id": 100,
                "event_version": 1,
                "definition_id": V1_DEFINITION,
                "path": "EventData.ServiceName",
                "label": "PID",
            }
        ],
    )
    localizer = EventLocalizer(OfflineResourceCatalog((signed,)))
    definition = make_definition(1, V1_DEFINITION, ("EventData.ServiceName", "EventData.PID"))

    with pytest.raises(KeyError, match="translated labels cannot be used as paths"):
        localizer.map_event(definition, {"PID": 42}, version="1.0.0", locale="zh-CN")


def test_wevt_event_definitions_keep_template_identities(get_absolute_path: Callable[[str], Path]) -> None:
    catalog = EventDefinitionCatalog.from_wevt_file(get_absolute_path("_data/mpengine_etw.wevt"))

    version_1 = catalog.lookup_one("0a002690-3839-4e3a-b3b6-96d8df868d99", 1, 1)
    version_2 = catalog.lookup_one("0a002690-3839-4e3a-b3b6-96d8df868d99", 1, 2)

    assert version_1.event.definition_id != version_2.event.definition_id
    assert version_1.fields_by_path["EventData.Id"].identity.version == 1
    assert version_2.fields_by_path["EventData.Id"].identity.definition_id == version_2.event.definition_id


def test_event_definitions_require_an_accepted_wevt_source(
    tmp_path: Path,
    get_absolute_path: Callable[[str], Path],
) -> None:
    resource = get_absolute_path("_data/services.wevt")
    record = ResourceRecord(
        resource,
        ResourceKind.WEVT,
        "0063715b-eeda-4007-9429-ad526f62696e",
        "1.0.0",
        sha256=hashlib.sha256(resource.read_bytes()).hexdigest(),
    )
    lookup = OfflineResourceCatalog((record,)).lookup_wevt(record.provider_id, "1.0.0")

    catalog = EventDefinitionCatalog.from_resource_lookup(lookup)
    definition = catalog.lookup_one(record.provider_id, 101, 0)

    assert definition.source is not None
    assert definition.source.path == resource

    with pytest.raises(FileNotFoundError):
        EventDefinitionCatalog.from_resource_lookup(OfflineResourceCatalog(()).lookup_wevt(record.provider_id))
