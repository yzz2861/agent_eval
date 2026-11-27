from __future__ import annotations

import json
from pathlib import Path

from dissect.eventlog.wevt import (
    EventDefinition,
    EventField,
    EventIdentity,
    EventLocalizer,
    FieldIdentity,
    LookupPolicy,
    OfflineResourceCatalog,
)

DATA = Path(__file__).parent / "offline_wevt"
PROVIDER_ID = "7b9a43c1-0f6a-4a5d-9e8b-1c2d3e4f5a6b"
V1_DEFINITION = "aaaaaaaa-1111-5111-8111-aaaaaaaaaaaa"
V2_DEFINITION = "bbbbbbbb-2222-5222-8222-bbbbbbbbbbbb"


def definition(event_version: int, definition_id: str, paths: tuple[str, ...]) -> EventDefinition:
    event = EventIdentity(PROVIDER_ID, 100, event_version, definition_id)
    return EventDefinition(event, tuple(EventField(FieldIdentity(event, path)) for path in paths))


def main() -> None:
    catalog = OfflineResourceCatalog.from_manifest(DATA / "manifest.json")
    localizer = EventLocalizer(catalog)
    policy = LookupPolicy(version_fallbacks=("0.9.0",))

    v1 = definition(
        1,
        V1_DEFINITION,
        ("EventData.ServiceName", "EventData.DisplayName", "EventData.PID"),
    )
    v1_values = {
        "EventData.ServiceName": "Spooler",
        "EventData.DisplayName": "Print Spooler",
        "EventData.PID": 4242,
    }
    v1_map = localizer.map_event(v1, v1_values, version="1.0.0", locale="zh-CN", policy=policy)

    v2 = definition(2, V2_DEFINITION, ("EventData.ServiceName",))
    v2_map = localizer.map_event(
        v2,
        {"EventData.ServiceName": "Spooler"},
        version="1.0.0",
        locale="zh-CN",
        policy=policy,
    )

    print("event v1: exact zh-CN 1.0.0 copy is unsigned, signed zh-CN 0.9.0 is used")
    print(f"{'actual field path':28} {'label':18} {'translated':10} source / fallback")
    for field in v1_map.fields:
        source = f"{field.source.locale}@{field.source.version}" if field.source else "-"
        reasons = ",".join(reason.value for reason in field.fallback_reasons) or "-"
        print(f"{field.path:28} {field.label:18} {field.translated!s:10} {source} / {reasons}")

    print("\nevent v1 lookup trail:")
    print(json.dumps(v1_map.fields[0].as_dict(), ensure_ascii=False, indent=2))

    print("\nevent v2 has the same path and label text, but a different version/definition:")
    for field in v2_map.fields:
        print(
            f"{field.path} -> {field.label} (translated={field.translated}, "
            f"reasons={','.join(reason.value for reason in field.fallback_reasons)})"
        )

    assert v1_map.values_by_path == v1_values
    assert v1_map.labels["EventData.ServiceName"] == v1_map.labels["EventData.DisplayName"] == "服务名"
    assert v1_map.labels["EventData.PID"] == "EventData.PID"
    assert v2_map.labels["EventData.ServiceName"] == "EventData.ServiceName"


if __name__ == "__main__":
    main()
