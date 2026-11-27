from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock
from uuid import UUID

import pytest

from dissect.etl.etl import Event, EventRecord, FieldStatus, parse_payload
from dissect.etl.exceptions import (
    ManifestDigestNotAllowedError,
    ManifestNotFoundError,
    ManifestVersionNotFoundError,
)
from dissect.etl.manifest import compile_xml
from dissect.etl.registry import ManifestArchivePolicy, ManifestRegistry, manifest_digest

PROVIDER_GUID = UUID("{12345678-1234-1234-1234-123456789012}")

# Two deliveries of the same provider: same event number/version, different field widths
# and a renamed field.
MANIFEST_V1 = """
<instrumentationManifest xmlns="http://schemas.microsoft.com/win/2004/08/events">
 <instrumentation><events>
  <provider name="TestProvider" guid="{12345678-1234-1234-1234-123456789012}">
   <templates>
    <template tid="TestTmpl">
     <data name="FieldA" inType="win:UInt32"/>
     <data name="FieldB" inType="win:UInt16"/>
    </template>
   </templates>
   <events>
    <event value="1" symbol="Test/Event" version="1" opcode="1" level="1" task="1"
           keyword="0" template="TestTmpl"/>
   </events>
  </provider>
 </events></instrumentation>
</instrumentationManifest>
"""

MANIFEST_V2 = """
<instrumentationManifest xmlns="http://schemas.microsoft.com/win/2004/08/events">
 <instrumentation><events>
  <provider name="TestProvider" guid="{12345678-1234-1234-1234-123456789012}">
   <templates>
    <template tid="TestTmpl">
     <data name="FieldA" inType="win:UInt64"/>
     <data name="RenamedB" inType="win:UInt32"/>
    </template>
   </templates>
   <events>
    <event value="1" symbol="Test/Event" version="1" opcode="1" level="1" task="1"
           keyword="0" template="TestTmpl"/>
   </events>
  </provider>
 </events></instrumentation>
</instrumentationManifest>
"""

# A delivery that only ships descriptor version 0.
MANIFEST_OLD = MANIFEST_V1.replace('version="1"', 'version="0"')


def build_registry(*contents: str) -> tuple[ManifestRegistry, list[str]]:
    registry = ManifestRegistry()
    digests = []
    for content in contents:
        module = compile_xml(PROVIDER_GUID, content, digest=manifest_digest(content))
        digests.append(module.MANIFEST_DIGEST)
        registry.register(module)
    return registry, digests


def test_manifest_digest_distinguishes_provider_lists() -> None:
    assert manifest_digest(MANIFEST_V1) != manifest_digest(MANIFEST_V2)


def test_registry_keeps_both_deliveries() -> None:
    registry, digests = build_registry(MANIFEST_V1, MANIFEST_V2)

    assert registry.versions(PROVIDER_GUID) == (1,)
    assert registry.digests(PROVIDER_GUID) == tuple(sorted(digests))
    assert len(registry.definitions(PROVIDER_GUID)) == 2


def test_selection_requires_archive_digest_when_versions_collide() -> None:
    registry, _ = build_registry(MANIFEST_V1, MANIFEST_V2)

    with pytest.raises(ManifestDigestNotAllowedError):
        registry.select(PROVIDER_GUID, 1)


@pytest.mark.parametrize("load_order", [(MANIFEST_V1, MANIFEST_V2), (MANIFEST_V2, MANIFEST_V1)])
def test_selection_is_independent_of_load_order(load_order: tuple[str, str]) -> None:
    registry, digests = build_registry(*load_order)
    policy = ManifestArchivePolicy.from_digests([digests[0]])

    definition = registry.select(PROVIDER_GUID, 1, policy)

    assert definition.digest == digests[0]
    info = definition.describe()
    assert info["provider_id"] == str(PROVIDER_GUID)
    assert info["descriptor_version"] == 1
    assert info["digest"] == digests[0]
    assert info["provider_name"] == "TestProvider"


def test_select_picks_fields_matching_allowed_digest() -> None:
    registry, digests = build_registry(MANIFEST_V1, MANIFEST_V2)
    header = SimpleNamespace(
        version=1,
        opcode=1,
        provider_id=PROVIDER_GUID,
        payload=memoryview((1).to_bytes(8, "little") + (2).to_bytes(4, "little")),
        is_64bit=False,
    )

    old_definition = registry.select(PROVIDER_GUID, 1, ManifestArchivePolicy.from_digests([digests[0]]))
    new_definition = registry.select(PROVIDER_GUID, 1, ManifestArchivePolicy.from_digests([digests[1]]))
    old = Event(header, old_definition.module, old_definition)
    new = Event(header, new_definition.module, new_definition)

    assert set(old.complete_fields()) == {"FieldA", "FieldB"}
    assert set(new.complete_fields()) == {"FieldA", "RenamedB"}
    assert old.manifest_info()["digest"] == digests[0]
    assert new.manifest_info()["digest"] == digests[1]


def test_missing_provider_and_version() -> None:
    registry, _ = build_registry(MANIFEST_OLD)

    with pytest.raises(ManifestNotFoundError):
        registry.select(UUID("{00000000-0000-0000-0000-000000000000}"), 0)

    with pytest.raises(ManifestVersionNotFoundError):
        registry.select(PROVIDER_GUID, 1)


def test_disallowed_digest_is_reported() -> None:
    registry, _ = build_registry(MANIFEST_V1)
    policy = ManifestArchivePolicy.from_digests(["sha256:not-allowed"])

    with pytest.raises(ManifestDigestNotAllowedError):
        registry.select(PROVIDER_GUID, 1, policy)


def _fake_etl(registry: ManifestRegistry, policy: ManifestArchivePolicy | None = None) -> Mock:
    etl = Mock()
    etl.manifest_registry = registry
    etl.archive_policy = policy or ManifestArchivePolicy()
    etl.review_items = []

    def add_review_item(
        reason: str,
        provider_id: object,
        descriptor_version: int | None,
        event_size: int,
        buffer_index: int,
        buffer_offset: int,
        record_offset: int,
    ) -> None:
        etl.review_items.append(
            SimpleNamespace(
                reason=reason,
                provider_id=provider_id,
                descriptor_version=descriptor_version,
                event_size=event_size,
                buffer_index=buffer_index,
                buffer_offset=buffer_offset,
                record_offset=record_offset,
                raw_offset=buffer_offset + record_offset,
            )
        )

    etl.add_review_item.side_effect = add_review_item
    return etl


def test_parse_payload_records_raw_event_location_when_version_missing() -> None:
    registry, _ = build_registry(MANIFEST_OLD)
    etl = _fake_etl(registry)
    header = SimpleNamespace(
        version=1,
        opcode=1,
        provider_id=PROVIDER_GUID,
        payload=memoryview(b""),
        is_64bit=False,
        size=0x58,
    )
    buffer = Mock(index=3, offset=0x1000)

    event = parse_payload(header, etl, buffer, record_offset=0x40)

    assert event.manifest_info() is None
    assert len(etl.review_items) == 1
    review = etl.review_items[0]
    assert review.buffer_index == 3
    assert review.buffer_offset == 0x1000
    assert review.record_offset == 0x40
    assert review.raw_offset == 0x1040
    assert review.provider_id == PROVIDER_GUID
    assert review.descriptor_version == 1
    assert review.event_size == 0x58


def test_parse_payload_marks_incomplete_fields() -> None:
    registry, digests = build_registry(MANIFEST_V1)
    etl = _fake_etl(registry, ManifestArchivePolicy.from_digests(digests))
    header = SimpleNamespace(
        version=1,
        opcode=1,
        provider_id=PROVIDER_GUID,
        payload=memoryview((1).to_bytes(4, "little")),
        is_64bit=False,
        size=4,
    )

    event = parse_payload(header, etl, Mock(index=0, offset=0), record_offset=0)

    assert event.complete_fields() == {}
    assert event.field_status() == {"FieldA": FieldStatus.INCOMPLETE, "FieldB": FieldStatus.INCOMPLETE}
    assert event.incomplete_fields()["_unparsed_byte_ranges"] == {"payload": (0, 4)}
    assert not event.is_complete()
    assert len(etl.review_items) == 1


def test_trailing_bytes_are_separated_from_complete_fields() -> None:
    registry, digests = build_registry(MANIFEST_V1)
    policy = ManifestArchivePolicy.from_digests(digests)
    definition = registry.select(PROVIDER_GUID, 1, policy)
    header = SimpleNamespace(
        version=1,
        opcode=1,
        provider_id=PROVIDER_GUID,
        payload=memoryview((1).to_bytes(4, "little") + (2).to_bytes(2, "little") + b"\x00\x00"),
        is_64bit=False,
    )

    event = Event(header, definition.module, definition)

    assert event.is_complete() is False
    assert event.complete_fields() == {"FieldA": 1, "FieldB": 2}
    assert event.field_status()["unparsed"] is FieldStatus.INCOMPLETE
    assert event.incomplete_fields()["_unparsed_byte_ranges"] == {"unparsed": (6, 2)}


def test_event_record_carries_buffer_location_into_review_items() -> None:
    registry, _ = build_registry(MANIFEST_OLD)
    etl = _fake_etl(registry)
    header = SimpleNamespace(
        version=1,
        opcode=1,
        provider_id=PROVIDER_GUID,
        payload=memoryview(b""),
        is_64bit=False,
        size=0,
    )
    buffer = Mock(index=5, offset=0x4000, etl=etl)
    record = EventRecord()
    record._header = header
    record._buffer = buffer
    record._record_offset = 0x70

    assert record.event.manifest_info() is None

    review = etl.review_items[0]
    assert review.buffer_index == 5
    assert review.buffer_offset == 0x4000
    assert review.record_offset == 0x70
    assert review.raw_offset == 0x4070
