from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from dissect.eventlog.wevt.offline import (
    FallbackReason,
    ResourceAttempt,
    ResourceKind,
    ResourceSource,
    normalize_provider_id,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from dissect.eventlog.wevt.offline import LookupPolicy, OfflineResourceCatalog, ResourceLookup, ResourceRecord
    from dissect.eventlog.wevt.wevt import WEVT


@dataclass(frozen=True, slots=True, order=True)
class EventIdentity:
    """Identity of an event definition in a specific provider version.

    The definition UUID is part of the identity so equal event ids and field paths from another
    template version can never be silently substituted.
    """

    provider_id: str
    event_id: int
    version: int
    definition_id: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider_id", normalize_provider_id(self.provider_id) or "")
        object.__setattr__(self, "event_id", int(self.event_id))
        object.__setattr__(self, "version", int(self.version))
        object.__setattr__(self, "definition_id", str(self.definition_id))


@dataclass(frozen=True, slots=True, order=True)
class FieldIdentity:
    """Identity of one event field independent of its translated label."""

    event: EventIdentity
    path: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", str(self.path))

    @property
    def provider_id(self) -> str:
        """Return the provider id."""
        return self.event.provider_id

    @property
    def event_id(self) -> int:
        """Return the event id."""
        return self.event.event_id

    @property
    def version(self) -> int:
        """Return the event version."""
        return self.event.version

    @property
    def definition_id(self) -> str:
        """Return the template/definition UUID."""
        return self.event.definition_id

    @property
    def name(self) -> str:
        """Return the final path component."""
        return self.path.rsplit(".", 1)[-1]


@dataclass(frozen=True, slots=True)
class EventField:
    """One field in a compiled event definition."""

    identity: FieldIdentity
    input_type: str | None = None
    output_type: str | None = None

    @property
    def path(self) -> str:
        """Return the stable, untranslated field path."""
        return self.identity.path


@dataclass(frozen=True, slots=True)
class EventDefinition:
    """An event definition and its fields for one event/version/definition combination."""

    event: EventIdentity
    fields: tuple[EventField, ...] = ()
    message_table_id: int | None = None
    source: ResourceSource | None = None

    @property
    def fields_by_path(self) -> dict[str, EventField]:
        """Return fields keyed only by their actual path."""
        return {field.path: field for field in self.fields}

    def field(self, path: str) -> EventField | None:
        """Return a field by exact path or final path component."""
        if path in self.fields_by_path:
            return self.fields_by_path[path]
        for field in self.fields:
            if field.identity.name == path:
                return field
        return None


class EventDefinitionCatalog:
    """Version and definition constrained event lookup."""

    def __init__(self, definitions: Iterable[EventDefinition]):
        self.definitions = tuple(definitions)
        self._by_provider: dict[tuple[str, int, int], tuple[EventDefinition, ...]] = {}
        for definition in self.definitions:
            key = (
                definition.event.provider_id,
                definition.event.event_id,
                definition.event.version,
            )
            self._by_provider[key] = (*self._by_provider.get(key, ()), definition)

    def lookup(
        self,
        provider_id: str,
        event_id: int,
        version: int,
        definition_id: str | None = None,
    ) -> tuple[EventDefinition, ...]:
        """Return definitions matching the exact provider, event id, version and optional UUID."""
        provider_id = normalize_provider_id(provider_id) or ""
        matches = self._by_provider.get((provider_id, int(event_id), int(version)), ())
        if definition_id is not None:
            matches = tuple(item for item in matches if item.event.definition_id == str(definition_id))
        return matches

    def lookup_one(
        self,
        provider_id: str,
        event_id: int,
        version: int,
        definition_id: str | None = None,
    ) -> EventDefinition:
        """Return exactly one matching definition or raise ``KeyError``."""
        matches = self.lookup(provider_id, event_id, version, definition_id)
        if len(matches) != 1:
            raise KeyError(f"expected one event definition, found {len(matches)}")
        return matches[0]

    @classmethod
    def from_wevt(cls, wevt: WEVT, source: ResourceSource | None = None) -> EventDefinitionCatalog:
        """Build definitions from a parsed WEVT provider.

        The TEMP UUID is the definition key; ``EVNT.version`` remains part of every field identity.
        Fields are named from the template descriptors, never from a language resource.
        """
        templates = {}
        events = []
        for wevt_type in wevt:
            if wevt_type.signature == "TTBL":
                for template in wevt_type:
                    templates[template.offset] = template
            elif wevt_type.signature == "EVNT":
                events.extend(wevt_type)

        provider_id = str(wevt.provider_id)
        definitions = []
        for event in events:
            template = templates.get(event.template_offset)
            definition_id = str(template.identifier) if template is not None else f"template@{event.template_offset}"
            event_identity = EventIdentity(provider_id, event.id, event.version, definition_id)
            fields = []
            if template is not None:
                descriptors = template.names or ()
                for descriptor in descriptors:
                    path = f"EventData.{descriptor.name}"
                    fields.append(
                        EventField(
                            FieldIdentity(event_identity, path),
                            input_type=descriptor.inType,
                            output_type=descriptor.outType,
                        )
                    )

            definitions.append(
                EventDefinition(
                    event=event_identity,
                    fields=tuple(fields),
                    message_table_id=event.message_table_id,
                    source=source,
                )
            )

        return cls(definitions)

    @classmethod
    def from_wevt_file(
        cls,
        path: str | Path,
        *,
        provider_id: str | None = None,
        source: ResourceSource | None = None,
    ) -> EventDefinitionCatalog:
        """Build definitions from a WEVT file that is already known to be trusted."""
        from dissect.eventlog.wevt.wevt import CRIM

        with Path(path).open("rb") as fh:
            crim = CRIM(fh)
            definitions = []
            for provider in crim.wevt_headers():
                if provider_id is not None and normalize_provider_id(provider_id) != str(provider.provider_id):
                    continue
                definitions.extend(cls.from_wevt(provider, source).definitions)
        return cls(definitions)

    @classmethod
    def from_resource_lookup(
        cls,
        lookup: ResourceLookup,
        *,
        provider_id: str | None = None,
    ) -> EventDefinitionCatalog:
        """Build definitions only from the accepted source of a constrained WEVT lookup."""
        if lookup.kind != ResourceKind.WEVT or lookup.source is None:
            raise FileNotFoundError("WEVT lookup did not resolve to a signed offline resource")
        return cls.from_wevt_file(lookup.source.path, provider_id=provider_id, source=lookup.source)


@dataclass(frozen=True, slots=True)
class FieldTranslation:
    """Translation result for one field, with source and every attempted candidate."""

    field: FieldIdentity
    label: str
    translated: bool
    source: ResourceSource | None = None
    attempts: tuple[ResourceAttempt, ...] = ()
    fallback_reasons: tuple[FallbackReason, ...] = ()

    @property
    def path(self) -> str:
        """Return the unchanged actual field path."""
        return self.field.path

    def as_dict(self) -> dict[str, Any]:
        """Return a serialisable translation record for review."""
        return {
            "path": self.path,
            "label": self.label,
            "translated": self.translated,
            "field_identity": {
                "provider_id": self.field.provider_id,
                "event_id": self.field.event_id,
                "event_version": self.field.version,
                "definition_id": self.field.definition_id,
                "path": self.field.path,
            },
            "source": self.source.as_dict() if self.source else None,
            "fallback_reasons": [reason.value for reason in self.fallback_reasons],
            "attempts": [attempt.as_dict() for attempt in self.attempts],
        }


@dataclass(frozen=True)
class LocalizedEventMap:
    """An event mapped by actual field path, with translated labels kept separate."""

    definition: EventDefinition
    values: Mapping[str, Any]
    fields: tuple[FieldTranslation, ...]

    @property
    def labels(self) -> dict[str, str]:
        """Return labels keyed by actual path, never by label text."""
        return {field.path: field.label for field in self.fields}

    @property
    def values_by_path(self) -> dict[str, Any]:
        """Return values keyed by actual path, independent of labels."""
        return dict(self.values)

    @property
    def untranslated(self) -> tuple[FieldTranslation, ...]:
        """Return fields whose names remain unchanged."""
        return tuple(field for field in self.fields if not field.translated)

    def as_dict(self, *, include_attempts: bool = False) -> dict[str, Any]:
        """Return a serialisable event map."""
        fields = []
        for field in self.fields:
            item = field.as_dict()
            if not include_attempts:
                item.pop("attempts")
            fields.append(item)
        return {
            "event": {
                "provider_id": self.definition.event.provider_id,
                "event_id": self.definition.event.event_id,
                "event_version": self.definition.event.version,
                "definition_id": self.definition.event.definition_id,
            },
            "values": dict(self.values),
            "labels": self.labels,
            "fields": fields,
        }


@dataclass(frozen=True, slots=True)
class MessageResource:
    """A signed language resource containing field labels keyed by field identity."""

    provider_id: str
    version: str
    locale: str
    labels: Mapping[FieldIdentity, str]
    source: ResourceSource

    def label_for(self, field: FieldIdentity) -> str | None:
        """Return the label for exactly this event version and definition."""
        return self.labels.get(field)

    @classmethod
    def from_path(cls, record: ResourceRecord, source: ResourceSource) -> MessageResource:
        """Load one manifest resource from disk and validate its metadata."""
        return cls.from_dict(json.loads(Path(record.path).read_text(encoding="utf-8")), record, source)

    @classmethod
    def from_dict(
        cls,
        payload: Mapping[str, Any],
        record: ResourceRecord,
        source: ResourceSource,
    ) -> MessageResource:
        """Build a message resource from decoded JSON data."""
        provider_id = normalize_provider_id(payload.get("provider_id")) or ""
        if provider_id != record.provider_id:
            raise ValueError("language resource provider_id does not match the manifest record")
        version = str(payload.get("version", ""))
        if version.casefold() != (record.version or ""):
            raise ValueError("language resource version does not match the manifest record")
        locale = str(payload.get("locale", "")).replace("_", "-").casefold()
        if locale != (record.locale or "").replace("_", "-").casefold():
            raise ValueError("language resource locale does not match the manifest record")

        labels = {}
        for item in payload.get("fields", []):
            event = EventIdentity(
                provider_id,
                item["event_id"],
                item["event_version"],
                item["definition_id"],
            )
            field = FieldIdentity(event, item["path"])
            labels[field] = str(item["label"])

        return cls(provider_id=provider_id, version=version, locale=locale, labels=labels, source=source)


class EventLocalizer:
    """Map event values and labels without changing the actual field paths."""

    def __init__(self, catalog: OfflineResourceCatalog):
        self.catalog = catalog
        self._cache: dict[Path, MessageResource | None] = {}
        self._cache_errors: dict[Path, str] = {}

    def map_event(
        self,
        definition: EventDefinition,
        values: Mapping[str | FieldIdentity, Any] | None = None,
        *,
        version: str | int | None = None,
        locale: str | None = None,
        policy: LookupPolicy | None = None,
    ) -> LocalizedEventMap:
        """Translate labels while keeping values keyed by the compiled field path."""
        if version is None and definition.source is not None:
            version = definition.source.version
        if locale is None and definition.source is not None:
            locale = definition.source.locale

        fields_by_path = definition.fields_by_path
        normalized_values = {}
        for key, value in (values or {}).items():
            if isinstance(key, FieldIdentity):
                if key not in {field.identity for field in definition.fields}:
                    raise KeyError(f"field identity {key!r} is not part of event {definition.event!r}")
                normalized_values[key.path] = value
                continue

            if key in fields_by_path:
                normalized_values[key] = value
                continue

            raise KeyError(f"{key!r} is not a field path; translated labels cannot be used as paths")

        translations = tuple(
            self.translate_field(field.identity, version=version, locale=locale, policy=policy)
            for field in definition.fields
        )
        return LocalizedEventMap(definition, normalized_values, translations)

    def translate_field(
        self,
        field: FieldIdentity,
        *,
        version: str | int | None = None,
        locale: str | None = None,
        policy: LookupPolicy | None = None,
    ) -> FieldTranslation:
        """Try each configured resource until this exact field identity has a label."""
        attempts = []
        for step, record in self.catalog.candidates(
            ResourceKind.MESSAGES,
            field.provider_id,
            version,
            locale,
            policy,
        ):
            if record is None:
                attempts.append(
                    ResourceAttempt(
                        reason=FallbackReason.MISSING_RESOURCE,
                        accepted=False,
                        detail=f"no signed language resource for version={step.version!r} locale={step.locale!r}",
                        requested_version=step.version,
                        requested_locale=step.locale,
                    )
                )
                continue

            accepted, digest, reason, detail = self.catalog.validate(record)
            if not accepted:
                attempts.append(ResourceAttempt(reason, False, record.path, record, detail))
                continue

            source = ResourceSource(record, digest, step.reason)
            resource, error = self._load(record, source)
            if resource is None:
                attempts.append(
                    ResourceAttempt(
                        FallbackReason.UNREADABLE_RESOURCE,
                        False,
                        record.path,
                        record,
                        error or "invalid language resource",
                    )
                )
                continue

            label = resource.label_for(field)
            if label is not None:
                attempts.append(
                    ResourceAttempt(step.reason, True, record.path, record, "label found for exact field identity")
                )
                reasons = () if step.reason == FallbackReason.EXACT else (step.reason,)
                return FieldTranslation(field, label, True, source, tuple(attempts), reasons)

            attempts.append(
                ResourceAttempt(
                    FallbackReason.FIELD_NOT_FOUND,
                    False,
                    record.path,
                    record,
                    f"resource has no label for event_version={field.version} "
                    f"definition_id={field.definition_id} path={field.path}",
                )
            )

        return FieldTranslation(
            field,
            field.path,
            False,
            None,
            tuple(attempts),
            (FallbackReason.UNTRANSLATED,),
        )

    def _load(self, record: ResourceRecord, source: ResourceSource) -> tuple[MessageResource | None, str | None]:
        if record.path in self._cache:
            return self._cache[record.path], self._cache_errors.get(record.path)

        try:
            resource = MessageResource.from_path(record, source)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            self._cache[record.path] = None
            self._cache_errors[record.path] = str(exc)
            return None, str(exc)

        self._cache[record.path] = resource
        return resource, None
