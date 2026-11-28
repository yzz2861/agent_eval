"""
Metadata provenance attribution.

A PDF document can carry the same archival field in two independent
metadata layers: the document information dictionary (Info) and the
XMP metadata stream. This module records *which* layer each value was
read from, validates every layer against its own rules (allowed keys,
value formats, update timestamps) and never fills a missing layer with
the other layer's value.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable

from ._utils import parse_iso8824_date
from .constants import DocumentInformationAttributes as DI
from .xmp import XmpInformation


class MissingMetadataLayerError(LookupError):
    """Raised when a value is requested from a layer that does not hold it."""


class MetadataLayer(Enum):
    """The two independent metadata layers of a PDF document."""

    INFO = "info"
    XMP = "xmp"


_INFO_ALLOWED_KEYS = {
    DI.TITLE,
    DI.AUTHOR,
    DI.SUBJECT,
    DI.KEYWORDS,
    DI.CREATOR,
    DI.PRODUCER,
    DI.CREATION_DATE,
    DI.MOD_DATE,
    DI.TRAPPED,
}


def _validate_info_text(value: Any) -> list[str]:
    if not isinstance(value, str):
        return [f"info value {value!r} is not a text string"]
    return []


def _validate_info_date(value: Any) -> list[str]:
    if not isinstance(value, str):
        return [f"info date {value!r} is not a text string"]
    try:
        parse_iso8824_date(value)
    except ValueError:
        return [f"info date {value!r} is not a valid PDF date (D:YYYYMMDDHHmmSS)"]
    return []


def _validate_xmp_text(value: Any) -> list[str]:
    if not isinstance(value, str):
        return [f"xmp value {value!r} is not a text string"]
    return []


def _validate_xmp_date(value: Any) -> list[str]:
    if not isinstance(value, datetime):
        return [f"xmp date {value!r} is not an ISO 8601 date"]
    return []


def _xmp_default_language(mapping: dict[str, str] | None) -> str | None:
    if not mapping:
        return None
    if "x-default" in mapping:
        return mapping["x-default"]
    return next(iter(mapping.values()))


@dataclass
class _FieldMapping:
    """How one canonical field is read and validated on each layer."""

    info_key: str
    info_getter: Callable[[Any], Any]
    xmp_getter: Callable[[XmpInformation], Any]
    info_validator: Callable[[Any], list[str]]
    xmp_validator: Callable[[Any], list[str]]


def _info_text_getter(key: str) -> Callable[[Any], Any]:
    def get(info: Any) -> Any:
        value = info.get(key)
        return None if value is None else str(value)

    return get


def _info_date_getter(key: str) -> Callable[[Any], Any]:
    def get(info: Any) -> Any:
        raw = info.get(key)
        if raw is None:
            return None
        try:
            return parse_iso8824_date(str(raw))
        except ValueError:
            return str(raw)

    return get


_FIELD_MAPPINGS: dict[str, _FieldMapping] = {
    "title": _FieldMapping(
        DI.TITLE,
        _info_text_getter(DI.TITLE),
        lambda xmp: _xmp_default_language(xmp.dc_title),
        _validate_info_text,
        _validate_xmp_text,
    ),
    "author": _FieldMapping(
        DI.AUTHOR,
        _info_text_getter(DI.AUTHOR),
        lambda xmp: None if not xmp.dc_creator else ", ".join(xmp.dc_creator),
        _validate_info_text,
        _validate_xmp_text,
    ),
    "subject": _FieldMapping(
        DI.SUBJECT,
        _info_text_getter(DI.SUBJECT),
        lambda xmp: _xmp_default_language(xmp.dc_description),
        _validate_info_text,
        _validate_xmp_text,
    ),
    "keywords": _FieldMapping(
        DI.KEYWORDS,
        _info_text_getter(DI.KEYWORDS),
        lambda xmp: xmp.pdf_keywords,
        _validate_info_text,
        _validate_xmp_text,
    ),
    "creator": _FieldMapping(
        DI.CREATOR,
        _info_text_getter(DI.CREATOR),
        lambda xmp: xmp.xmp_creator_tool,
        _validate_info_text,
        _validate_xmp_text,
    ),
    "producer": _FieldMapping(
        DI.PRODUCER,
        _info_text_getter(DI.PRODUCER),
        lambda xmp: xmp.pdf_producer,
        _validate_info_text,
        _validate_xmp_text,
    ),
    "creation_date": _FieldMapping(
        DI.CREATION_DATE,
        _info_date_getter(DI.CREATION_DATE),
        lambda xmp: xmp.xmp_create_date,
        _validate_info_date,
        _validate_xmp_date,
    ),
    "modification_date": _FieldMapping(
        DI.MOD_DATE,
        _info_date_getter(DI.MOD_DATE),
        lambda xmp: xmp.xmp_modify_date,
        _validate_info_date,
        _validate_xmp_date,
    ),
}


@dataclass
class LayerRecord:
    """
    One layer's own confirmation of a single field.

    A record only ever describes the layer it was read from; it is never
    completed with a value from the other layer.
    """

    layer: MetadataLayer
    value: Any
    raw_value: Any
    issues: list[str] = field(default_factory=list)
    updated_at: datetime | None = None
    copied_from: "MetadataLayer | None" = None

    @property
    def valid(self) -> bool:
        """Whether the value passed its layer's own validation."""
        return not self.issues


@dataclass
class FieldProvenance:
    """Attribution of one canonical field to the layers that confirm it."""

    field: str
    records: dict[MetadataLayer, LayerRecord] = field(default_factory=dict)

    @property
    def layers(self) -> set[MetadataLayer]:
        """Layers that actually hold a value for this field."""
        return set(self.records)

    def confirmed_by(self) -> set[MetadataLayer]:
        """
        Layers whose own record confirms this field.

        Even when both layers hold the same value, each confirmation stays
        attached to the layer it came from.
        """
        return {layer for layer, record in self.records.items() if record.valid}

    @property
    def agrees(self) -> bool | None:
        """
        Whether the layers hold the same value.

        Returns None when fewer than two layers hold the field, so a
        missing layer is never treated as agreeing by absence.
        """
        if len(self.records) < 2:
            return None
        values = [record.value for record in self.records.values()]
        return all(value == values[0] for value in values[1:])

    def value_for(self, layer: MetadataLayer) -> Any:
        """
        Value confirmed by the given layer only.

        Raises:
            MissingMetadataLayerError: if the layer does not hold this
                field. The other layer's value is never substituted.

        """
        try:
            return self.records[layer].value
        except KeyError:
            raise MissingMetadataLayerError(
                f"field {self.field!r} is not present in the {layer.value} layer; "
                "refusing to backfill it from another layer"
            ) from None


@dataclass
class CopyRecord:
    """Audit entry for an explicit, recorded copy between layers."""

    field: str
    source: MetadataLayer
    target: MetadataLayer
    value: Any
    copied_at: datetime


class MetadataProvenance:
    """
    Per-layer attribution of a document's metadata.

    Built with from_reader(). Reading is strictly non-destructive:
    no value is ever copied between layers implicitly. Copies only happen
    through copy_value(), which leaves an audit trail.
    """

    def __init__(self) -> None:
        self.fields: dict[str, FieldProvenance] = {}
        self.layer_issues: dict[MetadataLayer, list[str]] = {
            MetadataLayer.INFO: [],
            MetadataLayer.XMP: [],
        }
        self.layer_updated_at: dict[MetadataLayer, datetime | None] = {
            MetadataLayer.INFO: None,
            MetadataLayer.XMP: None,
        }
        self.copies: list[CopyRecord] = []

    @classmethod
    def from_reader(cls, reader: Any) -> "MetadataProvenance":
        """
        Collect provenance from a PdfReader.

        Args:
            reader: The reader whose info dictionary and XMP metadata
                stream are inspected independently.

        Returns:
            A provenance report keyed by canonical field name.

        """
        provenance = cls()
        info = reader.metadata
        xmp = reader.xmp_metadata
        if info is not None:
            provenance._check_info_keys(info)
            provenance.layer_updated_at[MetadataLayer.INFO] = cls._info_date(
                info, DI.MOD_DATE
            )
        if xmp is not None:
            provenance.layer_updated_at[MetadataLayer.XMP] = cls._xmp_date(
                xmp, provenance, "xmp_metadata_date"
            )
        for name, mapping in _FIELD_MAPPINGS.items():
            field_provenance = FieldProvenance(field=name)
            if info is not None:
                provenance._read_info_field(field_provenance, info, mapping)
            if xmp is not None:
                provenance._read_xmp_field(field_provenance, xmp, mapping)
            if field_provenance.records:
                provenance.fields[name] = field_provenance
        return provenance

    @staticmethod
    def _info_date(info: Any, key: str) -> datetime | None:
        raw = info.get(key)
        if raw is None:
            return None
        try:
            return parse_iso8824_date(str(raw))
        except ValueError:
            return None

    @staticmethod
    def _xmp_date(
        xmp: XmpInformation, provenance: "MetadataProvenance", attribute: str
    ) -> datetime | None:
        try:
            return getattr(xmp, attribute)
        except Exception as exc:
            provenance.layer_issues[MetadataLayer.XMP].append(
                f"xmp {attribute} could not be parsed: {exc}"
            )
            return None

    def _check_info_keys(self, info: Any) -> None:
        for key in info:
            if key not in _INFO_ALLOWED_KEYS:
                self.layer_issues[MetadataLayer.INFO].append(
                    f"info key {key} is outside the allowed range of the "
                    "document information dictionary"
                )

    def _read_info_field(
        self, field_provenance: FieldProvenance, info: Any, mapping: _FieldMapping
    ) -> None:
        raw = info.get(mapping.info_key)
        if raw is None:
            return
        value = mapping.info_getter(info)
        field_provenance.records[MetadataLayer.INFO] = LayerRecord(
            layer=MetadataLayer.INFO,
            value=value,
            raw_value=str(raw),
            issues=mapping.info_validator(str(raw)),
            updated_at=self.layer_updated_at[MetadataLayer.INFO],
        )

    def _read_xmp_field(
        self,
        field_provenance: FieldProvenance,
        xmp: XmpInformation,
        mapping: _FieldMapping,
    ) -> None:
        try:
            value = mapping.xmp_getter(xmp)
        except Exception as exc:
            self.layer_issues[MetadataLayer.XMP].append(
                f"xmp value for {field_provenance.field!r} could not be parsed: {exc}"
            )
            return
        if value is None:
            return
        field_provenance.records[MetadataLayer.XMP] = LayerRecord(
            layer=MetadataLayer.XMP,
            value=value,
            raw_value=value,
            issues=mapping.xmp_validator(value),
            updated_at=self.layer_updated_at[MetadataLayer.XMP],
        )

    def value_for(self, field_name: str, layer: MetadataLayer) -> Any:
        """
        Value of a field as confirmed by the given layer only.

        Raises:
            MissingMetadataLayerError: if the layer does not hold the
                field. The other layer's value is never substituted.

        """
        field_provenance = self.fields.get(field_name)
        if field_provenance is None:
            raise MissingMetadataLayerError(
                f"field {field_name!r} is not present in any metadata layer"
            )
        return field_provenance.value_for(layer)

    def disagreements(self) -> list[str]:
        """Fields confirmed by both layers with differing values."""
        return [
            name
            for name, field_provenance in self.fields.items()
            if field_provenance.agrees is False
        ]

    def copy_value(
        self,
        field_name: str,
        source: MetadataLayer,
        target: MetadataLayer,
        *,
        copied_at: datetime | None = None,
    ) -> CopyRecord:
        """
        Explicitly copy a field's value from one layer to the other.

        This is the only way a value may move between layers; the copy is
        recorded in the copies audit list and the target record is marked
        with copied_from so later audits can distinguish a recorded copy
        from two independent confirmations.

        Raises:
            MissingMetadataLayerError: if the source layer does not hold
                the field.

        """
        value = self.value_for(field_name, source)  # raises if absent
        record = CopyRecord(
            field=field_name,
            source=source,
            target=target,
            value=value,
            copied_at=copied_at or datetime.now(),
        )
        self.copies.append(record)
        source_record = self.fields[field_name].records[source]
        self.fields[field_name].records[target] = LayerRecord(
            layer=target,
            value=value,
            raw_value=source_record.raw_value,
            updated_at=source_record.updated_at,
            copied_from=source,
        )
        return record

    def report(self) -> str:
        """Human-readable summary of which layer confirmed each field."""
        lines = []
        for name, field_provenance in self.fields.items():
            parts = []
            for layer in MetadataLayer:
                record = field_provenance.records.get(layer)
                if record is None:
                    parts.append(f"{layer.value}: -")
                    continue
                note = ""
                if record.copied_from is not None:
                    note = f" (recorded copy from {record.copied_from.value})"
                elif record.issues:
                    note = f" (invalid: {'; '.join(record.issues)})"
                parts.append(f"{layer.value}: {record.value!r}{note}")
            lines.append(f"{name}: " + " | ".join(parts))
        return "\n".join(lines)

