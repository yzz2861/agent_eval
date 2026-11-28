from __future__ import annotations

import copy
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Literal

from dissect.cstruct.exception import NonInferableError, RedactionError
from dissect.cstruct.types.structure import Structure, Union

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Sequence

MaskAction = Literal["mask", "omit", "error"]
_UNSET = object()


class Redacted:
    """Sentinel value for a field that must not be present in an external copy."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "<redacted>"

    def __bool__(self) -> bool:
        return False

    def __reduce__(self) -> tuple[type[Redacted], tuple[()]]:
        return (Redacted, ())


REDACTED = Redacted()


@dataclass(frozen=True)
class SummaryField:
    """A summary field and the fields from which it is derived.

    A summary is ``non_inferable`` when it may not be exposed in an external copy, even if it could be recomputed from
    synthetic values. Such summaries are handled according to the policy's ``on_non_inferable`` action.

    Args:
        name: Name of the summary field.
        depends_on: Fields whose values contribute to the summary.
        compute: Optional callable that receives a mapping of safe field values and returns the new summary value. It
            receives neutral values for masked fields without an explicit replacement, never their original values.
        non_inferable: Whether the summary must be removed from an external copy.
    """

    name: str
    depends_on: tuple[str, ...] = ()
    compute: Callable[[Mapping[str, Any]], Any] | None = None
    non_inferable: bool = False


@dataclass(frozen=True)
class FieldExcerpt:
    """Location and controlled contents of a field in the original excerpt."""

    name: str
    offset: int
    length: int
    visible: bool
    masked: bool
    reason: str | None = None
    excerpt: bytes | None = None

    @property
    def end(self) -> int:
        return self.offset + self.length


@dataclass
class RedactionPolicy:
    """Policy describing which fields may be shared with an external reviewer.

    Args:
        approved: Allowlist of fields that may be visible. ``None`` means every field except ``masked`` is visible.
        masked: Fields that must be masked regardless of the allowlist.
        summaries: Summary fields, keyed by field name. Dependencies may be a :class:`SummaryField`, a mapping, an
            iterable of field names (optionally followed by a compute callable), or a callable.
        replacements: Replacement values for masked fields.
        mask_value: Value used for masked fields in the value-level copy. Defaults to ``None``.
        on_unapproved: How to handle fields outside the allowlist: ``mask`` (default), ``omit`` or ``error``.
        on_non_inferable: How to handle summaries that cannot be safely derived: ``mask`` (default), ``omit`` or
            ``error``.
    """

    approved: frozenset[str] | None = None
    masked: frozenset[str] = frozenset()
    summaries: dict[str, SummaryField] = field(default_factory=dict)
    replacements: dict[str, Any] = field(default_factory=dict)
    mask_value: Any = None
    on_unapproved: MaskAction = "mask"
    on_non_inferable: MaskAction = "mask"


RedactionRequest = RedactionPolicy


class ControlledCopy(Mapping[str, Any]):
    """A read-only, value-level copy of a parsed structure that is safe for external review.

    The original read result is never modified. ``dumps()`` returns the original excerpt with only masked or recomputed
    field ranges changed, so every visible field keeps its original byte offset.

    Attributes:
        excerpts: All known fields and their locations. Masked excerpts never contain their original bytes.
        positions: Byte spans ``(offset, length)`` of visible fields, relative to the start of the excerpt.
        summary_status: Per-summary status: ``kept``, ``recomputed``, ``masked`` or ``omitted``.
        masked: Names of fields whose value is replaced by the mask value.
        omitted: Names of fields absent from the external copy.
    """

    def __init__(
        self,
        values: Mapping[str, Any],
        excerpts: Mapping[str, FieldExcerpt],
        summary_status: Mapping[str, str],
        data: bytes | None,
        masked: Iterable[str] = (),
        omitted: Iterable[str] = (),
    ) -> None:
        self._values = dict(values)
        self._excerpts = dict(excerpts)
        self._summary_status = dict(summary_status)
        self._data = data
        self.masked = frozenset(masked)
        self.omitted = frozenset(omitted)

    def __getitem__(self, key: str) -> Any:
        return self._values[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        try:
            return self._values[name]
        except KeyError:
            raise AttributeError(name) from None

    def __bytes__(self) -> bytes:
        return self.dumps()

    def __repr__(self) -> str:
        return f"<ControlledCopy {dict(self._values)!r}>"

    @property
    def values(self) -> Mapping[str, Any]:
        return MappingProxyType(self._values)

    @property
    def excerpts(self) -> Mapping[str, FieldExcerpt]:
        return MappingProxyType(self._excerpts)

    @property
    def positions(self) -> Mapping[str, tuple[int, int]]:
        return MappingProxyType(
            {name: (excerpt.offset, excerpt.length) for name, excerpt in self._excerpts.items() if excerpt.visible}
        )

    @property
    def offsets(self) -> Mapping[str, int]:
        return MappingProxyType({name: position[0] for name, position in self.positions.items()})

    @property
    def summary_status(self) -> Mapping[str, str]:
        return MappingProxyType(self._summary_status)

    @property
    def redacted(self) -> frozenset[str]:
        return self.masked | self.omitted

    def dumps(self) -> bytes:
        """Return the controlled excerpt bytes, preserving the positions of all visible fields."""
        if self._data is None:
            raise RedactionError("No byte excerpt is available for this controlled copy")
        return self._data

    def to_dict(self) -> dict[str, Any]:
        return {name: _clone(value) for name, value in self._values.items()}


MaskedCopy = ControlledCopy


def controlled_copy(
    result: Structure | Mapping[str, Any],
    *,
    approved: Iterable[str] | None = None,
    masked: Iterable[str] | None = None,
    mask: Iterable[str] | None = None,
    summaries: Mapping[str, Any] | Iterable[Any] | None = None,
    summary_fields: Mapping[str, Any] | Iterable[Any] | None = None,
    replacements: Mapping[str, Any] | None = None,
    replacement: Mapping[str, Any] | None = None,
    mask_value: Any = _UNSET,
    mask_fill: bytes = b"\x00",
    on_unapproved: MaskAction = "mask",
    on_non_inferable: MaskAction = "mask",
    policy: RedactionPolicy | None = None,
    source: bytes | bytearray | memoryview | None = None,
    base_offset: int = 0,
) -> ControlledCopy:
    """Create a controlled copy of an existing :mod:`dissect.cstruct` read result.

    Only approved fields stay visible. Masked fields are replaced by ``mask_value`` (or an explicit replacement) in the
    returned mapping. Summary fields that depend on masked fields are either recomputed from safe values or redacted
    according to ``on_non_inferable``; their original value is never carried into the copy.

    The returned :meth:`ControlledCopy.dumps` output keeps the original byte layout. Visible fields therefore retain
    their exact offsets, while masked or omitted ranges are filled with zeros or an explicit replacement. The original
    result, and any ``source`` bytes supplied by the caller, are not modified.

    Args:
        result: Parsed structure or a mapping of field names to values.
        approved: Allowlist of fields for the external copy. If omitted, all fields except ``masked`` are visible.
        masked: Fields to mask by request. An explicitly masked field is never visible, even if also approved.
        mask: Alias for ``masked``.
        summaries: Summary fields and their dependencies. See :class:`SummaryField`.
        summary_fields: Alias for ``summaries``.
        replacements: Replacement values for masked fields. Values are encoded into the same byte span in ``dumps``.
        replacement: Alias for ``replacements``.
        mask_value: Value used for masked fields in the returned mapping. Defaults to ``None``.
        mask_fill: Byte pattern used for masked ranges without a replacement.
        on_unapproved: Action for fields outside the allowlist: ``mask``, ``omit`` or ``error``.
        on_non_inferable: Action for affected summaries without a safe recomputation: ``mask``, ``omit`` or ``error``.
        policy: Optional :class:`RedactionPolicy`. Explicit keyword arguments take precedence.
        source: Optional exact bytes of the parsed excerpt. Defaults to ``result.dumps()`` for structures.
        base_offset: Added to reported excerpts so callers can express an absolute evidence offset.

    Returns:
        A read-only :class:`ControlledCopy`.
    """
    if policy is not None:
        approved = policy.approved if approved is None else approved
        masked = set(policy.masked) | _as_name_set(masked) | _as_name_set(mask)
        summaries = _merge_summaries(policy.summaries, summaries, summary_fields)
        replacements = {**policy.replacements, **_as_mapping(replacements), **_as_mapping(replacement)}
        mask_value = policy.mask_value if mask_value is _UNSET else mask_value
        on_unapproved = policy.on_unapproved
        on_non_inferable = policy.on_non_inferable
    else:
        masked = _as_name_set(masked) | _as_name_set(mask)
        summaries = _merge_summaries(None, summaries, summary_fields)
        replacements = {**_as_mapping(replacements), **_as_mapping(replacement)}
        mask_value = None if mask_value is _UNSET else mask_value

    _validate_action(on_unapproved, "on_unapproved")
    _validate_action(on_non_inferable, "on_non_inferable")

    is_structure = isinstance(result, Structure)
    if is_structure:
        field_objects = {field._name: field for field in result.__class__.__fields__}
        field_names = list(field_objects)
        spans = _field_spans(result)
        excerpt_size = len(result.dumps())
        data = bytes(result.dumps() if source is None else source)
        if len(data) != excerpt_size:
            raise RedactionError(
                f"Source excerpt has {len(data)} bytes, but the parsed structure has {excerpt_size} bytes"
            )
    elif isinstance(result, Mapping):
        field_objects = {}
        field_names = list(result)
        spans = {}
        data = bytes(source) if source is not None else None
    else:
        raise TypeError("result must be a dissect.cstruct Structure or a mapping")

    known_fields = set(field_names)
    approved_set = known_fields if approved is None else _as_name_set(approved)
    _ensure_known(approved_set, known_fields, "approved")
    _ensure_known(masked, known_fields, "masked")
    _ensure_known(set(replacements), known_fields, "replacements")

    normalized_summaries = _normalize_summaries(summaries, known_fields)

    visibility = set(approved_set) - masked
    invalid_replacements = (set(replacements) & visibility) - set(normalized_summaries)
    if invalid_replacements:
        raise ValueError(
            f"Replacements are only supported for masked fields: {', '.join(sorted(invalid_replacements))}"
        )
    redaction_reason: dict[str, str] = {}
    if approved is not None:
        for name in known_fields - visibility:
            if name not in masked:
                redaction_reason[name] = "unapproved"
    for name in masked:
        redaction_reason[name] = "requested"

    recompute: dict[str, SummaryField] = {}
    changed = True
    while changed:
        changed = False
        for name, summary in normalized_summaries.items():
            if name in redaction_reason or name in recompute or name not in visibility:
                continue

            affected = _summary_affected(summary, redaction_reason)
            if not affected:
                continue

            if summary.non_inferable:
                redaction_reason[name] = "non-inferable"
                changed = True
            elif summary.compute is not None:
                recompute[name] = summary
            else:
                redaction_reason[name] = "non-inferable"
                changed = True

    masked_names: set[str] = set()
    omitted_names: set[str] = set()
    summary_status: dict[str, str] = {}
    for name, reason in redaction_reason.items():
        action = on_unapproved if reason == "unapproved" else on_non_inferable if reason == "non-inferable" else "mask"
        if action == "error":
            raise NonInferableError(f"Field {name!r} cannot be included in the external copy ({reason})")
        if action == "omit":
            omitted_names.add(name)
        else:
            masked_names.add(name)
        if name in normalized_summaries:
            summary_status[name] = "omitted" if action == "omit" else "masked"

    for name in normalized_summaries:
        if name not in summary_status:
            summary_status[name] = "pending" if name in recompute else "kept"

    values: dict[str, Any] = {}
    compute_values: dict[str, Any] = {}
    for name in field_names:
        if name in omitted_names:
            continue
        if name in recompute:
            continue
        field_obj = field_objects.get(name)
        span = spans.get(name)
        if name in masked_names:
            values[name] = _clone(replacements[name]) if name in replacements else mask_value
            compute_values[name] = (
                _clone(replacements[name]) if name in replacements else _neutral_value(field_obj, span)
            )
        else:
            value = getattr(result, name) if is_structure else result[name]
            values[name] = _clone(value)
            compute_values[name] = _clone(value)

    def _redact_during_compute(name: str, reason: str = "non-inferable") -> None:
        recompute.pop(name, None)
        action = on_non_inferable
        if action == "error":
            raise NonInferableError(f"Summary field {name!r} cannot be safely derived")
        if action == "omit":
            omitted_names.add(name)
            values.pop(name, None)
            compute_values.pop(name, None)
            summary_status[name] = "omitted"
        else:
            masked_names.add(name)
            values[name] = mask_value
            compute_values[name] = mask_value
            summary_status[name] = "masked"

    resolved: set[str] = set()

    def _resolve_summary(name: str, stack: tuple[str, ...]) -> None:
        if name in resolved or name in redaction_reason:
            return
        if name in stack:
            _redact_during_compute(name)
            return

        summary = recompute[name]
        for dependency in summary.depends_on:
            if dependency in recompute:
                _resolve_summary(dependency, (*stack, name))
            if dependency in omitted_names:
                _redact_during_compute(name)
                return

        try:
            value = summary.compute(MappingProxyType(dict(compute_values)))
        except NonInferableError:
            _redact_during_compute(name)
            return

        if value is REDACTED:
            _redact_during_compute(name)
            return

        values[name] = _clone(value)
        compute_values[name] = _clone(value)
        summary_status[name] = "recomputed"
        resolved.add(name)

    for name in list(recompute):
        _resolve_summary(name, ())
    for name in list(recompute):
        if name not in resolved:
            _redact_during_compute(name)

    data = _build_data(
        data,
        field_objects,
        spans,
        field_names,
        replacements,
        masked_names | omitted_names,
        {name: value for name, value in values.items() if name in resolved},
        mask_fill,
    )

    excerpts: dict[str, FieldExcerpt] = {}
    for name in field_names:
        span = spans.get(name)
        if span is None:
            continue
        start, length = span
        visible = name in values and name not in masked_names and name not in omitted_names
        reason = redaction_reason.get(name)
        if name in recompute and name not in resolved:
            visible = False
        excerpts[name] = FieldExcerpt(
            name=name,
            offset=base_offset + start,
            length=length,
            visible=visible,
            masked=name in masked_names or name in omitted_names,
            reason=reason,
            excerpt=data[start : start + length] if visible and data is not None else None,
        )

    return ControlledCopy(
        values=values,
        excerpts=excerpts,
        summary_status=summary_status,
        data=data,
        masked=masked_names,
        omitted=omitted_names,
    )


def redacted_copy(
    result: Structure | Mapping[str, Any],
    **kwargs: Any,
) -> ControlledCopy:
    """Alias for :func:`controlled_copy`."""
    return controlled_copy(result, **kwargs)


def create_controlled_copy(
    result: Structure | Mapping[str, Any],
    **kwargs: Any,
) -> ControlledCopy:
    """Alias for :func:`controlled_copy`."""
    return controlled_copy(result, **kwargs)


def redact(
    result: Structure | Mapping[str, Any],
    **kwargs: Any,
) -> ControlledCopy:
    """Alias for :func:`controlled_copy`."""
    return controlled_copy(result, **kwargs)


def _as_mapping(value: Mapping[str, Any] | None) -> dict[str, Any]:
    return {} if value is None else dict(value)


def _as_name_set(value: Iterable[str] | None) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, str):
        return {value}
    return set(value)


def _as_name_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(value)


def _merge_summaries(*values: Any) -> Mapping[str, Any] | Iterable[Any] | None:
    merged: dict[str, Any] = {}
    for value in values:
        if value is None:
            continue
        if isinstance(value, Mapping):
            merged.update(value)
        else:
            for item in value:
                if isinstance(item, SummaryField):
                    merged[item.name] = item
                elif isinstance(item, tuple) and len(item) == 2:
                    merged[item[0]] = item[1]
                else:
                    merged[item] = item
    return merged or None


def _normalize_summaries(
    summaries: Mapping[str, Any] | Iterable[Any] | None,
    known_fields: set[str],
) -> dict[str, SummaryField]:
    if summaries is None:
        return {}

    items = summaries.items() if isinstance(summaries, Mapping) else ((item, item) for item in summaries)
    normalized: dict[str, SummaryField] = {}
    for key, spec in items:
        name = spec.name if isinstance(spec, SummaryField) else key
        if not isinstance(name, str):
            raise TypeError("Summary field names must be strings")
        if name not in known_fields:
            raise ValueError(f"Unknown summary field: {name!r}")

        if isinstance(spec, SummaryField):
            summary = SummaryField(name, tuple(spec.depends_on), spec.compute, spec.non_inferable)
        elif callable(spec):
            summary = SummaryField(name, (), spec)
        elif isinstance(spec, str):
            dependencies = tuple(token for token in re.split(r"[,+\s]+", spec) if token)
            summary = SummaryField(name, dependencies)
        elif isinstance(spec, Mapping):
            dependencies = _as_name_tuple(
                spec.get(
                    "depends_on",
                    spec.get(
                        "depends",
                        spec.get("deps", spec.get("fields", spec.get("sources", spec.get("source_fields", ())))),
                    ),
                )
            )
            compute = spec.get("compute", spec.get("recompute", spec.get("calculate")))
            if compute is not None and not callable(compute):
                raise TypeError(f"Summary field {name!r} has a non-callable compute value")
            non_inferable = bool(spec.get("non_inferable", spec.get("never_inferable", False)))
            if spec.get("inferable") is False:
                non_inferable = True
            summary = SummaryField(name, dependencies, compute, non_inferable)
        elif isinstance(spec, Iterable):
            parts = list(spec)
            compute = parts.pop() if parts and callable(parts[-1]) else None
            dependencies = tuple(part for part in parts if isinstance(part, str))
            summary = SummaryField(name, dependencies, compute)
        else:
            raise TypeError(f"Unsupported summary specification for {name!r}")

        unknown_dependencies = set(summary.depends_on) - known_fields
        if unknown_dependencies:
            raise ValueError(
                f"Summary field {name!r} depends on unknown fields: {', '.join(sorted(unknown_dependencies))}"
            )
        normalized[name] = summary

    return normalized


def _summary_affected(summary: SummaryField, redacted_fields: Mapping[str, str]) -> bool:
    if summary.depends_on:
        return any(dependency in redacted_fields for dependency in summary.depends_on)
    # Without explicit dependencies we cannot prove that the summary is independent of redacted data.
    return bool(redacted_fields)


def _field_spans(result: Structure) -> dict[str, tuple[int, int]]:
    fields = result.__class__.__fields__
    if isinstance(result, Union):
        union_size = len(result.dumps())
        return {field._name: (0, union_size) for field in fields}

    spans: dict[str, tuple[int, int]] = {}
    sizes = result.__sizes__
    cursor = 0
    dynamic_seen = False
    bit_group_start: int | None = None
    bit_group_size = 0
    bit_group_bits = 0

    for field_obj in fields:
        if field_obj.offset is not None:
            start = field_obj.offset
        else:
            start = cursor
            if result.__class__.__align__ and dynamic_seen:
                start += -start & (field_obj.alignment - 1)

        if field_obj.bits:
            if bit_group_start is None or start != bit_group_start:
                bit_group_start = start
                bit_group_size = _type_size(field_obj.type) or 1
                bit_group_bits = bit_group_size * 8
            spans[field_obj._name] = (bit_group_start, bit_group_size)
            bit_group_bits -= field_obj.bits
            if bit_group_bits <= 0:
                cursor = max(cursor, bit_group_start + bit_group_size)
                bit_group_start = None
            continue

        bit_group_start = None
        size = sizes.get(field_obj._name)
        if size is None:
            size = _type_size(field_obj.type)
        if size is None:
            value = getattr(result, field_obj._name, None)
            if isinstance(value, (bytes, bytearray, str, list, tuple)):
                size = len(value)
            else:
                raise RedactionError(f"Cannot determine the byte size of field {field_obj._name!r}")

        spans[field_obj._name] = (start, size)
        cursor = max(cursor, start + size)
        if field_obj.type.__dynamic__:
            dynamic_seen = True

    return spans


def _type_size(type_: Any) -> int | None:
    try:
        return len(type_)
    except TypeError:
        return None


def _neutral_value(field: Any, span: tuple[int, int] | None) -> Any:
    if field is None:
        return None
    try:
        if issubclass(field.type, int):
            return field.type(0)
    except (TypeError, ValueError):
        pass
    if span is not None:
        return b"\x00" * span[1]
    return None


def _build_data(
    data: bytes | None,
    field_objects: Mapping[str, Any],
    spans: Mapping[str, tuple[int, int]],
    field_names: Sequence[str],
    replacements: Mapping[str, Any],
    masked_names: set[str],
    recomputed_values: Mapping[str, Any],
    mask_fill: bytes,
) -> bytes | None:
    if data is None:
        return None

    buffer = bytearray(data)
    fill = bytes(mask_fill)
    if not fill:
        raise ValueError("mask_fill must contain at least one byte")

    for name in field_names:
        if name not in masked_names or name not in spans:
            continue
        start, length = spans[name]
        replacement = replacements.get(name)
        encoded = _encode_mask(field_objects.get(name), replacement, length, fill)
        buffer[start : start + length] = encoded

    for name, value in recomputed_values.items():
        if name not in spans:
            continue
        start, length = spans[name]
        encoded = _encode_value(field_objects.get(name), value, length)
        buffer[start : start + length] = encoded

    return bytes(buffer)


def _encode_mask(field: Any, replacement: Any, length: int, fill: bytes) -> bytes:
    if replacement is None:
        return (fill * (length // len(fill) + 1))[:length]
    return _fit(_encode_value(field, replacement, length), length)


def _encode_value(field: Any, value: Any, length: int) -> bytes:
    if isinstance(value, memoryview):
        value = value.tobytes()
    if isinstance(value, bytearray):
        value = bytes(value)
    if isinstance(value, bytes):
        return _fit(value, length)
    if isinstance(value, str):
        return _fit(value.encode(), length)
    if field is not None:
        return _fit(field.type.dumps(value), length)
    raise TypeError("A serializable field type is required to encode replacement values")


def _fit(value: bytes, length: int) -> bytes:
    if len(value) > length:
        raise RedactionError(f"Replacement value is {len(value)} bytes, but the original field is only {length} bytes")
    return value + b"\x00" * (length - len(value))


def _ensure_known(names: Iterable[str], known: set[str], argument: str) -> None:
    unknown = set(names) - known
    if unknown:
        raise ValueError(f"Unknown field(s) in {argument}: {', '.join(sorted(unknown))}")


def _validate_action(action: str, argument: str) -> None:
    if action not in ("mask", "omit", "error"):
        raise ValueError(f"{argument} must be 'mask', 'omit' or 'error'")


def _clone(value: Any) -> Any:
    try:
        return copy.deepcopy(value)
    except Exception:
        return value
