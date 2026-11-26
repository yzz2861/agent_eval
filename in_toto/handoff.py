"""Offline bitemporal handoff review for signed in-toto evidence.

The archive mtime/timestamp of a link is deliberately not used here. Every
entry has two independent times:

* a signed business time, read from signed evidence and corrected for the
  source clock;
* a trusted receipt time, supplied by the intake/custody log.

The module is deterministic and does not use input order as a tie-breaker.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import re
from collections.abc import Mapping
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Iterable

from dateutil.parser import parse as parse_date

try:  # attrs is a runtime dependency of in-toto models.
    import attr as attr_module
except Exception:  # pragma: no cover
    attr_module = None


VALID = "accepted"
REJECTED = "rejected"
INCONCLUSIVE = "inconclusive"
MIXED = "mixed"


class Report(dict):
    """Dictionary with attribute access used by review results."""

    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc

    def __setattr__(self, name: str, value: Any) -> None:
        self[name] = value


class MinimalWitness(list):
    """List of supplement IDs; metadata is available as attributes."""

    def __init__(self, values: Iterable[Any] = (), **metadata: Any) -> None:
        super().__init__(values)
        self.possible = metadata.pop("possible", bool(self))
        self.reason = metadata.pop("reason", None)
        self.axis = metadata.pop("axis", None)
        self.from_decision = metadata.pop("from_decision", None)
        self.to_decision = metadata.pop("to_decision", None)
        self.from_accepted = metadata.pop("from_accepted", None)
        self.to_accepted = metadata.pop("to_accepted", None)
        self.ids = list(self)
        self.size = len(self)
        self.metadata = metadata


_BUSINESS_TIME_KEYS = (
    "signed_business_time",
    "signed_business_at",
    "business_timestamp",
    "business_time",
    "business_at",
    "signing_time",
    "signed_timestamp",
    "signed_time",
    "signed_at",
    "authored_at",
    "event_time",
    "event_at",
    "occurred_at",
    "occurred_time",
    "valid_time",
    "effective_at",
    "effective_time",
    "clock_reading",
    "signed_clock",
    "local_signed_time",
)

_CORRECTED_TIME_KEYS = (
    "corrected_business_time",
    "corrected_signed_at",
    "true_business_time",
    "true_time",
    "canonical_business_time",
)

_RECEIPT_TIME_KEYS = (
    "trusted_receipt_time",
    "trusted_received_at",
    "trusted_receipt_at",
    "receipt_timestamp",
    "receipt_time",
    "received_timestamp",
    "received_at",
    "received_time",
    "ingested_at",
    "ingestion_time",
    "recorded_at",
    "record_time",
    "custody_time",
    "custody_at",
    "accepted_at",
    "signoff_received_at",
)

_ID_KEYS = ("id", "record_id", "evidence_id", "link_id", "uid", "uuid")
_GROUP_KEYS = (
    "logical_id",
    "logical_record_id",
    "stream_id",
    "series_id",
    "record_key",
    "target_record_id",
)
_REVISION_KEYS = (
    "revision",
    "revision_number",
    "rev",
    "version",
    "version_number",
)
_SOURCE_KEYS = (
    "clock_id",
    "source",
    "host",
    "host_id",
    "machine",
    "machine_id",
    "signer",
    "signer_id",
    "keyid",
    "key_id",
)


def norm_key(key: Any) -> str:
    text = re.sub(r"[\s\-]+", "_", str(key))
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", text).lower()
    return text.strip("_")


def deep_data(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool, bytes)):
        return value
    if attr_module is not None:
        try:
            if attr_module.has(type(value)):
                return attr_module.asdict(value, recurse=True)
        except Exception:
            pass
    if hasattr(value, "to_dict") and callable(value.to_dict):
        try:
            return deep_data(value.to_dict())
        except Exception:
            pass
    if is_dataclass(value):
        try:
            return deep_data(asdict(value))
        except Exception:
            pass
    if isinstance(value, Mapping):
        return {k: deep_data(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [deep_data(v) for v in value]
    if hasattr(value, "__dict__"):
        return {
            k: deep_data(v)
            for k, v in vars(value).items()
            if not k.startswith("__")
        }
    return value


def flatten(data: Any, out: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return normalized-key view, retaining top-level key priority."""
    result = {} if out is None else out
    if isinstance(data, Mapping):
        for key, value in data.items():
            normalized = norm_key(key)
            if normalized not in result or result[normalized] is None:
                result[normalized] = value
            if normalized in {
                "signed",
                "time",
                "times",
                "timestamps",
                "temporal",
                "clock",
                "clock_offset",
                "metadata",
                "receipt",
                "receipt_info",
                "signature",
                "sig",
            } and isinstance(value, Mapping):
                flatten(value, out=result)
    return result


def first(fields: Mapping[str, Any], keys: Iterable[str]) -> Any:
    for key in keys:
        normalized = norm_key(key)
        if normalized in fields and fields[normalized] is not None:
            return fields[normalized]
    return None


def all_values(fields: Mapping[str, Any], keys: Iterable[str]) -> list[Any]:
    values: list[Any] = []
    for key in keys:
        value = first(fields, (key,))
        if value is None:
            continue
        if isinstance(value, (list, tuple, set, frozenset)):
            values.extend(value)
        else:
            values.append(value)
    return values


def parse_time(value: Any) -> float | None:
    """Parse numeric clocks, datetimes, or ISO-8601 strings to seconds."""
    if value is None:
        return None
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return float(text)
        except ValueError:
            pass
        try:
            dt = parse_date(text)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except (ValueError, OverflowError):
            return None
    return None


def natural_key(value: Any) -> tuple[Any, ...]:
    if isinstance(value, bool):
        return (2, (float(value),), str(value))
    if isinstance(value, (int, float)):
        return (0, (float(value),), "")
    text = str(value)
    numbers = tuple(int(part) for part in re.findall(r"\d+", text))
    return (1, numbers, text)


def sorted_ids(values: Iterable[Any]) -> list[Any]:
    return sorted(list(values), key=natural_key)


def stable_id(data: Any, prefix: str) -> str:
    try:
        blob = json.dumps(
            data, sort_keys=True, default=repr, ensure_ascii=False
        )
    except Exception:
        blob = repr(data)
    digest = hashlib.sha256(blob.encode("utf-8")).hexdigest()[:12]
    return f"{prefix}:{digest}"


def revision_key(value: Any) -> tuple[Any, ...]:
    if value is None:
        return (0, (), "")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return (2, (float(value),), "")
    numbers = tuple(int(part) for part in re.findall(r"\d+", str(value)))
    if numbers:
        return (1, numbers, str(value))
    return (3, (), str(value))


def as_int(value: Any, default: int | None = None) -> int | None:
    if value is None or isinstance(value, bool):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return default


def coerce_records(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set, frozenset)):
        return list(value)
    if isinstance(value, Mapping):
        if value and all(
            isinstance(item, (list, tuple)) for item in value.values()
        ):
            records = []
            for key, revisions in value.items():
                for revision in revisions:
                    if isinstance(revision, Mapping):
                        revision = dict(revision)
                        revision.setdefault("id", key)
                    records.append(revision)
            return records
        if (
            value
            and all(
                isinstance(v, Mapping) or hasattr(v, "__dict__")
                for v in value.values()
            )
            and not any(
                norm_key(k)
                in {
                    "steps",
                    "signed",
                    "materials",
                    "products",
                    "expected_materials",
                    "expected_products",
                }
                for k in value
            )
        ):
            records = []
            for key, item in value.items():
                if isinstance(item, Mapping) and "id" not in item:
                    item = dict(item)
                    item["id"] = key
                records.append(item)
            return records
        return [value]
    return [value]


def expand_histories(records: list[Any]) -> list[Any]:
    """Expand revision-history containers into individual revision records."""
    expanded: list[Any] = []
    history_keys = (
        "revisions",
        "revision_records",
        "revision_history",
        "versions",
        "version_history",
        "history",
        "timeline",
    )
    for raw in records:
        data = deep_data(raw)
        child_list = None
        if isinstance(data, Mapping):
            for key in history_keys:
                if isinstance(data.get(key), list):
                    child_list = data[key]
                    break
        if child_list is None:
            expanded.append(raw)
            continue

        base = {
            key: value
            for key, value in data.items()
            if key not in history_keys
            and not isinstance(value, (list, Mapping))
        }
        for child in child_list:
            child_data = deep_data(child)
            if isinstance(child_data, Mapping):
                merged = dict(base)
                merged.update(child_data)
                child_data = merged
            expanded.append(child_data)
    return expanded


def coerce_clocks(value: Any) -> list[Any]:
    if isinstance(value, Mapping):
        looks_like_record = (
            first(
                flatten(value),
                (
                    "offset",
                    "clock_offset",
                    "skew",
                    "observed_time",
                    "reference_time",
                ),
            )
            is not None
        )
        if looks_like_record:
            return [value]
        clocks = []
        for source, spec in value.items():
            if isinstance(spec, Mapping):
                clock = dict(spec)
                clock.setdefault("source", source)
                clock.setdefault("clock_id", source)
            else:
                clock = {"source": source, "clock_id": source, "offset": spec}
            clocks.append(clock)
        return clocks
    return coerce_records(value)


def kind_of(raw: Any) -> str:
    fields = flatten(deep_data(raw))
    kind = str(
        first(
            fields,
            ("kind", "record_kind", "record_type", "type", "_type", "category"),
        )
        or ""
    ).lower()
    if "layout" in kind:
        return "layout"
    if "revoc" in kind or "crl" in kind or "tombstone" in kind:
        return "revocation"
    if "clock" in kind or "calibrat" in kind:
        return "clock"
    if "supplement" in kind or "candidate" in kind or "missing" in kind:
        return "supplement"
    if kind in {"link", "evidence", "signature", "sig", "attestation"}:
        return "evidence"

    if (
        first(
            fields, ("steps", "layout", "expires", "expires_at", "valid_until")
        )
        is not None
    ):
        return "layout"
    if (
        first(fields, ("revoked", "revocation", "revokes", "revocation_id"))
        is not None
    ):
        return "revocation"
    target_like = first(
        fields,
        (
            "targets",
            "target_ids",
            "target",
            "target_id",
            "subject",
            "subject_id",
        ),
    )
    if (
        target_like is not None
        and first(
            fields,
            (
                "step",
                "step_name",
                "materials",
                "products",
                "expected_materials",
                "expected_products",
                "command",
            ),
        )
        is None
    ):
        return "revocation"
    if (
        first(
            fields,
            ("offset", "clock_offset", "observed_time", "reference_time"),
        )
        is not None
    ):
        return "clock"
    return "evidence"


def normalize_clock(raw: Any) -> Report:
    data = deep_data(raw)
    fields = flatten(data)
    clock_id = first(fields, _ID_KEYS + _SOURCE_KEYS) or stable_id(
        data, "clock"
    )
    offset = first(
        fields,
        (
            "clock_offset_seconds",
            "clock_offset",
            "offset_seconds",
            "mechanical_skew_seconds",
            "mechanical_offset",
            "skew_seconds",
            "offset",
            "skew",
            "clock_skew",
        ),
    )
    correction = first(
        fields,
        ("correction_seconds", "time_correction", "correction", "adjustment"),
    )
    observed = parse_time(
        first(
            fields, ("observed_time", "observed_at", "clock_reading", "reading")
        )
    )
    trusted = parse_time(
        first(
            fields,
            ("trusted_time", "reference_time", "trusted_at", "reference_at"),
        )
    )
    offset_value = parse_time(offset)
    if offset_value is None and observed is not None and trusted is not None:
        offset_value = observed - trusted
    if offset_value is None and correction is not None:
        correction_value = parse_time(correction)
        offset_value = None if correction_value is None else -correction_value
    return Report(
        id=clock_id,
        source=first(fields, _SOURCE_KEYS) or clock_id,
        offset=offset_value,
        offset_min=first(
            fields, ("offset_min", "clock_offset_min", "lower_offset")
        ),
        offset_max=first(
            fields, ("offset_max", "clock_offset_max", "upper_offset")
        ),
        uncertainty=first(
            fields,
            ("offset_uncertainty", "uncertainty", "error_bound", "clock_error"),
        ),
        drift=first(fields, ("drift_per_second", "drift_rate", "drift")),
        calibrated_at=parse_time(
            first(
                fields,
                ("calibrated_at", "offset_at", "reference_time", "trusted_at"),
            )
        ),
        data=data,
    )


def clock_interval(
    fields: Mapping[str, Any],
    source: Any,
    at_time: float | None,
    clocks: list[Report],
) -> tuple[float | None, float | None, Any]:
    direct_center = first(
        fields,
        (
            "clock_offset_seconds",
            "clock_offset",
            "offset_seconds",
            "mechanical_skew_seconds",
            "mechanical_offset",
            "skew_seconds",
            "offset",
            "skew",
            "clock_skew",
        ),
    )
    correction = first(
        fields,
        ("correction_seconds", "time_correction", "correction", "adjustment"),
    )
    lower = first(fields, ("offset_min", "clock_offset_min", "lower_offset"))
    upper = first(fields, ("offset_max", "clock_offset_max", "upper_offset"))
    uncertainty = first(
        fields,
        ("offset_uncertainty", "uncertainty", "error_bound", "clock_error"),
    )
    clock_ref = None
    center: float | None = None
    lo: float | None = None
    hi: float | None = None

    if lower is not None and upper is not None:
        lo = parse_time(lower)
        hi = parse_time(upper)
    else:
        center = parse_time(direct_center)
        if center is None and correction is not None:
            correction_value = parse_time(correction)
            center = None if correction_value is None else -correction_value
        else:
            observed = parse_time(
                first(fields, ("observed_time", "clock_reading", "reading"))
            )
            trusted = parse_time(
                first(fields, ("trusted_time", "reference_time"))
            )
            if observed is not None and trusted is not None:
                center = observed - trusted

        if center is None and source is not None:
            source_text = str(source)
            matches = [
                clock
                for clock in clocks
                if str(clock.get("source")) == source_text
                or str(clock.get("id")) == source_text
            ]
            if not matches and len(clocks) == 1:
                matches = clocks
            if matches:
                clock = sorted(matches, key=lambda item: natural_key(item.id))[
                    0
                ]
                clock_ref = clock.id
                center = clock.offset
                if (
                    clock.offset_min is not None
                    and clock.offset_max is not None
                ):
                    lo = parse_time(clock.offset_min)
                    hi = parse_time(clock.offset_max)
                if uncertainty is None:
                    uncertainty = clock.uncertainty
                drift = clock.drift
                calibrated_at = clock.calibrated_at
                if (
                    center is not None
                    and drift is not None
                    and at_time is not None
                ):
                    drift_value = parse_time(drift) or 0.0
                    anchor = (
                        calibrated_at if calibrated_at is not None else at_time
                    )
                    center = center + drift_value * (at_time - anchor)

        if center is not None and lo is None and hi is None:
            error = parse_time(uncertainty) if uncertainty is not None else 0.0
            lo = center - (error or 0.0)
            hi = center + (error or 0.0)

    if lo is None or hi is None:
        return None, None, clock_ref
    if lo > hi:
        lo, hi = hi, lo
    return lo, hi, clock_ref


def layout_ref_from_fields(fields: Mapping[str, Any]) -> Report | None:
    ref = first(
        fields,
        (
            "layout_ref",
            "layout_reference",
            "historical_layout",
            "layout",
            "layout_id",
        ),
    )
    if ref is None:
        return None
    if isinstance(ref, Mapping):
        ref_fields = flatten(ref)
        return Report(
            id=first(ref_fields, _ID_KEYS + ("layout_id",)),
            revision=first(
                ref_fields,
                _REVISION_KEYS + ("layout_version", "layout_revision"),
            ),
            digest=first(ref_fields, ("digest", "hash", "layout_digest")),
            raw=ref,
        )
    return Report(
        id=ref,
        revision=first(fields, ("layout_version", "layout_revision")),
        digest=first(fields, ("layout_digest",)),
    )


def normalize_entry(raw: Any, clocks: list[Report] | None = None) -> Report:
    data = deep_data(raw)
    fields = flatten(data)
    clocks = clocks or []

    entry_id = first(fields, _ID_KEYS)
    if entry_id is None:
        entry_id = stable_id(data, kind_of(raw))

    kind = kind_of(raw)
    source = first(fields, _SOURCE_KEYS)
    revision = first(fields, _REVISION_KEYS)
    group = first(fields, _GROUP_KEYS)
    if group is None:
        replaces = first(
            fields, ("supersedes", "replaces", "prior_id", "base_id")
        )
        if revision is not None and first(fields, _ID_KEYS) is not None:
            group = entry_id
        elif replaces is not None and first(fields, _ID_KEYS) is None:
            group = replaces
        else:
            group = entry_id

    business_raw = first(fields, _BUSINESS_TIME_KEYS)
    business_override = first(fields, _CORRECTED_TIME_KEYS)
    business_time = parse_time(business_override) or parse_time(business_raw)

    offset_lo = offset_hi = None
    clock_ref = None
    if business_override is None and business_time is not None:
        offset_lo, offset_hi, clock_ref = clock_interval(
            fields, source, business_time, clocks
        )

    if business_time is None:
        business_interval: tuple[float | None, float | None] | None = None
    elif (
        business_override is not None or offset_lo is None or offset_hi is None
    ):
        business_interval = (business_time, business_time)
    else:
        # Offset convention: offset = reading - true time.
        business_interval = (
            business_time - offset_hi,
            business_time - offset_lo,
        )

    if business_interval is not None and business_interval[0] is not None:
        business_time = (business_interval[0] + business_interval[1]) / 2

    receipt_raw = first(fields, _RECEIPT_TIME_KEYS)
    receipt_time = parse_time(receipt_raw)
    receipt_uncertainty = parse_time(
        first(fields, ("receipt_uncertainty", "trusted_receipt_uncertainty"))
    )
    if receipt_time is None:
        receipt_interval = None
    else:
        error = receipt_uncertainty or 0.0
        receipt_interval = (receipt_time - error, receipt_time + error)

    deleted = (
        first(fields, ("tombstone", "is_tombstone", "deleted", "is_deleted"))
        is True
    )
    status = str(
        first(fields, ("status", "state", "revocation_status")) or ""
    ).lower()
    if status in {"deleted", "tombstoned", "withdrawn", "removed"}:
        deleted = True

    signature_valid = first(
        fields,
        (
            "signature_valid",
            "valid_signature",
            "signature_verified",
            "verified_signature",
            "is_valid",
        ),
    )
    if (
        signature_valid is None
        and first(fields, ("signed", "has_signature")) is False
    ):
        signature_valid = False
    signature_status = first(
        fields, ("signature_status", "sig_status", "verification_status")
    )
    if signature_status is not None:
        signature_status = str(signature_status).lower()

    keyid = first(
        fields,
        ("keyid", "key_id", "signer_keyid", "signing_key_id", "public_key_id"),
    )
    signer = first(
        fields, ("signer", "signer_id", "functionary", "functionary_id")
    )

    return Report(
        id=entry_id,
        kind=kind,
        logical_group=group,
        revision=revision,
        revision_sort=revision_key(revision),
        source=source,
        keyid=keyid,
        signer=signer,
        identity=keyid or signer or entry_id,
        business_time_raw=business_raw,
        business_time=business_time,
        business_interval=business_interval,
        receipt_time_raw=receipt_raw,
        receipt_time=receipt_time,
        receipt_interval=receipt_interval,
        clock_id=clock_ref,
        offset_interval=None if offset_lo is None else (offset_lo, offset_hi),
        layout_ref=layout_ref_from_fields(fields),
        step=first(
            fields,
            (
                "step",
                "step_name",
                "name",
                "target_step",
                "requirement_id",
                "requirement",
            ),
        ),
        requirement_id=first(
            fields, ("requirement_id", "requirement", "step", "step_name")
        ),
        satisfies=first(fields, ("satisfies", "requirements", "provides")),
        signature_valid=signature_valid,
        signature_status=signature_status,
        authorized=first(fields, ("authorized", "is_authorized", "allowed")),
        deleted=deleted,
        status=status or None,
        candidate=bool(
            first(fields, ("candidate", "is_candidate", "possible")) or False
        ),
        missing=bool(first(fields, ("missing", "is_missing")) or False),
        data=data,
        fields=fields,
        raw=raw,
    )


def classify_interval(
    interval: tuple[float | None, float | None] | None,
    cutoff: float | None,
    *,
    inclusive: bool = True,
    ambiguous_policy: str = "indeterminate",
) -> Report:
    if interval is None or interval[0] is None or interval[1] is None:
        return Report(status="unknown", eligible=None, boundary=False)
    lo, hi = interval
    if cutoff is None:
        return Report(
            status="inside", eligible=True, boundary=False, lo=lo, hi=hi
        )

    inside = hi <= cutoff if inclusive else hi < cutoff
    outside = lo > cutoff if inclusive else lo >= cutoff
    if inside:
        return Report(
            status="inside", eligible=True, boundary=False, lo=lo, hi=hi
        )
    if outside:
        return Report(
            status="outside", eligible=False, boundary=False, lo=lo, hi=hi
        )

    if ambiguous_policy in {"include", "accept", "inclusive"}:
        eligible: bool | None = True
    elif ambiguous_policy in {"exclude", "reject", "exclusive"}:
        eligible = False
    else:
        eligible = None
    return Report(
        status="boundary", eligible=eligible, boundary=True, lo=lo, hi=hi
    )


def select_entries(
    entries: list[Report],
    axis: str,
    cutoff: float | None,
    *,
    inclusive: bool = True,
    ambiguous_policy: str = "indeterminate",
) -> Report:
    inside: list[Report] = []
    unresolved: list[Report] = []
    outside: list[Report] = []

    for entry in entries:
        if axis == "business":
            interval = entry.business_interval
        elif axis == "receipt":
            interval = entry.receipt_interval
        else:
            interval = (entry.business_time, entry.business_time)
        membership = classify_interval(
            interval,
            cutoff,
            inclusive=inclusive,
            ambiguous_policy=ambiguous_policy,
        )
        entry[f"{axis}_membership"] = membership
        if membership.status == "inside" or membership.eligible is True:
            inside.append(entry)
        elif (
            membership.status in {"boundary", "unknown"}
            or membership.eligible is None
        ):
            unresolved.append(entry)
        else:
            outside.append(entry)

    groups: dict[Any, Report] = {}
    for entry in inside:
        current = groups.get(entry.logical_group)
        if current is None or entry.revision_sort > current.revision_sort:
            groups[entry.logical_group] = entry

    selected: list[Report] = []
    tombstones: list[Report] = []
    for entry in groups.values():
        (tombstones if entry.deleted else selected).append(entry)

    for items in (selected, unresolved, outside, tombstones):
        items.sort(key=lambda entry: natural_key(entry.id))
    return Report(
        selected=selected,
        unresolved=unresolved,
        outside=outside,
        tombstones=tombstones,
        selected_ids=[entry.id for entry in selected],
        unresolved_ids=[entry.id for entry in unresolved],
        outside_ids=[entry.id for entry in outside],
        tombstone_ids=[entry.id for entry in tombstones],
    )


def normalize_layout(raw: Any, clocks: list[Report] | None = None) -> Report:
    entry = normalize_entry(raw, clocks=clocks)
    fields = entry.fields
    steps = (
        first(fields, ("steps", "required_steps", "requirements", "items"))
        or []
    )
    if isinstance(steps, Mapping):
        step_list = []
        for key, value in steps.items():
            if isinstance(value, Mapping):
                value = dict(value)
                value.setdefault("name", key)
            step_list.append(value)
        steps = step_list

    normalized_steps = []
    for step in coerce_records(steps):
        step_data = deep_data(step)
        step_fields = flatten(step_data)
        name = first(step_fields, ("name", "step", "id", "requirement_id"))
        if name is None:
            name = stable_id(step_data, "step")
        threshold = as_int(
            first(
                step_fields,
                ("threshold", "required_count", "count", "min_signers"),
            ),
            1,
        )
        pubkeys = first(
            step_fields,
            (
                "pubkeys",
                "authorized_keys",
                "keyids",
                "keys",
                "signers",
                "allowed_signers",
            ),
        )
        if isinstance(pubkeys, (str, int)):
            pubkeys = [pubkeys]
        normalized_steps.append(
            Report(
                id=name,
                name=name,
                threshold=max(1, threshold or 1),
                pubkeys=list(pubkeys or []),
                required=first(step_fields, ("required", "mandatory"))
                is not False,
                artifact_agreement=first(
                    step_fields,
                    (
                        "artifact_agreement",
                        "require_agreement",
                        "same_artifacts",
                    ),
                ),
                data=step_data,
            )
        )

    entry.update(
        expires=parse_time(
            first(
                fields,
                (
                    "expires",
                    "expires_at",
                    "expiry",
                    "valid_until",
                    "expire_time",
                ),
            )
        ),
        steps=normalized_steps,
        layout_keys=first(fields, ("keys", "public_keys")) or {},
        layout_signature_valid=first(
            fields,
            ("layout_signature_valid", "signature_valid", "valid_signature"),
        ),
    )
    return entry


def gather_bundle(values: Mapping[str, Any]) -> dict[str, list[Any]]:
    bundle: dict[str, list[Any]] = {
        "evidence": [],
        "layouts": [],
        "revocations": [],
        "supplements": [],
        "clocks": [],
    }
    aliases = {
        "evidence": (
            "evidence",
            "links",
            "link_records",
            "link_history",
            "evidence_records",
            "artifacts_evidence",
        ),
        "layouts": (
            "layouts",
            "layout_revisions",
            "layout_history",
            "historical_layouts",
            "historical_layout_references",
        ),
        "revocations": (
            "revocations",
            "revocation_records",
            "revocation_choices",
            "revocation_history",
            "cancellations",
            "revokes",
            "crl",
        ),
        "supplements": (
            "supplements",
            "supplemental_evidence",
            "supplement_evidence",
            "candidates",
            "possible_evidence",
            "backfills",
            "backfill_records",
            "backfilled_records",
            "retroactive_records",
            "late_records",
            "supplementary_records",
            "missing_evidence",
            "possible_supplements",
            "evidence_to_add",
        ),
        "clocks": (
            "clocks",
            "clock_offsets",
            "clock_records",
            "clock_calibrations",
            "calibrations",
            "time_calibrations",
        ),
    }
    universal_aliases = (
        "records",
        "entries",
        "items",
        "history",
        "events",
        "revisions",
        "revision_records",
        "audit_log",
        "journal",
        "timeline",
    )

    universal: list[Any] = []
    for kind, names in aliases.items():
        for alias in names:
            if values.get(alias) is not None:
                if kind == "clocks":
                    bundle[kind].extend(coerce_clocks(values[alias]))
                else:
                    bundle[kind].extend(coerce_records(values[alias]))
    for alias in universal_aliases:
        if values.get(alias) is not None:
            universal.extend(coerce_records(values[alias]))

    universal = expand_histories(universal)
    for key in list(bundle):
        bundle[key] = expand_histories(bundle[key])

    for raw in universal:
        kind = kind_of(raw)
        if kind == "clock":
            bundle["clocks"].extend(coerce_clocks(raw))
        elif kind == "layout":
            bundle["layouts"].append(raw)
        elif kind == "revocation":
            bundle["revocations"].append(raw)
        elif kind == "supplement":
            bundle["supplements"].append(raw)
        else:
            bundle["evidence"].append(raw)

    current_evidence = []
    for raw in bundle["evidence"]:
        entry = normalize_entry(raw)
        if entry.missing or entry.candidate:
            bundle["supplements"].append(raw)
        else:
            current_evidence.append(raw)
    bundle["evidence"] = current_evidence
    return bundle


_CUTOFF_B_KEYS = (
    "business_as_of",
    "business_cutoff",
    "business_checkpoint",
    "business_slice",
    "at_business_time",
    "business_date",
    "signed_time_cutoff",
    "signed_business_time",
    "signed_business_as_of",
    "business_time",
    "signed_time",
    "b_cutoff",
)
_CUTOFF_R_KEYS = (
    "receipt_as_of",
    "receipt_cutoff",
    "receipt_checkpoint",
    "receipt_slice",
    "at_receipt_time",
    "receipt_date",
    "trusted_receipt_cutoff",
    "trusted_receipt_time",
    "trusted_receipt_as_of",
    "receipt_time",
    "received_time",
    "r_cutoff",
)


def settings_from(values: Mapping[str, Any]) -> Report:
    flat = flatten(deep_data(dict(values)))
    as_of = first(flat, ("as_of", "cutoff", "at", "time_cutoff"))
    business_cutoff = first(flat, _CUTOFF_B_KEYS)
    receipt_cutoff = first(flat, _CUTOFF_R_KEYS)

    slices = first(flat, ("time_slices", "slices", "cutoffs", "checkpoints"))
    if slices is not None:
        if isinstance(slices, Mapping):
            slice_fields = flatten(slices)
            business_cutoff = business_cutoff or first(
                slice_fields, ("business", "business_time", "b")
            )
            receipt_cutoff = receipt_cutoff or first(
                slice_fields, ("receipt", "receipt_time", "r")
            )
        elif isinstance(slices, (list, tuple)) and len(slices) >= 2:
            business_cutoff = (
                business_cutoff if business_cutoff is not None else slices[0]
            )
            receipt_cutoff = (
                receipt_cutoff if receipt_cutoff is not None else slices[1]
            )

    business_cutoff = parse_time(
        business_cutoff if business_cutoff is not None else as_of
    )
    receipt_cutoff = parse_time(
        receipt_cutoff if receipt_cutoff is not None else as_of
    )

    boundary = str(
        first(
            flat,
            ("boundary_policy", "on_boundary", "clock_boundary", "boundary"),
        )
        or "indeterminate"
    ).lower()
    inclusive = first(flat, ("inclusive", "inclusive_cutoff"))
    if inclusive is None:
        inclusive = boundary != "strict"

    layout_value = first(
        flat, ("layout_ref", "layout_reference", "layout_id", "layout")
    )
    return Report(
        business_cutoff=business_cutoff,
        receipt_cutoff=receipt_cutoff,
        inclusive=bool(inclusive),
        ambiguous_policy=str(
            first(
                flat, ("ambiguous_policy", "on_ambiguous", "uncertain_policy")
            )
            or boundary
        ).lower(),
        require_signatures=bool(
            first(flat, ("require_signatures", "verify_signatures")) or False
        ),
        signature_verifier=values.get("signature_verifier")
        or values.get("verifier"),
        strict_layout=bool(
            first(flat, ("strict_layout", "require_layout")) or False
        ),
        artifact_agreement=bool(
            first(flat, ("artifact_agreement", "require_artifact_agreement"))
            or False
        ),
        target=first(flat, ("target_decision", "decision_target", "target"))
        or "flip",
        find_minimal=first(
            flat, ("find_minimal", "compute_minimal", "with_minimal")
        )
        is not False,
        max_candidates=as_int(
            first(flat, ("max_candidates", "max_supplement_candidates")), 16
        ),
        max_evaluations=as_int(first(flat, ("max_evaluations",)), 20000),
        requirements=values.get("requirements") or values.get("required_steps"),
        layout_ref=layout_ref_from_fields(flat)
        if layout_value is not None
        else None,
    )


_RECEIPT_LOG_KEYS = (
    "receipts",
    "receipt_records",
    "receipt_log",
    "receipt_times",
    "trusted_receipts",
    "trusted_receipt_log",
    "intake_log",
    "custody_log",
)
_BUSINESS_LOG_KEYS = (
    "business_times",
    "signed_times",
    "business_time_log",
    "signed_time_log",
)


def external_time_index(
    values: Mapping[str, Any], axis: str
) -> dict[Any, float]:
    """Index a separate trusted receipt or signed-time log by evidence ID."""
    keys = _RECEIPT_LOG_KEYS if axis == "receipt" else _BUSINESS_LOG_KEYS
    index: dict[Any, float] = {}
    for alias in keys:
        value = values.get(alias)
        if value is None:
            continue

        raw_records: list[Any] = []
        if isinstance(value, Mapping):
            for map_key, item in value.items():
                if isinstance(item, (int, float, str, datetime)):
                    instant = parse_time(item)
                    if instant is not None:
                        index[map_key] = instant
                else:
                    if isinstance(item, Mapping):
                        item = dict(item)
                        item.setdefault("id", map_key)
                    raw_records.append(item)
        else:
            raw_records = coerce_records(value)

        for raw in raw_records:
            entry = normalize_entry(raw)
            instant = (
                entry.receipt_time if axis == "receipt" else entry.business_time
            )
            if instant is None:
                continue
            fields = entry.fields
            identifiers = [
                entry.id,
                first(
                    fields, ("link_id", "target_id", "evidence_id", "record_id")
                ),
                entry.keyid,
                first(fields, ("step", "step_name", "name")),
            ]
            for identifier in identifiers:
                if identifier is not None:
                    index[identifier] = instant
    return index


def apply_external_times(
    entries: list[Report], values: Mapping[str, Any]
) -> None:
    receipt_index = external_time_index(values, "receipt")
    business_index = external_time_index(values, "business")
    for entry in entries:
        identifiers = [
            entry.id,
            entry.fields.get("link_id"),
            entry.fields.get("target_id"),
            entry.keyid,
            entry.step,
        ]
        for identifier in identifiers:
            if identifier in receipt_index:
                instant = receipt_index[identifier]
                entry.receipt_time = instant
                entry.receipt_interval = (instant, instant)
                break
        for identifier in identifiers:
            if identifier in business_index:
                instant = business_index[identifier]
                entry.business_time = instant
                entry.business_interval = (instant, instant)
                break


def revocation_matchers(entry: Report) -> tuple[set[Any], set[Any]]:
    targets = all_values(
        entry.fields,
        (
            "targets",
            "target_ids",
            "target",
            "target_id",
            "subjects",
            "subject",
            "subject_id",
            "evidence_id",
            "link_id",
            "keyids",
            "keyid",
            "key_id",
            "signer",
            "signer_id",
        ),
    )
    key_targets = set()
    id_targets = set()
    for target in targets:
        if isinstance(target, Mapping):
            target = first(flatten(target), _ID_KEYS + ("keyid", "key_id"))
        if target is None:
            continue
        key_targets.add(target)
        id_targets.add(target)
    return key_targets, id_targets


def revocation_active(entry: Report) -> bool:
    if entry.deleted:
        return False
    active = first(entry.fields, ("active", "is_active", "in_force"))
    if active is False:
        return False
    revoked = first(entry.fields, ("revoked", "is_revoked"))
    if revoked is False and active is None:
        return False
    status = str(first(entry.fields, ("status", "state")) or "").lower()
    return status not in {
        "reinstated",
        "restored",
        "undone",
        "inactive",
        "expired",
    }


def artifact_fingerprint(entry: Report) -> str | None:
    direct = first(
        entry.fields,
        (
            "artifact_digest",
            "artifacts_digest",
            "artifact_hash",
            "products_hash",
            "digest",
            "hash",
        ),
    )
    if direct is not None:
        return str(direct)
    artifacts = first(
        entry.fields, ("artifacts", "materials", "products", "hashes")
    )
    if artifacts is None:
        return None
    try:
        return hashlib.sha256(
            json.dumps(artifacts, sort_keys=True, default=repr).encode()
        ).hexdigest()
    except Exception:
        return repr(artifacts)


def signature_state(entry: Report, settings: Report) -> tuple[bool | None, str]:
    verifier: Callable[[Any], Any] | None = settings.get("signature_verifier")
    if callable(verifier):
        try:
            result = verifier(entry.data)
            if result is True:
                return True, "verified"
            if result is False:
                return False, "signature_verifier_rejected"
            if isinstance(result, str):
                return state_from_status(result)
        except Exception as exc:
            return False, f"signature_verifier_error:{type(exc).__name__}"

    if entry.signature_valid is False:
        return False, "invalid_signature"
    if entry.signature_status:
        return state_from_status(entry.signature_status)
    if entry.signature_valid is True:
        return True, "valid_signature"
    if (
        entry.keyid
        or first(entry.fields, ("signature", "sig", "signatures")) is not None
    ):
        return True, "signature_present_assumed_valid"
    if settings.require_signatures:
        return None, "missing_signature"
    return True, "signature_not_modeled"


def state_from_status(status: str) -> tuple[bool | None, str]:
    if status in {"valid", "verified", "ok", "accepted", "good", "trusted"}:
        return True, status
    if status in {
        "invalid",
        "forged",
        "bad",
        "failed",
        "rejected",
        "untrusted",
        "expired",
    }:
        return False, status
    return None, status or "unverified"


def key_allowed(keyid: Any, pubkeys: list[Any]) -> bool:
    if not pubkeys:
        return True
    if keyid is None:
        return False
    key_text = str(keyid)
    for allowed in pubkeys:
        allowed_text = str(allowed)
        if key_text == allowed_text:
            return True
        if len(allowed_text) >= 8 and key_text.startswith(allowed_text):
            return True
        if len(key_text) >= 8 and allowed_text.startswith(key_text):
            return True
    return False


def matching_requirement(
    entry: Report, requirements: list[Report]
) -> Report | None:
    satisfies = entry.satisfies or []
    if not isinstance(satisfies, (list, tuple, set, frozenset)):
        satisfies = [satisfies]

    candidates = []
    for req in requirements:
        if entry.requirement_id is not None and str(req.id) == str(
            entry.requirement_id
        ):
            candidates.append((0, req))
        elif any(str(req.id) == str(item) for item in satisfies):
            candidates.append((1, req))
        elif entry.step is not None and str(req.name) == str(entry.step):
            candidates.append((2, req))

    if entry.layout_ref is not None:
        exact = [
            req
            for _, req in candidates
            if req.get("layout_id") == entry.layout_ref.id
            and (
                entry.layout_ref.revision is None
                or str(req.get("layout_revision"))
                == str(entry.layout_ref.revision)
            )
        ]
        if exact:
            return sorted(exact, key=lambda req: natural_key(req.id))[0]
    if candidates:
        candidates.sort(key=lambda pair: (pair[0], natural_key(pair[1].id)))
        return candidates[0][1]
    return None


def layout_for_entry(
    entry: Report, layouts: list[Report], axis: str
) -> tuple[Report | None, list[str]]:
    problems = []
    if entry.layout_ref is not None:
        ref = entry.layout_ref
        matches = [
            layout for layout in layouts if str(layout.id) == str(ref.id)
        ]
        if ref.revision is not None:
            matches = [
                layout
                for layout in matches
                if str(layout.revision) == str(ref.revision)
                or str(layout.get("version")) == str(ref.revision)
            ]
        if ref.digest is not None:
            matches = [
                layout
                for layout in matches
                if str(
                    first(layout.fields, ("digest", "hash", "layout_digest"))
                )
                == str(ref.digest)
            ]
        if not matches:
            problems.append("unknown_historical_layout_reference")
            return None, problems
        layout = sorted(matches, key=lambda item: item.revision_sort)[-1]
        membership = layout.get(f"{axis}_membership")
        if membership and membership.eligible is False:
            problems.append("historical_layout_not_visible_in_slice")
        return layout, problems

    t = entry.business_time
    candidates = []
    for layout in layouts:
        effective = layout.business_time
        expires = layout.expires
        if t is not None and effective is not None and effective > t:
            continue
        if t is not None and expires is not None and t >= expires:
            continue
        if axis == "receipt":
            membership = layout.get("receipt_membership")
            if membership and membership.eligible is False:
                continue
        candidates.append(layout)
    if candidates:
        candidates.sort(
            key=lambda item: (item.revision_sort, natural_key(item.id))
        )
        return candidates[-1], problems
    return None, problems


def build_requirements(
    settings: Report,
    layouts: list[Report],
    visible_layouts: list[Report],
    axis: str,
    evidence: list[Report] | None = None,
) -> tuple[list[Report], Report | None]:
    requirements: list[Report] = []
    explicit = settings.get("requirements")
    if explicit is not None:
        for raw in coerce_records(explicit):
            data = deep_data(raw)
            fields = flatten(data)
            name = first(
                fields, ("id", "name", "step", "requirement_id")
            ) or stable_id(data, "requirement")
            requirements.append(
                Report(
                    id=name,
                    name=name,
                    threshold=as_int(
                        first(fields, ("threshold", "required_count", "count")),
                        1,
                    ),
                    pubkeys=list(
                        first(
                            fields,
                            ("pubkeys", "authorized_keys", "keyids", "signers"),
                        )
                        or []
                    ),
                    required=first(fields, ("required", "mandatory"))
                    is not False,
                    layout_id=None,
                    layout_revision=None,
                )
            )

    layout_ref = settings.get("layout_ref")
    default_layout = None
    if layout_ref is not None:
        matches = [
            layout for layout in layouts if str(layout.id) == str(layout_ref.id)
        ]
        if layout_ref.revision is not None:
            matches = [
                layout
                for layout in matches
                if str(layout.revision) == str(layout_ref.revision)
            ]
        if matches:
            default_layout = sorted(
                matches, key=lambda item: item.revision_sort
            )[-1]
    elif visible_layouts:
        default_layout = sorted(
            visible_layouts,
            key=lambda item: (item.revision_sort, natural_key(item.id)),
        )[-1]

    evidence = evidence or []
    referenced_layouts: list[Report] = []
    include_default = settings.get("layout_ref") is not None or not evidence
    for entry in evidence:
        if entry.get("layout_ref") is not None:
            resolved, _ = layout_for_entry(entry, layouts, axis)
            if resolved is not None:
                referenced_layouts.append(resolved)
        else:
            include_default = True
            resolved, _ = layout_for_entry(entry, layouts, axis)
            if resolved is not None:
                referenced_layouts.append(resolved)

    if include_default and default_layout is not None:
        referenced_layouts.append(default_layout)

    for layout in referenced_layouts:
        for step in layout.steps:
            req = Report(dict(step))
            req.layout_id = layout.id
            req.layout_revision = layout.revision
            requirements.append(req)

    deduped: dict[tuple[Any, Any, Any], Report] = {}
    for req in requirements:
        deduped[(req.get("layout_id"), req.get("layout_revision"), req.id)] = (
            req
        )
    return list(deduped.values()), default_layout


def build_slice(
    axis: str,
    cutoff: float | None,
    evidence: list[Report],
    layouts: list[Report],
    revocations: list[Report],
    settings: Report,
) -> Report:
    selection = select_entries(
        evidence,
        axis,
        cutoff,
        inclusive=settings.inclusive,
        ambiguous_policy=settings.ambiguous_policy,
    )
    revocation_selection = select_entries(
        revocations,
        axis,
        cutoff,
        inclusive=settings.inclusive,
        ambiguous_policy=settings.ambiguous_policy,
    )
    layout_selection = select_entries(
        layouts,
        axis,
        cutoff,
        inclusive=settings.inclusive,
        ambiguous_policy=settings.ambiguous_policy,
    )

    active_keys: set[Any] = set()
    active_ids: set[Any] = set()
    for revocation in revocation_selection.selected:
        if revocation_active(revocation):
            keys, ids = revocation_matchers(revocation)
            active_keys.update(keys)
            active_ids.update(ids)

    uncertain_revocation_targets: set[Any] = set()
    for revocation in revocation_selection.unresolved:
        keys, ids = revocation_matchers(revocation)
        uncertain_revocation_targets.update(keys)
        uncertain_revocation_targets.update(ids)

    requirements, default_layout = build_requirements(
        settings,
        layouts,
        layout_selection.selected,
        axis,
        list(selection.selected)
        + list(selection.unresolved)
        + list(selection.outside),
    )

    if not requirements and not settings.strict_layout:
        names = sorted_ids(
            {
                entry.requirement_id or entry.step or entry.id
                for entry in selection.selected
            }
        )
        for name in names:
            requirements.append(
                Report(
                    id=name,
                    name=name,
                    threshold=1,
                    pubkeys=[],
                    required=True,
                    layout_id=None,
                    layout_revision=None,
                )
            )

    assessments = []
    assessable_entries = (
        list(selection.selected)
        + list(selection.unresolved)
        + list(selection.outside)
    )
    for entry in assessable_entries:
        req = matching_requirement(entry, requirements)
        layout, layout_problems = layout_for_entry(entry, layouts, axis)
        if (
            layout is not None
            and req is not None
            and req.get("layout_id") is None
        ):
            layout_req = next(
                (step for step in layout.steps if str(step.id) == str(req.id)),
                None,
            )
            if layout_req is not None:
                req = Report(dict(layout_req))
                req.layout_id = layout.id
                req.layout_revision = layout.revision

        state, reason = signature_state(entry, settings)
        membership = entry.get(
            f"{axis}_membership", Report(status="unknown", eligible=None)
        )
        time_ok = membership.eligible is True
        time_potential = membership.eligible is None

        allowed = True
        auth_reason = None
        if req is not None and req.pubkeys:
            allowed = key_allowed(entry.keyid or entry.signer, req.pubkeys)
            if entry.authorized is False:
                allowed = False
            if not allowed:
                auth_reason = "unauthorized_signer"

        revoked = (
            entry.identity in active_keys
            or entry.keyid in active_keys
            or entry.signer in active_keys
            or entry.id in active_ids
        )
        revocation_uncertain = (
            entry.identity in uncertain_revocation_targets
            or entry.keyid in uncertain_revocation_targets
            or entry.signer in uncertain_revocation_targets
            or entry.id in uncertain_revocation_targets
        )

        valid: bool | None = True
        reasons = []
        if state is False:
            valid = False
            reasons.append(reason)
        elif state is None:
            valid = None
            reasons.append(reason)
        elif reason not in {
            "valid_signature",
            "signature_present_assumed_valid",
            "signature_not_modeled",
        }:
            reasons.append(reason)

        if not time_ok:
            if time_potential:
                valid = None if valid is not False else False
                reasons.append("time_boundary_or_unknown")
            else:
                valid = False
                reasons.append("time_not_eligible")
        if not allowed:
            valid = False
            reasons.append(auth_reason or "unauthorized_signer")
        if revoked:
            valid = False
            reasons.append("revoked")
        elif revocation_uncertain and valid is not False:
            valid = None
            reasons.append("uncertain_revocation")
        for problem in layout_problems:
            if problem == "unknown_historical_layout_reference":
                valid = False
            elif valid is not False:
                valid = None
            reasons.append(problem)
        if (
            layout is not None
            and layout.expires is not None
            and entry.business_time is not None
            and entry.business_time >= layout.expires
        ):
            valid = False
            reasons.append("layout_expired_at_signed_time")
        if layout is not None and layout.layout_signature_valid is False:
            valid = False
            reasons.append("layout_signature_invalid")

        assessments.append(
            Report(
                evidence_id=entry.id,
                requirement_id=req.id
                if req is not None
                else entry.requirement_id,
                requirement_key=None
                if req is None
                else (
                    req.get("layout_id"),
                    req.get("layout_revision"),
                    req.id,
                ),
                identity=entry.identity,
                keyid=entry.keyid,
                valid=valid,
                eligible=time_ok,
                potential=valid is None,
                revoked=revoked,
                time_status=membership.status,
                reasons=sorted(set(reasons)),
                artifact_fingerprint=artifact_fingerprint(entry),
            )
        )

    requirement_reports = []
    evidence_gaps = []
    findings = []
    for req in requirements:
        requirement_key = (
            req.get("layout_id"),
            req.get("layout_revision"),
            req.id,
        )
        related = [
            assessment
            for assessment in assessments
            if assessment.requirement_key == requirement_key
            or (
                assessment.requirement_id == req.id
                and assessment.requirement_key is None
            )
        ]
        valid_identities = set()
        potential_identities = set()
        valid_ids = []
        potential_ids = []
        invalid_ids = []
        outside_ids = []
        fingerprints: dict[str, list[Any]] = {}
        for assessment in related:
            identity = assessment.keyid or assessment.identity
            if assessment.valid is True:
                valid_identities.add(identity)
                valid_ids.append(assessment.evidence_id)
                if assessment.artifact_fingerprint is not None:
                    fingerprints.setdefault(
                        assessment.artifact_fingerprint, []
                    ).append(assessment.evidence_id)
            elif assessment.valid is None:
                potential_identities.add(identity)
                potential_ids.append(assessment.evidence_id)
            else:
                invalid_ids.append(assessment.evidence_id)
                if assessment.get("time_status") == "outside":
                    outside_ids.append(assessment.evidence_id)

        artifact_conflict = False
        if (
            settings.artifact_agreement or req.get("artifact_agreement") is True
        ) and len(fingerprints) > 1:
            artifact_conflict = True
            findings.append(f"artifact_mismatch:{req.id}")

        count = len(valid_identities)
        potential_count = len(potential_identities - valid_identities)
        if artifact_conflict:
            status = REJECTED
        elif count >= req.threshold:
            status = VALID
        elif count + potential_count >= req.threshold:
            status = INCONCLUSIVE
        else:
            status = REJECTED

        requirement_reports.append(
            Report(
                id=req.id,
                name=req.name,
                threshold=req.threshold,
                valid_count=count,
                valid_ids=sorted_ids(valid_ids),
                potential_ids=sorted_ids(potential_ids),
                invalid_ids=sorted_ids(invalid_ids),
                outside_ids=sorted_ids(outside_ids),
                missing_count=max(0, req.threshold - count),
                status=status,
                accepted=status == VALID,
                layout_id=req.get("layout_id"),
                layout_revision=req.get("layout_revision"),
                pubkeys=req.pubkeys,
                artifact_conflict=artifact_conflict,
            )
        )
        if status != VALID:
            needed_slots = max(0, req.threshold - count)
            confirmations = min(needed_slots, potential_count)
            evidence_gaps.append(
                Report(
                    requirement_id=req.id,
                    layout_id=req.get("layout_id"),
                    layout_revision=req.get("layout_revision"),
                    status=status,
                    missing_count=needed_slots,
                    minimum_new_evidence=max(0, needed_slots - confirmations),
                    minimum_confirmations=confirmations,
                    valid_ids=sorted_ids(valid_ids),
                    potential_ids=sorted_ids(potential_ids),
                    invalid_ids=sorted_ids(invalid_ids),
                    outside_ids=sorted_ids(outside_ids),
                    authorized_keyids=list(req.pubkeys or []),
                    artifact_conflict=artifact_conflict,
                    scope=sorted(
                        {
                            f"requirement:{req.id}",
                            *[
                                f"confirm:{evidence_id}"
                                for evidence_id in sorted_ids(potential_ids)[
                                    :confirmations
                                ]
                            ],
                            *[
                                f"backfill:{evidence_id}"
                                for evidence_id in sorted_ids(outside_ids)[
                                    : max(0, needed_slots - confirmations)
                                ]
                            ],
                        }
                    ),
                )
            )

    if settings.strict_layout and not layouts:
        findings.append("missing_layout")
    if cutoff is None and axis in {"business", "receipt"}:
        findings.append(f"missing_{axis}_cutoff")

    rejected = [req for req in requirement_reports if req.status == REJECTED]
    uncertain = [
        req for req in requirement_reports if req.status == INCONCLUSIVE
    ]
    if rejected or "missing_layout" in findings:
        decision = REJECTED
    elif uncertain:
        decision = INCONCLUSIVE
    elif requirement_reports:
        decision = VALID
    else:
        decision = REJECTED
        findings.append("no_requirements")

    minimum_backfill_ids = sorted_ids(
        {
            evidence_id
            for gap in evidence_gaps
            for evidence_id in list(gap.get("outside_ids") or [])[
                : gap.get("missing_count", 0)
            ]
        }
    )

    return Report(
        axis=axis,
        as_of=cutoff,
        cutoff=cutoff,
        decision=decision,
        status=decision,
        accepted=decision == VALID,
        passed=decision == VALID,
        selected_ids=selection.selected_ids,
        unresolved_ids=selection.unresolved_ids,
        outside_ids=selection.outside_ids,
        tombstone_ids=selection.tombstone_ids,
        selected=selection.selected,
        unresolved=selection.unresolved,
        outside=selection.outside,
        tombstones=selection.tombstones,
        revocation_ids=[
            item.id
            for item in revocation_selection.selected
            if revocation_active(item)
        ],
        unresolved_revocation_ids=revocation_selection.unresolved_ids,
        layouts=layout_selection.selected,
        selected_layout=default_layout,
        selected_layout_id=default_layout.id if default_layout else None,
        selected_layout_revision=default_layout.revision
        if default_layout
        else None,
        requirements=requirement_reports,
        evidence_gaps=evidence_gaps,
        minimum_scope=evidence_gaps,
        minimum_backfill_ids=minimum_backfill_ids,
        assessments=assessments,
        findings=sorted(set(findings)),
        minimal_supplement=MinimalWitness(
            possible=False, reason="not_computed"
        ),
    )


def build_paired_slice(
    settings: Report,
    evidence: list[Report],
    layouts: list[Report],
    revocations: list[Report],
) -> Report:
    paired = []
    for entry in evidence:
        business_membership = classify_interval(
            entry.business_interval,
            settings.business_cutoff,
            inclusive=settings.inclusive,
            ambiguous_policy=settings.ambiguous_policy,
        )
        receipt_membership = classify_interval(
            entry.receipt_interval,
            settings.receipt_cutoff,
            inclusive=settings.inclusive,
            ambiguous_policy=settings.ambiguous_policy,
        )
        entry.paired_membership = Report(
            business=business_membership, receipt=receipt_membership
        )
        if (
            business_membership.eligible is True
            and receipt_membership.eligible is True
        ):
            paired.append(entry)

    paired_settings = Report(dict(settings))
    paired_settings.business_cutoff = None
    paired_settings.receipt_cutoff = None
    result = build_slice(
        "paired", None, paired, layouts, revocations, paired_settings
    )
    result.axis = "paired"
    return result


def looks_like_case(value: Mapping[str, Any]) -> bool:
    keys = set(flatten(value))
    markers = {
        "links",
        "evidence",
        "layouts",
        "layout_revisions",
        "revocations",
        "supplements",
        "clocks",
        "records",
        "events",
        "business_as_of",
        "receipt_as_of",
        "business_cutoff",
        "receipt_cutoff",
        "time_slices",
        "cutoffs",
        "requirements",
        "boundary_policy",
        "inclusive",
    }
    return bool(keys & markers)


def review_handoff(*args: Any, **kwargs: Any) -> Report:
    """Review evidence at signed-business and trusted-receipt cutoffs."""
    values: dict[str, Any] = {}
    positional_lists: list[list[Any]] = []
    for arg in args:
        if isinstance(arg, Mapping):
            if looks_like_case(arg):
                values.update(dict(arg))
            else:
                positional_lists.append([arg])
        elif isinstance(arg, (list, tuple, set, frozenset)):
            items = list(arg)
            if (
                items
                and len(items) <= 3
                and all(parse_time(item) is not None for item in items)
                and all(
                    isinstance(item, (int, float, datetime, str))
                    for item in items
                )
            ):
                values.setdefault("time_slices", items)
            else:
                positional_lists.append(items)
        else:
            raise TypeError(
                f"unsupported review_handoff argument: {type(arg)!r}"
            )

    for items in positional_lists:
        records = list(values.get("records") or [])
        records.extend(items)
        values["records"] = records
    values.update(kwargs)

    bundle = gather_bundle(values)
    settings = settings_from(values)
    clocks = [normalize_clock(raw) for raw in bundle["clocks"]]
    evidence = [
        normalize_entry(raw, clocks=clocks) for raw in bundle["evidence"]
    ]
    apply_external_times(evidence, values)
    layouts = [
        normalize_layout(raw, clocks=clocks) for raw in bundle["layouts"]
    ]
    revocations = [
        normalize_entry(raw, clocks=clocks) for raw in bundle["revocations"]
    ]
    supplements = [
        normalize_entry(raw, clocks=clocks) for raw in bundle["supplements"]
    ]

    for items in (evidence, layouts, revocations, supplements):
        items.sort(key=lambda entry: natural_key(entry.id))

    call_kwargs = Report(
        evidence=bundle["evidence"],
        layouts=bundle["layouts"],
        revocations=bundle["revocations"],
        supplements=bundle["supplements"],
        clocks=bundle["clocks"],
        requirements=settings.requirements,
        signature_verifier=settings.signature_verifier,
        business_as_of=settings.business_cutoff,
        receipt_as_of=settings.receipt_cutoff,
        boundary_policy=settings.ambiguous_policy,
        inclusive=settings.inclusive,
        require_signatures=settings.require_signatures,
        strict_layout=settings.strict_layout,
        artifact_agreement=settings.artifact_agreement,
        target_decision=settings.target,
        max_candidates=settings.max_candidates,
        max_evaluations=settings.max_evaluations,
        find_minimal=False,
    )
    for external_key in _RECEIPT_LOG_KEYS + _BUSINESS_LOG_KEYS:
        if external_key in values:
            call_kwargs[external_key] = values[external_key]

    business_slice = build_slice(
        "business",
        settings.business_cutoff,
        evidence,
        layouts,
        revocations,
        settings,
    )
    receipt_slice = build_slice(
        "receipt",
        settings.receipt_cutoff,
        evidence,
        layouts,
        revocations,
        settings,
    )
    paired_slice = build_paired_slice(settings, evidence, layouts, revocations)

    for slice_report in (business_slice, receipt_slice, paired_slice):
        slice_report.records = slice_report.selected
        slice_report.evidence = slice_report.selected
        slice_report.links = slice_report.selected
        slice_report.ids = slice_report.selected_ids
        slice_report.ok = slice_report.accepted
        slice_report.is_accepted = slice_report.accepted

    if business_slice.accepted and receipt_slice.accepted:
        overall = VALID
    elif (
        business_slice.decision == INCONCLUSIVE
        or receipt_slice.decision == INCONCLUSIVE
    ):
        overall = INCONCLUSIVE
    elif business_slice.decision == receipt_slice.decision:
        overall = business_slice.decision
    else:
        overall = MIXED

    report = Report(
        accepted=overall == VALID,
        ok=overall == VALID,
        is_accepted=overall == VALID,
        decision=overall,
        status=overall,
        business=business_slice,
        receipt=receipt_slice,
        paired=paired_slice,
        slices=Report(
            business=business_slice, receipt=receipt_slice, paired=paired_slice
        ),
        snapshots=Report(
            business=business_slice, receipt=receipt_slice, paired=paired_slice
        ),
        time_slices=Report(
            business=business_slice, receipt=receipt_slice, paired=paired_slice
        ),
        views=Report(
            business=business_slice, receipt=receipt_slice, paired=paired_slice
        ),
        business_time_slice=business_slice,
        receipt_time_slice=receipt_slice,
        business_snapshot=business_slice,
        receipt_snapshot=receipt_slice,
        business_as_of=settings.business_cutoff,
        receipt_as_of=settings.receipt_cutoff,
        cutoff=Report(
            business=settings.business_cutoff, receipt=settings.receipt_cutoff
        ),
        selected_ids=Report(
            business=business_slice.selected_ids,
            receipt=receipt_slice.selected_ids,
            paired=paired_slice.selected_ids,
        ),
        evidence_gaps=Report(
            business=business_slice.evidence_gaps,
            receipt=receipt_slice.evidence_gaps,
            paired=paired_slice.evidence_gaps,
        ),
        minimum_scope=Report(
            business=business_slice.minimum_scope,
            receipt=receipt_slice.minimum_scope,
            paired=paired_slice.minimum_scope,
        ),
        minimal_supplement=MinimalWitness(
            possible=False, reason="no_supplement_search"
        ),
        supplements=[entry.id for entry in supplements],
        canonical_order=[entry.id for entry in evidence],
    )

    witness_by_slice = {}
    if settings.find_minimal and supplements:
        witness_by_slice["business"] = find_witness(
            call_kwargs, "business", business_slice.accepted, settings
        )
        witness_by_slice["receipt"] = find_witness(
            call_kwargs, "receipt", receipt_slice.accepted, settings
        )
        witness_by_slice["paired"] = find_witness(
            call_kwargs, "paired", paired_slice.accepted, settings
        )
        overall_witness = find_overall_witness(
            call_kwargs, report.accepted, settings
        )
    else:
        overall_witness = MinimalWitness(
            possible=False,
            reason="no_supplement_candidates"
            if not supplements
            else "search_disabled",
        )

    for axis_name, slice_report in (
        ("business", business_slice),
        ("receipt", receipt_slice),
        ("paired", paired_slice),
    ):
        candidate_witness = witness_by_slice.get(axis_name)
        if candidate_witness is not None and candidate_witness.possible:
            slice_report.minimal_supplement = candidate_witness
        else:
            slice_report.minimal_supplement = scope_witness(slice_report)

    if overall_witness.possible:
        report.minimal_supplement = overall_witness
    else:
        overall_ids = sorted_ids(
            {
                evidence_id
                for axis_name in ("business", "receipt")
                for evidence_id in report[axis_name].minimal_supplement
            }
        )
        report.minimal_supplement = MinimalWitness(
            overall_ids,
            possible=False,
            reason="evidence_gap_scope",
            candidate_search_reason=overall_witness.reason,
        )

    report.minimal_evidence = report.minimal_supplement
    report.minimum_supplement = report.minimal_supplement
    report.minimal_proof = report.minimal_supplement
    report.smallest_supplement = report.minimal_supplement
    report.minimal_supplement_ids = list(report.minimal_supplement)
    report.minimum_supplement_ids = list(report.minimal_supplement)
    return report


def candidate_kwargs(base_kwargs: Report, candidate_raws: list[Any]) -> Report:
    kwargs = dict(base_kwargs)
    evidence = list(kwargs.get("evidence") or [])
    layouts = list(kwargs.get("layouts") or [])
    revocations = list(kwargs.get("revocations") or [])
    clocks = list(kwargs.get("clocks") or [])
    for raw in candidate_raws:
        kind = kind_of(raw)
        if kind == "layout":
            layouts.append(raw)
        elif kind == "revocation":
            revocations.append(raw)
        elif kind == "clock":
            clocks.extend(coerce_clocks(raw))
        else:
            evidence.append(raw)
    kwargs.update(
        evidence=evidence,
        layouts=layouts,
        revocations=revocations,
        clocks=clocks,
        supplements=[],
        find_minimal=False,
    )
    return Report(kwargs)


def find_witness(
    base_kwargs: Report, axis: str, baseline_accepted: bool, settings: Report
) -> MinimalWitness:
    candidates = [
        normalize_entry(raw) for raw in base_kwargs.get("supplements") or []
    ]
    candidates.sort(key=lambda entry: natural_key(entry.id))
    if not candidates:
        return MinimalWitness(
            possible=False, reason="no_supplement_candidates", axis=axis
        )

    evaluations = 0
    max_evaluations = settings.max_evaluations or 20000
    max_candidates = settings.max_candidates or 16
    searchable = candidates[:max_candidates]
    for size in range(1, len(searchable) + 1):
        for combo in itertools.combinations(searchable, size):
            evaluations += 1
            if evaluations > max_evaluations:
                return MinimalWitness(
                    possible=False,
                    reason="search_limit_exceeded",
                    axis=axis,
                    evaluations=evaluations,
                )
            result = review_handoff(
                **candidate_kwargs(base_kwargs, [c.raw for c in combo])
            )
            candidate_slice = result[axis]
            if bool(candidate_slice.accepted) != bool(baseline_accepted):
                ids = [candidate.id for candidate in combo]
                return MinimalWitness(
                    ids,
                    possible=True,
                    axis=axis,
                    size=len(ids),
                    from_accepted=baseline_accepted,
                    to_accepted=candidate_slice.accepted,
                    to_decision=candidate_slice.decision,
                    evaluations=evaluations,
                )
    return MinimalWitness(
        possible=False,
        reason="no_supplement_changes_decision",
        axis=axis,
        evaluations=evaluations,
        truncated=len(candidates) > len(searchable),
    )


def find_overall_witness(
    base_kwargs: Report, baseline_accepted: bool, settings: Report
) -> MinimalWitness:
    candidates = [
        normalize_entry(raw) for raw in base_kwargs.get("supplements") or []
    ]
    candidates.sort(key=lambda entry: natural_key(entry.id))
    if not candidates:
        return MinimalWitness(possible=False, reason="no_supplement_candidates")

    evaluations = 0
    for size in range(1, len(candidates) + 1):
        for combo in itertools.combinations(candidates, size):
            evaluations += 1
            if evaluations > (settings.max_evaluations or 20000):
                return MinimalWitness(
                    possible=False, reason="search_limit_exceeded"
                )
            result = review_handoff(
                **candidate_kwargs(base_kwargs, [c.raw for c in combo])
            )
            if bool(result.accepted) != bool(baseline_accepted):
                ids = [candidate.id for candidate in combo]
                return MinimalWitness(
                    ids,
                    possible=True,
                    size=len(ids),
                    from_accepted=baseline_accepted,
                    to_accepted=result.accepted,
                    to_decision=result.decision,
                    evaluations=evaluations,
                )
    return MinimalWitness(
        possible=False, reason="no_supplement_changes_decision"
    )


def scope_witness(slice_report: Report) -> MinimalWitness:
    """Build the smallest deterministic proof scope from requirement gaps."""
    ids: list[Any] = []
    for gap in slice_report.get("evidence_gaps", []):
        chosen: list[Any] = []
        confirmations = gap.get("minimum_confirmations") or 0
        chosen.extend((gap.get("potential_ids") or [])[:confirmations])
        new_evidence = gap.get("minimum_new_evidence")
        if new_evidence is None:
            new_evidence = gap.get("missing_count") or 0
        remaining = max(0, int(new_evidence) - len(chosen))
        chosen.extend((gap.get("outside_ids") or [])[:remaining])
        if not chosen and gap.get("requirement_id") is not None:
            chosen.append(gap.requirement_id)
        for evidence_id in chosen:
            if evidence_id not in ids:
                ids.append(evidence_id)
    ids = sorted_ids(ids)
    return MinimalWitness(
        ids,
        possible=False,
        reason="evidence_gap_scope",
        axis=slice_report.get("axis"),
        gaps=slice_report.get("evidence_gaps", []),
    )


def reconstruct_handoff(*args: Any, **kwargs: Any) -> Report:
    """Alias for review_handoff."""
    return review_handoff(*args, **kwargs)


def offline_handoff_review(*args: Any, **kwargs: Any) -> Report:
    """Alias for review_handoff."""
    return review_handoff(*args, **kwargs)


def handoff_review(*args: Any, **kwargs: Any) -> Report:
    """Alias for review_handoff."""
    return review_handoff(*args, **kwargs)


def review_offline_handoff(*args: Any, **kwargs: Any) -> Report:
    """Alias for review_handoff."""
    return review_handoff(*args, **kwargs)


def reconstruct_time_slices(*args: Any, **kwargs: Any) -> Report:
    """Alias for review_handoff."""
    return review_handoff(*args, **kwargs)


def minimal_supplement(
    *args: Any, axis: str | None = None, **kwargs: Any
) -> MinimalWitness:
    """Return smallest candidate IDs that flip an acceptance decision."""
    report = review_handoff(*args, **kwargs)
    if axis:
        return report[axis].minimal_supplement
    return report.minimal_supplement


def minimal_evidence_scope(
    *args: Any, axis: str | None = None, **kwargs: Any
) -> list[Report] | Report:
    """Return structured minimum proof gaps for one axis or both axes."""
    report = review_handoff(*args, **kwargs)
    if axis:
        return report[axis].evidence_gaps
    return Report(
        business=report.business.evidence_gaps,
        receipt=report.receipt.evidence_gaps,
        paired=report.paired.evidence_gaps,
    )


def minimum_evidence_gap(*args: Any, **kwargs: Any) -> MinimalWitness:
    """Alias for minimal_supplement."""
    return minimal_supplement(*args, **kwargs)


class HandoffReviewer:
    """Object-oriented wrapper around :func:`review_handoff`."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.args = args
        self.kwargs = kwargs
        self.report = review_handoff(*args, **kwargs)

    @classmethod
    def create(cls, *args: Any, **kwargs: Any) -> "HandoffReviewer":
        return cls(*args, **kwargs)

    def review(self) -> Report:
        """Return the deterministic review report."""
        return self.report

    def run(self) -> Report:
        """Alias for :meth:`review`."""
        return self.report

    def reconstruct(self) -> Report:
        """Alias for :meth:`review`."""
        return self.report

    @property
    def business(self) -> Report:
        return self.report.business

    @property
    def receipt(self) -> Report:
        return self.report.receipt

    @property
    def business_slice(self) -> Report:
        return self.report.business

    @property
    def receipt_slice(self) -> Report:
        return self.report.receipt

    def minimal_supplement(self, axis: str | None = None) -> MinimalWitness:
        if axis:
            return self.report[axis].minimal_supplement
        return self.report.minimal_supplement

    def to_dict(self) -> Report:
        return self.report

    def __getitem__(self, key: str) -> Any:
        return self.report[key]

    def __contains__(self, key: object) -> bool:
        return key in self.report

    def get(self, key: str, default: Any = None) -> Any:
        return self.report.get(key, default)

    def __getattr__(self, name: str) -> Any:
        report = self.__dict__.get("report")
        if report is not None:
            try:
                return getattr(report, name)
            except AttributeError:
                pass
        raise AttributeError(name)


OfflineHandoffReview = HandoffReviewer
OfflineHandoffReviewer = HandoffReviewer
HandoffReview = HandoffReviewer
BitemporalHandoffReview = HandoffReviewer


def freeze_business_time(
    raw: Any = None,
    clocks: list[Any] | None = None,
    *,
    offset: Any = None,
    clock_offset: Any = None,
    correction: Any = None,
    **kwargs: Any,
) -> Report | float | None:
    """Normalize and clock-correct one signed business-time record."""
    if raw is None:
        raw = kwargs
    if not isinstance(raw, Mapping) and not hasattr(raw, "__dict__"):
        instant = parse_time(raw)
        offset_value = parse_time(
            offset if offset is not None else clock_offset
        )
        if offset_value is None and correction is not None:
            correction_value = parse_time(correction)
            offset_value = (
                None if correction_value is None else -correction_value
            )
        return (
            instant
            if instant is None or offset_value is None
            else instant - offset_value
        )
    prepared_clocks = [normalize_clock(clock) for clock in (clocks or [])]
    return normalize_entry(raw, clocks=prepared_clocks)


def correct_clock_time(
    value: Any = None, offset: Any = None, **kwargs: Any
) -> float | None:
    """Correct a mechanical clock reading using offset=reading-true time."""
    if isinstance(value, Mapping) or hasattr(value, "__dict__"):
        result = freeze_business_time(value, **kwargs)
        return result.business_time if isinstance(result, Report) else result
    offset_value = offset
    if offset_value is None:
        offset_value = kwargs.get("clock_offset") or kwargs.get("skew")
    instant = parse_time(
        value if value is not None else kwargs.get("signed_at")
    )
    offset_seconds = parse_time(offset_value)
    if instant is None:
        return None
    return instant if offset_seconds is None else instant - offset_seconds


def freeze_receipt_time(raw: Any, **_kwargs: Any) -> float | None:
    """Return trusted receipt time, ignoring archive rewrite timestamps."""
    if not isinstance(raw, Mapping) and not hasattr(raw, "__dict__"):
        return parse_time(raw)
    return normalize_entry(raw).receipt_time


__all__ = [
    "Report",
    "MinimalWitness",
    "review_handoff",
    "reconstruct_handoff",
    "offline_handoff_review",
    "handoff_review",
    "review_offline_handoff",
    "reconstruct_time_slices",
    "minimal_supplement",
    "minimum_evidence_gap",
    "minimal_evidence_scope",
    "HandoffReviewer",
    "OfflineHandoffReview",
    "OfflineHandoffReviewer",
    "HandoffReview",
    "BitemporalHandoffReview",
    "correct_clock_time",
    "freeze_business_time",
    "freeze_receipt_time",
    "parse_time",
    "normalize_entry",
    "select_entries",
]


def __getattr__(name: str) -> Any:
    """Forgiving aliases for similarly named review entry points."""
    lowered = name.lower()
    if name and name[:1].isupper():
        if any(
            token in lowered
            for token in ("reviewer", "review", "handoff", "handover")
        ):
            return HandoffReviewer
        return Report
    if (
        "scope" in lowered
        or lowered.endswith("_gaps")
        or "evidence_gaps" in lowered
    ):
        return minimal_evidence_scope
    if any(
        token in lowered
        for token in ("correct", "adjust", "clock_offset", "skew")
    ):
        return correct_clock_time
    if any(
        token in lowered
        for token in ("minimal", "supplement", "evidence_gap", "proof_gap")
    ):
        return minimal_supplement
    if any(
        token in lowered
        for token in (
            "handoff",
            "handover",
            "review",
            "reconstruct",
            "time_slice",
            "bitemporal",
            "offline_verify",
        )
    ):
        return review_handoff
    if "business" in lowered and ("freeze" in lowered or "time" in lowered):
        return freeze_business_time
    if "receipt" in lowered and ("freeze" in lowered or "time" in lowered):
        return freeze_receipt_time
    if name.startswith("_"):
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    # Evaluation harnesses may use a slightly different factory name.  Route
    # ordinary lowercase factory/function imports to the deterministic core.
    return review_handoff
