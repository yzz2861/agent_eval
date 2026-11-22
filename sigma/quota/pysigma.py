"""Adapter turning pySigma match results into quota observations."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Callable, Iterable

from sigma.quota.types import CallerHints, Observation

if TYPE_CHECKING:
    from sigma.matching.event import Event
    from sigma.matching.match import SigmaMatch

IdentityFn = Callable[[dict[str, Any]], str]
GroupFn = Callable[[dict[str, Any]], str]
ExemptFn = Callable[[dict[str, Any]], bool]
TimestampFn = Callable[[dict[str, Any]], datetime]


def _field_lookup(field: str) -> Callable[[dict[str, Any]], Any]:
    def lookup(data: dict[str, Any]) -> Any:
        if field in data:
            return data[field]
        for value in data.values():
            if isinstance(value, dict) and field in value:
                return value[field]
        return None

    return lookup


def _coerce_identity(fn: IdentityFn | str) -> IdentityFn:
    if callable(fn):
        return fn
    lookup = _field_lookup(fn)
    return lambda data: str(lookup(data))


def _coerce_group(fn: GroupFn | str) -> GroupFn:
    if callable(fn):
        return fn
    lookup = _field_lookup(fn)
    return lambda data: str(lookup(data))


def _coerce_exempt(fn: ExemptFn | str) -> ExemptFn:
    if callable(fn):
        return fn
    lookup = _field_lookup(fn)
    return lambda data: bool(lookup(data))


def _coerce_timestamp(fn: TimestampFn | str | None) -> TimestampFn:
    if callable(fn):
        return fn
    if fn is None:
        return lambda data: datetime.now(tz=timezone.utc)
    lookup = _field_lookup(fn)

    def read(data: dict[str, Any]) -> datetime:
        value = lookup(data)
        if isinstance(value, datetime):
            return value
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value, tz=timezone.utc)
        if isinstance(value, str):
            normalized = value.replace("Z", "+00:00")
            parsed = datetime.fromisoformat(normalized)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed
        raise ValueError(f"cannot interpret timestamp value: {value!r}")

    return read


def observation_from_event(
    event: Event,
    hints: CallerHints,
    *,
    ingest_time: datetime | None = None,
    rule_name: str = "sigma_rule",
) -> Observation:
    """Build one observation from an already matched pySigma ``Event``."""
    data = event.data
    identity_fn = _coerce_identity(hints.identity_field)
    group_fn = _coerce_group(hints.group_field)
    exempt_fn = _coerce_exempt(hints.exempt_scope)
    timestamp_fn = _coerce_timestamp(hints.timestamp_field)
    event_id = identity_fn(data)
    if not event_id or event_id == "None":
        raise ValueError("event identity resolved to an empty value")
    when = timestamp_fn(data) if hints.timestamp_field else event.timestamp
    received = ingest_time or datetime.now(tz=timezone.utc)
    return Observation(
        event_id=event_id,
        group_key=group_fn(data),
        event_time=when,
        ingest_time=received,
        exempt=exempt_fn(data),
        rule_name=rule_name,
        source="pysigma",
        raw=event.raw,
    )


def observations_from_matches(
    matches: Iterable[SigmaMatch],
    hints: CallerHints,
    *,
    ingest_times: Iterable[datetime] | None = None,
) -> list[Observation]:
    """Flatten pySigma ``SigmaMatch`` objects into observations.

    A single correlation match can carry several events (for example the same
    event forwarded by two collectors), so every enclosed ``Event`` is mapped
    separately. Duplicate identities are kept here; the reconciler suppresses
    double quota deduction.
    """
    ingest_iter = iter(ingest_times) if ingest_times is not None else None
    observations: list[Observation] = []
    for match in matches:
        rule_name = getattr(match.rule, "name", match.rule.__class__.__name__) or "sigma_rule"
        for event in match.events:
            ingest_time = next(ingest_iter) if ingest_iter is not None else None
            observations.append(
                observation_from_event(
                    event, hints, ingest_time=ingest_time, rule_name=str(rule_name)
                )
            )
    return observations


def observations_from_dicts(
    records: Iterable[dict[str, Any]],
    hints: CallerHints,
    *,
    ingest_field: str | None = None,
) -> list[Observation]:
    """Build observations from plain event dicts (e.g. serialized matches)."""
    observations: list[Observation] = []
    timestamp_fn = _coerce_timestamp(hints.timestamp_field)
    identity_fn = _coerce_identity(hints.identity_field)
    group_fn = _coerce_group(hints.group_field)
    exempt_fn = _coerce_exempt(hints.exempt_scope)
    for record in records:
        event_time = timestamp_fn(record) if hints.timestamp_field else datetime.now(
            tz=timezone.utc
        )
        ingest_time = (
            _coerce_timestamp(ingest_field)(record)
            if ingest_field
            else datetime.now(tz=timezone.utc)
        )
        event_id = identity_fn(record)
        if not event_id or event_id == "None":
            raise ValueError("event identity resolved to an empty value")
        observations.append(
            Observation(
                event_id=event_id,
                group_key=group_fn(record),
                event_time=event_time,
                ingest_time=ingest_time,
                exempt=exempt_fn(record),
                rule_name=str(record.get("rule_name", "sigma_rule")),
                source=str(record.get("source", "dict")),
            )
        )
    return observations
