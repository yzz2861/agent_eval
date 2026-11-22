"""
Offline re-verification layer for plugin-produced local timestamps.

Many registry plugins report timestamps as *local* wall-clock times of the analyzed host, while other fields are
already UTC. When the host's timezone was changed during its lifetime - or the timezone history is only partially
known - converting those local times with the *analyst machine's* timezone silently misplaces events (a +/-30 min
event can land on another day).

This module re-verifies plugin output offline, without touching the hive or the original values: the caller declares
which entry fields actually hold local times and supplies the confirmed UTC-offset evidence per time segment (e.g.
derived from the ``timezone_data2`` plugin, Windows event logs or other corroborating sources). Every reviewed value
is turned into an explicit set of UTC candidates, each backed by the evidence that produced it:

- Clock rollbacks (offset changes that make a local interval happen twice) naturally yield *multiple* candidates for
  observations inside the repeated window.
- Gaps in the timezone history yield *unresolved* values instead of a silently wrong conversion.
- Fields that are already UTC are passed through (normalized), never converted.
- The original value is always preserved verbatim under ``raw_value`` so it can be traced back to the plugin output.
"""

import datetime as dt
import logging
from collections.abc import Sequence
from typing import Any, Optional, Union

from regipy.plugins.utils import run_relevant_plugins

logger = logging.getLogger(__name__)

# A timestamp as found in plugin output: ISO-8601 string or datetime object.
TimeLike = Union[str, dt.datetime]

# Key under which the per-field review report is attached to a reviewed entry.
TIME_REVIEW_KEY = "time_review"

# Review statuses for local-time fields.
STATUS_RESOLVED = "resolved"  # Exactly one UTC candidate
STATUS_AMBIGUOUS = "ambiguous"  # Multiple UTC candidates (e.g. clock rollback repeated window)
STATUS_UNRESOLVED = "unresolved"  # No confirmed offset segment covers the value
STATUS_UTC_PASSTHROUGH = "utc_passthrough"  # Caller-declared UTC field, normalized but not converted
STATUS_INVALID = "invalid"  # Unparseable or self-contradictory value, raw value preserved


class TimezoneReviewError(ValueError):
    """Raised on inconsistent caller-supplied review configuration."""


class OffsetSegment:
    """
    One confirmed piece of UTC-offset evidence for the analyzed host.

    Bounds are expressed in UTC - the only monotonic reference when the local clock was changed. An open bound
    (None) means "unknown", which deliberately widens the candidate set instead of guessing.
    """

    def __init__(
        self,
        offset_minutes: int,
        evidence: str,
        start_utc: Optional[TimeLike] = None,
        end_utc: Optional[TimeLike] = None,
    ):
        self.offset_minutes = int(offset_minutes)
        self.evidence = str(evidence)
        self.start_utc = start_utc
        self.end_utc = end_utc

    def __repr__(self):
        return (
            f"OffsetSegment(offset_minutes={self.offset_minutes}, evidence={self.evidence!r}, "
            f"start_utc={self.start_utc!r}, end_utc={self.end_utc!r})"
        )


def _parse_datetime(value: TimeLike) -> dt.datetime:
    if isinstance(value, dt.datetime):
        return value
    if isinstance(value, str):
        text = value.strip()
        # datetime.fromisoformat on Python 3.9 does not accept the "Z" suffix
        if text.endswith(("Z", "z")):
            text = f"{text[:-1]}+00:00"
        return dt.datetime.fromisoformat(text)
    raise TypeError(f"Unsupported timestamp type: {type(value)!r}")


def _as_utc(value: TimeLike) -> dt.datetime:
    """Parse a timestamp and normalize it to an aware UTC datetime. Naive input is assumed to be UTC."""
    parsed = _parse_datetime(value)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def _coerce_segment(segment: Union[OffsetSegment, dict[str, Any]]) -> OffsetSegment:
    if isinstance(segment, OffsetSegment):
        return segment
    if isinstance(segment, dict):
        return OffsetSegment(
            offset_minutes=segment["offset_minutes"],
            evidence=segment["evidence"],
            start_utc=segment.get("start_utc"),
            end_utc=segment.get("end_utc"),
        )
    raise TypeError(f"Unsupported offset segment: {segment!r}")


def _segment_covers(segment: OffsetSegment, candidate_utc: dt.datetime) -> bool:
    start = _as_utc(segment.start_utc) if segment.start_utc is not None else None
    end = _as_utc(segment.end_utc) if segment.end_utc is not None else None
    if start is not None and candidate_utc < start:
        return False
    return not (end is not None and candidate_utc >= end)


def review_local_value(
    value: TimeLike,
    offset_segments: Sequence[Union[OffsetSegment, dict[str, Any]]],
) -> dict[str, Any]:
    """
    Turn one local-time value into an evidence-backed set of UTC candidates.

    A candidate is produced for every offset segment whose confirmed UTC validity interval contains
    ``value - offset``. The result is always JSON-serializable and never raises on bad input - unparseable values
    are reported with ``status == "invalid"`` and the raw value preserved.
    """
    raw_value = value
    try:
        parsed = _parse_datetime(value)
    except (TypeError, ValueError) as ex:
        logger.warning(f"Could not parse local timestamp {value!r}: {ex}")
        return {"status": STATUS_INVALID, "raw_value": raw_value, "reason": str(ex), "candidates": []}

    if parsed.tzinfo is not None:
        reason = "Value already carries timezone info; declare the field as a UTC field instead"
        logger.warning(f"{reason}: {value!r}")
        return {"status": STATUS_INVALID, "raw_value": raw_value, "reason": reason, "candidates": []}

    candidates_by_utc: dict[dt.datetime, dict[str, Any]] = {}
    for segment in [_coerce_segment(s) for s in offset_segments]:
        candidate_utc = (parsed - dt.timedelta(minutes=segment.offset_minutes)).replace(tzinfo=dt.timezone.utc)
        if not _segment_covers(segment, candidate_utc):
            continue
        candidate = candidates_by_utc.setdefault(candidate_utc, {"offset_minutes": segment.offset_minutes, "evidence": []})
        if segment.evidence not in candidate["evidence"]:
            candidate["evidence"].append(segment.evidence)

    candidates = [
        {"utc": candidate_utc.isoformat(), **candidates_by_utc[candidate_utc]} for candidate_utc in sorted(candidates_by_utc)
    ]

    if not candidates:
        status = STATUS_UNRESOLVED
    elif len(candidates) == 1:
        status = STATUS_RESOLVED
    else:
        status = STATUS_AMBIGUOUS

    return {"status": status, "raw_value": raw_value, "candidates": candidates}


def review_utc_value(value: TimeLike) -> dict[str, Any]:
    """Normalize a caller-declared UTC value without converting it. Naive input is flagged with assumed_utc."""
    raw_value = value
    try:
        parsed = _parse_datetime(value)
    except (TypeError, ValueError) as ex:
        logger.warning(f"Could not parse UTC timestamp {value!r}: {ex}")
        return {"status": STATUS_INVALID, "raw_value": raw_value, "reason": str(ex)}

    result: dict[str, Any] = {
        "status": STATUS_UTC_PASSTHROUGH,
        "raw_value": raw_value,
        "utc": _as_utc(parsed).isoformat(),
    }
    if parsed.tzinfo is None:
        result["assumed_utc"] = True
    return result


def review_entry(
    entry: dict[str, Any],
    local_time_fields: Sequence[str],
    offset_segments: Sequence[Union[OffsetSegment, dict[str, Any]]],
    utc_fields: Sequence[str] = (),
) -> dict[str, Any]:
    """
    Review one plugin entry. The input entry is never mutated; the returned copy carries a ``time_review`` block
    with one report per declared field, and every original field (and raw value) stays intact.
    """
    reviewed = dict(entry)
    report: dict[str, Any] = {}
    for field_name in local_time_fields:
        if field_name in entry:
            report[field_name] = review_local_value(entry[field_name], offset_segments)
    for field_name in utc_fields:
        if field_name in entry:
            report[field_name] = review_utc_value(entry[field_name])
    if report:
        reviewed[TIME_REVIEW_KEY] = report
    return reviewed


def review_entries(
    entries: Sequence[dict[str, Any]],
    local_time_fields: Sequence[str],
    offset_segments: Sequence[Union[OffsetSegment, dict[str, Any]]],
    utc_fields: Sequence[str] = (),
) -> list:
    """Review a list of plugin entries (the shape of ``Plugin.entries`` for most plugins)."""
    overlap = set(local_time_fields) & set(utc_fields)
    if overlap:
        raise TimezoneReviewError(f"Fields declared as both local and UTC: {sorted(overlap)}")
    segments = [_coerce_segment(s) for s in offset_segments]
    return [
        review_entry(entry, local_time_fields, segments, utc_fields) if isinstance(entry, dict) else entry for entry in entries
    ]


def review_plugin_results(
    plugin_results: dict[str, Any],
    local_time_fields: Sequence[str],
    offset_segments: Sequence[Union[OffsetSegment, dict[str, Any]]],
    utc_fields: Sequence[str] = (),
) -> dict[str, Any]:
    """
    Review the output of ``regipy.plugins.utils.run_relevant_plugins`` (a plugin name -> entries mapping).
    List-shaped entries are reviewed; dict-shaped plugin output and error records pass through untouched.
    """
    reviewed: dict[str, Any] = {}
    for plugin_name, entries in plugin_results.items():
        if isinstance(entries, list):
            reviewed[plugin_name] = review_entries(entries, local_time_fields, offset_segments, utc_fields=utc_fields)
        else:
            reviewed[plugin_name] = entries
    return reviewed


def run_plugins_with_time_review(
    registry_hive,
    local_time_fields: Sequence[str],
    offset_segments: Sequence[Union[OffsetSegment, dict[str, Any]]],
    utc_fields: Sequence[str] = (),
    plugins: Optional[Sequence[str]] = None,
    include_unvalidated: bool = False,
    continue_on_error: bool = False,
) -> dict[str, Any]:
    """
    Run regipy's existing plugin entry point on an offline hive and re-verify the local timestamps in the output.

    Plugins are executed with ``as_json=True`` so the reviewed result is deterministic and JSON-serializable.
    """
    plugin_results = run_relevant_plugins(
        registry_hive,
        as_json=True,
        plugins=list(plugins) if plugins else None,
        include_unvalidated=include_unvalidated,
        continue_on_error=continue_on_error,
    )
    return review_plugin_results(plugin_results, local_time_fields, offset_segments, utc_fields=utc_fields)
