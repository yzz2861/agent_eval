"""Normalize existing plugin output into adjudication :class:`Fact` objects.

Each normalizer consumes the exact entry shape produced by the corresponding
regipy plugin and emits facts whose propositions are deliberately conservative:

* AmCache ``\\Root\\File`` / ``InventoryApplicationFile`` entries prove that a
  file was *present* on the volume. AmCache alone never proves execution.
* UserAssist entries with a positive run counter support the strong
  ``execution_occurred`` proposition; zero counters are weak context only.
* BAM entries record per-SID background activity and support strong
  ``execution_occurred`` facts attributable to that SID.
* ShimCache entries only support the weak ``execution_possible`` proposition:
  the cache is populated for compatibility reasons and its flag does not
  reliably encode execution.
"""

from __future__ import annotations

import datetime as dt
from typing import Any, Callable, Optional

from regipy.evidence.models import (
    CollectionWindow,
    Fact,
    FactStrength,
    Proposition,
    UserIdentity,
)
from regipy.evidence.pathnorm import normalize_path

AMCACHE_SOURCE = "amcache"
USER_ASSIST_SOURCE = "user_assist"
BAM_SOURCE = "background_activity_moderator"
SHIMCACHE_SOURCE = "shimcache"


class SourceContext:
    """Per-source context the raw plugin entries do not carry themselves.

    ``identity`` attributes an otherwise anonymous artifact to a user (used
    for user-scoped hives such as NTUSER.DAT). ``window`` is the acquisition
    window of the source hive. Without a window the facts are still emitted,
    but cross-hive splicing will hold them back as unalignable.
    """

    def __init__(
        self,
        source: str,
        window: Optional[CollectionWindow] = None,
        identity: Optional[UserIdentity] = None,
        volume_mappings: Optional[dict[str, str]] = None,
    ) -> None:
        self.source = source
        self.window = window or CollectionWindow(source_name=source)
        self.identity = identity
        self.volume_mappings = volume_mappings


def _parse_timestamp(value: Any) -> Optional[dt.datetime]:
    if value is None or value == "":
        return None
    if isinstance(value, dt.datetime):
        return value
    parsed = dt.datetime.fromisoformat(str(value))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed


def _make_fact(
    index: int,
    context: SourceContext,
    proposition: Proposition,
    strength: FactStrength,
    path: str,
    observed_at: Optional[dt.datetime],
    identity: Optional[UserIdentity],
    raw: dict[str, Any],
    machine_wide: bool = False,
) -> Fact:
    normalized = normalize_path(path, context.volume_mappings)
    return Fact(
        fact_id=f"{context.source}:{index}",
        source=context.source,
        proposition=proposition,
        strength=strength,
        path=normalized.normalized,
        observed_at=observed_at,
        identity=identity,
        collection_window=context.window,
        machine_wide=machine_wide,
        raw=raw,
    )


def normalize_amcache(entries: list[dict[str, Any]], context: SourceContext) -> list[Fact]:
    """Normalize AmCache plugin entries into ``file_present`` facts."""
    facts: list[Fact] = []
    for index, entry in enumerate(entries):
        path = entry.get("full_path") or entry.get("name")
        if not path:
            continue
        observed_at = _parse_timestamp(entry.get("timestamp"))
        facts.append(
            _make_fact(
                index,
                context,
                Proposition.FILE_PRESENT,
                FactStrength.WEAK,
                path,
                observed_at,
                context.identity,
                entry,
                machine_wide=True,
            )
        )
    return facts


def normalize_user_assist(entries: list[dict[str, Any]], context: SourceContext) -> list[Fact]:
    """Normalize UserAssist entries into execution facts.

    A positive ``run_counter`` is required for the strong proposition: entries
    with a zero counter show the program was enumerated by Explorer, not run.
    """
    facts: list[Fact] = []
    for index, entry in enumerate(entries):
        path = entry.get("name")
        if not path:
            continue
        observed_at = _parse_timestamp(entry.get("timestamp"))
        run_counter = entry.get("run_counter")
        try:
            executed = run_counter is not None and int(run_counter) > 0
        except (TypeError, ValueError):
            executed = False
        proposition = Proposition.EXECUTION_OCCURRED if executed else Proposition.EXECUTION_POSSIBLE
        strength = FactStrength.STRONG if executed else FactStrength.WEAK
        facts.append(
            _make_fact(index, context, proposition, strength, path, observed_at, context.identity, entry)
        )
    return facts


def normalize_bam(entries: list[dict[str, Any]], context: SourceContext) -> list[Fact]:
    """Normalize BAM entries into per-SID ``execution_occurred`` facts."""
    facts: list[Fact] = []
    for index, entry in enumerate(entries):
        path = entry.get("executable")
        if not path:
            continue
        observed_at = _parse_timestamp(entry.get("timestamp"))
        sid = entry.get("sid")
        identity = UserIdentity(sid=sid) if sid else context.identity
        facts.append(
            _make_fact(
                index,
                context,
                Proposition.EXECUTION_OCCURRED,
                FactStrength.STRONG,
                path,
                observed_at,
                identity,
                entry,
            )
        )
    return facts


def normalize_shimcache(entries: list[dict[str, Any]], context: SourceContext) -> list[Fact]:
    """Normalize ShimCache entries into weak ``execution_possible`` facts."""
    facts: list[Fact] = []
    for index, entry in enumerate(entries):
        path = entry.get("path")
        if not path:
            continue
        observed_at = _parse_timestamp(entry.get("last_mod_date"))
        facts.append(
            _make_fact(
                index,
                context,
                Proposition.EXECUTION_POSSIBLE,
                FactStrength.WEAK,
                path,
                observed_at,
                context.identity,
                entry,
                machine_wide=True,
            )
        )
    return facts


Normalizer = Callable[[list[dict[str, Any]], SourceContext], list[Fact]]

NORMALIZERS: dict[str, Normalizer] = {
    AMCACHE_SOURCE: normalize_amcache,
    USER_ASSIST_SOURCE: normalize_user_assist,
    BAM_SOURCE: normalize_bam,
    SHIMCACHE_SOURCE: normalize_shimcache,
}

# Plugin ``NAME`` values are identical to the source keys above; keep an alias
# map so callers can pass plugin classes/names without memorizing conventions.
PLUGIN_NAME_TO_SOURCE = {
    "amcache": AMCACHE_SOURCE,
    "user_assist": USER_ASSIST_SOURCE,
    "background_activity_moderator": BAM_SOURCE,
    "shimcache": SHIMCACHE_SOURCE,
}
