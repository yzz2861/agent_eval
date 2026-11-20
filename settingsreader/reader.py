"""Offline reader for the two redundant security settings regions.

The device keeps two copies of its security settings table and alternates
between them.  A write interrupted by a power loss can leave the newest copy
half written or without its commit marker, while the previous copy is still
intact.  Picking "the copy with the largest counter" is therefore unsafe and
can describe an uncommitted configuration as active.

This module only reads.  It parses both regions with a caller supplied cstruct
layout, derives the provable write state of each region and selects an active
candidate using wrap-aware generation comparison.  Everything that cannot be
proven to be committed is returned as evidence only.
"""

from __future__ import annotations

import io
import os
from typing import BinaryIO

from settingsreader.model import (
    ChecksumRule,
    ChecksumStatus,
    RegionObservation,
    SelectionResult,
    TableLayout,
    WriteState,
)



def read_settings(source: BinaryIO | str | bytes | os.PathLike, layout: TableLayout) -> SelectionResult:
    """Read both settings regions and select the provably active table.

    Args:
        source: A seekable binary stream, a filesystem path, an ``os.PathLike``
            or the raw image bytes.  Paths are opened read-only, so the image
            is never modified.
        layout: Caller supplied table layout and decision rules.

    Returns:
        A :class:`SelectionResult` describing both regions and the active
        candidate.  When no region is provably committed the active candidate
        is ``None`` and every parsed region is reported as evidence only.
    """
    if isinstance(source, (bytes, bytearray, memoryview)):
        stream = io.BytesIO(bytes(source))
    elif hasattr(source, "read"):
        stream = source
    else:
        stream = open(os.fspath(source), "rb")
    try:
        return _read_stream(stream, layout)
    finally:
        if stream is not source:
            stream.close()


def select_active(
    observations: list[RegionObservation] | tuple[RegionObservation, ...],
    layout: TableLayout,
) -> tuple[int | None, bool]:
    """Select the active region using wrap-aware generation comparison.

    Only committed regions participate.  Generations are compared on a
    circular counter: with modulus ``m``, ``candidate`` is newer than the
    current winner when ``(candidate - winner) mod m`` lands in the first half
    of the counter range.  A distance of exactly half a turn cannot be
    disambiguated and counts as a tie; ties are broken deterministically by
    keeping the region with the lowest index while flagging ``tie``.

    Args:
        observations: Region observations in layout order.
        layout: Layout supplying the generation modulus.

    Returns:
        A ``(active_index, tie)`` tuple; ``active_index`` is ``None`` when no
        committed region exists.
    """
    committed = [region for region in observations if region.is_committed]
    if not committed:
        return None, False

    modulus = layout.modulus
    winner = committed[0]
    tie = False
    for candidate in committed[1:]:
        relation = _generation_relation(winner.generation, candidate.generation, modulus)
        if relation > 0:
            winner = candidate
            tie = False
        elif relation == 0:
            tie = True

    return winner.index, tie


def _generation_relation(current: int, candidate: int, modulus: int) -> int:
    """Compare two generations on a wrapping counter of size ``modulus``.

    Returns ``1`` when ``candidate`` is newer, ``-1`` when it is older and
    ``0`` when the two generations are indistinguishable (equal or exactly
    half a turn apart).
    """
    forward = (candidate - current) % modulus
    if forward == 0 or forward == modulus // 2:
        return 0
    return 1 if forward < modulus // 2 else -1


def _read_stream(stream: BinaryIO, layout: TableLayout) -> SelectionResult:
    observations = [
        _read_region(stream, layout, index, offset)
        for index, offset in enumerate(layout.region_offsets)
    ]
    active_index, tie = select_active(observations, layout)
    return SelectionResult(regions=observations, active_index=active_index, tie=tie)


def _read_region(stream: BinaryIO, layout: TableLayout, index: int, offset: int) -> RegionObservation:
    stream.seek(offset)
    raw = stream.read(layout.record_size)

    observation = RegionObservation(index=index, offset=offset, state=WriteState.PARTIAL, raw=raw)
    if len(raw) < layout.record_size:
        observation.error = (
            f"region truncated: read {len(raw)} of {layout.record_size} bytes, write was interrupted"
        )
        return observation

    if _is_erased(raw, layout.erased_fill):
        observation.state = WriteState.ERASED
        observation.error = "region still holds the erased fill pattern; no write ever completed here"
        return observation

    try:
        record = layout.record_type(raw)
    except Exception as exc:
        observation.error = f"record could not be parsed: {exc.__class__.__name__}: {exc}"
        return observation

    observation.record = record
    observation.generation = getattr(record, layout.generation_field)
    observation.committed = getattr(record, layout.commit_field)

    checksum_status, checksum_error = _evaluate_checksum(raw, record, layout)
    observation.checksum_status = checksum_status
    if checksum_status in (ChecksumStatus.INVALID, ChecksumStatus.ERROR):
        observation.state = WriteState.PARTIAL
        observation.error = checksum_error
        return observation

    if observation.committed != layout.committed_value:
        observation.state = WriteState.PENDING
        observation.error = (
            f"record is intact but commit field {layout.commit_field}="
            f"{observation.committed!r} does not mark it committed; write did not reach the commit marker"
        )
        return observation

    observation.state = WriteState.COMMITTED
    observation.error = None
    return observation


def _evaluate_checksum(
    raw: bytes,
    record: object,
    layout: TableLayout,
) -> tuple[ChecksumStatus, str | None]:
    rule: ChecksumRule | None = layout.checksum_rule
    if rule is None:
        return ChecksumStatus.NOT_CONFIGURED, None
    try:
        valid = rule(raw, record)
    except Exception as exc:
        return ChecksumStatus.ERROR, f"checksum rule raised {exc.__class__.__name__}: {exc}"
    if valid:
        return ChecksumStatus.VALID, None
    stored = getattr(record, layout.checksum_field) if layout.checksum_field else "unknown"
    return ChecksumStatus.INVALID, f"stored checksum {stored!r} does not validate; write was interrupted"


def _is_erased(raw: bytes, erased_fill: int) -> bool:
    return all(byte == erased_fill for byte in raw)


__all__ = ["read_settings", "select_active"]
