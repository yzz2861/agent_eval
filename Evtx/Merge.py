"""
Offline, reviewable merging of multiple collections of the same Windows
Event Log (.evtx) volume, built on the block and record access interfaces
of python-evtx (Evtx.Evtx.Evtx / FileHeader / ChunkHeader / Record).

The module is deliberately offline and never modifies the input files.
Every event in the result keeps the full provenance of every physical copy
it was merged from (source file, chunk offset, record offset, sha256), so a
forensic reviewer can retrace each merge decision to bytes on disk.

Duplicate detection is content based, not record-number based:
  - record numbers are only unique within one log generation (an "era");
  - a log clear resets the counter to 1, so the same number can identify
    distinct events that must be kept side by side, not collapsed;
  - two copies of one physical record are detected by comparing the raw
    record bytes (sha256), never by record number alone.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os

import Evtx.Evtx as evtx

from .BinaryParser import ParseException
from .Evtx import InvalidRecordException

CHUNK_SIZE = 0x10000
CHUNK_HEADER_SIZE = 0x200
RECORD_MAGIC = 0x2A2A
UINT64_READ_LIMIT = 0xFFFFFFFFFFFFFFFF


# Era-boundary reason codes. Each code is a distinct, defensible claim about
# why the running record number decreased while scanning one source in order.
BOUNDARY_CIRCULAR_WRAP = "circular_buffer_wrap"
BOUNDARY_LOG_CLEAR = "log_clear_segmentation"
BOUNDARY_COUNTER_WRAPAROUND = "record_id_wraparound_at_uint64_limit"
BOUNDARY_UNRESOLVED = "unresolved_number_drop"

# Record-number reuse classification for same-number/different-byte events.
REUSE_CLEAR = "distinct_event_after_log_clear"
REUSE_CONFLICT = "unresolved_same_number_conflict"


@dataclass(frozen=True)
class SourceSpec:
    """A collection source as declared by the calling investigator."""

    path: str
    source_id: str
    description: str = ""
    collected_at: str = ""
    collector: str = ""

    def as_dict(self):
        return {
            "source_id": self.source_id,
            "path": self.path,
            "description": self.description,
            "collected_at": self.collected_at,
            "collector": self.collector,
        }


@dataclass(frozen=True)
class Provenance:
    """One physical occurrence of an event record inside one source file."""

    source_id: str
    path: str
    chunk_index: int
    chunk_offset: int
    record_offset: int
    record_num: int
    timestamp: str | None
    size: int
    sha256: str

    def as_dict(self):
        return {
            "source_id": self.source_id,
            "path": self.path,
            "chunk_index": self.chunk_index,
            "chunk_offset": self.chunk_offset,
            "record_offset": self.record_offset,
            "record_num": self.record_num,
            "timestamp": self.timestamp,
            "size": self.size,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class EraBoundary:
    """A detected point where the running record number decreased."""

    source_id: str
    chunk_index: int
    previous_record_num: int
    next_record_num: int
    previous_timestamp: str
    next_timestamp: str
    reason: str
    rationale: str

    def as_dict(self):
        return {
            "source_id": self.source_id,
            "chunk_index": self.chunk_index,
            "previous_record_num": self.previous_record_num,
            "next_record_num": self.next_record_num,
            "previous_timestamp": self.previous_timestamp,
            "next_timestamp": self.next_timestamp,
            "reason": self.reason,
            "rationale": self.rationale,
        }


@dataclass
class ChunkCoverage:
    """Parse status and claimed/observed coverage of one 64KiB chunk."""

    chunk_index: int
    chunk_offset: int
    magic_ok: bool
    checksum_ok: bool
    records_read: int
    claimed_file_first: int | None
    claimed_file_last: int | None
    claimed_log_first: int | None
    claimed_log_last: int | None
    coverage_known: bool
    error: str | None = None

    def as_dict(self):
        return {
            "chunk_index": self.chunk_index,
            "chunk_offset": self.chunk_offset,
            "magic_ok": self.magic_ok,
            "checksum_ok": self.checksum_ok,
            "records_read": self.records_read,
            "claimed_file_first_record_number": self.claimed_file_first,
            "claimed_file_last_record_number": self.claimed_file_last,
            "claimed_log_first_record_number": self.claimed_log_first,
            "claimed_log_last_record_number": self.claimed_log_last,
            "coverage_known": self.coverage_known,
            "error": self.error,
        }


@dataclass
class ScannedSource:
    """The structured, reviewable result of scanning one EVTX file."""

    spec: SourceSpec
    file_sha256: str
    file_size: int
    next_record_number: int
    oldest_chunk: int
    current_chunk_number: int
    chunk_coverage: list[ChunkCoverage] = field(default_factory=list)
    provenance: list[Provenance] = field(default_factory=list)
    boundaries: list[EraBoundary] = field(default_factory=list)
    era_breakpoints: list[int] = field(default_factory=list)
    parse_errors: list[str] = field(default_factory=list)
    truncation_notes: list[str] = field(default_factory=list)

    def eras(self):
        """Yield (era_index_within_source, provenance_list) pairs."""
        breaks = self.era_breakpoints + [len(self.provenance)]
        start = 0
        for era_index, end in enumerate(breaks):
            yield era_index, self.provenance[start:end]
            start = end


@dataclass
class MergedEvent:
    """One logical event, with every physical copy that represented it."""

    global_era: int
    record_num: int
    timestamp: str
    sha256: str
    occurrences: list[Provenance] = field(default_factory=list)
    reuse_classification: str | None = None
    duplicate_basis: str = ""

    @property
    def copy_count(self):
        return len(self.occurrences)

    def is_duplicate(self):
        return self.copy_count > 1

    def as_dict(self):
        return {
            "global_era": self.global_era,
            "record_num": self.record_num,
            "timestamp": self.timestamp,
            "sha256": self.sha256,
            "copy_count": self.copy_count,
            "duplicate_basis": self.duplicate_basis,
            "reuse_classification": self.reuse_classification,
            "occurrences": [p.as_dict() for p in self.occurrences],
        }


@dataclass
class MergeResult:
    sources: list[ScannedSource]
    events: list[MergedEvent]
    boundaries: list[EraBoundary]
    same_number_pairs: list[dict]

    def as_dict(self):
        return {
            "sources": [_source_summary(s) for s in self.sources],
            "event_count": len(self.events),
            "duplicate_event_count": sum(1 for e in self.events if e.is_duplicate()),
            "same_number_reuse_count": len(self.same_number_pairs),
            "era_boundaries": [b.as_dict() for b in self.boundaries],
            "same_number_pairs": self.same_number_pairs,
            "events": [e.as_dict() for e in self.events],
        }

    def to_json(self, indent=2):
        return json.dumps(self.as_dict(), indent=indent, sort_keys=False)


def _source_summary(scanned):
    return {
        "spec": scanned.spec.as_dict(),
        "file_sha256": scanned.file_sha256,
        "file_size": scanned.file_size,
        "header_next_record_number": scanned.next_record_number,
        "header_oldest_chunk": scanned.oldest_chunk,
        "header_current_chunk_number": scanned.current_chunk_number,
        "records_scanned": len(scanned.provenance),
        "era_breakpoints": scanned.era_breakpoints,
        "parse_errors": scanned.parse_errors,
        "truncation_notes": scanned.truncation_notes,
        "chunk_coverage": [c.as_dict() for c in scanned.chunk_coverage],
    }


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _record_fingerprint(record):
    """Hash the raw on-disk record bytes; identical copies hash equally."""
    return hashlib.sha256(record.data()).hexdigest()


def _isoformat(timestamp):
    if timestamp is None:
        return None
    return timestamp.isoformat()


def _safe_call(getter):
    """Return (value, None) or (None, error_text) for a header accessor."""
    try:
        return getter(), None
    except (ParseException, OverflowError, ValueError, struct_error()) as exc:
        return None, "{}: {}".format(type(exc).__name__, exc)


def struct_error():
    import struct

    return struct.error


def _safe_timestamp(record):
    try:
        return _isoformat(record.timestamp())
    except (ParseException, OverflowError, ValueError, struct_error()) as exc:
        return "invalid_timestamp: {}".format(exc)


def _classify_boundary(previous_num, next_num, previous_ts, next_ts):
    """
    Decide why the running record number decreased, returning
    (reason_code, human_readable_rationale).

    The three defensible cases are intentionally distinct:
      * the counter reached the uint64 limit and wrapped (rare/impossible in
        practice, but named explicitly so it is never confused with a clear);
      * the circular buffer reused the oldest chunk slot: the new records
        carry older timestamps than the records they follow on disk;
      * a real log clear segmented the log: numbering restarts low while the
        timeline keeps moving forward.
    Anything that fits none of these is reported, not guessed.
    """
    if previous_num >= UINT64_READ_LIMIT:
        return (
            BOUNDARY_COUNTER_WRAPAROUND,
            "running record number reached the uint64 maximum and wrapped; "
            "this is counter wraparound, not a log clear",
        )

    if next_ts is not None and previous_ts is not None and next_ts < previous_ts:
        return (
            BOUNDARY_CIRCULAR_WRAP,
            "record number reset while the next timestamp (" + str(next_ts)
            + ") predates the previous timestamp (" + str(previous_ts)
            + "); consistent with circular-buffer slot reuse, not a clear",
        )

    if next_num < previous_num:
        return (
            BOUNDARY_LOG_CLEAR,
            "record number fell from " + str(previous_num) + " to "
            + str(next_num) + " without going backwards in time; consistent"
            " with a log clear that restarted numbering at 1",
        )

    return (
        BOUNDARY_UNRESOLVED,
        "record number decreased but no wraparound/clear signature matched",
    )


def _scan_chunk(log, chunk, chunk_index, spec, coverage):
    # Walk one chunk record by record using the same Record interface the
    # library exposes, but manually so a corrupt tail record cannot silently
    # truncate the scan. A failure at/after the declared next_record_offset is
    # the normal end-of-chunk sentinel; a failure inside the active region
    # marks coverage unknown instead of trusting the header numbers.
    provenance = []
    chunk_end = chunk.offset() + CHUNK_SIZE
    try:
        next_record_offset = chunk.next_record_offset()
        active_end = chunk.offset() + next_record_offset
    except (ParseException, OverflowError, ValueError, struct_error()) as exc:
        next_record_offset = None
        active_end = chunk_end
        coverage.coverage_known = False
        coverage.error = "next_record_offset unreadable: {}".format(exc)

    try:
        record = chunk.first_record()
    except InvalidRecordException as exc:
        # An empty chunk has no active region (next_record_offset == 0x200).
        # If the header still claims records, the first record itself is
        # corrupt: report unknown coverage instead of a silent empty chunk.
        if next_record_offset is not None and next_record_offset > CHUNK_HEADER_SIZE:
            coverage.coverage_known = False
            coverage.error = (coverage.error + "; " if coverage.error else "") + "first_record invalid: {}".format(exc)
        return provenance
    except (ParseException, OverflowError, ValueError, struct_error()) as exc:
        coverage.coverage_known = False
        coverage.error = (coverage.error + "; " if coverage.error else "") + "first_record failed: {}".format(exc)
        return provenance

    while record.offset() < active_end and record.length() > 0:
        try:
            size = record.size()
            num = record.record_num()
            if size <= 0 or size > CHUNK_SIZE or record.offset() + size > chunk_end:
                raise ParseException("record size {} out of chunk bounds".format(size))
            if record.magic() != RECORD_MAGIC:
                raise ParseException("bad record magic {:#x}".format(record.magic()))
            timestamp = _safe_timestamp(record)
            fingerprint = _record_fingerprint(record)
        except (ParseException, OverflowError, ValueError, struct_error()) as exc:
            coverage.coverage_known = False
            coverage.error = (coverage.error + "; " if coverage.error else "") + (
                "record parse failed at " + hex(record.offset()) + ": "
                + "{}: {}".format(type(exc).__name__, exc)
            )
            break

        provenance.append(Provenance(
            source_id=spec.source_id,
            path=spec.path,
            chunk_index=chunk_index,
            chunk_offset=chunk.offset(),
            record_offset=record.offset(),
            record_num=num,
            timestamp=timestamp,
            size=size,
            sha256=fingerprint,
        ))
        coverage.records_read += 1
        try:
            record = evtx.Record(chunk._buf, record.offset() + size, chunk)
        except InvalidRecordException:
            # Mirrors ChunkHeader.records(): the end sentinel is not an error.
            break
        except (ParseException, OverflowError, ValueError, struct_error()) as exc:
            if record.offset() >= active_end:
                break
            coverage.coverage_known = False
            coverage.error = (coverage.error + "; " if coverage.error else "") + "next record failed: {}".format(exc)
            break

    return provenance


def scan_source(spec):
    """
    Parse one EVTX file offline into a ScannedSource. Never raises on a
    malformed chunk: a damaged chunk is reported with coverage_known=False
    and scanning continues with the remaining chunks.
    """
    if not os.path.isfile(spec.path):
        raise FileNotFoundError(spec.path)

    provenance = []
    coverage_list = []
    boundaries = []
    era_breakpoints = []
    parse_errors = []
    truncation_notes = []

    with evtx.Evtx(spec.path) as log:
        header = log.get_file_header()
        next_record_number = header.next_record_number()
        oldest_chunk = header.oldest_chunk()
        current_chunk_number = header.current_chunk_number()
        declared_chunks = header.chunk_count()

        running_num = None
        running_ts = None
        for chunk_index, chunk in enumerate(header.chunks(include_inactive=False)):
            magic_ok = False
            checksum_ok = False
            try:
                magic_ok = chunk.check_magic()
            except (ParseException, OverflowError, ValueError, struct_error()) as exc:
                parse_errors.append("chunk {} magic check failed: {}".format(chunk_index, exc))
            try:
                checksum_ok = chunk.verify()
            except (ParseException, OverflowError, ValueError, struct_error()) as exc:
                parse_errors.append("chunk {} checksum failed: {}".format(chunk_index, exc))

            coverage = ChunkCoverage(
                chunk_index=chunk_index,
                chunk_offset=chunk.offset(),
                magic_ok=magic_ok,
                checksum_ok=checksum_ok,
                records_read=0,
                claimed_file_first=_safe_call(chunk.file_first_record_number)[0],
                claimed_file_last=_safe_call(chunk.file_last_record_number)[0],
                claimed_log_first=_safe_call(chunk.log_first_record_number)[0],
                claimed_log_last=_safe_call(chunk.log_last_record_number)[0],
                coverage_known=magic_ok and checksum_ok,
            )
            if not magic_ok:
                coverage.coverage_known = False
                coverage.error = (coverage.error + "; " if coverage.error else "") + "invalid chunk magic"
                coverage_list.append(coverage)
                continue

            chunk_records = _scan_chunk(log, chunk, chunk_index, spec, coverage)
            coverage_list.append(coverage)

            for item in chunk_records:
                if running_num is not None and item.record_num is not None and item.record_num < running_num:
                    reason, rationale = _classify_boundary(
                        running_num, item.record_num, running_ts, item.timestamp
                    )
                    boundaries.append(EraBoundary(
                        source_id=spec.source_id,
                        chunk_index=chunk_index,
                        previous_record_num=running_num,
                        next_record_num=item.record_num,
                        previous_timestamp=running_ts,
                        next_timestamp=item.timestamp,
                        reason=reason,
                        rationale=rationale,
                    ))
                    if reason in (BOUNDARY_LOG_CLEAR, BOUNDARY_COUNTER_WRAPAROUND):
                        era_breakpoints.append(len(provenance))
                if item.record_num is not None:
                    running_num = item.record_num
                if item.timestamp is not None:
                    running_ts = item.timestamp
                provenance.append(item)

            if coverage.error:
                parse_errors.append("chunk {}: {}".format(chunk_index, coverage.error))


    observed_chunks = len(coverage_list)
    if observed_chunks < declared_chunks:
        truncation_notes.append(
            "file header declares " + str(declared_chunks) + " chunks but only "
            + str(observed_chunks) + " were readable; tail coverage is unknown"
        )

    return ScannedSource(
        spec=spec,
        file_sha256=sha256_file(spec.path),
        file_size=os.path.getsize(spec.path),
        next_record_number=next_record_number,
        oldest_chunk=oldest_chunk,
        current_chunk_number=current_chunk_number,
        chunk_coverage=coverage_list,
        provenance=provenance,
        boundaries=boundaries,
        era_breakpoints=era_breakpoints,
        parse_errors=parse_errors,
        truncation_notes=truncation_notes,
    )


class _UnionFind:
    def __init__(self):
        self._parent = {}

    def add(self, item):
        self._parent.setdefault(item, item)

    def find(self, item):
        root = item
        while self._parent[root] != root:
            root = self._parent[root]
        while self._parent[item] != item:
            parent = self._parent[item]
            self._parent[item] = root
            item = parent
        return root

    def union(self, left, right):
        self.add(left)
        self.add(right)
        self._parent[self.find(left)] = self.find(right)


def _assign_global_eras(scanned_sources):
    # Two local eras are the same global era when they share at least one
    # physical record (identical sha256): that only happens when the same
    # event was exported in more than one collection window. Eras created by
    # a log clear share no records with the pre-clear era and stay separate.
    uf = _UnionFind()
    descriptor = {}
    hash_to_nodes = {}
    for scanned in scanned_sources:
        for local_era, records in scanned.eras():
            node = (scanned.spec.source_id, local_era)
            uf.add(node)
            timestamps = [item.timestamp for item in records if item.timestamp]
            descriptor[node] = min(timestamps) if timestamps else ""
            for item in records:
                owner = hash_to_nodes.get(item.sha256)
                if owner is not None:
                    uf.union(node, owner)
                else:
                    hash_to_nodes[item.sha256] = node

    # order the distinct global eras by their earliest timestamp
    roots = {}
    for node in descriptor:
        root = uf.find(node)
        roots.setdefault(root, descriptor[node])
        roots[root] = min(roots[root], descriptor[node])
    ordered_roots = sorted(roots, key=lambda root: (roots[root], root))
    root_to_global = {root: index for index, root in enumerate(ordered_roots)}
    return {node: root_to_global[uf.find(node)] for node in descriptor}


def merge_sources(specs):
    """
    Merge the given caller-declared collection sources into one reviewable
    MergeResult. The sources are scanned independently first, then aligned.
    """
    scanned = [scan_source(spec) for spec in specs]
    era_map = _assign_global_eras(scanned)

    # key: (global_era, sha256) -> MergedEvent
    events = {}
    # record_num -> list of MergedEvent, for same-number side-by-side review
    by_number = {}
    all_boundaries = []

    for source in scanned:
        for local_era, records in source.eras():
            global_era = era_map[(source.spec.source_id, local_era)]
            for item in records:
                key = (global_era, item.sha256)
                event = events.get(key)
                if event is None:
                    event = MergedEvent(
                        global_era=global_era,
                        record_num=item.record_num,
                        timestamp=item.timestamp,
                        sha256=item.sha256,
                    )
                    events[key] = event
                    by_number.setdefault(item.record_num, []).append(event)
                event.occurrences.append(item)
        all_boundaries.extend(source.boundaries)

    same_number_pairs = []
    clear_eras = {b.source_id for b in all_boundaries if b.reason == BOUNDARY_LOG_CLEAR}
    for record_num, group in sorted(by_number.items(), key=lambda kv: kv[0]):
        distinct = {event.sha256 for event in group}
        if len(group) > 1 and len(distinct) > 1:
            # Same record number, different bytes: keep every one of these.
            # Distinct eras with a clear present means post-clear number reuse;
            # two different bytes sharing one era is an unresolved conflict.
            eras = {event.global_era for event in group}
            classification = REUSE_CLEAR if len(eras) > 1 and clear_eras else REUSE_CONFLICT
            for event in group:
                event.reuse_classification = classification
            same_number_pairs.append({
                "record_num": record_num,
                "global_eras": sorted(eras),
                "classification": classification,
                "events": [event.as_dict() for event in group],
            })

    merged_events = list(events.values())
    for event in merged_events:
        if event.copy_count > 1:
            sources_named = sorted({occ.source_id for occ in event.occurrences})
            noun = "copy" if event.copy_count == 1 else "copies"
            event.duplicate_basis = (
                "identical sha256 of raw record bytes across "
                + str(event.copy_count) + " " + noun + " from sources: "
                + ", ".join(sources_named)
            )

    return MergeResult(
        sources=scanned,
        events=merged_events,
        boundaries=all_boundaries,
        same_number_pairs=same_number_pairs,
    )


def sort_events(events, order="desc"):
    """
    Sort merged events. "desc" (default) is newest-first and tolerates
    out-of-order timestamps; ties break by era and record number.
    """
    reverse = order == "desc"
    return sorted(
        events,
        key=lambda e: (e.timestamp or "", e.global_era, e.record_num if e.record_num is not None else -1),
        reverse=reverse,
    )


def write_jsonl(result, path):
    """One JSON object per merged event, suitable for ingest/review tooling."""
    with open(path, "w", encoding="utf-8") as handle:
        for event in sort_events(result.events):
            handle.write(json.dumps(event.as_dict(), sort_keys=False) + "\n")


def write_report(result, path):
    """Full structured report: sources, coverage, boundaries, every event."""
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(result.to_json())
