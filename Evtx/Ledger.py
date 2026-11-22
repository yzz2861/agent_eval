"""Review coverage ledger for read-only EVTX evidence review.

This module sits next to the read-only :class:`Evtx.Evtx` parser.  It
does not modify an EVTX file; it only inventories records through the
existing ``records()`` interface and reasons about which real record
positions have been reviewed.

The workflow is intentionally evidence-centric:

1. Scan one or more exhibits into the ledger.  Every inventoried record
   keeps its real position (record number, absolute file offset and log
   timestamp).  Records whose metadata, structure or XML content cannot
   be read are retained with an anomaly reason.
2. Reviewers file receipts for contiguous record ranges (or explicit
   record numbers).  A receipt is bound to the field requirements that
   were active when it was issued.
3. Summaries report coverage per evidence scope.  An old receipt is
   reused only while the field requirements it certified still satisfy
   the active requirements and its bound record positions still match
   the current inventory.

Overlapping log-time ranges from different exhibits are merged into a
union, never summed.  Record counts remain per evidence scope because
two exhibits can legitimately hold different original records that
happen to cover the same wall-clock interval.
"""

from __future__ import absolute_import

import datetime
import hashlib
import json

__all__ = [
    "CoverageLedger",
    "FieldRequirements",
    "RecordEntry",
    "Receipt",
    "TraceHit",
    "UnreviewedRecord",
]


UTC = datetime.timezone.utc


def _as_utc(value):
    """Return a timezone-aware UTC datetime, assuming naive means UTC."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _time_value(value):
    """Return a sortable/comparable numeric value for a datetime."""
    if value is None:
        return None
    return _as_utc(value).timestamp()


def _time_iso(value):
    if value is None:
        return None
    return _as_utc(value).isoformat()


def _parse_time(value):
    if value is None or isinstance(value, datetime.datetime):
        return value
    text = str(value)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return datetime.datetime.fromisoformat(text)


def _merge_intervals(intervals, contiguous=False, key=None):
    """Merge inclusive intervals into their union.

    ``key`` maps interval endpoints to comparable values.  It exists so
    timezone-naive and timezone-aware timestamps can be merged together
    without comparing incompatible datetime objects directly.
    """
    if key is None:
        key = lambda value: value

    ordered = []
    for lo, hi in intervals:
        if lo is None or hi is None:
            continue
        lo_value, hi_value = key(lo), key(hi)
        if hi_value < lo_value:
            lo, hi = hi, lo
            lo_value, hi_value = hi_value, lo_value
        ordered.append((lo_value, hi_value, lo, hi))
    ordered.sort(key=lambda item: (item[0], item[1]))

    merged = []
    for lo_value, hi_value, lo, hi in ordered:
        if merged:
            last_lo_value, last_hi_value, last_lo, last_hi = merged[-1]
            touches = lo_value <= last_hi_value
            if contiguous and lo_value is not None and last_hi_value is not None:
                touches = touches or lo_value == last_hi_value + 1
            if touches:
                if hi_value > last_hi_value:
                    merged[-1] = (last_lo_value, hi_value, last_lo, hi)
                continue
        merged.append((lo_value, hi_value, lo, hi))
    return [(lo, hi) for _, _, lo, hi in merged]


def _interval_span(intervals, key=_time_value):
    """Return the summed duration covered by an already merged union."""
    total = 0.0
    for lo, hi in intervals:
        if lo is None or hi is None:
            continue
        total += key(hi) - key(lo)
    return total


def _fingerprint_entries(entries):
    """Build a stable digest for the bound positions of a receipt."""
    digest = hashlib.sha256()
    for entry in sorted(entries, key=lambda item: (item.record_num is None, item.record_num, item.offset or 0)):
        digest.update(
            (
                "{}|{}|{}|{}|{}\n".format(
                    entry.record_num,
                    entry.offset,
                    _time_iso(entry.timestamp),
                    entry.length,
                    entry.content_digest,
                )
            ).encode("utf-8")
        )
    return digest.hexdigest()

def _entry_binding(entry):
    """A JSON-friendly per-record position bound by a receipt."""
    return {
        "record_num": entry.record_num,
        "offset": entry.offset,
        "timestamp": _time_iso(entry.timestamp),
        "length": entry.length,
        "content_digest": entry.content_digest,
        "source": entry.source,
    }


class FieldRequirements(object):
    """The named fields a review must certify.

    Receipts are bound to the stable :meth:`key` of the field set in
    effect when they were issued.  The human-readable ``name`` is a
    label only; the field set is the part that governs reuse.
    """

    def __init__(self, name, fields=None, version=None):
        if hasattr(fields, "keys") and not isinstance(fields, (list, tuple, set, frozenset)):
            fields = fields.keys()
        self._name = str(name)
        self._fields = frozenset(str(field) for field in (fields or ()))
        self._version = version

    def name(self):
        return self._name

    def fields(self):
        return self._fields

    required_fields = fields

    def version(self):
        return self._version

    def key(self):
        """A stable digest of the required field names."""
        digest = hashlib.sha256()
        for field in sorted(self._fields):
            digest.update(field.encode("utf-8"))
            digest.update(b"\x00")
        if self._version is not None:
            digest.update(b"version\x00")
            digest.update(str(self._version).encode("utf-8"))
            digest.update(b"\x00")
        return digest.hexdigest()

    fingerprint = key

    def satisfies(self, other):
        """Return True when this specification covers ``other`` fields."""
        if isinstance(other, FieldRequirements):
            other = other.fields()
        return frozenset(other) <= self._fields

    def __eq__(self, other):
        return (
            isinstance(other, FieldRequirements)
            and self._name == other._name
            and self._fields == other._fields
            and self._version == other._version
        )

    def __hash__(self):
        return hash((self._name, self._fields, self._version))

    def __repr__(self):
        return "FieldRequirements(name={!r}, fields={!r}, version={!r})".format(
            self._name, sorted(self._fields), self._version
        )


class RecordEntry(object):
    """One real record position inventoried from an evidence exhibit."""

    def __init__(
        self,
        evidence,
        record_num,
        offset,
        timestamp,
        anomaly=None,
        source=None,
        chunk_offset=None,
        length=None,
        content_digest=None,
    ):
        self.evidence = evidence
        self.record_num = record_num
        self.offset = offset
        self.timestamp = _parse_time(timestamp)
        self.anomaly = anomaly
        self.source = source
        self.chunk_offset = chunk_offset
        self.relative_offset = None if offset is None or chunk_offset is None else offset - chunk_offset
        self.length = length
        self.content_digest = content_digest

    def is_anomalous(self):
        return self.anomaly is not None

    def sort_key(self):
        return (self.record_num is None, self.record_num or 0, self.offset or 0, self.source or "")

    def position(self):
        """Return a JSON-friendly description of the real record location."""
        return {
            "evidence": self.evidence,
            "source": self.source,
            "record_num": self.record_num,
            "offset": self.offset,
            "chunk_offset": self.chunk_offset,
            "relative_offset": self.relative_offset,
            "length": self.length,
            "timestamp": _time_iso(self.timestamp),
            "content_digest": self.content_digest,
            "anomaly": self.anomaly,
        }

    location = position

    def __repr__(self):
        return "RecordEntry(evidence={!r}, record_num={!r}, offset={!r}, anomaly={!r})".format(
            self.evidence, self.record_num, self.offset, self.anomaly
        )



class Receipt(object):
    """An immutable review receipt for a real evidence range.

    The receipt is bound to the field requirement set that was active
    when it was issued, and to the real record positions (number, file
    offset and timestamp) of the records that were reviewed.  Optional
    ``record_numbers`` supports a disjoint set of positions; otherwise
    the inclusive record-number range is used.
    """

    def __init__(
        self,
        receipt_id,
        evidence,
        reviewer,
        requirement_name,
        requirement_key,
        first_record_num,
        last_record_num,
        first_offset=None,
        last_offset=None,
        first_timestamp=None,
        last_timestamp=None,
        note="",
        requirement_fields=None,
        record_numbers=None,
        content_digest=None,
        issued_at=None,
        source=None,
        metadata=None,
        positions=None,
    ):
        self.receipt_id = receipt_id
        self.evidence = evidence
        self.reviewer = reviewer
        self.requirement_name = requirement_name
        self.requirement_key = requirement_key
        self.first_record_num = first_record_num
        self.last_record_num = last_record_num
        self.first_offset = first_offset
        self.last_offset = last_offset
        self.first_timestamp = first_timestamp
        self.last_timestamp = last_timestamp
        self.note = note
        self.requirement_fields = None if requirement_fields is None else frozenset(str(f) for f in requirement_fields)
        self.record_numbers = None if record_numbers is None else frozenset(int(n) for n in record_numbers)
        self.content_digest = content_digest
        self.issued_at = issued_at
        self.source = source
        self.metadata = dict(metadata or {})
        self.positions = None if positions is None else [dict(position) for position in positions]

    def covers_record(self, record_num):
        if record_num is None:
            return False
        if self.record_numbers is not None:
            return int(record_num) in self.record_numbers
        if self.first_record_num is None or self.last_record_num is None:
            return False
        return self.first_record_num <= int(record_num) <= self.last_record_num

    def covers_timestamp(self, timestamp):
        if timestamp is None or self.first_timestamp is None or self.last_timestamp is None:
            return False
        return _time_value(self.first_timestamp) <= _time_value(timestamp) <= _time_value(self.last_timestamp)

    def record_range(self):
        if self.record_numbers is not None and self.record_numbers:
            return (min(self.record_numbers), max(self.record_numbers))
        if self.first_record_num is None or self.last_record_num is None:
            return None
        return (self.first_record_num, self.last_record_num)

    def record_count(self):
        if self.record_numbers is not None:
            return len(self.record_numbers)
        span = self.record_range()
        if span is None:
            return 0
        return span[1] - span[0] + 1

    @property
    def bound_fields(self):
        return self.requirement_fields

    def to_dict(self):
        return {
            "receipt_id": self.receipt_id,
            "evidence": self.evidence,
            "source": self.source,
            "reviewer": self.reviewer,
            "requirement_name": self.requirement_name,
            "requirement_key": self.requirement_key,
            "requirement_fields": None if self.requirement_fields is None else sorted(self.requirement_fields),
            "first_record_num": self.first_record_num,
            "last_record_num": self.last_record_num,
            "first_offset": self.first_offset,
            "last_offset": self.last_offset,
            "first_timestamp": _time_iso(self.first_timestamp),
            "last_timestamp": _time_iso(self.last_timestamp),
            "record_numbers": None if self.record_numbers is None else sorted(self.record_numbers),
            "content_digest": self.content_digest,
            "issued_at": _time_iso(self.issued_at),
            "note": self.note,
            "metadata": dict(self.metadata),
            "positions": None if self.positions is None else [dict(position) for position in self.positions],
        }

    @classmethod
    def from_dict(cls, data):
        fields = data.get("requirement_fields", data.get("fields"))
        record_numbers = data.get("record_numbers")
        return cls(
            receipt_id=data.get("receipt_id", data.get("id")),
            evidence=data.get("evidence", data.get("scope")),
            reviewer=data.get("reviewer", ""),
            requirement_name=data.get("requirement_name", data.get("requirements_name", "")),
            requirement_key=data.get("requirement_key", ""),
            first_record_num=data.get("first_record_num", data.get("start_record_num")),
            last_record_num=data.get("last_record_num", data.get("end_record_num")),
            first_offset=data.get("first_offset"),
            last_offset=data.get("last_offset"),
            first_timestamp=_parse_time(data.get("first_timestamp")),
            last_timestamp=_parse_time(data.get("last_timestamp")),
            note=data.get("note", ""),
            requirement_fields=fields,
            record_numbers=record_numbers,
            content_digest=data.get("content_digest", data.get("range_digest")),
            issued_at=_parse_time(data.get("issued_at")),
            source=data.get("source"),
            metadata=data.get("metadata"),
            positions=data.get("positions"),
        )

    def __repr__(self):
        return "Receipt({!r}, evidence={!r}, records={!r}, reviewer={!r})".format(
            self.receipt_id, self.evidence, self.record_range(), self.reviewer
        )


class UnreviewedRecord(object):
    """An inventoried record that cannot be handed off as reviewed."""

    def __init__(self, entry, reasons, active_receipt_ids=None, stale_receipt_ids=None):
        self.entry = entry
        self.reasons = tuple(reasons)
        self.active_receipt_ids = tuple(active_receipt_ids or ())
        self.stale_receipt_ids = tuple(stale_receipt_ids or ())

    def to_dict(self):
        result = self.entry.position()
        result.update(
            {
                "reasons": list(self.reasons),
                "active_receipt_ids": list(self.active_receipt_ids),
                "stale_receipt_ids": list(self.stale_receipt_ids),
            }
        )
        return result

    def __repr__(self):
        return "UnreviewedRecord(record_num={!r}, reasons={!r})".format(self.entry.record_num, self.reasons)


class TraceHit(object):
    """One receipt covering a traced position, with reuse status."""

    def __init__(self, receipt, active, reasons=None):
        self.receipt = receipt
        self.active = bool(active)
        self.reasons = tuple(reasons or ())

    @property
    def reusable(self):
        return self.active

    def to_dict(self):
        return {
            "receipt_id": self.receipt.receipt_id,
            "reviewer": self.receipt.reviewer,
            "active": self.active,
            "reasons": list(self.reasons),
        }

    def __repr__(self):
        return "TraceHit({!r}, active={!r}, reasons={!r})".format(
            self.receipt.receipt_id, self.active, self.reasons
        )



class CoverageLedger(object):
    """A review coverage ledger layered over read-only EVTX parsing.

    The ledger never edits an evidence file.  It inventories real record
    positions, keeps receipts traceable by identifier, and computes
    coverage only from receipts that are still reusable under the active
    field requirements and whose bound positions still match the
    evidence.
    """

    def __init__(self, requirements=None, reuse_policy="compatible"):
        self._requirements = requirements or FieldRequirements("default", ())
        self._reuse_policy = reuse_policy
        self._inventory = {}
        self._receipts = []
        self._receipt_seq = 0
        self._status_cache = {}

    def requirements(self):
        return self._requirements

    field_requirements = requirements

    def set_requirements(self, requirements):
        """Activate a new field requirement set.

        Receipts bound to a requirement that no longer covers the active
        fields become stale immediately and stop contributing coverage.
        """
        self._requirements = requirements or FieldRequirements("default", ())
        self._status_cache.clear()
        return self

    def reuse_policy(self):
        return self._reuse_policy

    def set_reuse_policy(self, policy):
        if policy not in ("exact", "compatible", "any"):
            raise ValueError("unknown receipt reuse policy: {!r}".format(policy))
        self._reuse_policy = policy
        self._status_cache.clear()
        return self

    def _store_entries(self, evidence, entries, append):
        entries = sorted(entries, key=lambda entry: entry.sort_key())
        if append and evidence in self._inventory:
            combined = []
            seen = set()
            for entry in list(self._inventory[evidence]) + entries:
                marker = (entry.source, entry.record_num, entry.offset, entry.content_digest)
                if marker in seen:
                    continue
                seen.add(marker)
                combined.append(entry)
            entries = sorted(combined, key=lambda entry: entry.sort_key())
        self._inventory[evidence] = entries
        self._status_cache.clear()
        return list(entries)

    def _entry_from_record(self, evidence, record, source, render):
        record_num = offset = timestamp = length = chunk_offset = content_digest = None
        anomalies = []

        try:
            record_num = int(record.record_num())
        except Exception as exc:
            anomalies.append(
                "record_metadata_unreadable: unreadable record metadata (record_num): {}: {}".format(
                    type(exc).__name__, exc
                )
            )
        try:
            offset = int(record.offset())
        except Exception as exc:
            anomalies.append(
                "record_metadata_unreadable: unreadable record metadata (offset): {}: {}".format(
                    type(exc).__name__, exc
                )
            )
        try:
            timestamp = record.timestamp()
        except Exception as exc:
            anomalies.append(
                "record_metadata_unreadable: unreadable record metadata (timestamp): {}: {}".format(
                    type(exc).__name__, exc
                )
            )

        if timestamp is not None and getattr(timestamp, "year", 1) < 1970:
            anomalies.append("record_timestamp_invalid: {} is not a usable log time".format(timestamp))
            timestamp = None

        try:
            chunk = getattr(record, "_chunk", None)
            if chunk is not None:
                chunk_offset = int(chunk.offset())
        except Exception:
            chunk_offset = None

        try:
            if hasattr(record, "length"):
                length = int(record.length())
            elif hasattr(record, "size"):
                length = int(record.size())
        except Exception:
            length = None

        try:
            if hasattr(record, "data"):
                payload = record.data()
                if payload is not None:
                    content_digest = hashlib.sha256(payload).hexdigest()
        except Exception:
            content_digest = None

        try:
            if hasattr(record, "verify") and not record.verify():
                anomalies.append("record_verify_failed: record failed verification (size fields disagree)")
        except Exception as exc:
            anomalies.append("record_verify_failed: {}: {}".format(type(exc).__name__, exc))

        if render and hasattr(record, "xml"):
            try:
                record.xml()
            except Exception as exc:
                anomalies.append(
                    "record_content_abnormal: abnormal record content: {}: {}".format(
                        type(exc).__name__, exc
                    )
                )

        anomaly = "; ".join(anomalies) if anomalies else None
        return RecordEntry(
            evidence,
            record_num,
            offset,
            timestamp,
            anomaly=anomaly,
            source=source,
            chunk_offset=chunk_offset,
            length=length,
            content_digest=content_digest,
        )

    def scan_evidence(self, evidence, log, source=None, render=True, append=False):
        """Inventory one evidence scope through a read-only log object.

        ``log`` may be an opened :class:`Evtx.Evtx` or any object exposing
        ``records()``.  Records are never modified.  A failure while
        reading the record stream is retained as an anomaly so a broken
        file cannot silently look fully unreviewed and unknown.
        """
        entries = []
        try:
            for record in log.records():
                entries.append(self._entry_from_record(evidence, record, source, render))
        except Exception as exc:
            entries.append(
                RecordEntry(
                    evidence,
                    None,
                    None,
                    None,
                    anomaly="record_stream_aborted: {}: {}".format(type(exc).__name__, exc),
                    source=source,
                )
            )
        return self._store_entries(evidence, entries, append)

    def scan_entries(self, evidence, entries, append=False):
        """Inventory synthetic or previously built record entries.

        This is the seam for small self-made fixtures.  Items may be
        :class:`RecordEntry` instances or mappings with the same keys.
        """
        normalized = []
        for item in entries:
            if isinstance(item, RecordEntry):
                entry = RecordEntry(
                    evidence,
                    item.record_num,
                    item.offset,
                    item.timestamp,
                    anomaly=item.anomaly,
                    source=item.source,
                    chunk_offset=item.chunk_offset,
                    length=item.length,
                    content_digest=item.content_digest,
                )
            elif hasattr(item, "record_num"):
                entry = RecordEntry(
                    evidence,
                    item.record_num,
                    getattr(item, "offset", None),
                    getattr(item, "timestamp", None),
                    anomaly=getattr(item, "anomaly", None),
                    source=getattr(item, "source", None),
                    chunk_offset=getattr(item, "chunk_offset", None),
                    length=getattr(item, "length", None),
                    content_digest=getattr(item, "content_digest", None),
                )
            else:
                entry = RecordEntry(
                    evidence,
                    item.get("record_num"),
                    item.get("offset"),
                    _parse_time(item.get("timestamp")),
                    anomaly=item.get("anomaly"),
                    source=item.get("source"),
                    chunk_offset=item.get("chunk_offset"),
                    length=item.get("length"),
                    content_digest=item.get("content_digest"),
                )
            normalized.append(entry)
        return self._store_entries(evidence, normalized, append)

    def scan_file(self, evidence, path, source=None, render=True, append=False):
        """Open an EVTX file read-only and inventory it under ``evidence``."""
        from .Evtx import Evtx

        with Evtx(path) as log:
            return self.scan_evidence(evidence, log, source=source, render=render, append=append)

    scan_evtx = scan_file

    def inventory(self, evidence=None):
        if evidence is None:
            return {scope: list(entries) for scope, entries in self._inventory.items()}
        return list(self._inventory.get(evidence, ()))

    def evidence_scopes(self):
        return sorted(self._inventory.keys())

    def record_entries(self, evidence):
        return self.inventory(evidence)

    def records(self, evidence=None):
        return self.inventory(evidence)


    def _scope_entries(self, evidence, source=None):
        entries = list(self._inventory.get(evidence, ()))
        if source is not None:
            entries = [entry for entry in entries if entry.source == source]
        return entries

    def _next_receipt_id(self):
        self._receipt_seq += 1
        return "R{:04d}".format(self._receipt_seq)

    def _note_receipt_id(self, receipt_id):
        text = str(receipt_id or "")
        if text.startswith("R") and text[1:].isdigit():
            self._receipt_seq = max(self._receipt_seq, int(text[1:]))

    def issue_receipt(
        self,
        evidence,
        reviewer,
        first_record_num=None,
        last_record_num=None,
        note="",
        record_numbers=None,
        source=None,
        issued_at=None,
    ):
        """File a receipt for records actually present in the inventory.

        The receipt stores the real positions (offset and timestamp)
        derived from the scanned inventory, and is bound to the currently
        active field requirements.
        """
        if evidence not in self._inventory:
            raise ValueError("evidence scope {!r} has not been scanned".format(evidence))

        if record_numbers is not None:
            wanted = set(int(number) for number in record_numbers)
            entries = [
                entry
                for entry in self._scope_entries(evidence, source)
                if entry.record_num is not None and entry.record_num in wanted
            ]
            if first_record_num is None and entries:
                first_record_num = min(entry.record_num for entry in entries)
            if last_record_num is None and entries:
                last_record_num = max(entry.record_num for entry in entries)
        else:
            if first_record_num is None or last_record_num is None:
                raise ValueError("first_record_num and last_record_num are required")
            if first_record_num > last_record_num:
                raise ValueError("first_record_num must not exceed last_record_num")
            entries = [
                entry
                for entry in self._scope_entries(evidence, source)
                if entry.record_num is not None and first_record_num <= entry.record_num <= last_record_num
            ]

        if not entries:
            raise ValueError(
                "no scanned records of {!r} in requested review range".format(evidence)
            )

        offsets = [entry.offset for entry in entries if entry.offset is not None]
        timestamps = [entry.timestamp for entry in entries if entry.timestamp is not None]
        fields = self._requirements.fields()
        receipt = Receipt(
            receipt_id=self._next_receipt_id(),
            evidence=evidence,
            reviewer=reviewer,
            requirement_name=self._requirements.name(),
            requirement_key=self._requirements.key(),
            first_record_num=first_record_num,
            last_record_num=last_record_num,
            first_offset=min(offsets) if offsets else None,
            last_offset=max(offsets) if offsets else None,
            first_timestamp=min(timestamps, key=_time_value) if timestamps else None,
            last_timestamp=max(timestamps, key=_time_value) if timestamps else None,
            note=note,
            requirement_fields=fields,
            record_numbers=None if record_numbers is None else sorted(int(n) for n in record_numbers),
            content_digest=_fingerprint_entries(entries),
            issued_at=issued_at,
            source=source,
            positions=[_entry_binding(entry) for entry in entries],
        )
        self._receipts.append(receipt)
        self._status_cache.clear()
        return receipt

    def add_receipt(self, receipt):
        """Register a receipt filed earlier or by another reviewer."""
        if not receipt.receipt_id:
            receipt.receipt_id = self._next_receipt_id()
        else:
            existing = self.get_receipt(receipt.receipt_id)
            if existing is receipt:
                return receipt
            if existing is not None:
                raise ValueError("duplicate receipt id: {!r}".format(receipt.receipt_id))
            self._note_receipt_id(receipt.receipt_id)
        self._receipts.append(receipt)
        self._status_cache.clear()
        return receipt

    def add_receipts(self, receipts):
        for receipt in receipts:
            self.add_receipt(receipt)
        return self.receipts()

    def load_receipts(self, data):
        """Load receipts from a list, a mapping with ``receipts``, or a path."""
        if isinstance(data, str):
            with open(data, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        if isinstance(data, dict):
            items = data.get("receipts", data.get("items", [data]))
        else:
            items = data
        for item in items:
            if not isinstance(item, Receipt):
                item = Receipt.from_dict(item)
            self.add_receipt(item)
        return self.receipts()

    load_receipts_json = load_receipts

    def receipts(self, evidence=None, reviewer=None):
        result = []
        for receipt in self._receipts:
            if evidence is not None and receipt.evidence != evidence:
                continue
            if reviewer is not None and receipt.reviewer != reviewer:
                continue
            result.append(receipt)
        return result

    def get_receipt(self, receipt_id):
        for receipt in self._receipts:
            if receipt.receipt_id == receipt_id:
                return receipt
        return None

    def _receipt_requirement_key(self, receipt):
        if receipt.requirement_key:
            return receipt.requirement_key
        if receipt.requirement_fields is not None:
            return FieldRequirements(receipt.requirement_name or "receipt", receipt.requirement_fields).key()
        return None

    def receipt_status(self, receipt):
        """Return the reasons a receipt cannot be reused (empty means active)."""
        cache_key = receipt.receipt_id if receipt.receipt_id else id(receipt)
        if cache_key in self._status_cache:
            return self._status_cache[cache_key]
        reasons = []

        receipt_key = self._receipt_requirement_key(receipt)
        exact_match = receipt_key is not None and receipt_key == self._requirements.key()
        if not exact_match:
            compatible = (
                self._reuse_policy == "any"
                or (
                    self._reuse_policy == "compatible"
                    and receipt.requirement_fields is not None
                    and frozenset(receipt.requirement_fields) >= frozenset(self._requirements.fields())
                )
            )
            if not compatible:
                reasons.append(
                    (
                        "requirements_changed: receipt {!r} is bound to superseded "
                        "field requirements {!r}; active requirements are {!r}"
                    ).format(
                        receipt.receipt_id,
                        sorted(receipt.requirement_fields) if receipt.requirement_fields is not None else None,
                        sorted(self._requirements.fields()),
                    )
                )

        entries = self._scope_entries(receipt.evidence, receipt.source)
        if receipt.evidence not in self._inventory:
            reasons.append("evidence_not_scanned: {!r} is not in the current inventory".format(receipt.evidence))
            result = tuple(reasons)
            self._status_cache[cache_key] = result
            return result

        bound = [entry for entry in entries if receipt.covers_record(entry.record_num)]
        if not bound:
            reasons.append("receipt_range_empty: no inventoried record remains in the receipt range")
            result = tuple(reasons)
            self._status_cache[cache_key] = result
            return result

        if receipt.record_numbers is not None:
            present = {entry.record_num for entry in bound}
            missing = sorted(set(receipt.record_numbers) - present)
            if missing:
                reasons.append("record_missing: receipt positions no longer inventoried: {!r}".format(missing))

        if receipt.positions:
            entries_by_number = {}
            for entry in entries:
                entries_by_number.setdefault(entry.record_num, []).append(entry)
            for position in receipt.positions:
                number = position.get("record_num")
                matches = entries_by_number.get(number, ())
                if not matches:
                    reasons.append(
                        "record_missing: receipt position record {} is no longer inventoried".format(number)
                    )
                    continue
                for entry in matches:
                    if position.get("offset") is not None and entry.offset != position.get("offset"):
                        reasons.append(
                            "record_offset_changed: record {} is at offset {}, receipt recorded {}".format(
                                number, entry.offset, position.get("offset")
                            )
                        )
                    recorded_timestamp = _parse_time(position.get("timestamp"))
                    if recorded_timestamp is not None and entry.timestamp is not None:
                        if _time_value(entry.timestamp) != _time_value(recorded_timestamp):
                            reasons.append(
                                "record_timestamp_changed: record {} timestamp no longer matches the receipt".format(
                                    number
                                )
                            )
                    if position.get("content_digest") and entry.content_digest:
                        if entry.content_digest != position.get("content_digest"):
                            reasons.append(
                                "record_content_changed: record {} content changed".format(number)
                            )
        else:
            offset_values = [entry.offset for entry in bound if entry.offset is not None]
            if receipt.first_offset is not None and offset_values and min(offset_values) != receipt.first_offset:
                reasons.append(
                    "record_offset_changed: first bound offset is {}, receipt recorded {}".format(
                        min(offset_values), receipt.first_offset
                    )
                )
            if receipt.last_offset is not None and offset_values and max(offset_values) != receipt.last_offset:
                reasons.append(
                    "record_offset_changed: last bound offset is {}, receipt recorded {}".format(
                        max(offset_values), receipt.last_offset
                    )
                )

            timestamp_values = [entry.timestamp for entry in bound if entry.timestamp is not None]
            if receipt.first_timestamp is not None and timestamp_values:
                if min(timestamp_values, key=_time_value) != receipt.first_timestamp:
                    reasons.append("record_timestamp_changed: first bound timestamp no longer matches the receipt")
            if receipt.last_timestamp is not None and timestamp_values:
                if max(timestamp_values, key=_time_value) != receipt.last_timestamp:
                    reasons.append("record_timestamp_changed: last bound timestamp no longer matches the receipt")

            if receipt.content_digest:
                actual = _fingerprint_entries(bound)
                if actual != receipt.content_digest:
                    reasons.append("record_content_changed: bound record positions or content changed")

        result = tuple(reasons)
        self._status_cache[cache_key] = result
        return result

    def reuse_reasons(self, receipt):
        return self.receipt_status(receipt)

    def is_active(self, receipt):
        return not self.receipt_status(receipt)

    is_reusable = is_active

    def active_receipts(self, evidence=None):
        return [receipt for receipt in self.receipts(evidence) if self.is_active(receipt)]

    def stale_receipts(self, evidence=None):
        return [receipt for receipt in self.receipts(evidence) if not self.is_active(receipt)]

    def _covering_receipts(self, evidence, record_num, source=None):
        result = []
        for receipt in self.receipts(evidence):
            if not receipt.covers_record(record_num):
                continue
            if receipt.source is not None and source is not None and receipt.source != source:
                continue
            result.append(receipt)
        return result

    def _active_covering(self, evidence, record_num, source=None):
        return [
            receipt
            for receipt in self._covering_receipts(evidence, record_num, source)
            if self.is_active(receipt)
        ]

    def reviewed_bindings(self, evidence):
        """Return ``(entry, active_receipt_ids)`` for actually reviewed records."""
        bindings = []
        for entry in self._scope_entries(evidence):
            if entry.record_num is None or entry.anomaly is not None:
                continue
            active = self._active_covering(evidence, entry.record_num, entry.source)
            if active:
                bindings.append((entry, tuple(receipt.receipt_id for receipt in active)))
        return bindings

    def reviewed_entries(self, evidence):
        return [entry for entry, _ in self.reviewed_bindings(evidence)]

    def reviewed_record_numbers(self, evidence):
        return sorted({entry.record_num for entry in self.reviewed_entries(evidence)})

    def reviewed_bindings_for_range(self, evidence, first_record_num, last_record_num):
        return [
            (entry, ids)
            for entry, ids in self.reviewed_bindings(evidence)
            if first_record_num <= entry.record_num <= last_record_num
        ]

    def reviewed_intervals(self, evidence):
        """The merged record-number intervals actually reviewed.

        Contiguous but anomalous positions and absent records split the
        intervals, so the result reflects real reviewed records rather
        than merely the receipt envelope.
        """
        numbers = self.reviewed_record_numbers(evidence)
        return _merge_intervals([(number, number) for number in numbers], contiguous=True)

    def covered_intervals(self, evidence):
        """The merged envelope of reusable receipts, including gaps."""
        intervals = []
        for receipt in self.active_receipts(evidence):
            if receipt.record_numbers is not None:
                intervals.extend((number, number) for number in receipt.record_numbers)
            else:
                record_range = receipt.record_range()
                if record_range is not None:
                    intervals.append(record_range)
        return _merge_intervals(intervals, contiguous=True)

    receipt_intervals = covered_intervals


    def _time_runs_for_receipt(self, evidence, receipt):
        bound = [
            entry
            for entry in self._scope_entries(evidence, receipt.source)
            if entry.record_num is not None
            and entry.anomaly is None
            and receipt.covers_record(entry.record_num)
        ]
        bound.sort(key=lambda entry: (entry.record_num, entry.offset or 0))
        runs = []
        current = []
        for entry in bound:
            if entry.timestamp is None:
                continue
            if current and entry.record_num != current[-1].record_num + 1:
                runs.append(current)
                current = []
            current.append(entry)
        if current:
            runs.append(current)

        intervals = []
        for run in runs:
            timestamps = [entry.timestamp for entry in run if entry.timestamp is not None]
            if timestamps:
                intervals.append(
                    (
                        min(timestamps, key=_time_value),
                        max(timestamps, key=_time_value),
                    )
                )
        return intervals

    def _time_intervals_for(self, evidence=None):
        scopes = [evidence] if evidence is not None else self.evidence_scopes()
        intervals = []
        for scope in scopes:
            for receipt in self.active_receipts(scope):
                intervals.extend(self._time_runs_for_receipt(scope, receipt))
        return _merge_intervals(intervals, key=_time_value)

    def reviewed_time_intervals(self, evidence=None):
        """The merged union of reviewed log-time ranges.

        When ``evidence`` is omitted, ranges from all exhibits are merged
        together.  Overlapping wall-clock ranges are therefore counted
        once, never added.
        """
        return self._time_intervals_for(evidence)

    def raw_reviewed_time_seconds(self, evidence=None):
        scopes = [evidence] if evidence is not None else self.evidence_scopes()
        total = 0.0
        for scope in scopes:
            for receipt in self.active_receipts(scope):
                total += _interval_span(self._time_runs_for_receipt(scope, receipt), key=_time_value)
        return total

    def reviewed_duration(self, evidence=None):
        """Total reviewed log time over the merged union, not a sum of overlaps."""
        return datetime.timedelta(seconds=_interval_span(self.reviewed_time_intervals(evidence), key=_time_value))

    def overlap_time_seconds(self, evidence=None):
        """Seconds that would have been double-counted by naive summing."""
        union = _interval_span(self.reviewed_time_intervals(evidence), key=_time_value)
        return max(0.0, self.raw_reviewed_time_seconds(evidence) - union)

    double_counted_time_seconds = overlap_time_seconds

    def overlap_duration(self, evidence=None):
        return datetime.timedelta(seconds=self.overlap_time_seconds(evidence))

    def unreviewed(self, evidence, first_record_num=None, last_record_num=None):
        """Return records that cannot be handed off, with explicit reasons."""
        results = []
        for entry in self._scope_entries(evidence):
            if first_record_num is not None and entry.record_num is not None:
                if entry.record_num < first_record_num:
                    continue
            if last_record_num is not None and entry.record_num is not None:
                if entry.record_num > last_record_num:
                    continue

            if entry.record_num is None:
                results.append(
                    UnreviewedRecord(
                        entry,
                        [entry.anomaly or "record_number_unknown"],
                    )
                )
                continue

            covering = self._covering_receipts(evidence, entry.record_num, entry.source)
            active = [receipt for receipt in covering if self.is_active(receipt)]
            stale = [receipt for receipt in covering if not self.is_active(receipt)]

            reasons = []
            if not active:
                reasons.append("no_active_receipt: not covered by any active receipt")
                if stale:
                    details = []
                    for receipt in stale:
                        details.append(
                            "{} not reused ({})".format(
                                receipt.receipt_id,
                                "; ".join(self.receipt_status(receipt)) or "not reusable",
                            )
                        )
                    reasons.append("only_stale_receipts: {}".format(", ".join(details)))
            if entry.anomaly is not None:
                reasons.append(entry.anomaly)

            if reasons:
                results.append(
                    UnreviewedRecord(
                        entry,
                        reasons,
                        active_receipt_ids=[receipt.receipt_id for receipt in active],
                        stale_receipt_ids=[receipt.receipt_id for receipt in stale],
                    )
                )
        return results

    def is_handoff_ready(self, evidence, first_record_num, last_record_num):
        """True only when every real record in the segment is reviewed clean."""
        entries = [
            entry
            for entry in self._scope_entries(evidence)
            if entry.record_num is not None and first_record_num <= entry.record_num <= last_record_num
        ]
        if not entries:
            return False
        return not self.unreviewed(evidence, first_record_num, last_record_num)

    def trace(self, evidence, record_num=None, offset=None, source=None):
        """Trace every receipt covering one real record position."""
        if record_num is None and offset is not None:
            for entry in self._scope_entries(evidence, source):
                if entry.offset == offset:
                    record_num = entry.record_num
                    break
        if record_num is None:
            return []
        hits = []
        for receipt in self.receipts(evidence):
            if receipt.source is not None and source is not None and receipt.source != source:
                continue
            if not receipt.covers_record(record_num):
                continue
            reasons = self.receipt_status(receipt)
            hits.append(TraceHit(receipt, not reasons, reasons))
        return hits

    trace_record = trace

    def trace_receipt(self, receipt_id):
        """Return a receipt together with its reuse status and bound records."""
        receipt = self.get_receipt(receipt_id)
        if receipt is None:
            return None
        reasons = self.receipt_status(receipt)
        bound = [
            entry.position()
            for entry in self._scope_entries(receipt.evidence, receipt.source)
            if receipt.covers_record(entry.record_num)
        ]
        return {
            "receipt": receipt.to_dict(),
            "active": not reasons,
            "reasons": list(reasons),
            "bound_records": bound,
        }

    def record_coverage(self, evidence, record_num, source=None):
        entry = None
        for candidate in self._scope_entries(evidence, source):
            if candidate.record_num == record_num:
                entry = candidate
                break
        if entry is None:
            return None
        hits = self.trace(evidence, record_num=record_num, source=source)
        active_ids = [hit.receipt.receipt_id for hit in hits if hit.active]
        stale_ids = [hit.receipt.receipt_id for hit in hits if not hit.active]
        reasons = []
        if entry.anomaly is not None:
            reasons.append(entry.anomaly)
        if not active_ids:
            reasons.append("no_active_receipt")
        result = entry.position()
        result.update(
            {
                "reviewed": bool(active_ids) and entry.anomaly is None,
                "reasons": reasons,
                "active_receipt_ids": active_ids,
                "stale_receipt_ids": stale_ids,
                "receipts": [hit.to_dict() for hit in hits],
            }
        )
        return result

    def coverage(self, evidence=None):
        """Return one row per real record position with review status."""
        scopes = [evidence] if evidence is not None else self.evidence_scopes()
        rows = []
        for scope in scopes:
            for entry in self._scope_entries(scope):
                if entry.record_num is None:
                    item = entry.position()
                    item.update(
                        {
                            "reviewed": False,
                            "reasons": [entry.anomaly or "record_number_unknown"],
                            "active_receipt_ids": [],
                            "stale_receipt_ids": [],
                        }
                    )
                    rows.append(item)
                    continue
                item = self.record_coverage(scope, entry.record_num, entry.source)
                if item is not None:
                    rows.append(item)
        return rows

    coverage_records = coverage

    def coverage_in_time_range(self, start, end, evidence=None):
        """Return coverage rows whose real log time falls in the range."""
        start_value = _time_value(_parse_time(start))
        end_value = _time_value(_parse_time(end))
        if end_value < start_value:
            start_value, end_value = end_value, start_value
        scopes = [evidence] if evidence is not None else self.evidence_scopes()
        rows = []
        for scope in scopes:
            for entry in self._scope_entries(scope):
                if entry.timestamp is None:
                    continue
                value = _time_value(entry.timestamp)
                if not (start_value <= value <= end_value):
                    continue
                if entry.record_num is None:
                    item = entry.position()
                    item.update(
                        {
                            "reviewed": False,
                            "reasons": [entry.anomaly or "record_number_unknown"],
                            "active_receipt_ids": [],
                            "stale_receipt_ids": [],
                        }
                    )
                    rows.append(item)
                else:
                    item = self.record_coverage(scope, entry.record_num, entry.source)
                    if item is not None:
                        rows.append(item)
        return rows

    def reviewed_in_time_range(self, start, end, evidence=None):
        """Return only records in the time range that are actually reviewed."""
        return [
            item
            for item in self.coverage_in_time_range(start, end, evidence)
            if item.get("reviewed")
        ]

    records_in_time_range = coverage_in_time_range

    def summary(self):
        """A structured coverage report per evidence scope."""
        scopes = {}
        for evidence in self.evidence_scopes():
            entries = self._inventory[evidence]
            bindings = self.reviewed_bindings(evidence)
            reviewed_positions = []
            for entry, receipt_ids in bindings:
                position = entry.position()
                position["receipt_ids"] = list(receipt_ids)
                reviewed_positions.append(position)
            scopes[evidence] = {
                "records": len(entries),
                "anomalies": sum(1 for entry in entries if entry.anomaly is not None),
                "reviewed_records": len(bindings),
                "reviewed_intervals": self.reviewed_intervals(evidence),
                "reviewed_time_intervals": self.reviewed_time_intervals(evidence),
                "reviewed_positions": reviewed_positions,
                "unreviewed": [item.to_dict() for item in self.unreviewed(evidence)],
                "receipts": [receipt.receipt_id for receipt in self.receipts(evidence)],
                "active_receipts": [receipt.receipt_id for receipt in self.active_receipts(evidence)],
                "stale_receipts": [receipt.receipt_id for receipt in self.stale_receipts(evidence)],
                "covered_intervals": self.covered_intervals(evidence),
            }
        return {
            "requirements": {
                "name": self._requirements.name(),
                "key": self._requirements.key(),
                "fields": sorted(self._requirements.fields()),
                "version": self._requirements.version(),
            },
            "reuse_policy": self._reuse_policy,
            "evidence": scopes,
            "receipts": [receipt.to_dict() for receipt in self.receipts()],
            "reviewed_time_intervals": self.reviewed_time_intervals(),
            "reviewed_duration": self.reviewed_duration(),
            "overlap_time_seconds": self.overlap_time_seconds(),
            "records_total": sum(len(entries) for entries in self._inventory.values()),
            "reviewed_records_total": sum(scope["reviewed_records"] for scope in scopes.values()),
        }

    def to_dict(self, include_receipts=True):
        """Return a JSON-friendly copy of :meth:`summary`."""
        data = self.summary()
        if not include_receipts:
            data = dict(data)
            data.pop("receipts", None)
        return _json_value(data)

    def to_json(self, indent=2, include_receipts=True):
        return json.dumps(self.to_dict(include_receipts=include_receipts), indent=indent, sort_keys=True)

    def write_json(self, path, indent=2, include_receipts=True):
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(self.to_json(indent=indent, include_receipts=include_receipts))
            handle.write("\n")

    def __repr__(self):
        return "CoverageLedger(scopes={!r}, receipts={!r}, requirements={!r})".format(
            self.evidence_scopes(), len(self._receipts), self._requirements.name()
        )


def _json_value(value):
    if isinstance(value, datetime.datetime):
        return _time_iso(value)
    if isinstance(value, datetime.timedelta):
        return value.total_seconds()
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted(_json_value(item) for item in value)
    return value
