"""Read-only generational comparison for two Registry hive snapshots.

Path equality is only one signal.  This module correlates path, parent path,
record offsets, record/value bytes, content fingerprints and timestamps while
keeping weak or tied correspondences ambiguous.
"""

from __future__ import print_function

import binascii
import hashlib
import io
import json
import os
import struct

from . import RegistryParse
from .Registry import Registry

try:
    _PathLike = os.PathLike
except AttributeError:  # Python 2.7 compatibility
    _PathLike = None


SCHEMA_VERSION = "generational-diff/1"

UNCHANGED = "unchanged"
MODIFIED = "modified"
MIGRATED = "migrated"
MIGRATION_CANDIDATE = "migration_candidate"
REBUILD_CANDIDATE = "rebuild_candidate"
INDETERMINATE = "indeterminate"
ADDED = "added"
REMOVED = "removed"
TIMESTAMP_ONLY = "timestamp_only"

CREATED = ADDED
DELETED = REMOVED
REBUILT = REBUILD_CANDIDATE
UNKNOWN = INDETERMINATE
MOVED = MIGRATED

HIGH = "high"
MEDIUM = "medium"
LOW = "low"


def _hex(data):
    return binascii.hexlify(bytes(data or b"")).decode("ascii")


def _sha256(data):
    return hashlib.sha256(bytes(data or b"")).hexdigest()


def _normalized_name(name):
    return (name or "").strip().lower()


def _normalized_path(path_tuple):
    return "\\" + "\\".join(path_tuple) if path_tuple else "\\"


def _diff_ranges(old, new):
    old = bytes(old or b"")
    new = bytes(new or b"")
    if len(old) == len(new):
        index = 0
        while index < len(old):
            if old[index] == new[index]:
                index += 1
                continue
            start = index
            while index < len(old) and old[index] != new[index]:
                index += 1
            yield start, index
        return

    end = min(len(old), len(new))
    index = 0
    while index < end:
        if old[index] != new[index]:
            start = index
            while index < end and old[index] != new[index]:
                index += 1
            yield start, index
        else:
            index += 1
    if len(old) != len(new):
        yield end, max(len(old), len(new))


class ByteEvidence(object):
    """Raw bytes supporting a correspondence or change."""

    def __init__(self, kind, description, old_offset=None, new_offset=None,
                 old_bytes=None, new_bytes=None):
        self.kind = kind
        self.description = description
        self.old_offset = old_offset
        self.new_offset = new_offset
        self.offset = old_offset if old_offset == new_offset else None
        self.old_bytes = bytes(old_bytes) if old_bytes is not None else None
        self.new_bytes = bytes(new_bytes) if new_bytes is not None else None
        self.before = self.old_bytes
        self.after = self.new_bytes

    @property
    def old_hex(self):
        return _hex(self.old_bytes)

    @property
    def new_hex(self):
        return _hex(self.new_bytes)

    @property
    def before_hex(self):
        return self.old_hex

    @property
    def after_hex(self):
        return self.new_hex

    def to_dict(self):
        return {
            "kind": self.kind,
            "description": self.description,
            "old_offset": self.old_offset,
            "new_offset": self.new_offset,
            "offset": self.offset,
            "old_hex": self.old_hex,
            "new_hex": self.new_hex,
            "old_sha256": _sha256(self.old_bytes),
            "new_sha256": _sha256(self.new_bytes),
        }


class ValueSnapshot(object):
    def __init__(self, key, registry_value, side):
        vk = registry_value._vkrecord
        self.side = side
        self.key_path = key.logical_path
        self.name = registry_value.name()
        try:
            self.raw_name = vk.name()
        except Exception:
            self.raw_name = ""
        self.normalized_name = _normalized_name(self.raw_name)
        self.value_type = registry_value.value_type()
        self.type_name = registry_value.value_type_str()
        self.vk_offset = vk.offset()
        self.raw_bytes = b""
        self.parsed_value = None
        self.error = None
        try:
            self.raw_bytes = bytes(registry_value.raw_data() or b"")
        except Exception as exc:
            self.error = str(exc)
        try:
            self.parsed_value = registry_value.value()
        except Exception as exc:
            if self.error is None:
                self.error = str(exc)

        self.vk_raw = b""
        try:
            name_length = vk.unpack_word(0x02)
            self.vk_raw = bytes(vk.unpack_binary(0, 0x14 + name_length))
        except Exception:
            pass

        self.data_offset = None
        self.data_inline = False
        try:
            literal_length = vk.raw_data_length()
            if literal_length < 5 or literal_length >= 0x80000000:
                self.data_offset = self.vk_offset + 0x08
                self.data_inline = True
            else:
                cell_offset = vk.abs_offset_from_hbin_offset(
                    vk.unpack_dword(0x08))
                self.data_offset = cell_offset + 0x04
        except Exception:
            pass

        self.timestamp_ticks = None
        self.timestamp = None
        try:
            if registry_value.timestamp() is not None:
                self.timestamp = registry_value.timestamp()
                # The parser exposes the datetime; raw ticks are not retained
                # by VKRecord.timestamp(), so leave ticks unset unless needed.
        except Exception:
            pass

        self.digest = _sha256(self._canonical_payload().encode("utf-8"))

    def _canonical_payload(self):
        return json.dumps({
            "name": self.normalized_name,
            "type": self.value_type,
            "raw_sha256": _sha256(self.raw_bytes),
            "raw_length": len(self.raw_bytes),
        }, sort_keys=True, separators=(",", ":"))

    def to_dict(self):
        return {
            "side": self.side,
            "key_path": self.key_path,
            "name": self.name,
            "normalized_name": self.normalized_name,
            "value_type": self.value_type,
            "type_name": self.type_name,
            "vk_offset": self.vk_offset,
            "data_offset": self.data_offset,
            "data_inline": self.data_inline,
            "raw_hex": _hex(self.raw_bytes),
            "raw_sha256": _sha256(self.raw_bytes),
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "digest": self.digest,
            "error": self.error,
        }


class KeySnapshot(object):
    def __init__(self, registry_key, side, path_tuple, parent_offset=None):
        nk = registry_key._nkrecord
        self.side = side
        self.name = registry_key.name()
        self.normalized_name = _normalized_name(self.name)
        self.path_tuple = tuple(_normalized_name(part) for part in path_tuple)
        self.logical_path = _normalized_path(self.path_tuple)
        self.registry_path = None
        try:
            self.registry_path = registry_key.path()
        except Exception:
            pass

        self.nk_offset = nk.offset()
        self.nk_cell_offset = self.nk_offset - 4
        self.parent_offset = parent_offset
        self.is_root = bool(nk.is_root())
        self.flags = nk.unpack_word(0x02)
        self.subkey_count = nk.subkey_number()
        self.value_count = nk.values_number()
        self.parent_pointer = None
        try:
            self.parent_pointer = nk.unpack_dword(0x10)
        except Exception:
            pass

        self.timestamp_ticks = nk.unpack_qword(0x04)
        self.timestamp = None
        try:
            self.timestamp = RegistryParse.parse_windows_timestamp(
                self.timestamp_ticks)
        except Exception:
            try:
                self.timestamp = registry_key.timestamp()
            except Exception:
                self.timestamp = None
        self.timestamp_available = bool(self.timestamp_ticks)

        self.cell_size = None
        try:
            signed_size = struct.unpack_from(
                "<i", nk._buf, self.nk_cell_offset)[0]
            self.cell_size = abs(signed_size)
        except Exception:
            pass

        self.nk_raw = b""
        try:
            name_length = nk.unpack_word(0x48)
            self.nk_raw = bytes(nk.unpack_binary(0, 0x4C + name_length))
        except Exception:
            if self.cell_size:
                data_length = max(0, self.cell_size - 4)
                self.nk_raw = bytes(
                    nk._buf[self.nk_offset:self.nk_offset + data_length])

        self.nk_digest = _sha256(self.nk_raw)
        self.normalized_nk_digest = _sha256(self._normalized_nk_bytes())

        self.children = list(registry_key.subkeys())
        self.child_names = [_normalized_name(child.name())
                            for child in self.children]
        self.values = []
        for value in registry_key.values():
            try:
                self.values.append(ValueSnapshot(self, value, side))
            except Exception:
                continue
        self.values_by_name = dict((value.normalized_name, value)
                                   for value in self.values)
        self.values_digest = _sha256("|".join(
            value.digest for value in sorted(
                self.values, key=lambda item: item.normalized_name)
        ).encode("utf-8"))
        self.content_digest = _sha256(json.dumps({
            "name": self.normalized_name,
            "flags": self.flags,
            "subkey_count": self.subkey_count,
            "values_digest": self.values_digest,
            "value_digests": sorted(value.digest for value in self.values),
        }, sort_keys=True, separators=(",", ":")).encode("utf-8"))

    def _normalized_nk_bytes(self):
        normalized = bytearray(self.nk_raw)
        for offset, length in (
            (0x04, 0x08),  # timestamp
            (0x10, 0x04),  # parent offset
            (0x1C, 0x04),  # stable subkey list offset
            (0x20, 0x04),  # volatile subkey list offset
            (0x28, 0x04),  # value list offset
            (0x2C, 0x04),  # security descriptor offset
            (0x30, 0x04),  # class name offset
        ):
            if offset + length <= len(normalized):
                normalized[offset:offset + length] = b"\x00" * length
        return bytes(normalized)

    def to_dict(self):
        return {
            "side": self.side,
            "name": self.name,
            "normalized_name": self.normalized_name,
            "path": self.logical_path,
            "registry_path": self.registry_path,
            "nk_offset": self.nk_offset,
            "nk_cell_offset": self.nk_cell_offset,
            "parent_offset": self.parent_offset,
            "flags": self.flags,
            "subkey_count": self.subkey_count,
            "value_count": self.value_count,
            "timestamp_ticks": self.timestamp_ticks,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "timestamp_available": self.timestamp_available,
            "nk_hex": _hex(self.nk_raw),
            "nk_sha256": self.nk_digest,
            "normalized_nk_sha256": self.normalized_nk_digest,
            "values_digest": self.values_digest,
            "content_digest": self.content_digest,
            "child_names": self.child_names,
            "values": [value.to_dict() for value in self.values],
        }


class HiveGeneration(object):
    def __init__(self, source, side="old", label=None):
        self.label = label or side
        self.side = side
        self.registry = open_registry(source)
        self.keys = []
        self.by_offset = {}
        self.by_path = {}
        self._snapshot_tree()

    def _snapshot_tree(self):
        root = self.registry.root()
        seen = set()

        def visit(registry_key, path_tuple, parent_offset):
            nk_offset = registry_key._nkrecord.offset()
            if nk_offset in seen:
                return None
            seen.add(nk_offset)
            snapshot = KeySnapshot(
                registry_key, self.side, path_tuple, parent_offset)
            self.keys.append(snapshot)
            self.by_offset[snapshot.nk_offset] = snapshot
            self.by_path[snapshot.path_tuple] = snapshot
            for child in snapshot.children:
                child_name = _normalized_name(child.name())
                visit(child, path_tuple + (child_name,), snapshot.nk_offset)
            return snapshot

        visit(root, (), None)

    def to_dict(self):
        return {
            "label": self.label,
            "side": self.side,
            "keys": [key.to_dict() for key in self.keys],
        }


def open_registry(source):
    if isinstance(source, Registry):
        return source
    if hasattr(source, "read"):
        return Registry(source)
    if isinstance(source, (bytes, bytearray)):
        return Registry(io.BytesIO(bytes(source)))
    if isinstance(source, str):
        return Registry(source)
    if _PathLike is not None and isinstance(source, _PathLike):
        return Registry(os.fspath(source))
    raise TypeError("unsupported hive source: %r" % (type(source),))


class Candidate(object):
    def __init__(self, candidate_id, old_key=None, new_key=None,
                 relation="correspondence", confidence=LOW, score=0,
                 support=None, conflicts=None, evidence=None):
        self.id = candidate_id
        self.old_key = old_key
        self.new_key = new_key
        self.relation = relation
        self.kind = relation
        self.confidence = confidence
        self.score = score
        self.support = list(support or [])
        self.conflicts = list(conflicts or [])
        self.evidence = list(evidence or [])
        self.ambiguous = False
        self.peer_ids = []

    @property
    def old_path(self):
        return self.old_key.logical_path if self.old_key else None

    @property
    def new_path(self):
        return self.new_key.logical_path if self.new_key else None

    def to_dict(self):
        return {
            "id": self.id,
            "kind": self.kind,
            "relation": self.relation,
            "confidence": self.confidence,
            "score": self.score,
            "ambiguous": self.ambiguous,
            "peer_ids": list(self.peer_ids),
            "old_path": self.old_path,
            "new_path": self.new_path,
            "old_nk_offset": self.old_key.nk_offset if self.old_key else None,
            "new_nk_offset": self.new_key.nk_offset if self.new_key else None,
            "support": self.support,
            "conflicts": self.conflicts,
            "evidence": [item.to_dict() for item in self.evidence],
        }


class Change(object):
    def __init__(self, change_id, kind, old_key=None, new_key=None,
                 candidates=None, confidence=LOW, ambiguous=False,
                 reasons=None, evidence=None):
        self.id = change_id
        self.kind = kind
        self.category = kind
        self.old_key = old_key
        self.new_key = new_key
        self.candidates = list(candidates or [])
        self.confidence = confidence
        self.ambiguous = ambiguous
        self.equal_candidates = ambiguous
        self.reasons = list(reasons or [])
        self.evidence = list(evidence or [])

    @property
    def old_path(self):
        return self.old_key.logical_path if self.old_key else None

    @property
    def new_path(self):
        return self.new_key.logical_path if self.new_key else None

    @property
    def path(self):
        return self.new_path or self.old_path

    def is_modified(self):
        return self.kind == MODIFIED

    def is_migration(self):
        return self.kind in (MIGRATED, MIGRATION_CANDIDATE)

    def is_rebuild_candidate(self):
        return self.kind == REBUILD_CANDIDATE

    def is_indeterminate(self):
        return self.kind == INDETERMINATE

    def to_dict(self):
        return {
            "id": self.id,
            "kind": self.kind,
            "category": self.category,
            "confidence": self.confidence,
            "ambiguous": self.ambiguous,
            "equal_candidates": self.equal_candidates,
            "old_path": self.old_path,
            "new_path": self.new_path,
            "path": self.path,
            "old_nk_offset": self.old_key.nk_offset if self.old_key else None,
            "new_nk_offset": self.new_key.nk_offset if self.new_key else None,
            "candidate_ids": [candidate.id for candidate in self.candidates],
            "candidates": [candidate.to_dict() for candidate in self.candidates],
            "reasons": self.reasons,
            "evidence": [item.to_dict() for item in self.evidence],
        }


class HiveDiff(object):
    def __init__(self, old, new, candidates, path_changes, changes):
        self.schema_version = SCHEMA_VERSION
        self.old = old
        self.new = new
        self.candidates = candidates
        self.correspondences = candidates
        self.matches = candidates
        self.path_changes = path_changes
        self.changes = changes
        self.events = changes
        self.findings = changes

    @property
    def evidence(self):
        result = []
        for candidate in self.candidates:
            result.extend(candidate.evidence)
        for change in self.changes:
            result.extend(change.evidence)
        for change in self.path_changes:
            result.extend(change.evidence)
        return result

    def _filter(self, kind):
        return [change for change in self.changes if change.kind == kind]

    @property
    def modified(self):
        return self._filter(MODIFIED)

    @property
    def migrations(self):
        return self._filter(MIGRATED)

    @property
    def migrated(self):
        return self.migrations

    @property
    def rebuild_candidates(self):
        return self._filter(REBUILD_CANDIDATE)

    @property
    def indeterminate(self):
        return self._filter(INDETERMINATE)

    @property
    def uncertain(self):
        return self.indeterminate

    @property
    def ambiguous(self):
        return [change for change in self.changes if change.ambiguous]

    @property
    def added(self):
        return self._filter(ADDED)

    @property
    def removed(self):
        return self._filter(REMOVED)

    @property
    def created(self):
        return self.added

    @property
    def deleted(self):
        return self.removed

    @property
    def rebuilt(self):
        return self.rebuild_candidates

    @property
    def unknown(self):
        return self.indeterminate

    @property
    def moved(self):
        return self.migrations

    @property
    def migration_candidates(self):
        return self._filter(MIGRATION_CANDIDATE)

    @property
    def timestamp_only(self):
        return self._filter(TIMESTAMP_ONLY)

    def changes_for_path(self, path):
        wanted = tuple(_normalized_name(part)
                       for part in path.replace("/", "\\").split("\\")
                       if part not in ("", "(default)"))
        results = []
        for change in self.changes:
            path_tuples = []
            if change.old_key is not None:
                path_tuples.append(change.old_key.path_tuple)
            if change.new_key is not None:
                path_tuples.append(change.new_key.path_tuple)
            for candidate in change.candidates:
                if candidate.old_key is not None:
                    path_tuples.append(candidate.old_key.path_tuple)
                if candidate.new_key is not None:
                    path_tuples.append(candidate.new_key.path_tuple)
            if wanted in path_tuples:
                results.append(change)
        return results

    def to_dict(self):
        return {
            "schema_version": self.schema_version,
            "old": self.old.to_dict(),
            "new": self.new.to_dict(),
            "candidates": [candidate.to_dict() for candidate in self.candidates],
            "path_changes": [change.to_dict() for change in self.path_changes],
            "changes": [change.to_dict() for change in self.changes],
        }


def compare_hives(old_source, new_source, old_label="old", new_label="new"):
    old = HiveGeneration(old_source, "old", old_label)
    new = HiveGeneration(new_source, "new", new_label)
    differ = _GenerationalDiffer(old, new)
    return differ.compare()


# Friendly aliases for callers expecting either naming convention.
generational_diff = compare_hives
diff_hives = compare_hives
compare_generations = compare_hives
compare_snapshots = compare_hives
diff_registries = compare_hives
diff_snapshots = compare_hives


def snapshot_hive(source, side="snapshot", label=None):
    return HiveGeneration(source, side=side, label=label)


class GenerationalDiff(object):
    """Facade for callers that prefer an object-oriented API."""

    def __init__(self, old_source=None, new_source=None, **kwargs):
        self._result = None
        if old_source is not None and new_source is not None:
            self._result = compare_hives(old_source, new_source, **kwargs)

    @classmethod
    def compare(cls, old_source, new_source, **kwargs):
        return compare_hives(old_source, new_source, **kwargs)

    def diff(self, old_source=None, new_source=None, **kwargs):
        if old_source is not None and new_source is not None:
            self._result = compare_hives(old_source, new_source, **kwargs)
        if self._result is None:
            raise ValueError("provide old_source and new_source to diff()")
        return self._result

    def __getattr__(self, name):
        result = self.__dict__.get("_result")
        if result is None:
            raise AttributeError(name)
        return getattr(result, name)


class _GenerationalDiffer(object):
    def __init__(self, old, new):
        self.old = old
        self.new = new
        self.candidate_number = 0
        self.change_number = 0

    def compare(self):
        candidates = self._build_candidates()
        self._resolve_ties(candidates)
        path_changes = self._build_path_changes()
        changes = self._build_changes(candidates)
        return HiveDiff(self.old, self.new, candidates, path_changes, changes)

    def _next_candidate_id(self):
        self.candidate_number += 1
        return "candidate-%d" % self.candidate_number

    def _next_change_id(self):
        self.change_number += 1
        return "change-%d" % self.change_number

    def _build_candidates(self):
        pairs = {}

        def add_pair(old_key, new_key, via):
            key = (old_key.nk_offset, new_key.nk_offset)
            if key in pairs:
                pairs[key]["via"].add(via)
                return
            pairs[key] = {"old": old_key, "new": new_key, "via": set([via])}

        for path, old_key in self.old.by_path.items():
            new_key = self.new.by_path.get(path)
            if new_key is not None:
                add_pair(old_key, new_key, "path")

        for offset, old_key in self.old.by_offset.items():
            new_key = self.new.by_offset.get(offset)
            if new_key is not None:
                add_pair(old_key, new_key, "offset")

        old_content = {}
        new_content = {}
        for key in self.old.keys:
            old_content.setdefault(key.content_digest, []).append(key)
        for key in self.new.keys:
            new_content.setdefault(key.content_digest, []).append(key)
        for digest, old_keys in old_content.items():
            if digest not in new_content:
                continue
            for old_key in old_keys:
                for new_key in new_content[digest]:
                    add_pair(old_key, new_key, "content")

        old_values = {}
        new_values = {}
        for key in self.old.keys:
            if key.values:
                old_values.setdefault(key.values_digest, []).append(key)
        for key in self.new.keys:
            if key.values:
                new_values.setdefault(key.values_digest, []).append(key)
        for digest, old_keys in old_values.items():
            if digest not in new_values or digest == _sha256(b""):
                continue
            for old_key in old_keys:
                for new_key in new_values[digest]:
                    add_pair(old_key, new_key, "values")

        candidates = []
        for item in pairs.values():
            signals = self._signals(item["old"], item["new"], item["via"])
            evidence = self._key_evidence(item["old"], item["new"])
            relation, confidence = self._classify_pair(signals)
            candidate = Candidate(
                self._next_candidate_id(),
                item["old"], item["new"], relation, confidence,
                signals["score"], signals["support"], signals["conflicts"],
                evidence)
            candidate.signals = signals
            candidates.append(candidate)
        return candidates

    def _signals(self, old_key, new_key, via):
        old_parent_path = old_key.path_tuple[:-1]
        new_parent_path = new_key.path_tuple[:-1]
        path_equal = old_key.path_tuple == new_key.path_tuple
        name_equal = old_key.normalized_name == new_key.normalized_name
        parent_path_equal = old_parent_path == new_parent_path
        offset_equal = old_key.nk_offset == new_key.nk_offset
        parent_offset_equal = (
            old_key.parent_offset is not None and
            old_key.parent_offset == new_key.parent_offset)
        timestamp_equal = (
            old_key.timestamp_available and new_key.timestamp_available and
            old_key.timestamp_ticks == new_key.timestamp_ticks)
        content_equal = old_key.content_digest == new_key.content_digest
        values_equal = old_key.values_digest == new_key.values_digest
        record_equal = old_key.normalized_nk_digest == new_key.normalized_nk_digest
        child_names_equal = old_key.child_names == new_key.child_names

        score = 0
        support = []
        if path_equal:
            score += 35
            support.append("same_path")
        if name_equal:
            score += 15
            support.append("same_name")
        if parent_path_equal:
            score += 15
            support.append("same_parent_path")
        if offset_equal:
            score += 20
            support.append("same_nk_offset")
        if parent_offset_equal:
            score += 10
            support.append("same_parent_offset")
        if content_equal:
            score += 25
            support.append("same_content_fingerprint")
        if values_equal and old_key.values:
            score += 15
            support.append("same_value_content")
        if record_equal:
            score += 15
            support.append("same_normalized_nk_record")
        if child_names_equal:
            score += 5
            support.append("same_child_names")
        if timestamp_equal:
            score += 5
            support.append("same_timestamp")
        if "path" in via and not path_equal:
            support.append("path_index")
        if "offset" in via and not offset_equal:
            support.append("offset_index")

        conflicts = []
        if offset_equal and not path_equal:
            conflicts.append("same_offset_different_path")
        if offset_equal and not name_equal:
            conflicts.append("same_offset_different_name")
        if path_equal and not offset_equal:
            conflicts.append("same_path_different_offset")
        if old_key.timestamp_available and new_key.timestamp_available and \
                old_key.timestamp_ticks != new_key.timestamp_ticks:
            conflicts.append("different_timestamp")
        if not values_equal:
            conflicts.append("different_value_content")
        if not record_equal:
            conflicts.append("different_normalized_nk_record")

        return {
            "score": score,
            "support": support,
            "conflicts": conflicts,
            "path_equal": path_equal,
            "name_equal": name_equal,
            "parent_path_equal": parent_path_equal,
            "offset_equal": offset_equal,
            "parent_offset_equal": parent_offset_equal,
            "timestamp_equal": timestamp_equal,
            "content_equal": content_equal,
            "values_equal": values_equal,
            "record_equal": record_equal,
            "child_names_equal": child_names_equal,
            "via": sorted(via),
        }

    def _only_timestamp_changed(self, signals, old_key, new_key):
        if signals["timestamp_equal"]:
            return False
        if not signals["values_equal"]:
            return False
        if not signals["record_equal"]:
            return False
        return True

    def _classify_pair(self, signals):
        path_equal = signals["path_equal"]
        offset_equal = signals["offset_equal"]
        name_equal = signals["name_equal"]
        content_equal = signals["content_equal"]
        values_equal = signals["values_equal"]
        record_equal = signals["record_equal"]

        if path_equal and offset_equal and name_equal:
            if self._only_timestamp_changed(signals, None, None):
                return TIMESTAMP_ONLY, MEDIUM
            if content_equal and record_equal and signals["timestamp_equal"]:
                return UNCHANGED, HIGH
            if record_equal and signals["parent_offset_equal"]:
                return MODIFIED, HIGH
            return MODIFIED, MEDIUM

        if path_equal and not offset_equal:
            return REBUILD_CANDIDATE, MEDIUM

        if offset_equal and not path_equal:
            if name_equal and (content_equal or values_equal or record_equal):
                return MIGRATED, MEDIUM
            return INDETERMINATE, LOW

        if not path_equal and (content_equal or values_equal):
            return MIGRATION_CANDIDATE, LOW

        return INDETERMINATE, LOW

    def _key_evidence(self, old_key, new_key):
        evidence = []
        if old_key.timestamp_ticks != new_key.timestamp_ticks:
            evidence.append(ByteEvidence(
                "nk_timestamp",
                "NK last-write timestamp bytes",
                old_key.nk_offset + 0x04,
                new_key.nk_offset + 0x04,
                struct.pack("<Q", old_key.timestamp_ticks),
                struct.pack("<Q", new_key.timestamp_ticks)))

        if old_key.parent_pointer != new_key.parent_pointer:
            evidence.append(ByteEvidence(
                "nk_parent_pointer",
                "NK parent relative offset field",
                old_key.nk_offset + 0x10,
                new_key.nk_offset + 0x10,
                struct.pack("<I", old_key.parent_pointer or 0),
                struct.pack("<I", new_key.parent_pointer or 0)))

        if old_key.nk_raw != new_key.nk_raw:
            evidence.append(ByteEvidence(
                "nk_record",
                "Logical NK record bytes",
                old_key.nk_offset,
                new_key.nk_offset,
                old_key.nk_raw,
                new_key.nk_raw))

        for name, old_value in old_key.values_by_name.items():
            new_value = new_key.values_by_name.get(name)
            if new_value is None:
                evidence.append(ByteEvidence(
                    "missing_value", "Value absent from new generation",
                    old_offset=old_value.vk_offset,
                    old_bytes=old_value.vk_raw))
                continue
            evidence.extend(self._value_evidence(old_value, new_value))

        for name, new_value in new_key.values_by_name.items():
            if name not in old_key.values_by_name:
                evidence.append(ByteEvidence(
                    "added_value", "Value absent from old generation",
                    new_offset=new_value.vk_offset,
                    new_bytes=new_value.vk_raw))
        return evidence

    def _value_evidence(self, old_value, new_value):
        evidence = []
        if old_value.raw_bytes != new_value.raw_bytes or \
                old_value.value_type != new_value.value_type:
            for start, end in _diff_ranges(old_value.raw_bytes,
                                           new_value.raw_bytes):
                old_start = None
                new_start = None
                if old_value.data_offset is not None:
                    old_start = old_value.data_offset + start
                if new_value.data_offset is not None:
                    new_start = new_value.data_offset + start
                evidence.append(ByteEvidence(
                    "value_data",
                    "Raw value data changed",
                    old_start,
                    new_start,
                    old_value.raw_bytes[start:end],
                    new_value.raw_bytes[start:end]))

        if old_value.vk_raw != new_value.vk_raw:
            evidence.append(ByteEvidence(
                "vk_record",
                "Logical VK record bytes changed",
                old_value.vk_offset,
                new_value.vk_offset,
                old_value.vk_raw,
                new_value.vk_raw))
        return evidence

    def _resolve_ties(self, candidates):
        by_old = {}
        for candidate in candidates:
            if candidate.old_key is not None:
                by_old.setdefault(candidate.old_key.nk_offset, []).append(candidate)

        for group in by_old.values():
            best_score = max(item.score for item in group)
            winners = [item for item in group if item.score == best_score]
            if len(winners) > 1:
                winner_ids = set(item.id for item in winners)
                for item in winners:
                    item.ambiguous = True
                    item.peer_ids = sorted(winner_ids - set([item.id]))

    def _build_path_changes(self):
        changes = []
        old_paths = self.old.by_path
        new_paths = self.new.by_path
        change_number = 0

        for path in sorted(set(old_paths) | set(new_paths)):
            old_key = old_paths.get(path)
            new_key = new_paths.get(path)
            change_number += 1
            if old_key is None:
                kind = ADDED
                evidence = [ByteEvidence(
                    "nk_record", "NK record at added path",
                    new_offset=new_key.nk_offset, new_bytes=new_key.nk_raw)]
            elif new_key is None:
                kind = REMOVED
                evidence = [ByteEvidence(
                    "nk_record", "NK record at removed path",
                    old_offset=old_key.nk_offset, old_bytes=old_key.nk_raw)]
            elif old_key.nk_raw == new_key.nk_raw and \
                    old_key.values_digest == new_key.values_digest:
                kind = UNCHANGED
                evidence = []
            else:
                kind = MODIFIED
                evidence = self._key_evidence(old_key, new_key)
            changes.append(Change(
                "path-change-%d" % change_number, kind,
                old_key, new_key, confidence=HIGH if old_key and new_key else MEDIUM,
                evidence=evidence))
        return changes

    def _build_changes(self, candidates):
        by_old = {}
        for candidate in candidates:
            if candidate.old_key is not None:
                by_old.setdefault(candidate.old_key.nk_offset, []).append(candidate)

        changes = []
        referenced_new = set()

        for old_key in self.old.keys:
            group = by_old.get(old_key.nk_offset, [])
            if not group:
                changes.append(Change(
                    self._next_change_id(), REMOVED, old_key=old_key,
                    confidence=HIGH,
                    reasons=["no_corresponding_active_key"],
                    evidence=[ByteEvidence(
                        "nk_record", "Last available NK bytes",
                        old_offset=old_key.nk_offset,
                        old_bytes=old_key.nk_raw)]))
                continue

            best_score = max(item.score for item in group)
            winners = [item for item in group if item.score == best_score]
            for candidate in group:
                if candidate.new_key is not None:
                    referenced_new.add(candidate.new_key.nk_offset)

            if len(winners) > 1:
                evidence = []
                for candidate in winners:
                    evidence.extend(candidate.evidence)
                changes.append(Change(
                    self._next_change_id(), INDETERMINATE, old_key=old_key,
                    candidates=winners, confidence=LOW, ambiguous=True,
                    reasons=["multiple_equal_scoring_candidates"],
                    evidence=evidence))
                continue

            winner = winners[0]
            referenced_new.add(winner.new_key.nk_offset)
            kind = winner.relation
            confidence = winner.confidence
            ambiguous = False
            reasons = list(winner.support)

            if kind in (INDETERMINATE,):
                changes.append(Change(
                    self._next_change_id(), INDETERMINATE, old_key=old_key,
                    new_key=winner.new_key, candidates=[winner],
                    confidence=LOW, reasons=winner.conflicts + reasons,
                    evidence=winner.evidence))
            else:
                changes.append(Change(
                    self._next_change_id(), kind, old_key=old_key,
                    new_key=winner.new_key, candidates=[winner],
                    confidence=confidence, ambiguous=ambiguous,
                    reasons=reasons, evidence=winner.evidence))

        for new_key in self.new.keys:
            if new_key.nk_offset in referenced_new:
                continue
            changes.append(Change(
                self._next_change_id(), ADDED, new_key=new_key,
                confidence=HIGH, reasons=["no_corresponding_old_key"],
                evidence=[ByteEvidence(
                    "nk_record", "New NK bytes",
                    new_offset=new_key.nk_offset, new_bytes=new_key.nk_raw)]))

        return changes
