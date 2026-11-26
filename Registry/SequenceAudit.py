from __future__ import print_function

import json
import os
import re
from collections import defaultdict, deque

from . import Registry as registry_api


ORDINAL_KEYS = (
    "baseline_ordinal",
    "original_ordinal",
    "source_ordinal",
    "approved_ordinal",
    "ordinal",
    "原序号",
    "原始序号",
    "序号",
)

ZERO_BASED_INDEX_KEYS = ("original_index", "baseline_index", "source_index", "index")
VALUE_KEYS = (
    "member", "recipient", "approved_value", "member_value",
    "value", "name", "成员", "接收者"
)
NOTE_KEYS = ("note", "notes", "description", "approval_note", "说明", "批准说明")
ID_KEYS = ("id", "approval_id", "ticket", "ticket_id", "审批编号")
ACTION_KEYS = ("action", "operation", "type", "动作")
APPEND_ACTIONS = {"append", "add", "authorize", "authorised", "authorized", "追加", "新增"}


def _first_present(mapping, keys):
    for key in keys:
        if key in mapping and mapping[key] is not None:
            return mapping[key]
    return None


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def build_alias_map(aliases=None, case_insensitive=False):
    alias_map = {}

    def fold(value):
        if case_insensitive and isinstance(value, str):
            return value.casefold()
        return value

    def bind(alias, canonical):
        alias_map[fold(alias)] = fold(canonical)

    for item in _as_list(aliases):
        if isinstance(item, dict):
            for key, value in item.items():
                if isinstance(value, (list, tuple, set)):
                    bind(key, key)
                    for alias in value:
                        bind(alias, key)
                elif isinstance(value, str):
                    bind(key, key)
                    bind(value, key)
        elif isinstance(item, (list, tuple)) and item:
            canonical = item[0]
            for alias in item:
                bind(alias, canonical)
        elif isinstance(item, str):
            bind(item, item)

    return alias_map


def identity_for(value, alias_map=None, case_insensitive=False):
    folded = value.casefold() if case_insensitive and isinstance(value, str) else value
    alias_map = alias_map or {}
    return alias_map.get(folded, folded)


class SequenceMember(object):
    def __init__(self, ordinal, value, key_path=None, value_name=None,
                 key_offset=None, value_offset=None, byte_offset=None,
                 byte_length=None, raw_hex=None, identity=None,
                 absolute_offset=None):
        self.ordinal = ordinal
        self.index = ordinal - 1
        self.value = value
        self.key_path = key_path
        self.value_name = value_name
        self.key_offset = key_offset
        self.value_offset = value_offset
        self.byte_offset = byte_offset
        self.byte_length = byte_length
        self.raw_hex = raw_hex
        self.identity = identity if identity is not None else value
        self.absolute_offset = absolute_offset

    def to_dict(self):
        return {
            "ordinal": self.ordinal,
            "index": self.index,
            "value": self.value,
            "identity": self.identity,
            "key_path": self.key_path,
            "value_name": self.value_name,
            "key_offset": _hex(self.key_offset),
            "value_offset": _hex(self.value_offset),
            "byte_offset": self.byte_offset,
            "absolute_offset": _hex(self.absolute_offset),
            "byte_length": self.byte_length,
            "raw_hex": self.raw_hex,
        }


class SequenceSnapshot(object):
    def __init__(self, source=None, hive=None, key_path=None, value_name=None,
                 key_offset=None, value_offset=None, raw_hex=None, members=None):
        self.source = source
        self.hive = hive
        self.key_path = key_path
        self.value_name = value_name
        self.key_offset = key_offset
        self.value_offset = value_offset
        self.raw_encoding = "utf-16le"
        self.raw_hex = raw_hex
        self.raw_data_offset = None
        self.members = members or []

    @property
    def values(self):
        return [member.value for member in self.members]

    def ordinal(self, number):
        for member in self.members:
            if member.ordinal == number:
                return member
        return None

    def to_dict(self):
        return {
            "source": self.source,
            "hive": self.hive,
            "key_path": self.key_path,
            "value_name": self.value_name,
            "key_offset": _hex(self.key_offset),
            "value_offset": _hex(self.value_offset),
            "raw_data_offset": _hex(self.raw_data_offset),
            "raw_encoding": self.raw_encoding,
            "raw_hex": self.raw_hex,
            "values": self.values,
            "members": [member.to_dict() for member in self.members],
        }


def _hex(value):
    if value is None:
        return None
    return hex(value)


def snapshot_from_value(registry_value, key=None, source=None, alias_map=None,
                        case_insensitive=False):
    key_path = key.path() if key is not None else None
    key_offset = key._nkrecord.offset() if key is not None else None
    vk = registry_value._vkrecord
    value_name = registry_value.name()
    raw = registry_value.raw_data() or b""
    parsed = vk.multisz_members()
    raw_length_field = vk.raw_data_length()
    data_offset = vk.data_offset()
    if raw_length_field >= 0x80000000:
        raw_data_offset = data_offset
    elif raw_length_field <= 0x3FD8:
        raw_data_offset = data_offset + 4
    else:
        raw_data_offset = None

    members = []
    for item in parsed:
        value = item.value
        members.append(SequenceMember(
            ordinal=item.ordinal,
            value=value,
            key_path=key_path,
            value_name=value_name,
            key_offset=key_offset,
            value_offset=vk.offset(),
            byte_offset=item.byte_offset,
            byte_length=item.byte_length,
            raw_hex=item.raw_bytes.hex(),
            identity=identity_for(value, alias_map, case_insensitive),
            absolute_offset=(raw_data_offset + item.byte_offset
                             if raw_data_offset is not None else None),
        ))

    snapshot = SequenceSnapshot(
        source=source,
        key_path=key_path,
        value_name=value_name,
        key_offset=key_offset,
        value_offset=vk.offset(),
        raw_hex=raw.hex(),
        members=members,
    )
    snapshot.raw_data_offset = raw_data_offset
    return snapshot


def read_sequence(hive, key_path=None, value_name=None, alias_map=None,
                  aliases=None, case_insensitive=False):
    """Read one ordered REG_MULTI_SZ from a path, stream, Registry, key, or value."""
    if alias_map is None and aliases is not None:
        alias_map = build_alias_map(aliases, case_insensitive)
    source = None
    key = None

    if isinstance(hive, registry_api.RegistryValue):
        parent_key = key_path if isinstance(key_path, registry_api.RegistryKey) else None
        return snapshot_from_value(
            hive, parent_key, alias_map=alias_map,
            case_insensitive=case_insensitive
        )

    if isinstance(hive, registry_api.RegistryKey):
        key = hive
        if value_name is None and isinstance(key_path, str):
            value_name = key_path
    elif isinstance(hive, registry_api.Registry):
        reg = hive
    elif hasattr(hive, "read"):
        reg = registry_api.Registry(hive)
    elif isinstance(hive, (str, bytes, os.PathLike)):
        source = os.fspath(hive)
        reg = registry_api.Registry(source)
    else:
        raise TypeError("Unsupported hive/sequence source: %r" % type(hive))

    if key is None:
        key = _open_key(reg, key_path)
    if key is None:
        raise ValueError("A key path or RegistryKey is required")
    if value_name is None:
        raise ValueError("A value name is required")

    value = key.value(value_name)
    snapshot = snapshot_from_value(
        value, key=key, source=source, alias_map=alias_map,
        case_insensitive=case_insensitive
    )
    if source:
        snapshot.hive = os.path.basename(source)
    return snapshot


load_sequence = read_sequence


def _open_key(reg, key_path):
    root = reg.root()
    if key_path is None or key_path == "":
        return root

    separator = chr(92)
    normalized = key_path.replace("/", separator)
    if normalized in (root.name(), root.path()):
        return root

    first, separator, remainder = normalized.partition(separator)
    if first.lower() == root.name().lower():
        return root.find_key(remainder) if remainder else root
    try:
        return reg.open(normalized)
    except Exception:
        parts = [part for part in normalized.split(separator) if part]
        for start in range(1, len(parts)):
            candidate = separator.join(parts[start:])
            try:
                return _open_key(reg, candidate)
            except Exception:
                continue
        raise


def _coerce_snapshot(sequence, alias_map=None, case_insensitive=False):
    if isinstance(sequence, SequenceSnapshot):
        if alias_map:
            for member in sequence.members:
                member.identity = identity_for(member.value, alias_map, case_insensitive)
        return sequence

    values = sequence if isinstance(sequence, (list, tuple)) else list(sequence)
    members = []
    for ordinal, value in enumerate(values, 1):
        if isinstance(value, SequenceMember):
            members.append(value)
        elif isinstance(value, dict):
            member = SequenceMember(
                ordinal=value.get("ordinal", ordinal),
                value=value.get("value", ""),
                identity=value.get("identity"),
            )
            if member.identity is None:
                member.identity = identity_for(member.value, alias_map, case_insensitive)
            members.append(member)
        else:
            members.append(SequenceMember(
                ordinal=ordinal,
                value=value,
                identity=identity_for(value, alias_map, case_insensitive),
            ))
    return SequenceSnapshot(members=members)


class SequenceComparison(object):
    def __init__(self, before, after, matches, added, removed):
        self.before = before
        self.after = after
        self.matches = matches
        self.added = added
        self.removed = removed
        self.set_before = set(before.values)
        self.set_after = set(after.values)
        self.set_added = self.set_after - self.set_before
        self.set_removed = self.set_before - self.set_after
        baseline_order = [match["before_ordinal"] for match in matches]
        self.order_changed = baseline_order != sorted(baseline_order)
        self.reorder_only = not added and not removed and self.order_changed
        self.unchanged = not added and not removed and not self.order_changed
        self.set_misses_occurrence_change = self.set_before == self.set_after and (
            len(before.members) != len(after.members) or self.order_changed
        )

    @property
    def appended(self):
        return self.added

    def to_dict(self):
        return {
            "before": self.before.to_dict(),
            "after": self.after.to_dict(),
            "matches": self.matches,
            "added": self.added,
            "removed": self.removed,
            "appended": self.added,
            "set_before": sorted(self.set_before),
            "set_after": sorted(self.set_after),
            "set_added": sorted(self.set_added),
            "set_removed": sorted(self.set_removed),
            "order_changed": self.order_changed,
            "reorder_only": self.reorder_only,
            "unchanged": self.unchanged,
            "set_misses_occurrence_change": self.set_misses_occurrence_change,
        }


def compare_sequences(before, after, aliases=None, case_insensitive=False,
                      alias_map=None):
    resolved_alias_map = build_alias_map(aliases, case_insensitive)
    if alias_map:
        resolved_alias_map.update(alias_map)
    alias_map = resolved_alias_map
    before = _coerce_snapshot(before, alias_map, case_insensitive)
    after = _coerce_snapshot(after, alias_map, case_insensitive)

    queues = defaultdict(deque)
    for member in before.members:
        key = identity_for(member.value, alias_map, case_insensitive)
        member.identity = key
        queues[key].append(member)

    after_occurrence = defaultdict(int)
    matches = []
    added = []
    for member in after.members:
        key = identity_for(member.value, alias_map, case_insensitive)
        member.identity = key
        after_occurrence[key] += 1
        duplicate_number = after_occurrence[key]
        if queues[key]:
            source = queues[key].popleft()
            matches.append({
                "value": member.value,
                "identity": key,
                "before_ordinal": source.ordinal,
                "after_ordinal": member.ordinal,
                "before_duplicate_number": _occurrence_number(before, source),
                "after_duplicate_number": duplicate_number,
                "position_delta": member.ordinal - source.ordinal,
            })
        else:
            added.append({
                "value": member.value,
                "identity": key,
                "current_ordinal": member.ordinal,
                "duplicate_number": duplicate_number,
                "at_end": member.ordinal == len(after.members),
                "raw_hex": member.raw_hex,
                "value_offset": _hex(member.value_offset),
                "byte_offset": member.byte_offset,
                "absolute_offset": _hex(member.absolute_offset),
            })

    removed = []
    for queue in queues.values():
        for source in queue:
            removed.append({
                "value": source.value,
                "identity": source.identity,
                "baseline_ordinal": source.ordinal,
                "raw_hex": source.raw_hex,
            })

    removed.sort(key=lambda item: item["baseline_ordinal"])
    return SequenceComparison(before, after, matches, added, removed)


def _occurrence_number(snapshot, target):
    number = 0
    for member in snapshot.members:
        if member.identity == target.identity:
            number += 1
        if member.ordinal == target.ordinal:
            return number
    return number


def parse_approval_note(note):
    result = {}
    if not isinstance(note, str):
        return result

    ordinal_patterns = (
        r"(?:baseline|original|source)[ _-]?ordinal[ #：:]*([0-9]+)",
        r"ordinal[ #：:]*([0-9]+)",
        r"原序号[ #：:]*([0-9]+)",
        r"原始序号[ #：:]*([0-9]+)",
        r"序号[ #：:]*([0-9]+)",
        r"第[ ]*([0-9]+)[ ]*(?:项|个|号|条)",
        r"#([0-9]+)",
    )
    for pattern in ordinal_patterns:
        match = re.search(pattern, note, flags=re.IGNORECASE)
        if match:
            result["baseline_ordinal"] = int(match.group(1))
            break

    quoted = re.search(r"""[“"']([^”"']+)[”"']""", note)
    if quoted:
        result["value"] = quoted.group(1)
    return result


def load_approval_record(record):
    if isinstance(record, (str, bytes, os.PathLike)) and os.path.exists(os.fspath(record)):
        with open(record, "r", encoding="utf-8") as handle:
            return json.load(handle)
    if hasattr(record, "read"):
        return json.load(record)
    if isinstance(record, str):
        try:
            return json.loads(record)
        except ValueError:
            return {"approvals": [{"note": record}]}
    return record


def normalize_approvals(record):
    record = load_approval_record(record)
    if not record:
        return []
    if isinstance(record, list):
        return [item if isinstance(item, dict) else {"note": item} for item in record]
    if isinstance(record, dict):
        for key in ("approvals", "records", "approved_changes", "items", "审批记录"):
            if isinstance(record.get(key), list):
                return record[key]
        if _first_present(record, ID_KEYS + ORDINAL_KEYS + VALUE_KEYS + NOTE_KEYS):
            return [record]
    return []


def approval_value(approval):
    note = _first_present(approval, NOTE_KEYS)
    parsed_note = parse_approval_note(note) if note else {}
    return _first_present(approval, VALUE_KEYS) or parsed_note.get("value")


def approval_ordinal(approval):
    note = _first_present(approval, NOTE_KEYS)
    parsed_note = parse_approval_note(note) if note else {}
    ordinal = _first_present(approval, ORDINAL_KEYS)
    if ordinal is None:
        index = _first_present(approval, ZERO_BASED_INDEX_KEYS)
        if index is not None:
            return int(index) + 1
    if ordinal is None:
        ordinal = parsed_note.get("baseline_ordinal")
    return int(ordinal) if ordinal is not None else None


def _approval_aliases(approval, global_alias_map):
    aliases = dict(global_alias_map or {})
    extra = approval.get("aliases") or approval.get("alias") or approval.get("别名")
    approved_value = approval_value(approval)
    if extra and approved_value:
        extra = _as_list(extra)
        aliases.update(build_alias_map({approved_value: extra}))
    return aliases


def _scope_matches(approval, snapshot):
    key_path = approval.get("key_path") or approval.get("key") or approval.get("键路径")
    value_name = (approval.get("value_name") or approval.get("registry_value")
                  or approval.get("值名称"))
    if key_path and snapshot.key_path and not _key_path_matches(key_path, snapshot.key_path):
        return False
    if value_name and snapshot.value_name and value_name.lower() != snapshot.value_name.lower():
        return False
    return True


def _key_path_matches(expected, actual):
    separator = chr(92)

    def parts(path):
        return [part.lower() for part in str(path).replace("/", separator).split(separator) if part]

    expected_parts = parts(expected)
    actual_parts = parts(actual)
    if not expected_parts or not actual_parts:
        return False
    common_length = min(len(expected_parts), len(actual_parts))
    return expected_parts[-common_length:] == actual_parts[-common_length:]


def audit_comparison(comparison, approval_record=None, aliases=None, case_insensitive=False):
    record = load_approval_record(approval_record)
    approvals = normalize_approvals(record)
    global_alias_map = build_alias_map(aliases, case_insensitive)
    if isinstance(record, dict) and record.get("aliases"):
        global_alias_map.update(build_alias_map(record.get("aliases"), case_insensitive))
    decisions = []
    used = set()

    for candidate in comparison.added:
        decision = {
            "status": "unauthorized",
            "current_ordinal": candidate["current_ordinal"],
            "value": candidate["value"],
            "identity": candidate["identity"],
            "at_end": candidate["at_end"],
        }

        for approval_index, approval in enumerate(approvals):
            if approval_index in used or not isinstance(approval, dict):
                continue
            action = _first_present(approval, ACTION_KEYS)
            if action and str(action).lower() not in APPEND_ACTIONS:
                continue
            if not _scope_matches(approval, comparison.after):
                continue

            ordinal = approval_ordinal(approval)
            approved_value = approval_value(approval)
            alias_map = _approval_aliases(approval, global_alias_map)
            source = comparison.before.ordinal(ordinal) if ordinal is not None else None
            extra_aliases = approval.get("aliases") or approval.get("alias") or approval.get("别名")
            if extra_aliases and source is not None:
                alias_map.update(build_alias_map(
                    {source.value: _as_list(extra_aliases)}, case_insensitive
                ))

            if ordinal is not None and source is None:
                decision["status"] = "invalid_approval"
                decision["approval_id"] = _first_present(approval, ID_KEYS)
                decision["reason"] = "approval cites missing baseline ordinal %s" % ordinal
                continue

            if source is not None:
                expected_identity = identity_for(source.value, alias_map, case_insensitive)
                candidate_identity = identity_for(candidate["value"], alias_map, case_insensitive)
                if candidate_identity != expected_identity:
                    decision["failed_approval_id"] = _first_present(approval, ID_KEYS)
                    decision["baseline_ordinal"] = ordinal
                    decision["reason"] = (
                        "candidate does not match baseline ordinal %s (%r)" % (ordinal, source.value)
                    )
                    continue
            elif approved_value is not None:
                expected_identity = identity_for(approved_value, alias_map, case_insensitive)
                candidate_identity = identity_for(candidate["value"], alias_map, case_insensitive)
                if candidate_identity != expected_identity:
                    continue
                possible = [
                    member.ordinal for member in comparison.before.members
                    if identity_for(member.value, alias_map, case_insensitive) == expected_identity
                ]
                ordinal = possible[0] if len(possible) == 1 else None
                if len(possible) > 1:
                    decision["ambiguous_baseline_ordinals"] = possible
            else:
                continue

            used.add(approval_index)
            decision.update({
                "status": "authorized",
                "approval_id": _first_present(approval, ID_KEYS),
                "baseline_ordinal": ordinal,
                "reason": "approved append maps to baseline ordinal %s" % ordinal,
            })
            break

        decisions.append(decision)

    authorized = [item for item in decisions if item["status"] == "authorized"]
    unauthorized = [item for item in decisions if item["status"] != "authorized"]

    if comparison.reorder_only:
        verdict = "reorder-only; no append is present, so no append authorization is required"
    elif not comparison.added:
        verdict = "no appended occurrence detected"
    elif not unauthorized:
        verdict = "all appended occurrences are authorized"
    elif authorized:
        verdict = "one or more appends are authorized; at least one occurrence is not"
    else:
        verdict = "no appended occurrence matches an approval record"

    return AuditReport(comparison, decisions, authorized, unauthorized, verdict)


class AuditReport(object):
    def __init__(self, comparison, decisions, authorized, unauthorized, verdict):
        self.comparison = comparison
        self.decisions = decisions
        self.authorized = authorized
        self.unauthorized = unauthorized
        self.verdict = verdict

    def to_dict(self):
        result = self.comparison.to_dict()
        result.update({
            "decisions": self.decisions,
            "authorized_appends": self.authorized,
            "unauthorized_appends": self.unauthorized,
            "verdict": self.verdict,
        })
        return result


def audit_sequences(before, after, approval_record=None, aliases=None,
                    case_insensitive=False, approvals=None, approval=None):
    if approval_record is None:
        approval_record = approvals if approvals is not None else approval
    comparison = compare_sequences(before, after, aliases, case_insensitive)
    return audit_comparison(comparison, approval_record, aliases, case_insensitive)


def audit_hives(baseline_hive, current_hive, key_path, value_name,
                approval_record=None, aliases=None, case_insensitive=False,
                approvals=None, approval=None):
    if approval_record is None:
        approval_record = approvals if approvals is not None else approval
    alias_map = build_alias_map(aliases, case_insensitive)
    before = read_sequence(
        baseline_hive, key_path, value_name,
        alias_map=alias_map, case_insensitive=case_insensitive
    )
    after = read_sequence(
        current_hive, key_path, value_name,
        alias_map=alias_map, case_insensitive=case_insensitive
    )
    return audit_sequences(before, after, approval_record, aliases, case_insensitive)


def compare_hives(baseline_hive, current_hive, key_path, value_name,
                  aliases=None, case_insensitive=False):
    alias_map = build_alias_map(aliases, case_insensitive)
    before = read_sequence(
        baseline_hive, key_path, value_name,
        alias_map=alias_map, case_insensitive=case_insensitive
    )
    after = read_sequence(
        current_hive, key_path, value_name,
        alias_map=alias_map, case_insensitive=case_insensitive
    )
    return compare_sequences(before, after, aliases, case_insensitive)


sequence_diff = compare_sequences
diff_sequences = compare_sequences
hive_sequence_diff = compare_hives
diff_hives = compare_hives
audit_sequence = audit_sequences
authorize_changes = audit_sequences
