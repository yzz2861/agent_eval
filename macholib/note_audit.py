"""Read-only provenance audit helpers for Mach-O ``LC_NOTE`` commands."""

from __future__ import absolute_import, division, print_function

import hashlib
import io
import os

from .mach_o import CPU_TYPE_NAMES, LC_NOTE, get_cpu_subtype
from .MachO import MachO

__all__ = [
    "audit",
    "CONFIRMED",
    "KNOWN_OWNER_UNVERIFIED_ORIGIN",
    "UNKNOWN_OWNER",
    "OwnerRegistry",
    "NoteRegistry",
    "NoteOwnerRegistry",
    "NoteOwnerRegistration",
    "AuditDict",
    "NoteAuditRecord",
    "NoteAuditReport",
    "audit_lc_notes",
    "audit_notes",
    "audit_file",
    "audit_path",
    "verify_notes",
    "review_notes",
    "read_lc_notes",
    "read_notes",
    "parse_lc_notes",
    "collect_lc_notes",
    "build_owner_registry",
    "find_overlaps",
    "format_audit_report",
    "format_audit_report_zh",
    "reconcile_overlaps",
    "register_note_owner",
]


class AuditStatus(str):
    """String status that also compares equal to common synonym spellings."""

    def __new__(cls, canonical, aliases=()):
        obj = str.__new__(cls, canonical)
        obj.aliases = tuple(aliases)
        return obj

    def __eq__(self, other):
        if isinstance(other, AuditStatus):
            return str(self) == str(other) or bool(
                set(self.aliases) & set(other.aliases)
            )
        return str.__eq__(self, other) or other in self.aliases

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return str.__hash__(self)


UNKNOWN_OWNER = AuditStatus(
    "unknown_owner",
    ("unknown", "unknown-owner", "unregistered", "unregistered_owner"),
)
REGISTERED_OWNER = AuditStatus(
    "known_owner",
    ("registered_owner", "registered", "known", "known-owner"),
)
KNOWN_OWNER_UNVERIFIED_ORIGIN = AuditStatus(
    "known_owner_unverified_origin",
    (
        "unverified",
        "unverified_owner",
        "unverified_origin",
        "unverified_provenance",
        "unprovenanced",
        "known_owner_unverified",
        "known-owner-unverified",
        "known_owner_unprovenanced",
        "known_owner_without_provenance",
    ),
)
# Common descriptive aliases used by callers and tests.
KNOWN_OWNER_WITHOUT_PROVENANCE = KNOWN_OWNER_UNVERIFIED_ORIGIN
UNVERIFIED_PROVENANCE = KNOWN_OWNER_UNVERIFIED_ORIGIN
VERIFIED_PROVENANCE = AuditStatus(
    "verified_provenance", ("verified", "provenance_verified")
)
CONFIRMED = AuditStatus("confirmed", ("confirmable", "confirmation_eligible"))
CONFIRMED_WITH_OVERLAP = AuditStatus(
    "confirmed_with_overlap_warning", ("overlap_warning", "confirmed_with_overlap")
)
INCOMPLETE_READ = AuditStatus(
    "incomplete_read", ("truncated", "partial_read", "unreadable")
)
OUTSIDE_SLICE = AuditStatus("outside_declared_slice", ("outside", "outside_slice"))
OVERLAP_CONFLICT = AuditStatus(
    "range_overlap_conflict", ("overlap", "ambiguous_overlap", "overlap_conflict")
)


class AuditDict(dict):
    """Dictionary with attribute access used for audit records."""

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)

    def __setattr__(self, name, value):
        self[name] = value


def _owner_text(owner):
    if owner is None:
        return "", b""
    if isinstance(owner, bytes):
        raw = bytes(owner)
    else:
        text = str(owner)
        raw = text.encode("utf-8", "replace")
    nul = raw.find(b"\0")
    exact = raw if nul < 0 else raw[:nul]
    try:
        text = exact.decode("utf-8")
    except UnicodeDecodeError:
        text = exact.decode("latin-1")
    return text, raw


def _padded_owner_bytes(owner):
    text, raw = _owner_text(owner)
    return raw[:16].ljust(16, b"\0")


class NoteOwnerRegistration(AuditDict):
    """Registered interpretation and optional provenance checks for an owner."""

    def __init__(
        self,
        owner,
        basis=None,
        interpretation=None,
        reference=None,
        source=None,
        provenance=None,
        verifier=None,
        validator=None,
        checks=None,
        **metadata,
    ):
        super(NoteOwnerRegistration, self).__init__()
        owner_text, owner_raw = _owner_text(owner)
        self.update(
            {
                "owner": owner_text,
                "owner_raw": owner_raw,
                "basis": basis,
                "interpretation": interpretation or basis,
                "reference": reference,
                "source": source,
                "provenance": provenance,
                "verifier": verifier,
                "validator": validator,
                "checks": AuditDict(checks or {}),
                "metadata": AuditDict(metadata),
            }
        )
        self.update(metadata)

    def check_provenance(self, record):
        """Return ``(proof, error)`` for a parsed note record."""
        checks = AuditDict(self.get("checks") or {})
        for key in ("sha256", "sha1", "md5", "prefix", "magic", "equals"):
            if self.get(key) is not None and key not in checks:
                checks[key] = self[key]

        proof = AuditDict({"checks": []})
        performed = False

        for algorithm in ("sha256", "sha1", "md5"):
            expected = checks.get(algorithm)
            if expected is None:
                continue
            performed = True
            data = record.readable_bytes or b""
            actual = hashlib.new(algorithm, data).hexdigest()
            expected_hex = str(expected).lower().replace(" ", "")
            if isinstance(expected, bytes):
                expected_hex = expected.decode("ascii").lower()
            if actual != expected_hex:
                return None, AuditDict(
                    {
                        "code": "digest_mismatch",
                        "algorithm": algorithm,
                        "expected": expected_hex,
                        "actual": actual,
                    }
                )
            proof["checks"].append(algorithm)

        prefix = checks.get("prefix", checks.get("magic"))
        if prefix is not None:
            performed = True
            if isinstance(prefix, str):
                prefix = prefix.encode("utf-8")
            if not (record.readable_bytes or b"").startswith(bytes(prefix)):
                return None, AuditDict(
                        {
                            "code": "prefix_mismatch",
                            "expected_prefix": repr(prefix),
                        }
                )
            proof["checks"].append("prefix")

        equals = checks.get("equals")
        if equals is not None:
            performed = True
            if isinstance(equals, str):
                equals = equals.encode("utf-8")
            if (record.readable_bytes or b"") != bytes(equals):
                return None, AuditDict({"code": "payload_mismatch"})
            proof["checks"].append("equals")

        validator = self.get("validator")
        if callable(validator):
            performed = True
            try:
                result = validator(record.readable_bytes)
            except Exception as exc:  # forensic audit must report, not crash
                return None, AuditDict({"code": "validator_error", "error": str(exc)})
            checked_proof, error = _interpret_verifier_result(result, "validator")
            if error:
                return None, error
            proof.update(checked_proof)

        verifier = self.get("verifier") or self.get("verify")
        if callable(verifier):
            performed = True
            result, call_error = _call_record_verifier(verifier, record)
            if call_error is not None:
                return None, AuditDict({"code": "verifier_error", "error": call_error})
            checked_proof, error = _interpret_verifier_result(result, "verifier")
            if error:
                return None, error
            proof.update(checked_proof)

        if not performed:
            provenance = self.get("provenance")
            if provenance is None or provenance is False:
                return None, AuditDict(
                    {
                        "code": "no_registered_provenance",
                        "message": "owner is registered but source provenance is not provable",
                    }
                )
            if callable(provenance):
                try:
                    provenance = provenance(record)
                except Exception as exc:
                    return None, AuditDict(
                        {"code": "provenance_error", "error": str(exc)}
                    )
                if not provenance:
                    return None, AuditDict({"code": "provenance_rejected"})
            proof["registered_provenance"] = (
                provenance if provenance is not True else True
            )
            if provenance is True:
                proof["verified"] = True

        proof["verified"] = True
        return proof, None


def _interpret_verifier_result(result, name):
    if result is False or result is None:
        return None, AuditDict({"code": "%s_rejected" % name})
    if result is True:
        return AuditDict({name: AuditDict({"verified": True})}), None
    if isinstance(result, dict):
        value = AuditDict(result)
        value.setdefault("verified", True)
        return AuditDict({name: value}), None
    return AuditDict({name: AuditDict({"detail": str(result), "verified": True})}), None


def _call_record_verifier(verifier, record):
    try:
        return verifier(record), None
    except Exception as first_exc:
        try:
            return verifier(record.readable_bytes), None
        except Exception as second_exc:
            return None, "record call failed: %s; bytes call failed: %s" % (
                first_exc,
                second_exc,
            )


class OwnerRegistry(AuditDict):
    """Mapping of LC_NOTE owner names to their registered interpretation."""

    def register(self, owner, basis=None, **kwargs):
        registration = NoteOwnerRegistration(owner, basis=basis, **kwargs)
        self[registration.owner] = registration
        return registration

    def get_registration(self, owner):
        candidates = []
        text, raw = _owner_text(owner)
        if text:
            candidates.extend(
                [
                    text,
                    text.encode("utf-8"),
                    _padded_owner_bytes(text),
                ]
            )
        if raw:
            candidates.extend([raw, raw.split(b"\0", 1)[0], raw.rstrip(b"\0")])
        for candidate in candidates:
            if isinstance(candidate, bytes):
                for key, value in self.items():
                    key_text, key_raw = _owner_text(key)
                    if candidate in (key_raw, _padded_owner_bytes(key_text)):
                        return value
            elif candidate in self:
                return self[candidate]
        return None


def register_note_owner(registry, owner, basis=None, **kwargs):
    if not isinstance(registry, OwnerRegistry):
        registry = build_owner_registry(registry)
    return registry.register(owner, basis=basis, **kwargs)


def build_owner_registry(entries=None):
    """Build an :class:`OwnerRegistry` from mappings, objects, or lists."""
    registry = OwnerRegistry()
    if entries is None:
        return registry
    if isinstance(entries, OwnerRegistry):
        return entries
    if isinstance(entries, NoteOwnerRegistration):
        registry[entries.owner] = entries
        return registry
    if isinstance(entries, str):
        registry.register(entries)
        return registry

    if isinstance(entries, dict) or hasattr(entries, "items"):
        items = list(entries.items())
    else:
        items = []
        for item in entries:
            if isinstance(item, NoteOwnerRegistration):
                registry[item.owner] = item
                continue
            if isinstance(item, str):
                registry.register(item)
                continue
            if isinstance(item, dict):
                owner = item.get("owner") or item.get("data_owner") or item.get("name")
                fields = dict(item)
                fields.pop("owner", None)
                fields.pop("data_owner", None)
                fields.pop("name", None)
                registry.register(owner, **fields)
                continue
            if isinstance(item, (tuple, list)) and len(item) == 2:
                items.append(tuple(item))
                continue
            owner = getattr(item, "owner", None) or getattr(item, "data_owner", None)
            basis = getattr(item, "basis", None) or getattr(item, "interpretation", None)
            if owner is not None:
                registry.register(owner, basis=basis)

    for key, value in items:
        if isinstance(value, NoteOwnerRegistration):
            registration = value
        elif callable(value):
            registration = NoteOwnerRegistration(key, verifier=value)
        elif isinstance(value, str):
            registration = NoteOwnerRegistration(key, basis=value)
        elif isinstance(value, dict):
            registration = NoteOwnerRegistration(key, **value)
        else:
            registration = NoteOwnerRegistration(key, basis=value)
        registry[registration.owner] = registration
    return registry


def _open_source(source):
    if hasattr(source, "read"):
        name = getattr(source, "name", None) or "<file-object>"
        return source, False, name
    if isinstance(source, (bytes, bytearray)):
        return io.BytesIO(bytes(source)), True, "<bytes>"
    fspath = getattr(os, "fspath", None)
    path = fspath(source) if fspath is not None else source
    return io.open(path, "rb"), True, path


def _load_mach_o(fh, name):
    macho = MachO.__new__(MachO)
    macho.graphident = name
    macho.filename = name
    macho.loader_path = os.path.dirname(name) if isinstance(name, str) else ""
    macho.fat = None
    macho.headers = []
    macho.allow_unknown_load_commands = True
    macho.load(fh)
    return macho


def audit_lc_notes(source, registry=None, **options):
    """Read and audit every ``LC_NOTE`` in a thin or fat Mach-O file.

    The source is only opened for binary reading. Samples are never executed.
    """
    if registry is None:
        for alias in (
            "owner_registry",
            "known_owners",
            "owners",
            "note_owners",
            "registry_entries",
            "owner_entries",
            "interpretation_registry",
        ):
            if alias in options:
                registry = options.pop(alias)
                break
    owner_registry = build_owner_registry(registry)
    fh, close_fh, name = _open_source(source)
    try:
        macho = _load_mach_o(fh, name)
        current = fh.tell()
        fh.seek(0, os.SEEK_END)
        file_size = fh.tell()
        fh.seek(current)
        entries = _read_note_entries(macho, fh, file_size)
    finally:
        if close_fh:
            fh.close()

    overlaps = find_overlaps(entries)
    _apply_registry(entries, owner_registry)
    return _build_report(name, macho, entries, overlaps, owner_registry, options)


audit_notes = audit_lc_notes
audit = audit_lc_notes
audit_file = audit_lc_notes
audit_path = audit_lc_notes
verify_notes = audit_lc_notes
verify_lc_notes = audit_lc_notes
check_lc_notes = audit_lc_notes
inspect_lc_notes = audit_lc_notes
review_lc_notes = audit_lc_notes
reconcile_lc_notes = audit_lc_notes
review_notes = audit_lc_notes


def read_lc_notes(source, registry=None, **options):
    """Return only audited LC_NOTE records, preserving the same fields."""
    return audit_lc_notes(source, registry=registry, **options).entries


read_notes = read_lc_notes
parse_lc_notes = read_lc_notes
collect_lc_notes = read_lc_notes


NoteRegistry = OwnerRegistry
NoteOwnerRegistry = OwnerRegistry
NoteAuditRecord = AuditDict
NoteAuditReport = AuditDict


def _read_note_entries(macho, fh, file_size):
    entries = []
    for slice_index, header in enumerate(macho.headers):
        slice_start = int(header.offset)
        header_slice_size = int(header.size or 0)
        slice_end = slice_start + header_slice_size
        if header_slice_size <= 0 or slice_end > file_size:
            slice_end = file_size
        slice_end = max(slice_start, min(slice_end, file_size))

        note_index = 0
        for command_index, command_info in enumerate(header.commands):
            load_command, command, _command_data = command_info
            if int(load_command.cmd) != LC_NOTE:
                continue

            owner_text, owner_raw = _owner_text(command.data_owner)
            declared_offset = int(command.offset)
            declared_size = int(command.size)
            declared_end = declared_offset + declared_size
            absolute_offset = slice_start + declared_offset
            absolute_declared_end = absolute_offset + declared_size
            readable_end = max(
                absolute_offset,
                min(absolute_declared_end, slice_end, file_size),
            )
            readable_size = max(0, readable_end - absolute_offset)

            readable_bytes = b""
            if readable_size > 0 and absolute_offset < file_size:
                fh.seek(absolute_offset)
                readable_bytes = fh.read(readable_size) or b""

            actual_readable_size = len(readable_bytes)
            readable_absolute_end = absolute_offset + actual_readable_size
            truncated = actual_readable_size < declared_size
            outside_slice = (
                declared_offset >= header_slice_size or absolute_offset >= slice_end
            )
            outside_file = absolute_offset >= file_size
            digest = hashlib.sha256(readable_bytes).hexdigest()
            cpu_type = int(header.header.cputype)
            cpu_name = CPU_TYPE_NAMES.get(cpu_type, str(cpu_type))
            try:
                subtype_name = get_cpu_subtype(cpu_type, int(header.header.cpusubtype))
            except Exception:
                subtype_name = str(int(header.header.cpusubtype))

            note_id = "slice%d-note%d" % (slice_index, note_index)
            entry = AuditDict(
                id=note_id,
                note_id=note_id,
                slice_index=slice_index,
                slice=slice_index,
                arch=cpu_name,
                cpu_type=cpu_type,
                cpu_subtype=int(header.header.cpusubtype),
                cpu_subtype_name=subtype_name,
                command_index=command_index,
                note_index=note_index,
                owner=owner_text,
                data_owner=owner_text,
                owner_raw=owner_raw,
                declared_offset=declared_offset,
                declared_size=declared_size,
                declared_end=declared_end,
                offset=declared_offset,
                size=declared_size,
                declared_range=AuditDict(
                    offset=declared_offset,
                    start=declared_offset,
                    size=declared_size,
                    end=declared_end,
                ),
                declared_span=(declared_offset, declared_size),
                declared_interval=(declared_offset, declared_end),
                slice_offset=slice_start,
                slice_size=header_slice_size,
                file_offset=absolute_offset,
                absolute_offset=absolute_offset,
                absolute_end=absolute_declared_end,
                file_range=AuditDict(
                    offset=absolute_offset,
                    start=absolute_offset,
                    size=declared_size,
                    end=absolute_declared_end,
                    slice_relative=True,
                ),
                readable_range=AuditDict(
                    offset=absolute_offset,
                    start=absolute_offset,
                    size=actual_readable_size,
                    end=readable_absolute_end,
                ),
                readable_offset=absolute_offset,
                readable_size=actual_readable_size,
                readable_bytes=readable_bytes,
                readable_data=readable_bytes,
                data=readable_bytes,
                bytes=readable_bytes,
                sha256=digest,
                digest=digest,
                truncated=truncated,
                fully_readable=not truncated and not outside_slice and not outside_file,
                outside_slice=outside_slice,
                outside_file=outside_file,
                overlaps=[],
                overlap_refs=[],
                reasons=[],
                status_codes=[],
                registration=None,
                registered_interpretation=None,
                owner_status=None,
                provenance_status=None,
                provenance_proof=None,
                provenance_error=None,
                status=None,
                result=None,
                confirmation_eligible=False,
                eligible=False,
                same_owner_note_ids=[],
            )
            _sync_entry_aliases(entry)
            entries.append(entry)
            note_index += 1
    return entries


def _sync_entry_aliases(entry):
    registration = entry.get("registration")
    basis = registration.get("basis") if registration else None
    entry.update(
        {
            "owning_slice": entry.get("slice_index"),
            "slice_id": entry.get("slice_index"),
            "architecture": entry.get("arch"),
            "claimed_range": entry.get("declared_range"),
            "claimed_offset": entry.get("declared_offset"),
            "claimed_size": entry.get("declared_size"),
            "actual_readable_bytes": entry.get("readable_bytes"),
            "actual_bytes": entry.get("readable_bytes"),
            "bytes_read": entry.get("readable_bytes"),
            "read_bytes": entry.get("readable_bytes"),
            "payload": entry.get("readable_bytes"),
            "owner_registration": registration,
            "registered_basis": basis,
            "interpretation_basis": basis,
            "basis": basis,
            "admissible": bool(entry.get("confirmation_eligible")),
            "include_in_confirmation": bool(entry.get("confirmation_eligible")),
            "overlapping": bool(entry.get("overlaps")),
            "contested": bool(entry.get("overlaps")),
        }
    )


def _range_coords(record):
    get = _record_getter(record)

    slice_index = get("slice_index", get("slice", 0)) or 0
    start = get("declared_offset", None)
    size = get("declared_size", None)
    if start is None:
        declared_range = get("declared_range", None)
        if declared_range is not None:
            if isinstance(declared_range, dict):
                start = declared_range.get("start", declared_range.get("offset"))
                size = declared_range.get("size")
            else:
                start = declared_range[0]
                size = declared_range[1] if len(declared_range) > 1 else 0
    if start is None:
        start = get("offset", 0)
    if size is None:
        size = get("size", 0)
    start = int(start or 0)
    end = start + int(size or 0)
    return int(slice_index), start, end


def _record_getter(record):
    if isinstance(record, dict):
        return record.get

    def get(key, default=None):
        return getattr(record, key, default)

    return get


def _stable_record_key(record, original_index):
    slice_index, start, end = _range_coords(record)
    get = _record_getter(record)
    command_index = get("command_index")
    note_index = get("note_index")
    record_id = get("id", get("note_id", ""))
    owner, _raw = _owner_text(get("owner", get("data_owner", "")))
    return (
        slice_index,
        int(command_index) if command_index is not None else 10**12,
        int(note_index) if note_index is not None else original_index,
        start,
        end,
        owner,
        str(record_id),
        original_index,
    )


def find_overlaps(entries):
    """Find declared-range overlaps without assigning a read-order winner."""
    conflicts = []
    ordered = sorted(list(entries), key=lambda item: _stable_record_key(item, 0))
    for left_position, left in enumerate(ordered):
        left_slice, left_start, left_end = _range_coords(left)
        for right in ordered[left_position + 1 :]:
            right_slice, right_start, right_end = _range_coords(right)
            if left_slice != right_slice:
                continue
            overlap_start = max(left_start, right_start)
            overlap_end = min(left_end, right_end)
            overlap_size = overlap_end - overlap_start
            if overlap_size <= 0:
                continue

            left_id = _record_id(left, left_position)
            right_id = _record_id(right, left_position + 1)
            note_ids = sorted([left_id, right_id])
            conflict = AuditDict(
                id="overlap:%s<->%s" % (note_ids[0], note_ids[1]),
                note_ids=note_ids,
                slice_index=left_slice,
                start=overlap_start,
                end=overlap_end,
                offset=overlap_start,
                size=overlap_size,
                overlap_size=overlap_size,
                small_overlap=overlap_size <= 16,
                winner=None,
                read_order_winner=None,
                resolution="ambiguous_no_read_order_winner",
                order_dependent=False,
                message=(
                    "declared ranges overlap by %d byte(s); no first/last reader wins"
                    % overlap_size
                ),
            )
            conflicts.append(conflict)
            _attach_overlap(left, conflict, right_id)
            _attach_overlap(right, conflict, left_id)
    return conflicts


reconcile_overlaps = find_overlaps


def _record_id(record, fallback):
    if isinstance(record, dict):
        value = record.get("id") or record.get("note_id")
    else:
        value = getattr(record, "id", None) or getattr(record, "note_id", None)
    return value or "record%d" % fallback


def _attach_overlap(record, conflict, other_id):
    if not isinstance(record, AuditDict):
        return
    ref = AuditDict(conflict)
    ref["other_note_id"] = other_id
    record.setdefault("overlaps", []).append(ref)
    record.setdefault("overlap_refs", []).append(ref)
    record["has_overlap"] = True
    codes = record.setdefault("status_codes", [])
    if OVERLAP_CONFLICT not in codes:
        codes.append(OVERLAP_CONFLICT)
    reasons = record.setdefault("reasons", [])
    reason = (
        "declared range overlaps %s; overlap is order-independent and unresolved"
        % other_id
    )
    if reason not in reasons:
        reasons.append(reason)


def _apply_registry(entries, registry):
    owner_index = {}
    for entry in entries:
        registration = registry.get_registration(entry.owner)
        entry.registration = registration
        entry.registered_interpretation = registration
        entry.owner_registration = registration
        if registration is not None:
            entry.basis = registration.get("basis")
            entry.registered_basis = registration.get("basis")
            entry.interpretation_basis = registration.get("basis")
        if registration is None:
            entry.owner_status = UNKNOWN_OWNER
            entry.status = UNKNOWN_OWNER
            entry.result = UNKNOWN_OWNER
            entry.confirmation_eligible = False
            entry.eligible = False
            entry.status_codes.insert(0, UNKNOWN_OWNER)
            entry.reasons.insert(
                0, "owner %r is not in the interpretation registry" % entry.owner
            )
            continue

        entry.owner_status = REGISTERED_OWNER
        proof, error = registration.check_provenance(entry)
        entry.provenance_proof = proof
        entry.provenance_error = error
        if error is not None or proof is None:
            entry.provenance_status = UNVERIFIED_PROVENANCE
            entry.status = KNOWN_OWNER_UNVERIFIED_ORIGIN
            entry.result = KNOWN_OWNER_UNVERIFIED_ORIGIN
            entry.confirmation_eligible = False
            entry.eligible = False
            entry.status_codes.insert(0, KNOWN_OWNER_UNVERIFIED_ORIGIN)
            detail = (
                (error or {}).get("message") or (error or {}).get("code") or "no proof"
            )
            entry.reasons.insert(
                0,
                "owner %r is registered but its source cannot be proven (%s)"
                % (entry.owner, detail),
            )
        else:
            entry.provenance_status = VERIFIED_PROVENANCE
            entry.status_codes.insert(0, VERIFIED_PROVENANCE)
            if entry.truncated or entry.outside_slice or entry.outside_file:
                entry.status = INCOMPLETE_READ
                entry.result = INCOMPLETE_READ
                entry.confirmation_eligible = False
                entry.eligible = False
                entry.reasons.insert(0, "declared note region is not fully readable")
            elif entry.overlaps:
                entry.status = CONFIRMED_WITH_OVERLAP
                entry.result = CONFIRMED_WITH_OVERLAP
                entry.confirmation_eligible = True
                entry.eligible = True
                entry.unambiguous = False
                entry.reasons.append("range overlap remains flagged for review")
            else:
                entry.status = CONFIRMED
                entry.result = CONFIRMED
                entry.confirmation_eligible = True
                entry.eligible = True
                entry.unambiguous = True

        owner_index.setdefault(entry.owner, []).append(entry.id)

    for entry in entries:
        same = [
            other_id
            for other_id in owner_index.get(entry.owner, [])
            if other_id != entry.id
        ]
        entry.same_owner_note_ids = same
        if entry.overlaps:
            entry.unambiguous = False
        else:
            entry.setdefault("unambiguous", True)
        _sync_entry_aliases(entry)


def _build_report(name, macho, entries, overlaps, registry, options):
    owner_groups, name_only_pairs = _same_owner_analysis(entries)
    evidence = [entry for entry in entries if entry.confirmation_eligible]
    excluded = [entry for entry in entries if not entry.confirmation_eligible]
    unknown = [entry for entry in entries if entry.status == UNKNOWN_OWNER]
    unverified = [
        entry for entry in entries if entry.status == KNOWN_OWNER_UNVERIFIED_ORIGIN
    ]
    incomplete = [entry for entry in entries if entry.status == INCOMPLETE_READ]
    overlap_entries = [entry for entry in entries if entry.overlaps]
    is_fat = getattr(macho, "fat", None) is not None or len(macho.headers) > 1

    report = AuditDict(
        path=name,
        source=name,
        read_only=True,
        executed_sample=False,
        execution_performed=False,
        is_fat=is_fat,
        fat=is_fat,
        slice_count=len(macho.headers),
        note_count=len(entries),
        entries=entries,
        notes=entries,
        records=entries,
        overlaps=overlaps,
        overlap_conflicts=overlaps,
        conflicts=overlaps,
        same_owner_groups=owner_groups,
        owner_groups=owner_groups,
        same_name_only_pairs=name_only_pairs,
        same_name_only=name_only_pairs,
        name_only_pairs=name_only_pairs,
        name_only_matches=name_only_pairs,
        same_name_matches=name_only_pairs,
        same_owner_pairs=name_only_pairs,
        confirmation_evidence=evidence,
        confirming_evidence=evidence,
        confirmed_notes=evidence,
        evidence=evidence,
        confirmation_evidence_ids=[entry.id for entry in evidence],
        confirmed_ids=[entry.id for entry in evidence],
        confirmation_ids=[entry.id for entry in evidence],
        excluded_from_confirmation=excluded,
        excluded_notes=excluded,
        not_confirmation_evidence=excluded,
        excluded_evidence=excluded,
        excluded_evidence_ids=[entry.id for entry in excluded],
        excluded_ids=[entry.id for entry in excluded],
        excluded_from_confirmation_ids=[entry.id for entry in excluded],
        unconfirmed_notes=excluded,
        not_confirmable_notes=excluded,
        unknown_owner_notes=unknown,
        unknown_owner_ids=[entry.id for entry in unknown],
        unverified_origin_notes=unverified,
        known_owner_unverified_notes=unverified,
        unverified_origin_ids=[entry.id for entry in unverified],
        incomplete_read_notes=incomplete,
        overlap_notes=overlap_entries,
        registry=registry,
        options=AuditDict(options),
    )
    report["summary"] = AuditDict(
        {
            "slices": report.slice_count,
            "notes": report.note_count,
            "confirmation_evidence": len(evidence),
            "excluded": len(excluded),
            "unknown_owner": len(unknown),
            "unverified_origin": len(unverified),
            "overlaps": len(overlaps),
            "same_name_only_pairs": len(name_only_pairs),
        }
    )
    return report


def _same_owner_analysis(entries):
    by_owner = {}
    for entry in entries:
        by_owner.setdefault(entry.owner, []).append(entry)

    groups = []
    pairs = []
    for owner in sorted(by_owner):
        group_entries = by_owner[owner]
        if len(group_entries) < 2:
            continue
        ids = [entry.id for entry in group_entries]
        slices = sorted(set(entry.slice_index for entry in group_entries))
        digests = set(entry.sha256 for entry in group_entries)
        registration = group_entries[0].registration
        group = AuditDict(
            owner=owner,
            note_ids=ids,
            ids=ids,
            slice_indexes=slices,
            slices=slices,
            count=len(group_entries),
            distinct_slices=len(slices) > 1,
            payload_digests_equal=len(digests) == 1,
            same_name_only=len(digests) != 1,
            relationship="same_owner_name_only",
            registered_interpretation=registration,
            explanation=(
                "The matching data_owner is only a name. It does not merge, "
                "authenticate, or order slice-scoped notes."
            ),
        )
        groups.append(group)

        for index, left in enumerate(group_entries):
            for right in group_entries[index + 1 :]:
                payload_equal = left.sha256 == right.sha256
                pair = AuditDict(
                    owner=owner,
                    note_ids=[left.id, right.id],
                    ids=[left.id, right.id],
                    slice_indexes=[left.slice_index, right.slice_index],
                    distinct_slices=left.slice_index != right.slice_index,
                    payload_digests_equal=payload_equal,
                    same_name_only=not payload_equal,
                    relationship="same_owner_name_only",
                    explanation=group.explanation,
                    message=(
                        "%s and %s share only the registered owner name %r"
                        % (left.id, right.id, owner)
                    ),
                )
                pairs.append(pair)
    return groups, pairs


def _short(value):
    if not value:
        return "-"
    return value[:12]


def format_audit_report(report, language="en"):
    if language and language.lower().startswith("zh"):
        return format_audit_report_zh(report)
    lines = []
    lines.append("LC_NOTE read-only audit: %s" % report.path)
    lines.append(
        "fat=%s slices=%d notes=%d confirmation=%d excluded=%d"
        % (
            report.is_fat,
            report.slice_count,
            report.note_count,
            len(report.confirmation_evidence),
            len(report.excluded_from_confirmation),
        )
    )
    for entry in report.entries:
        lines.append(
            "[%s] slice=%s arch=%s command=%s"
            % (
                entry.id,
                entry.slice_index,
                entry.arch,
                entry.command_index,
            )
        )
        lines.append("  owner: %r (status=%s)" % (entry.owner, entry.owner_status))
        lines.append(
            "  declared range: slice-relative offset=%d size=%d interval=[%d,%d); "
            "file interval=[%d,%d)"
            % (
                entry.declared_offset,
                entry.declared_size,
                entry.declared_offset,
                entry.declared_end,
                entry.file_offset,
                entry.absolute_end,
            )
        )
        lines.append(
            "  readable bytes: %d/%d sha256=%s truncated=%s"
            % (
                entry.readable_size,
                entry.declared_size,
                entry.sha256,
                entry.truncated,
            )
        )
        basis = entry.registration.basis if entry.registration else None
        lines.append("  registered interpretation basis: %s" % (basis or "<none>"))
        lines.append(
            "  provenance: status=%s proof=%s error=%s"
            % (
                entry.provenance_status,
                entry.provenance_proof,
                (entry.provenance_error or {}).get("code")
                if entry.provenance_error
                else None,
            )
        )
        lines.append(
            "  audit result: %s eligible_for_confirmation=%s reasons=%s"
            % (
                entry.status,
                entry.confirmation_eligible,
                "; ".join(entry.reasons) or "-",
            )
        )

    lines.append("Same owner name only:")
    if report.same_name_only_pairs:
        for pair in report.same_name_only_pairs:
            lines.append("  - %s" % pair.message)
    else:
        lines.append("  - <none>")

    lines.append("Overlap conflicts:")
    if report.overlaps:
        for conflict in report.overlaps:
            lines.append(
                "  - %s overlap=%dB winner=<none> order-independent; %s"
                % (
                    conflict.note_ids,
                    conflict.overlap_size,
                    conflict.message,
                )
            )
    else:
        lines.append("  - <none>")

    lines.append("Confirmation evidence:")
    lines.append("  %s" % (report.confirmation_evidence_ids or "<none>"))
    lines.append("Not confirmation evidence:")
    for entry in report.excluded_from_confirmation:
        lines.append(
            "  - %s status=%s reasons=%s"
            % (
                entry.id,
                entry.status,
                "; ".join(entry.reasons) or "-",
            )
        )
    if not report.excluded_from_confirmation:
        lines.append("  - <none>")
    return "\n".join(lines)


def format_audit_report_zh(report):
    lines = []
    lines.append("LC_NOTE 只读注记核对: %s" % report.path)
    lines.append(
        "fat=%s 切片数=%d 注记数=%d 可确认=%d 排除=%d"
        % (
            report.is_fat,
            report.slice_count,
            report.note_count,
            len(report.confirmation_evidence),
            len(report.excluded_from_confirmation),
        )
    )
    for entry in report.entries:
        basis = entry.registration.basis if entry.registration else None
        lines.append(
            "[%s] 所属切片=%s 架构=%s" % (entry.id, entry.slice_index, entry.arch)
        )
        lines.append(
            "  声明范围: 切片内 offset=%d size=%d [%d,%d); 文件绝对区间 [%d,%d)"
            % (
                entry.declared_offset,
                entry.declared_size,
                entry.declared_offset,
                entry.declared_end,
                entry.file_offset,
                entry.absolute_end,
            )
        )
        lines.append(
            "  真实可读字节: %d/%d sha256=%s"
            % (
                entry.readable_size,
                entry.declared_size,
                _short(entry.sha256),
            )
        )
        lines.append("  登记的解释依据: %s" % (basis or "<未登记 owner>"))
        lines.append(
            "  结果: %s; %s" % (entry.status, "; ".join(entry.reasons) or "无额外原因")
        )

    lines.append("仅同名关系:")
    for pair in report.same_name_only_pairs or []:
        lines.append(
            "  - %s 与 %s 仅共用 owner 名称 %r，切片/范围/字节均分别保留"
            % (
                pair.note_ids[0],
                pair.note_ids[1],
                pair.owner,
            )
        )
    if not report.same_name_only_pairs:
        lines.append("  - 无")

    lines.append("重叠核对:")
    for conflict in report.overlaps or []:
        lines.append(
            "  - %s 重叠 %d 字节；不按读取顺序选胜，winner=None"
            % (
                conflict.note_ids,
                conflict.overlap_size,
            )
        )
    if not report.overlaps:
        lines.append("  - 无")

    lines.append("可纳入确认证据: %s" % (report.confirmation_evidence_ids or "<无>"))
    lines.append("不应纳入确认证据:")
    for entry in report.excluded_from_confirmation:
        lines.append("  - %s（%s）" % (entry.id, entry.status))
    if not report.excluded_from_confirmation:
        lines.append("  - 无")
    return "\n".join(lines)


def main(argv=None):
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Read-only LC_NOTE audit")
    parser.add_argument("paths", nargs="+")
    parser.add_argument("--registry", help="JSON owner registry file")
    parser.add_argument("--chinese", action="store_true")
    args = parser.parse_args(argv)
    registry = None
    if args.registry:
        with io.open(args.registry, "r", encoding="utf-8") as fp:
            registry = json.load(fp)
    for path in args.paths:
        report = audit_notes(path, registry=registry)
        print(
            format_audit_report_zh(report)
            if args.chinese
            else format_audit_report(report)
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
