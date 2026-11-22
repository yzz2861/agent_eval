"""
Read-only auditing of LC_NOTE load commands in Mach-O files.

The auditor in this module only ever *reads* files: it parses Mach-O
headers (thin and fat) with :class:`macholib.MachO.MachO`, locates
``LC_NOTE`` load commands and reads the declared note payloads.  File
contents are never executed and the audited file is never modified.

For every note the audit preserves:

* the slice it belongs to (index, cpu type, file range),
* the declared range (offset and size as recorded in the load command),
* the actually readable bytes (declared range clamped to the slice),
* the registered interpretation basis used to explain the note.

Owners are interpreted through a :class:`NoteRegistry`.  An owner that
is not registered yields ``unknown-owner``; a registered owner whose
payload does not match the registered basis yields ``unproven-owner``.
Those are deliberately different results: the former says nothing is
known about the owner, the latter says the owner is known but this
particular note cannot be proven to come from it.

Overlapping declared ranges within one slice are flagged symmetrically
on every note involved, so a small overlap is never decided by the
order in which the notes happen to be read.
"""

from __future__ import print_function

from macholib.MachO import MachO
from macholib.mach_o import CPU_TYPE_NAMES, LC_NOTE

__all__ = [
    "STATUS_CONFIRMED",
    "STATUS_UNKNOWN_OWNER",
    "STATUS_UNPROVEN_OWNER",
    "NoteBasis",
    "NoteRegistry",
    "AuditedNote",
    "NoteAuditReport",
    "audit_notes",
]

#: The owner is registered and the payload matches the registered basis.
STATUS_CONFIRMED = "confirmed"

#: The owner is not present in the registry at all.
STATUS_UNKNOWN_OWNER = "unknown-owner"

#: The owner is registered, but the payload does not match the
#: registered basis, so the note's provenance cannot be proven.
STATUS_UNPROVEN_OWNER = "unproven-owner"


class NoteBasis(object):
    """
    Registered interpretation basis for a known ``data_owner``.

    ``magic`` is the byte prefix a genuine note payload must start
    with, ``description`` explains what the note records and
    ``reference`` cites where the registration comes from, so the
    audit trail can name the basis it relied on.
    """

    def __init__(self, owner, magic=b"", description="", reference=""):
        if not owner:
            raise ValueError("owner must be a non-empty string")
        self.owner = owner
        self.magic = magic
        self.description = description
        self.reference = reference

    def matches(self, payload):
        """
        True when *payload* provably originates from this owner.
        """
        return bool(self.magic) and payload.startswith(self.magic)

    def __repr__(self):
        return "<NoteBasis owner=%r reference=%r>" % (self.owner, self.reference)


class NoteRegistry(object):
    """
    Registry of interpretation bases, keyed by ``data_owner``.
    """

    def __init__(self):
        self._bases = {}

    def register(self, owner, magic=b"", description="", reference=""):
        """
        Register and return the :class:`NoteBasis` for *owner*.
        """
        basis = NoteBasis(
            owner, magic=magic, description=description, reference=reference
        )
        self._bases[owner] = basis
        return basis

    def lookup(self, owner):
        """
        Return the registered :class:`NoteBasis` for *owner*, or None.
        """
        return self._bases.get(owner)

    def __contains__(self, owner):
        return owner in self._bases

    def __len__(self):
        return len(self._bases)


class AuditedNote(object):
    """
    One observed LC_NOTE, tied to the slice it was read from.

    ``declared_offset``/``declared_size`` are the range as declared by
    the load command (relative to the start of its slice);
    ``readable_offset`` is the absolute file offset of the first
    readable byte and ``payload`` holds the ``readable_size`` bytes
    that could actually be read within the slice bounds.
    """

    def __init__(
        self,
        slice_index,
        cpu_name,
        slice_offset,
        slice_size,
        owner,
        declared_offset,
        declared_size,
        readable_offset,
        readable_size,
        payload,
        basis,
        status,
    ):
        self.slice_index = slice_index
        self.cpu_name = cpu_name
        self.slice_offset = slice_offset
        self.slice_size = slice_size
        self.owner = owner
        self.declared_offset = declared_offset
        self.declared_size = declared_size
        self.readable_offset = readable_offset
        self.readable_size = readable_size
        self.payload = payload
        self.basis = basis
        self.status = status
        # Indices of other notes whose declared range overlaps this
        # one, filled in by audit_notes() after deterministic sorting.
        self.overlaps = ()

    @property
    def declared_end(self):
        return self.declared_offset + self.declared_size

    @property
    def truncated(self):
        """
        True when the declared range is not fully readable.
        """
        return self.readable_size != self.declared_size

    @property
    def is_confirmation_evidence(self):
        """
        True when this note may be used as confirmation evidence.
        """
        return (
            self.status == STATUS_CONFIRMED
            and not self.truncated
            and not self.overlaps
        )

    def exclusion_reasons(self):
        """
        Human-readable reasons why this note is not evidence.
        """
        reasons = []
        if self.status == STATUS_UNKNOWN_OWNER:
            reasons.append("owner %r is not registered" % (self.owner,))
        elif self.status == STATUS_UNPROVEN_OWNER:
            reasons.append(
                "owner %r is registered but the payload does not match "
                "the registered basis" % (self.owner,)
            )
        if self.truncated:
            reasons.append(
                "declared range is not fully readable "
                "(%d of %d bytes)" % (self.readable_size, self.declared_size)
            )
        if self.overlaps:
            reasons.append(
                "declared range overlaps %s"
                % (", ".join("note[%d]" % (i,) for i in self.overlaps),)
            )
        return reasons

    def __repr__(self):
        return "<AuditedNote slice=%d owner=%r status=%r>" % (
            self.slice_index,
            self.owner,
            self.status,
        )


class NoteAuditReport(object):
    """
    Result of auditing every LC_NOTE in one file.
    """

    def __init__(self, filename, notes):
        self.filename = filename
        self.notes = list(notes)

    def confirmed_evidence(self):
        """
        Notes that may be used as confirmation evidence.
        """
        return [note for note in self.notes if note.is_confirmation_evidence]

    def same_owner_groups(self):
        """
        Groups of notes that share an owner but are not the same note.

        Returns a list of ``(owner, [note indices])`` for owners used
        by more than one note whose payloads differ: such notes are
        merely same-named and cannot corroborate each other.
        """
        by_owner = {}
        for index, note in enumerate(self.notes):
            by_owner.setdefault(note.owner, []).append(index)
        groups = []
        for owner in sorted(by_owner):
            indices = by_owner[owner]
            if len(indices) < 2:
                continue
            payloads = set(self.notes[i].payload for i in indices)
            if len(payloads) > 1:
                groups.append((owner, indices))
        return groups

    def explain(self):
        """
        Human-readable audit output, one finding per line.
        """
        lines = [
            "LC_NOTE audit of %s: %d note(s)" % (self.filename, len(self.notes))
        ]
        for index, note in enumerate(self.notes):
            if note.basis is None:
                basis = "(none registered)"
            else:
                basis = note.basis.reference or "(registered, no reference)"
            lines.append(
                "note[%d] slice=%d (%s) owner=%r "
                "declared=[0x%x,+0x%x) readable=%d/%d status=%s basis=%s"
                % (
                    index,
                    note.slice_index,
                    note.cpu_name,
                    note.owner,
                    note.declared_offset,
                    note.declared_size,
                    note.readable_size,
                    note.declared_size,
                    note.status,
                    basis,
                )
            )
        for owner, indices in self.same_owner_groups():
            lines.append(
                "notes %s share owner %r but differ in content: "
                "merely same-named"
                % (", ".join("note[%d]" % (i,) for i in indices), owner)
            )
        for index, note in enumerate(self.notes):
            if note.is_confirmation_evidence:
                continue
            for reason in note.exclusion_reasons():
                lines.append(
                    "note[%d] excluded from confirmation evidence: %s"
                    % (index, reason)
                )
        return "\n".join(lines)


def _decode_owner(raw_owner):
    return raw_owner.split(b"\x00", 1)[0].decode("utf-8", "replace")


def audit_notes(filename, registry):
    """
    Audit every LC_NOTE load command in *filename* against *registry*
    and return a :class:`NoteAuditReport`.

    The file is only read, never modified, and none of its contents
    are executed.  Declared note offsets are interpreted relative to
    the start of the slice that carries the load command, and the
    readable bytes are clamped to that slice's bounds.
    """
    macho = MachO(filename, allow_unknown_load_commands=True)
    notes = []
    with open(filename, "rb") as fp:
        for slice_index, header in enumerate(macho.headers):
            cpu_name = CPU_TYPE_NAMES.get(
                header.header.cputype, "cpu(%d)" % (header.header.cputype,)
            )
            slice_end = header.offset + header.size
            for cmd_load, cmd_cmd, _cmd_data in header.commands:
                if cmd_load.cmd != LC_NOTE:
                    continue
                owner = _decode_owner(cmd_cmd.data_owner)
                declared_offset = cmd_cmd.offset
                declared_size = cmd_cmd.size
                absolute = header.offset + declared_offset
                readable_size = min(declared_size, max(0, slice_end - absolute))
                fp.seek(absolute)
                payload = fp.read(readable_size)
                basis = registry.lookup(owner)
                if basis is None:
                    status = STATUS_UNKNOWN_OWNER
                elif basis.matches(payload):
                    status = STATUS_CONFIRMED
                else:
                    status = STATUS_UNPROVEN_OWNER
                notes.append(
                    AuditedNote(
                        slice_index=slice_index,
                        cpu_name=cpu_name,
                        slice_offset=header.offset,
                        slice_size=header.size,
                        owner=owner,
                        declared_offset=declared_offset,
                        declared_size=declared_size,
                        readable_offset=absolute,
                        readable_size=readable_size,
                        payload=payload,
                        basis=basis,
                        status=status,
                    )
                )

    # Deterministic order: audit results must never depend on the
    # order load commands happen to appear in the file.
    notes.sort(
        key=lambda note: (
            note.slice_index,
            note.declared_offset,
            note.declared_size,
            note.owner,
        )
    )

    # Flag overlapping declared ranges symmetrically: every note
    # involved in an overlap is marked, so no note can "win" a small
    # overlap just by being read first.
    for index, note in enumerate(notes):
        overlaps = []
        for other_index, other in enumerate(notes):
            if other_index == index:
                continue
            if other.slice_index != note.slice_index:
                continue
            if (
                note.declared_offset < other.declared_end
                and other.declared_offset < note.declared_end
            ):
                overlaps.append(other_index)
        note.overlaps = tuple(overlaps)

    return NoteAuditReport(filename, notes)
