"""
Read-only pairwise comparison of (fat) Mach-O files, slice by slice.

The packaging toolchain (for example ``macholib.MachOStandalone``) rewrites
dylib references inside load commands.  Growing or shrinking those commands
shifts every file offset that follows, so two archives of the same universal
binary are rarely byte identical even when *nothing else* changed.

This module provides a read-only audit interface that compares two fat
Mach-O files and explains every difference it observes per architecture
slice:

* load command changes expected of a reference rewrite (dylib/rpath strings
  and the layout effects of their size changes);
* segment content changes that cannot be explained by those layout shifts,
  located to byte ranges on both sides;
* code signature coverage and signature content changes;
* missing evidence: absent or duplicate slices, malformed data, or layout
  changes that do not follow from the rewritten commands.

Nothing in this module ever writes to either input file: both inputs are
opened read-only through :class:`macholib.MachO.MachO` and all analysis
operates on bytes read once into memory.
"""

from dataclasses import dataclass

from macholib.MachO import MachO
from macholib import mach_o
from macholib.ptypes import sizeof

#: Load commands whose payload is (or may contain) a path string rewritten by
#: packaging tools.  Only changes inside these commands are accepted as
#: "explained" reference rewrites.
DEFAULT_ALLOWED_COMMANDS = frozenset(
    {
        mach_o.LC_LOAD_DYLIB,
        mach_o.LC_LOAD_WEAK_DYLIB,
        mach_o.LC_REEXPORT_DYLIB,
        mach_o.LC_LOAD_UPWARD_DYLIB,
        mach_o.LC_LAZY_LOAD_DYLIB,
        mach_o.LC_ID_DYLIB,
        mach_o.LC_RPATH,
        mach_o.LC_LOAD_DYLINKER,
        mach_o.LC_ID_DYLINKER,
        mach_o.LC_DYLD_ENVIRONMENT,
    }
)

#: LinkEdit data-bearing commands whose offsets must move with the explained
#: layout shift; the bytes they point at are compared separately.
_LINKEDIT_DATA_COMMANDS = frozenset(
    {
        mach_o.LC_CODE_SIGNATURE,
        mach_o.LC_SYMTAB,
        mach_o.LC_DYSYMTAB,
        mach_o.LC_FUNCTION_STARTS,
        mach_o.LC_DATA_IN_CODE,
        mach_o.LC_CODE_SEGMENT_SPLIT_INFO,
        mach_o.LC_DYLIB_CODE_SIGN_DRS,
        mach_o.LC_LINKER_OPTIMIZATION_HINT,
        mach_o.LC_DYLD_INFO,
        mach_o.LC_DYLD_INFO_ONLY,
        mach_o.LC_DYLD_EXPORTS_TRIE,
        mach_o.LC_DYLD_CHAINED_FIXUPS,
    }
)


def _lc_name(cmd):
    return mach_o.LC_NAMES.get(cmd, "LC_UNKNOWN_0x%08X" % (cmd,))


def _arch_label(cputype, cpusubtype):
    type_name = mach_o.CPU_TYPE_NAMES.get(
        cputype, "cpu_0x%08X" % (cputype & 0xFFFFFFFF)
    )
    sub_name = mach_o.get_cpu_subtype(cputype, cpusubtype)
    return "%s/%s" % (type_name, sub_name)


@dataclass(frozen=True)
class ByteRange:
    """A byte interval inside one of the two compared files.

    ``file_offset`` addresses the whole fat file; ``slice_offset`` addresses
    the same byte relative to the start of the architecture slice.
    """

    file_offset: int
    length: int
    slice_offset: int

    @property
    def end(self):
        return self.file_offset + self.length

    @property
    def slice_end(self):
        return self.slice_offset + self.length

    def __str__(self):
        return "file[%d:%d] slice[%d:%d]" % (
            self.file_offset,
            self.end,
            self.slice_offset,
            self.slice_end,
        )


@dataclass
class LoadCommandView:
    """Raw, index-stable view of one load command in a slice.

    ``embedded_offsets`` maps the byte offset (inside ``raw``) of every
    file-offset field the command carries (segment fileoff, LinkEdit
    dataoff, ...) to its parsed value; those fields legitimately move when a
    preceding reference rewrite changes the command layout.
    """

    index: int
    cmd: int
    cmdsize: int
    slice_offset: int
    raw: bytes
    embedded_offsets: dict
    masked_fields: dict = None

    @property
    def name(self):
        return _lc_name(self.cmd)


@dataclass
class SegmentView:
    """File-backed region described by an LC_SEGMENT[_64] command."""

    name: str
    fileoff: int
    filesize: int
    command_index: int


@dataclass
class SignatureView:
    """Code signature region described by LC_CODE_SIGNATURE."""

    dataoff: int
    datasize: int
    command_index: int
    present: bool


@dataclass
class SliceView:
    """Everything the comparator needs to know about one slice."""

    arch_key: tuple
    arch_label: str
    fat_offset: int
    fat_size: int
    slice_index: int
    endian: str
    is_64: bool
    header_size: int
    sizeofcmds: int
    ncmds: int
    commands: list
    segments: list
    signature: object
    data: bytes

    @property
    def header_end(self):
        return self.header_size + self.sizeofcmds

    def range_for_slice_offsets(self, start, end):
        return ByteRange(self.fat_offset + start, end - start, start)


def _extract_path_string(command_view, endian=">"):
    """Return the embedded lc_str payload of a path-bearing command.

    All path-bearing commands store an lc_str offset at byte 8; dylib
    commands place metadata before it but the offset semantics are the
    same.  Returns ``None`` when the offset does not point inside the
    command.
    """
    raw = command_view.raw
    if len(raw) < 12:
        return None
    order = "big" if endian == ">" else "little"
    string_offset = int.from_bytes(raw[8:12], byteorder=order)
    if string_offset <= 0 or string_offset >= len(raw):
        return None
    return raw[string_offset:].rstrip(b"\x00")


def _parse_slice(macho_header, raw_data, slice_index, fat_arch):
    """Build a :class:`SliceView` from a parsed macholib header.

    Load command raw bytes are sliced directly out of ``raw_data`` so later
    comparisons need no further file access.
    """
    endian = macho_header.endian
    is_64 = macho_header.MH_MAGIC in (
        mach_o.MH_MAGIC_64,
        mach_o.MH_CIGAM_64,
    )
    header_struct = mach_o.mach_header_64 if is_64 else mach_o.mach_header
    header_size = sizeof(header_struct)
    mh = macho_header.header

    commands = []
    segments = []
    signature = SignatureView(0, 0, -1, False)
    masked_fields = {}
    cursor = header_size
    for index, (lc, cmd, _data) in enumerate(macho_header.commands):
        cmdsize = int(lc.cmdsize)
        raw = bytes(raw_data[cursor : cursor + cmdsize])
        embedded_offsets = {}
        command_value = int(lc.cmd)
        if command_value in (mach_o.LC_SEGMENT, mach_o.LC_SEGMENT_64):
            # After the 8-byte command header and 16-byte segname come
            # vmaddr, vmsize, fileoff and filesize, each pointer sized.  All
            # four are layout-sensitive under a reference rewrite, but only
            # fileoff names a byte range inside the file, so the other three
            # are masked out for byte comparison while fileoff is additionally
            # exposed as an embedded file offset.
            pointer_size = 8 if is_64 else 4
            layout_fields = (
                int(cmd.vmaddr),
                int(cmd.vmsize),
                int(cmd.fileoff),
                int(cmd.filesize),
            )
            for field_index, value in enumerate(layout_fields):
                field_start = 8 + 16 + field_index * pointer_size
                if field_index == 2:
                    embedded_offsets[field_start] = value
                else:
                    masked_fields[field_start] = pointer_size
        elif command_value in _LINKEDIT_DATA_COMMANDS:
            # linkedit_data_command stores dataoff immediately after the
            # 8-byte load command header; datasize stays layout invariant.
            embedded_offsets[8] = int(cmd.dataoff)
        view = LoadCommandView(
            index,
            command_value,
            cmdsize,
            cursor,
            raw,
            embedded_offsets,
        )
        view.masked_fields = dict(masked_fields)
        masked_fields = {}
        commands.append(view)
        if command_value in (mach_o.LC_SEGMENT, mach_o.LC_SEGMENT_64):
            segname = cmd.segname.rstrip(b"\x00").decode("ascii", "replace")
            segments.append(
                SegmentView(
                    segname,
                    int(cmd.fileoff),
                    int(cmd.filesize),
                    index,
                )
            )
        elif command_value == mach_o.LC_CODE_SIGNATURE:
            signature = SignatureView(
                int(cmd.dataoff), int(cmd.datasize), index, True
            )
        cursor += cmdsize

    cputype = int(fat_arch.cputype)
    cpusubtype = int(fat_arch.cpusubtype)
    return SliceView(
        arch_key=(cputype, cpusubtype),
        arch_label=_arch_label(cputype, cpusubtype),
        fat_offset=int(fat_arch.offset),
        fat_size=int(fat_arch.size),
        slice_index=slice_index,
        endian=endian,
        is_64=is_64,
        header_size=header_size,
        sizeofcmds=int(mh.sizeofcmds),
        ncmds=int(mh.ncmds),
        commands=commands,
        segments=segments,
        signature=signature,
        data=bytes(raw_data),
    )


def _parse_blob(path, blob):
    """Parse a fat Mach-O blob using macholib without writing anything."""
    import io

    macho = MachO.__new__(MachO)
    macho.graphident = path
    macho.filename = path
    macho.loader_path = ""
    macho.fat = None
    macho.headers = []
    macho.allow_unknown_load_commands = True
    macho.load(io.BytesIO(blob))
    if macho.fat is None:
        raise ValueError("%r is not a fat/universal Mach-O file" % (path,))

    if macho.fat.magic == mach_o.FAT_MAGIC:
        arch_struct = mach_o.fat_arch
    else:
        arch_struct = mach_o.fat_arch64
    arch_size = sizeof(arch_struct)
    arch_count = int(macho.fat.nfat_arch)
    fat_header_size = sizeof(mach_o.fat_header)

    slices = []
    for index, header in enumerate(macho.headers):
        arch = arch_struct.from_fileobj(
            io.BytesIO(
                blob[
                    fat_header_size
                    + index * arch_size : fat_header_size
                    + (index + 1) * arch_size
                ]
            ),
            _endian_=">",
        )
        start = header.offset
        end = start + header.size
        slices.append(
            _parse_slice(header, blob[start:end], index, arch)
        )
    return slices


def parse_file(path):
    """Parse ``path`` read-only into a list of :class:`SliceView` objects.

    The file is opened once with ``"rb"`` and parsing runs on the in-memory
    copy; no write handle is ever taken.
    """
    with open(path, "rb") as handle:
        blob = handle.read()
    return _parse_blob(path, blob)


def parse_bytes(name, blob):
    """Parse an in-memory fat Mach-O blob without touching the filesystem."""
    return _parse_blob(name, bytes(blob))


# ---------------------------------------------------------------------------
# Comparison result model
# ---------------------------------------------------------------------------

#: Category constants used on every finding.  Keeping them as module level
#: strings lets callers filter programmatically without importing classes.
EXPLAINED_LAYOUT = "explained_layout"
EXPLAINED_LOAD_COMMAND = "explained_load_command"
UNEXPLAINED_CONTENT = "unexplained_content"
UNEXPLAINED_HEADER = "unexplained_header"
SIGNATURE_CHANGE = "signature_change"
MISSING_EVIDENCE = "missing_evidence"


@dataclass
class Finding:
    """One audited difference, located on both sides of the comparison.

    ``category`` is one of the module-level ``*`` constants.  ``detail``
    carries a short, machine-stable keyword (for example
    ``"segment_content"``) while ``message`` is human readable.
    """

    category: str
    detail: str
    message: str
    arch_label: str = ""
    before_range: object = None
    after_range: object = None
    before_index: object = None
    after_index: object = None


@dataclass
class LayoutShift:
    """A single explained displacement inside a slice.

    ``shift`` is the cumulative delta applied at ``slice_offset``: bytes at or
    after that offset in the "before" slice are found at
    ``offset + shift`` in the "after" slice.
    """

    slice_offset: int
    shift: int
    command_index: int
    command_name: str
    reason: str


@dataclass
class SliceComparison:
    """Result of comparing one matched architecture, or one unmatched side."""

    arch_key: object
    arch_label: str
    before: object = None
    after: object = None
    findings: list = None
    layout_shifts: list = None
    explained_delta: int = 0

    def __post_init__(self):
        if self.findings is None:
            self.findings = []
        if self.layout_shifts is None:
            self.layout_shifts = []


@dataclass
class ComparisonReport:
    """Top-level report for a pair of fat Mach-O files."""

    before_name: str
    after_name: str
    slice_comparisons: list

    @property
    def findings(self):
        for comparison in self.slice_comparisons:
            for finding in comparison.findings:
                yield finding

    def findings_by_category(self, category):
        return [f for f in self.findings if f.category == category]

    @property
    def has_unexplained_changes(self):
        return any(
            finding.category
            in (UNEXPLAINED_CONTENT, UNEXPLAINED_HEADER)
            for finding in self.findings
        )


# ---------------------------------------------------------------------------
# Slice matching (handles reordered, absent and duplicate architectures)
# ---------------------------------------------------------------------------


def _group_slices(slices):
    groups = {}
    for view in slices:
        groups.setdefault(view.arch_key, []).append(view)
    for views in groups.values():
        views.sort(key=lambda view: view.slice_index)
    return groups


def match_slices(before_slices, after_slices):
    """Pair slices by architecture, stable within duplicate architecture.

    Returns ``(pairs, only_before, only_after)`` where each pair is
    ``(before_view, after_view)``.  Architectures that occur on only one side
    are reported separately so callers can record missing evidence instead of
    guessing a counterpart.  When an architecture appears more than once the
    occurrences are paired by ordinal (slice order on each side); leftover
    duplicates are returned as unmatched.
    """
    before_groups = _group_slices(before_slices)
    after_groups = _group_slices(after_slices)
    pairs = []
    only_before = []
    only_after = []
    for key in sorted(set(before_groups) | set(after_groups)):
        left = before_groups.get(key, [])
        right = after_groups.get(key, [])
        common = min(len(left), len(right))
        for index in range(common):
            pairs.append((left[index], right[index]))
        only_before.extend(left[common:])
        only_after.extend(right[common:])
    return pairs, only_before, only_after



# ---------------------------------------------------------------------------
# Load command comparison and layout attribution
# ---------------------------------------------------------------------------


def _command_path(view, endian=">"):
    return _extract_path_string(view, endian)


def _mask_embedded_offsets(view):
    """Return command bytes with layout-sensitive fields zeroed.

    Two copies of the same load command can differ only in embedded file
    offsets (segment fileoff, LinkEdit dataoff) and the segment address/size
    fields that track them when a reference rewrite shifts the layout.
    Zeroing them lets the remaining bytes (names, protection bits, ...) be
    compared directly.
    """
    masked = bytearray(view.raw)
    pointer_size = 8 if view.cmd == mach_o.LC_SEGMENT_64 else 4
    field_starts = set(view.embedded_offsets)
    field_starts.update((view.masked_fields or {}).keys())
    for field_start in field_starts:
        for index in range(field_start, field_start + pointer_size):
            if index < len(masked):
                masked[index] = 0
    return bytes(masked)


def _embedded_offset_deltas(left, right):
    """Yield (field_start, before_value, after_value) for moved anchors."""
    for field_start in sorted(left.embedded_offsets):
        before_value = left.embedded_offsets[field_start]
        after_value = right.embedded_offsets.get(field_start)
        if after_value is not None and after_value != before_value:
            yield field_start, before_value, after_value


def _command_field_range(slice_view, command_view, field_start, pointer_size):
    start = command_view.slice_offset + field_start
    return slice_view.range_for_slice_offsets(
        start, start + pointer_size
    )


def _compare_command_pair(
    left,
    right,
    allowed,
    findings,
    shifts,
    arch_label,
    left_endian=">",
    right_endian=">",
    left_slice=None,
    right_slice=None,
):
    delta = right.cmdsize - left.cmdsize
    if left.cmd != right.cmd:
        findings.append(
            Finding(
                MISSING_EVIDENCE,
                "load_command_type",
                "command %d changed type %s -> %s"
                % (left.index, left.name, right.name),
                arch_label,
                before_index=left.index,
                after_index=right.index,
            )
        )
        return 0

    if left.cmd in allowed:
        left_path = _command_path(left, left_endian)
        right_path = _command_path(right, right_endian)
        if left_path != right_path or left.raw != right.raw:
            findings.append(
                Finding(
                    EXPLAINED_LOAD_COMMAND,
                    "reference_rewrite",
                    "%s at index %d: %r -> %r (cmdsize %d -> %d)"
                    % (
                        left.name,
                        left.index,
                        left_path,
                        right_path,
                        left.cmdsize,
                        right.cmdsize,
                    ),
                    arch_label,
                    before_range=(
                        left_slice.range_for_slice_offsets(
                            left.slice_offset,
                            left.slice_offset + left.cmdsize,
                        )
                        if left_slice is not None
                        else None
                    ),
                    after_range=(
                        right_slice.range_for_slice_offsets(
                            right.slice_offset,
                            right.slice_offset + right.cmdsize,
                        )
                        if right_slice is not None
                        else None
                    ),
                    before_index=left.index,
                    after_index=right.index,
                )
            )
            if delta:
                # Everything at or beyond the *end* of the resized command is
                # displaced.  The boundary is recorded in before-slice
                # coordinates so every later anchor can ask "what shift
                # applied to my original offset?".
                shifts.append(
                    LayoutShift(
                        left.slice_offset + left.cmdsize,
                        delta,
                        left.index,
                        left.name,
                        "path rewrite changed command size",
                    )
                )
        return delta

    if _mask_embedded_offsets(left) != _mask_embedded_offsets(right):
        findings.append(
            Finding(
                UNEXPLAINED_HEADER,
                "load_command_bytes",
                "non-rewritable command %s at index %d changed outside its "
                "file-offset fields" % (left.name, left.index),
                arch_label,
                before_index=left.index,
                after_index=right.index,
            )
        )
    pointer_size = 8 if left.cmd == mach_o.LC_SEGMENT_64 else 4
    for field_start, before_value, after_value in _embedded_offset_deltas(
        left, right
    ):
        findings.append(
            Finding(
                EXPLAINED_LAYOUT,
                "embedded_offset",
                "%s at index %d moved its file offset %d -> %d"
                % (
                    left.name,
                    left.index,
                    before_value,
                    after_value,
                ),
                arch_label,
                before_range=_command_field_range(
                    left_slice, left, field_start, pointer_size
                ),
                after_range=_command_field_range(
                    right_slice, right, field_start, pointer_size
                ),
                before_index=left.index,
                after_index=right.index,
            )
        )
    return 0


def _coalesce_ranges(indices):
    ranges = []
    start = None
    previous = None
    for index in indices:
        if start is None:
            start = previous = index
        elif index == previous + 1:
            previous = index
        else:
            ranges.append((start, previous + 1))
            start = previous = index
    if start is not None:
        ranges.append((start, previous + 1))
    return ranges


def diff_ranges(before_bytes, after_bytes):
    """Compare two equal-length buffers, return differing (start, end)."""
    if len(before_bytes) != len(after_bytes):
        raise ValueError("diff_ranges requires equal-length buffers")
    differing = [
        index
        for index, (left, right) in enumerate(zip(before_bytes, after_bytes))
        if left != right
    ]
    return _coalesce_ranges(differing)


def _total_shift(shifts):
    """Total displacement produced by every explained layout change."""
    return sum(shift.shift for shift in shifts)


# Slice data is placed on at least this alignment in practice; the padding
# between the load commands and the first segment can absorb part of a
# command-size growth, so an anchor may move by less than the raw delta.
_ANCHOR_ALIGNMENT = 8


def _explained_anchor_shift(before_offset, after_offset, total_delta):
    """Return the displacement when alignment can account for it, else None.

    A reference rewrite grows the command area by ``total_delta`` bytes, but
    segment anchors are aligned: padding that existed before the rewrite can
    shrink, so the observed displacement sits between zero and ``total_delta``
    and both anchor values must stay naturally aligned.
    """
    displacement = after_offset - before_offset
    if displacement < 0 or displacement > max(total_delta, 0):
        return None
    if total_delta >= 0:
        aligned = (
            before_offset % _ANCHOR_ALIGNMENT == 0
            and after_offset % _ANCHOR_ALIGNMENT == 0
        )
        if aligned:
            return displacement
    if displacement == total_delta:
        return displacement
    return None


def _verify_layout(left, right, shifts, findings, arch_label):
    """Check segment anchors follow the explained command-size shifts.

    Every segment anchor sits after the load-command area.  The header-bearing
    segment (``__TEXT``) spans the resized commands and grows by the raw
    command delta; payload anchors move by that delta minus any alignment
    padding that the rewrite consumes.  Anything outside these explained
    displacements is reported as missing evidence rather than guessed at.
    """
    total_delta = _total_shift(shifts)
    left_segments = {segment.name: segment for segment in left.segments}
    right_segments = {segment.name: segment for segment in right.segments}
    for name in sorted(set(left_segments) | set(right_segments)):
        left_segment = left_segments.get(name)
        right_segment = right_segments.get(name)
        if left_segment is None or right_segment is None:
            findings.append(
                Finding(
                    MISSING_EVIDENCE,
                    "segment_missing",
                    "segment %r present on only one side" % (name,),
                    arch_label,
                )
            )
            continue
        size_delta = right_segment.filesize - left_segment.filesize
        header_segment = left_segment.fileoff == 0
        if header_segment:
            # __TEXT spans the header and load commands up to the first
            # aligned payload anchor, so its filesize tracks where that
            # anchor lands after the rewrite (delta minus absorbed padding),
            # not the raw command-size delta.
            header_growth = _explained_anchor_shift(
                left_segment.filesize,
                right_segment.filesize,
                total_delta,
            )
            if header_growth is None:
                findings.append(
                    Finding(
                        MISSING_EVIDENCE,
                        "segment_size",
                        "header segment %r filesize changed %d -> %d in a "
                        "way the %d-byte rewrite and alignment cannot "
                        "explain"
                        % (
                            name,
                            left_segment.filesize,
                            right_segment.filesize,
                            total_delta,
                        ),
                        arch_label,
                    )
                )
            elif header_growth:
                findings.append(
                    Finding(
                        EXPLAINED_LAYOUT,
                        "header_segment_size",
                        "header segment %r grew %d bytes with the rewritten "
                        "commands" % (name, header_growth),
                        arch_label,
                        before_range=left.range_for_slice_offsets(
                            0, left_segment.filesize
                        ),
                        after_range=right.range_for_slice_offsets(
                            0, right_segment.filesize
                        ),
                    )
                )
            continue
        if size_delta != 0:
            findings.append(
                Finding(
                    MISSING_EVIDENCE,
                    "segment_size",
                    "payload segment %r changed filesize %d -> %d"
                    % (
                        name,
                        left_segment.filesize,
                        right_segment.filesize,
                    ),
                    arch_label,
                )
            )
        displacement = _explained_anchor_shift(
            left_segment.fileoff, right_segment.fileoff, total_delta
        )
        if displacement is None:
            findings.append(
                Finding(
                    MISSING_EVIDENCE,
                    "unexplained_layout",
                    "segment %r fileoff %d -> %d cannot be explained by the "
                    "%d-byte rewrite and segment alignment"
                    % (
                        name,
                        left_segment.fileoff,
                        right_segment.fileoff,
                        total_delta,
                    ),
                    arch_label,
                )
            )
        elif displacement:
            findings.append(
                Finding(
                    EXPLAINED_LAYOUT,
                    "segment_anchor",
                    "segment %r displaced %d bytes by the reference rewrite"
                    " and alignment" % (name, displacement),
                    arch_label,
                    before_range=left.range_for_slice_offsets(
                        left_segment.fileoff,
                        left_segment.fileoff + left_segment.filesize,
                    ),
                    after_range=right.range_for_slice_offsets(
                        right_segment.fileoff,
                        right_segment.fileoff + right_segment.filesize,
                    ),
                )
            )



def _segment_content_findings(left, right, shifts, findings, arch_label):
    """Compare segment payloads, honoring explained shifts and signatures."""
    left_segments = {segment.name: segment for segment in left.segments}
    right_segments = {segment.name: segment for segment in right.segments}
    signature_left = left.signature
    signature_right = right.signature
    for name in sorted(set(left_segments) & set(right_segments)):
        left_segment = left_segments[name]
        right_segment = right_segments[name]
        if left_segment.filesize != right_segment.filesize:
            continue
        shift = right_segment.fileoff - left_segment.fileoff
        left_start = left_segment.fileoff
        right_start = right_segment.fileoff
        left_end = left_start + left_segment.filesize
        right_end = right_start + right_segment.filesize
        if (
            left_end > len(left.data)
            or right_end > len(right.data)
        ):
            findings.append(
                Finding(
                    MISSING_EVIDENCE,
                    "segment_out_of_bounds",
                    "segment %r extends past slice end" % (name,),
                    arch_label,
                )
            )
            continue
        left_payload = left.data[left_start:left_end]
        right_payload = right.data[right_start:right_end]
        if left_payload == right_payload:
            continue
        ranges = diff_ranges(left_payload, right_payload)
        for local_start, local_end in ranges:
            before_range = left.range_for_slice_offsets(
                left_start + local_start, left_start + local_end
            )
            after_range = right.range_for_slice_offsets(
                right_start + local_start, right_start + local_end
            )
            in_signature = _inside_signature(
                signature_left, left_start + local_start, local_end
            ) or _inside_signature(
                signature_right, right_start + local_start, local_end
            )
            category = SIGNATURE_CHANGE if in_signature else UNEXPLAINED_CONTENT
            detail = (
                "signature_bytes" if in_signature else "segment_content"
            )
            findings.append(
                Finding(
                    category,
                    detail,
                    "segment %r bytes differ at slice offset %d (%d bytes)"
                    % (
                        name,
                        left_start + local_start,
                        local_end - local_start,
                    ),
                    arch_label,
                    before_range=before_range,
                    after_range=after_range,
                )
            )


def _inside_signature(signature, slice_offset, length):
    if not signature.present:
        return False
    start = signature.dataoff
    end = start + signature.datasize
    return start <= slice_offset and slice_offset + length <= end


def _signature_content_findings(left, right, findings, arch_label):
    """Compare signature bytes directly, located on both sides.

    Signatures sit in their own LinkEdit region rather than inside a payload
    segment, so they are compared independently and never surface as ordinary
    segment content drift.
    """
    signature_left = left.signature
    signature_right = right.signature
    if not (signature_left.present and signature_right.present):
        return
    if signature_left.datasize != signature_right.datasize:
        # Coverage change is already reported; byte compare needs equal size.
        return
    left_start = signature_left.dataoff
    right_start = signature_right.dataoff
    left_payload = left.data[left_start : left_start + signature_left.datasize]
    right_payload = right.data[
        right_start : right_start + signature_right.datasize
    ]
    if left_payload == right_payload:
        return
    for local_start, local_end in diff_ranges(left_payload, right_payload):
        findings.append(
            Finding(
                SIGNATURE_CHANGE,
                "signature_bytes",
                "code signature bytes differ at slice offset %d (%d bytes)"
                % (left_start + local_start, local_end - local_start),
                arch_label,
                before_range=left.range_for_slice_offsets(
                    left_start + local_start, left_start + local_end
                ),
                after_range=right.range_for_slice_offsets(
                    right_start + local_start, right_start + local_end
                ),
            )
        )


def _compare_signature_coverage(left, right, shifts, findings, arch_label):
    """Report signature presence/coverage moves and unexplained size changes."""
    signature_left = left.signature
    signature_right = right.signature
    if not signature_left.present and not signature_right.present:
        return
    if signature_left.present != signature_right.present:
        findings.append(
            Finding(
                SIGNATURE_CHANGE,
                "signature_presence",
                "code signature present before=%s after=%s"
                % (signature_left.present, signature_right.present),
                arch_label,
            )
        )
        return
    total_delta = _total_shift(shifts)
    signature_shift = _explained_anchor_shift(
        signature_left.dataoff,
        signature_right.dataoff,
        total_delta,
    )
    if signature_shift is None:
        findings.append(
            Finding(
                MISSING_EVIDENCE,
                "signature_layout",
                "signature dataoff %d -> %d cannot be explained by the "
                "%d-byte rewrite and alignment"
                % (
                    signature_left.dataoff,
                    signature_right.dataoff,
                    total_delta,
                ),
                arch_label,
            )
        )
    elif signature_shift:
        findings.append(
            Finding(
                EXPLAINED_LAYOUT,
                "signature_anchor",
                "signature displaced %d bytes by the reference rewrite and "
                "alignment" % (signature_shift,),
                arch_label,
                before_range=left.range_for_slice_offsets(
                    signature_left.dataoff,
                    signature_left.dataoff + signature_left.datasize,
                ),
                after_range=right.range_for_slice_offsets(
                    signature_right.dataoff,
                    signature_right.dataoff + signature_right.datasize,
                ),
            )
        )
    if signature_left.datasize != signature_right.datasize:
        findings.append(
            Finding(
                SIGNATURE_CHANGE,
                "signature_coverage",
                "signature coverage changed %d -> %d bytes"
                % (signature_left.datasize, signature_right.datasize),
                arch_label,
                before_range=left.range_for_slice_offsets(
                    signature_left.dataoff,
                    signature_left.dataoff + signature_left.datasize,
                ),
                after_range=right.range_for_slice_offsets(
                    signature_right.dataoff,
                    signature_right.dataoff + signature_right.datasize,
                ),
            )
        )



SIZEOFCMDS_FIELD_OFFSET = 20  # mach_header[_64]: magic,cputype,cpusubtype,
# filetype,ncmds then sizeofcmds (all 4-byte fields).


def _compare_header_region(left, right, findings, arch_label):
    """Compare the mach header itself (load command area handled per cmd).

    The ``sizeofcmds`` field legitimately grows or shrinks with a reference
    rewrite, so its change is classified as explained layout rather than an
    unexplained header edit.
    """
    header_size = min(left.header_size, right.header_size)
    left_header = bytearray(left.data[:header_size])
    right_header = bytearray(right.data[:header_size])
    sizeofcmds_changed = (
        left.sizeofcmds != right.sizeofcmds
        and left_header[SIZEOFCMDS_FIELD_OFFSET:SIZEOFCMDS_FIELD_OFFSET + 4]
        != right_header[SIZEOFCMDS_FIELD_OFFSET:SIZEOFCMDS_FIELD_OFFSET + 4]
    )
    if sizeofcmds_changed:
        findings.append(
            Finding(
                EXPLAINED_LAYOUT,
                "sizeofcmds",
                "mach header sizeofcmds %d -> %d follows the rewritten "
                "commands" % (left.sizeofcmds, right.sizeofcmds),
                arch_label,
                before_range=left.range_for_slice_offsets(
                    SIZEOFCMDS_FIELD_OFFSET,
                    SIZEOFCMDS_FIELD_OFFSET + 4,
                ),
                after_range=right.range_for_slice_offsets(
                    SIZEOFCMDS_FIELD_OFFSET,
                    SIZEOFCMDS_FIELD_OFFSET + 4,
                ),
            )
        )
        for index in range(4):
            left_header[SIZEOFCMDS_FIELD_OFFSET + index] = 0
            right_header[SIZEOFCMDS_FIELD_OFFSET + index] = 0
    if bytes(left_header) != bytes(right_header):
        for local_start, local_end in diff_ranges(
            bytes(left_header), bytes(right_header)
        ):
            findings.append(
                Finding(
                    UNEXPLAINED_HEADER,
                    "mach_header_bytes",
                    "mach header bytes differ at offset %d" % (local_start,),
                    arch_label,
                    before_range=left.range_for_slice_offsets(
                        local_start, local_end
                    ),
                    after_range=right.range_for_slice_offsets(
                        local_start, local_end
                    ),
                )
            )
    if left.header_size != right.header_size:
        findings.append(
            Finding(
                MISSING_EVIDENCE,
                "header_size",
                "mach header size %d -> %d"
                % (left.header_size, right.header_size),
                arch_label,
            )
        )
    if left.ncmds != right.ncmds:
        findings.append(
            Finding(
                MISSING_EVIDENCE,
                "command_count",
                "load command count %d -> %d" % (left.ncmds, right.ncmds),
                arch_label,
            )
        )


def compare_slice_pair(left, right, allowed_commands=DEFAULT_ALLOWED_COMMANDS):
    """Compare two matched :class:`SliceView` objects, read-only."""
    comparison = SliceComparison(
        arch_key=left.arch_key,
        arch_label=left.arch_label,
        before=left,
        after=right,
    )
    findings = comparison.findings
    shifts = comparison.layout_shifts

    _compare_header_region(left, right, findings, left.arch_label)

    command_count = min(len(left.commands), len(right.commands))
    explained_delta = 0
    for index in range(command_count):
        explained_delta += _compare_command_pair(
            left.commands[index],
            right.commands[index],
            allowed_commands,
            findings,
            shifts,
            left.arch_label,
            left.endian,
            right.endian,
            left,
            right,
        )
    comparison.explained_delta = explained_delta

    _verify_layout(left, right, shifts, findings, left.arch_label)
    _compare_signature_coverage(
        left, right, shifts, findings, left.arch_label
    )
    _signature_content_findings(
        left, right, findings, left.arch_label
    )
    _segment_content_findings(
        left, right, shifts, findings, left.arch_label
    )
    return comparison


def _unmatched_comparison(view, side):
    comparison = SliceComparison(
        arch_key=view.arch_key,
        arch_label=view.arch_label,
        before=view if side == "before" else None,
        after=view if side == "after" else None,
    )
    comparison.findings.append(
        Finding(
            MISSING_EVIDENCE,
            "slice_absent",
            "architecture %s exists only in the %s file; no counterpart to "
            "compare against" % (view.arch_label, side),
            view.arch_label,
            before_range=(
                view.range_for_slice_offsets(0, view.fat_size)
                if side == "before"
                else None
            ),
            after_range=(
                view.range_for_slice_offsets(0, view.fat_size)
                if side == "after"
                else None
            ),
        )
    )
    return comparison


def compare_files(
    before_path,
    after_path,
    allowed_commands=DEFAULT_ALLOWED_COMMANDS,
):
    """Read-only pairwise comparison of two fat Mach-O files.

    Parses both files through :func:`parse_file`, matches architecture
    slices (tolerating reordering, absent and duplicate architectures) and
    returns a :class:`ComparisonReport` whose findings are split into
    explained layout effects, unexplained content, signature changes and
    missing evidence.
    """
    before_slices = parse_file(before_path)
    after_slices = parse_file(after_path)
    return _compare_parsed(
        before_path,
        after_path,
        before_slices,
        after_slices,
        allowed_commands,
    )


def compare_blobs(
    before_name,
    before_blob,
    after_name,
    after_blob,
    allowed_commands=DEFAULT_ALLOWED_COMMANDS,
):
    """In-memory variant of :func:`compare_files`; nothing touches disk."""
    before_slices = parse_bytes(before_name, before_blob)
    after_slices = parse_bytes(after_name, after_blob)
    return _compare_parsed(
        before_name,
        after_name,
        before_slices,
        after_slices,
        allowed_commands,
    )


def _compare_parsed(
    before_name,
    after_name,
    before_slices,
    after_slices,
    allowed_commands,
):
    pairs, only_before, only_after = match_slices(
        before_slices, after_slices
    )
    comparisons = []
    for left, right in pairs:
        comparisons.append(
            compare_slice_pair(left, right, allowed_commands)
        )
    for view in only_before:
        comparisons.append(_unmatched_comparison(view, "before"))
    for view in only_after:
        comparisons.append(_unmatched_comparison(view, "after"))
    return ComparisonReport(before_name, after_name, comparisons)


# ---------------------------------------------------------------------------
# Readable reporting and command line entry point
# ---------------------------------------------------------------------------

_CATEGORY_TITLES = (
    (EXPLAINED_LOAD_COMMAND, "Explained reference rewrites"),
    (EXPLAINED_LAYOUT, "Explained layout changes"),
    (UNEXPLAINED_CONTENT, "Unexplained segment content changes"),
    (UNEXPLAINED_HEADER, "Unexplained header changes"),
    (SIGNATURE_CHANGE, "Code signature changes"),
    (MISSING_EVIDENCE, "Missing evidence / unprovable changes"),
)


def _format_range(byte_range):
    if byte_range is None:
        return "<no region on this side>"
    return str(byte_range)


def render_report(report):
    """Render a :class:`ComparisonReport` as a human-readable string."""
    lines = [
        "slice diff: %s -> %s"
        % (report.before_name, report.after_name),
        "architecture slices compared: %d"
        % len(report.slice_comparisons),
        "",
    ]
    for comparison in report.slice_comparisons:
        lines.append(
            "architecture %s (before slice %d, after slice %s)"
            % (
                comparison.arch_label,
                comparison.before.slice_index
                if comparison.before is not None
                else -1,
                comparison.after.slice_index
                if comparison.after is not None
                else "absent",
            )
        )
        if comparison.layout_shifts:
            lines.append("  layout shifts:")
            for shift in comparison.layout_shifts:
                lines.append(
                    "    +%d bytes from slice offset %d via %s (%s)"
                    % (
                        shift.shift,
                        shift.slice_offset,
                        shift.command_name,
                        shift.reason,
                    )
                )
        grouped = {}
        for finding in comparison.findings:
            grouped.setdefault(finding.category, []).append(finding)
        if not grouped:
            lines.append("  no differences")
        for category, title in _CATEGORY_TITLES:
            for finding in grouped.get(category, []):
                lines.append(
                    "  [%s] %s: %s"
                    % (category, finding.detail, finding.message)
                )
                lines.append(
                    "      before: %s"
                    % _format_range(finding.before_range)
                )
                lines.append(
                    "      after:  %s"
                    % _format_range(finding.after_range)
                )
        lines.append("")
    return "\n".join(lines)


def main(argv=None):
    """Command line entry: compare two fat Mach-O files read-only."""
    import argparse

    parser = argparse.ArgumentParser(
        description=(
            "Read-only pairwise audit of two (fat) Mach-O files, explaining "
            "per-slice reference rewrites, layout shifts, content edits, "
            "signature changes and missing evidence."
        )
    )
    parser.add_argument("before", help="path to the original fat Mach-O")
    parser.add_argument("after", help="path to the repackaged fat Mach-O")
    args = parser.parse_args(argv)
    report = compare_files(args.before, args.after)
    print(render_report(report))
    return 1 if report.has_unexplained_changes else 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
