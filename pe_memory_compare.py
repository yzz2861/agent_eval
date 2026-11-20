"""Read-only comparison of an on-disk PE image against a sparse memory view.

The loader does not leave a freshly loaded image byte-identical to its file:

* sections are mapped from file offsets to their virtual addresses and zero
  padded,
* base relocations are applied when the preferred image base is unavailable,
* the import address table (IAT) is overwritten with resolved entry points.

This module models those transformations for the architectures it supports
and reports every *remaining* difference. It never modifies the parsed PE,
never executes the image, and does not rely on any Windows API. Memory is
captured sparsely: a byte whose page was not captured is reported as
undetermined rather than silently treated as zero (and therefore as a
modification). An unrecognised relocation type is recorded against the exact
bytes it covers; it never causes a whole section to be skipped.

Public entry point: :func:`compare_disk_to_memory`.
"""

import struct

import pefile


# ---------------------------------------------------------------------------
# Verdicts assigned to individual RVAs.
# ---------------------------------------------------------------------------

#: The byte matches the loader-adjusted reference image.
VERDICT_MATCH = "match"
#: The byte differs, but a base-relocation transform explains it exactly.
VERDICT_EXPLAINED_RELOCATION = "explained_relocation"
#: The byte differs, but import binding (IAT / ILT overwrite) explains it.
VERDICT_EXPLAINED_IAT = "explained_iat"
#: The byte differs and no loader transform accounts for it.
VERDICT_SUSPECT = "suspect"
#: Captured memory falls outside the mapped image entirely.
VERDICT_SUSPECT_OUT_OF_IMAGE = "suspect_out_of_image"
#: The page backing this byte was not captured; no judgment is possible.
VERDICT_UNDETERMINED_MISSING_PAGE = "undetermined_missing_page"
#: A relocation of an unsupported type covers this byte.
VERDICT_UNDETERMINED_UNKNOWN_RELOC = "undetermined_unknown_reloc"
#: Catch-all for bytes that cannot be classified for another documented reason.
VERDICT_UNDETERMINED = "undetermined"
#: Two distinct loader transforms claim the same byte.
VERDICT_CONFLICT = "conflict"
#: Two distinct loader transforms claim the same byte.
VERDICT_CONFLICT = "conflict"

EXPLAINED_VERDICTS = (
    VERDICT_EXPLAINED_RELOCATION,
    VERDICT_EXPLAINED_IAT,
)
SUSPECT_VERDICTS = (VERDICT_SUSPECT, VERDICT_SUSPECT_OUT_OF_IMAGE)
UNDETERMINED_VERDICTS = (
    VERDICT_UNDETERMINED_MISSING_PAGE,
    VERDICT_UNDETERMINED_UNKNOWN_RELOC,
    VERDICT_UNDETERMINED,
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class MemoryCompareError(Exception):
    """Base class for errors raised by the comparison backend."""


class UnsupportedArchitecture(MemoryCompareError):
    """The image machine type has no modelled loader transforms."""


class InvalidMemoryMap(MemoryCompareError):
    """The supplied fragments overlap or describe an inconsistent capture."""


# ---------------------------------------------------------------------------
# Evidence objects. Every explained byte must point at one of these.
# ---------------------------------------------------------------------------


class RelocationEvidence:
    """Loader evidence: a single base-relocation fixup.

    Attributes:
        reloc_type: Numeric IMAGE_REL_BASED_* type.
        type_name: Symbolic type name.
        rva: RVA the fixup is applied at.
        width: Number of bytes the fixup touches.
        disk_value: Reference value before the loader delta is added.
        expected_value: Value predicted after applying the loader delta.
        delta: ``load_base - preferred_image_base``.
        paired_low_rva: For HIGHADJ, the RVA of the companion LOW entry.
    """

    kind = "relocation"

    def __init__(
        self,
        reloc_type,
        type_name,
        rva,
        width,
        disk_value,
        expected_value,
        delta,
        paired_low_rva=None,
    ):
        self.reloc_type = reloc_type
        self.type_name = type_name
        self.rva = rva
        self.width = width
        self.disk_value = disk_value
        self.expected_value = expected_value
        self.delta = delta
        self.paired_low_rva = paired_low_rva
        self.evidence_id = ("reloc", reloc_type, rva, width)

    @property
    def span(self):
        return (self.rva, self.rva + self.width)

    def to_dict(self):
        return {
            "kind": self.kind,
            "type": self.type_name,
            "rva": self.rva,
            "span": list(self.span),
            "disk_value": self.disk_value,
            "expected_value": self.expected_value,
            "delta": self.delta,
        }

    def __repr__(self):
        return (
            f"RelocationEvidence({self.type_name} at rva={self.rva:#x}, "
            f"width={self.width}, disk={self.disk_value:#x} -> "
            f"expected={self.expected_value:#x})"
        )


class UnknownRelocationEvidence:
    """A relocation entry whose type the backend cannot model.

    The covered bytes are marked undetermined rather than ignored; the
    evidence retains everything needed for a human or another tool to decide.
    """

    kind = "unknown_relocation"

    def __init__(self, reloc_type, rva, width, reason):
        self.reloc_type = reloc_type
        self.type_name = pefile.RELOCATION_TYPE.get(
            reloc_type, ("IMAGE_REL_BASED_UNKNOWN",)
        )[0]
        self.rva = rva
        self.width = width
        self.reason = reason
        self.evidence_id = ("unknown_reloc", reloc_type, rva, width)

    @property
    def span(self):
        return (self.rva, self.rva + self.width)

    def to_dict(self):
        return {
            "kind": self.kind,
            "type": self.type_name,
            "rva": self.rva,
            "span": list(self.span),
            "reason": self.reason,
        }

    def __repr__(self):
        return (
            f"UnknownRelocationEvidence(type={self.reloc_type} at "
            f"rva={self.rva:#x}, width={self.width})"
        )


class IATBindingEvidence:
    """Loader evidence: overwrite of one import thunk slot.

    Attributes:
        rva: RVA of the thunk slot.
        width: Bytes occupied by the slot.
        table: ``"IAT"`` or ``"ILT"``.
        dll: Importing DLL name as stored on disk (best effort).
        symbol: Symbol name or ``"ordinal N"`` (best effort).
        disk_value: Thunk value stored on disk (hint/name RVA or ordinal).
    """

    kind = "iat_binding"

    def __init__(self, rva, width, table, dll, symbol, disk_value):
        self.rva = rva
        self.width = width
        self.table = table
        self.dll = dll
        self.symbol = symbol
        self.disk_value = disk_value
        self.evidence_id = ("iat", table, rva, width)

    @property
    def span(self):
        return (self.rva, self.rva + self.width)

    def to_dict(self):
        return {
            "kind": self.kind,
            "table": self.table,
            "dll": self.dll,
            "symbol": self.symbol,
            "rva": self.rva,
            "span": list(self.span),
            "disk_value": self.disk_value,
        }

    def __repr__(self):
        return (
            f"IATBindingEvidence({self.table} {self.dll}!{self.symbol} at "
            f"rva={self.rva:#x}, width={self.width})"
        )


class ExplanationConflict:
    """Two distinct loader transforms claim the same byte."""

    def __init__(self, rva, evidences):
        self.rva = rva
        self.evidences = tuple(evidences)

    def to_dict(self):
        return {
            "rva": self.rva,
            "evidences": [e.to_dict() for e in self.evidences],
        }

    def __repr__(self):
        joined = ", ".join(repr(e) for e in self.evidences)
        return f"ExplanationConflict(rva={self.rva:#x}, [{joined}])"


class ByteDifference:
    """A single byte whose captured value differs from the reference."""

    def __init__(self, rva, disk_value, memory_value, verdict, evidence):
        self.rva = rva
        self.disk_value = disk_value
        self.memory_value = memory_value
        self.verdict = verdict
        self.evidence = tuple(evidence)

    def __repr__(self):
        return (
            f"ByteDifference(rva={self.rva:#x}, disk={self.disk_value:02x}, "
            f"mem={self.memory_value:02x}, verdict={self.verdict})"
        )


class MemoryFragment:
    """A contiguous captured chunk of the loaded image.

    Args:
        start_rva: RVA of the first captured byte.
        data: Raw captured bytes.
    """

    def __init__(self, start_rva, data):
        self.start_rva = int(start_rva)
        if self.start_rva < 0:
            raise InvalidMemoryMap("fragment start_rva must be non-negative")
        self.data = bytes(data)

    @property
    def end_rva(self):
        return self.start_rva + len(self.data)

    def __repr__(self):
        return f"MemoryFragment(rva={self.start_rva:#x}, len={len(self.data)})"


def _merge_points(points):
    """Merge sorted single RVAs into contiguous ``[start, end)`` runs."""
    if not points:
        return []
    ranges = []
    start = prev = points[0]
    for rva in points[1:]:
        if rva == prev + 1:
            prev = rva
            continue
        ranges.append((start, prev + 1))
        start = prev = rva
    ranges.append((start, prev + 1))
    return ranges


def _merge_ranges(ranges):
    """Merge possibly-overlapping ``[start, end)`` tuples."""
    if not ranges:
        return []
    ranges = sorted(ranges)
    merged = [list(ranges[0])]
    for start, end in ranges[1:]:
        if start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return [tuple(r) for r in merged]


# ---------------------------------------------------------------------------
# Architecture model
# ---------------------------------------------------------------------------

_REL_ABSOLUTE = pefile.RELOCATION_TYPE["IMAGE_REL_BASED_ABSOLUTE"]
_REL_HIGH = pefile.RELOCATION_TYPE["IMAGE_REL_BASED_HIGH"]
_REL_LOW = pefile.RELOCATION_TYPE["IMAGE_REL_BASED_LOW"]
_REL_HIGHLOW = pefile.RELOCATION_TYPE["IMAGE_REL_BASED_HIGHLOW"]
_REL_HIGHADJ = pefile.RELOCATION_TYPE["IMAGE_REL_BASED_HIGHADJ"]
_REL_DIR64 = pefile.RELOCATION_TYPE["IMAGE_REL_BASED_DIR64"]


def _architecture_table():
    """Build the per-machine loader model used by the comparator."""
    pe32 = pefile.OPTIONAL_HEADER_MAGIC_PE
    pe32_plus = pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS
    return {
        pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_I386"]: {
            "name": "x86",
            "optional_magic": pe32,
            "pointer_size": 4,
            "ordinal_flag": pefile.IMAGE_ORDINAL_FLAG,
            "reloc_types": {
                _REL_HIGH: (2, "high16"),
                _REL_LOW: (2, "low16"),
                _REL_HIGHLOW: (4, "absolute32"),
                _REL_HIGHADJ: (2, "highadj"),
            },
        },
        pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]: {
            "name": "x64",
            "optional_magic": pe32_plus,
            "pointer_size": 8,
            "ordinal_flag": pefile.IMAGE_ORDINAL_FLAG64,
            "reloc_types": {
                _REL_HIGH: (2, "high16"),
                _REL_LOW: (2, "low16"),
                _REL_HIGHLOW: (4, "absolute32"),
                _REL_HIGHADJ: (2, "highadj"),
                _REL_DIR64: (8, "absolute64"),
            },
        },
    }


_ARCHITECTURES = _architecture_table()


def build_reference_image(pe):
    """Return the zero-based memory layout of the on-disk image.

    The result is a bytearray indexed by RVA. It mirrors the loader view
    before relocations and import binding: headers plus each section at its
    virtual address, with BSS zero-filled and file-alignment padding
    discarded. The supplied pe is never modified.
    """
    mapped = bytearray(pe.header)

    for section in pe.sections:
        if section.Misc_VirtualSize == 0 and section.SizeOfRawData == 0:
            continue
        va = section.VirtualAddress
        section_data = bytearray(section.get_data())
        virtual_size = section.Misc_VirtualSize
        if virtual_size:
            if virtual_size < len(section_data):
                section_data = section_data[:virtual_size]
            elif virtual_size > len(section_data):
                section_data += b"\x00" * (virtual_size - len(section_data))
        end = va + len(section_data)
        if end > len(mapped):
            mapped.extend(b"\x00" * (end - len(mapped)))
        mapped[va:end] = section_data

    return mapped


class MemoryImageView:
    """Read-only sparse view of captured memory, indexed by RVA."""

    def __init__(self, fragments):
        self._chunks = []
        self.present = {}
        for fragment in fragments:
            self._chunks.append((fragment.start_rva, fragment.data))
            for offset, value in enumerate(fragment.data):
                rva = fragment.start_rva + offset
                if rva in self.present:
                    raise InvalidMemoryMap(
                        f"fragments overlap at rva {rva:#x}"
                    )
                self.present[rva] = value
        self._chunks.sort(key=lambda item: item[0])

    def read(self, rva):
        return self.present.get(rva)

    def is_present(self, rva):
        return rva in self.present

    def covered_rvas(self):
        return self.present.keys()

    def present_pages(self, page_size):
        return {rva // page_size for rva in self.present}


# ---------------------------------------------------------------------------
# Loader transform #1: base relocations
# ---------------------------------------------------------------------------


def _read_unsigned(data, rva, size):
    fmt = {2: "<H", 4: "<I", 8: "<Q"}[size]
    return struct.unpack(fmt, bytes(data[rva:rva + size]))[0]


def _read_signed(data, rva, size):
    fmt = {2: "<h", 4: "<i", 8: "<q"}[size]
    return struct.unpack(fmt, bytes(data[rva:rva + size]))[0]


def _reloc_type_name(rtype):
    for name, value in pefile.RELOCATION_TYPE.items():
        if value == rtype:
            return name
    return f"IMAGE_REL_BASED_UNKNOWN_{rtype}"


def build_relocation_evidence(pe, reference, delta, arch):
    """Walk the base-relocation directory and produce per-RVA evidence.

    Every modelled entry yields a RelocationEvidence describing the exact
    loader arithmetic and the bytes it is allowed to explain. An unmodelled
    entry yields an UnknownRelocationEvidence against its own slot only; it
    never silences a whole section. ABSOLUTE entries are table padding.

    Returns (evidence_map, unknown_map, warnings).
    """
    evidence_map = {}
    unknown_map = {}
    warnings = []

    if not hasattr(pe, "DIRECTORY_ENTRY_BASERELOC"):
        return evidence_map, unknown_map, warnings

    def record(ev):
        for rva in range(ev.span[0], ev.span[1]):
            if rva >= len(reference):
                warnings.append(
                    f"relocation at rva {ev.rva:#x} points outside image"
                )
                continue
            evidence_map.setdefault(rva, ev)

    for block in pe.DIRECTORY_ENTRY_BASERELOC:
        entries = block.entries
        idx = 0
        while idx < len(entries):
            entry = entries[idx]
            idx += 1
            rtype = entry.type
            rva = entry.rva

            if rtype == _REL_ABSOLUTE:
                continue

            if rtype == _REL_HIGHADJ:
                # HIGHADJ is a pair: the next entry supplies the low 16 bits
                # of the same 32-bit target and must be consumed here.
                if idx >= len(entries):
                    warnings.append(
                        "dangling IMAGE_REL_BASED_HIGHADJ without companion "
                        f"at rva {rva:#x}"
                    )
                    unknown_map.setdefault(
                        rva,
                        UnknownRelocationEvidence(
                            rtype, rva, 2,
                            "dangling HIGHADJ entry",
                        ),
                    )
                    continue
                companion = entries[idx]
                idx += 1
                if companion.type != _REL_ABSOLUTE:
                    warnings.append(
                        "IMAGE_REL_BASED_HIGHADJ companion at "
                        f"rva {companion.rva:#x} is not ABSOLUTE"
                    )
                old = (_read_signed(reference, rva, 2) << 16) & 0xFFFFFFFF
                adjusted = (old + companion.rva + delta) & 0xFFFFFFFF
                record(
                    RelocationEvidence(
                        rtype,
                        _reloc_type_name(rtype),
                        rva,
                        2,
                        old,
                        adjusted,
                        delta,
                        paired_low_rva=companion.rva,
                    )
                )
                continue

            spec = arch["reloc_types"].get(rtype)
            if spec is None:
                # Unknown / architecture-specific type we do not model.
                # Mark the slot undetermined instead of dropping it or
                # ignoring the whole section.
                width = arch["pointer_size"]
                warnings.append(
                    f"unmodelled relocation type {rtype} at rva {rva:#x}; "
                    "slot marked undetermined rather than ignored"
                )
                unknown_map.setdefault(
                    rva,
                    UnknownRelocationEvidence(
                        rtype,
                        rva,
                        width,
                        "relocation type not modelled for this architecture",
                    ),
                )
                continue

            width, kind = spec
            if rva < 0 or rva + width > len(reference):
                warnings.append(
                    f"relocation at rva {rva:#x} (type {rtype}) overruns image"
                )
                unknown_map.setdefault(
                    rva,
                    UnknownRelocationEvidence(
                        rtype,
                        rva,
                        width,
                        "relocation target outside mapped image",
                    ),
                )
                continue

            old = _read_unsigned(reference, rva, width)
            if kind == "high16":
                new_value = (old + (delta >> 16)) & 0xFFFF
            elif kind == "low16":
                new_value = (old + delta) & 0xFFFF
            elif kind == "absolute32":
                new_value = (old + delta) & 0xFFFFFFFF
            else:  # absolute64
                new_value = (old + delta) & 0xFFFFFFFFFFFFFFFF

            record(
                RelocationEvidence(
                    rtype,
                    _reloc_type_name(rtype),
                    rva,
                    width,
                    old,
                    new_value,
                    delta,
                )
            )

    return evidence_map, unknown_map, warnings


# ---------------------------------------------------------------------------
# Loader transform #2: import binding (IAT / ILT overwrite)
# ---------------------------------------------------------------------------


def _walk_thunk_table(pe, reference, table_rva, width, ordinal_flag):
    """Yield (slot_rva, disk_value, by_ordinal) for one thunk table."""
    rva = table_rva
    while rva is not None and rva >= 0 and rva + width <= len(reference):
        value = int.from_bytes(reference[rva:rva + width], "little")
        if value == 0:
            return
        yield rva, value, bool(value & ordinal_flag)
        rva += width


def _symbol_label(pe, value, ordinal_flag, width):
    if value & ordinal_flag:
        return f"ordinal {value & 0xFFFF}"
    name_rva = value & ((1 << (8 * width)) - 1)
    name_rva &= ~0x1
    try:
        raw = pe.get_data(name_rva + 2, 64)
        name = raw.split(b"\x00", 1)[0]
        return name.decode("ascii", errors="replace")
    except pefile.PEFormatError:
        return "<unreadable import name>"


def build_iat_evidence(pe, reference, arch, include_ilt):
    """Collect loader-owned IAT (and optionally ILT) slot evidence.

    The loader overwrites every IAT slot with a resolved address. The ILT is
    normally left intact, but bound imports resolve it too, so it is only
    treated as loader-owned when include_ilt is set.
    """
    records = []
    warnings = []
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return records, warnings

    width = arch["pointer_size"]
    ordinal_flag = arch["ordinal_flag"]

    for descriptor in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = bytes(descriptor.dll or b"<unknown dll>").decode(
            "ascii", errors="replace"
        )
        struct = descriptor.struct

        if struct.FirstThunk:
            for slot_rva, disk_value, by_ordinal in _walk_thunk_table(
                pe, reference, struct.FirstThunk, width, ordinal_flag
            ):
                symbol = _symbol_label(pe, disk_value, ordinal_flag, width)
                records.append(
                    (
                        slot_rva,
                        width,
                        IATBindingEvidence(
                            slot_rva,
                            width,
                            "IAT",
                            dll_name,
                            symbol,
                            disk_value,
                        ),
                    )
                )

        if include_ilt and struct.OriginalFirstThunk:
            for slot_rva, disk_value, by_ordinal in _walk_thunk_table(
                pe,
                reference,
                struct.OriginalFirstThunk,
                width,
                ordinal_flag,
            ):
                symbol = _symbol_label(pe, disk_value, ordinal_flag, width)
                records.append(
                    (
                        slot_rva,
                        width,
                        IATBindingEvidence(
                            slot_rva,
                            width,
                            "ILT",
                            dll_name,
                            symbol,
                            disk_value,
                        ),
                    )
                )

    return records, warnings


# ---------------------------------------------------------------------------
# Comparison report
# ---------------------------------------------------------------------------


class ComparisonReport:
    """Byte-level verdicts, evidence, conflicts and undetermined ranges."""

    def __init__(self):
        self.verdicts = {}
        self.evidence = {}
        self.differences = []
        self.conflicts = []
        self.warnings = []
        self.out_of_image_bytes = {}
        self.architecture = None
        self.image_size = 0
        self.page_size = 0
        self.expected_load_base = 0
        self.actual_load_base = 0
        self.load_delta = 0

    def add_evidence(self, rva, evidence):
        self.evidence.setdefault(rva, []).append(evidence)

    def ranges(self, verdict):
        points = sorted(r for r, v in self.verdicts.items() if v == verdict)
        return _merge_points(points)

    @property
    def suspect_ranges(self):
        merged = list(self.ranges(VERDICT_SUSPECT))
        merged.extend(self.ranges(VERDICT_SUSPECT_OUT_OF_IMAGE))
        return _merge_ranges(merged)

    @property
    def explained_ranges(self):
        merged = list(self.ranges(VERDICT_EXPLAINED_RELOCATION))
        merged.extend(self.ranges(VERDICT_EXPLAINED_IAT))
        return _merge_ranges(merged)

    @property
    def undetermined_ranges(self):
        merged = list(self.ranges(VERDICT_UNDETERMINED_MISSING_PAGE))
        merged.extend(self.ranges(VERDICT_UNDETERMINED_UNKNOWN_RELOC))
        merged.extend(self.ranges(VERDICT_UNDETERMINED))
        return _merge_ranges(merged)

    @property
    def missing_page_ranges(self):
        return self.ranges(VERDICT_UNDETERMINED_MISSING_PAGE)

    @property
    def unknown_reloc_ranges(self):
        return self.ranges(VERDICT_UNDETERMINED_UNKNOWN_RELOC)

    def summary(self):
        return {
            "architecture": self.architecture,
            "image_size": self.image_size,
            "page_size": self.page_size,
            "expected_load_base": self.expected_load_base,
            "actual_load_base": self.actual_load_base,
            "load_delta": self.load_delta,
            "suspect": self.suspect_ranges,
            "explained": self.explained_ranges,
            "undetermined": self.undetermined_ranges,
            "missing_pages": self.missing_page_ranges,
            "unknown_relocations": self.unknown_reloc_ranges,
            "conflicts": [
                {"rva": c.rva, "evidences": [repr(e) for e in c.evidences]}
                for c in self.conflicts
            ],
            "warnings": list(self.warnings),
        }


# ---------------------------------------------------------------------------
# Comparator
# ---------------------------------------------------------------------------


class MemoryImageComparator:
    """Compare the on-disk image against a sparse loaded image.

    Single use: build once per comparison and read the ComparisonReport.
    The supplied pefile.PE is never mutated.
    """

    def __init__(
        self,
        pe,
        fragments,
        actual_load_base,
        page_size=0x1000,
        include_ilt=True,
    ):
        machine = pe.FILE_HEADER.Machine
        arch = _ARCHITECTURES.get(machine)
        if arch is None:
            raise UnsupportedArchitecture(
                "no loader-transform model for machine "
                f"{pefile.MACHINE_TYPE.get(machine, hex(machine))}"
            )
        if page_size <= 0:
            raise ValueError("page_size must be positive")

        self.pe = pe
        self.arch = arch
        self.page_size = int(page_size)
        self.actual_load_base = int(actual_load_base)
        self.include_ilt = bool(include_ilt)
        self.view = MemoryImageView(fragments)
        self.reference = build_reference_image(pe)
        self.report = ComparisonReport()

        preferred = pe.OPTIONAL_HEADER.ImageBase
        self.delta = self.actual_load_base - preferred
        self._evidence = {}

    def _record(self, start_rva, size, evidence):
        for rva in range(start_rva, start_rva + size):
            self._evidence.setdefault(rva, []).append(evidence)

    def run(self):
        self._collect_relocation_evidence()
        self._collect_iat_evidence()
        self._classify_bytes()
        report = self.report
        report.architecture = self.arch["name"]
        report.image_size = len(self.reference)
        report.page_size = self.page_size
        report.expected_load_base = self.pe.OPTIONAL_HEADER.ImageBase
        report.actual_load_base = self.actual_load_base
        report.load_delta = self.delta
        return report

    def _collect_relocation_evidence(self):
        reloc_map, unknown_map, warnings = build_relocation_evidence(
            self.pe, self.reference, self.delta, self.arch
        )
        self.report.warnings.extend(warnings)
        for rva, evidence in reloc_map.items():
            self._record(rva, 1, evidence)
        for rva, evidence in unknown_map.items():
            start, end = evidence.span
            for slot in range(max(0, start), min(end, len(self.reference))):
                self._record(slot, 1, evidence)

    def _collect_iat_evidence(self):
        records, warnings = build_iat_evidence(
            self.pe, self.reference, self.arch, self.include_ilt
        )
        self.report.warnings.extend(warnings)
        for slot_rva, width, evidence in records:
            self._record(slot_rva, width, evidence)

    def _classify_bytes(self):
        report = self.report
        image_size = len(self.reference)
        present_pages = self.view.present_pages(self.page_size)

        # 1. Missing pages first: never zero-fill, never call it tampering.
        for rva in range(image_size):
            if (rva // self.page_size) not in present_pages:
                report.verdicts[rva] = VERDICT_UNDETERMINED_MISSING_PAGE

        # 2. Observed bytes outside the mapped image.
        for rva in sorted(self.view.covered_rvas()):
            if rva >= image_size:
                report.out_of_image_bytes[rva] = self.view.read(rva)
                report.verdicts[rva] = VERDICT_SUSPECT_OUT_OF_IMAGE

        # 3. Compare every observed byte that belongs to the image.
        for rva in sorted(self.view.covered_rvas()):
            if rva >= image_size:
                continue
            mem_value = self.view.read(rva)
            disk_value = self.reference[rva]
            if mem_value == disk_value:
                continue
            self._classify_difference(rva, disk_value, mem_value)

        # 3b. An unsupported relocation type makes its whole slot
        # undeterminable even when the captured bytes happen to match: we
        # cannot model the transform, so we never claim the byte is clean.
        for rva, evidences in self._evidence.items():
            if rva in report.verdicts or rva >= image_size:
                continue
            unknown = [
                e for e in evidences
                if isinstance(e, UnknownRelocationEvidence)
            ]
            if unknown:
                for evidence in self._distinct(unknown):
                    report.add_evidence(rva, evidence)
                report.verdicts[rva] = VERDICT_UNDETERMINED_UNKNOWN_RELOC

        # 4. Keep evidence on equal/no-diff bytes too (e.g. no-op reloc).
        for rva, evidences in self._evidence.items():
            if rva in report.verdicts or rva >= image_size:
                continue
            for evidence in self._distinct(evidences):
                report.add_evidence(rva, evidence)

        # 5. Distinct overlapping explanations on one byte are conflicts.
        for rva, evidences in self._evidence.items():
            distinct = self._distinct(evidences)
            if len({self._evidence_key(e) for e in distinct}) > 1:
                report.conflicts.append(ExplanationConflict(rva, distinct))

    @staticmethod
    def _evidence_key(evidence):
        if isinstance(evidence, IATBindingEvidence):
            return ("iat", evidence.table, evidence.rva)
        if isinstance(evidence, UnknownRelocationEvidence):
            return ("unknown_reloc", evidence.rva, evidence.reloc_type)
        return ("reloc", evidence.rva, evidence.reloc_type)

    def _distinct(self, evidences):
        distinct = []
        seen = set()
        for evidence in evidences:
            key = self._evidence_key(evidence)
            if key in seen:
                continue
            seen.add(key)
            distinct.append(evidence)
        return distinct

    def _classify_difference(self, rva, disk_value, mem_value):
        report = self.report
        evidences = self._distinct(self._evidence.get(rva, []))
        for evidence in evidences:
            report.add_evidence(rva, evidence)

        unknown = [e for e in evidences
                   if isinstance(e, UnknownRelocationEvidence)]
        relocs = [e for e in evidences
                  if isinstance(e, RelocationEvidence)]
        iats = [e for e in evidences
                if isinstance(e, IATBindingEvidence)]

        if unknown:
            # Unsupported reloc type: undeterminable, never clean nor ignored.
            report.verdicts[rva] = VERDICT_UNDETERMINED_UNKNOWN_RELOC
            report.differences.append(
                ByteDifference(
                    rva, disk_value, mem_value,
                    VERDICT_UNDETERMINED_UNKNOWN_RELOC, unknown,
                )
            )
            return

        if relocs and iats:
            # Two different loader mechanisms claim the same byte: conflict.
            report.conflicts.append(ExplanationConflict(rva, relocs + iats))
            report.verdicts[rva] = VERDICT_CONFLICT
            report.differences.append(
                ByteDifference(
                    rva, disk_value, mem_value,
                    VERDICT_CONFLICT, relocs + iats,
                )
            )
            return

        if relocs:
            report.verdicts[rva] = VERDICT_EXPLAINED_RELOCATION
            report.differences.append(
                ByteDifference(
                    rva, disk_value, mem_value,
                    VERDICT_EXPLAINED_RELOCATION, relocs,
                )
            )
            return

        if iats:
            report.verdicts[rva] = VERDICT_EXPLAINED_IAT
            report.differences.append(
                ByteDifference(
                    rva, disk_value, mem_value,
                    VERDICT_EXPLAINED_IAT, iats,
                )
            )
            return

        # No loader transformation covers this byte: a real suspect byte.
        report.verdicts[rva] = VERDICT_SUSPECT
        report.differences.append(
            ByteDifference(
                rva, disk_value, mem_value, VERDICT_SUSPECT, []
            )
        )


def compare_pe_memory(
    pe,
    fragments,
    actual_load_base,
    page_size=0x1000,
    include_ilt=True,
):
    """Compare a parsed on-disk PE with a sparse captured memory image.

    Args:
        pe: A pefile.PE parsed from the disk file. It is never mutated.
        fragments: Iterable of MemoryFragment covering the captured pages.
        actual_load_base: Image base the OS loader used in the process.
        page_size: Loader page size (normally 0x1000). Image pages without a
            fragment are reported undeterminable, never as tampering.
        include_ilt: Whether the Import Lookup Table is loader-owned.

    Returns:
        ComparisonReport with byte-level verdicts, evidence, conflicts and
        undeterminable ranges.
    """
    comparator = MemoryImageComparator(
        pe,
        fragments,
        actual_load_base,
        page_size=page_size,
        include_ilt=include_ilt,
    )
    return comparator.run()
