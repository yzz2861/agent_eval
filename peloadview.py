"""Explicit PE loading-strategy views.

Additive companion to :mod:pefile. It never mutates pefile lenient default
parsing; instead it re-derives, from raw on-disk bytes, an explicit
multi-valued mapping between three byte sources:

* on-disk file ranges (PointerToRawData / SizeOfRawData),
* zero-filled BSS ranges (the part of Misc.VirtualSize beyond raw data),
* virtual addresses (RVA ranges produced by VirtualAddress).

Two documented loading strategies are materialised and compared.

file_backed
    Flat-file strategy, mirroring PE.get_data: an RVA is translated via the
    first section whose RVA range contains it, and the backing file offset is
    read directly. Overlapping sections make this ambiguous; pefile keeps only
    the first hit, while every candidate is retained.

memory_mapped
    OS-loader strategy, mirroring PE.get_memory_mapped_image: headers, then
    sections, are laid out at their RVAs; raw bytes are clamped to
    Misc.VirtualSize and the BSS tail is zero filled. Later sections
    overwrite earlier bytes at the same RVA.

Anything outside the documented PE/COFF alignment rules is not guessed: the
affected RVA resolves to RVAStatus.UNKNOWN.
"""

import struct

MIN_FILE_ALIGNMENT = 0x200
MAX_FILE_ALIGNMENT = 0x10000
PAGE_SIZE = 0x1000

IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_SHARED = 0x10000000
IMAGE_SCN_MEM_DISCARDABLE = 0x02000000

IMAGE_DIRECTORY_ENTRY_EXPORT = 0

DOS_MAGIC = b"MZ"
PE_SIGNATURE = b"PE\x00\x00"
PE32_MAGIC = 0x10B
PE32_PLUS_MAGIC = 0x20B


class RVAStatus:
    """Resolution status for an RVA under one loading strategy."""

    RESOLVED = "resolved"
    ZERO_FILL = "zero_fill"
    AMBIGUOUS = "ambiguous"
    TRUNCATED = "truncated"
    UNKNOWN = "unknown"


class LoadViewError(ValueError):
    """Raised when the bytes do not form a parseable PE image."""


def is_power_of_two(value):
    return value > 0 and (value & (value - 1)) == 0


def validate_alignments(file_alignment, section_alignment, size_of_headers, sections):
    """Validate the documented PE/COFF alignment rules.

    Returns a list of reasons; an empty list means every modelled rule is
    satisfied. A non-empty list means affected RVAs must be reported as
    RVAStatus.UNKNOWN rather than guessed.
    """

    reasons = []

    if not MIN_FILE_ALIGNMENT <= file_alignment <= MAX_FILE_ALIGNMENT:
        reasons.append(
            "FileAlignment must be a power of two between 0x200 and 0x10000 "
            f"inclusive; got {file_alignment:#x}"
        )
    elif not is_power_of_two(file_alignment):
        reasons.append(f"FileAlignment {file_alignment:#x} is not a power of two")

    if section_alignment < PAGE_SIZE:
        if section_alignment != file_alignment:
            reasons.append(
                "When SectionAlignment < 0x1000 it must equal FileAlignment "
                f"(SectionAlignment={section_alignment:#x}, "
                f"FileAlignment={file_alignment:#x})"
            )
    elif section_alignment < file_alignment:
        reasons.append(
            "SectionAlignment must be >= FileAlignment "
            f"(SectionAlignment={section_alignment:#x}, "
            f"FileAlignment={file_alignment:#x})"
        )

    if not is_power_of_two(section_alignment):
        reasons.append(
            f"SectionAlignment {section_alignment:#x} is not a power of two"
        )

    if size_of_headers % file_alignment != 0:
        reasons.append(
            "SizeOfHeaders must be a multiple of FileAlignment "
            f"(SizeOfHeaders={size_of_headers:#x}, "
            f"FileAlignment={file_alignment:#x})"
        )

    for index, section in enumerate(sections):
        label = section.name or f"section#{index}"
        if section.pointer_to_raw_data != 0 and (
            section.pointer_to_raw_data % file_alignment != 0
        ):
            reasons.append(
                f"Section {label!r}: PointerToRawData "
                f"{section.pointer_to_raw_data:#x} is not a multiple of "
                f"FileAlignment {file_alignment:#x}"
            )
        if (
            section_alignment >= PAGE_SIZE
            and section.virtual_address % section_alignment != 0
        ):
            reasons.append(
                f"Section {label!r}: VirtualAddress "
                f"{section.virtual_address:#x} is not a multiple of "
                f"SectionAlignment {section_alignment:#x}"
            )

    return reasons


class SectionInfo:
    """Normalised view of one IMAGE_SECTION_HEADER and its derived ranges."""

    def __init__(self, index, name, virtual_address, virtual_size,
                 pointer_to_raw_data, size_of_raw_data, characteristics):
        self.index = index
        self.name = name
        self.virtual_address = virtual_address
        self.virtual_size = virtual_size
        self.pointer_to_raw_data = pointer_to_raw_data
        self.size_of_raw_data = size_of_raw_data
        self.characteristics = characteristics

    @property
    def virtual_end(self):
        return self.virtual_address + self.virtual_size

    @property
    def raw_end(self):
        return self.pointer_to_raw_data + self.size_of_raw_data

    @property
    def is_bss_only(self):
        return self.pointer_to_raw_data == 0 and self.size_of_raw_data == 0

    @property
    def executable(self):
        return bool(self.characteristics & IMAGE_SCN_MEM_EXECUTE)

    @property
    def shared(self):
        return bool(self.characteristics & IMAGE_SCN_MEM_SHARED)

    def __repr__(self):
        return (
            f"SectionInfo({self.name!r}, rva={self.virtual_address:#x}+"
            f"{self.virtual_size:#x}, raw={self.pointer_to_raw_data:#x}+"
            f"{self.size_of_raw_data:#x})"
        )


class ByteSource:
    """One reproducible origin for the byte(s) at an RVA.

    kind is one of:
      "section_raw"  - byte read from an on-disk section range,
      "header"       - byte read from the mapped PE headers,
      "zero_fill"    - BSS byte with no on-disk backing (loader writes 0),
      "truncated"    - header claims raw bytes but the file ends early.
    """

    def __init__(self, kind, byte_value=None, file_offset=None,
                 section=None, rva=None, length=1):
        self.kind = kind
        self.byte_value = byte_value
        self.file_offset = file_offset
        self.section = section
        self.rva = rva
        self.length = length

    def __repr__(self):
        if self.kind == "zero_fill":
            return f"ByteSource(zero_fill rva={self.rva:#x})"
        if self.kind == "truncated":
            return f"ByteSource(truncated rva={self.rva:#x})"
        return (
            f"ByteSource({self.kind} section={self.section.name!r} "
            f"rva={self.rva:#x} file_offset={self.file_offset:#x} "
            f"byte={self.byte_value:#04x})"
        )


class RVAResolution:
    """Result of resolving an RVA under one strategy.

    status is a RVAStatus value. sources lists every ByteSource candidate
    (multiple only for the ambiguous file_backed strategy). value is the
    single byte the documented strategy actually yields, or None when the
    status is TRUNCATED or UNKNOWN.
    """

    def __init__(self, rva, status, sources, value=None):
        self.rva = rva
        self.status = status
        self.sources = sources
        self.value = value

    def __repr__(self):
        value = "None" if self.value is None else f"{self.value:#04x}"
        return (
            f"RVAResolution(rva={self.rva:#x}, status={self.status}, "
            f"value={value}, sources={len(self.sources)})"
        )


class AlignmentInfo:
    """Outcome of validating the documented alignment rules."""

    def __init__(self, supported, reasons):
        self.supported = supported
        self.reasons = reasons

    def __repr__(self):
        state = "supported" if self.supported else "unsupported"
        return f"AlignmentInfo({state}, reasons={self.reasons!r})"


def _read_struct(data, fmt, offset):
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data):
        raise LoadViewError(
            f"structure of {size} bytes at offset {offset:#x} exceeds file "
            f"of {len(data):#x} bytes"
        )
    return struct.unpack_from(fmt, data, offset)


class LoadedPE:
    """Lightweight, strict-enough PE parse used to build the two views.

    Only the fields needed to model RVA byte provenance are decoded. The raw
    bytes are kept so every reported value can be recomputed.
    """

    def __init__(self, data):
        if isinstance(data, bytearray):
            data = bytes(data)
        if not isinstance(data, bytes):
            raise LoadViewError("data must be bytes or bytearray")
        self.data = data
        self._parse()

    def _parse(self):
        data = self.data
        if len(data) < 0x40 or data[:2] != DOS_MAGIC:
            raise LoadViewError("missing MZ signature")
        (e_lfanew,) = _read_struct(data, "<I", 0x3C)
        if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != PE_SIGNATURE:
            raise LoadViewError("missing PE signature")

        coff = e_lfanew + 4
        (
            self.machine,
            number_of_sections,
            self.time_date_stamp,
            _pointer_to_symbol_table,
            _number_of_symbols,
            size_of_optional_header,
            self.characteristics,
        ) = _read_struct(data, "<HHIIIHH", coff)

        optional_offset = coff + 20
        if size_of_optional_header < 2:
            raise LoadViewError("missing optional header")
        (magic,) = _read_struct(data, "<H", optional_offset)
        if magic == PE32_MAGIC:
            self.is_64 = False
        elif magic == PE32_PLUS_MAGIC:
            self.is_64 = True
        else:
            raise LoadViewError(f"unknown optional header magic {magic:#x}")

        self._parse_optional_header(optional_offset)
        self._parse_sections(
            optional_offset + size_of_optional_header, number_of_sections
        )

        self.alignment = AlignmentInfo(
            supported=not self.alignment_reasons,
            reasons=self.alignment_reasons,
        )

    def _parse_optional_header(self, offset):
        data = self.data
        # Windows-specific fields start at offset 28 (PE32) or 24 (PE32+).
        if not self.is_64:
            windows_offset = offset + 28
            image_base_fmt = "<I"
            image_base_size = 4
        else:
            windows_offset = offset + 24
            image_base_fmt = "<Q"
            image_base_size = 8

        # The Windows-specific fields start right after ImageBase, whose size
        # differs between PE32 (4 bytes) and PE32+ (8 bytes). SectionAlignment
        # and FileAlignment follow immediately.
        alignment_offset = windows_offset + (8 if self.is_64 else 4)
        (
            self.section_alignment,
            self.file_alignment,
        ) = _read_struct(data, "<II", alignment_offset)
        # SizeOfImage / SizeOfHeaders / CheckSum sit at Windows-specific
        # offset 28 (PE32) or 32 (PE32+); the gap is the wider PE32+ ImageBase.
        size_offset = windows_offset + (32 if self.is_64 else 28)
        (
            self.size_of_image,
            self.size_of_headers,
            self.checksum,
        ) = _read_struct(data, "<III", size_offset)
        (self.image_base,) = _read_struct(
            data, image_base_fmt, windows_offset
        )
        self.image_base_size = image_base_size

        if not self.is_64:
            entry_rva_offset = offset + 16
        else:
            entry_rva_offset = offset + 16
        (self.address_of_entry_point,) = _read_struct(
            data, "<I", entry_rva_offset
        )

        # NumberOfRvaAndSizes is at optional-header offset 92 (PE32) or 108
        # (PE32+), i.e. Windows-specific offset 64 or 84; the directory
        # entries start on the next byte.
        if not self.is_64:
            count_offset = windows_offset + 64
        else:
            count_offset = windows_offset + 84
        (self.number_of_rva_and_sizes,) = _read_struct(
            data, "<I", count_offset
        )
        self.data_directories = {}
        entry_offset = count_offset + 4
        for index in range(self.number_of_rva_and_sizes):
            entry_pos = entry_offset + index * 8
            if entry_pos + 8 > len(data):
                break
            rva, size = _read_struct(data, "<II", entry_pos)
            self.data_directories[index] = (rva, size)

    def _parse_sections(self, table_offset, number_of_sections):
        self.sections = []
        for index in range(number_of_sections):
            pos = table_offset + index * 40
            raw = _read_struct(data := self.data, "<8sIIIIIIHHI", pos)
            (
                name_bytes,
                virtual_size,
                virtual_address,
                size_of_raw_data,
                pointer_to_raw_data,
                _pointer_relocs,
                _pointer_line,
                _num_relocs,
                _num_line,
                characteristics,
            ) = raw
            name = name_bytes.split(b"\x00", 1)[0]
            self.sections.append(
                SectionInfo(
                    index,
                    name,
                    virtual_address,
                    virtual_size,
                    pointer_to_raw_data,
                    size_of_raw_data,
                    characteristics,
                )
            )

        self.alignment_reasons = validate_alignments(
            self.file_alignment,
            self.section_alignment,
            self.size_of_headers,
            self.sections,
        )

    def directory(self, index):
        return self.data_directories.get(index, (0, 0))


class LoadingView:
    """Base class holding the multi-valued RVA -> source mapping."""

    strategy = None

    def __init__(self, loaded_pe):
        self.pe = loaded_pe
        self.data = loaded_pe.data
        self.header_size = min(loaded_pe.size_of_headers, len(self.data))

    def _header_source(self, rva):
        if 0 <= rva < self.header_size:
            return ByteSource(
                kind="header",
                byte_value=self.data[rva],
                file_offset=rva,
                rva=rva,
            )
        return None

    def _section_raw_span(self, section):
        """Return (raw_file_start, raw_file_end) actually present on disk."""

        if section.is_bss_only:
            return None
        start = section.pointer_to_raw_data
        end = min(section.raw_end, len(self.data))
        if start >= len(self.data):
            return (start, start)
        return (start, max(start, end))

    def resolve(self, rva, length=1):
        raise NotImplementedError

    def read(self, rva, length):
        """Resolve each byte and return (status, bytes).

        The aggregate status is the most severe encountered: UNKNOWN beats
        TRUNCATED beats AMBIGUOUS beats ZERO_FILL beats RESOLVED.
        """

        order = [
            RVAStatus.RESOLVED,
            RVAStatus.ZERO_FILL,
            RVAStatus.AMBIGUOUS,
            RVAStatus.TRUNCATED,
            RVAStatus.UNKNOWN,
        ]
        severity = {name: rank for rank, name in enumerate(order)}
        resolutions = [self.resolve(rva + offset) for offset in range(length)]
        worst = max(
            (res.status for res in resolutions),
            key=lambda name: severity[name],
        )
        if worst in (RVAStatus.UNKNOWN, RVAStatus.TRUNCATED):
            return worst, None
        output = bytes(
            b if (b := res.value) is not None else 0 for res in resolutions
        )
        return worst, output


class FileBackedView(LoadingView):
    """Flat-file strategy (PE.get_data semantics, all candidates retained)."""

    strategy = "file_backed"

    def _candidate_sources(self, rva):
        """Enumerate every section that claims this RVA."""

        sources = []
        for section in self.pe.sections:
            if not (section.virtual_address <= rva < section.virtual_end):
                continue
            if section.is_bss_only:
                sources.append(
                    ByteSource(kind="zero_fill", rva=rva, section=section)
                )
                continue
            file_offset = (
                rva - section.virtual_address + section.pointer_to_raw_data
            )
            if file_offset < len(self.data):
                sources.append(
                    ByteSource(
                        kind="section_raw",
                        byte_value=self.data[file_offset],
                        file_offset=file_offset,
                        section=section,
                        rva=rva,
                    )
                )
            else:
                sources.append(
                    ByteSource(
                        kind="truncated",
                        file_offset=file_offset,
                        section=section,
                        rva=rva,
                    )
                )
        return sources

    def resolve(self, rva, length=1):
        if length != 1:
            raise ValueError("resolve() handles a single byte; use read()")
        if not self.pe.alignment.supported:
            return RVAResolution(rva, RVAStatus.UNKNOWN, [])

        sources = self._candidate_sources(rva)
        if not sources:
            header_source = self._header_source(rva)
            if header_source is not None:
                return RVAResolution(
                    rva, RVAStatus.RESOLVED, [header_source],
                    value=header_source.byte_value,
                )
            return RVAResolution(rva, RVAStatus.UNKNOWN, [])

        if any(source.kind == "truncated" for source in sources):
            return RVAResolution(rva, RVAStatus.TRUNCATED, sources)

        raw_sources = [s for s in sources if s.kind == "section_raw"]
        zero_sources = [s for s in sources if s.kind == "zero_fill"]

        if len(raw_sources) > 1:
            distinct = {source.byte_value for source in raw_sources}
            if len(distinct) > 1:
                return RVAResolution(rva, RVAStatus.AMBIGUOUS, sources)

        if raw_sources:
            if zero_sources:
                return RVAResolution(
                    rva, RVAStatus.AMBIGUOUS,
                    raw_sources + zero_sources,
                )
            chosen = raw_sources[0]
            status = (
                RVAStatus.AMBIGUOUS if len(raw_sources) > 1
                else RVAStatus.RESOLVED
            )
            return RVAResolution(
                rva, status, sources, value=chosen.byte_value
            )

        return RVAResolution(rva, RVAStatus.ZERO_FILL, sources, value=0)


class MemoryMappedView(LoadingView):
    """OS-loader strategy (PE.get_memory_mapped_image semantics)."""

    strategy = "memory_mapped"

    def __init__(self, loaded_pe):
        super().__init__(loaded_pe)
        self.image_size = loaded_pe.size_of_image
        self.overwritten_rvas = []
        self._build_image()

    def _build_image(self):
        # Pre-size to SizeOfImage; every byte is tracked with its source.
        self.image = bytearray(self.image_size)
        self.provenance = [None] * self.image_size
        self._status = [RVAStatus.RESOLVED] * self.image_size

        if not self.pe.alignment.supported:
            for rva in range(self.image_size):
                self._status[rva] = RVAStatus.UNKNOWN
            return

        # Headers occupy RVA [0, SizeOfHeaders).
        for rva in range(self.header_size):
            self.image[rva] = self.data[rva]
            self.provenance[rva] = ByteSource(
                kind="header",
                byte_value=self.data[rva],
                file_offset=rva,
                rva=rva,
            )

        for section in self.pe.sections:
            self._place_section(section)

    def _place_section(self, section):
        raw_length = 0 if section.is_bss_only else section.size_of_raw_data
        virtual_length = section.virtual_size

        for offset in range(virtual_length):
            rva = section.virtual_address + offset
            if rva >= self.image_size:
                break

            if self.provenance[rva] is not None:
                self.overwritten_rvas.append(rva)

            if offset < raw_length:
                file_offset = section.pointer_to_raw_data + offset
                if file_offset < len(self.data):
                    self.image[rva] = self.data[file_offset]
                    self.provenance[rva] = ByteSource(
                        kind="section_raw",
                        byte_value=self.data[file_offset],
                        file_offset=file_offset,
                        section=section,
                        rva=rva,
                    )
                    self._status[rva] = RVAStatus.RESOLVED
                else:
                    self.image[rva] = 0
                    self.provenance[rva] = ByteSource(
                        kind="truncated",
                        file_offset=file_offset,
                        section=section,
                        rva=rva,
                    )
                    self._status[rva] = RVAStatus.TRUNCATED
            else:
                self.image[rva] = 0
                self.provenance[rva] = ByteSource(
                    kind="zero_fill",
                    section=section,
                    rva=rva,
                )
                self._status[rva] = RVAStatus.ZERO_FILL

    def resolve(self, rva, length=1):
        if length != 1:
            raise ValueError("resolve() handles a single byte; use read()")
        if not self.pe.alignment.supported:
            return RVAResolution(rva, RVAStatus.UNKNOWN, [])
        if rva < 0 or rva >= self.image_size:
            return RVAResolution(rva, RVAStatus.UNKNOWN, [])
        source = self.provenance[rva]
        sources = [] if source is None else [source]
        status = self._status[rva]
        if status in (RVAStatus.TRUNCATED, RVAStatus.UNKNOWN):
            return RVAResolution(rva, status, sources)
        return RVAResolution(
            rva, status, sources, value=self.image[rva]
        )

    def overlaps(self):
        """Return RVAs where a later section overwrote an earlier mapping."""

        return list(self.overwritten_rvas)


def _intersect(start_a, end_a, start_b, end_b):
    start = max(start_a, start_b)
    end = min(end_a, end_b)
    return (start, end) if start < end else None


class LoadImage:
    """Both loading strategies for one PE, plus cross-view conflict data."""

    def __init__(self, data):
        self.pe = LoadedPE(data)
        self.file_backed = FileBackedView(self.pe)
        self.memory_mapped = MemoryMappedView(self.pe)

    @property
    def data(self):
        return self.pe.data

    @property
    def alignment(self):
        return self.pe.alignment

    def section_rva_overlaps(self):
        """Return RVA ranges claimed by more than one section.

        Each item is (rva_start, rva_end, [sections]) and is independent of
        the loading strategy, so the ambiguity is preserved even where the
        bytes happen to be equal.
        """

        results = []
        sections = self.pe.sections
        for index, left in enumerate(sections):
            for right in sections[index + 1 :]:
                overlap = _intersect(
                    left.virtual_address,
                    left.virtual_end,
                    right.virtual_address,
                    right.virtual_end,
                )
                if overlap is not None:
                    results.append((overlap[0], overlap[1], [left, right]))
        return results

    def shared_ranges(self):
        """Ranges backed by IMAGE_SCN_MEM_SHARED sections."""

        return [
            (section.virtual_address, section.virtual_end, section)
            for section in self.pe.sections
            if section.shared
        ]

    def executable_ranges(self):
        """Ranges backed by executable sections."""

        return [
            (section.virtual_address, section.virtual_end, section)
            for section in self.pe.sections
            if section.executable
        ]


def compare_byte(image, rva):
    """Resolve one RVA in both views and describe the disagreement."""

    file_res = image.file_backed.resolve(rva)
    mem_res = image.memory_mapped.resolve(rva)
    agree = (
        file_res.status not in (RVAStatus.UNKNOWN, RVAStatus.TRUNCATED)
        and mem_res.status not in (RVAStatus.UNKNOWN, RVAStatus.TRUNCATED)
        and file_res.value == mem_res.value
    )
    return {
        "rva": rva,
        "file_backed": file_res,
        "memory_mapped": mem_res,
        "agree": agree,
    }


def report_entry_point(image):
    """Report how the entry-point byte is resolved under each strategy."""

    rva = image.pe.address_of_entry_point
    if rva == 0:
        return {
            "rva": 0,
            "present": False,
            "note": "image has no entry point (AddressOfEntryPoint == 0)",
        }
    comparison = compare_byte(image, rva)
    comparison["present"] = True
    return comparison


def _parse_exports(image):
    """Minimal export-directory parse using the memory_mapped view."""

    rva, size = image.pe.directory(IMAGE_DIRECTORY_ENTRY_EXPORT)
    if rva == 0:
        return []

    status, header = image.memory_mapped.read(rva, 40)
    if status in (RVAStatus.UNKNOWN, RVAStatus.TRUNCATED) or header is None:
        return [{"error": f"export directory at {rva:#x} is {status}"}]

    (
        _characteristics,
        _time_date_stamp,
        _major,
        _minor,
        _name_rva,
        _base,
        number_of_functions,
        _number_of_names,
        address_of_functions,
        _address_of_names,
        _address_of_name_ordinals,
    ) = struct.unpack("<IIHHIIIIIII", header)

    func_status, func_table = image.memory_mapped.read(
        address_of_functions, number_of_functions * 4
    )
    if func_table is None:
        return [
            {
                "error": (
                    "export AddressOfFunctions table at "
                    f"{address_of_functions:#x} is {func_status}"
                )
            }
        ]

    targets = []
    for index in range(number_of_functions):
        target_rva = struct.unpack_from("<I", func_table, index * 4)[0]
        if target_rva == 0:
            continue
        targets.append(
            {
                "ordinal": index,
                "target_rva": target_rva,
                "forwarded": rva <= target_rva < rva + size,
            }
        )
    return targets


def report_exports(image):
    """Resolve every non-null export target RVA under both strategies."""

    targets = _parse_exports(image)
    if targets and "error" in targets[0]:
        return targets

    report = []
    for target in targets:
        if target["forwarded"]:
            target["resolution"] = None
            target["note"] = "forwarder string RVA, not code"
            report.append(target)
            continue
        target["resolution"] = compare_byte(image, target["target_rva"])
        report.append(target)
    return report


def report_executable_regions(image):
    """Scan executable sections for overlapping / conflicting RVA bytes.

    For each executable RVA the file_backed view is checked for ambiguity and
    both views are compared. Ranges of identical status are merged so the
    output stays compact and reproducible.
    """

    findings = []
    for start, end, section in image.executable_ranges():
        rva = start
        while rva < end:
            comparison = compare_byte(image, rva)
            file_res = comparison["file_backed"]
            ambiguous = file_res.status == RVAStatus.AMBIGUOUS
            truncated = (
                file_res.status == RVAStatus.TRUNCATED
                or comparison["memory_mapped"].status == RVAStatus.TRUNCATED
            )
            unknown = (
                file_res.status == RVAStatus.UNKNOWN
                or comparison["memory_mapped"].status == RVAStatus.UNKNOWN
            )
            if not (ambiguous or truncated or unknown or not comparison["agree"]):
                rva += 1
                continue

            kind = (
                RVAStatus.UNKNOWN if unknown
                else RVAStatus.TRUNCATED if truncated
                else RVAStatus.AMBIGUOUS if ambiguous
                else "cross_view_mismatch"
            )
            run_end = rva + 1
            while run_end < end:
                next_cmp = compare_byte(image, run_end)
                next_file = next_cmp["file_backed"]
                next_kind = (
                    RVAStatus.UNKNOWN
                    if next_file.status == RVAStatus.UNKNOWN
                    or next_cmp["memory_mapped"].status == RVAStatus.UNKNOWN
                    else RVAStatus.TRUNCATED
                    if next_file.status == RVAStatus.TRUNCATED
                    or next_cmp["memory_mapped"].status == RVAStatus.TRUNCATED
                    else RVAStatus.AMBIGUOUS
                    if next_file.status == RVAStatus.AMBIGUOUS
                    else "cross_view_mismatch"
                    if not next_cmp["agree"]
                    else None
                )
                if next_kind != kind:
                    break
                run_end += 1

            findings.append(
                {
                    "section": section.name,
                    "rva_start": rva,
                    "rva_end": run_end,
                    "kind": kind,
                    "first_byte": comparison,
                }
            )
            rva = run_end
    return findings


def build_report(image):
    """Convenience aggregator covering entry point, exports and code."""

    return {
        "alignment_supported": image.alignment.supported,
        "alignment_reasons": image.alignment.reasons,
        "section_rva_overlaps": [
            {
                "rva_start": start,
                "rva_end": end,
                "sections": [section.name for section in sections],
            }
            for start, end, sections in image.section_rva_overlaps()
        ],
        "entry_point": report_entry_point(image),
        "exports": report_exports(image),
        "executable_conflicts": report_executable_regions(image),
        "memory_overwritten_rvas": image.memory_mapped.overlaps(),
    }
