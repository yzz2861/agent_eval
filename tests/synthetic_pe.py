"""
Tiny, fully synthetic PE generator used by the memory-comparison tests.

No Windows, no third-party assembler and no sample files: every byte of these
images is built here from the PE/COFF specification. The images are small
enough that individual RVAs are known up front, which lets the tests assert
exact explained/suspect/undetermined intervals.
"""

import struct

PAGE = 0x1000
FILE_ALIGN = 0x200


def _align(value, alignment):
    return (value + alignment - 1) // alignment * alignment


class SyntheticPE:
    """A minimal PE32/PE32+ image with imports and base relocations.

    The layout is fixed and deliberately tiny:

    * headers (one file-aligned block),
    * .text at RVA 0x1000 holding a relocatable pointer and code bytes,
    * .rdata at RVA 0x2000 holding the import directory, ILT, IAT, hint/name
      blob and the DLL name,
    * .reloc at RVA 0x3000 holding one base-relocation block.
    """

    PREFERRED_BASE = 0x00400000
    TEXT_RVA = 0x1000
    RDATA_RVA = 0x2000
    RELOC_RVA = 0x3000

    def __init__(self, pe32_plus=False):
        self.pe32_plus = pe32_plus
        self.machine = 0x8664 if pe32_plus else 0x14C
        self.pointer_size = 8 if pe32_plus else 4
        self.magic = 0x20B if pe32_plus else 0x10B
        # PE32+ images use a canonical 64-bit preferred base so relocation
        # deltas stay positive and realistic.
        self.PREFERRED_BASE_X64 = 0x0000000140000000
        self.image_base = (
            self.PREFERRED_BASE_X64 if pe32_plus else self.PREFERRED_BASE
        )

        # Fixed RVAs inside .rdata. Each thunk table reserves two full
        # pointer-sized slots (plus the terminator), so fixed 0x20 spacing
        # works for both 32-bit and 64-bit images without overlap.
        self.ilt_rva = self.RDATA_RVA + 0x00
        self.iat_rva = self.RDATA_RVA + 0x20
        self.import_desc_rva = self.RDATA_RVA + 0x40
        self.hint_name_rva = self.RDATA_RVA + 0x80
        self.dll_name_rva = self.RDATA_RVA + 0xC0

        # .text content: a pointer-sized absolute field that gets relocated,
        # followed by ordinary code bytes used for the patch scenario. The
        # section virtual size (and raw data) covers both fields fully.
        self.reloc_target_rva = self.TEXT_RVA + 0x10
        # A separate pointer-sized slot used only by the unknown-relocation
        # scenario; it stays inside the .text page and never overlaps.
        self.unknown_reloc_rva = self.TEXT_RVA + 0x20
        self.code_patch_rva = self.TEXT_RVA + 0x40
        text = bytearray(0x80)
        # Initial value of the relocated field: the preferred image base.
        struct.pack_into(
            "<Q" if pe32_plus else "<I",
            text,
            self.reloc_target_rva - self.TEXT_RVA,
            self.image_base,
        )
        # A recognisable instruction-like pattern used by the patch test.
        text[self.code_patch_rva - self.TEXT_RVA :
             self.code_patch_rva - self.TEXT_RVA + 4] = b"\x90\x90\x90\x90"
        self.text_data = bytes(text)

    @property
    def preferred_base(self):
        return self.image_base

    def _pack_pointer(self, value):
        return struct.pack("<Q" if self.pe32_plus else "<I", value)

    def _build_rdata(self):
        rdata = bytearray(0x200)
        ps = self.pointer_size
        ordinal_flag = 0x8000000000000000 if self.pe32_plus else 0x80000000

        # Hint/name blob: hint=1 then NUL-terminated symbol name.
        hint_name = struct.pack("<H", 1) + b"SyntheticFunction" + b"\x00"
        offset = self.hint_name_rva - self.RDATA_RVA
        rdata[offset:offset + len(hint_name)] = hint_name

        # DLL name.
        dll_name = b"synthetic.dll" + b"\x00"
        offset = self.dll_name_rva - self.RDATA_RVA
        rdata[offset:offset + len(dll_name)] = dll_name

        # ILT and IAT both point at the hint/name entry on disk.
        thunk_value = self.hint_name_rva
        ilt = self._pack_pointer(thunk_value) + self._pack_pointer(0)
        iat = self._pack_pointer(thunk_value) + self._pack_pointer(0)
        rdata[self.ilt_rva - self.RDATA_RVA:
              self.ilt_rva - self.RDATA_RVA + len(ilt)] = ilt
        rdata[self.iat_rva - self.RDATA_RVA:
              self.iat_rva - self.RDATA_RVA + len(iat)] = iat

        # One import descriptor followed by a zeroed terminator.
        desc = struct.pack(
            "<IIIII",
            self.ilt_rva,                # OriginalFirstThunk (ILT)
            0,                           # TimeDateStamp
            0,                           # ForwarderChain
            self.dll_name_rva,           # Name
            self.iat_rva,                # FirstThunk (IAT)
        )
        desc += b"\x00" * 20
        offset = self.import_desc_rva - self.RDATA_RVA
        rdata[offset:offset + len(desc)] = desc

        # Keep the ordinal flag reachable for callers building variants.
        self.ordinal_flag = ordinal_flag
        return bytes(rdata)

    def _build_reloc(self, extra_type=None):
        """Build one .reloc block covering the .text page.

        extra_type optionally injects an unmodelled relocation type so the
        unknown-type path can be exercised without editing real binaries.
        """
        page_rva = self.TEXT_RVA
        target_offset = self.reloc_target_rva - page_rva
        primary_type = 10 if self.pe32_plus else 3  # DIR64 / HIGHLOW
        words = [
            (primary_type << 12) | target_offset,
        ]
        if extra_type is not None:
            unknown_offset = self.unknown_reloc_rva - page_rva
            words.append((extra_type << 12) | unknown_offset)
        # ABSOLUTE padding to keep the block 4-byte aligned.
        while (len(words) + 2) % 2:
            words.append(0)
        block = struct.pack("<II", page_rva, 8 + 2 * len(words))
        block += b"".join(struct.pack("<H", w) for w in words)
        return block


    def build(self, extra_reloc_type=None):
        rdata = self._build_rdata()
        reloc = self._build_reloc(extra_type=extra_reloc_type)

        sections = [
            (b".text\x00\x00\x00", self.text_data, self.TEXT_RVA, 0x60000020),
            (b".rdata\x00\x00", rdata, self.RDATA_RVA, 0x40000040),
            (b".reloc\x00\x00", reloc, self.RELOC_RVA, 0x42000040),
        ]

        optional_header_size = self._optional_header_size()
        # e_lfanew (0x40) + PE signature (4) + COFF header (20) then the
        # optional header; the section table follows immediately.
        section_table_offset = 0x40 + 4 + 20 + optional_header_size
        section_table_size = 40 * len(sections)
        size_of_headers = _align(
            section_table_offset + section_table_size, FILE_ALIGN
        )
        image_size = _align(self.RELOC_RVA + PAGE, PAGE)

        headers = self._build_headers(
            sections,
            size_of_headers,
            optional_header_size,
            image_size,
            len(reloc),
        )

        blob = bytearray(headers)
        # Section raw data starts at the first file-aligned slot after headers.
        raw_offset = size_of_headers
        section_records = []
        for name, data, rva, characteristics in sections:
            raw_size = _align(len(data), FILE_ALIGN)
            section_records.append(
                (name, data, rva, raw_offset, raw_size, characteristics)
            )
            raw_offset += raw_size

        # Patch section table now that raw offsets/sizes are known.
        table = bytearray()
        for name, data, rva, raw_off, raw_size, characteristics in section_records:
            table += self._section_header(
                name, len(data), rva, raw_size, raw_off, characteristics
            )
        blob[section_table_offset:section_table_offset + len(table)] = table

        for name, data, rva, raw_off, raw_size, characteristics in section_records:
            if len(blob) < raw_off:
                blob += b"\x00" * (raw_off - len(blob))
            blob += data
            blob += b"\x00" * (raw_size - len(data))

        return bytes(blob)

    def _optional_header_size(self):
        # Fixed fields (PE32: 96, PE32+: 120) plus 16 data directories.
        if self.pe32_plus:
            return 120 + 16 * 8
        return 96 + 16 * 8

    def _build_headers(
        self,
        sections,
        size_of_headers,
        optional_header_size,
        image_size,
        reloc_size,
    ):
        # DOS header: minimal, with e_lfanew pointing at the PE signature.
        dos = bytearray(0x40)
        dos[0:2] = b"MZ"
        e_lfanew = 0x40
        struct.pack_into("<I", dos, 0x3C, e_lfanew)

        num_sections = len(sections)
        file_header = struct.pack(
            "<HHIIIHH",
            self.machine,
            num_sections,
            0,                  # TimeDateStamp
            0,                  # PointerToSymbolTable
            0,                  # NumberOfSymbols
            optional_header_size,
            0x0102,             # Characteristics: EXECUTABLE_IMAGE | 32BIT_MACHINE
        )
        if self.pe32_plus:
            # Drop the 32BIT_MACHINE characteristic for the 64-bit image.
            file_header = struct.pack(
                "<HHIIIHH",
                self.machine,
                num_sections,
                0, 0, 0,
                optional_header_size,
                0x0022,
            )

        optional = self._build_optional_header(
            size_of_headers, image_size, reloc_size
        )

        headers = bytearray(size_of_headers)
        headers[0:len(dos)] = dos
        offset = e_lfanew
        headers[offset:offset + 4] = b"PE\x00\x00"
        offset += 4
        headers[offset:offset + len(file_header)] = file_header
        offset += len(file_header)
        headers[offset:offset + len(optional)] = optional
        return bytes(headers)

    def _build_optional_header(self, size_of_headers, image_size, reloc_size):
        import_dir_rva = self.import_desc_rva
        import_dir_size = 40
        reloc_dir_rva = self.RELOC_RVA
        directories = [(0, 0)] * 16
        # Directory 1 = import, 5 = base relocation, 12 = IAT.
        directories[1] = (import_dir_rva, import_dir_size)
        directories[5] = (reloc_dir_rva, reloc_size)
        directories[12] = (self.iat_rva, self.pointer_size * 2)
        dir_blob = b"".join(
            struct.pack("<II", rva, size) for rva, size in directories
        )

        common = dict(
            linker=(14, 0),
            code_sizes=(0x200, 0, 0),
            entry=0,
            base_of_code=self.TEXT_RVA,
            alignment=(PAGE, FILE_ALIGN),
            versions=((6, 0), (0, 0), (6, 0)),
            reserved=0,
            image_size=image_size,
            size_of_headers=size_of_headers,
            checksum=0,
            subsystem=(3, 0),
            stack=(0x100000, 0x1000),
            heap=(0x100000, 0x1000),
            loader_flags=0,
            num_dirs=16,
        )

        if self.pe32_plus:
            fixed = struct.pack(
                "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
                self.magic,
                common["linker"][0], common["linker"][1],
                *common["code_sizes"],
                common["entry"],
                common["base_of_code"],
                self.image_base,
                common["alignment"][0], common["alignment"][1],
                common["versions"][0][0], common["versions"][0][1],
                common["versions"][1][0], common["versions"][1][1],
                common["versions"][2][0], common["versions"][2][1],
                common["reserved"],
                common["image_size"],
                common["size_of_headers"],
                common["checksum"],
                common["subsystem"][0], common["subsystem"][1],
                common["stack"][0], common["stack"][1],
                common["heap"][0], common["heap"][1],
                common["loader_flags"],
                common["num_dirs"],
            )
        else:
            fixed = struct.pack(
                "<HBB7II2I6H3I2H4I2I",
                self.magic,
                common["linker"][0], common["linker"][1],
                *common["code_sizes"],
                common["entry"],
                common["base_of_code"],
                self.RDATA_RVA,
                self.image_base,
                common["alignment"][0], common["alignment"][1],
                common["versions"][0][0], common["versions"][0][1],
                common["versions"][1][0], common["versions"][1][1],
                common["versions"][2][0], common["versions"][2][1],
                common["reserved"],
                common["image_size"],
                common["size_of_headers"],
                common["checksum"],
                common["subsystem"][0], common["subsystem"][1],
                common["stack"][0], common["stack"][1],
                common["heap"][0], common["heap"][1],
                common["loader_flags"],
                common["num_dirs"],
            )
        return fixed + dir_blob

    @staticmethod
    def _section_header(name, virtual_size, virtual_address, raw_size,
                        raw_offset, characteristics):
        return struct.pack(
            "<8sIIIIIIHHI",
            name,
            virtual_size,
            virtual_address,
            raw_size,
            raw_offset,
            0,                  # PointerToRelocations
            0,                  # PointerToLinenumbers
            0,                  # NumberOfRelocations
            0,                  # NumberOfLinenumbers
            characteristics,
        )


def loader_memory_image(pe_builder, disk_bytes, new_base,
                        bind_iat=True, patch=None, drop_pages=None,
                        extra_reloc_type=None):
    """Simulate the post-loader memory image of a synthetic PE.

    Applies, independently of the backend under test:

    * section mapping at virtual addresses with zero padding,
    * base relocations for the requested load base,
    * IAT binding with deterministic fake resolved addresses,
    * optional byte patches and missing (dropped) pages.

    Returns (full_image_by_rva, present_rvas) where present_rvas is the set
    of RVAs a sparse capture would contain.
    """
    import pefile

    parsed = pefile.PE(data=disk_bytes, fast_load=True)
    parsed.parse_data_directories(
        directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
        ]
    )

    # Size the buffer from the virtual layout (not the file size), matching
    # how the loader maps sections and BSS.
    virtual_end = max(
        section.VirtualAddress + max(section.Misc_VirtualSize,
                                     section.SizeOfRawData)
        for section in parsed.sections
    )
    image = bytearray(_align(virtual_end, PAGE))
    # Map headers.
    image[0:len(parsed.header)] = parsed.header
    # Map sections: only the in-memory (virtual) portion is present.
    for section in parsed.sections:
        data = section.get_data()
        va = section.VirtualAddress
        virtual_size = section.Misc_VirtualSize or len(data)
        data = data[:virtual_size]
        if virtual_size > len(data):
            data = data + b"\x00" * (virtual_size - len(data))
        image[va:va + len(data)] = data

    delta = new_base - parsed.OPTIONAL_HEADER.ImageBase

    # Apply relocations manually (not via pefile.relocate_image, which mutates
    # the PE object; this simulator stays independent of the backend).
    if hasattr(parsed, "DIRECTORY_ENTRY_BASERELOC"):
        for block in parsed.DIRECTORY_ENTRY_BASERELOC:
            for entry in block.entries:
                rva = entry.rva
                rtype = entry.type
                if rtype == 0:
                    continue
                if rtype == 3:  # HIGHLOW
                    value = struct.unpack_from("<I", image, rva)[0]
                    struct.pack_into("<I", image, rva, (value + delta) & 0xFFFFFFFF)
                elif rtype == 10:  # DIR64
                    value = struct.unpack_from("<Q", image, rva)[0]
                    struct.pack_into("<Q", image, rva, (value + delta) & 0xFFFFFFFFFFFFFFFF)
                # Other types are only injected in dedicated unknown-type tests
                # and are intentionally left unapplied by the simulator.

    if bind_iat and hasattr(parsed, "DIRECTORY_ENTRY_IMPORT"):
        ps = pe_builder.pointer_size
        fake_address = new_base + 0x70000
        for descriptor in parsed.DIRECTORY_ENTRY_IMPORT:
            slot = descriptor.struct.FirstThunk
            count = 0
            while True:
                raw = bytes(image[slot:slot + ps])
                if int.from_bytes(raw, "little") == 0:
                    break
                image[slot:slot + ps] = (
                    (fake_address + count * 0x10).to_bytes(ps, "little")
                )
                slot += ps
                count += 1

    if patch:
        for rva, value in patch.items():
            image[rva] = value

    drop_pages = set(drop_pages or [])
    present = {
        rva
        for rva in range(len(image))
        if (rva // PAGE) not in drop_pages
    }
    return bytearray(image), present
