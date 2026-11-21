"""Demo: feed two synthetic PE files through the approval check.

Builds two simplified PE32 binaries in memory (static imports, delay-load
imports, ordinal-only imports), resolves ordinal identities against a fake
ordlookup-style symbol directory, and shows why the same dependency gets
different verdicts under purpose A ("intranet-viewer") and purpose B
("external-minimal").
"""

import struct

import pefile

import approval_check as ac

SECTION_RVA = 0x1000
SECTION_RAW = 0x200
SECTION_SIZE = 0x800
ORDINAL_FLAG = 0x80000000


class SectionBuilder:
    """Allocates data inside the single PE section, returning RVAs."""

    def __init__(self):
        self.buf = bytearray(SECTION_SIZE)
        self.pos = 0

    def align(self, n):
        self.pos = (self.pos + n - 1) & ~(n - 1)

    def write(self, data):
        offset = self.pos
        self.buf[offset : offset + len(data)] = data
        self.pos += len(data)
        return SECTION_RVA + offset

    def write_at_rva(self, rva, data):
        self.buf[rva - SECTION_RVA : rva - SECTION_RVA + len(data)] = data


def _emit_import_tables(sec, symbols):
    """Emit hint/name strings plus INT and IAT for one DLL's symbols."""
    entries = []
    for kind, value in symbols:
        if kind == "name":
            sec.align(2)
            hint_name_rva = sec.write(struct.pack("<H", 0) + value + b"\x00")
            entries.append(hint_name_rva)
        else:  # ordinal-only import
            entries.append(ORDINAL_FLAG | value)
    sec.align(4)
    table = b"".join(struct.pack("<I", e) for e in entries) + b"\x00" * 4
    int_rva = sec.write(table)
    iat_rva = sec.write(table)
    return int_rva, iat_rva


def build_pe(static_imports, delay_imports):
    """Build a minimal PE32 with the given imports.

    static_imports / delay_imports: lists of
    (dll_name, [("name", b"Func") | ("ord", n), ...]).
    """
    sec = SectionBuilder()

    # Reserve space for the descriptor arrays (null-terminated lists).
    import_desc_rva = SECTION_RVA + sec.pos
    sec.pos += 20 * (len(static_imports) + 1)
    delay_desc_rva = SECTION_RVA + sec.pos
    sec.pos += 32 * (len(delay_imports) + 1)

    for i, (dll, symbols) in enumerate(static_imports):
        int_rva, iat_rva = _emit_import_tables(sec, symbols)
        name_rva = sec.write(dll.encode() + b"\x00")
        sec.write_at_rva(
            import_desc_rva + 20 * i,
            struct.pack("<IIIII", int_rva, 0, 0, name_rva, iat_rva),
        )

    for i, (dll, symbols) in enumerate(delay_imports):
        int_rva, iat_rva = _emit_import_tables(sec, symbols)
        name_rva = sec.write(dll.encode() + b"\x00")
        sec.write_at_rva(
            delay_desc_rva + 32 * i,
            # grAttrs=1 -> members hold RVAs (post-VS6 format)
            struct.pack("<IIIIIIII", 1, name_rva, 0, iat_rva, int_rva, 0, 0, 0),
        )

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)  # e_lfanew

    coff = struct.pack(
        "<HHIIIHH",
        0x14C,  # IMAGE_FILE_MACHINE_I386
        1,  # NumberOfSections
        0, 0, 0,
        0xE0,  # SizeOfOptionalHeader
        0x0102,  # EXECUTABLE_IMAGE | 32BIT_MACHINE
    )

    optional = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x10B, 0, 0,  # Magic (PE32), linker version
        0x200, 0x200, 0,  # SizeOfCode / InitializedData / UninitializedData
        SECTION_RVA,  # AddressOfEntryPoint
        SECTION_RVA,  # BaseOfCode
        0x2000,  # BaseOfData
        0x400000,  # ImageBase
        0x1000, 0x200,  # SectionAlignment / FileAlignment
        4, 0, 0, 0, 4, 0,  # OS / image / subsystem versions
        0,  # Win32VersionValue
        0x2000,  # SizeOfImage
        SECTION_RAW,  # SizeOfHeaders
        0,  # CheckSum
        3,  # Subsystem: WINDOWS_CUI
        0,  # DllCharacteristics
        0x100000, 0x1000, 0x100000, 0x1000,  # stack / heap reserve+commit
        0,  # LoaderFlags
        16,  # NumberOfRvaAndSizes
    )
    directories = [(0, 0)] * 16
    directories[1] = (import_desc_rva, 20 * (len(static_imports) + 1))
    directories[13] = (delay_desc_rva, 32 * (len(delay_imports) + 1))
    optional += b"".join(struct.pack("<II", *d) for d in directories)

    section_header = struct.pack(
        "<8sIIIIIIHHI",
        b".rdata\x00\x00",
        SECTION_SIZE,  # VirtualSize
        SECTION_RVA,  # VirtualAddress
        SECTION_SIZE,  # SizeOfRawData
        SECTION_RAW,  # PointerToRawData
        0, 0, 0, 0,
        0x40000040,  # INITIALIZED_DATA | MEM_READ
    )

    headers = bytes(dos) + b"PE\x00\x00" + coff + optional + section_header
    headers = headers.ljust(SECTION_RAW, b"\x00")
    return headers + bytes(sec.buf)


# Fake ordlookup-style symbol directory: the only place that can attach
# names to legacy.dll's ordinal-only exports.
FAKE_SYMBOL_DIRECTORY = {
    b"legacy.dll": {7: b"LegacyInit", 12: b"LegacyProcess"},
}

# viewer.exe: every dependency is explainable under purpose A.
VIEWER_PE = build_pe(
    static_imports=[
        ("core.dll", [("name", b"ReadConfig"), ("name", b"WriteLog")]),
        ("legacy.dll", [("ord", 7)]),  # identity recoverable via symbol dir
    ],
    delay_imports=[
        ("plugin.dll", [("name", b"Render")]),
    ],
)

# agent.exe: imports legacy.dll by an ordinal the symbol directory does
# not know, so its identity stays incomplete.
AGENT_PE = build_pe(
    static_imports=[
        ("core.dll", [("name", b"ReadConfig")]),
        ("legacy.dll", [("ord", 99)]),  # unknown to the symbol directory
    ],
    delay_imports=[
        ("plugin.dll", [("name", b"Render")]),
    ],
)

PURPOSE_A = ac.PurposePolicy(
    name="intranet-viewer (A)",
    required={"core.dll", "legacy.dll"},
    runtime_optional={"plugin.dll"},
)

PURPOSE_B = ac.PurposePolicy(
    name="external-minimal (B)",
    required={"core.dll"},
    runtime_optional=set(),  # no runtime choice tolerated
)


def run():
    artifacts = [("viewer.exe", VIEWER_PE), ("agent.exe", AGENT_PE)]
    for pe_name, data in artifacts:
        for policy in (PURPOSE_A, PURPOSE_B):
            pe = pefile.PE(data=data)
            try:
                findings, review_view = ac.evaluate(
                    pe, policy, symbol_directory=FAKE_SYMBOL_DIRECTORY
                )
            finally:
                pe.close()
            print(ac.render_report(pe_name, policy, findings, review_view))
            print()


if __name__ == "__main__":
    run()
