"""Pure-byte minimal PE fixture builder.

The generated images contain only a .rsrc section holding RT_MANIFEST
resources. They are real PE/COFF structures (not mocked objects), so pefile
parses them through its normal read-only entry points. Headers are rendered
with pefile Structure instances to guarantee field layout. No Windows
toolchain is required.
"""
from __future__ import annotations

import struct

import pefile

MACHINE_I386 = 0x014C
MACHINE_AMD64 = 0x8664
MACHINE_ARM64 = 0xAA64

RT_MANIFEST = 24
RESOURCE_NAME_MANIFEST = 1
DOS_STUB_SIZE = 0x40
PE_SIGNATURE_OFFSET = 0x80
NUMBER_OF_DIRECTORIES = 16
RESOURCE_DIRECTORY_INDEX = 2

_MACHINES = {
    "i386": MACHINE_I386,
    "amd64": MACHINE_AMD64,
    "arm64": MACHINE_ARM64,
}


def _align(value, boundary):
    return (value + boundary - 1) // boundary * boundary


def _build_rsrc(rsrc_rva, manifests):
    """Build a .rsrc section containing one RT_MANIFEST with N languages.

    Offsets are relative to the section start. Directory entry offsets to
    nested directories set the high bit; data entry offsets are plain.
    """
    ordered = sorted(manifests.items())
    count = len(ordered)
    type_dir_off = 0
    name_dir_off = 16 + 8
    lang_dir_off = name_dir_off + 16 + 8
    first_data_entry_off = lang_dir_off + (16 + 8 * count)
    cursor = _align(first_data_entry_off + 16 * count, 8)
    blob_records = []
    for lang_id, blob in ordered:
        blob_off = cursor
        blob_records.append((lang_id, blob_off, blob))
        cursor = _align(cursor + len(blob), 8)
    section = bytearray(cursor)
    struct.pack_into("<IIHHHH", section, type_dir_off, 0, 0, 0, 0, 0, 1)
    struct.pack_into("<II", section, type_dir_off + 16, RT_MANIFEST, 0x80000000 | name_dir_off)
    struct.pack_into("<IIHHHH", section, name_dir_off, 0, 0, 0, 0, 0, 1)
    struct.pack_into("<II", section, name_dir_off + 16, RESOURCE_NAME_MANIFEST, 0x80000000 | lang_dir_off)
    struct.pack_into("<IIHHHH", section, lang_dir_off, 0, 0, 0, 0, 0, count)
    for index, (lang_id, _blob_off, _blob) in enumerate(blob_records):
        data_entry_off = first_data_entry_off + index * 16
        struct.pack_into("<II", section, lang_dir_off + 16 + index * 8, lang_id, data_entry_off)
    for index, (lang_id, blob_off, blob) in enumerate(blob_records):
        data_entry_off = first_data_entry_off + index * 16
        struct.pack_into("<IIII", section, data_entry_off, rsrc_rva + blob_off, len(blob), 0, 0)
        section[blob_off:blob_off + len(blob)] = blob
    return bytes(section)


def _optional_header(is_pe32_plus, image_base, size_of_image, size_of_headers):
    fmt = pefile.PE.__IMAGE_OPTIONAL_HEADER64_format__ if is_pe32_plus else pefile.PE.__IMAGE_OPTIONAL_HEADER_format__
    header = pefile.Structure(fmt)
    header.Magic = 0x20B if is_pe32_plus else 0x10B
    header.MajorLinkerVersion = 14
    header.MinorLinkerVersion = 0
    header.SizeOfCode = 0
    header.SizeOfInitializedData = 0
    header.SizeOfUninitializedData = 0
    header.AddressOfEntryPoint = 0
    header.BaseOfCode = 0x1000
    if not is_pe32_plus:
        header.BaseOfData = 0
    header.ImageBase = image_base
    header.SectionAlignment = 0x1000
    header.FileAlignment = 0x200
    header.MajorOperatingSystemVersion = 6
    header.MinorOperatingSystemVersion = 0
    header.MajorImageVersion = 0
    header.MinorImageVersion = 0
    header.MajorSubsystemVersion = 0
    header.MinorSubsystemVersion = 0
    header.Reserved1 = 0
    header.SizeOfImage = size_of_image
    header.SizeOfHeaders = size_of_headers
    header.CheckSum = 0
    header.Subsystem = 3
    header.DllCharacteristics = 0
    if is_pe32_plus:
        header.SizeOfStackReserve = 0x100000
        header.SizeOfStackCommit = 0x1000
        header.SizeOfHeapReserve = 0x100000
        header.SizeOfHeapCommit = 0x1000
    else:
        header.SizeOfStackReserve = 0x100000
        header.SizeOfStackCommit = 0x1000
        header.SizeOfHeapReserve = 0x100000
        header.SizeOfHeapCommit = 0x1000
    header.LoaderFlags = 0
    header.NumberOfRvaAndSizes = NUMBER_OF_DIRECTORIES
    return header


def build_pe_with_manifests(manifests, machine="amd64"):
    """Return PE bytes whose .rsrc section carries the given manifest map.

    manifests maps a numeric language id (e.g. 0x409) to manifest bytes.
    machine is one of "i386", "amd64" or "arm64" (or a numeric Machine id).
    An empty mapping produces an image with a resource section but no
    RT_MANIFEST entry; use build_empty_pe for a section-less image.
    """
    machine_id = _MACHINES.get(machine, machine)
    is_pe32_plus = machine_id in (MACHINE_AMD64, MACHINE_ARM64)
    image_base = 0x140000000 if is_pe32_plus else 0x400000
    rsrc_rva = 0x1000
    rsrc_raw = _build_rsrc(rsrc_rva, manifests)
    rsrc_raw_size = _align(len(rsrc_raw), 0x200)
    rsrc_virtual_size = _align(len(rsrc_raw), 0x1000)
    size_of_image = rsrc_rva + rsrc_virtual_size
    file_header = pefile.Structure(pefile.PE.__IMAGE_FILE_HEADER_format__)
    file_header.Machine = machine_id
    file_header.NumberOfSections = 1
    file_header.TimeDateStamp = 0
    file_header.PointerToSymbolTable = 0
    file_header.NumberOfSymbols = 0
    file_header.Characteristics = 0x0102
    opt_header = _optional_header(is_pe32_plus, image_base, size_of_image, 0x200)
    opt_size = opt_header.sizeof()
    file_header.SizeOfOptionalHeader = opt_size + NUMBER_OF_DIRECTORIES * 8
    section_header = pefile.Structure(pefile.PE.__IMAGE_SECTION_HEADER_format__)
    section_header.Name = b".rsrc\x00\x00\x00"
    section_header.Misc = len(rsrc_raw)
    section_header.Misc_PhysicalAddress = len(rsrc_raw)
    section_header.Misc_VirtualSize = len(rsrc_raw)
    section_header.VirtualAddress = rsrc_rva
    section_header.SizeOfRawData = rsrc_raw_size
    section_header.PointerToRawData = 0x200
    section_header.PointerToRelocations = 0
    section_header.PointerToLinenumbers = 0
    section_header.NumberOfRelocations = 0
    section_header.NumberOfLinenumbers = 0
    section_header.Characteristics = 0x40000040
    headers = bytearray(0x200)
    headers[0:2] = b"MZ"
    struct.pack_into("<I", headers, 0x3C, PE_SIGNATURE_OFFSET)
    headers[PE_SIGNATURE_OFFSET:PE_SIGNATURE_OFFSET + 4] = b"PE\x00\x00"
    cursor = PE_SIGNATURE_OFFSET + 4
    file_blob = file_header.__pack__()
    headers[cursor:cursor + len(file_blob)] = file_blob
    cursor += len(file_blob)
    opt_blob = opt_header.__pack__()
    headers[cursor:cursor + len(opt_blob)] = opt_blob
    cursor += len(opt_blob)
    data_dir = pefile.Structure(pefile.PE.__IMAGE_DATA_DIRECTORY_format__)
    for index in range(NUMBER_OF_DIRECTORIES):
        data_dir.VirtualAddress = rsrc_rva if index == RESOURCE_DIRECTORY_INDEX else 0
        data_dir.Size = len(rsrc_raw) if index == RESOURCE_DIRECTORY_INDEX else 0
        blob = data_dir.__pack__()
        headers[cursor:cursor + len(blob)] = blob
        cursor += len(blob)
    section_blob = section_header.__pack__()
    headers[cursor:cursor + len(section_blob)] = section_blob
    body = rsrc_raw + b"\x00" * (rsrc_raw_size - len(rsrc_raw))
    return bytes(headers) + body


def build_empty_pe(machine="amd64"):
    """Return PE bytes with a .rsrc section containing no RT_MANIFEST."""
    return build_pe_with_manifests({}, machine=machine)


def make_manifest(level="asInvoker", ui_access=False, auto_elevate=None):
    """Return a standalone application manifest as UTF-8 bytes.

    level=None omits requestedExecutionLevel entirely (the no-declaration
    case); auto_elevate adds the windowsSettings autoElevate element behind
    the inventory "allow auto elevation" column.
    """
    trust = ""
    if level is not None:
        ui = "true" if ui_access else "false"
        trust = (
            "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">"
            "<security><requestedPrivileges>"
            f"<requestedExecutionLevel level=\"{level}\" uiAccess=\"{ui}\"/>"
            "</requestedPrivileges></security></trustInfo>"
        )
    settings = ""
    if auto_elevate is not None:
        value = "true" if auto_elevate else "false"
        settings = (
            "<application xmlns=\"urn:schemas-microsoft-com:asm.v3\">"
            "<windowsSettings>"
            f"<autoElevate xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">{value}</autoElevate>"
            "</windowsSettings></application>"
        )
    return (
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
        "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">"
        + trust + settings + "</assembly>"
    ).encode("utf-8")
