"""Mutable PE model backed by a byte buffer.

The model keeps a raw PE image, parses it with pefile for structural
information, and exposes coordinate-aware write helpers used by the
structure-preserving mutators in :mod:`pefuzz.mutators`.
"""


import struct
from dataclasses import dataclass

import pefile

from .records import FieldRef


@dataclass
class Anchor:
    """A typed, tracked reference into the image."""

    rva: int
    kind: str
    size: int = 4
    note: str = ""


class PEError(Exception):
    """Raised when a mutation cannot be performed on a PE image."""


class PEModel:
    """A thin, mutating wrapper around a raw PE byte string."""

    def __init__(self, data, fast_load=True):
        self.data = bytearray(data)
        self.anchors = []
        pe = pefile.PE(data=bytes(self.data), fast_load=fast_load)
        pe.parse_data_directories()
        self.pe = pe

    def bytes(self):
        return bytes(self.data)

    def reparse(self):
        self.pe = pefile.PE(data=bytes(self.data), fast_load=True)
        self.pe.parse_data_directories()
        return self.pe

    # ------------------------------------------------------------------
    # coordinate helpers
    # ------------------------------------------------------------------
    def rva_to_offset(self, rva):
        return self.pe.get_offset_from_rva(rva)

    def offset_to_rva(self, offset):
        return self.pe.get_rva_from_offset(offset)

    def write_at_offset(self, offset, blob):
        end = offset + len(blob)
        if end > len(self.data):
            raise PEError(f"write beyond EOF: offset={offset:#x} len={len(blob)}")
        self.data[offset:end] = blob

    def write_at_rva(self, rva, blob):
        self.write_at_offset(self.rva_to_offset(rva), blob)

    def read_at_rva(self, rva, length):
        offset = self.rva_to_offset(rva)
        return bytes(self.data[offset:offset + length])

    def write_u32_at_rva(self, rva, value):
        self.write_at_rva(rva, struct.pack("<I", value & 0xFFFFFFFF))

    def write_u16_at_rva(self, rva, value):
        self.write_at_rva(rva, struct.pack("<H", value & 0xFFFF))

    def write_cstring_at_rva(self, rva, blob):
        payload = blob + b"\x00"
        self.write_at_rva(rva, payload)

    def find_cstring(self, needle):
        raw = bytes(self.data)
        hit = raw.find(needle + b"\x00")
        if hit < 0:
            raise PEError(f"string not found: {needle!r}")
        return self.offset_to_rva(hit)

    # ------------------------------------------------------------------
    # layout helpers
    # ------------------------------------------------------------------
    def sections(self):
        return list(self.pe.sections)

    def section_by_name(self, name):
        raw = name if isinstance(name, bytes) else name.encode()
        raw = raw.ljust(8, b"\x00")[:8]
        for section in self.pe.sections:
            if section.Name == raw:
                return section
        raise PEError(f"section not found: {name}")

    def directory(self, index):
        return self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[index]

    def set_directory(self, index, rva, size):
        entry = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[index]
        struct_offset = entry.get_file_offset()
        self.write_at_offset(struct_offset, struct.pack("<II", rva, size))
        entry.VirtualAddress = rva
        entry.Size = size

    def is_mapped_rva(self, rva):
        for section in self.pe.sections:
            start = section.VirtualAddress
            end = start + max(section.Misc_VirtualSize, section.SizeOfRawData)
            if start <= rva < end:
                return True
        return False

    # ------------------------------------------------------------------
    # anchors: typed references into the image
    # ------------------------------------------------------------------
    def add_anchor(self, rva, kind, size=4, note=""):
        if not (0 <= rva < 0x10000000):
            raise PEError(f"anchor rva out of range: {rva:#x}")
        anchor = Anchor(rva=rva, kind=kind, size=size, note=note)
        self.anchors.append(anchor)
        return anchor

    def scan_references(self, rva_lo, rva_hi):
        """Return RVAs of every 32-bit word whose value is in range."""
        hits = []
        for section in self.pe.sections:
            base = section.VirtualAddress
            span = max(section.Misc_VirtualSize, section.SizeOfRawData)
            data = section.get_data()
            for offset in range(0, len(data) - 3):
                (value,) = struct.unpack_from("<I", data, offset)
                if rva_lo <= value < rva_hi:
                    hits.append(base + offset)
        return hits

    def relocate_rva_refs(self, lo, hi, delta, record):
        for ref_rva in self.scan_references(lo, hi):
            offset = self.rva_to_offset(ref_rva)
            (value,) = struct.unpack_from("<I", self.data, offset)
            new_value = value + delta
            struct.pack_into("<I", self.data, offset, new_value)
            note = f"RVA ref {value:#x} -> {new_value:#x}"
            record.dependent_fields.append(
                FieldRef("rva", ref_rva, note)
            )

    def move_section_raw(self, name, new_raw_offset, record=None):
        """Relocate a section raw blob and rewrite every reference.

        Only the file offset of the raw data changes; the section RVA is
        preserved so that every RVA-based directory pointer stays valid.
        The section header PointerToRawData field is patched in place.
        """
        section = self.section_by_name(name)
        old_raw = section.PointerToRawData
        raw_size = section.SizeOfRawData
        if new_raw_offset == old_raw:
            raise PEError("new raw offset equals current one")
        if new_raw_offset + raw_size > len(self.data):
            raise PEError("relocation would run past end of file")
        alignment = self.pe.OPTIONAL_HEADER.FileAlignment
        if new_raw_offset % alignment != 0:
            raise PEError("new raw offset breaks FileAlignment constraint")

        blob = bytes(self.data[old_raw:old_raw + raw_size])
        new_image = bytearray(self.data)
        new_image[old_raw:old_raw + raw_size] = b"\x00" * raw_size
        new_image[new_raw_offset:new_raw_offset + raw_size] = blob
        self.data = new_image

        header_offset = section.get_file_offset()
        ptr_field = header_offset + 20
        struct.pack_into("<I", self.data, ptr_field, new_raw_offset)

        if record is not None:
            label = section.Name.rstrip(b"\x00").decode(errors="replace")
            note = label + ".PointerToRawData "
            note += hex(old_raw) + " -> " + hex(new_raw_offset)
            record.dependent_fields.append(
                FieldRef("file_offset", ptr_field, note)
            )
            record.expected_invariants.extend([
                "section.VirtualAddress unchanged",
                "all data-directory RVAs still resolve inside the section",
                "DOS/PE headers remain byte-identical",
            ])
        self.reparse()
        return old_raw

    def content_end_rva(self, name):
        section = self.section_by_name(name)
        raw = section.get_data()
        trimmed = raw.rstrip(b"\x00")
        return section.VirtualAddress + len(trimmed)

    def free_rva_in_section(self, name, length):
        return self.content_end_rva(name)

    def move_payload_to_section(self, src_rva, length, dst_name, record):
        """Move a payload to another section, preserving all RVA references.

        Returns the destination RVA.  Every 32-bit word in the image that
        pointed into the moved range is rewritten with the fixed delta, as
        are the supplied directory headers and recorded anchors.
        """
        if not self.is_mapped_rva(src_rva):
            raise PEError("source RVA is not mapped by any section")
        dst = self.section_by_name(dst_name)
        dst_rva = self.free_rva_in_section(dst_name, length)
        if dst_rva + length > dst.VirtualAddress + dst.Misc_VirtualSize:
            raise PEError("destination section lacks virtual space")

        src_offset = self.rva_to_offset(src_rva)
        blob = bytes(self.data[src_offset:src_offset + length])
        dst_offset = self.rva_to_offset(dst_rva)
        if dst_offset + length > len(self.data):
            raise PEError("destination raw space exceeds file size")
        self.write_at_offset(dst_offset, blob)
        self.data[src_offset:src_offset + length] = b"\x00" * length

        delta = dst_rva - src_rva
        self.relocate_rva_refs(src_rva, src_rva + length, delta, record)
        record.dependent_fields.append(
            FieldRef(
                "rva",
                src_rva,
                "payload moved " + hex(src_rva) + " -> " + hex(dst_rva),
            )
        )
        record.expected_invariants.extend([
            "import and export semantics unchanged",
            "moved payload bytes are identical",
            "no RVA pointer left dangling into the old range",
        ])
        self.reparse()
        return dst_rva
