"""Synthetic, fully in-memory mini-PE builder.

The builder emits small but well-formed PE32 images that carry real data
directories (export, import with two DLLs, a three-level resource tree,
debug entries and base relocations).  Because the corpus is generated
deterministically from plain Python objects the fuzzer never depends on
external binaries and every produced file comfortably fits in a few KiB.
"""

import struct

FILE_ALIGNMENT = 0x200
SECTION_ALIGNMENT = 0x1000
IMAGE_BASE = 0x00400000

IMAGE_DOS_SIGNATURE = 0x5A4D
IMAGE_NT_SIGNATURE = 0x00004550

DIR_EXPORT = 0
DIR_IMPORT = 1
DIR_RESOURCE = 2
DIR_BASERELOC = 5
DIR_DEBUG = 6
NUM_DATA_DIRS = 16

IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000


class _Blob:
    """Growable buffer tracked by relative offset inside a section."""

    def __init__(self):
        self._chunks = []
        self.length = 0

    def add(self, data, align=1):
        pad = (-self.length) % align
        if pad:
            self._chunks.append(b"\x00" * pad)
            self.length += pad
        relative = self.length
        self._chunks.append(data)
        self.length += len(data)
        return relative

    def bytes(self):
        return b"".join(self._chunks)


class MiniPEBuilder:
    """Builds a tiny PE32 image exercising many parser directories at once."""

    def __init__(self, imports=None, exports=None, resources=None,
                 debug_entries=2, slack=0x600, include_relocs=True):
        self.imports = imports or {
            b"KERNEL32.dll": [
                b"LoadLibraryA", b"GetProcAddress", b"ExitProcess",
            ],
            b"USER32.dll": [b"MessageBoxA", 42],
        }
        self.exports = exports or [
            (b"MiniExportOne", 1),
            (b"MiniExportTwo", 2),
            (b"MiniExportByOrd", 3),
        ]
        self.resources = resources or {
            101: b"RES-DATA-101",
            102: b"RES-DATA-102",
        }
        self.debug_entries = debug_entries
        self.slack = slack
        self.include_relocs = include_relocs

    def build(self):
        rdata, info = self._build_rdata()
        if self.include_relocs:
            reloc_rel = rdata.add(self._reloc_block(), align=4)
        else:
            reloc_rel = None
        text = self._build_text()

        headers_size = FILE_ALIGNMENT
        text_rva = SECTION_ALIGNMENT
        text_raw = headers_size
        rdata_rva = SECTION_ALIGNMENT * 2
        rdata_raw = headers_size + FILE_ALIGNMENT
        size_of_image = SECTION_ALIGNMENT * 3

        def to_rva(relative):
            return rdata_rva + relative

        data_dirs = self._data_directories(info, to_rva, reloc_rel)
        dos = self._dos_header(headers_size)
        nt = self._nt_headers(
            entry_rva=text_rva,
            size_of_image=size_of_image,
            headers_size=headers_size,
            data_dirs=data_dirs,
        )
        sections = self._section_headers(
            text_rva, text_raw, len(text),
            rdata_rva, rdata_raw, rdata.length,
        )
        header_blob = dos + nt + sections
        header_blob += b"\x00" * (headers_size - len(header_blob))

        image = bytearray()
        image += header_blob
        image += text
        image += b"\x00" * (FILE_ALIGNMENT - len(text))
        patched_rdata = self._patch_rdata(rdata, info, rdata_rva, rdata_raw)
        image += patched_rdata
        image += b"\x00" * (-len(image) % FILE_ALIGNMENT)
        if self.slack:
            filler = bytes((index % 251) + 1 for index in range(self.slack))
            image += filler
        return bytes(image)


    def _build_rdata(self):
        blob = _Blob()
        info = {}

        # ---- export directory --------------------------------------
        export_names = [name for name, _ in self.exports]
        dll_name_rel = blob.add(b"minipe.dll\x00")
        export_header_rel = blob.add(b"\x00" * 40, align=4)
        functions_rel = blob.add(
            struct.pack("<%dI" % len(self.exports),
                        *[0x1000 + 0x10 * i for i in range(len(self.exports))]),
            align=4,
        )
        name_ptrs_rel = blob.add(b"\x00" * 4 * len(export_names), align=4)
        ordinals_rel = blob.add(
            struct.pack("<%dH" % len(export_names),
                        *range(len(export_names))),
            align=2,
        )
        name_string_rels = []
        for name in export_names:
            name_string_rels.append(blob.add(name + b"\x00"))
        info["export"] = {
            "header_rel": export_header_rel,
            "header_size": 40,
            "dll_name_rel": dll_name_rel,
            "functions_rel": functions_rel,
            "name_ptrs_rel": name_ptrs_rel,
            "ordinals_rel": ordinals_rel,
            "name_string_rels": name_string_rels,
            "count": len(self.exports),
        }

        # ---- import directory (two DLLs) ---------------------------
        dll_order = list(self.imports.keys())
        descriptor_rel = blob.add(b"\x00" * 20 * (len(dll_order) + 1), align=4)
        import_info = []
        for dll in dll_order:
            symbols = self.imports[dll]
            dll_name_rel = blob.add(dll + b"\x00")
            ilt_rel = blob.add(
                self._thunk_table(symbols), align=4
            )
            iat_rel = blob.add(
                self._thunk_table(symbols), align=4
            )
            hint_rels = []
            for symbol in symbols:
                if isinstance(symbol, int):
                    hint_rels.append(None)
                else:
                    hint_rels.append(blob.add(self._hint_name(symbol)))
            import_info.append(
                {
                    "dll_name_rel": dll_name_rel,
                    "ilt_rel": ilt_rel,
                    "iat_rel": iat_rel,
                    "hint_rels": hint_rels,
                }
            )
        info["import"] = {
            "descriptor_rel": descriptor_rel,
            "descriptors": import_info,
            "size": 20 * (len(dll_order) + 1),
        }

        info["resource"] = self._build_resource_part(blob)
        info["debug"] = self._build_debug_part(blob)
        return blob, info


    def _build_resource_part(self, blob):
        """Three-level resource tree: root -> type -> name -> data entry."""
        resource_ids = sorted(self.resources.keys())
        leaf_count = len(resource_ids)
        header_size = 16
        entry_size = 8
        data_entry_size = 16

        alignment_pad = (-blob.length) % 4
        if alignment_pad:
            blob.add(b"\x00" * alignment_pad)
        root_rel = blob.length
        type_dir_rel = root_rel + header_size + entry_size
        name_dir_block = header_size + entry_size
        name_dir_start = type_dir_rel + header_size + leaf_count * entry_size
        data_entry_start = name_dir_start + leaf_count * name_dir_block
        payload_start = data_entry_start + leaf_count * data_entry_size

        payload_rels = []
        cursor = payload_start
        for resource_id in resource_ids:
            payload_rels.append(cursor)
            cursor += len(self.resources[resource_id])
            cursor = (cursor + 3) & ~3

        root_dir = self._resource_dir(1, 0)
        root_entry = struct.pack(
            "<II", 10, 0x80000000 | (type_dir_rel - root_rel)
        )
        blob.add(root_dir + root_entry)

        type_dir = self._resource_dir(leaf_count, 0)
        type_entries = b""
        for index in range(leaf_count):
            name_dir_rel = name_dir_start + index * name_dir_block
            type_entries += struct.pack(
                "<II",
                resource_ids[index],
                0x80000000 | (name_dir_rel - root_rel),
            )
        blob.add(type_dir + type_entries)

        data_entry_rels = []
        for index in range(leaf_count):
            name_dir_rel = name_dir_start + index * name_dir_block
            data_entry_rel = data_entry_start + index * data_entry_size
            name_dir = self._resource_dir(1, 0)
            name_entry = struct.pack(
                "<II",
                0,
                data_entry_rel - root_rel,
            )
            blob.add(name_dir + name_entry)
            data_entry_rels.append(data_entry_rel)

        for index in range(leaf_count):
            blob.add(b"\x00" * data_entry_size)

        for resource_id in resource_ids:
            blob.add(self.resources[resource_id], align=4)

        return {
            "root_rel": root_rel,
            "data_entry_rels": data_entry_rels,
            "data_payload_rels": payload_rels,
            "resource_ids": resource_ids,
            "total_size": blob.length - root_rel,
        }

    def _build_debug_part(self, blob):
        entry_count = self.debug_entries
        table_rel = blob.add(b"\x00" * 28 * entry_count, align=4)
        payload_rels = []
        for index in range(entry_count):
            payload_rels.append(
                blob.add(b"DBG-PAYLOAD-%d" % index, align=4)
            )
        return {
            "table_rel": table_rel,
            "payload_rels": payload_rels,
            "size": 28 * entry_count,
        }


    def _thunk_table(self, symbols):
        words = []
        for symbol in symbols:
            if isinstance(symbol, int):
                words.append(0x80000000 | symbol)
            else:
                words.append(0)
        words.append(0)
        return struct.pack("<%dI" % len(words), *words)

    def _hint_name(self, name):
        return struct.pack("<H", 0) + name + b"\x00"

    def _resource_dir(self, id_entries, named_entries):
        return struct.pack(
            "<IIHHHH",
            0,
            0,
            0,
            0,
            named_entries,
            id_entries,
        )

    def _reloc_block(self):
        block = struct.pack("<II", 0x1000, 8)
        return block

    def _build_text(self):
        return b"\xC3" * 16


    def _data_directories(self, info, to_rva, reloc_rel):
        export = info["export"]
        resource = info["resource"]
        debug = info["debug"]
        import_info = info["import"]
        directories = [(0, 0)] * NUM_DATA_DIRS
        directories[DIR_EXPORT] = (
            to_rva(export["header_rel"]),
            export["header_size"],
        )
        directories[DIR_IMPORT] = (
            to_rva(import_info["descriptor_rel"]),
            import_info["size"],
        )
        resource_size = (
            resource["root_rel"] + resource["total_size"]
        )
        directories[DIR_RESOURCE] = (
            to_rva(resource["root_rel"]),
            resource_size,
        )
        if self.include_relocs:
            directories[DIR_BASERELOC] = (to_rva(reloc_rel), 8)
        directories[DIR_DEBUG] = (
            to_rva(debug["table_rel"]),
            debug["size"],
        )
        return b"".join(struct.pack("<II", rva, size) for rva, size in directories)

    def _dos_header(self, pe_offset):
        dos = bytearray(64)
        struct.pack_into("<H", dos, 0, IMAGE_DOS_SIGNATURE)
        struct.pack_into("<I", dos, 60, 64)
        return bytes(dos)

    def _nt_headers(self, entry_rva, size_of_image, headers_size, data_dirs):
        file_header = struct.pack(
            "<HHIIIHH",
            0x14C,
            2,
            0,
            0,
            0,
            224,
            0x0102,
        )
        optional = struct.pack(
            "<HBBIII",
            0x10B,
            1,
            0,
            0x200,
            0x800,
            0,
        )
        optional += struct.pack(
            "<IIII",
            entry_rva,
            SECTION_ALIGNMENT,
            SECTION_ALIGNMENT * 2,
            IMAGE_BASE,
        )
        optional += struct.pack(
            "<II",
            SECTION_ALIGNMENT,
            FILE_ALIGNMENT,
        )
        optional += struct.pack("<HHHHHH", 4, 0, 0, 0, 4, 0)
        optional += struct.pack(
            "<IIII",
            0,
            size_of_image,
            headers_size,
            0,
        )
        optional += struct.pack("<HH", 3, 0)
        optional += struct.pack(
            "<IIIII",
            0x100000,
            0x1000,
            0x100000,
            0x1000,
            0,
        )
        optional += struct.pack("<I", NUM_DATA_DIRS)
        optional += data_dirs
        nt = struct.pack("<I", IMAGE_NT_SIGNATURE)
        nt += file_header
        nt += optional
        return nt

    def _section_header(self, name, virtual_size, virtual_address,
                        raw_size, raw_pointer, characteristics):
        return struct.pack(
            "<8sIIIIIIHHI",
            name,
            virtual_size,
            virtual_address,
            raw_size,
            raw_pointer,
            0,
            0,
            0,
            0,
            characteristics,
        )

    def _section_headers(self, text_rva, text_raw, text_len,
                         rdata_rva, rdata_raw, rdata_len):
        text_header = self._section_header(
            b".text\x00\x00\x00",
            FILE_ALIGNMENT,
            text_rva,
            FILE_ALIGNMENT,
            text_raw,
            IMAGE_SCN_CNT_CODE
            | IMAGE_SCN_MEM_EXECUTE
            | IMAGE_SCN_MEM_READ,
        )
        rdata_header = self._section_header(
            b".rdata\x00\x00",
            rdata_len,
            rdata_rva,
            max(FILE_ALIGNMENT, ((rdata_len + 0x1FF) // 0x200) * 0x200),
            rdata_raw,
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
        )
        return text_header + rdata_header


    def _patch_rdata(self, blob, info, rdata_rva, rdata_raw):
        raw = bytearray(blob.bytes())

        def write_u32(relative, value):
            struct.pack_into("<I", raw, relative, value & 0xFFFFFFFF)

        def write_u16(relative, value):
            struct.pack_into("<H", raw, relative, value & 0xFFFF)

        export = info["export"]
        header = export["header_rel"]
        write_u32(header + 12, rdata_rva + export["dll_name_rel"])
        write_u32(header + 20, export["count"])
        write_u32(header + 24, export["count"])
        write_u32(header + 28, rdata_rva + export["functions_rel"])
        write_u32(header + 32, rdata_rva + export["name_ptrs_rel"])
        write_u32(header + 36, rdata_rva + export["ordinals_rel"])
        for index, name_rel in enumerate(export["name_string_rels"]):
            write_u32(
                export["name_ptrs_rel"] + 4 * index,
                rdata_rva + name_rel,
            )

        import_info = info["import"]
        for index, descriptor in enumerate(import_info["descriptors"]):
            slot = import_info["descriptor_rel"] + 20 * index
            write_u32(slot + 0, rdata_rva + descriptor["ilt_rel"])
            write_u32(slot + 12, rdata_rva + descriptor["dll_name_rel"])
            write_u32(slot + 16, rdata_rva + descriptor["iat_rel"])
            for symbol_index, hint_rel in enumerate(descriptor["hint_rels"]):
                if hint_rel is None:
                    continue
                thunk_rel = descriptor["ilt_rel"] + 4 * symbol_index
                write_u32(thunk_rel, rdata_rva + hint_rel)
                thunk_rel = descriptor["iat_rel"] + 4 * symbol_index
                write_u32(thunk_rel, rdata_rva + hint_rel)

        resource = info["resource"]
        for index, payload_rel in enumerate(resource["data_payload_rels"]):
            entry_rel = resource["data_entry_rels"][index]
            write_u32(entry_rel + 0, rdata_rva + payload_rel)
            payload_size = len(
                self.resources[resource["resource_ids"][index]]
            )
            write_u32(entry_rel + 4, payload_size)
            write_u32(entry_rel + 8, 0)
            write_u32(entry_rel + 12, 0)

        debug = info["debug"]
        for index, payload_rel in enumerate(debug["payload_rels"]):
            slot = debug["table_rel"] + 28 * index
            write_u32(slot + 0, 0)
            write_u32(slot + 4, 0)
            write_u32(slot + 8, 0)
            write_u32(slot + 12, 2)
            write_u32(slot + 16, 12)
            write_u32(slot + 20, rdata_rva + payload_rel)
            write_u32(slot + 24, rdata_raw + payload_rel)

        return bytes(raw)


def build_mini_pe(seed=None, imports=None, exports=None, resources=None,
                  debug_entries=2, slack=0x600, include_relocs=True):
    """Construct a deterministic, well-formed sub-4KB PE32 image.

    The optional seed is accepted for API symmetry with the fuzz harness;
    the builder is deterministic given its structural arguments.
    """
    builder = MiniPEBuilder(
        imports=imports,
        exports=exports,
        resources=resources,
        debug_entries=debug_entries,
        slack=slack,
        include_relocs=include_relocs,
    )
    return builder.build()
