"""Structure-preserving mutators for pefile fuzzing.

Every mutator returns a :class:`~pefuzz.records.MutationRecord` describing
the fields it depended on and the invariants that must still hold after
the transformation.  A parallel family of ``break_*`` mutators deliberately
violates exactly one constraint while keeping the remainder of the image
coherent, so that differential tests can prove the parser notices the
damage rather than silently accepting it.
"""

import struct

from .model import PEModel, PEError
from .records import MutationRecord, FieldRef, SemanticChange


def _record(name, allowed):
    return MutationRecord(name=name, allowed_semantic_changes=list(allowed))


# ----------------------------------------------------------------------
# structure-preserving mutators
# ----------------------------------------------------------------------
def move_section_raw(data, section_name, new_raw_offset):
    """Move a section raw blob to a new file offset, fixing references."""
    model = PEModel(data)
    record = _record(
        "move_section_raw",
        [SemanticChange.COORDINATE_ONLY],
    )
    old_raw = model.move_section_raw(section_name, new_raw_offset, record)
    record.summary = (
        "section " + section_name + " raw data moved from "
        + hex(old_raw) + " to " + hex(new_raw_offset)
    )
    return model.bytes(), record


def move_directory_payload(data, directory_index, dst_section_name):
    """Move the raw payload backing a data directory into another section.

    All RVA references into the payload (including the directory header
    itself) are rewritten, while the parseable semantics stay identical.
    """
    model = PEModel(data)
    entry = model.directory(directory_index)
    if not entry.VirtualAddress:
        raise PEError("directory is empty: " + str(directory_index))
    record = _record(
        "move_directory_payload",
        [SemanticChange.COORDINATE_ONLY],
    )
    dst_rva = model.move_payload_to_section(
        entry.VirtualAddress, entry.Size, dst_section_name, record
    )
    model.set_directory(directory_index, dst_rva, entry.Size)
    record.dependent_fields.append(
        FieldRef(
            "rva",
            dst_rva,
            "data directory[" + str(directory_index) + "] header repointed",
        )
    )
    model.reparse()
    record.summary = (
        "directory " + str(directory_index) + " payload relocated to RVA "
        + hex(dst_rva)
    )
    return model.bytes(), record


def replace_import_name(data, dll_index, symbol_index, new_name):
    """Replace one imported symbol name in place or inside spare space.

    The thunk layout and ordinal/name flag stay untouched; only the bytes
    of the hint/name table string change.  The new name must fit inside the
    existing string slot so that no coordinates move.
    """
    model = PEModel(data)
    imports = getattr(model.pe, "DIRECTORY_ENTRY_IMPORT", None)
    if not imports or dll_index >= len(imports):
        raise PEError("import descriptor not found: " + str(dll_index))
    symbols = imports[dll_index].imports
    if symbol_index >= len(symbols):
        raise PEError("import symbol not found: " + str(symbol_index))
    symbol = symbols[symbol_index]
    if symbol.name is None:
        raise PEError("ordinal-only imports cannot be renamed")
    if symbol.struct_table.AddressOfData == 0:
        raise PEError("symbol has no hint/name table entry")

    name_rva = symbol.struct_table.AddressOfData + 2
    old_name = symbol.name
    if isinstance(old_name, str):
        old_name = old_name.encode()
    new_blob = new_name if isinstance(new_name, bytes) else new_name.encode()
    if len(new_blob) > len(old_name):
        raise PEError(
            "new name longer than existing slot; coordinate move not allowed"
        )

    slot = model.read_at_rva(name_rva, len(old_name) + 1)
    if slot[:len(old_name)] != old_name:
        raise PEError("import name slot mismatch")
    padding = b"\x00" * (len(old_name) - len(new_blob))
    model.write_at_rva(name_rva, new_blob + padding + b"\x00")

    record = _record(
        "replace_import_name",
        [SemanticChange.IMPORT_NAME],
    )
    record.dependent_fields.append(
        FieldRef("rva", name_rva, "hint/name table string bytes")
    )
    record.expected_invariants.extend([
        "number of import descriptors unchanged",
        "number of imported symbols per descriptor unchanged",
        "DLL names unchanged",
        "ordinal imports remain ordinal imports",
    ])
    record.summary = (
        "import " + old_name.decode(errors="replace") + " renamed to "
        + new_blob.decode(errors="replace")
    )
    model.reparse()
    return model.bytes(), record


def reorder_import_descriptors(data, permutation=None):
    """Reorder import descriptors without changing import semantics.

    Import descriptors are independent records terminated by an all-zero
    entry; reordering them changes neither DLL names nor symbols.
    """
    model = PEModel(data)
    descriptors = getattr(model.pe, "DIRECTORY_ENTRY_IMPORT", None)
    if not descriptors or len(descriptors) < 2:
        raise PEError("need at least two import descriptors to reorder")

    count = len(descriptors)
    if permutation is None:
        permutation = list(range(count))
        permutation[0], permutation[1] = permutation[1], permutation[0]
    if sorted(permutation) != list(range(count)):
        raise PEError("permutation must cover every descriptor exactly once")

    first = descriptors[0].struct.get_file_offset()
    desc_size = descriptors[0].struct.sizeof()
    original = [
        bytes(
            model.data[
                first + i * desc_size:first + (i + 1) * desc_size
            ]
        )
        for i in range(count)
    ]
    zero_sentinel = b"\x00" * desc_size
    rebuilt = b"".join(original[i] for i in permutation) + zero_sentinel
    total = count * desc_size
    model.write_at_offset(first, rebuilt[:total] + zero_sentinel)

    record = _record(
        "reorder_import_descriptors",
        [SemanticChange.NONE],
    )
    record.dependent_fields.append(
        FieldRef("file_offset", first, "IMAGE_IMPORT_DESCRIPTOR array order")
    )
    record.expected_invariants.extend([
        "multiset of imported DLL names unchanged",
        "every DLL keeps the same imported symbols",
        "null terminator still present",
    ])
    record.summary = "import descriptors permuted: " + str(permutation)
    model.reparse()
    return model.bytes(), record


def reorder_resource_entries(data, level=0):
    """Swap two sibling entries inside a resource directory table.

    Resource directory entries are an unordered set of name/id pairs, so
    swapping siblings changes no semantic content; the tree shape and all
    data leaves stay identical.  ``level`` selects the directory depth to
    perturb (0 = root, 1 = type, 2 = name).
    """
    model = PEModel(data)
    resource = getattr(model.pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if resource is None:
        raise PEError("image has no resource directory")

    target = _nth_resource_dir(resource, level)
    entries = target.entries
    if len(entries) < 2:
        raise PEError("target resource directory has fewer than two entries")

    entry_size = entries[0].struct.sizeof()
    first_offset = entries[0].struct.get_file_offset()
    second_offset = entries[1].struct.get_file_offset()
    if second_offset != first_offset + entry_size:
        raise PEError("resource entries are not contiguous; aborting swap")

    first_bytes = bytes(model.data[first_offset:first_offset + entry_size])
    second_bytes = bytes(model.data[second_offset:second_offset + entry_size])
    model.write_at_offset(first_offset, second_bytes)
    model.write_at_offset(second_offset, first_bytes)

    record = _record(
        "reorder_resource_entries",
        [SemanticChange.NONE],
    )
    record.dependent_fields.append(
        FieldRef(
            "file_offset",
            first_offset,
            "resource directory entry order at depth " + str(level),
        )
    )
    record.expected_invariants.extend([
        "resource tree depth unchanged",
        "number of data leaves and their bytes unchanged",
        "entry id/name multiset unchanged",
    ])
    record.summary = "swapped two resource entries at depth " + str(level)
    model.reparse()
    return model.bytes(), record


def _nth_resource_dir(root, level):
    node = root
    for _ in range(level + 1):
        child = None
        for entry in node.entries:
            directory = getattr(entry, "directory", None)
            if directory is not None:
                child = directory
                break
        if child is None:
            raise PEError("resource tree is shallower than requested level")
        node = child
    return node


def reorder_debug_entries(data, permutation=None):
    """Reorder independent IMAGE_DEBUG_DIRECTORY records."""
    model = PEModel(data)
    entries = getattr(model.pe, "DIRECTORY_ENTRY_DEBUG", None)
    if not entries or len(entries) < 2:
        raise PEError("need at least two debug entries to reorder")
    count = len(entries)
    if permutation is None:
        permutation = list(range(count))
        permutation[0], permutation[1] = permutation[1], permutation[0]
    if sorted(permutation) != list(range(count)):
        raise PEError("permutation must cover every debug entry once")

    first = entries[0].struct.get_file_offset()
    size = entries[0].struct.sizeof()
    blobs = [
        bytes(model.data[first + i * size:first + (i + 1) * size])
        for i in range(count)
    ]
    model.write_at_offset(first, b"".join(blobs[i] for i in permutation))

    record = _record(
        "reorder_debug_entries",
        [SemanticChange.NONE],
    )
    record.dependent_fields.append(
        FieldRef("file_offset", first, "debug directory record order")
    )
    record.expected_invariants.extend([
        "multiset of debug entry types unchanged",
        "debug payload pointers unchanged",
    ])
    record.summary = "debug entries permuted: " + str(permutation)
    model.reparse()
    return model.bytes(), record


# ----------------------------------------------------------------------
# single-constraint breakage modes
# ----------------------------------------------------------------------
def break_dos_magic(data):
    """Corrupt only the DOS ``MZ`` magic (DOS-header rejection path)."""
    model = PEModel(data)
    offset = model.pe.DOS_HEADER.get_file_offset()
    original = bytes(model.data[offset:offset + 2])
    if original != b"MZ":
        raise PEError("DOS magic missing; cannot demonstrate single break")
    model.write_at_offset(offset, b"ZZ")
    record = _record("break_dos_magic", [SemanticChange.DOS_HEADER])
    record.broken_constraint = "DOS_HEADER.e_magic == IMAGE_DOS_SIGNATURE"
    record.dependent_fields.append(
        FieldRef("file_offset", offset, "e_magic bytes MZ -> ZZ")
    )
    record.expected_invariants.append(
        "parser must reject before reaching any data directory"
    )
    record.summary = "DOS magic corrupted; failure must stay at DOS layer"
    return model.bytes(), record


def break_section_raw_pointer(data, section_name):
    """Point PointerToRawData beyond EOF while keeping all other fields."""
    model = PEModel(data)
    section = model.section_by_name(section_name)
    field = section.get_file_offset() + 20
    bad = len(model.data) + 0x200
    struct.pack_into("<I", model.data, field, bad)
    record = _record(
        "break_section_raw_pointer",
        [SemanticChange.SUSPICIOUS_DIAGNOSTIC],
    )
    record.broken_constraint = (
        "section.PointerToRawData + SizeOfRawData <= len(file)"
    )
    record.dependent_fields.append(
        FieldRef("file_offset", field, "PointerToRawData set beyond EOF")
    )
    record.expected_invariants.append(
        "parser must emit a section parse warning"
    )
    record.summary = "section raw pointer deliberately dangling"
    return model.bytes(), record


def break_directory_rva(data, directory_index):
    """Point one data-directory RVA at unmapped space; nothing else moves."""
    model = PEModel(data)
    entry = model.directory(directory_index)
    if not entry.VirtualAddress:
        raise PEError("directory empty: " + str(directory_index))
    bad_rva = model.pe.OPTIONAL_HEADER.SizeOfImage + 0x1000
    struct_field = entry.get_file_offset()
    struct.pack_into("<I", model.data, struct_field, bad_rva)
    record = _record(
        "break_directory_rva",
        [SemanticChange.SUSPICIOUS_DIAGNOSTIC],
    )
    record.broken_constraint = (
        "data directory VirtualAddress maps inside a section"
    )
    record.dependent_fields.append(
        FieldRef("file_offset", struct_field, "directory RVA made invalid")
    )
    record.expected_invariants.append(
        "parser must warn that the directory failed to process"
    )
    record.summary = (
        "directory " + str(directory_index) + " RVA points at unmapped memory"
    )
    return model.bytes(), record


def break_import_name_rva(data, dll_index=0, symbol_index=0):
    """Corrupt one ILT thunk so its hint/name RVA no longer resolves.

    The import descriptor and DLL name stay valid; only a single thunk
    pointer is made dangling, which forces pefile to emit an invalid-import
    diagnostic.
    """
    model = PEModel(data)
    imports = getattr(model.pe, "DIRECTORY_ENTRY_IMPORT", None)
    if not imports or dll_index >= len(imports):
        raise PEError("import descriptor missing")
    symbols = imports[dll_index].imports
    if symbol_index >= len(symbols):
        raise PEError("import symbol missing")
    symbol = symbols[symbol_index]
    if symbol.name is None:
        raise PEError("ordinal-only thunk has no name RVA to break")
    thunk = symbol.struct_table
    thunk_field = thunk.get_file_offset()
    bad = model.pe.OPTIONAL_HEADER.SizeOfImage + 0x800
    struct.pack_into("<I", model.data, thunk_field, bad)
    record = _record(
        "break_import_name_rva",
        [SemanticChange.SUSPICIOUS_DIAGNOSTIC],
    )
    record.broken_constraint = (
        "ILT thunk AddressOfData resolves to a readable hint/name record"
    )
    record.dependent_fields.append(
        FieldRef("file_offset", thunk_field, "thunk name RVA made dangling")
    )
    record.expected_invariants.append(
        "import descriptor and DLL name remain parseable"
    )
    record.summary = "import thunk name RVA deliberately broken"
    return model.bytes(), record


def break_resource_depth(data):
    """Force an excessively nested resource table via one offset field."""
    model = PEModel(data)
    resource = getattr(model.pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if resource is None:
        raise PEError("image has no resource directory")
    deepest = _nth_resource_dir(resource, 1)
    if not deepest.entries:
        raise PEError("deepest resource directory has no entries")
    target = deepest.entries[0].struct
    offset = target.get_file_offset() + 4
    bogus_offset = 0x80000000 | 0x00100000
    struct.pack_into("<I", model.data, offset, bogus_offset)
    record = _record(
        "break_resource_depth",
        [SemanticChange.SUSPICIOUS_DIAGNOSTIC],
    )
    record.broken_constraint = (
        "resource nesting depth <= MAX_RESOURCE_DEPTH and offsets resolve"
    )
    record.dependent_fields.append(
        FieldRef("file_offset", offset, "leaf entry marked as nested directory")
    )
    record.expected_invariants.append(
        "parser must emit a resource-depth/parse warning, not crash"
    )
    record.summary = "resource leaf converted into bogus nested directory"
    return model.bytes(), record
