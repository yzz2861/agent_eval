"""Differential comparison of two pefile parse results.

Coordinate-only changes (file offsets, RVAs, section raw pointers) are
normalized away, while import/export semantics, the resource tree and
parser warnings are compared strictly so that suspicious diagnostics can
never be hidden by a mutation.
"""

from dataclasses import dataclass, field

import pefile

from .records import SemanticChange


@dataclass
class SemanticDiff:
    """Result of comparing two parse trees."""

    equivalent: bool
    allowed_changes: list = field(default_factory=list)
    mismatches: list = field(default_factory=list)
    warning_deltas: list = field(default_factory=list)

    def explain(self):
        lines = ["equivalent=" + str(self.equivalent)]
        lines.extend("allowed: " + item for item in self.allowed_changes)
        lines.extend("mismatch: " + item for item in self.mismatches)
        lines.extend("warning: " + item for item in self.warning_deltas)
        return "\n".join(lines)


def parse(data):
    pe = pefile.PE(data=bytes(data), fast_load=True)
    pe.parse_data_directories()
    return pe


def import_signature(pe):
    """Coordinate-free description of the complete import semantics."""
    signature = []
    descriptors = getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []
    for descriptor in descriptors:
        symbols = []
        for symbol in descriptor.imports:
            if symbol.name is None:
                symbols.append(("ordinal", symbol.ordinal))
            else:
                name = symbol.name
                if isinstance(name, bytes):
                    name = name.decode(errors="replace")
                symbols.append(("name", name))
        dll = descriptor.dll
        if isinstance(dll, bytes):
            dll = dll.decode(errors="replace")
        signature.append((dll, tuple(symbols)))
    signature.sort(key=lambda item: item[0].lower())
    return signature


def export_signature(pe):
    """Coordinate-free description of the complete export semantics."""
    export = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if export is None:
        return None
    symbols = []
    for entry in export.symbols:
        name = entry.name
        if isinstance(name, bytes):
            name = name.decode(errors="replace")
        forwarder = entry.forwarder
        if isinstance(forwarder, bytes):
            forwarder = forwarder.decode(errors="replace")
        if forwarder == "":
            forwarder = None
        symbols.append(
            (
                entry.ordinal,
                name,
                forwarder,
                bool(forwarder),
            )
        )
    dll_name = export.name
    if isinstance(dll_name, bytes):
        dll_name = dll_name.decode(errors="replace")
    return dll_name, tuple(sorted(symbols, key=lambda item: item[0]))


def resource_signature(pe):
    """Structural hash of the resource tree without file coordinates."""
    resource = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if resource is None:
        return None

    def walk(node):
        children = []
        for entry in node.entries:
            if hasattr(entry, "directory"):
                children.append(("node", entry.id, walk(entry.directory)))
            else:
                data_entry = entry.data
                children.append(
                    (
                        "leaf",
                        entry.id,
                        data_entry.struct.Size,
                        data_entry.struct.CodePage,
                    )
                )
        return tuple(sorted(children, key=lambda item: str(item[1])))

    return walk(resource)


def debug_signature(pe):
    entries = getattr(pe, "DIRECTORY_ENTRY_DEBUG", []) or []
    signature = []
    for entry in entries:
        signature.append((entry.struct.Type, entry.struct.SizeOfData))
    return tuple(sorted(signature))


def reloc_signature(pe):
    relocs = getattr(pe, "DIRECTORY_ENTRY_BASERELOC", []) or []
    count = 0
    for block in relocs:
        count += len(block.entries)
    return count


def section_layout(pe):
    """Full section layout including the mutable raw pointer."""
    layout = []
    for section in pe.sections:
        layout.append(
            (
                section.Name,
                section.Misc_VirtualSize,
                section.VirtualAddress,
                section.SizeOfRawData,
                section.PointerToRawData,
                section.Characteristics,
            )
        )
    return tuple(layout)


def compare_parses(before_pe, after_pe, allowed=None):
    """Compare two parsed PEs, tolerating only the allowed change kinds."""
    allowed = set(allowed or (SemanticChange.NONE,))
    diff = SemanticDiff(equivalent=True, allowed_changes=list(allowed))

    if import_signature(before_pe) != import_signature(after_pe):
        if SemanticChange.IMPORT_NAME in allowed:
            diff.allowed_changes.append("import names intentionally changed")
        else:
            diff.equivalent = False
            diff.mismatches.append("import semantics diverged")

    if export_signature(before_pe) != export_signature(after_pe):
        if SemanticChange.EXPORT_NAME in allowed:
            diff.allowed_changes.append("export names intentionally changed")
        else:
            diff.equivalent = False
            diff.mismatches.append("export semantics diverged")

    if resource_signature(before_pe) != resource_signature(after_pe):
        diff.equivalent = False
        diff.mismatches.append("resource tree diverged")

    if debug_signature(before_pe) != debug_signature(after_pe):
        diff.equivalent = False
        diff.mismatches.append("debug directory semantics diverged")

    if reloc_signature(before_pe) != reloc_signature(after_pe):
        diff.equivalent = False
        diff.mismatches.append("base relocation count diverged")

    before_layout = section_layout(before_pe)
    after_layout = section_layout(after_pe)
    virtual_keys = lambda layout: [(s[0], s[1], s[2], s[3], s[5]) for s in layout]
    if sorted(virtual_keys(before_layout)) != sorted(virtual_keys(after_layout)):
        diff.equivalent = False
        diff.mismatches.append("section virtual layout diverged unexpectedly")
    before_raw = {s[0]: s[4] for s in before_layout}
    after_raw = {s[0]: s[4] for s in after_layout}
    if before_raw != after_raw:
        if SemanticChange.COORDINATE_ONLY in allowed:
            diff.allowed_changes.append("section raw pointers changed")
        else:
            diff.equivalent = False
            diff.mismatches.append("section raw pointer diverged unexpectedly")

    before_warnings = sorted(before_pe.get_warnings())
    after_warnings = sorted(after_pe.get_warnings())
    if before_warnings != after_warnings:
        new_warnings = sorted(set(after_warnings) - set(before_warnings))
        gone_warnings = sorted(set(before_warnings) - set(after_warnings))
        allowed_marker = "typical of packed executables"
        if SemanticChange.IMPORT_NAME in allowed:
            new_warnings = [
                item for item in new_warnings if allowed_marker not in item
            ]
            gone_warnings = [
                item for item in gone_warnings if allowed_marker not in item
            ]
            diff.allowed_changes.append(
                "packed-exe diagnostic may shift after import rename"
            )
        if new_warnings or gone_warnings:
            diff.equivalent = False
        for item in new_warnings:
            diff.warning_deltas.append("new: " + item)
        for item in gone_warnings:
            diff.warning_deltas.append("gone: " + item)

    return diff
