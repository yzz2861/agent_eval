"""Readable rendering of analysis results (text and Markdown)."""

from __future__ import annotations

from .model import EvidenceKind, LEVEL_DESCRIPTIONS


KIND_SHORT = {
    EvidenceKind.FILE_POINTER: "FILE",
    EvidenceKind.INDEX_ONLY: "IDX",
    EvidenceKind.RUNTIME_UNRESOLVED: "RT",
}


def kind_counts(result):
    counts = {kind: 0 for kind in EvidenceKind}
    for _module, _symbol, node in result.walk_evidence():
        counts[node.kind] += 1
    return counts


def level_name(level):
    return level.value + " - " + LEVEL_DESCRIPTIONS[level]


def render_text(result):
    lines = []
    lines.append("Read-only delay-load evidence view: " + result.source)
    lines.append("machine=" + result.machine + " fragment=" + str(result.is_fragment))
    counts = kind_counts(result)
    lines.append("evidence totals: " + ", ".join(
        kind.value + "=" + str(counts[kind]) for kind in EvidenceKind))
    if result.removed_targets:
        lines.append("removed targets: " + ", ".join(result.removed_targets))
    lines.append("")
    for module in result.modules:
        header = "MODULE " + module.dll + " (descriptor RVA 0x%x)" % module.descriptor_rva
        lines.append(header)
        for node in module.module_evidence:
            flag = "REMOVED " if node.removed else ""
            lines.append("  " + flag + node.level.value + " [" + KIND_SHORT[node.kind] + "] " + node.location + " = " + node.format_value())
            lines.append("      " + node.detail)
        for symbol in module.symbols:
            if symbol.still_viable:
                status = "VIABLE"
            else:
                status = "BROKEN@" + symbol.broken_level.value
            lines.append("  SYMBOL " + symbol.symbol + " -> " + status)
            for node in symbol.chain:
                flag = "REMOVED " if node.removed else ""
                lines.append("    " + flag + node.level.value + " [" + KIND_SHORT[node.kind] + "] " + node.location + " = " + node.format_value())
                lines.append("        " + node.detail)
        lines.append("")
    if result.warnings:
        lines.append("warnings:")
        lines.extend("  - " + item for item in result.warnings)
    return chr(10).join(lines)


def _row(node):
    prefix = "REMOVED: " if node.removed else ""
    return ("| " + prefix + node.level.value + " | " + node.kind.value + " | `"
            + node.location + "` | `" + node.format_value() + "` | " + node.detail + " |")


def render_markdown(result):
    lines = []
    lines.append("# Read-only delay-load evidence view")
    lines.append("")
    lines.append("- source: `" + result.source + "`")
    lines.append("- machine: `" + result.machine + "`")
    lines.append("- fragment input: `" + str(result.is_fragment) + "`")
    if result.image_base is not None:
        lines.append("- image base: `0x%x`" % result.image_base)
    counts = kind_counts(result)
    lines.append("")
    lines.append("## Evidence classification totals")
    lines.append("")
    lines.append("| Class | Count | Meaning |")
    lines.append("| --- | ---: | --- |")
    meanings = {
        EvidenceKind.FILE_POINTER: "target pointer physically present in the file",
        EvidenceKind.INDEX_ONLY: "table slot keeps an ordinal/index only",
        EvidenceKind.RUNTIME_UNRESOLVED: "filled by the loader, not provable statically",
    }
    for kind in EvidenceKind:
        lines.append("| " + kind.value + " | " + str(counts[kind]) + " | " + meanings[kind] + " |")
    if result.removed_targets:
        lines.append("")
        lines.append("## Removal simulation")
        lines.append("")
        lines.append("Removed target(s): `" + ", ".join(result.removed_targets) + "`")
    lines.append("")
    lines.append("## Transfer-path evidence")
    for module in result.modules:
        lines.append("")
        lines.append("### " + module.dll)
        lines.append("")
        lines.append("Descriptor RVA: `0x%x`" % module.descriptor_rva)
        lines.append("")
        lines.append("| Level | Class | Location | Value | Detail |")
        lines.append("| --- | --- | --- | --- | --- |")
        for node in module.module_evidence:
            lines.append(_row(node))
        for symbol in module.symbols:
            if symbol.still_viable:
                verdict = "viable"
            else:
                verdict = "loses proof at " + symbol.broken_level.value
            lines.append("")
            lines.append("#### symbol `" + symbol.symbol + "` -> " + verdict)
            lines.append("")
            lines.append("| Level | Class | Location | Value | Detail |")
            lines.append("| --- | --- | --- | --- | --- |")
            for node in symbol.chain:
                lines.append(_row(node))
    if result.warnings:
        lines.append("")
        lines.append("## Warnings")
        lines.append("")
        lines.extend("- " + item for item in result.warnings)
    return chr(10).join(lines)


def render_removal_summary(result, broken_levels):
    lines = []
    lines.append("")
    lines.append("## Removal verdict")
    lines.append("")
    if broken_levels:
        lines.append("First transfer-path level that loses its proof:")
        for level in broken_levels:
            lines.append("- `" + level.value + "` - " + LEVEL_DESCRIPTIONS[level])
    else:
        lines.append("No evidence chain was broken by this removal.")
    lines.append("")
    lines.append("Dependencies still provable after removal:")
    viable = []
    for module in result.modules:
        for symbol in module.viable_symbols:
            viable.append(module.dll + " -> " + symbol.symbol)
    if viable:
        lines.extend("- `" + item + "`" for item in viable)
    else:
        lines.append("- none")
    return chr(10).join(lines)
