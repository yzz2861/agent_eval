"""Command line entry point for read-only field attribution audits."""

from __future__ import annotations

import argparse
import json

from .audit import classify_fields
from .model import AuditTable, VerdictKind


def _parse_table(spec: str) -> AuditTable:
    parts = spec.split(":")
    if len(parts) != 5:
        raise argparse.ArgumentTypeError(
            "table spec must be name:section:width:start:count, e.g. ftab:.rodata:4:0:3"
        )
    name, section, width, start, count = parts
    return AuditTable(
        range_name=name,
        section_name=section,
        field_width=int(width),
        start_field=int(start),
        field_count=int(count),
    )


KIND_MARK = {
    VerdictKind.PROVEN: "PROVEN  ",
    VerdictKind.CANDIDATE: "CANDIDAT",
    VerdictKind.GAP: "GAP     ",
}

def _render_text(results) -> str:
    lines: list[str] = []
    for result in results:
        title = result.source
        lines.append(f"== {title} ==")
        lines.append(f"machine={result.machine} class={result.elf_class} endian={result.endianness} arch_supported={result.arch_supported}")
        lines.append(f"read-only audit; relocations_applied={False}")
        for table in result.tables:
            lines.append(f"range {table.range_name}: section={table.section_name} width={table.field_width} slots=[{table.start_field}..{table.start_field + table.field_count - 1}]")
        for overlap in result.overlaps:
            lines.append(f"OVERLAP: {overlap.detail}")
        for warning in result.warnings:
            lines.append(f"note: {warning}")
        for verdict in result.fields:
            marker = KIND_MARK[verdict.kind]
            lines.append(
                f"  [{marker}] slot={verdict.field_index} {verdict.section_name}+{verdict.section_offset:#x}"
                f" width={verdict.width} raw=0x{verdict.raw_bytes_hex}"
            )
            for reason in verdict.reasons:
                lines.append(f"             - {reason}")
            for evidence in verdict.relocations:
                addend = "n/a" if evidence.addend is None else str(evidence.addend)
                lines.append(
                    f"             * {evidence.form.value} {evidence.reloc_section}[{evidence.entry_index}]"
                    f" r_offset={evidence.r_offset:#x} type={evidence.r_info_type_name}"
                    f" symidx={evidence.symbol_index} sym={evidence.symbol_name!r} addend={addend} ({evidence.addend_source})"
                )
            if verdict.overlaps:
                joined = ", ".join(verdict.overlaps)
                lines.append(f"             ! also claimed by ranges: {joined}")
        lines.append(f"summary={result.summary()}")
        lines.append("")
    return "\n".join(lines)

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Read-only ELF function-table field attribution audit")
    parser.add_argument("path", help="path to a relocatable .o or an ar .a archive")
    parser.add_argument(
        "-t", "--table", action="append", required=True, type=_parse_table,
        help="analyst range spec name:section:width:start:count (repeatable)"
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    results = classify_fields(args.path, args.table)
    if args.json:
        print(json.dumps([r.to_dict() for r in results], indent=2, ensure_ascii=False))
    else:
        print(_render_text(results))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
