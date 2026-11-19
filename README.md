# elf_table_audit

Read-only field attribution auditing for firmware function tables stored in
relocatable ELF objects (.o) and ar archives of them. It replaces the old
byte-only inventory that treated not-yet-relocated slots as null references.

The analyst supplies the table section, field width and slot range; the tool
reads symbols and relocations through the pyelftools parsing layer and returns
evidence-backed verdicts. Nothing is loaded or executed, and no relocation is
ever applied to target memory.

## Verdicts

- proven: a relocation points at a named symbol; the reference is real even
  when the field bytes are all zero. An SHN_UNDEF symbol stays proven, with a
  separate note that link-time resolution is still pending.
- candidate: relocation evidence exists but cannot be proven here: an
  unnamed/special symbol index, or a machine outside the validated set.
- gap: no explaining relocation. Zero bytes mean genuinely empty; non-zero
  bytes without a relocation are reported as having no attribution basis.

Each verdict carries the relocation section name, entry index, r_offset, type,
symbol index/name/section and the addend together with its source.

## Relocation representations

Both common ELF forms are detected per relocation section.

- REL (e.g. EM_386): no inline addend; the addend lives in the field bytes.
- RELA (e.g. EM_X86_64): explicit r_addend.

## Supported architectures (first version)

EM_386 (32), EM_X86_64 (64), EM_ARM (32), EM_AARCH64 (64) and EM_RISCV (32/64).
Objects for other machines are still parsed read-only, but relocation-based
findings are downgraded to candidate with an architecture warning rather than
speculatively interpreted.

## Grouped records and overlapping ranges

Repeat -t to audit several named groups. When two analyst ranges claim the same
section bytes, an OVERLAP note names both ranges and the first shared offset,
and each affected field lists the other ranges claiming it.

## Usage

    python -m elf_table_audit path/to/module.o -t ftab:.rodata:4:0:3
    python -m elf_table_audit path/to/lib.a -t ftab:.rodata:4:0:3 --json

The spec is name:section:width:start_slot:slot_count. Field width must be one of
1, 2, 4 or 8 bytes.

## Read-only guarantee

Inputs are fully read into in-memory buffers and parsed via ELFFile over
io.BytesIO. The package contains no relocation application, no section loading
and no code execution; test_field_audit asserts the input bytes are unchanged.

## Three-slot micro objects

fixtures/micro_ftab_rel_i386.o (REL) and fixtures/micro_ftab_rela_x86_64.o
(RELA) each contain three slots:

1. zero bytes plus a relocation -> proven symbol reference;
2. zero bytes with no relocation -> genuinely empty gap;
3. non-zero bytes with no relocation -> unexplained evidence gap.
