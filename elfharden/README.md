
## Verdict statuses

- `pass` - positive hardening evidence found in the authoritative view(s)
- `fail` - an authoritative view explicitly shows the weak setting
- `partial` - RELRO region exists but immediate binding is not requested
- `conflict` - two legal views imply different verdicts; both are retained
- `indeterminate` - not enough evidence to decide (no convention-based guess)
- `not_applicable` - rule does not apply, e.g. bind timing on a static image

## Evidence ranges

Every evidence record carries a `file_range` (`start`/`size`/`end`) pointing
at the exact bytes backing the conclusion, plus a `memory_range` for loadable
segment/section views and the originating `view`. Memory-only segments such as
`PT_GNU_STACK` (`p_filesz == 0`) cite the program-header entry itself so the
conclusion still names a real file interval. Dynamic tags cite their own
`Elf_Dyn` entry, which lets the report distinguish a segment dynamic table
from a section dynamic table at different offsets.

## Minimal byte fixtures

`elfharden.builder` hand-assembles sub-1 KiB ELF64 little-endian images with
`struct` (no toolchain). `fixture_pair()` returns two artifacts that share
identical section declarations and payload while their program headers select
different load views:

- `tests/fixtures/declared_strict_view.elf` - NX stack, `PT_GNU_RELRO`,
  BIND_NOW via the dynamic table the segment points at
- `tests/fixtures/declared_lax_view.elf` - same sections, but executable
  `PT_GNU_STACK`, no `PT_GNU_RELRO`, and a segment dynamic table without
  BIND_NOW; the section view still declares the strict table

The lax fixture therefore yields `conflict` for stack and bind timing and
`indeterminate` for RELRO, demonstrating that disagreements are surfaced
rather than guessed away.

## CLI

```sh
python -m elfharden --rule relro --rule bind_now path/to/binary
python -m elfharden binary1 binary2   # multiple files emit a JSON array
```

## Local regression

```sh
TMPDIR=<writable-tmp> ./run_local_regression.sh
```

The runner stages the package and tests into a writable temp directory and
links the in-tree `elftools` and real ELF corpus, so nothing is installed and
no binary under test is executed. The same tests also run under plain pytest
where parent-directory traversal is permitted.
