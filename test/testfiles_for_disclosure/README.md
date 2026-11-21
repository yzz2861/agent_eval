# Disclosure-audit fixtures

These two ELF relocatable objects are intentionally tiny and are consumed
by `test/test_elf_disclosure.py` and `scripts/elf_disclosure.py`.

- `approved.elf`: one `ET_REL` object with `public_api` in `.text` and a
  single DWARF compile unit, `public_unit.c`. Under `policy.json` it passes.
- `leaky.elf`: built from `#line 1 "secret_impl.c"` with line-tables-only
  DWARF. Every symbol name and the `STT_FILE` name were erased, and the
  referenced name bytes in `.strtab` were zeroed. The `.debug_line` table
  still contains `secret_impl.c`, so the file cannot pass disclosure review.

`policy.json` allows only `public_api`, `public_unit.c`, and `leaky_unit.c`.
The leaky object keeps `leaky_unit.c` as its approved compile unit, which
makes the `secret_impl.c` row an indirect, unapproved source reference.

Reproduction used clang with an x86-64 Linux target:

```
clang --target=x86_64-unknown-linux-gnu -g -O0 \
  -fdebug-compilation-dir=/build -c public_unit.c -o approved.elf
clang --target=x86_64-unknown-linux-gnu -gline-tables-only -O0 \
  -fdebug-compilation-dir=/build -c leaky_unit.c -o leaky.elf
```

The leaky binary was then edited in place to zero every symbol `st_name`,
its referenced `.strtab` bytes, and the `STT_FILE` name only. Section names
and all DWARF sections were left intact.
