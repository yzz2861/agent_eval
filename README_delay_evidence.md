# Read-only PE delay-load evidence view

A static, loader-free reverse-engineering view of the delay-load transfer
path. It reads a PE file (or a raw byte fragment / local dump) and lists the
structures that prove how a delay-loaded DLL is reached, classifying every
piece of evidence into one of three buckets.

## Evidence classes

- `FILE_POINTER` - a target pointer physically present in the file bytes
  (directory entries, descriptor RVAs, hint/name pointers, bind-time VA,
  guard table entries). The file proves the target on its own.
- `INDEX_ONLY` - a table slot that keeps only an ordinal/index; the table
  position is provable but the resolved target is not.
- `RUNTIME_UNRESOLVED` - produced by the loader at process start
  (`phmod` module base, patched IAT value, indirect guard pointer target,
  delay IAT slots without a static relocation). Cannot be explained from
  the file alone.

## Transfer-path levels

L1 data directory -> L2 delay descriptor -> L3 Import Name Table ->
L4 Import Address Table -> L5 Bound IAT -> L6 Unload IAT ->
L7 module handle slot -> L8 load-config guard structures ->
L9 code references (base relocations).

## Safety

The package never invokes the operating system loader. It only parses bytes
with the bundled `pefile` library and `struct`. A test asserts that no
`ctypes`, `subprocess`, `dlopen` or `winreg` import exists in the package.

## CLI

```sh
# analyze a full PE
python -m delay_evidence view path/to/image.dll

# analyze a raw fragment (requires the RVA of its first byte)
python -m delay_evidence view fragment.bin --base-rva 0x2000

# simulate removing one transfer target and report the level that loses proof
python -m delay_evidence remove image.dll appcrt140.dll
python -m delay_evidence remove image.dll "appcrt140.dll!#1234"

# compare two PEs that bind the same DLL name differently
python -m delay_evidence compare left.dll right.dll
```

All commands accept `--format markdown --output report.md`.

## Removal semantics

Removal is purely logical: the input bytes are never modified. Evidence
belonging to the target is flagged removed, and the report states the first
transfer-path level at which the chain loses its proof. Other already
confirmed dependencies stay viable, which demonstrates exactly which level
broke.

## Samples and tests

Synthetic, fully parseable PE32+ images are built in pure Python
(`delay_evidence/sample_builder.py`); no external toolchain is needed.
Regenerate the sample corpus with:

```sh
python -m delay_evidence.make_samples
python run_tests.py
```

`run_tests.py` is a sandbox-safe runner used because pytest walks parent
directories that this restricted workspace cannot read. On a normal machine
`python -m pytest tests` runs the same pytest-style suite unchanged.
