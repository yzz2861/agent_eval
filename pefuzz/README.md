# pefuzz — structure-preserving fuzzing for pefile

`pefuzz` addresses the problem where a fuzz corpus mostly fails at the DOS
header and never reaches the deep PE data directories.  It builds fully
synthetic, sub-4KB PE32 images and mutates them while keeping the image
internally consistent, so the pefile parser keeps walking into the export,
import, three-level resource, debug and relocation directories.

## Modules

- `builder.py` — deterministic mini-PE generator (exports, two-DLL imports,
  three-level resource tree, debug entries, base relocations).
- `model.py` — mutable byte-buffer model with RVA/offset mapping, typed
  anchors, reference scanning and section/payload relocation.
- `mutators.py` — structure-preserving mutators and single-constraint
  breakage modes.  Every call returns a `MutationRecord`.
- `records.py` — `MutationRecord`, `FieldRef`, and the `SemanticChange`
  categories a transformation is allowed to produce.
- `compare.py` — coordinate-tolerant semantic diff of two parse results.
  Import/export semantics, the resource tree, debug/reloc counts and parser
  warnings are compared strictly.
- `coverage.py` — `sys.settrace` based counter of which directory parsers
  run and how deep the recursive resource parser nests.
- `reducer.py` — delta-debugging reduction that removes directories,
  sections and trailing slack while preserving the deep-path fingerprint.
- `harness.py` — fixed-seed, offline generator of the full fuzz case set.

## Structure-preserving mutations

- `move_section_raw` — relocate a section raw blob and fix its pointer.
- `move_directory_payload` — move a directory payload across sections,
  rewriting every RVA reference and the directory header.
- `replace_import_name` — rename an imported symbol inside its existing
  slot (no coordinate movement).
- `reorder_import_descriptors`, `reorder_resource_entries`,
  `reorder_debug_entries` — reorder dependency-free directory entries.

## Single-constraint breakage modes

`break_dos_magic`, `break_section_raw_pointer`, `break_directory_rva`,
`break_import_name_rva`, and `break_resource_depth` each violate exactly
one constraint and record it in `MutationRecord.broken_constraint`.

## Running the offline regression suite

```
python run_offline_tests.py
```

The suite uses only synthetic images and a fixed RNG seed, performs no
network access, and finishes in well under thirty seconds.  Use
`python generate_replay_sample.py` to (re)write `tests/replay_defect.bin`,
a sub-4KB replayable defect that still reaches the deep resource path.
