# Offline address attribution

This document describes the offline attribution path built on pyelftools. It is
intended for crash platforms that receive a runtime address and must decide
which supplied symbol package produced the reported source file and line.

The implementation is in `elftools/elf/address_attribution.py`. The command-line
entry point is `scripts/attribute_address.py`.

## Why the caller supplies everything

The input to this path is deliberately explicit:

* the module ELF (not an auto-discovered file and not a core dump);
* every external debug ELF that may be considered, including same-named files
  from different packages;
* one or more instance load mappings;
* the runtime addresses to attribute.

The tool does not search the filesystem for `.gnu_debuglink` targets, does not
pick a debug file because its name matches, and does not use the network. This
prevents a stale or wrong package from becoming authoritative merely because
the crash platform guessed its path.

## Identity materials

An external debug file is compared with the main ELF using the materials that
are actually present:

| Material | Result when both sides have it | Result when it is absent |
| --- | --- | --- |
| GNU build ID (`.note.gnu.build-id`) | Match is strong evidence; different values are an explicit contradiction | Recorded as missing evidence, not as a conflict |
| `.gnu_debuglink` filename and CRC32 | The CRC is checked only when the candidate basename matches the name in the main ELF; matching CRC is strong evidence, a different CRC is a contradiction | Recorded as missing/not applicable |
| Split-DWARF identity (`dwo_id`) | An overlap is strong evidence; disjoint non-empty sets are a contradiction | Recorded as missing evidence |
| ELF class, endianness, machine | A different value is a contradiction | Never invented when a header cannot be read |

The resulting per-file status is one of:

* `verified`: at least one strong material matches and no material contradicts.
* `conflict`: an available material explicitly disagrees.
* `unverified`: no contradiction was found, but no shared strong material was
  available, so line answers remain provisional.

Architecture equality alone is not enough to mark a file as verified, because
all packages for one firmware target normally share it.

## Load mappings

Two mapping forms are supported, and any number of either form may be supplied.
Each mapping is evaluated separately. Answers from different mappings are never
silently merged.

### Uniform load bias

`elf_vaddr = runtime_address - bias`

By default the translation is accepted only when the runtime address lies in one
of the main ELF's `PT_LOAD` spans after the bias is applied. If the main ELF has
no `PT_LOAD` spans, the mapping is marked unbounded and a diagnostic is emitted.

### Explicit regions

Each region supplies `runtime_start`, `runtime_end`, `elf_start`, and optionally
`elf_size`. A runtime address in `[runtime_start, runtime_end)` translates to:

`elf_start + (runtime_address - runtime_start)`

This form is appropriate for firmware whose segments are not loaded with a
single uniform bias. Overlapping regions are legal; the report keeps each
translation and its region label.

## Line tables

Line rows are read from:

* the main ELF when it has DWARF line data (`include_main` defaults to true);
* every explicitly supplied external debug file;
* normal `.debug_line` sections and GNU compressed `.zdebug_line` sections;
* split-DWARF `.debug_line.dwo` sections;
* standalone line units that are not referenced by any `.debug_info` CU.

This makes the path usable with separate debug packages, packages that contain
only line data, and trimmed packages that do not cover every address. A missing
row is reported as an evidence gap (`unresolved`), not as an identity conflict.

A row applies to the half-open range from its address to the next row address in
the same sequence. The `end_sequence` row is a boundary and is not returned as a
source line. If several rows share one address, each distinct file/line/column
answer is kept. An unterminated sequence is usable but marked in the candidate
source and note.

## Statuses returned per address

* `resolved`: at least one verified file/line answer exists and all verified
  answers agree.
* `ambiguous`: more than one verified file/line answer remains, for example two
  plausible mappings or two verified packages.
* `provisional`: only unverified candidates exist.
* `unresolved`: no usable candidate exists. The reason distinguishes an address
  outside every mapping, a mapped address with no line row, and an address for
  which only identity-conflicting candidates were found.

Candidates from `conflict` files are returned under `rejected_candidates`, not
under `candidates`. Each candidate carries:

* `file`, `path`, `line`, `column`, `discriminator`, `is_stmt`;
* `mapping` and `link_address`;
* `source` with artifact id/path, line section, line-program offset, CU offset,
  unit and sequence indexes, file index, compilation directory, and region;
* `trust`, `identity_status`, and `accepted`.

## Conflict records for the crash platform

The top-level `conflicts` array contains one record per external debug file
whose line data cannot be connected to the main ELF. A record contains:

* a stable `id`, `kind` (`identity_conflict` or `identity_unverified`), and
  severity;
* the artifact id, absolute path, basename, and the ids and paths of other
  files with the same basename (`same_basename_as` and
  `same_basename_artifacts`);
* the full identity comparison, including `contradictions` and `missing`;
* aggregate line-table statistics: units, rows, sequences, address span,
  covered bytes, and source files;
* `requested_address_coverage`, showing exactly which plausible file/line rows
  this file would have produced for the requested addresses and mappings.

The last field is the intended operator trail: an on-call engineer can see that
a same-named file has a complete-looking line table, see the precise rows it
would have returned, and still see that its build ID or CRC is disconnected.

The CLI can write these records separately with `--conflicts-out`, so the crash
platform can ingest them without re-parsing the full report.

## Request JSON

Paths in a request file are resolved relative to the directory containing that
file, not the process working directory.

```json
{
  "main_elf": "artifacts/firmware.elf",
  "debug_files": [
    {"path": "packages/A/debuglink.debug", "id": "package-A"},
    {"path": "packages/B/debuglink.debug", "id": "package-B"}
  ],
  "mappings": [
    {"name": "reported-base", "bias": "0x10000"},
    {
      "name": "alternate-base",
      "regions": [
        {"runtime_start": "0x11100", "runtime_end": "0x11200", "elf_start": "0x110f"}
      ]
    }
  ],
  "addresses": ["0x11149", "0x11157"]
}
```

## CLI

Using a request file:

```text
python scripts/attribute_address.py --config request.json --output report.json \
    --conflicts-out conflicts.json --strict
```

Using direct arguments:

```text
python scripts/attribute_address.py \
    --main firmware.elf \
    --debug packages/A/debuglink.debug \
    --debug packages/B/debuglink.debug \
    --bias reported=0x10000 \
    --region alternate=0x11100:0x11200:0x110f \
    --address 0x11149 \
    --output report.json
```

`--strict` exits with status 3 if any address is unresolved, provisional, or
ambiguous, or if a conflict record exists. Input errors exit with status 2.

## Python API

```python
from elftools.elf.address_attribution import (
    DebugFile, LoadMapping, attribute_addresses,
)

report = attribute_addresses(
    "firmware.elf",
    [
        DebugFile("packages/A/debuglink.debug", id="package-A"),
        DebugFile("packages/B/debuglink.debug", id="package-B"),
    ],
    [LoadMapping.from_bias("reported", 0x10000)],
    [0x11149, 0x11157],
)
payload = report.to_dict()
```

`request_from_config()` builds the same request from a JSON-compatible object,
and `AttributionReport.write_json()` writes the report.

## Current scope

The path attributes code addresses through line tables. It does not symbolize
inlined frames or recover a function name when no line row exists. For an
`ET_REL` input whose line rows are section-relative, the caller must provide a
mapping that accounts for the section placement; the tool does not invent a
link address.
