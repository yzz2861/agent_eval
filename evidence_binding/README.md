# Read-only registry evidence binding

This package supports a forensic binding check over a case bundle that mixes
three kinds of registry material:

- live storage: primary hive files as found on the live store;
- log copies: primary hives together with SYSTEM.LOG1 / SYSTEM.LOG2 transaction logs;
- case file excerpts: standalone JSON manifests containing registry records saved separately from any hive.

Every byte-level operation runs on in-memory copies. Source files are only
opened for reading; transaction-log recovery is applied to a BytesIO buffer
and the recovered view is never written back over an evidence file.

## Binding rules

Two record occurrences are placed in the same exhibit only when a provable source chain links them.

1. A live hive and its in-memory recovered view form one hive family. Inside a
   family, the cell offset identifies a record, so the live and recovered
   occurrences of the same NK/VK cell bind into one exhibit.
2. An excerpt joins an existing exhibit only when it carries full provenance
   (source SHA-256, hive sequence numbers, record kind and absolute offset) and
   that claim resolves to a delivered source file and an existing cell whose
   content fingerprint matches.
3. Content-only excerpts never bind. Two excerpts with identical content but no
   common-source proof stay as two separate exhibits, and identical records found
   in byte-different hives stay separate as well.
4. Allocated cells that cannot be reached from the live root key are reported
   with reachability = unreachable so their weak provenance is visible.

## Excerpt manifest schema

Excerpts are JSON files identified by `manifest_type: registry-excerpt/v1`. Each record may embed a provenance block. The required provenance fields are:

- source_sha256, source_sequence1, source_sequence2
- record_absolute_offset_hex, record_relative_offset_hex, record_kind

A record without the provenance block (or with required fields missing) is graded
`content_only` and always opens its own exhibit.

## Output: two-generation directory

```
<output>/
    index.json            # machine-readable global index
    index.txt             # human-readable summary
    exhibits/
        EXH-001/
            locations.json
            locations.txt
        EXH-002/
            ...
```

The first generation is the output root with its index; the second generation is
one directory per exhibit. Each locations.txt spells out the bundle path, artifact
kind, absolute and hive-relative offsets, reachability, provenance grade, the
layer-by-layer citation chain (REGF header, HBIN, cell, NK/VK record, data cell) and
any binding blockers.

## Usage

`python -m evidence_binding.cli <case_bundle_dir> <output_dir>`

The casework/ directory contains reproducible builders and ready-made bundles/outputs:

- build_demo_bundle.py: compact bundle of three small hives plus full and content-only excerpts;
- build_log_recovery_bundle.py: separate SYSTEM + LOG1/LOG2 recovery set, kept apart so the default output directory stays small.
