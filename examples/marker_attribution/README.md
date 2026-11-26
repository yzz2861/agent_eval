# Observable marker attribution demo

This directory contains a reproducible forensic attribution scenario.

- `program_a.elf` and `program_b.elf` are ordinary x86-64 `ET_EXEC` programs.
  They start from normal linked pyelftools test binaries; `build_demo.py`
  appends a non-allocated `.note.obs` section and relocates the section header
  table without changing the existing `PT_LOAD` mappings.
- `manifest.json` is the external pre-release attribution checklist.
- `report.json` is the generated static audit result.

Rebuild the ELF fixtures and manifest:

```sh
python examples/marker_attribution/build_demo.py
```

Run the audit from the repository root:

```sh
python marker_audit.py \
  examples/marker_attribution/program_a.elf \
  examples/marker_attribution/program_b.elf \
  --manifest examples/marker_attribution/manifest.json \
  --output examples/marker_attribution/report.json
```

The custom note owner is the asserted provider and `n_type` is
`0x4f425301`. Its descriptor is JSON with `name`, `address`, and optional
`size` fields. The auditor also understands an `OBS1` binary descriptor and
key/value text descriptors.

In the checked-in scenario:

- `boot.attested` has the same mapped coordinate and approved Acme attribution
  in both programs.
- `release.gate` has an approved Release Ops attribution in `program_b.elf`.
- Acme's `heartbeat` occurrences are approved exact matches, but the name also
  appears at a second location from Beta Driver.
- Acme's `trace.flush` occurrence in `program_a.elf` is approved, while the
  Beta Tracing occurrence in `program_b.elf` creates a name/location/provider
  conflict.
- `telemetry.dma` points outside every mapping; `runtime.watermark` points into
  `.bss` zero-fill and therefore has no file-backed offset.
- `shadow.event` and `debug.probe` are absent from the external manifest.
