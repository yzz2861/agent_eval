# Offline system-library dependency audit

`elftools.elf.syslib_audit` cross-checks three things for firmware ELF inputs:

1. dynamic dependencies from `DT_NEEDED`, `DT_SONAME`, `DT_RPATH`, and
   `DT_RUNPATH`;
2. GNU symbol-version requirements from `SHT_GNU_verneed`, plus the concrete
   undefined symbols and versions from `SHT_GNU_versym`;
3. a caller-supplied loader environment declaration containing hardware
   images, loader search paths, and provider evidence.

The module is static and offline. It parses the input ELF as data. Paths
named in provider declarations are metadata only: the audit never opens,
maps, executes, or dynamically loads them. A missing provider is therefore
reported as missing evidence, not as a fallback filesystem lookup.

## Command line

```sh
python scripts/syslib_audit.py ARTIFACT.elf [ARTIFACT.elf ...] \
    --environment ENVIRONMENT.json
python -m elftools.elf.syslib_audit ARTIFACT.elf -e ENVIRONMENT.json --format text
```

The JSON report is written to standard output unless `-o FILE` is used.
The exit code is 0 when every dependency is signed off, 1 for invalid input,
and 2 when at least one dependency needs evidence.

## Environment declaration

```json
{
  "schema": "elf-syslib-env/v1",
  "id": "fleet-image-set",
  "hardware_images": [
    {
      "id": "hw-borealis",
      "arch": "x86_64",
      "elf_class": 64,
      "endianness": "little",
      "search_paths": ["/opt/fleet/hw-borealis/lib"]
    }
  ],
  "target_images": ["hw-borealis"],
  "loader": {
    "search_paths": ["/opt/fleet/hw-borealis/lib", "/opt/fleet/lib"]
  },
  "providers": [
    {
      "soname": "libz.so.1",
      "provider": "zlib",
      "version": "1.2.13",
      "path": "/opt/fleet/hw-borealis/lib/libz.so.1",
      "images": ["hw-borealis"],
      "arch": "x86_64",
      "elf_class": 64,
      "endianness": "little",
      "symbol_versions": ["ZLIB_1.2.3.5"],
      "evidence": {"source": "system manifest", "verified": true},
      "priority": 10
    }
  ]
}
```

`providers` may also be written as a `libraries` mapping from soname to one
candidate or a list of candidates. Images may be a list or a mapping. Common
aliases such as `name`, `file`, `release`, `exported_versions`,
`hardware_images`, and `ld_library_path` are accepted.

## Matching and candidate retention

A provider is eligible for a dependency only when all of these hold:

- its soname equals the `DT_NEEDED` name;
- it is available on the target hardware image, if it declares images;
- architecture, ELF class, and endianness are compatible when declared;
- it is not explicitly marked unverified;
- every required symbol version is present in its declared version evidence;
- when the declaration lists individual exported symbols, every required
  `symbol@version` pair is present.

All candidates are retained in the report, including candidates that were
rejected and the reason for rejection. This includes multiple provider
versions of the same soname. The selected candidate is recorded in
`selected` when there is one target image, and in `selected_by_image` for
multi-image audits.

Selection order is deterministic:

1. candidates marked `preferred`, `default`, `selected`, or `pin`;
2. an environment `preferred` entry matching id, version, path, or basename;
3. lower numeric `priority` (or `rank`/`order`);
4. earlier loader search path;
5. newer provider version;
6. path, then candidate id.

## Image-specific dependencies

If every declared candidate for a dependency is restricted to hardware
images, the union of those images is reported in
`candidate_hardware_images`. The dependency is marked `image_specific` when
that union is narrower than the environment image set, and the narrower
union is then also reported in `only_on_hardware_images`. If the current target
image is outside the union, the dependency needs evidence for that image and
the artifact is not signed off.

## Report statuses

Each dependency and artifact has a status of `signed_off` or
`pending_evidence`. Missing external libraries carry
`external: true`, `evidence_missing: true`, an empty candidate list, and a
reason stating that no library path was opened.

When requesters need the machine-oriented form, `audit()`,
`audit_elf()`, `audit_manifest()`, and `audit_artifacts()` return the same
schema as the CLI.
