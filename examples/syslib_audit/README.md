# Offline system-library audit example

The sample is a real versioned shared object that requires:

- `libz.so.1` with symbol version `ZLIB_1.2.3.5`
- `libc.so.6` with symbol versions `GLIBC_2.2.5` and `GLIBC_2.4`

Both environment declarations describe the fictional hardware images
`hw-atlas` and `hw-borealis`. Library paths in the declarations are fictional
and are never opened by the audit.

## Signed-off environment

```sh
python scripts/syslib_audit.py examples/syslib_audit/sample_versioned.so.elf \
    -e examples/syslib_audit/env_signed.json
```

Result: `signed_off`. Two candidates are retained for each soname:
`libz.so.1` 1.2.11 and 1.2.13, and `libc.so.6` 2.31 and 2.35. The loader
declaration selects `libz.so.1` 1.2.13 and `libc.so.6` 2.35. `libz.so.1` is
marked image-specific because every declared provider exists only on
`hw-borealis`.

The checked-in report is `report_signed.json`.

## Pending-evidence environment

```sh
python scripts/syslib_audit.py examples/syslib_audit/sample_versioned.so.elf \
    -e examples/syslib_audit/env_pending.json
```

This declaration targets `hw-atlas` and contains no `libz.so.1` provider
evidence. The same sample therefore returns `pending_evidence`: `libz.so.1`
is reported as missing evidence and is not opened, while `libc.so.6` still
keeps both candidates and the selected 2.35 provider.

The checked-in report is `report_pending.json`. The CLI exits 0 for a
signed-off report and 2 when evidence is missing.
