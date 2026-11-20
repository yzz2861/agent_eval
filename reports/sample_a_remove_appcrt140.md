# Read-only delay-load evidence view

- source: `sample_a_generation_v1.dll`
- machine: `IMAGE_FILE_MACHINE_AMD64`
- fragment input: `False`
- image base: `0x140000000`

## Evidence classification totals

| Class | Count | Meaning |
| --- | ---: | --- |
| FILE_POINTER | 6 | target pointer physically present in the file |
| INDEX_ONLY | 0 | table slot keeps an ordinal/index only |
| RUNTIME_UNRESOLVED | 3 | filled by the loader, not provable statically |

## Removal simulation

Removed target(s): `appcrt140.dll`

## Transfer-path evidence

### kernel32.dll

Descriptor RVA: `0x210b`

| Level | Class | Location | Value | Detail |
| --- | --- | --- | --- | --- |
| L2_DELAY_DESCRIPTOR | FILE_POINTER | `IMAGE_DELAYLOAD_DESCRIPTOR.szName` | `0x200e` | file-resident RVA of the DLL name string |
| L7_MODULE_HANDLE_SLOT | RUNTIME_UNRESOLVED | `IMAGE_DELAYLOAD_DESCRIPTOR.phmod` | `0x3148` | phmod names a .data slot; the loader writes the module base at first load, no target is provable from the file |
| L6_UNLOAD_IAT | FILE_POINTER | `IMAGE_DELAYLOAD_DESCRIPTOR.pUnloadIAT` | `0x20d3` | file-resident RVA of the unload (clean copy) IAT |

#### symbol `Sleep` -> viable

| Level | Class | Location | Value | Detail |
| --- | --- | --- | --- | --- |
| L3_NAME_TABLE | FILE_POINTER | `INT[0]` | `0x202c` | file-resident RVA to hint/name blob (hint=0, name='Sleep') |
| L4_THUNK_TABLE | FILE_POINTER | `IAT[0]` | `0x202c` | file-resident value (typically a copy of the INT hint/name RVA) |
| L9_CODE_REFERENCE | RUNTIME_UNRESOLVED | `no relocation for IAT slot 0x20bb` | `-` | no static relocation; the runtime helper resolves the slot on demand, caller binding is not file-provable |

#### symbol `GetLastError` -> viable

| Level | Class | Location | Value | Detail |
| --- | --- | --- | --- | --- |
| L3_NAME_TABLE | FILE_POINTER | `INT[1]` | `0x2034` | file-resident RVA to hint/name blob (hint=0, name='GetLastError') |
| L4_THUNK_TABLE | FILE_POINTER | `IAT[1]` | `0x2034` | file-resident value (typically a copy of the INT hint/name RVA) |
| L9_CODE_REFERENCE | RUNTIME_UNRESOLVED | `no relocation for IAT slot 0x20c3` | `-` | no static relocation; the runtime helper resolves the slot on demand, caller binding is not file-provable |
## Removal verdict

First transfer-path level that loses its proof:
- `L2_DELAY_DESCRIPTOR` - IMAGE_DELAYLOAD_DESCRIPTOR for one delay-loaded DLL

Dependencies still provable after removal:
- `kernel32.dll -> Sleep`
- `kernel32.dll -> GetLastError`