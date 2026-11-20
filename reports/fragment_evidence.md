# Read-only delay-load evidence view

- source: `delay_directory_fragment.bin`
- machine: `FRAGMENT`
- fragment input: `True`

## Evidence classification totals

| Class | Count | Meaning |
| --- | ---: | --- |
| FILE_POINTER | 5 | target pointer physically present in the file |
| INDEX_ONLY | 1 | table slot keeps an ordinal/index only |
| RUNTIME_UNRESOLVED | 2 | filled by the loader, not provable statically |

## Transfer-path evidence

### appcrt140.dll

Descriptor RVA: `0x20eb`

| Level | Class | Location | Value | Detail |
| --- | --- | --- | --- | --- |
| L2_DELAY_DESCRIPTOR | FILE_POINTER | `IMAGE_DELAYLOAD_DESCRIPTOR.szName` | `0x2000` | file-resident RVA of the DLL name string |
| L7_MODULE_HANDLE_SLOT | RUNTIME_UNRESOLVED | `IMAGE_DELAYLOAD_DESCRIPTOR.phmod` | `0x3140` | module handle slot filled by loader; not provable in a dump |

#### symbol `slot[0]` -> viable

| Level | Class | Location | Value | Detail |
| --- | --- | --- | --- | --- |
| L4_THUNK_TABLE | FILE_POINTER | `thunk[0]` | `0x140070000` | bound VA 0x140070000 recorded at bind time |

#### symbol `slot[1]` -> viable

| Level | Class | Location | Value | Detail |
| --- | --- | --- | --- | --- |
| L4_THUNK_TABLE | INDEX_ONLY | `thunk[1]` | `0x80000000000004d2` | ordinal-only slot, index 1234 |

### kernel32.dll

Descriptor RVA: `0x210b`

| Level | Class | Location | Value | Detail |
| --- | --- | --- | --- | --- |
| L2_DELAY_DESCRIPTOR | FILE_POINTER | `IMAGE_DELAYLOAD_DESCRIPTOR.szName` | `0x200e` | file-resident RVA of the DLL name string |
| L7_MODULE_HANDLE_SLOT | RUNTIME_UNRESOLVED | `IMAGE_DELAYLOAD_DESCRIPTOR.phmod` | `0x3148` | module handle slot filled by loader; not provable in a dump |

#### symbol `slot[0]` -> viable

| Level | Class | Location | Value | Detail |
| --- | --- | --- | --- | --- |
| L4_THUNK_TABLE | FILE_POINTER | `thunk[0]` | `0x202c` | file-resident hint/name RVA |

#### symbol `slot[1]` -> viable

| Level | Class | Location | Value | Detail |
| --- | --- | --- | --- | --- |
| L4_THUNK_TABLE | FILE_POINTER | `thunk[1]` | `0x2034` | file-resident hint/name RVA |