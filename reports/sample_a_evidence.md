# Read-only delay-load evidence view

- source: `sample_a_generation_v1.dll`
- machine: `IMAGE_FILE_MACHINE_AMD64`
- fragment input: `False`
- image base: `0x140000000`

## Evidence classification totals

| Class | Count | Meaning |
| --- | ---: | --- |
| FILE_POINTER | 19 | target pointer physically present in the file |
| INDEX_ONLY | 3 | table slot keeps an ordinal/index only |
| RUNTIME_UNRESOLVED | 8 | filled by the loader, not provable statically |

## Transfer-path evidence

### appcrt140.dll

Descriptor RVA: `0x20eb`

| Level | Class | Location | Value | Detail |
| --- | --- | --- | --- | --- |
| L2_DELAY_DESCRIPTOR | FILE_POINTER | `IMAGE_DELAYLOAD_DESCRIPTOR.szName` | `0x2000` | file-resident RVA of the DLL name string |
| L7_MODULE_HANDLE_SLOT | RUNTIME_UNRESOLVED | `IMAGE_DELAYLOAD_DESCRIPTOR.phmod` | `0x3140` | phmod names a .data slot; the loader writes the module base at first load, no target is provable from the file |
| L6_UNLOAD_IAT | FILE_POINTER | `IMAGE_DELAYLOAD_DESCRIPTOR.pUnloadIAT` | `0x208b` | file-resident RVA of the unload (clean copy) IAT |
| L5_BOUND_IAT | FILE_POINTER | `IMAGE_DELAYLOAD_DESCRIPTOR.dwTimeStamp` | `0x12345678` | non-zero timestamp marks a bound delay import |
| L8_LOAD_CONFIG | FILE_POINTER | `LOAD_CONFIG.GuardCFCheckFunctionPointer` | `0x3150` | file-resident RVA naming the guard pointer slot; the slot itself is filled by the loader |
| L8_LOAD_CONFIG | RUNTIME_UNRESOLVED | `GuardCFCheckFunctionPointer target slot` | `0x0` | indirect guard pointer slot is empty on disk |
| L8_LOAD_CONFIG | FILE_POINTER | `LOAD_CONFIG.GuardCFDispatchFunctionPointer` | `0x3158` | file-resident RVA naming the guard pointer slot; the slot itself is filled by the loader |
| L8_LOAD_CONFIG | RUNTIME_UNRESOLVED | `GuardCFDispatchFunctionPointer target slot` | `0x0` | indirect guard pointer slot is empty on disk |
| L8_LOAD_CONFIG | FILE_POINTER | `LOAD_CONFIG.GuardAddressTakenIatEntryTable` | `0x3160` | file-resident RVA of guard IAT table (4 entries) |
| L8_LOAD_CONFIG | FILE_POINTER | `GuardAddressTakenIatEntry[0]` | `0x205b` | file-resident RVA to a delay IAT slot |
| L8_LOAD_CONFIG | FILE_POINTER | `GuardAddressTakenIatEntry[1]` | `0x2063` | file-resident RVA to a delay IAT slot |
| L8_LOAD_CONFIG | FILE_POINTER | `GuardAddressTakenIatEntry[2]` | `0x20bb` | file-resident RVA to a delay IAT slot |
| L8_LOAD_CONFIG | FILE_POINTER | `GuardAddressTakenIatEntry[3]` | `0x20c3` | file-resident RVA to a delay IAT slot |

#### symbol `crt_initialize` -> viable

| Level | Class | Location | Value | Detail |
| --- | --- | --- | --- | --- |
| L3_NAME_TABLE | FILE_POINTER | `INT[0]` | `0x201b` | file-resident RVA to hint/name blob (hint=0, name='crt_initialize') |
| L4_THUNK_TABLE | FILE_POINTER | `IAT[0]` | `0x140070000` | bound slot holds pre-resolved value 0x140070000 from bind time |
| L5_BOUND_IAT | FILE_POINTER | `BoundIAT[0]` | `0x140070000` | bind-time address 0x140070000 recorded in the file |
| L9_CODE_REFERENCE | RUNTIME_UNRESOLVED | `no relocation for IAT slot 0x205b` | `-` | no static relocation; the runtime helper resolves the slot on demand, caller binding is not file-provable |

#### symbol `#1234` -> viable

| Level | Class | Location | Value | Detail |
| --- | --- | --- | --- | --- |
| L3_NAME_TABLE | INDEX_ONLY | `INT[1]` | `0x80000000000004d2` | name table slot carries ordinal index 1234 only |
| L4_THUNK_TABLE | INDEX_ONLY | `IAT[1]` | `0x80000000000004d2` | thunk slot keeps ordinal index 1234 only; target unresolved |
| L5_BOUND_IAT | INDEX_ONLY | `BoundIAT[1]` | `0x80000000000004d2` | bound slot for ordinal 1234; index-only table entry |
| L9_CODE_REFERENCE | RUNTIME_UNRESOLVED | `no relocation for IAT slot 0x2063` | `-` | no static relocation; the runtime helper resolves the slot on demand, caller binding is not file-provable |

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