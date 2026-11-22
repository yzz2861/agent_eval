# Metadata-only property/interface contract audit

Source: `samples/readonly-overloads.dll`

Method: `dnfile` metadata tables only. No assembly load, no CLR host, no reflection, no IL execution.

## Verification table

| # | Type | Sealed | Interface | Property | Interface setter | Route | Implementation MethodDef | Property link | External write | Conclusion |
|---|------|--------|-----------|----------|------------------|-------|--------------------------|---------------|----------------|------------|
| 1 | `MetadataSamples.ReadOnlyFacade` | yes | `MetadataSamples.Contracts.IReadOnlyValue` | `Value` | none | none | - | n/a | no | NO - interface property has no setter |
| 2 | `MetadataSamples.ReadOnlyFacade` | yes | `MetadataSamples.Contracts.IValueWriter` | `Value` | `MethodSemantics#3` -> `MethodDef#3` | none | - | n/a | no | NO - interface is not implemented |

## Evidence trace

### Finding 1: `MetadataSamples.ReadOnlyFacade` / `MetadataSamples.Contracts.IReadOnlyValue` / `Value`

- `TypeDef` target: `TypeDef#3` (0x02000003, file 0x320); sealed=True.
- Interface declaration: `TypeDef#1` (0x02000001, file 0x304).
- Property association: `PropertyMap#1` (0x15000001, file 0x394) -> `Property#1` (0x17000001, file 0x3A0).
- Same-name/overload scan:
  - `MethodDef#4` (0x06000004, file 0x358) `MetadataSamples.ReadOnlyFacade::set_Value` `instance void (int32)` flags=public, final, virtual, hidebysig, newslot, specialname; same-signature=None; relation=unrelated_same_name (name/prefix collision; the selected interface property has no setter to compare against).
  - `MethodDef#5` (0x06000005, file 0x366) `MetadataSamples.ReadOnlyFacade::set_Value` `static void (string)` flags=public, static, hidebysig; same-signature=None; relation=unrelated_same_name (name/prefix collision; the selected interface property has no setter to compare against).
  - `MethodDef#6` (0x06000006, file 0x374) `MetadataSamples.ReadOnlyFacade::set_Value` `instance void (int32, string)` flags=private, hidebysig; same-signature=None; relation=unrelated_same_name (name/prefix collision; the selected interface property has no setter to compare against).
- Conclusion: **NO - interface property has no setter**; external_write_accessor=False.

### Finding 2: `MetadataSamples.ReadOnlyFacade` / `MetadataSamples.Contracts.IValueWriter` / `Value`

- `TypeDef` target: `TypeDef#3` (0x02000003, file 0x320); sealed=True.
- Interface declaration: `TypeDef#2` (0x02000002, file 0x312).
- Property association: `PropertyMap#2` (0x15000002, file 0x398) -> `Property#2` (0x17000002, file 0x3A6).
- Interface setter: `MethodSemantics#3` (0x18000003, file 0x3BE) -> `MethodDef#3` (0x06000003, file 0x34A).
- Same-name/overload scan:
  - `MethodDef#4` (0x06000004, file 0x358) `MetadataSamples.ReadOnlyFacade::set_Value` `instance void (int32)` flags=public, final, virtual, hidebysig, newslot, specialname; same-signature=True; relation=unrelated_same_name (same name and signature as the interface setter, but no Property association and no MethodImpl mapping).
  - `MethodDef#5` (0x06000005, file 0x366) `MetadataSamples.ReadOnlyFacade::set_Value` `static void (string)` flags=public, static, hidebysig; same-signature=False; relation=unrelated_same_name (same method name/prefix, but a different signature and no interface mapping).
  - `MethodDef#6` (0x06000006, file 0x374) `MetadataSamples.ReadOnlyFacade::set_Value` `instance void (int32, string)` flags=private, hidebysig; same-signature=False; relation=unrelated_same_name (same method name/prefix, but a different signature and no interface mapping).
- Conclusion: **NO - interface is not implemented**; external_write_accessor=False.
