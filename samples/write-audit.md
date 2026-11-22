# Metadata-only property/interface contract audit

Source: `samples/write-overloads.dll`

Method: `dnfile` metadata tables only. No assembly load, no CLR host, no reflection, no IL execution.

## Verification table

| # | Type | Sealed | Interface | Property | Interface setter | Route | Implementation MethodDef | Property link | External write | Conclusion |
|---|------|--------|-----------|----------|------------------|-------|--------------------------|---------------|----------------|------------|
| 1 | `MetadataSamples.InheritedWriteFacade` | yes | `MetadataSamples.Contracts.IValueWriter` | `Value` | `MethodSemantics#3` -> `MethodDef#3` | inherited-implicit | `MethodDef#5` | yes | **YES** | YES - external write accessor |
| 2 | `MetadataSamples.WriteFacade` | yes | `MetadataSamples.Contracts.IValueWriter` | `Value` | `MethodSemantics#3` -> `MethodDef#3` | implicit | `MethodDef#9` | yes | **YES** | YES - external write accessor |
| 3 | `MetadataSamples.ExplicitWriteFacade` | yes | `MetadataSamples.Contracts.IValueWriter` | `Value` | `MethodSemantics#3` -> `MethodDef#3` | explicit | `MethodDef#10` | n/a (MethodImpl) | **YES** | YES - external write accessor |

## Evidence trace

### Finding 1: `MetadataSamples.InheritedWriteFacade` / `MetadataSamples.Contracts.IValueWriter` / `Value`

- `TypeDef` target: `TypeDef#4` (0x02000004, file 0x336); sealed=True.
- Interface declaration: `TypeDef#2` (0x02000002, file 0x31A).
- Property association: `PropertyMap#2` (0x15000002, file 0x42A) -> `Property#2` (0x17000002, file 0x444).
- Interface setter: `MethodSemantics#3` (0x18000003, file 0x468) -> `MethodDef#3` (0x06000003, file 0x37C).
- InterfaceImpl: `InterfaceImpl#2` (0x09000002, file 0x40C); implemented on `MetadataSamples.BaseWriter` (inherited).
- Inheritance path: `MetadataSamples.InheritedWriteFacade` -> `MetadataSamples.BaseWriter`.
- Implicit matching MethodDef: `MethodDef#5` (0x06000005, file 0x398).
- Class property association: `PropertyMap#3` (0x15000003, file 0x42E) -> `Property#3` (0x17000003, file 0x44A) -> `MethodSemantics#5` (0x18000005, file 0x474).
- Concrete setter body: `MethodDef#5` (0x06000005, file 0x398); flags=public, final, virtual, hidebysig, newslot, specialname.
- Same-name/overload scan:
  - `MethodDef#5` (0x06000005, file 0x398) `MetadataSamples.BaseWriter::set_Value` `instance void (int32)` flags=public, final, virtual, hidebysig, newslot, specialname; same-signature=True; relation=mapped_implementation (MethodDef is the concrete body selected for the interface setter).
- Conclusion: **YES - external write accessor**; external_write_accessor=True.

### Finding 2: `MetadataSamples.WriteFacade` / `MetadataSamples.Contracts.IValueWriter` / `Value`

- `TypeDef` target: `TypeDef#5` (0x02000005, file 0x344); sealed=True.
- Interface declaration: `TypeDef#2` (0x02000002, file 0x31A).
- Property association: `PropertyMap#2` (0x15000002, file 0x42A) -> `Property#2` (0x17000002, file 0x444).
- Interface setter: `MethodSemantics#3` (0x18000003, file 0x468) -> `MethodDef#3` (0x06000003, file 0x37C).
- InterfaceImpl: `InterfaceImpl#4` (0x09000004, file 0x414); implemented on `MetadataSamples.WriteFacade`.
- Implicit matching MethodDef: `MethodDef#9` (0x06000009, file 0x3D0).
- Class property association: `PropertyMap#5` (0x15000005, file 0x436) -> `Property#4` (0x17000004, file 0x450) -> `MethodSemantics#7` (0x18000007, file 0x480).
- Concrete setter body: `MethodDef#9` (0x06000009, file 0x3D0); flags=public, final, virtual, hidebysig, newslot, specialname.
- Same-name/overload scan:
  - `MethodDef#6` (0x06000006, file 0x3A6) `MetadataSamples.WriteFacade::set_Value` `static void (string)` flags=public, static, hidebysig; same-signature=False; relation=unrelated_same_name (same method name/prefix, but a different signature and no interface mapping).
  - `MethodDef#7` (0x06000007, file 0x3B4) `MetadataSamples.WriteFacade::set_Value` `instance void (int32, bool)` flags=private, hidebysig; same-signature=False; relation=unrelated_same_name (same method name/prefix, but a different signature and no interface mapping).
  - `MethodDef#9` (0x06000009, file 0x3D0) `MetadataSamples.WriteFacade::set_Value` `instance void (int32)` flags=public, final, virtual, hidebysig, newslot, specialname; same-signature=True; relation=mapped_implementation (MethodDef is the concrete body selected for the interface setter).
- Conclusion: **YES - external write accessor**; external_write_accessor=True.

### Finding 3: `MetadataSamples.ExplicitWriteFacade` / `MetadataSamples.Contracts.IValueWriter` / `Value`

- `TypeDef` target: `TypeDef#6` (0x02000006, file 0x352); sealed=True.
- Interface declaration: `TypeDef#2` (0x02000002, file 0x31A).
- Property association: `PropertyMap#2` (0x15000002, file 0x42A) -> `Property#2` (0x17000002, file 0x444).
- Interface setter: `MethodSemantics#3` (0x18000003, file 0x468) -> `MethodDef#3` (0x06000003, file 0x37C).
- InterfaceImpl: `InterfaceImpl#6` (0x09000006, file 0x41C); implemented on `MetadataSamples.ExplicitWriteFacade`.
- Explicit override: `MethodImpl#1` (0x19000001, file 0x48C).
- MethodImpl declaration: `MemberRef#1` (0x0A000001, file 0x420) (`MetadataSamples.Contracts.IValueWriter::set_Value` `instance void (int32)`).
- Concrete setter body: `MethodDef#10` (0x0600000A, file 0x3DE); flags=private, final, virtual, hidebysig, newslot, specialname.
- Same-name/overload scan:
  - `MethodDef#10` (0x0600000A, file 0x3DE) `MetadataSamples.ExplicitWriteFacade::set_Value` `instance void (int32)` flags=private, final, virtual, hidebysig, newslot, specialname; same-signature=True; relation=mapped_implementation (MethodDef is the concrete body selected for the interface setter).
  - `MethodDef#11` (0x0600000B, file 0x3EC) `MetadataSamples.ExplicitWriteFacade::set_Value` `static void (string)` flags=public, static, hidebysig; same-signature=False; relation=unrelated_same_name (same method name/prefix, but a different signature and no interface mapping).
- Conclusion: **YES - external write accessor**; external_write_accessor=True.
