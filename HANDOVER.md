# 分离调试材料交接结果

生成时间（UTC）：`2026-11-22T18:22:02.059109+00:00`

本结果只使用 pyelftools 的只读 ELF/DWARF 接口。没有改写、strip 或重新链接任何文件。

## 批准口径

- 批准上限：`2` 份编译单元
- 批准名册：**未随材料提供**
- 选择规则：只交接在两套 dwz 编码中都独立确认身份的 CU，再按批准上限截断。
- 路径信任：常规路径只用于找候选，绝不单独采信；候选必须满足声明中的 CRC32 或 build-id，或可复算的 .debug_sup 摘要。
- 查找顺序：材料所在目录，其次 `.debug/`；绝对路径和逃逸目录的候选直接排除。

## 材料与绑定校验

### `test/testfiles_for_unittests/debuglink`

- 角色：`object`
- SHA-1：`02c7f921036839dd3acd101a3de948526eecd315`
- build-id：`f5d41d8cbc24e069c7e7a9f52cd8ab24a8f19900`
- 链接类型：`gnu_debuglink`
- 声明文件名：`debuglink.debug`
- 声明 CRC32：`0x29b7c5f1`
- 解析路径：`test/testfiles_for_unittests/debuglink.debug`
- 校验状态：**confirmed**
- 绑定依据：`crc32+build-id`
- 声明值等于候选 build-id：`True`

| CU offset | 类型 | 名称 | comp_dir | 身份来源 | 外部引用 | 身份已确认 |
|---|---|---|---|---|---|---|
| `0x0` | `DW_TAG_compile_unit` | `debuglink.c` | `/home/gabriele/Projects` | inline | - | 是 |

### `test/testfiles_for_unittests/debuglink.debug`

- 角色：`debug-file`
- SHA-1：`9e10d22165d696a473c95069deec2846b4f60867`
- build-id：`f5d41d8cbc24e069c7e7a9f52cd8ab24a8f19900`
- 链接类型：`none`
- 声明文件名：`None`
- 解析路径：`None`
- 校验状态：**not-linked**
- 说明：no separate-debug declaration in this file

| CU offset | 类型 | 名称 | comp_dir | 身份来源 | 外部引用 | 身份已确认 |
|---|---|---|---|---|---|---|
| `0x0` | `DW_TAG_compile_unit` | `debuglink.c` | `/home/gabriele/Projects` | inline | - | 是 |

### `test/testfiles_for_unittests/test_debugsup.common`

- 角色：`supplementary`
- SHA-1：`6f6e3c8283fce2b2ef52e9e262def3d21a77a717`
- build-id：`None`
- 链接类型：`debug_sup`
- 声明文件名：`None`
- 声明 .debug_sup checksum：`1425c80eec347bb214ad120cec5a6ace8fe9e53b73`
- 解析路径：`None`
- 校验状态：**supplementary**
- 说明：this file declares itself as a supplementary object; it has no outbound link to resolve

| CU offset | 类型 | 名称 | comp_dir | 身份来源 | 外部引用 | 身份已确认 |
|---|---|---|---|---|---|---|
| `0x0` | `DW_TAG_partial_unit` | `None` | `None` | supplementary | - | 否 |
| `0x38e` | `DW_TAG_partial_unit` | `None` | `None` | supplementary | - | 否 |

### `test/testfiles_for_unittests/test_debugsup1.debug`

- 角色：`debug-primary`
- SHA-1：`e6e52d902ecbb97899cd78ec2aa25f931f06c7d2`
- build-id：`f9f2b6d3d5f991f22c7ac24344cdbe5738be4095`
- 链接类型：`debug_sup`
- 声明文件名：`test_debugsup.common`
- 声明 .debug_sup checksum：`1425c80eec347bb214ad120cec5a6ace8fe9e53b73`
- 解析路径：`test/testfiles_for_unittests/test_debugsup.common`
- 校验状态：**unconfirmed**
- 说明：the declared checksum is not derivable from the delivered supplementary file and the file carries no build ID; equality with the candidate's own .debug_sup token is not independent evidence
- 候选文件 SHA-1：`6f6e3c8283fce2b2ef52e9e262def3d21a77a717`
- 与候选自声明 token 相同：`True`
- 声明摘要等于候选整文件 SHA-1：`False`
- 声明摘要等于候选整文件 MD5：`False`
- 声明值等于候选 build-id：`False`

| CU offset | 类型 | 名称 | comp_dir | 身份来源 | 外部引用 | 身份已确认 |
|---|---|---|---|---|---|---|
| `0x0` | `DW_TAG_compile_unit` | `../sysdeps/x86_64/start.S` | `/build/glibc/src/glibc/csu` | supplementary | DW_FORM_strp_sup=3 | 否 |
| `0x28` | `DW_TAG_compile_unit` | `../sysdeps/x86/abi-note.c` | `/usr/src/debug/glibc/csu` | inline | DW_FORM_ref_sup4=14, DW_FORM_strp_sup=42 | 是 |
| `0x28f` | `DW_TAG_compile_unit` | `init.c` | `/usr/src/debug/glibc/csu` | inline | DW_FORM_ref_sup4=2, DW_FORM_strp_sup=2 | 是 |
| `0x2cb` | `DW_TAG_compile_unit` | `../sysdeps/x86_64/crti.S` | `/build/glibc/src/glibc/csu` | supplementary | DW_FORM_strp_sup=3 | 否 |
| `0x2ee` | `DW_TAG_compile_unit` | `../sysdeps/x86_64/crtn.S` | `/build/glibc/src/glibc/csu` | supplementary | DW_FORM_strp_sup=3 | 否 |

### `test/testfiles_for_unittests/test_debugsup2.debug`

- 角色：`debug-primary`
- SHA-1：`e6e52d902ecbb97899cd78ec2aa25f931f06c7d2`
- build-id：`f9f2b6d3d5f991f22c7ac24344cdbe5738be4095`
- 链接类型：`debug_sup`
- 声明文件名：`test_debugsup.common`
- 声明 .debug_sup checksum：`1425c80eec347bb214ad120cec5a6ace8fe9e53b73`
- 解析路径：`test/testfiles_for_unittests/test_debugsup.common`
- 校验状态：**unconfirmed**
- 说明：the declared checksum is not derivable from the delivered supplementary file and the file carries no build ID; equality with the candidate's own .debug_sup token is not independent evidence
- 候选文件 SHA-1：`6f6e3c8283fce2b2ef52e9e262def3d21a77a717`
- 与候选自声明 token 相同：`True`
- 声明摘要等于候选整文件 SHA-1：`False`
- 声明摘要等于候选整文件 MD5：`False`
- 声明值等于候选 build-id：`False`

| CU offset | 类型 | 名称 | comp_dir | 身份来源 | 外部引用 | 身份已确认 |
|---|---|---|---|---|---|---|
| `0x0` | `DW_TAG_compile_unit` | `../sysdeps/x86_64/start.S` | `/build/glibc/src/glibc/csu` | supplementary | DW_FORM_strp_sup=3 | 否 |
| `0x28` | `DW_TAG_compile_unit` | `../sysdeps/x86/abi-note.c` | `/usr/src/debug/glibc/csu` | inline | DW_FORM_ref_sup4=14, DW_FORM_strp_sup=42 | 是 |
| `0x28f` | `DW_TAG_compile_unit` | `init.c` | `/usr/src/debug/glibc/csu` | inline | DW_FORM_ref_sup4=2, DW_FORM_strp_sup=2 | 是 |
| `0x2cb` | `DW_TAG_compile_unit` | `../sysdeps/x86_64/crti.S` | `/build/glibc/src/glibc/csu` | supplementary | DW_FORM_strp_sup=3 | 否 |
| `0x2ee` | `DW_TAG_compile_unit` | `../sysdeps/x86_64/crtn.S` | `/build/glibc/src/glibc/csu` | supplementary | DW_FORM_strp_sup=3 | 否 |

### `test/testfiles_for_unittests/test_gnudebugaltlink.common`

- 角色：`debug-file`
- SHA-1：`ea015874d2b6cf646ca93ecc8bad8803fc55057d`
- build-id：`d1852aca42cb92038ef6a252ff3fe800f04598b3`
- 链接类型：`none`
- 声明文件名：`None`
- 解析路径：`None`
- 校验状态：**not-linked**
- 说明：no separate-debug declaration in this file

| CU offset | 类型 | 名称 | comp_dir | 身份来源 | 外部引用 | 身份已确认 |
|---|---|---|---|---|---|---|
| `0x0` | `DW_TAG_partial_unit` | `None` | `None` | supplementary | - | 否 |
| `0x38e` | `DW_TAG_partial_unit` | `None` | `None` | supplementary | - | 否 |

### `test/testfiles_for_unittests/test_gnudebugaltlink1.debug`

- 角色：`debug-primary`
- SHA-1：`391843215673037cb283308f444b3e4151defba0`
- build-id：`f9f2b6d3d5f991f22c7ac24344cdbe5738be4095`
- 链接类型：`gnu_debugaltlink`
- 声明文件名：`test_gnudebugaltlink.common`
- 声明 build-id：`d1852aca42cb92038ef6a252ff3fe800f04598b3`
- 解析路径：`test/testfiles_for_unittests/test_gnudebugaltlink.common`
- 校验状态：**confirmed**
- 绑定依据：`build-id`
- 候选文件 SHA-1：`ea015874d2b6cf646ca93ecc8bad8803fc55057d`
- 候选文件 build-id：`d1852aca42cb92038ef6a252ff3fe800f04598b3`
- 声明值等于候选 build-id：`True`

| CU offset | 类型 | 名称 | comp_dir | 身份来源 | 外部引用 | 身份已确认 |
|---|---|---|---|---|---|---|
| `0x0` | `DW_TAG_compile_unit` | `../sysdeps/x86_64/start.S` | `/build/glibc/src/glibc/csu` | supplementary | DW_FORM_GNU_strp_alt=3 | 是 |
| `0x28` | `DW_TAG_compile_unit` | `../sysdeps/x86/abi-note.c` | `/usr/src/debug/glibc/csu` | inline | DW_FORM_GNU_ref_alt=14, DW_FORM_GNU_strp_alt=42 | 是 |
| `0x28f` | `DW_TAG_compile_unit` | `init.c` | `/usr/src/debug/glibc/csu` | inline | DW_FORM_GNU_ref_alt=2, DW_FORM_GNU_strp_alt=2 | 是 |
| `0x2cb` | `DW_TAG_compile_unit` | `../sysdeps/x86_64/crti.S` | `/build/glibc/src/glibc/csu` | supplementary | DW_FORM_GNU_strp_alt=3 | 是 |
| `0x2ee` | `DW_TAG_compile_unit` | `../sysdeps/x86_64/crtn.S` | `/build/glibc/src/glibc/csu` | supplementary | DW_FORM_GNU_strp_alt=3 | 是 |

### `test/testfiles_for_unittests/test_gnudebugaltlink2.debug`

- 角色：`debug-primary`
- SHA-1：`391843215673037cb283308f444b3e4151defba0`
- build-id：`f9f2b6d3d5f991f22c7ac24344cdbe5738be4095`
- 链接类型：`gnu_debugaltlink`
- 声明文件名：`test_gnudebugaltlink.common`
- 声明 build-id：`d1852aca42cb92038ef6a252ff3fe800f04598b3`
- 解析路径：`test/testfiles_for_unittests/test_gnudebugaltlink.common`
- 校验状态：**confirmed**
- 绑定依据：`build-id`
- 候选文件 SHA-1：`ea015874d2b6cf646ca93ecc8bad8803fc55057d`
- 候选文件 build-id：`d1852aca42cb92038ef6a252ff3fe800f04598b3`
- 声明值等于候选 build-id：`True`

| CU offset | 类型 | 名称 | comp_dir | 身份来源 | 外部引用 | 身份已确认 |
|---|---|---|---|---|---|---|
| `0x0` | `DW_TAG_compile_unit` | `../sysdeps/x86_64/start.S` | `/build/glibc/src/glibc/csu` | supplementary | DW_FORM_GNU_strp_alt=3 | 是 |
| `0x28` | `DW_TAG_compile_unit` | `../sysdeps/x86/abi-note.c` | `/usr/src/debug/glibc/csu` | inline | DW_FORM_GNU_ref_alt=14, DW_FORM_GNU_strp_alt=42 | 是 |
| `0x28f` | `DW_TAG_compile_unit` | `init.c` | `/usr/src/debug/glibc/csu` | inline | DW_FORM_GNU_ref_alt=2, DW_FORM_GNU_strp_alt=2 | 是 |
| `0x2cb` | `DW_TAG_compile_unit` | `../sysdeps/x86_64/crti.S` | `/build/glibc/src/glibc/csu` | supplementary | DW_FORM_GNU_strp_alt=3 | 是 |
| `0x2ee` | `DW_TAG_compile_unit` | `../sysdeps/x86_64/crtn.S` | `/build/glibc/src/glibc/csu` | supplementary | DW_FORM_GNU_strp_alt=3 | 是 |

## 重复件

- SHA-1 `391843215673037cb283308f444b3e4151defba0`：`test/testfiles_for_unittests/test_gnudebugaltlink1.debug`, `test/testfiles_for_unittests/test_gnudebugaltlink2.debug`
  - byte-identical copies; they must not be counted as independent approval evidence
- SHA-1 `e6e52d902ecbb97899cd78ec2aa25f931f06c7d2`：`test/testfiles_for_unittests/test_debugsup1.debug`, `test/testfiles_for_unittests/test_debugsup2.debug`
  - byte-identical copies; they must not be counted as independent approval evidence

## 路径复用探针

同一目录里出现其他同名/同类文件时，路径查找会成功打开错误的候选；下表用实际字节说明哪些候选会被拒绝。

- 声明类型 `gnu_debuglink`，期望值 `0x29b7c5f1`
  - `test/testfiles_for_unittests/dwarf_v5_forms.debug`：实际值 `0xd4ccd3a1`，接受=False，原因=crc32 mismatch
  - `test/testfiles_for_unittests/test_debugsup1.debug`：实际值 `0xda169ce2`，接受=False，原因=crc32 mismatch
  - `test/testfiles_for_unittests/test_debugsup2.debug`：实际值 `0xda169ce2`，接受=False，原因=crc32 mismatch
  - `test/testfiles_for_unittests/test_gnudebugaltlink1.debug`：实际值 `0x3018a030`，接受=False，原因=crc32 mismatch
  - `test/testfiles_for_unittests/test_gnudebugaltlink2.debug`：实际值 `0x3018a030`，接受=False，原因=crc32 mismatch
- 声明类型 `gnu_debugaltlink`，期望值 `d1852aca42cb92038ef6a252ff3fe800f04598b3`
  - `test/testfiles_for_unittests/debuglink.debug`：实际值 `f5d41d8cbc24e069c7e7a9f52cd8ab24a8f19900`，接受=False，原因=build-id mismatch
  - `test/testfiles_for_unittests/dwarf_v5_forms.debug`：实际值 `63c4f5b1ddcef78724d26ceaec7cee75f1972f43`，接受=False，原因=build-id mismatch
  - `test/testfiles_for_unittests/test_debugsup.common`：实际值 `None`，接受=False，原因=no build-id
  - `test/testfiles_for_unittests/test_debugsup1.debug`：实际值 `f9f2b6d3d5f991f22c7ac24344cdbe5738be4095`，接受=False，原因=build-id mismatch
  - `test/testfiles_for_unittests/test_debugsup2.debug`：实际值 `f9f2b6d3d5f991f22c7ac24344cdbe5738be4095`，接受=False，原因=build-id mismatch
  - `test/testfiles_for_unittests/test_gnudebugaltlink1.debug`：实际值 `f9f2b6d3d5f991f22c7ac24344cdbe5738be4095`，接受=False，原因=build-id mismatch

## 两套 dwz 包的同一性

- `.debug_sup` 主文件 build-id：['f9f2b6d3d5f991f22c7ac24344cdbe5738be4095']
- `.gnu_debugaltlink` 主文件 build-id：['f9f2b6d3d5f991f22c7ac24344cdbe5738be4095']
- `.debug_sup` common 的 `.debug_info` SHA-1：`5c981ea6927ed8c359fc12982fed3331fba86902`
- `.gnu_debugaltlink` common 的 `.debug_info` SHA-1：`5c981ea6927ed8c359fc12982fed3331fba86902`
- 两套 common 的 `.debug_info` 是否为同一份：**是**
- 两边并集可确认的原始 CU 数：`5`
- 两边交集（可同时被两套证据确认）的原始 CU 数：`2`
- 两套 common 各含两个 `DW_TAG_partial_unit`（`0x0`、`0x38e`），`.debug_info` 哈希相同；它们是支撑单元，不额外产生审批名额。

## 交接结论

- 批准并交接的编译单元数：**2**
  - `/usr/src/debug/glibc/csu/../sysdeps/x86/abi-note.c`
  - `/usr/src/debug/glibc/csu/init.c`
  - 范围外、不进入交接：`/build/glibc/src/glibc/csu/../sysdeps/x86_64/crti.S`
  - 范围外、不进入交接：`/build/glibc/src/glibc/csu/../sysdeps/x86_64/crtn.S`
  - 范围外、不进入交接：`/build/glibc/src/glibc/csu/../sysdeps/x86_64/start.S`
  - 已确认但未占用本次名额：`/home/gabriele/Projects/debuglink.c`
- 两套包合并后可新增的批准单元：`0`
- 两套 dwz 包包含同一组五个原始编译单元，只是两种链接编码，不是两次独立构建。
- .debug_sup 包只能独立确认两个内联身份串；补充文件摘要不可复算，其余三个 CU 身份及全部补充引用仍属未确认。
- .gnu_debugaltlink 包通过补充文件 build-id 可确认全部五个 CU；交接主证据取这一套，批准上限仍为两份。
- debuglink/debuglink.debug 自身已由 CRC32+build-id 完整确认，但它是独立材料；批准名册未到时不计入本次两份名额。
- 拼接两套包或按文件名重复计数都不会产生新的审批权。

## 未能确认的引用

### `test/testfiles_for_unittests/test_debugsup1.debug`

链接状态：`unconfirmed`；未确认引用合计：`69`
这里的 `resolved=True` 只表示在候选补充文件里找到了目标；候选文件未与声明绑定，因此引用仍按未确认处理。


- CU `0x0` `../sysdeps/x86_64/start.S`（supplementary）：DW_FORM_strp_sup=3
  - `DW_AT_name` @ DIE `0xc` form `DW_FORM_strp_sup` raw `146` resolved=True
  - `DW_AT_comp_dir` @ DIE `0xc` form `DW_FORM_strp_sup` raw `1046` resolved=True
  - `DW_AT_producer` @ DIE `0xc` form `DW_FORM_strp_sup` raw `73` resolved=True
- CU `0x28` `../sysdeps/x86/abi-note.c`（inline）：DW_FORM_strp_sup=42, DW_FORM_ref_sup4=14
  - `DW_AT_producer` @ DIE `0x34` form `DW_FORM_strp_sup` raw `296` resolved=True
  - `DW_AT_import` @ DIE `0x46` form `DW_FORM_ref_sup4` raw `922` resolved=True
  - `DW_AT_import` @ DIE `0x4b` form `DW_FORM_ref_sup4` raw `12` resolved=True
  - `DW_AT_name` @ DIE `0x50` form `DW_FORM_strp_sup` raw `875` resolved=True
  - `DW_AT_type` @ DIE `0x50` form `DW_FORM_ref_sup4` raw `17` resolved=True
  - `DW_AT_name` @ DIE `0x5c` form `DW_FORM_strp_sup` raw `864` resolved=True
  - `DW_AT_type` @ DIE `0x5c` form `DW_FORM_ref_sup4` raw `24` resolved=True
  - `DW_AT_name` @ DIE `0x68` form `DW_FORM_strp_sup` raw `843` resolved=True
- CU `0x28f` `init.c`（inline）：DW_FORM_strp_sup=2, DW_FORM_ref_sup4=2
  - `DW_AT_producer` @ DIE `0x29b` form `DW_FORM_strp_sup` raw `296` resolved=True
  - `DW_AT_import` @ DIE `0x2ad` form `DW_FORM_ref_sup4` raw `922` resolved=True
  - `DW_AT_name` @ DIE `0x2b2` form `DW_FORM_strp_sup` raw `586` resolved=True
  - `DW_AT_type` @ DIE `0x2c5` form `DW_FORM_ref_sup4` raw `927` resolved=True
- CU `0x2cb` `../sysdeps/x86_64/crti.S`（supplementary）：DW_FORM_strp_sup=3
  - `DW_AT_name` @ DIE `0x2d7` form `DW_FORM_strp_sup` raw `96` resolved=True
  - `DW_AT_comp_dir` @ DIE `0x2d7` form `DW_FORM_strp_sup` raw `1046` resolved=True
  - `DW_AT_producer` @ DIE `0x2d7` form `DW_FORM_strp_sup` raw `73` resolved=True
- CU `0x2ee` `../sysdeps/x86_64/crtn.S`（supplementary）：DW_FORM_strp_sup=3
  - `DW_AT_name` @ DIE `0x2fa` form `DW_FORM_strp_sup` raw `121` resolved=True
  - `DW_AT_comp_dir` @ DIE `0x2fa` form `DW_FORM_strp_sup` raw `1046` resolved=True
  - `DW_AT_producer` @ DIE `0x2fa` form `DW_FORM_strp_sup` raw `73` resolved=True

### `test/testfiles_for_unittests/test_debugsup2.debug`

链接状态：`unconfirmed`；未确认引用合计：`69`
这里的 `resolved=True` 只表示在候选补充文件里找到了目标；候选文件未与声明绑定，因此引用仍按未确认处理。


- CU `0x0` `../sysdeps/x86_64/start.S`（supplementary）：DW_FORM_strp_sup=3
  - `DW_AT_name` @ DIE `0xc` form `DW_FORM_strp_sup` raw `146` resolved=True
  - `DW_AT_comp_dir` @ DIE `0xc` form `DW_FORM_strp_sup` raw `1046` resolved=True
  - `DW_AT_producer` @ DIE `0xc` form `DW_FORM_strp_sup` raw `73` resolved=True
- CU `0x28` `../sysdeps/x86/abi-note.c`（inline）：DW_FORM_strp_sup=42, DW_FORM_ref_sup4=14
  - `DW_AT_producer` @ DIE `0x34` form `DW_FORM_strp_sup` raw `296` resolved=True
  - `DW_AT_import` @ DIE `0x46` form `DW_FORM_ref_sup4` raw `922` resolved=True
  - `DW_AT_import` @ DIE `0x4b` form `DW_FORM_ref_sup4` raw `12` resolved=True
  - `DW_AT_name` @ DIE `0x50` form `DW_FORM_strp_sup` raw `875` resolved=True
  - `DW_AT_type` @ DIE `0x50` form `DW_FORM_ref_sup4` raw `17` resolved=True
  - `DW_AT_name` @ DIE `0x5c` form `DW_FORM_strp_sup` raw `864` resolved=True
  - `DW_AT_type` @ DIE `0x5c` form `DW_FORM_ref_sup4` raw `24` resolved=True
  - `DW_AT_name` @ DIE `0x68` form `DW_FORM_strp_sup` raw `843` resolved=True
- CU `0x28f` `init.c`（inline）：DW_FORM_strp_sup=2, DW_FORM_ref_sup4=2
  - `DW_AT_producer` @ DIE `0x29b` form `DW_FORM_strp_sup` raw `296` resolved=True
  - `DW_AT_import` @ DIE `0x2ad` form `DW_FORM_ref_sup4` raw `922` resolved=True
  - `DW_AT_name` @ DIE `0x2b2` form `DW_FORM_strp_sup` raw `586` resolved=True
  - `DW_AT_type` @ DIE `0x2c5` form `DW_FORM_ref_sup4` raw `927` resolved=True
- CU `0x2cb` `../sysdeps/x86_64/crti.S`（supplementary）：DW_FORM_strp_sup=3
  - `DW_AT_name` @ DIE `0x2d7` form `DW_FORM_strp_sup` raw `96` resolved=True
  - `DW_AT_comp_dir` @ DIE `0x2d7` form `DW_FORM_strp_sup` raw `1046` resolved=True
  - `DW_AT_producer` @ DIE `0x2d7` form `DW_FORM_strp_sup` raw `73` resolved=True
- CU `0x2ee` `../sysdeps/x86_64/crtn.S`（supplementary）：DW_FORM_strp_sup=3
  - `DW_AT_name` @ DIE `0x2fa` form `DW_FORM_strp_sup` raw `121` resolved=True
  - `DW_AT_comp_dir` @ DIE `0x2fa` form `DW_FORM_strp_sup` raw `1046` resolved=True
  - `DW_AT_producer` @ DIE `0x2fa` form `DW_FORM_strp_sup` raw `73` resolved=True

## 缺失支撑材料

- `test/testfiles_for_unittests/test_debugsup1.debug`（debug_sup / unconfirmed）：the declared checksum is not derivable from the delivered supplementary file and the file carries no build ID; equality with the candidate's own .debug_sup token is not independent evidence
- `test/testfiles_for_unittests/test_debugsup2.debug`（debug_sup / unconfirmed）：the declared checksum is not derivable from the delivered supplementary file and the file carries no build ID; equality with the candidate's own .debug_sup token is not independent evidence
- `test/testfiles_for_unittests/test_debugsup.common`（supplementary-identity / unconfirmed）：no .note.gnu.build-id and no producer digest manifest for the supplementary file; the delivered bytes cannot reproduce the declared .debug_sup checksum
- `test/testfiles_for_unittests/test_debugsup1`（object-side / missing）：stripped/original ELF object that declares this debug file was not delivered, so the debug material cannot be bound to a delivered build artifact
- `test/testfiles_for_unittests/test_debugsup2`（object-side / missing）：stripped/original ELF object that declares this debug file was not delivered, so the debug material cannot be bound to a delivered build artifact
- `test/testfiles_for_unittests/test_gnudebugaltlink1`（object-side / missing）：stripped/original ELF object that declares this debug file was not delivered, so the debug material cannot be bound to a delivered build artifact
- `test/testfiles_for_unittests/test_gnudebugaltlink2`（object-side / missing）：stripped/original ELF object that declares this debug file was not delivered, so the debug material cannot be bound to a delivered build artifact
- `(approval roster)`（approval-roster / missing）：the signed approval roster naming the two approved CUs is not part of the delivered material; the selection below is the conservative intersection of independently confirmed identities

