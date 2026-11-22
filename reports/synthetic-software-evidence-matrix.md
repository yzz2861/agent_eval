# 合成 SOFTWARE 映像判定对照

所有输入均以只读方式打开；结果由 `Registry.DeletionEvidence.analyze_deletion` 生成。

| 样例 | before | after | 判定 | 原因 | 旧 VK 槽位 | 旧数据槽位 | 批次对齐 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 01_reallocated | `software_before.hive` | `software_after_reallocated.hive` | `REALLOCATED` | `OLD_VK_CELL_START_REUSED` | `allocated` | `free` | `ALIGNED` |
| 02_released | `software_before.hive` | `software_after_released.hive` | `RELEASED` | `OLD_VK_CELL_IS_FREE` | `free` | `free` | `NOT_PROVIDED` |
| 03_not_collected | `software_before_not_collected.hive` | `software_after_not_collected.hive` | `NOT_COLLECTED` | `TARGET_NOT_IN_EITHER_SNAPSHOT` | `no_external_cell` | `no_external_cell` | `NOT_PROVIDED` |
| 04_wrong_hive | `software_before.hive` | `software_after_wrong_hive.hive` | `UNDETERMINED` | `MATERIAL_MISMATCH` | `allocated` | `free` | `ALIGNED` |

## 要点

- 同一基线配合“槽位已空闲”的 after 得到 `RELEASED`。
- 同一基线配合“原槽位保存 Rotation”的 after 得到 `REALLOCATED`；单独这一个 after 不能证明释放瞬间存在。
- 两份都没有 Policy 的映像得到 `NOT_COLLECTED`，因为没有基线物理身份，不能解释为删除。
- 内部 hive 名称不一致时，即使 after 的槽位看起来被复用，也只输出 `UNDETERMINED`。
