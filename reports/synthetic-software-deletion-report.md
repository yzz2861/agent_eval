# SOFTWARE Hive 删除证据查询报告

## 结论

- 判定：`REALLOCATED`（原槽位已再分配）
- 原因代码：`OLD_VK_CELL_START_REUSED`
- 完整配置项路径：`SOFTWARE\Contoso\Agent!Policy`
- 只读模式：`True`

较早快照确实捕获过该值；后续快照的活动树中没有该值，而同一 VK cell 起始位置已被另一个配置项占用。这证明原槽位发生了再分配，但不能单独证明两次采集之间曾出现可观察的“先释放、后复用”中间状态，也不能证明删除动作、时间和操作者。

## 输入与批次

| 时点 | 文件 | hive SHA-256 | sequence1/2 | 最后写入 (UTC) | HBIN 大小 |
| --- | --- | --- | --- | --- | --- |
| before | `tests/reg_samples/deletion/software_before.hive` | `4fb9f5833bee62b8b50aaa67393eadb9e766129456cd0d0edeb466c2d6fa79ef` | 7/7 | 2026-11-20T08:00:00Z | 0x1000 |
| after | `tests/reg_samples/deletion/software_after_reallocated.hive` | `7e745cbe52357f8d5283716cd15b1ef37fd4e1b36811e238e8c81ed0cbfafc14` | 8/8 | 2026-11-20T09:00:00Z | 0x1000 |

- 材料一致性：`MATCH`
- 快照批次：`snapshot:before:seq2=7:4fb9f5833bee`；`snapshot:after:seq2=8:7e745cbe5235`
- 离线批次对齐：`ALIGNED`
- 旧 VK 槽位被离线脏页覆盖：`True`
- 脏页内容匹配 after 槽位：`True`
- 离线日志 `tests/reg_samples/deletion/software_after_reallocated.SOFTWARE.LOG1` SHA-256 `151fce8e9ce7f364e62b656909e10364c297ac073dd7e189a8a3fa0ab55b990a`，HvLE 序号 `[8]`，有效 `True`

## 物理身份

- KV 路径：`SOFTWARE\Contoso\Agent!Policy`
- NK cell RVA：`0xd0`
- values list 索引：`0`
- VK cell RVA / 大小：`0x150` / `40`
- VK cell 绝对偏移：`0x1150`
- VK cell SHA-256：`a6aeda5140547de08eca220a7c47f5c8bac8d22e25167ea58926b6b5688a472c`
- 数据存储：`external_cell`；数据 SHA-256：`808d711a54cc1b8bb8b7cc406ecbec0f9f4e9a8d98b7f88538cc5376b81b8472`
- 数据 cell RVA：`0x178`
- 数据 cell SHA-256：`515c281c1b1c01d9d938e54846c854a21d52cefc52b4206f86a0c1eb4760f63a`

后续映像中的旧槽位状态：

- 状态：`allocated`；关系：`exact`
- cell 大小 / 签名：`40` / `vk`
- 与旧 cell 完整字节相同：`False`
- 与旧 cell 负载字节相同（忽略 cell 头）：`False`
- 新占用值：`Rotation`，类型 `RegDWord`，预览 `30`
- 旧数据槽位：`free`；负载字节与旧数据相同：`True`

## 这对映像说明了什么

较早快照确实捕获过该值，因此后续“查不到”不是从未采集。后续快照在**完全相同的 VK cell 起始位置**保存了另一个配置项，而旧配置项的外部数据槽位已经空闲；这证明旧 VK 槽位被再分配/覆盖，足以否定旧值仍然有效，但不能单独证明两次采集之间出现过可观察的释放瞬间。

- 较早快照确实捕获到 SOFTWARE\Contoso\Agent!Policy；VK cell RVA 为 0x150（绝对偏移 0x1150），数据存储方式为 external_cell。
- 后续快照的活动树中不存在 SOFTWARE\Contoso\Agent!Policy。
- 后续快照中，旧 VK 槽位 RVA 0x150 的状态为 allocated（关系=exact，大小=40，签名=vk）。
- 复用后的 VK cell 现在保存配置项 'Rotation'（SOFTWARE\Contoso\Agent!Rotation），类型为 RegDWord，数据预览为 '30'。
- 后续快照中，旧外部数据槽位 RVA 0x178 的状态为 free。
- 离线事务批次对齐状态=ALIGNED；旧 VK cell 是否被脏页覆盖=True；脏页内容是否与后续槽位一致=True。

## 还缺什么证据

- `INTERMEDIATE_FREE_STATE`：需要一份中间快照或事务批次，显示旧 VK 槽位在另一个配置项占用它之前确实处于空闲状态。
- `DELETION_TRANSACTION_OR_AUDIT_EVENT`：需要能把消失过程绑定到具体操作、时间和操作者的事务记录、审计日志、EDR 或部署工具日志。
- `FULL_DISK_PROVENANCE`：需要两份 hive 快照的采集哈希、设备/镜像标识和完整的证据保管链记录。

## 限制

- 只有当后续 hive 没有被重新组织时，cell RVA 才可直接比较；Windows 8+ 的 hive 重组会移动 cell。
- 空闲 cell 只能证明存储被释放，不能证明是谁或什么操作发起删除；空闲 cell 中的残留字节也可能来自更早的内容。
- 解析后的 hive 中不存在某个值，不等于该值从未存在；也可能是采集范围、快照时点或获取过程造成的缺口。
- 新格式事务日志保存的是脏页映像和序号，不包含语义化的操作名称、进程、用户或操作者身份。
- 槽位再分配只能证明后续状态覆盖或复用了旧槽位起始位置，不能证明两份快照之间一定出现过可观察的空闲状态。
