# Registry 删除证据查询

`Registry.DeletionEvidence` 是只读分析层。它不调用事务日志回放写接口，不修改 hive，也不把日志应用到源文件。输入始终以 `rb` 打开，输出只包含 JSON 或 Markdown 报告。

## 判定

| 判定 | 含义 | 必要条件 |
| --- | --- | --- |
| `RELEASED` | 后续映像中旧值槽位已释放 | 基线有值；后续活动树无值；旧 VK cell 在后续快照中为空闲 cell（或并入空闲 cell） |
| `REALLOCATED` | 旧 VK 槽位起始位置已被另一结构占用 | 基线有值；后续活动树无值；同一 cell 起始位置在后续快照中已分配且内容不同 |
| `NOT_COLLECTED` | 压根没有采到 | 两份快照都没有值；没有可比较的物理身份 |
| `PRESENT` / `PRESENT_MODIFIED` | 仍存在 | 后续活动树仍能解析到该值 |
| `UNDETERMINED` | 无法判定 | hive 身份、格式、时间/序号顺序、日志窗口或槽位可比性冲突 |

`RELEASED` 是存储释放证据，不等于已经证明删除动作、时间或操作者。`REALLOCATED` 证明槽位被覆盖或重用，不证明两次快照之间一定出现过可观察的空闲状态。

## 证据字段

报告至少包含：

- 完整路径：`query.value_path`，例如 `SOFTWARE\Contoso\Agent!Policy`。
- 物理身份：`key_nk_cell_rva`、`values_list_index`、`vk_cell_rva`、`vk_cell_size`、外部数据 `data_cell_rva`，以及 cell 绝对偏移和 SHA-256。
- 快照批次：`transaction_batches.snapshot_sequences`，含 `sequence1`、`sequence2`、hive SHA-256 和 `batch_id`。
- 离线批次：HvLE 序号、脏页范围、是否覆盖旧 VK cell、脏页是否与后续槽位一致。
- 槽位状态：`exact`、`inside_free_cell`、`inside_allocated_cell`、`beyond_captured_hbins` 等关系，以及完整字节/负载字节是否与旧 cell 相同。

## 材料对不上

以下情况强制输出 `UNDETERMINED`，即使物理槽位看起来像释放或再分配：

- before/after 不是主 hive，或内部 hive 名称、格式版本、cluster factor 不一致。
- 不同映像的 `sequence2` 相同，或 after 的序号/最后写入时间早于 before。
- 提供的离线日志不是新格式 HvLE、校验失败、hive 名称不匹配，或 HvLE 序号晚于 after 快照。早于 before 的批次只记为警告。
- 旧 VK cell 超出后续快照的 `hbins_size`，或落在不可解析的空隙。
- 路径解析到不同规范路径。

## 命令

```sh
python samples/deletion_evidence.py \
  --before software_before.hive \
  --after software_after.hive \
  --key SOFTWARE\Contoso\Agent \
  --value Policy \
  --log software_after.SOFTWARE.LOG1 \
  --format markdown
```

`--log` 可重复；`--log1`/`--log2` 是别名。`--format json` 输出机读证据。`--output` 只写报告文件；若它指向任一输入 hive/日志，命令会拒绝执行。根目录的 `deletion_evidence.py` 是同一入口。

Python 接口：

```python
from Registry.DeletionEvidence import analyze_deletion

report = analyze_deletion(
    "software_before.hive",
    "software_after.hive",
    r"SOFTWARE\Contoso\Agent",
    "Policy",
    ["software_after.SOFTWARE.LOG1"],
)
```

## 合成映像

生成器：`tests/make_synthetic_hives.py`。固定输出到 `tests/reg_samples/deletion/`。

- `software_before.hive`：`SOFTWARE\Contoso\Agent!Policy = Enabled`，VK cell RVA `0x150`，外部数据 cell RVA `0x178`，sequence 7。
- `software_after_reallocated.hive`：活动树中 `Policy` 消失；同一 VK cell RVA `0x150` 保存 `Rotation = 30`（RegDWord）；旧数据 cell RVA `0x178` 为空闲；sequence 8。
- `software_after_released.hive`：同一 VK cell 与数据 cell 都变为空闲，保留旧负载字节，用于验证 `RELEASED`。
- `software_before_not_collected.hive` / `software_after_not_collected.hive`：两份都没有 `Policy`，用于验证 `NOT_COLLECTED`。
- `software_after_wrong_hive.hive`：内部 hive 名称改为 `SYSTEM`，用于验证材料不一致。
- `software_after_reallocated.SOFTWARE.LOG1`：一个有效的 HvLE 批次，序号 8，脏页覆盖第一个 HBIN，内容与 after 的槽位一致，但不包含释放中间态。

## 限制

- cell RVA 只在 HBIN 布局未重组时可直接比较；Windows 8+ 重组会移动 cell。
- 空闲 cell 不能证明删除操作者或意图；残留字节可能更旧。
- 事务日志是脏页映像，不是语义操作日志，不含进程、用户或操作名。
- 两份 hive 即使名称相同，也可能来自不同设备；仍需镜像/设备标识和保管链。

## 测试

```sh
python -m pytest tests/test_deletion_evidence.py
```
