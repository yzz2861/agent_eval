# CVSS 政策预检（Policy Pre-check）

本目录在 Red Hat 官方 `cvss` 评分内核（v2 / v3.0 / v3.1 / v4.0，已通过 56 项官方向量测试）之上，
增加一层面向风险评审会的**政策预检**工具。目标是回答一个具体问题：

> 一个边缘指标改动取值，会不会让同一类事实从“常规工单”直接跳到“紧急处置”？

## 设计原则

1. **评分内核是唯一事实来源。** 所有向量都由 `cvss` 库构造并打分；构造抛错的组合一律不进入分析，
   因此无法合成规范里不成立的向量（见 `policy_audit/universe.py`）。
2. **政策只能收窄、不能发明。** 指标白名单只是在内核证明合法的宇宙上做子集筛选。
3. **缺少候选不等于表决通过。** 任何合法但未被白名单覆盖的向量，都作为 `uncovered` 与
   `blocked_adjacencies` 显式上报，评审结论为 `needs-review`。

## 有限的可用指标组合（base 向量宇宙）

| 版本   | base 指标数 | 合法组合数 | 说明 |
|--------|-------------|------------|------|
| CVSS 2.0  | 6 | 729 | 全部笛卡尔组合均被内核接受 |
| CVSS 3.0  | 8 | 2592 | 与 3.1 同指标域 |
| CVSS 3.1  | 8 | 2592 | 本工具主用版本 |
| CVSS 4.0  | 11 | 104976 | 仅 base 指标；含安全指标的可选扩展不在 base 宇宙 |

非法取值（如 `AV:X`、`S:X`、缺必填项、v4 的 `SA:Z`）会被内核抛出 `CVSSxError`，工具不会给它们打分。

## 什么算“一个独立事实”

定义：**恰好一个 base 指标改变取值**（例如 `C:N -> C:H`），其余指标完全相同，且改动前后两个向量都
是内核接受的合法向量。两个满足该条件的向量互为邻接（adjacency）。

- 单事实邻接总数：v3.1 = 18144，v2 = 4374（全量白名单下）。
- 图遍历只在这些合法邻接上进行；遍历到的连通区、跨档边、最短见证都可由同一内核复算。

## 分档与连通区

分档表在政策 JSON 中显式给出，必须构成从 0.0 起、无重叠无缺口、末档开口的连续划分，否则
`load_policy` 直接拒绝（`PolicyError`）。

- 全量白名单下，整个 base 宇宙是**单一连通区**，且该连通区横跨所有档位（跨档连通区 = 1）。
- `cross_band_edges`：单事实即跨档的边。
- `band_skipping_edges`：单事实**越过中间档**的边（例如 Critical 直接到 Medium），这是评审会最关心的
  “意外跳跃”。v3.1 有 376 条，v2 有 12 条。

## 最短变化见证（可复算）

`BandGraph.shortest_witness` 用 BFS 在覆盖子图内求两个向量间的最短单事实路径，输出每一步的向量、
分数、档位与变化事实。示例（v3.1，全零影响 -> 三高影响）距离为 3：

```
None      CVSS:3.1/.../C:N/I:N/A:N  0.0
C:N->H    .../C:H/I:N/A:N           7.5  High
I:N->H    .../C:H/I:H/A:N           9.1  Critical
A:N->H    .../C:H/I:H/A:H           9.8  Critical
```

注意第一步 `C:N->H` 就从 None 档跳到 High 档（跨过 Low/Medium），这本身就是一条跳档见证。

## 跨版本审查：旧版顺滑、新版跳跃

跨版本不能直接比较向量，因为指标集合不同。`examples/compare_v2_v31.json` 显式给出：

- 指标级映射（canonical 指标 -> 各版本本地指标）；
- 取值级映射（v2 的 `C`(Complete) 对应 v3.1 的 `H`，`P` 对应 `L`）；
- 未映射指标的固定基线（v2 `Au:N`；v3.1 `PR:N/UI:N/S:U`）。

只有在两个版本都能落到合法向量的候选才进入共享空间；任何一版无法落地都记为 `unavailable`，
不参与表决。共享空间 48 个向量、288 条单事实边，其中 80 条为版本间不一致的“意外跳跃”。典型例证：

| 事实 | CVSS 2.0（旧，顺滑） | CVSS 3.1（新，跳跃） |
|------|---------------------|---------------------|
| `AV:N->A` | 9.4 -> 7.8，High -> High（不动） | 9.1 -> 8.1，**Critical -> High**（紧急掉档） |
| `AC:L->H` | 9.4 -> 7.1，High -> High | 9.1 -> 7.4，**Critical -> High** |
| `C:N->H` | 7.8 -> 9.4，High -> High | 7.5 -> 9.1，**High -> Critical**（常规升紧急） |
| `AV:L->A` | 6.6 -> 7.8，**Medium -> High** | 7.7 -> 8.1，High -> High（不动） |

同一份分档配置在 v2 下相邻事实不改变处置，在 v3.1 下却会在“常规/加急/紧急”之间跳变——这正是需要
评审会复核的版本漂移。

## 用法

```bash
# 文本摘要（退出码 1 表示 needs-review，0 表示 pass，2 表示配置错误）
python3 -m policy_audit.cli --policy examples/policy_full.json

# 完整 JSON 工件
python3 -m policy_audit.cli --policy examples/policy_full.json --json > report.json

# 受限白名单：展示“缺失候选不算通过”
python3 -m policy_audit.cli --policy examples/policy_restricted.json

# 跨版本对照
python3 -m policy_audit.cli --policy examples/policy_full.json \
    --compare examples/compare_v2_v31.json

# 重新生成 reports/ 下全部可复算工件
python3 recompute.py
```

## 工件

- `examples/policy_full.json` / `policy_restricted.json`：全量与受限政策。
- `examples/compare_v2_v31.json`：跨版本指标/取值映射与基线。
- `reports/audit_full.json`、`reports/audit_restricted.json`：单版本完整审计（含每条跳档见证、
  每对档位的最短见证、被白名单挡断的邻接）。
- `reports/compare_v2_v31.json`：跨版本逐条边对照。
- `tests/test_policy_audit.py`：11 项单元测试，锁定宇宙规模、锚点分、非法向量拒绝、缺失候选、
  单事实不变量、跳档与跨版本跳跃。
