# Bandit 插件升级离线回归链路

只依赖 Python 标准库，消费调用方冻结的人工裁决样本与两份原生
`bandit -f json` 扫描结果，按规则关注点 / 代码家族 / 有效适用范围做
逐格对照，并对重点群组执行可单独设下限的回归门禁。

## 目录

- `regression/`：回归工具包（模型、加载、对照引擎、门禁、报告、CLI）
- `fixtures/frozen/`：冻结输入
  - `freeze.json`：冻结批次元数据
  - `samples.json`：人工裁决样本（含 sha256，允许 `duplicate_of` 重复行）
  - `rule_catalogue.json`：规则目录（规则 ID、家族、默认严重度）
  - `applicability.json`：样本 x 规则适用矩阵，`in_scope=false` 排除出分母
  - `gate.json`：默认召回率下限与重点群组单独门槛
  - `src/company/`：冻结样本对应的源码
- `fixtures/scans/`：升级前 / 升级后两份 Bandit JSON 扫描结果
- `tests/`：unittest 测试
- `output/`：生成物（两份 Markdown 短报告 + 机器可读 JSON）

## 分母防膨胀规则

- 重复样本（`duplicate_of`）在构建对照格前剔除，不进入任何分母。
- 同一 `(文件, 规则, line_range)` 的多条命中去重为一条，
  `duplicate_hits_removed` 单独留痕。
- `in_scope=false` 的适用矩阵单元格不计入有效适用分母。

## 三态分别复算

每个有效适用格只会得到一种结论：

- `hit`：扫描命中；再按人工裁决拆成应报命中与误报仍报。
- `scan_missing`：规则在用、应有发现但扫描静默（扫描缺失）。
- `rule_disabled`：该规则在本次扫描被停用（与扫描缺失区分）。
- `correctly_silent`：人工裁决无发现且扫描保持静默（确实没有报）。
- `out_of_scope`：不在有效适用范围，排除出分母。

召回率 = 应报命中 / 应有发现格，误报不计入分子，因此不会超过 100%。

## 门禁

- `default_min_recall` 为默认下限；`gate.json` 中每个家族可单独覆盖。
- `block_on_critical_miss=true` 的群组只要丢失人工确认的 HIGH 发现即阻断，
  阻断证据写入报告二与 JSON 的 `reasons`。
- 命中总数仅作背景展示，不参与门禁，避免“多报几项就过关”。

## 运行

    python3 -m regression \
      --frozen-dir fixtures/frozen \
      --old-scan fixtures/scans/old_bandit.json \
      --new-scan fixtures/scans/new_bandit.json \
      --output-dir output \
      --sample-root fixtures/frozen

或执行 `./run_regression.sh`。门禁阻断时进程退出码为 1。

## 测试

    python3 -m unittest discover -s tests -v
