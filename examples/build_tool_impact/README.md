# 构建工具离线影响核算示例

这个示例回答一个具体问题：供应商公告说某段时间分发的构建工具存在安全问题，成品 SBOM 里只记录了工具名，如何判断哪一次构建、哪一个发行包真正受影响。

核算只读取本地文件，不访问网络：

- `data/frozen-build-archive.json`：明确冻结的构建行为归档。必须声明 `"frozen": true`，并记录每个构建实际使用的工具版本、拉取时间、使用时间、来源仓库、commit 和工具摘要。
- `data/tool-advisory.json`：工具仓公告。记录受影响版本、受影响来源 commit、受影响工具摘要、工具分发时间窗和修复版本。
- `data/sbom/*.cdx.json`：发行包 SBOM。组件通过 `component.hashes` 和 `component.evidence.identity` 声明发行包摘要，通过 `component.evidence.occurrences` 记录观测位置，通过 `metadata.tools` 记录工具名。示例中的 SBOM 只写工具名，不写工具摘要，和问题描述一致。

## 核算规则

1. 冻结归档优先于 SBOM 中的摘要声明。SBOM 摘要只用于识别发行包，不用于证明构建过程。
2. 先按发行标识精确匹配归档记录；没有发行标识时，才用发行包摘要加组件名、版本匹配。摘要相同但存在多条构建记录时，直接列为不可确认，不做猜测。
3. 工具来源 commit 或工具摘要命中公告时，判定受影响，即使版本标签看起来是修复版本。
4. 工具来源 commit 和摘要都明确不命中公告时，可以清除受影响版本标签的嫌疑。
5. 工具版本受影响但来源未知时，按实际拉取或使用时间判断：早于恶意分发时间窗开始，可以排除；处于或晚于时间窗，列为不可确认。
6. 复制件和镜像件没有独立构建行为，不能继承源构建的结论，必须重验工具来源。
7. 重制件只在它自己的冻结构建记录上核算，不能自动继承源构建的结论；它的独立记录可以给出新的结论。
8. 工具来源不可确认的发行包单列，不进入“未受影响”计数。

## 运行

```bash
python -m cyclonedx.contrib.build_impact \
  --archive examples/build_tool_impact/data/frozen-build-archive.json \
  --advisory examples/build_tool_impact/data/tool-advisory.json \
  --sbom-dir examples/build_tool_impact/data/sbom \
  --json-out examples/build_tool_impact/audit-sheet.json \
  --markdown-out examples/build_tool_impact/audit-sheet.md \
  --csv-out examples/build_tool_impact/audit-sheet.csv
```

`--fail-on affected|unconfirmed|any` 可以在 CI 中把受影响或不可确认的发行包变成非零退出码。

## 示例批次

六个发行包的 SBOM 摘要完全相同，外观上都是正常包；只有冻结归档才能区分它们的实际构建历史。

六个示例发行包的 SBOM 摘要完全相同：

`84ff0b62b508841b3010e8707eb0b0c9463bb8a052580903b08f93c30829cda0`

但冻结归档显示它们的构建历史不同：

| 发行标识 | 构建 | 历史 | 工具 | 工具来源 | 结论 | 需要重验工具来源 |
| --- | --- | --- | --- | --- | --- | --- |
| `REL-US-EARLY` | B-4101 | 原始构建 | forgepack 2.3.0 | `a1b2c3d4e5f6` / `00fb493a8cba` | 未受影响 | 否 |
| `REL-EU-BAD` | B-4102 | 原始构建 | forgepack 2.4.1 | `9f2c7d1e4b6a` / `3eb43e330685` | 受影响 | 否 |
| `REL-APAC-REBUILD` | B-4103 | 重制，独立构建记录 | forgepack 2.4.4 | `5a6b7c8d9e0f` / `da51cd3aa2cc` | 未受影响 | 否 |
| `REL-CN-PINNED` | B-4104 | 原始构建 | forgepack 2.4.1 | `c0ffee123456` / `55f1e0c0a020` | 未受影响 | 否 |
| `REL-LATAM-COPY` | B-4105 | B-4101 的复制件 | 无独立调用 | 不可确认 | 工具不可确认 | **是** |
| `REL-US-LATE` | B-4106 | 原始构建 | forgepack 2.4.4 | `5a6b7c8d9e0f` / `da51cd3aa2cc` | 未受影响 | 否 |

关键点：

- `REL-EU-BAD` 的工具来源摘要命中公告，虽然发行包摘要和其余五个相同，仍然判定受影响。
- `REL-CN-PINNED` 的版本 `2.4.1` 在受影响版本列表中，但它使用的是固定干净来源，且拉取时间早于恶意分发时间窗，因此可以排除。
- `REL-APAC-REBUILD` 是重制件，不继承 B-4101 的结论，而是用自己的 B-4103 构建记录重新核算。
- `REL-LATAM-COPY` 是 B-4101 的复制件。B-4101 本身未受影响，但复制动作没有独立工具调用，所以不能继承 B-4101 的干净结论。它是本批次唯一需要重验工具来源的发行包。

审核单中的 `requires_tool_provenance_reverification=YES` 列和 `tool_provenance_unconfirmed` 单列区域都只指向 `REL-LATAM-COPY`。

## 输出

- `audit-sheet.json`：机器可读审核单，包含每个发行包的组件、摘要、证据位置、构建记录、工具来源、结论和原因。
- `audit-sheet.md`：人工审核单，包含摘要相同的批次视图、受影响清单、未受影响清单、工具不可确认单列和明确的重验结论。
- `audit-sheet.csv`：扁平审核单，适合表格工具筛选 `requires_tool_provenance_reverification=yes`。

## 重新生成示例 SBOM

```bash
python examples/build_tool_impact/generate_sample_data.py
```
