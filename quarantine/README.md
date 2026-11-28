# 隔离附件重新送审名单

周末更新格式识别规则后，用当前 `filetype` 匹配能力重新扫描仍在隔离区的
附件，并结合两份接收政策计算需要重新签收（重新送审）的名单。

运行方式：

```bash
python -m quarantine.cli          # 可读报告
python -m quarantine.cli --json   # 两份政策的结构化结果
```

测试：

```bash
python -m unittest discover -s tests -p 'test_*.py'
```

## 模块结构

- `quarantine/rules.py`：规则注册表。按 `filetype.types.TYPES` 的权威顺序
  展开为 100 条可单独寻址的规则；一个格式名可由多条规则支撑。
- `quarantine/engine.py`：只读取本地字节（路径、`bytes`/`bytearray`、文件
  对象，均只看前 8192 字节），按注册表顺序评估并记录所有命中规则。
- `quarantine/policy.py`：两份接收政策与重新送审判定。
- `quarantine/data.py`：调用方提供的小型历史结果和 10 个隔离附件样本。
- `quarantine/cli.py`：报告入口。

## 匹配顺序

`filetype.match` 对规则按固定顺序短路求值，**第一个返回 `True` 的规则胜出**，
注册表严格复刻该顺序：图像 → 音频 → 视频 → 字体 → 文档 → 归档 → 应用。
顺序对结果有实际影响：

- OOXML/ODF 文档本身是 ZIP 包。`docx/xlsx/pptx/odt/ods/odp/epub` 排在通用
  `zip` 规则之前；当文档结构证据被截断时，文档规则不命中，附件会按顺序
  回退为 `zip`（见 `ATT-004` 的截断实验与 `test_docx_falls_back_to_zip...`）。
- `dcm`（DICOM）在图像组和归档组各有一个匹配器，图像组在前，因此同一份
  DICOM 数据始终由 `dcm.image-group` 胜出。
- 一个格式内的多条规则同样按序短路，例如 `zst` 先评估常规帧，再评估
  可跳过帧；`doc` 的三条 OLE 规则按注册表顺序依次尝试。

引擎同时返回“胜出规则”和“全部命中规则”，因此顺序敏感的歧义可以直接看到。

## 规则拆分与规则级签收

部分 `filetype` 类型把多条替代签名收在同一个匹配器里（例如 `Zstd` 同时
处理常规帧和可跳过帧）。注册表用独立 predicate 把它们拆成带稳定 ID 的规则，
例如：

- `zst.frame`：常规帧魔数 `28 B5 2F FD` 系列，4 字节即可证实。
- `zst.skippable`：可跳过帧头 `50 2A 4D 1x` + 载荷长度 + 后续常规帧，需要
  至少 16 字节，且首字节无法通过常规帧规则。

这让“旧批准只适用单条规则”可以精确表达：旧批准记录的是 `zst.frame`，
周末后附件改由 `zst.skippable` 命中时，即便格式名仍是 `zst`，规则级政策
也要求重新签收。

## 证据是否足够

证据判定分两层：

1. **规则下限**（`Rule.min_bytes`）：该签名需要的最小完整字节数，例如
   可跳过帧需要 16 字节、`tar` 的 ustar 魔数在偏移 257 处需要 262 字节。
2. **网关证据阈值**（`Policy.evidence_floor`，示例为 4 字节）：即使匹配器
   的魔数守卫更短，网关也要求完整签名块。3 字节 JPEG SOI 能被 `filetype`
   识别为 `jpg`，但达不到 4 字节阈值，标记为 `evidence-insufficient`
   （`ATT-006`）。

若捕获短到任何规则都无法命中，则结果为 `unrecognized-format`，同样需要
重新送审，因为没有当前证据可以承接旧批准。

## 两份政策的差异及影响

| 维度 | `legacy-rule`（旧） | `format-level`（新） |
| --- | --- | --- |
| 签收绑定对象 | 单条规则 ID | 格式名（extension/MIME） |
| 同格式换规则 | 重新签收 | 同格式任意当前规则承接，免签收 |
| 规则退役 | 旧规则 ID 消失即重新签收 | 同格式仍有现行规则则免签收 |
| 准入名单 | 不含 `rtf` | 新增 `rtf` |
| 证据阈值 | 4 字节 | 4 字节 |

对既有结果的影响（10 个样本）：旧政策需重新签收 6 个，新政策只需 2 个。

- `ATT-002`（**验收示例**）：格式名 `zst` 未变，但旧批准仅覆盖
  `zst.frame`，当前仅命中 `zst.skippable`。旧政策判 `matched-rule-changed`
  需签收；新政策因格式名一致直接放行。
- `ATT-003`：同为 `doc`，但三条 OLE 规则中的命中规则由
  `doc.worddoc-stream` 变为 `doc.root-entry`，旧政策需签收，新政策放行。
- `ATT-009`：旧批准引用已退役的 `tar.legacy-ustar`，当前规则表只有 `tar`。
  旧政策判 `rule-retired` 需签收；新政策按格式族承接放行。
- `ATT-008`：`rtf` 在旧名单外判 `format-not-allowed`，新名单已接纳而放行。
- `ATT-006`：两份政策都因证据不足需重新送审。
- `ATT-007`：格式由 `doc` 变为 `docx`，两份政策都判 `format-changed`。
- `ATT-001/004/005/010`：规则与格式均稳定，两份政策都直接放行。

## 判定原因码

- `matched-rule-changed`：格式名相同但命中规则不同（仅规则级政策产生）。
- `rule-retired`：旧批准的规则 ID 已不在当前注册表（仅规则级政策产生）。
- `format-changed`：当前识别格式与旧批准格式不一致。
- `evidence-insufficient`：命中规则但头部字节低于网关证据阈值。
- `unrecognized-format`：没有任何当前规则匹配。
- `format-not-allowed`：格式不在该政策准入名单。
- `no-prior-approval`：历史结果中没有该附件的批准记录。
