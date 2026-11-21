# ole_provenance - 原件/派生件 OLE 流对照办法

移交证据时，常从一个大 OLE 文档里挑出几个流（子存储）组成派生交接包，
交接文件会重写目录位置，导出时流名也可能变化。本工具回答一个问题：
派生包里的某个流，对应原件的哪个目录项、哪些字节？
如果证据不足，则给出并列候选并说明原因。

## 原则

- 原件与派生件都只通过 olefile 的读取接口（`OleFileIO.openstream` 及
  olefile 解析出的 FAT/MiniFAT/目录元数据）读取，不做裸文件雕刻。
- 旁车（sidecar，JSON）只带核查材料：流路径、名称、大小、内容的
  SHA-256、在原件中的字节区间、以及可选的来源证明（source proof）。
  旁车不携带任何流字节。
- 对照结论由旁车里当前剩余的证据实时重算：撤掉一条来源证明，
  唯一对应会自动降级为歧义（并列候选）。

## 判定规则

对派生包中的每个流：

1. 以 SHA-256 + 大小 在原件目录项中找候选。相同字节可能属于两条
   不同证物，因此候选可能不止一个。
2. 名称只作旁证提示（`name_hint`）：导出时可能改过名，相同名字不能
   作为定论，不同名字也不能排除。
3. 来源证明（导出工具在交接时记录的 derived_path 到 original_path 的
   映射）可以把多个候选收窄为一个；指向字节不匹配目录项的证明会被
   标记为矛盾（contradicted），不参与定论。

结论三档：

- `unique`：只剩一个原件目录项（内容唯一，或被一条来源证明锁定）。
- `ambiguous`：多个原件目录项持有相同字节且没有存活的来源证明，
  报告全部并列候选及其字节区间。
- `unmatched`：原件中没有这些字节（导出后被改动，或并非来自此原件）。

`resolve` 默认重新打开两个文件重算哈希，旁车过期或文件被改动时会
给出 WARNING 而不是静默采信。

## 用法

    # 生成演示样本（原件含两个字节相同的流 StreamA / streamB_copy）
    python -m ole_provenance sample exhibits/

    # 建旁车，合并导出日志里的来源证明
    python -m ole_provenance build exhibits/original.ole exhibits/derived.ole \
        exhibits/sidecar.json --proofs exhibits/export_log.json

    # 对照：renamed_export 经 proof-1 唯一对应到 Evidence/streamB_copy
    python -m ole_provenance resolve exhibits/sidecar.json

    # 撤掉一条来源证明后再次对照：自动降级为并列候选
    python -m ole_provenance drop-proof exhibits/sidecar.json proof-1
    python -m ole_provenance resolve exhibits/sidecar.json

`resolve` 的退出码：全部唯一为 0；存在歧义、未匹配或警告时为 1，
便于流水线卡口。

## 旁车格式（ole-stream-provenance/1）

- `original` / `derived`：文件名、整文件 SHA-256，以及每个流的
  `path`、`name`、`sid`、`size`、`sha256`、`chain`（fat/minifat）、
  `byte_ranges`（[文件偏移, 长度] 列表，按 FAT/MiniFAT 链算出，
  可直接按偏移回读原件核对字节）。
- `source_proofs`：`id`、`derived_path`、`original_path`、
  `export_name`、`note` 等核查材料。

## 布局

- `ole_provenance/sidecar.py`：旁车构建、解析、证明维护。
- `ole_provenance/cfbf_writer.py`：最小 CFBF 写入器，仅用于生成样本。
- `ole_provenance/sample.py`：演示样本（两个相同字节的流 + 改名导出）。
- `ole_provenance/cli.py`：命令行入口。
- `tests/test_ole_provenance.py`：含"撤证明即降级"的回归测试。
