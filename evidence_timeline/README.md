# evidence_timeline — 合成 CMS 时间回执时间线解释器

本包只做 **ASN.1 解析与结构性哈希核对**，不做任何签名验证、证书链判断或
时间戳机构信任决策。所有“可信/不可信”结论由调用方通过 `TrustInputs`
传入；包内只重算消息摘要（哈希比较，不是密码学验签），并解释每条时间回执
当时承诺了哪段真实字节。

## 边界与设计原则

- **只用 asn1crypto 解析** 调用方提供的合成 CMS / TST 字节，不引入其他
  ASN.1 依赖，也不修改 asn1crypto 本体。
- **信任结论外部注入**：`TrustInputs(token_verdicts={...})`，取值仅允许
  `trusted / rejected / undetermined`，非法值在边界直接报错。
- **记录真实字节范围**：每条承诺都给出宿主记录内的 `[start, end)` 区间，
  并验证区间字节重算哈希等于 TSTInfo 的 messageImprint。
- **缺材料不倒推原件**：找不到前置记录时，只报告缺失段的摘要和“仍可走通
  的后段”，不会猜测或重建缺失原件的内容。
- **换包装可识别**：外层 ContentInfo 变化但内层原记录字节完整保留时，
  标记 `repackaged=True`，原承诺仍按原字节范围核对通过，时间线不断链。

## 三段回执样本

`evidence_timeline/samples.py` 构造隔几年补盖一次的合成材料：

| 记录 | 回执时间 | 回执承诺对象 | 前置回执 |
| --- | --- | --- | --- |
| `stage1-2018` | 2018-06-01 | 原 CMS 签名 OCTET STRING 的内容字节（RFC 3161 签名时间戳） | 无 |
| `stage2-2021` | 2021-06-01 | 整份 stage1 记录 DER（归档续期式回执） | stage1-2018 |
| `stage3-2024` | 2024-06-01 | 整份 stage2 记录 DER | stage2-2021 |

签名 OCTET STRING 中放的是标记字节而非真实签名；结构本身是合法的
CMS `SignedData` / TSTInfo，asn1crypto 可完整往返解析。

## 演示命令

```
python3 -m evidence_timeline.cli --scenario clean --out-dir sample_output
python3 -m evidence_timeline.cli --scenario repackaged --out-dir sample_output/repack
python3 -m evidence_timeline.cli --scenario replaced-middle --out-dir sample_output/replaced
```

- `clean`：三段齐全，无缺口，可证窗口
  `tst-serial-1 -> tst-serial-2 -> tst-serial-3`。
- `repackaged`：stage1 被套进不同外层 ContentInfo；输出标记
  `outer packaging changed; original commitment still verifiable`，
  且时间线无缺口。
- `replaced-middle`：用一份无回执的外来 CMS 替换中间记录。时间表读出
  tst-serial-3 的 imprint 仍指向缺失的 2021 段（给出期望 sha256），
  可证窗口退化为 `tst-serial-1 -> tst-serial-3`，明确说明缺的是哪段
  可证历史，且不倒推原件。

加 `--json` 可同时输出结构化 JSON。生成的 `.der` 写入 `--out-dir`。

## 编程接口

```python
from evidence_timeline import TimelineAnalyzer, TrustInputs, TrustInput
from evidence_timeline.samples import build_three_stage_sample

records, _ = build_three_stage_sample()
analyzer = TimelineAnalyzer(TrustInputs(token_verdicts={
    'tst-serial-1': TrustInput.TRUSTED,
    'tst-serial-2': TrustInput.TRUSTED,
    'tst-serial-3': TrustInput.TRUSTED,
}))
for record in records:
    analyzer.add_record(record.record_id, record.blob)
timeline = analyzer.build()

for entry in timeline.timeline:
    print(entry.token_id, entry.commitment.kind,
          [str(r) for r in entry.commitment.byte_ranges],
          entry.predecessor, entry.trust)
```

## 模块说明

- `parser.py`：递归解析外层包装、封装内容、签名者 unsignedAttrs 中的
  ContentInfo，只登记每条记录直接持有的回执，避免把前序记录里的回执
  重复算成当前记录的承诺。
- `offsets.py`：在 DER blob 中定位子编码的真实字节区间。
- `analyzer.py`：候选承诺匹配（签名内容 / SignerInfo / 嵌套记录 /
  整记录）、前置回执解析、换包装标记、缺口与可证窗口计算。
- `model.py`：结构化结果类型与调用方信任输入。
- `samples.py`：合成 CMS 与三段时间回执样本、换包装与替换中间记录材料。
- `cli.py`：命令行演示。

## 测试

```
python3 -m unittest tests_evidence_timeline.test_timeline -v
```

覆盖：时间线顺序、真实字节区间哈希核对、前置链、调用方信任边界、
换包装不断链、替换/缺失中间段的精确缺口报告。
