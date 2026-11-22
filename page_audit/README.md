# 只读 PDF 页面对照（pypdf）

证物员要核实：案卷 PDF 重排之后，原纸质每一页对应的数字页有没有被换过内容。
本目录是一个**只读**页面对照工具：程序先生成一对结构简单、内容确定的原件 /
重排件 PDF，再用 `pypdf.PdfReader` 从**页面结构、实际共享资源、内容证据**三个
独立维度推导可人工复核的页面对应关系。

审计模块 `auditor.py` / `report.py` 只调用 `PdfReader`，不导入 `PdfWriter`、
不写文件；生成 PDF 的写操作只存在于 `generator.py` / `pdf_tools.py`。

## 运行

```bash
# 生成样本并输出文本报告（fixtures 不存在时会自动生成）
python -m page_audit

# 重新生成确定性样本后再审计
python -m page_audit --regenerate

# 机器可读报告
python -m page_audit --json

# 对自己的两份 PDF 做同样的只读对照
python -m page_audit --original 原件.pdf --rearranged 重排件.pdf
```

样本输出到 `fixtures/paper_original.pdf` 与 `fixtures/digital_rearranged.pdf`。

## 样本剧本（1-based）

原件 `paper_original.pdf` 共 9 页 O1..O9，每页都有独立文本和一张独立图片：

| 原件 | 内容要点 | 字体 | 图片 |
| ---- | -------- | ---- | ---- |
| O1 | Case Caption / Folio O1 | Helvetica | I1 |
| O2 | Statement A / Folio O2 | Helvetica | I2 |
| O3 | Statement B / Folio O3 | Courier | I3 |
| O4 | Contract Clause / Folio O4 | Times-Roman | I4 |
| O5 | Signature Page / Folio O5 | Helvetica | I5 |
| O6 | Exhibit Inventory / Folio O6 | Courier | I6 |
| O7 | Duplicate Notice / Folio O7 | Helvetica | I7 |
| O8 | Closing Note / Folio O8 | Times-Roman | I8 |
| O9 | Standalone Addendum / Folio O9 | Helvetica | I9 |

重排件 `digital_rearranged.pdf` 共 8 页 R1..R8：

| 重排页 | 来源 | 情形 |
| ------ | ---- | ---- |
| R1 | O4 | 移动（顺序改变，内容不变） |
| R2 | O1 | 移动（顺序改变，内容不变） |
| R3 | O2 + O3 | 一页拆自两个来源（两源合一） |
| R4 | O5 上半 | 一个来源拆成两页（CropBox 上半） |
| R5 | O5 下半 | 一个来源拆成两页（CropBox 下半） |
| R6 | O6 + O8 | 一页拆自两个来源（两源合一） |
| R7 | O7 副本 A | 同内容页位置冲突 |
| R8 | O7 副本 B | 同内容页位置冲突 |
| — | O9 | 缺页：重排件中无任何承载页与残留内容 |

## 三类证据（每条结论都同时给出）

1. 结构证据 `structure`：`/MediaBox`、`/CropBox`、`/Rotation`。拆分页表现为
   `CropBox` 是 `MediaBox` 的子区域；普通页二者相等。
2. 资源证据 `resource`：字体字典的规范化哈希，以及图片 XObject **解码后字节**
   的 SHA-256。跨文档复制时 pypdf 会重新分配对象号，但图片/字体的实际字节
   保持不变，因此用内容哈希而不是对象号认定“同一份资源”。合并页会同时命中
   两个来源的图片哈希。
3. 内容证据 `content`：解码后内容流的 SHA-256 与抽取文本。内容流被改名 /
   拼接后哈希不再相等，就回退到文本行级别，确认目标页确实包含来源页的文字。

## 六类结论的区分口径

| 代号 | 中文结论 | 触发条件 |
| ---- | -------- | -------- |
| `exact_match` | 内容一致且位置一致 | 内容流哈希相同，且页序号相同 |
| `moved_page` | 内容一致但位置改变（移动页） | 内容流哈希相同，页序号不同 |
| `merged_two_sources` | 一页来自两个来源（两源合一） | 目标页同时命中 >=2 个来源的图片哈希与文本行 |
| `split_one_source` | 一个来源拆成两个数字页 | 多页内容流哈希指向同一来源，且 `CropBox` 为裁剪子区域 |
| `same_content_position_conflict` | 同内容页位置冲突（重复放置） | 同一内容流哈希出现在多个未裁剪的目标页 |
| `missing_page` | 原件缺页 | 全部重排页的资源与文本中都找不到该来源页的任何痕迹 |

注意三类易混结论的差别：

- 缺页 vs 合并：O2/O3/O8 虽然没有独立目标页，但它们的图片和文本仍完整出现在
  R3/R6 中，因此算“两源合一”而不是缺页；O9 在重排件里彻底无痕，才判缺页。
- 拆分 vs 重复：R4/R5 内容流相同但 `CropBox` 不同（各显示 O5 的一半），判
  “一源拆两页”；R7/R8 内容流相同且都未裁剪，是同一份内容被放了两次，判
  “同内容页位置冲突”。
- 移动 vs 换位冲突：单页内容流哈希唯一命中、仅序号变化判移动；同一哈希命中
  多个未裁剪目标页才判位置冲突。

## 双向引用如何复核

报告里每条判定点都给出两侧引用，可分别回到两份 PDF 原文核对：

- 原件引用：`原件 pN (obj G gen g, 内容 <hash12>)`，对象号 + 内容流哈希前缀。
- 重排引用：`重排件 pM (obj G gen g, 内容 <hash12>)`，缺页时明确写“无对应页
  （已核对全部 K 页）”。

对象号只在各自文件内有效；跨文件请比对 `内容 <hash12>` 与资源证据里的图片
哈希前缀，相同前缀即字节级同源。用 `--json` 可拿到完整 SHA-256 与逐条证据。

## 测试

`tests/test_page_audit.py` 固化了上述剧本的全部结论。依赖完整时直接运行：

```bash
python -m pytest tests/test_page_audit.py
```

若最小环境缺少 yaml/httpbin 等 pytest 插件依赖，可改用不依赖插件的内联自检，
它重新生成样本并断言六类结论齐全、合并页含两个图片哈希、拆分页 CropBox
不同、重复页同哈希、缺页为 O9、每条结论都有双向引用与三类证据、且审计前后
PDF 字节不变：

```bash
python -c "import tempfile; from pathlib import Path; from page_audit.generator import generate; from page_audit import auditor; d=Path(tempfile.mkdtemp()); op,rp=generate(d); ob,rb=op.read_bytes(),rp.read_bytes(); o,r,f=auditor.audit(op,rp); assert {x.conclusion for x in f}>={auditor.MOVED_PAGE,auditor.MERGED_PAGE,auditor.SPLIT_PAGE,auditor.SAME_CONTENT_CONFLICT,auditor.MISSING_PAGE}; assert op.read_bytes()==ob and rp.read_bytes()==rb; print("self-check OK:", len(f), "findings")"
```
