# 水印引用复核工具

这个目录用 `pypdf` 把三类标识对齐：

- 页面身份：页序与页对象间接引用，例如 `4 0 R`、`5 0 R`。
- 资源作用域：页面自有 `/Resources`，或沿 `/Parent` 链找到的可继承 `/Resources`。
- 内容流引用：只有解析到真实的 `/Name Do`，并能在当前资源作用域解析到水印 XObject，才算实际使用。

## 当前样本

工作区中没有题述外部批次 PDF 或原始回执附件；因此这里生成了一个最小但结构完整的对照样本：

- `fixtures/two_page_shared_template.pdf`：两页是不同页对象 `4 0 R` 和 `5 0 R`。
- 两页均无页面自有 `/Resources`，共同继承模板页树对象 `12 0 R` 的资源对象 `9 0 R`。
- 共享资源中的 `/WM` 指向水印 Form XObject `8 0 R`。
- 第 1 页内容对象 `10 0 R` 含 `/WM Do`，可证明使用水印。
- 第 2 页内容对象 `11 0 R` 没有 `/WM Do`；它只能通过模板作用域看到 `/WM`，属于只声明资源。
- `fixtures/review_receipt.example.json` 是对应的合成回执，声称两页均已加水印；复核结论只支持第 1 页。

## 重新生成与复核

```bash
PYTHONPATH=. .venv/bin/python watermark_audit/make_fixtures.py
PYTHONPATH=. .venv/bin/python watermark_audit/audit_watermarks.py audit \
  --pdf watermark_audit/fixtures/two_page_shared_template.pdf \
  --receipt watermark_audit/fixtures/review_receipt.example.json
```

复核真实合并档案时，把 `--pdf` 指向实际文件即可；`--receipt` 可选，支持包含 `specified_pages` 或 `page_claims` 的 JSON。

## 产物

- `evidence/REVIEW_REPORT.md`：汇总表和回执裁决。
- `evidence/two_page_shared_template/SHARED_TEMPLATE_EVIDENCE.md`：两页合并证据。
- `evidence/two_page_shared_template/page_01_object_4_evidence.md`：第 1 页独立证据。
- `evidence/two_page_shared_template/page_02_object_5_evidence.md`：第 2 页独立证据。
- `evidence/two_page_shared_template/audit_report.json`：机器可读完整结果。
- `evidence/two_page_shared_template/page_*_content_*.txt`：解码后的页内内容流。

## 判定边界

仅在 `/Resources/XObject` 中出现水印对象，或 `pypdf` 的资源枚举能看到它，不能证明水印被绘制。正常证据链必须是：

`页对象 -> /Contents -> /WM Do -> 当前作用域 /Resources/XObject/WM -> 水印 Form XObject`。

若调用发生在 Form XObject 内，工具会继续递归解析嵌套 `Do`；但不会把未被内容流静态引用的资源计为已使用。

