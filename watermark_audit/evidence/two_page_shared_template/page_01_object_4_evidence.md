# 页内水印证据：第 1 页

- 档案：`watermark_audit/fixtures/two_page_shared_template.pdf`
- PDF SHA-256：`04553164968c53e94082489bf224821877138747ddce3df84825fc202f7aedd8`
- 页面对象：`4 0 R`
- 判定：**proven_watermark_use**
- 回执声明：`{"page": 1, "receipt_status": "watermark_applied"}`

## 1. 页面身份与资源作用域

1. 持有者 `4 0 R`（/Page）；自有 /Resources=`False`；资源对象=`无 /Resources`
2. 持有者 `12 0 R`（/Pages）；自有 /Resources=`True`；资源对象=`9 0 R`
3. 持有者 `2 0 R`（/Pages）；自有 /Resources=`False`；资源对象=`无 /Resources`
- 生效资源由持有者 `12 0 R` 提供。

## 2. 水印对象与真实引用

- `/WM` -> `8 0 R`：**used**
  - 识别依据：resource name matches watermark pattern: /WM
  - 识别依据：decoded stream contains /Watermark marker or watermark text
  - 引用链：`page 1 object [4, 0] -> page /Contents op#12: /WM Do`

## 3. Do 操作与水印标记

- 页面直写操作统计：图形/路径 `4` 个，文本 `4` 个，Do `1` 个。
- 操作计数：`{"q": 3, "RG": 1, "w": 1, "re": 2, "S": 1, "Q": 3, "BT": 1, "Tf": 1, "Td": 1, "Tj": 1, "ET": 1, "Do": 1, "rg": 1, "f": 1}`
- 操作 #12：`/WM Do` -> `8 0 R`（/Form）
- 水印标记：`{"source": {"label": "Form XObject /WM", "object": [8, 0]}, "operation_index": 0, "operator": "BDC", "watermark_marked_content": "['/Artifact', {'/Type': '/Pagination', '/Subtype': '/Watermark'}]"}`

## 4. 解码后的页内流

内容对象 `10 0 R`，158 bytes，SHA-256 `82efa3bef21d719c84328dab0e6948073ecde0f7fbf6524b0c23d09efdbaf8b5`：
~~~~
q
0.12 0.31 0.58 RG
2 w
72 706 468 42 re S
Q
BT
/FBody 18 Tf
72 724 Td
(Page 1: content invokes /WM) Tj
ET
q
/WM Do
Q
q
0.2 0.55 0.25 rg
72 120 180 10 re f
Q

~~~~

XObject `/WM` -> `8 0 R` 解码流：
~~~~
/Artifact << /Type /Pagination /Subtype /Watermark >> BDC
q
0.82 0.82 0.82 rg
1 0 0 1 72 390 cm
0.94 -0.34 0.34 0.94 0 0 cm
BT
/FWM 46 Tf
1 0 0 1 0 0 Tm
(TEMPLATE WM OBJECT 7F3A) Tj
ET
Q
EMC

~~~~

## 5. 原始页面对象

~~~~
{
  "/Type": "/Page",
  "/MediaBox": [
    0.0,
    0.0,
    612,
    792
  ],
  "/Parent": "12 0 R",
  "/Contents": "10 0 R"
}
~~~~

## 6. 独立复核命令

~~~~bash
PYTHONPATH=. .venv/bin/python watermark_audit/audit_watermarks.py audit --pdf watermark_audit/fixtures/two_page_shared_template.pdf --receipt watermark_audit/fixtures/review_receipt.example.json
~~~~
