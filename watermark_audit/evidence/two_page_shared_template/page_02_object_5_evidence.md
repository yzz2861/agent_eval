# 页内水印证据：第 2 页

- 档案：`watermark_audit/fixtures/two_page_shared_template.pdf`
- PDF SHA-256：`04553164968c53e94082489bf224821877138747ddce3df84825fc202f7aedd8`
- 页面对象：`5 0 R`
- 判定：**watermark_resource_only_declared**
- 回执声明：`{"page": 2, "receipt_status": "watermark_applied"}`

## 1. 页面身份与资源作用域

1. 持有者 `5 0 R`（/Page）；自有 /Resources=`False`；资源对象=`无 /Resources`
2. 持有者 `12 0 R`（/Pages）；自有 /Resources=`True`；资源对象=`9 0 R`
3. 持有者 `2 0 R`（/Pages）；自有 /Resources=`False`；资源对象=`无 /Resources`
- 生效资源由持有者 `12 0 R` 提供。

## 2. 水印对象与真实引用

- `/WM` -> `8 0 R`：**declared_only**
  - 识别依据：resource name matches watermark pattern: /WM
  - 识别依据：decoded stream contains /Watermark marker or watermark text
  - 内容流没有对应的 Do 操作；仅声明资源，不能证明水印被绘制。

## 3. Do 操作与水印标记

- 页面直写操作统计：图形/路径 `4` 个，文本 `4` 个，Do `0` 个。
- 操作计数：`{"q": 2, "RG": 1, "w": 1, "re": 2, "S": 1, "Q": 2, "BT": 1, "Tf": 1, "Td": 1, "Tj": 1, "ET": 1, "rg": 1, "f": 1}`
- 本页静态内容流未发现任何 Do XObject 调用。

## 4. 解码后的页内流

内容对象 `11 0 R`，154 bytes，SHA-256 `686acbacb5ead683e86557584885433acb1adb65d677a6f214bb868b6037bb41`：
~~~~
q
0.58 0.18 0.12 RG
2 w
72 706 468 42 re S
Q
BT
/FBody 18 Tf
72 724 Td
(Page 2: inherited /WM is not invoked) Tj
ET
q
0.2 0.4 0.8 rg
72 120 260 10 re f
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
  "/Contents": "11 0 R"
}
~~~~

## 6. 独立复核命令

~~~~bash
PYTHONPATH=. .venv/bin/python watermark_audit/audit_watermarks.py audit --pdf watermark_audit/fixtures/two_page_shared_template.pdf --receipt watermark_audit/fixtures/review_receipt.example.json
~~~~
