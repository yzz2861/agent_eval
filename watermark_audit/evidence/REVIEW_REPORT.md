# 水印回执复核汇总

- 档案：`watermark_audit/fixtures/two_page_shared_template.pdf`
- 页数：2
- 可证明使用水印：`[1]`
- 只声明水印资源：`[2]`
- 未发现水印特征：`[]`

## 回执裁决

- 回执声称页面：`[1, 2]`
- 证据支持：`[1]`
- 仅资源声明、不支持已应用：`[2]`
- 无证据、不支持已应用：`[]`

## 逐页判定

| 页码 | 页对象 | 判定 | 实际引用 | 只声明资源 |
|---:|---|---|---|---|
| 1 | `4 0 R` | proven_watermark_use | /WM | — |
| 2 | `5 0 R` | watermark_resource_only_declared | — | /WM |
