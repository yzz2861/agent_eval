# OLE 预览来源离线交叉验证报告

## 验证范围

本报告仅使用本地 `olefile` 读取复合文件，不访问网络。每个复合文件分别枚举存储分支、流、剪贴板类型、关系清单和摘要，并把预览引用与容器内源流做哈希交叉验证。

## artifacts/missing-source-preview.ole

- 容器 SHA-256：`8794620c299bca1062d60a9d4e164cb959183a8a05392104131d758be77b8aff`
- 容器大小：`5632` 字节
- 存储分支：`AttachmentPreview`, `DocumentPreview`
- 流数量：`7`

| 证据 ID | 容器归属 | 存储分支 | 剪贴板类型 | 源流解析 | 哈希一致 | 结论上限 |
|---|---|---|---|---|---|---|
| DOC-PREVIEW-001 | document_preview | `DocumentPreview` | `49153` / JPEG | 缺源流：`Archive/SharedContent` 不存在 | 不可核对 | 仅能证明预览声明和哈希；不能证明源流存在、来源链条或真实性 |
| ATT-PREVIEW-001 | attachment_preview | `AttachmentPreview` | `49153` / JPEG | 缺源流：`Archive/SharedContent` 不存在 | 不可核对 | 仅能证明预览声明和哈希；不能证明源流存在、来源链条或真实性 |

### 流清单

- `AttachmentPreview/ClipboardType`
- `AttachmentPreview/PreviewRef`
- `AttachmentPreview/Summary`
- `Crosswalk`
- `DocumentPreview/ClipboardType`
- `DocumentPreview/PreviewRef`
- `DocumentPreview/Summary`

## artifacts/fully-verifiable-file.ole

- 容器 SHA-256：`24968a379523121bdc6cb6126805d609f2fdb80671ccffeda591b0a307077d62`
- 容器大小：`39424` 字节
- 存储分支：`Archive`, `AttachmentPreview`, `DocumentPreview`
- 流数量：`8`

| 证据 ID | 容器归属 | 存储分支 | 剪贴板类型 | 源流解析 | 哈希一致 | 结论上限 |
|---|---|---|---|---|---|---|
| DOC-PREVIEW-001 | document_preview | `DocumentPreview` | `49153` / JPEG | 可解析：`Archive/SharedContent` | 是 | 可证明预览内容及证据关系来源 |
| ATT-PREVIEW-001 | attachment_preview | `AttachmentPreview` | `49153` / JPEG | 可解析：`Archive/SharedContent` | 是 | 可证明预览内容及证据关系来源 |

### 流清单

- `Archive/SharedContent`
- `AttachmentPreview/ClipboardType`
- `AttachmentPreview/PreviewRef`
- `AttachmentPreview/Summary`
- `Crosswalk`
- `DocumentPreview/ClipboardType`
- `DocumentPreview/PreviewRef`
- `DocumentPreview/Summary`

## 综合判断

- `missing-source-preview.ole` 中，文档预览与附件预览仍位于两个独立容器分支，但其共同引用的 `Archive/SharedContent` 不存在；只能证明两个关系声明引用了相同哈希，不能证明该哈希对应字节真实存在或来源真实。
- `fully-verifiable-file.ole` 中，两个独立容器分支引用同一个 `Archive/SharedContent` 归档流；相同内容只保存一份，归档哈希与两条关系声明均一致。
- 因此，外部复核报告把两个预览合并成一份图像证据的结论上限过高：即使字节相同，文档预览和附件预览的证据关系也必须分别归属到各自容器。
