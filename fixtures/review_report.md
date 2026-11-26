# 泛型保密声明复核结果

- 程序集：`ReviewSample`
- 声明标识：`CONFIDENTIAL-REVIEW-016`

| 入口 | 状态 | 判定位置 | 可依赖来源 | 待证外部引用 |
| --- | --- | --- | --- | --- |
| `0x0A000001` ReviewAudit.IntBox::Read | supported_with_pending_external_evidence | 开放泛型定义上的声明 | `0x06000003` ReviewAudit.Box&#96;1::Read（开放泛型定义上的声明） | `Missing.Contracts` |
| `0x0A000002` ReviewAudit.StringBox::Write | supported_with_pending_external_evidence | 闭合/实例实现上的声明 | `0x06000004` ReviewAudit.StringBox::Write（闭合/实例实现上的声明） | `Missing.Contracts` |
| `0x06000005` ReviewAudit.ExplicitEndpoint::ConfirmExplicit | supported | 显式接口映射指向的接口声明 | `0x06000002` ReviewAudit.IConfidential::Confirm（显式接口映射指向的接口声明） | 无 |

## 外部引用

- `0x23000001` `Missing.Contracts` 1.0.0.0：缺失，保留待证
