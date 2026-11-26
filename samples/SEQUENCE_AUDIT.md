# 有序 REG_MULTI_SZ 审计对照

这份验收材料从 tests/reg_samples/issue22.hive 派生两份离线 hive：

- tests/reg_samples/audit_recipients_baseline.hive
- tests/reg_samples/audit_recipients_current.hive

重新生成命令：

    python samples/build_audit_sequence_fixtures.py

输出完整 JSON 报告：

    python samples/sequence_audit.py --json

## 合法重复成员与批准追加

键位置为 AuditConfig（NK 偏移 0x1024），值为 AuditRecipients（VK 偏移 0x136c）。

基线序号：

1. alice
2. 空字符串
3. bob
4. alice（第 1 项的合法重复声明）
5. rob（审批记录中 bob 的别名）

当前 hive 在第 6 位追加 bob。集合导出仍是空字符串、alice、bob、rob 四项，
因此看不出这次重复声明。samples/audit_approvals.json 中的 APR-094-01
明确批准追加基线原序号 3 的成员，所以当前第 6 项可映射并授权到原序号 3。

## 仅重排样本

ReorderOnly 的基线是：

1. alice
2. bob
3. alice
4. 空字符串

当前顺序是空字符串、alice、alice、bob。出现次序映射为：

- 当前第 1 项 <- 基线第 4 项
- 当前第 2 项 <- 基线第 1 项
- 当前第 3 项 <- 基线第 3 项
- 当前第 4 项 <- 基线第 2 项

两边成员计数完全相同，因此结论是 reorder-only：没有新增出现项，也不需要追加授权。

## 未批准对照

DeniedAppend 从 carol、dan 变为 carol、dan、eve。
审批记录没有对应条目，因此第 3 项 eve 保持 unauthorized。
