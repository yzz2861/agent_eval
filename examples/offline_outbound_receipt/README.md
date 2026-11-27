# 离线外发签收示例

这个示例把“原件被签名”和“派生件可以外发”拆成两条独立事实。简版通知里的
`Delivery-Marker: signature-valid` 只是从原件复制的文字，不参与任何验签或交付判断。

## 证据链

- `notice-original.txt` 由原件签发方生成分离签名 `notice-original.txt.asc`。
- `derivation.json` 由独立的脱敏台签发，声明原件的 SHA-256 与简版的 SHA-256 之间的派生关系。
- `release-approval.json` 由发布审批方签发，并绑定 `derivation.json` 的 SHA-256。
- `outbound-receipt.json` 由外发台用 PGPy 分离签名，记录上述证据各自的摘要和签名路径。
- 简版 `notice-external.txt` 没有自己的密码学签名，其中继承的交付标记不构成签名证据。

验证器要求：

1. 外发签收本身的签名覆盖签收文件的原始字节。
2. 原件摘要与签收声明一致，且原件的分离签名可验证。
3. 独立派生声明由声明中的签发方签名，并且实际原件摘要、实际附件摘要都与声明一致。
4. 发布审批的摘要与签收一致，审批签名可验证，且审批绑定的是实际派生声明的摘要。
5. 简版是否有自己的签名，通过检查实际附件旁的分离签名或内联签名得到，不读取继承的文字标记。

## 运行

在仓库根目录执行：

```bash
python -m pgpy.handoff examples/offline_outbound_receipt/archive
```

正常归档输出三个核心事实：

```json
{
  "original_signature_valid": true,
  "derivative_deliverable": true,
  "simplified_has_own_signature": false
}
```

简版没有自己的签名并不妨碍这次交付，因为交付依据是独立的派生声明、发布审批和已签名的外发签收，而不是原件签名或继承的交付标记。

## 同名但摘要不匹配的附件

`negative/notice-external.txt` 与正常附件同名，但内容不同。接收台显式指定这个附件：

```bash
python -m pgpy.handoff examples/offline_outbound_receipt/archive \
  --derivative examples/offline_outbound_receipt/negative/notice-external.txt
```

输出会保留原件验签结果，同时拒收派生件，并定位到缺失覆盖的交接声明：

```json
{
  "original_signature_valid": true,
  "derivative_deliverable": false,
  "simplified_has_own_signature": false,
  "missing_evidence": ["handoff.derivation.derivative.sha256"],
  "failures": [
    {
      "code": "DERIVATION_DERIVATIVE_DIGEST_MISMATCH",
      "claim": "handoff.derivation.derivative.sha256",
      "evidence": "derivation.json"
    }
  ]
}
```

退出码约定：交付成功为 `0`，证据不足或摘要不匹配为 `1`，参数或签收文件无法读取也会体现在 JSON 的 `failures` 中。

## 重新生成

示例只使用仓库中的测试密钥，不应作为生产密钥使用：

```bash
python examples/offline_outbound_receipt/build_fixture.py
```

生成器会重建 `archive/`、`negative/` 和 `expected/`，并通过同一个验证器生成两份预期报告。
