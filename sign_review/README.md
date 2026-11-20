# sign_review：基于 pypdf 的签后差异审阅

## 目标

法务拿到两份已签名表单，签名的字节校验均显示有效，但后续又发生了不同程度的修订。
本包不做任何密码学判断，只负责：

1. 把 PDF 按增量更新拆成一个个修订（revision）；
2. 把每个签名的 `/ByteRange` 映射到它实际覆盖的那个修订；
3. 对签名之后的每个修订做字段、字段外观、页面内容/几何、共享资源与继承属性的逐项比对；
4. 依据调用方显式传入的 `ReviewPolicy` 判定每项变更是 `allowed` 还是 `unauthorized`；
5. 无法完整解析的尾部修订标记为 `truncated`，一律留作人工待查。

签名是否有效由调用方实现 `SignatureVerifier` 注入，库本身不做信任决策。

## 模块

- `revisions.py`：字节级扫描 `%%EOF`/`startxref`，解析 xref，输出 `RevisionScan` 与截断片段。
- `snapshot.py`：把某个修订前缀解析为字段、页面、资源、继承属性的纯数据快照。
- `engine.py`：编排签名映射、逐版差异、许可裁决与 `ReviewRecord` 组装。
- `verifiers.py`：验证器协议、结构占位验证器与 ByteRange 摘要验证器。
- `demo/fixtures.py`：用 pypdf 增量更新构造多修订 PDF 夹具。
- `demo/run_review.py`：生成两条可复核 JSON 记录的可运行示例。

## 接口

```python
from sign_review import review_pdf_bytes, ReviewPolicy
from sign_review.verifiers import StructuralStubVerifier

policy = ReviewPolicy(
    allowed_field_fills=frozenset({"officer_name", "case_id"}),
    allowed_field_appearance=frozenset(),
    allow_page_changes=False,
    allow_shared_resource_changes=False,
    allow_inherited_attr_changes=False,
)
record = review_pdf_bytes(pdf_bytes, policy, StructuralStubVerifier(), source="form.pdf")
record.decision            # clear_to_proceed 或 manual_review
record.routing_reason      # 人工流转时的直接原因
record.deciding_findings   # 触发人工的具体发现项（可复核）
record.findings            # 全部逐项发现，含 from_revision/to_revision
```

实现带 `verify(data, signature) -> VerificationResult` 的类即可对接真实 PKI；
`ByteRangeDigestVerifier` 演示了只对签名覆盖字节取摘要的接缝。

## 两条可复核记录

运行 `python -m sign_review.demo.run_review` 后在 `demo/output/` 生成：

- `review_record_clear.json`：仅含许可字段填写，决定 `clear_to_proceed`，可继续流转。
- `review_record_manual.json`：含未授权外观、页面内容、共享资源、继承属性改动，
  决定 `manual_review`，`deciding_findings` 指出首项触发原因及每个受影响页面。

每条记录含修订字节偏移、签名修订索引、验证器名称与结论、逐项发现与策略依据，
可据此回到原始字节独立复核。

## 测试

`sign_review/tests/test_review.py` 覆盖修订扫描、ByteRange 映射、许可裁决、
验证器注入、共享资源多页影响、继承属性归属与截断待查，共 18 个用例。
