# elev_audit

只读的 Windows UAC 执行级别审计工具包，构建在仓库内的 `pefile` 只读入口之上，
用于核对内部制品清单中「允许通过系统自动提升权限」一栏与已批准例外是否一致。

## 设计约束

- **不取用扫描工作站本机的任何默认值**。当制品没有清单或没有 
  `requestedExecutionLevel` 声明时，记录为 `no_declaration` / 
  `evidence_missing`，绝不推断成 `asInvoker`。
- **证据自带出处与哈希**。每条清单证据都记录来源（PE 资源路径或调用者提供的
  独立清单）、语言 ID、SHA-256、解析错误与发现项。
- **语言分支单独记录**。同一 RT_MANIFEST 下多个语言 ID 视为相互独立的证物，
  出现多于一个分支时给出 `language_branch` 标记。
- **一份例外只覆盖它明示批准过的范围**：制品 ID、架构（Machine）、PE/清单哈希、
  语言分支以及调用者声明的部署条件；任何一项不匹配都会给出明确原因码，
  不会跨制品或跨架构放行。
- **接受调用者交来的独立清单和部署条件**，通过 
  `attach_external_manifest` / `DeploymentConditions` 接入，来源同样留痕。

## 模块

- `elev_audit/bytepe.py`：纯字节 PE 夹具构建器，生成只含 `.rsrc`/RT_MANIFEST 
  的真实 PE/COFF（i386、amd64、arm64，多语言），头部用 pefile 的 `Structure` 
  渲染，无需 Windows 工具链。
- `elev_audit/evidence.py`：用 `pefile.PE(data=..., fast_load=True)` 只读打开内存
  字节，仅解析资源目录，抽取执行级别、`uiAccess`、`autoElevate`。
- `elev_audit/policy.py`：`ApprovedException` 范围匹配与 `audit_artifact` 裁定
  （`approved` / `rejected` / `inconclusive`）。
- `examples/demo_approval_drift.py`：端到端演示，一条原本可放行的批准记录如何在
  架构重定向、清单重建（新增 autoElevate）、新增语言分支、部署条件变化后失效。

## 快速使用

```python
from elev_audit import (
    ApprovedException, DeploymentConditions, audit_artifact,
    build_pe_with_manifests, extract_embedded_evidence, make_manifest,
)

pe_bytes = build_pe_with_manifests({0x409: make_manifest("requireAdministrator")},
                                   machine="i386")
evidence = extract_embedded_evidence(pe_bytes, "tool.exe")
approval = ApprovedException(
    exception_id="EXC-1",
    artifact_ids=["tool.exe"],
    architectures=[evidence.machine],
    approved_levels=["requireAdministrator"],
)
report = audit_artifact(evidence, [approval],
                        DeploymentConditions({"channel": "internal"}))
print(report["verdict"])
```

## 测试

```bash
.venv/bin/python -m pytest tests/test_elev_evidence.py tests/test_elev_policy.py \
    --confcutdir=tests -p no:cacheprovider
# 受限沙箱下父目录不可 stat，--confcutdir 把收集范围限定在 tests 内
.venv/bin/python examples/demo_approval_drift.py
```
