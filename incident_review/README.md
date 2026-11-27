# incident_review — 旧证书缺席结论的复审工具

事故材料中两次备份的采集记录均为"未找到旧证书"，但记录同时显示当时只采集了
规定别名的一部分。本目录用 pyjks 读取各次备份的**公开证书视图**（可信证书条目
+ 私钥条目的证书链，不解密任何私钥），与每次采集声明的范围做时序核对，
对指定证书给出三类证据：

- **确有观察**（observed）：公开证书视图中直接看到目标证书；
- **能证明在声明范围内缺席**（absent_in_scope）：声明范围被完整核对且目标不在其中；
- **无法排除**（inconclusive）：声明范围存在缺口，"未找到"不构成缺席证据。

目标证书的身份只看公开证书本身（DER 编码的 SHA-256 指纹），与别名无关——
别名在两次备份之间被改过也能靠指纹接上。

## 两份夹具

- `fixtures/case_scope_gap/`：两次采集都只覆盖规定别名的一部分，留有一段范围
  缺口。历史"未找到"结论证据强度为**弱**（无法排除）；复审实际在两份备份中都
  直接观察到了目标证书（别名 `legacy-root` → `retired-root-2023`）。
- `fixtures/case_full_inventory/`：每次采集都是覆盖全部规定别名的完整盘点单。
  T0 确有观察，T1/T2 能证明在声明范围内缺席，历史结论证据强度为**强**。

## 用法

```sh
# 重新生成夹具（只需 openssl；JKS 由 pyjks 自己写出）
.venv/bin/python incident_review/make_fixtures.py

# 复审全部夹具并在 reports/ 下生成报告
.venv/bin/python incident_review/audit.py

# 测试
.venv/bin/python -m unittest discover -s incident_review -t incident_review
```

## 文件说明

- `make_fixtures.py`：生成两份夹具（openssl 造证书，pyjks 写 JKS 与清单）。
- `audit.py`：复审逻辑与报告渲染；`public_cert_view()` 只读公开材料。
- `fixtures/*/manifest.json`：规定别名清单、目标证书指纹、备份时间线、
  每次采集的声明范围与采集记录。
- `reports/*.md`：复审产出的中文报告。
- `test_audit.py`：验证三类证据、别名接续与两案不同的证据强度。
