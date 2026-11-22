# 回归报告二 · 门禁裁决

- 总体门禁结论：**阻断（BLOCK）**（冻结批次 `adjudication-freeze-2026-11`）
- 升级后原始命中 15 条，升级前 12 条；总数对比不参与门禁，只作背景

## 重点群组门槛
- `command_injection`：阻断；下限召回率 100%，实测 75%（升级前 75%）
    - 阻断证据：recall 75.0% < floor 1.00
    - 阻断证据：confirmed HIGH finding lost: B602 @ src/company/s01_os_system.py
- `temp_file`：阻断；下限召回率 80%，实测 0%（升级前 0%）
    - 阻断证据：recall 0.0% < floor 0.80
- `tls_validation`：通过；下限召回率 80%，实测 100%（升级前 100%）
- `unsafe_deserialization`：通过；下限召回率 100%，实测 100%（升级前 100%）
- `weak_crypto`：通过；下限召回率 80%，实测 100%（升级前 100%）

## 关键缺失明细（升级后仍为扫描缺失的高严重项）
- `B602` @ `src/company/s01_os_system.py`（家族 command_injection，严重度 HIGH，人工裁决 confirmed）
