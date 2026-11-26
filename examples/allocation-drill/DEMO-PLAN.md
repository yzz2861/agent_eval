# 离线整改分工预演 / Offline remediation allocation drill

- 状态 / Status: `conflicts`
- 审计结果 / Audit result: `examples/allocation-drill/audit-result.json`
- 方案表 / Plan table: `examples/allocation-drill/allocation-plan.toml`
- 覆盖 / Covered: 4/6 alert environments; 1 combination(s) assigned
- 冲突 / Conflicts: 1 error(s), 0 warning(s)

## 受影响环境 / Affected environments

| Environment | Lockfile | Vulnerable packages from audit |
| --- | --- | --- |
| `web` | `examples/allocation-drill/pylock.web.toml` | cryptography 44.0.2 (ADV-2026-5103); django 4.2.26 (ADV-2026-5101); django 4.2.26 (ADV-2026-5102) |
| `worker` | `examples/allocation-drill/pylock.worker.toml` | cryptography 44.0.2 (ADV-2026-5103); django 4.2.26 (ADV-2026-5101); django 4.2.26 (ADV-2026-5102) |

## 每组承接的组合 / Group assignments

| Group | Owner | Accepted combinations | Slots used | Remaining |
| --- | --- | --- | ---: | ---: |
| `django-4.2-line` | Lin | - | 0/2 | 2 |
| `crypto-line` | Chen | - | 0/1 | 1 |
| `cross-env-release` | Riley (only cross-environment release manager) | `django-4.2.27-shared-batch` | 1/1 | 0 |

### 组合内容 / Combination scope

#### `django-4.2.27-shared-batch` → `cross-env-release`

- Apply the complete Django 4.2.27 batch to both image consumers
- Findings covered together: `ADV-2026-5101`, `ADV-2026-5102`
- Environments: `web`, `worker`
- Atomic changes: `django` -> `4.2.27` (line `4.2`)
- Slot cost: 1; cross-environment: `True`

## 候选组合可行性 / Candidate feasibility

| Combination | Cross-env | Eligible groups | Static blockers |
| --- | --- | --- | --- |
| `django-4.2.27-shared-batch` | `True` | `cross-env-release` | `django-4.2-line`: cross_environment_not_supported; `crypto-line`: cross_environment_not_supported,version_line_scope_mismatch |
| `cryptography-44.0.3-shared-batch` | `True` | `cross-env-release` | `django-4.2-line`: cross_environment_not_supported,version_line_scope_mismatch; `crypto-line`: cross_environment_not_supported |

## 共用镜像一致性 / Shared image consistency

- **`base-python-runtime`** environments: `web`, `worker`
  - image tag/version: image version `py3.12-2026.11.27-security-train`
  - `cryptography`: no selected target decision
  - `django`: `4.2.27` from `django-4.2.27-shared-batch` on `web`, `worker`

## 无法分配的冲突条件 / Unassignable conflicts

- **`capacity_exhausted`** [`cryptography-44.0.3-shared-batch`]: combination 'cryptography-44.0.3-shared-batch' needs 1 slot(s), but eligible groups have no remaining capacity after the selected plan

## 逐告警抢名额预演 / Why alert-by-alert grabbing fails

Naive alert grabbing claims 1 alert(s) and hits 2 capacity/scope failure(s). It does not understand that several alerts can be one atomic combination costing one slot.

| Alert | Environments | Grabbed group | Result | Reason |
| --- | --- | --- | --- | --- |
| `ADV-2026-5101@django` | `web`, `worker` | `cross-env-release` | `claimed` |  |
| `ADV-2026-5102@django` | `web`, `worker` | - | `failed` | no eligible available slot |
| `ADV-2026-5103@cryptography` | `web`, `worker` | - | `failed` | no eligible available slot |

## 排班范围 / Group responsibility scope

- `django-4.2-line` (Lin): capacity `2`, cross-environment `False`, scope: `django`@`4.2`
- `crypto-line` (Chen): capacity `1`, cross-environment `False`, scope: `cryptography`@`44.0`
- `cross-env-release` (Riley (only cross-environment release manager)): capacity `1`, cross-environment `True`, scope: `*`

