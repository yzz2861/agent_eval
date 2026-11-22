# 部署阶段复核样本（离线）

这套小样本演示如何借 `pip-audit` 的 PEP 751 锁文件读取能力与离线审计结果，按部署阶段（构建机 / 运行镜像）复核漏洞，而不是按包名粗暴合并。

## 输入

- `build-host.pylock.toml`：构建机阶段锁，依赖组 `build`，含环境标记与可见 wheel 制品。
- `runtime-image.pylock.toml`：运行镜像阶段锁，依赖组 `runtime`，同样保留标记、制品与一个无版本的源码树包。
- `offline-advisories.json`：冻结的离线通告快照（schema `pip-audit-offline-review/v1`），替代在线 OSV/PyPI 查询。
- `exemptions.toml`：调用方给的整改/豁免清单，每条都绑定明确角色；`registered_roles` 声明已登记角色。

## 关键规则

1. 豁免只在「包名+版本+通告+角色」全部匹配时生效。
2. 构建机角色的豁免不会抵销运行镜像里同一归档的告警。
3. 标记不匹配当前环境的包记为 `not-selected`，保留通告依据但不产生运行时告警。
4. 豁免指向未登记角色时，该条被独立保留（`role-not-registered`），运行时仍需处置并计入告警。
5. 无版本包沿用 pip-audit 的 skipped 语义，保留 `skip_reason`。

## 覆盖的对照场景

| 包 | 构建机 | 运行镜像 | 说明 |
| --- | --- | --- | --- |
| `requests 2.32.2` | exempt | open（运行时告警） | 同名同版本同 sha256 归档，构建豁免不抵销运行时 |
| `wheel` / `setuptools` | exempt | 不存在 | 仅构建工具，角色匹配，正确豁免 |
| `urllib3 2.2.1` | 不存在 | exempt | 运行时角色的正确豁免（含别名匹配） |
| `pywin32` / `colorama` | not-selected | not-selected | win32 标记在 linux 环境下不选中 |
| `jinja2 3.1.4` | 不存在 | role-not-registered（运行时告警） | 豁免指向未登记角色 `legacy-ci`，独立保留 |
| `certifi` | 不存在 | 无通告、不告警 | 干净版本 |
| `internal-utils` | 不存在 | skipped | 无版本源码树 |

## 运行

```
python examples/deployment_review/run_review.py samples <输出 report.json 路径>
```

输出报告 schema 为 `deployment-stage-review/v1`，每个角色独立成段；`runtime_warnings` 只收录未被抵销的运行时告警，且每条都带通告依据与未生效豁免的原因。
