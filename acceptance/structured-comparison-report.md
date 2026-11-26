# 结构化注册表对照验收报告

## 结论

选定的已知类型是 **Windows 防火墙 `v2` 规则值**：一个 `REG_SZ` 中同时包含 `Name`、`Desc` 等展示字段，以及 `Action`、`Active`、端口/地址和 `LUAuth` SDDL 等安全字段。
原始字节比较会把三者都报成“注册表值变化”；结构化对照能解释前两个只改展示属性，第三个才是真正的安全设置变化。

| 验收快照 | 原始字节不同 | 结构化判定 | 权限变化 | 说明 |
|---|---:|---|---:|---|
| `firewall-display-name-only` | 是 | `display_only` | 否 | 仅展示字段变化；原始字节虽不同，不构成权限变化 |
| `firewall-display-description-only` | 是 | `display_only` | 否 | 仅展示字段变化；原始字节虽不同，不构成权限变化 |
| `firewall-security-action-block` | 是 | `security_change` | 是 | 安全相关字段或安全描述符发生真实变化 |

## 三个快照的差别

### firewall-display-name-only：display_only

Display Name resource identifier changed

- 夹具：`acceptance/snapshots/firewall-rule-display-name.json`
- 原始字节是否不同：是
- 是否判定为权限/安全变化：**否**
- 解释：仅展示字段变化；原始字节虽不同，不构成权限变化

| 字段 | 分类 | 基线值 | 对照值 | 值的相对偏移 | 绝对原始偏移 |
|---|---|---|---|---:|---:|
| `Name` | display | `@wifidisplay.dll,-10200` | `@wifidisplay.dll,-10299` | 248 | `5993692` |

原始字节块（绝对偏移 = python-registry 原始数据起点 `5993444` + 相对偏移）：

| 相对偏移 | 绝对偏移 | 长度 | 映射字段 | 字节变化 |
|---:|---:|---:|---|---|
| 290 | 5993734 | 1 | Name | `30 -> 39` |
| 292 | 5993736 | 1 | Name | `30 -> 39` |

### firewall-display-description-only：display_only

Display Description resource identifier changed

- 夹具：`acceptance/snapshots/firewall-rule-display-description.json`
- 原始字节是否不同：是
- 是否判定为权限/安全变化：**否**
- 解释：仅展示字段变化；原始字节虽不同，不构成权限变化

| 字段 | 分类 | 基线值 | 对照值 | 值的相对偏移 | 绝对原始偏移 |
|---|---|---|---|---:|---:|
| `Desc` | display | `@wifidisplay.dll,-10201` | `@wifidisplay.dll,-10298` | 306 | `5993750` |

原始字节块（绝对偏移 = python-registry 原始数据起点 `5993444` + 相对偏移）：

| 相对偏移 | 绝对偏移 | 长度 | 映射字段 | 字节变化 |
|---:|---:|---:|---|---|
| 348 | 5993792 | 1 | Desc | `30 -> 39` |
| 350 | 5993794 | 1 | Desc | `31 -> 38` |

### firewall-security-action-block：security_change

Firewall action changed from Allow to Block

- 夹具：`acceptance/snapshots/firewall-rule-security-action.json`
- 原始字节是否不同：是
- 是否判定为权限/安全变化：**是**
- 解释：安全相关字段或安全描述符发生真实变化

| 字段 | 分类 | 基线值 | 对照值 | 值的相对偏移 | 绝对原始偏移 |
|---|---|---|---|---:|---:|
| `Action` | security | `Allow` | `Block` | 26 | `5993470` |

原始字节块（绝对偏移 = python-registry 原始数据起点 `5993444` + 相对偏移）：

| 相对偏移 | 绝对偏移 | 长度 | 映射字段 | 字节变化 |
|---:|---:|---:|---|---|
| 26 | 5993470 | 1 | Action | `41 -> 42` |
| 30 | 5993474 | 1 | Action | `6c -> 6f` |
| 32 | 5993476 | 1 | Action | `6f -> 63` |
| 34 | 5993478 | 1 | Action | `77 -> 6b` |

## 批准核对字段与偏移追踪

该快照命中的批准核对字段如下；只有其中安全相关字段的语义变化会被判定为权限变化：

`action`, `application_path`, `direction`, `display_context`, `display_description`, `display_name`, `enabled_state`, `local_user_authorization`, `profile`, `protocol`, `schema_version`

未批准/版本专有字段：`tag_keyword`。这些字段保留原值、别名状态和偏移；若发生变化，结论是 `needs_review`，不会被原始字节差异直接升级为权限变化。

每个字段都在 `raw_byte_offsets` / `byte_offsets` 中记录相对原始值起点的偏移和长度；若快照来自 python-registry，还会给出 hive 文件内绝对偏移。

## 未知版本

未知版本不会被直接升级成权限变化，也不会丢失。解析器仍逐字段记录偏移，并把版本放入 `unknown_versions`：

```json
{
  "component": "firewall_rule_schema",
  "version": "2.99",
  "token": "v2.99",
  "byte_offset": 0,
  "absolute_byte_offset": 0,
  "byte_length": 10
}
```

## 别名与引用来源

多个别名解析到同一个规范描述；每个别名都单独保留来源。例如 `LPort` -> `local_port`（Local port or port alias）。

| 别名 | 接口 | 来源 |
|---|---|---|
| `LPort` | registry token | `EMPIRICAL-SYSTEM-HIVE` |
| `localport` | netsh parameter | `MS-NETSH` |
| `LocalPort` | PowerShell parameter | `MS-NETFIREWALLRULE` |

## 服务键安全描述符对照组

另一类常见形态是服务键：`DisplayName`、`Description` 是普通展示字段，`Security\Security` 是二进制自相对安全描述符。
该对照组证明同一套结构判定也适用于真实 DACL 位变化。

| 对照快照 | 原始值不同 | 判定 | 权限变化 | 差别 |
|---|---:|---|---:|---|
| `service-rasman-display-name-only` | 是 | `display_only` | 否 | 仅展示字符串变化 |
| `service-rasman-display-description-only` | 是 | `display_only` | 否 | 仅展示字符串变化 |
| `service-rasman-security-dacl-bit` | 是 | `security_change` | 是 | DACL/SD 语义变化：dacl |

## 复现命令

```sh
.venv/bin/python samples/structured_acceptance.py
.venv/bin/python samples/structured_report.py
.venv/bin/python -m pytest tests/test_structured_comparison.py -q
```
