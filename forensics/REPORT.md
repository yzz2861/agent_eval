# 取证复核报告：pcapng 归档输入覆盖分析

## 对象与材料

- 归档：`forensics/evidence/capture.pcapng`（两个 section，纯离线解读，不做任何在线采集）
- 独立采集配置：`forensics/evidence/capture_config.json`（操作侧记录，声明性文本）
- 取证清单：`forensics/evidence/manifest.json`，声明 "Session A 的两个接口 (eth0, eth1) 均完整留存了 TCP/23 (telnet) 类流量"
- 复现：`PYTHONPATH=$PWD .venv/bin/python forensics/make_fixture.py && PYTHONPATH=$PWD .venv/bin/python forensics/analyze_archive.py`

## 三层证据严格分层

| 层 | 来源 | 效力 |
| --- | --- | --- |
| 配置声明 | `capture_config.json` 的 `capture_filter` | 操作者事后/事前记录，声明文本 |
| 归档内声明 | IDB 的 `if_filter` 选项（type=0，BPF 文本） | 采集时写入归档的声明文本；离线无法验证其是否被正确编译执行 |
| 实际出现的包 | EPB 块逐个解析 | 归档中真实存在的包，是覆盖结论的唯一直接证据 |

辅助旁证：ISB 计数（`isb_ifrecv` / `isb_filteraccept` / `isb_usrdeliv`），可把"声明"与"实际包集合"互相印证。

## 提取结果（按 section × interface_id）

### Section 0（session A，10:00–10:05 UTC）

- `interface_id=0` eth0：配置与 IDB 均无过滤器。实际出现 4 包：到 192.0.2.5 与 192.0.2.7 的 TCP/23、UDP/53、TCP/80。ISB：`ifrecv=4, usrdeliv=4`。
- `interface_id=1` eth1：配置声明与 IDB `if_filter` 均为 `tcp port 23 and host 192.0.2.5`。实际仅出现 2 包，全部是到/自 192.0.2.5 的 TCP/23。ISB：`ifrecv=9, filteraccept=2, usrdeliv=2`。

### Section 1（session B，11:00–11:05 UTC）

- `interface_id=0` eth0：配置声明与 IDB `if_filter` 均为 `tcp port 23`。实际出现 1 包：到 192.0.2.9 的 TCP/23。ISB：`ifrecv=5, filteraccept=1, usrdeliv=1`。

## 复核结论

1. **清单声明被归档自身证伪。** eth1 的 IDB 携带 `if_filter`，与"完整留存"直接矛盾；ISB 显示 9 个到达包仅 2 个被过滤器接受。eth1 只留存了 TCP/23 中"host 192.0.2.5"的子集。eth0 一侧无过滤且计数闭合，其 TCP/23 留存可视为完整。
2. **相同 interface ID 在另一 section 的含义不同。** pcapng 的接口编号按 section 从 0 重新分配，由本 section 的 IDB 定义。Section 1 的 `interface_id=0` 虽也叫 eth0，却是另一个接口实例，且自带 `tcp port 23` 过滤声明。跨 section 汇总必须以 `(section, interface_id)` 二元组为键，否则会把"无过滤的完整留存"与"有过滤的子集留存"错误合并。
3. **两种"缺席"依据不同，复核时必须分开表述：**
   - **"这批没有出现"**（以 eth0 为例）：该接口无任何过滤声明，且 `isb_ifrecv == isb_usrdeliv`，采集窗口内到达的包应当全部留存。此时归档中缺少某类包，可作为"窗口内未观测到"的证据（仍受窗口时长、链路易达性限制）。
   - **"这一类从未被纳入采集"**（以 eth1 为例）：依据是三重印证——IDB `if_filter` 声明文本、独立配置的 `capture_filter`、ISB 计数差（`ifrecv=9` vs `filteraccept=2`）。被过滤掉的类**根本不可能出现在归档里**，其缺席对"线上是否存在该流量"不作任何证明。
4. **声明文本的效力边界。** `if_filter` 与独立配置都只是声明：离线归档无法验证过滤器是否被正确编译或执行。只有当声明、ISB 计数差、实际包集合三者一致时，才能把缺席归因为采集过滤而非线上静默；若声明有过滤但计数闭合且包集合完整，则应以实际包为准。

## 复核操作要点

- 引用缺席结论时，必须注明它属于哪一类，并附上对应依据（无过滤+计数闭合 / 过滤声明+计数差）。
- 过滤表达式一律按声明文本引用，不断言其语义已被执行。
- 跨 section 的同名/同号接口不得合并覆盖结论。
