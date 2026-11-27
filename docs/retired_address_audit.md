# 退役地址只读核对

`tools/retired_address_audit.py` 是一个基于 `dpkt` 的只读核对工具，用于回答一个很具体的问题：工单说旧设备已经下线，保全文件却还留着旧地址，这些地址现在到底属于谁？

工具不做资产变更，也不写回任何输入。它把下面三类带时间的记录叠在一起：

- `DHCPACK`：用 `dpkt.dhcp` 解析，取 `yiaddr`、`chaddr`、option 51 租期、option 54 服务器。pcap 时间戳作为租约起点。
- ARP：用 `dpkt.arp` 解析。ARP request 的 sender `(spa, sha)` 是绑定；它的 target 不是绑定。ARP reply 的 sender 和 target 都是绑定。
- 设备交接单、迁移工单、保全文件：按地址、站点和时间对齐。

输出分三类，另保留一个证据不足的兜底类：

| 结论 | 含义 |
| --- | --- |
| `old_device` / 仍属旧设备 | 交接后仍出现旧 MAC 的 DHCPACK/ARP，或旧租约跨过交接时点且仍有效 |
| `new_device` / 可归到新设备 | 交接单把地址转给新设备，且没有更晚的旧设备身份；新 DHCPACK/ARP 会加强结论 |
| `in_use_only` / 只能确认地址在用 | 有 DHCPACK/ARP 证明地址在用，但 MAC 不属于旧设备，也不属于交接单中的新设备 |
| `unverified` / 证据不足 | 连地址在用的运行时证据都没有 |

每个地址的结论都带 `supporting_records`、`absent_records`、`context_records` 和 `conflicting_records`。每条缺席记录还带 `observation.status`：

- `covered`：采集覆盖该时段，确实没有观察到这条记录；此时“缺席”可以作为反向证据。
- `lost` / `degraded` / `ended` / `unknown`：采集没有可靠覆盖；缺席会被降级为 `weakens_conclusion`，不能用来证明地址没被旧设备继续使用。
- 文档类缺席（例如没有交接单）标记为 `documentation_gap`，既不计作运行时反向证据，也不假装采集缺口。

## 快速运行

```bash
PYTHONPATH=. python -m tools.retired_address_audit \
  --ticket tests/fixtures/retired_addresses/ticket.json \
  --preservation tests/fixtures/retired_addresses/preservation.json \
  --handover tests/fixtures/retired_addresses/handovers.jsonl \
  --dhcp-pcap tests/fixtures/retired_addresses/dhcp-east.pcap \
  --arp-pcap tests/fixtures/retired_addresses/arp-east.pcap \
  --coverage tests/fixtures/retired_addresses/coverage.json
```

默认输出 JSON。需要 Markdown 报告时加 `--format markdown`，或把 `--output` 指向 `.md` 文件（格式会按后缀推断）。

```bash
PYTHONPATH=. python -m tools.retired_address_audit ... --format markdown --output report.md
```

如果希望旧设备仍持有地址时返回非零状态，加 `--fail-on-old`，此时退出码为 `2`。输出路径与任一输入路径相同会被拒绝。

## 输入格式

所有表格输入都接受 JSON、JSONL/NDJSON 或 CSV。JSON 顶层可以是数组，也可以是包含约定数组字段的对象。

### 迁移工单

```json
{
  "ticket_id": "CHG-20261128-017",
  "title": "Retire two edge appliances",
  "devices": [
    {
      "device_id": "edge-old-a",
      "name": "OLD-A",
      "site": "east",
      "mac": "00:1a:2b:3c:4d:01",
      "decommissioned_at": "2026-11-01T00:00:00Z",
      "role": "old"
    }
  ],
  "new_devices": [
    {
      "device_id": "edge-new-a",
      "name": "NEW-A",
      "site": "east",
      "mac": "00:1a:2b:3c:4d:11",
      "role": "new"
    }
  ]
}
```

CSV 列名可以是 `device_id,id,name,site,mac,decommissioned_at,role`。没有 `role` 时，带下线时间的记录按旧设备处理，否则按新设备处理。

### 保全文件

```json
{
  "file_id": "PRESERVE-2026-11-25",
  "recorded_at": "2026-11-25T00:00:00Z",
  "addresses": [
    {
      "record_id": "PRES-001",
      "address": "10.20.0.10",
      "site": "east",
      "legacy_device": "edge-old-a",
      "legacy_mac": "00:1a:2b:3c:4d:01"
    }
  ]
}
```

约定数组字段是 `addresses`、`claims` 或 `records`。每条记录必须有 `address`；`legacy_device` 可以用设备 ID 或设备名，`legacy_mac` 可作为工单缺失时的补充身份。

### 设备交接单

JSONL 每行一条：

```json
{"record_id":"HO-001","at":"2026-11-03T00:00:00Z","site":"east","address":"10.20.0.10","from_device":"edge-old-a","to_device":"edge-new-a","from_mac":"00:1a:2b:3c:4d:01","to_mac":"00:1a:2b:3c:4d:11","ticket_id":"CHG-20261128-017"}
```

必须提供 `address`、`at`，以及 `to_device` 或 `to_mac` 之一。`to_mac` 缺失时会尝试从工单的新设备清单按 `to_device` 补全。

### 采集覆盖说明

```json
{
  "capture": [
    {"source":"dhcp","site":"west","start":"2026-11-03T00:00:00Z","end":"2026-11-28T00:00:00Z","status":"lost","reason":"west collector outage"}
  ]
}
```

`source` 支持 `dhcp` 和 `arp`；`status` 支持 `covered`、`lost`、`degraded`。没有覆盖说明时，工具只能根据已给 pcap 中是否出现记录来判断，并在输出中标注 `unknown`。

## 时间规则

对每个保全地址：

1. 取该地址交接单时间与旧设备工单下线时间的较晚者作为切点时点。
2. 旧设备 DHCPACK 起始于切点之后，属于旧身份证据。
3. 旧设备 DHCPACK 起始于切点之前，但租期结束晚于切点且核对时点仍未到期，属于“跨切点旧租约”。
4. 新设备 DHCPACK/ARP 起始更晚时覆盖更早的旧身份；如果旧租约的结束时间仍晚于新确认，会额外产生 `lease_overlap` 冲突记录，提示核查旧租约是否被提前终止。
5. 更晚的未知 MAC 会覆盖交接单归属，降为 `in_use_only`。
6. 工单下线时间到交接时间之间仍观察到旧设备身份时，会作为过程异常写入 `caveats`。
7. 工单下线之后仍出现旧设备 DHCPACK/ARP 时，除结论外还会产生 `decommission_contradiction` 冲突，指明工单与运行时记录互相矛盾。

## 输出要点

- `inputs`：每个输入的 SHA-256、字节数、角色，用来证明核对前后输入未变。
- `captures`：解析出的 DHCPACK/ARP 记录数量。
- `coverage_windows` / `control_plane_gaps`：控制面采集窗口和已知缺口。
- `addresses[]`：每个地址的结论、置信度、支持记录、缺席记录、上下文、冲突、时间线。
- `summary.old_device_addresses`：仍然绑定旧设备的地址列表，可直接用于 `--fail-on-old`。

## 固化场景

`tests/fixtures/retired_addresses/` 是一个可重建的小场景：

- `10.20.0.10`：保全属旧设备，交接后旧设备还有一条跨切点租约；随后新设备拿到同一地址的 DHCPACK 和 ARP。结论为 `new_device`，同时保留 `lease_overlap` 冲突。
- `10.20.0.11`：交接后旧设备继续拿到 DHCPACK 和 ARP，没有交接单。结论为 `old_device`。
- `10.20.0.12`：只有未知 MAC 的 ARP，结论为 `in_use_only`。
- `10.30.0.20`：西站控制面采集中断，只剩交接单。结论为 `new_device` 但置信度低；DHCP/ARP 的缺席全部标记为 `lost`，只削弱结论，不作为反向证据。

`expected_verdicts.json` 固化了这四条结论、支持记录、缺席记录及其采集状态。`build_pcaps.py` 可重建两个很小的 pcap：

```bash
PYTHONPATH=. python tests/fixtures/retired_addresses/build_pcaps.py
```

## 测试

```bash
PYTHONPATH=. pytest -q -o addopts='' --rootdir=tests --confcutdir=tests tests/test_retired_address_audit.py
```

测试覆盖：pcap 解析、ARP request 不作为 target 绑定、跨切点旧租约、未知 MAC 降级、冻结结论、输入只读、输出防覆盖、CLI 退出码。

## 边界

- 只解析 `DHCPACK`，不把 DHCP OFFER/REQUEST 当作确认；不解析 DHCP RELEASE/DECLINE。
- ARP 没有 TTL/缓存寿命建模，ARP 记录视为该时点的观测，不自动推断当前仍然有效。
- 站点来自工单/保全/交接单；pcap 本身不带站点标签。地址与站点冲突会进入 `warnings`。
- 同一地址有多条交接单时，以最新一条作为当前归属，较早的交接单保留为历史上下文；同时会记录 `multiple_handovers` 警告。
