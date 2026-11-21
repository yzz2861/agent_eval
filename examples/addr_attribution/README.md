# Address attribution across isolated broadcast domains

After a datacenter migration, one case file can contain the same address
briefly used by different devices in two isolated broadcast domains.  The
tool in this directory reads offline pcaps with dpkt, joins the device
inventory and maintenance windows supplied by the evidence custodian, and
constrains address ownership using only visible layer-2 relationships.

## Evidence rules

- **Mirror caveat**: a mirror sees less than the original interface, so
  absence of traffic proves nothing, and seeing only *requests* for an
  address (ARP who-has target, IP destination) is never treated as an
  ownership confirmation.
- **Confirmation** comes from the address speaking for itself: ARP is-at
  replies and IP packets sourced from the address, tied to the sender MAC.
- **Both sides valid**: if an address is confirmed in both domains, the
  report keeps both (`status: both_domains`).
- **One-sided conflict**: if one domain confirms the address for more than
  one MAC, that side is reported as a conflict and located by packet
  sequence numbers (1-based frame numbers in that domain's pcap).
- Observations inside a custodian maintenance window are flagged with
  `in_maintenance` so expected migration overlap is visible.

## Usage

```
python make_sample_case.py sample_case
python addr_attribution.py \
    --pcap domain-a=sample_case/domain-a.pcap \
    --pcap domain-b=sample_case/domain-b.pcap \
    --devices sample_case/devices.csv \
    --maintenance sample_case/maintenance.csv
```

Custodian CSV formats:

- `devices.csv`: `device_id,mac,ip` (`ip` may be blank)
- `maintenance.csv`: `device_id,start,end` (epoch seconds or ISO 8601)

Run the tests with:

```
python -m pytest test_addr_attribution.py
```
