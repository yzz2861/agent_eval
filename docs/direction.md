# Offline direction attribution

`dpkt.direction` audits captured frames against a **trusted mirror-port table**
and an accepted **capture scope**.  It is an offline helper: it reads pcap or
pcapng files and never opens a socket or sends a packet.

The important rule is that a MAC address is *link evidence*, not a direction.
The direction comes from the mirror ledger record for the capture point and its
VLAN.  This matters when the same MAC is seen at two different capture points,
because a MAC-only rule gives both frames the same label.

## Inputs

The mirror-port table can be JSON or CSV.  JSON may be a list of records or an
object with a `mirror_ports`/`ports`/`entries` key:

```json
{
  "mirror_ports": [
    {"capture_point": "SPAN-A", "mirror_port": "Gi0/1", "device": "leaf-01",
     "vlan": 100, "direction": "ingress", "trusted": true},
    {"capture_point": "SPAN-B", "mirror_port": "Gi0/2", "device": "leaf-02",
     "vlan": 200, "direction": "egress", "trusted": true}
  ]
}
```

`direction` accepts `ingress`/`inbound`/`rx`/`in`, `egress`/`outbound`/`tx`/`out`,
`both`/`bidirectional`, and the Chinese labels `入站`, `出站`, `双向`.  A record
may also use `outer_vlan`/`svlan` and `inner_vlan`/`cvlan`; `vlan_role` selects
whether the ledger VLAN refers to the outer or inner tag.

The capture scope is JSON:

```json
{
  "capture_points": ["SPAN-A", "SPAN-B"],
  "vlans": [100, 200],
  "start": "2026-11-23T00:00:00Z",
  "end": "2026-11-24T00:00:00Z"
}
```

Optional scope keys are `addresses` (MAC/IP values that must appear in the
frame), `mirror_ports`, and `require_vlan_tag`.

Claims may be a JSON list, a JSON object mapping frame index to direction, or
CSV with `frame,direction,capture_point,vlan,basis` columns:

```json
[
  {"frame": 0, "direction": "outbound", "capture_point": "SPAN-A",
   "vlan": 100, "basis": "src_mac=02:00:00:00:00:01"},
  {"frame": 1, "direction": "outbound", "capture_point": "SPAN-B",
   "vlan": 200, "basis": "src_mac=02:00:00:00:00:01"},
  {"frame": 2, "direction": "outbound", "capture_point": "SPAN-A",
   "basis": "src_mac=02:00:00:00:00:01"}
]
```

## Command line

```console
$ python -m dpkt.direction audit \
    --mirror mirror-ports.json \
    --scope capture-scope.json \
    --claims direction-claims.json \
    --capture SPAN-A=span-a.pcapng \
    --capture SPAN-B=span-b.pcapng
```

Add `--json` for the full machine-readable audit, `--output report.json` to
write that report to disk, and `--fail-on-conflict` to exit with status 2 when
at least one claim directly contradicts the ledger.
`python -m dpkt.direction demo` runs the built-in three-frame demonstration.

## Evidence retained per frame

Each frame keeps the link type, source/destination MAC, EtherType, the complete
outer VLAN tag stack (802.1Q/802.1ad/legacy QinQ), captured and on-wire length,
truncation state, SHA-256 of the captured bytes, the dpkt protocol stack, and
IPv4/IPv6/transport fields when they can be parsed.  `vlan_tags[0]` is the
outer tag; `vlan_tags[1]` is the first inner tag.  Up to 32 tags are scanned so
the outer tag is not lost when a frame carries more tags than dpkt normally
decapsulates.

## Direction outcomes

* `verified` - exactly one direction is supported by the trusted ledger.
* `ambiguous` - the ledger permits several directions (for example a
  bidirectional SPAN port, or an untagged frame at a port with several VLAN
  records).  The candidate set is retained.
* `vlan_conflict` - the frame has an outer tag that disagrees with every
  trusted record for that capture point.
* `unattributed` - no trusted record covers the capture point.
* `unverifiable` - the L2 header is truncated or the link type is unsupported;
  no direction is invented.
* `out_of_scope` - the capture scope rejects the frame.

A claim is a **direct conflict** only when the ledger gives a definite, single
direction and the claim differs (or when the claim asserts the wrong capture
point/VLAN).  A claim about a frame with a truncated L2 header is reported as
`unverifiable`, not as a conflict.  A claim that happens to match the ledger but
is based only on a MAC address is reported as `match_weak_basis`; the match is
supported by the ledger, not by the MAC address.

## Demonstration fixture

`build_demo()` writes a pcapng with two interfaces named by pcapng `if_name`
options and three frames:

1. SPAN-A, VLAN 100, same source MAC, normal L2 header.  The ledger says this
   point is ingress-only, so an `outbound` claim conflicts.
2. SPAN-B, VLAN 200, the same source MAC, normal L2 header.  The ledger says
   this point is egress-only, so the same `outbound` claim matches.
3. SPAN-A, only the first 10 bytes of the Ethernet header.  The EtherType and
   VLAN cannot be read, so any direction claim is unverifiable.

The conclusion therefore names frame 0 as the claim that directly conflicts
with the ledger, while frame 2 is excluded from conflict counting.
