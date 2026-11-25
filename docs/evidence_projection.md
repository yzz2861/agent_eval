# Offline evidence projection

`dpkt.evidence` is a read-only projector for a narrow disclosure case: a
small number of captured records leave the internal network, but only an
explicit allow-list of Ethernet/VLAN/IPv4 header fields may be shown.  The
module never rewrites a capture and never opens a socket.

## Command line

```sh
python -m dpkt.evidence project capture.pcap.gz \
    --records 0,2-4 \
    --fields eth.dst,eth.src,vlan.id,ip.hl,ip.ttl,ip.p,ip.src,ip.dst \
    --output projection.json

python -m dpkt.evidence verify projection.json --source capture.pcap.gz
```

`verify` exits non-zero when the projection no longer matches its
commitments or when a fresh projection of the source differs.

## Schema

A projection contains:

- `source`: the pcap digest, link type, snap length, and record count, but
  not packet bytes or an internal filesystem path.
- `policy`: the exact field allow-list and selected record indexes.
- `redaction`: the projection-scoped HMAC salt and the address field list.
- `records`: selected records with `record_header_offset`, `packet_offset`,
  captured/original lengths, truncation state, and decoded encapsulation.
- `commitment`: a manifest SHA-256 over the complete projection body.

Every selected field has one of two states:

- `located`: `source` gives the field byte range in the saved capture.
  `offset` is zero-based from the captured frame; `file_offset` is absolute
  in the uncompressed pcap byte stream.  `bit_offset`/`bit_length` describe
  bit fields such as `vlan.id`, `ip.hl`, and `ip.offset`.  `commitment`
  binds the disclosed representation and source range.
- `unlocated`: `source` and `representation` are `null`.  No position is
  guessed for an unknown encapsulation; truncation simply leaves the
  missing suffix unlocated while already captured header fields remain
  visible.

## Representations

Address fields (`eth.src`, `eth.dst`, `ip.src`, `ip.dst`) always use:

```json
{"kind": "redacted", "algorithm": "hmac-sha256", "family": "ipv4",
 "value": "hmac-sha256:..."}
```

Other allow-listed fields use one of:

```json
{"kind": "verbatim", "encoding": "uint", "value": 64}
{"kind": "verbatim", "encoding": "hex", "value": "01010100"}
```

Thus a consumer can tell desensitized addresses from values that are
disclosed exactly, without a raw-address field anywhere in the output.

## Verification

`verify(projection)` checks the manifest and every field commitment and
rejects a changed disclosed value, byte offset, file offset, or record
position.  `verify(projection, source=...)` additionally re-projects the
capture and rejects a different source or any value/source-range mismatch.
The small fixture at `examples/data/evidence_projection.pcap.gz` covers one
VLAN tag, IPv4 IHL 5 and 6, an untagged frame, a frame truncated in the
IPv4 header, and an unknown inner encapsulation.
