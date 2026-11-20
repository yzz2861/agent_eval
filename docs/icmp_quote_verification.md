# ICMP quoted-packet verification

An ICMP/ICMPv6 error carries only a prefix of the datagram that triggered it.
Those embedded bytes are a quote, not a second observation at the capture
point.  `dpkt.icmp_quote` separates the two and produces a queryable
evidence table.

## Usage

```python
from dpkt.icmp_quote import verify_icmp_quotes

table = verify_icmp_quotes(capture_bytes)  # pcap/pcapng bytes are accepted
for row in table:
    print(row.frame_index, row.status, row.quote_len, row.candidate_indices)
```

The input can also be a path, a binary file object, or an iterable of
`(timestamp, frame)` items.  For an iterable of IP packets without a link
layer, pass `linktype=dpkt.pcap.DLT_RAW`.

## Evidence fields

- `quote_len` is the number of bytes actually present in the quote.  It is
  never inferred from the embedded IP length field.
- `quoted_packet_len` is the length claimed by the embedded IP header.
  `quote_complete` and `quote_missing_bytes` compare the two without
  pretending the quote is a full captured packet.
- `extension_headers` records the IPv6 extension chain (and IPv4 options)
  with offsets, lengths and completeness; `extension_headers_truncated`
  flags a quote that ends inside the chain.
- `candidates` contains every top-level captured packet whose bytes match
  the quote.  `candidate_indices` preserves all of them; a repeated original
  is reported as `conflict` instead of silently choosing one.
- `partial_candidates` records captured packets that end before the quote
  does, together with the number of bytes that could be checked.

Matching first compares the quoted bytes exactly.  If no exact candidate
exists, it retries with IPv4 TTL/header checksum or IPv6 Hop Limit masked,
because routers may rewrite those fields.  Each candidate keeps its
`match_mode` (`exact` or `normalized`), and the row exposes `exact_match`,
so a normalized association is never silently presented as byte-exact.

## Querying outcomes

```python
complete = table.query(status='complete')       # exactly one observed original
only_quote = table.query(status='quote_only')   # quote without any original
conflict = table.query(status='conflict')       # multiple equally matching originals

# aliases: matched, only_quote, ambiguous
assert table.query(status='matched') == complete
assert table.query(status='ambiguous') == conflict
```

Rows can also be filtered by `family`/`ip_version`, `src`, `dst`,
`proto`, `quote_len`, `quote_truncated`, `icmp_truncated`,
`capture_truncated`, `has_extension_headers`, `candidate_count`,
`match_mode`, `exact_match` or a custom `where` callable.  `table.to_json()`
and `table.to_csv()` export the same rows.

## Command line

```console
$ python -m dpkt.icmp_quote capture.pcap --status conflict --format json
$ python -m dpkt.icmp_quote capture.pcap --extension-headers
```

The module's tests build one in-memory capture containing a complete match, a
quote with no observed original, and a two-candidate conflict, plus IPv6
extension-header and truncation cases.
