# Offline DNS audit

`dns_audit` uses `dpkt` to parse saved DNS captures and turns matched
question/response pairs into bounded name, address, alias, and negative claims.

## Run

```bash
python -m dns_audit --capture edge_a=a.pcap --capture edge_b=b.pcap --report text
python -m dns_audit --capture edge_a=a.pcap --report json
python -m dns_audit --demo
```

Compatibility entrypoints are also provided: `dns_offline_audit.py`,
`dns_alias_audit.py`, and `offline_alias_observer.py`.

## Evidence rules

- Matching never crosses capture domains. The same DNS txid at two collectors
  is recorded as a collision, not as one transaction.
- A response is unique only when same domain, txid, question section, reverse
  five-tuple, and time order identify one query.
- Indistinguishable same-domain candidates remain `ambiguous`; unmatched
  responses remain `orphan_response`. Neither produces a claim.
- Claims carry collector/source/frame references, match basis, observation
  window, TTL extrapolation, and TC/truncation status.
- CNAME traces stay inside one domain. Missing terminal addresses, multiple
  targets, cycles, and truncation are explicit review reasons.
- Address equality is reported only for names in the same capture domain and
  only for saved observations. It is not a global or permanent claim.

The in-memory demo contains the same txid in two domains, same-domain
duplicate candidates, a complete alias closure, and an incomplete chain.
