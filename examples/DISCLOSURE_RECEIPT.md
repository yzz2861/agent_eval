# Local disclosure receipts

This optional receipt builder sits beside the existing in-toto Link,
signature, and rule checks. It does not verify signatures itself. The caller
must first verify Link signatures and the applicable layout rules, then pass
only those step materials into `in_toto.disclosure`.

## Run the fictional fork/rename demo

```sh
PYTHONPATH=. .venv/bin/python examples/disclosure_receipt_demo.py
```

The demo writes text artifacts, signed Links, public keys, disclosure
requests, and paired receipts to `disclosure-demo-output/`. It also calls
`in_toto_verify` for the authorized chains.

## Receipt boundary

- `internal.json` keeps complete Link payloads, internal paths, digests,
  rule bases, diagnostics, and unauthorized branches for local review.
- `public.json` contains only the approval purpose, optional explicit public
  artifact label, explicit per-step fields, and a chain status.
- Equal digests do not create edges. Two artifacts are connected only when a
  checked material/product or MATCH rule basis references both nodes.
- Rename correlation is disclosed only through caller-approved public fields.
  The internal receipt retains old/new paths and original digests.
- Unauthorized, undisclosed, or divergent provenance produces the same generic
  `evidence_gap` public object. Public receipts contain no generated IDs,
  key IDs, error codes, counts of hidden branches, or internal diagnostics.

## CLI

```sh
PYTHONPATH=. .venv/bin/python -m in_toto.disclosure request.json \
  --internal-out internal.json \
  --public-out public.json
```

The request schema is exercised by `tests/test_disclosure.py` and the demo's
generated `requests/*.json` files.
