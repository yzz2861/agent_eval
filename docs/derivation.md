# Derived-Relationship Analysis

The same credential often appears in more than one textual form: the raw
value in one file, a percent-encoded copy in another, a JSON-escaped or
Base64-wrapped variant in a third. Treating each form as an independent leak
creates duplicate findings, while merging on superficial similarity (shared
prefixes, shared suffixes, masks) incorrectly conflates genuinely different
credentials that happen to look alike.

The `detect_secrets.derivation` backend solves both problems by merging
candidates **only** when a canonical, verifiable decoding relationship
exists between their raw values.

## Allowed Transforms

Only these in-process, one-directional decode transforms are permitted:

- `url_decode` — percent-encoding such as `%2F`
- `json_unescape` — JSON string escaping such as `\\u002f` and `\\n`
- `base64_decode` — standard Base64 layers
- `hex_decode` — hexadecimal layers

Every edge passes a strict round-trip check: decoding must succeed and
re-encoding must reproduce the observed bytes exactly. A chain is bounded to
`MAX_CHAIN_DEPTH = 3` edges and never revisits a value, so multi-layer
encodings are supported while unbounded search and collision-driven merges
are not. No external verification service is ever contacted.

## Merge Rules

1. Two candidates merge only when each can decode, within the chain bound,
   to an identical value through a verified chain.
2. Masking, shared prefixes/suffixes and edit-distance similarity never
   cause a merge. Look-alike pairs that fail every decode test are listed
   separately under `unverifiable_relationships` for manual review.
3. Every transform step records its transform name, the original source
   location of the candidate, and domain-separated identities of its input
   and output values.
4. Tenant labels participate in occurrence identities, so identical
   credentials belonging to different tenants are never merged.

## Persistence and Plaintext

Reports and baselines store domain-separated, irreversible HMAC-SHA256
identities only. Four HMAC domains (`occurrence`, `intermediate-value`,
`derived-group`, `unverified-relationship`) ensure an identity computed for
one purpose can never be confused with another. Plaintext candidate values
live solely in the in-memory analysis for the duration of a scan and can be
dropped explicitly with `clear_plaintext`. The `assert_no_plaintext` helper
gives callers an end-to-end guarantee that a serialized report never
contains raw credential material.

## CLI

```
detect-secrets scan . --all-files \
    --derivation-report derivation.json \
    --derivation-tenant acme
```

The regular baseline output is unchanged; the derivation report is an
additional, plaintext-free sidecar. Repeated scans over unchanged inputs
produce byte-identical reports.
