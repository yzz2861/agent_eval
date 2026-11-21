# Offline CMS time-stamp receipt inventory

`timestamp_audit` turns CMS/RFC 3161 time-stamp tokens into reviewable
provenance records for offline exhibit inventories. It is built entirely on
the local `asn1crypto` parse tree and standard-library hashing: no network
calls, no revocation fetching and no trust decisions are made by the tool.

## What determines identity

A receipt is associated with an exhibit only when both values declared inside
the TSTInfo `messageImprint` match a digest recomputed from the local exhibit
bytes:

1. the digest algorithm OID (`messageImprint.hashAlgorithm.algorithm`), and
2. the imprint digest bytes (`messageImprint.hashedMessage`).

The displayed `genTime` is recorded for readability and grouped in
`same_gen_time_groups`, but it never participates in matching. Two summary
pages printed at the exact same instant stay distinct whenever their declared
imprint digests differ.

## Explicit, separate failure states

- `bytes_missing`: the exhibit path does not resolve to a readable file, so
  no local digest could be computed; the exhibit still appears in
  `exhibits_without_receipt`.
- `algorithm_uninterpretable`: the receipt declared an algorithm OID the
  local hashlib build cannot map; the OID and raw imprint digest are retained
  for manual review, no digest is guessed.
- `no_local_match`: the algorithm was computable, but no available exhibit
  bytes produced the declared imprint digest.
- `unparseable_container` / `malformed_nested_token`: DER that could not be
  decoded; the error is reported instead of aborting the whole run.

## Signature authenticity

The tool never verifies signatures. Every receipt starts with
`signature_verdict = unprovided`; the caller attaches its own conclusion
keyed by `receipt_id`, the SHA-256 of the TimeStampToken DER bytes.
Supported verdicts are `valid`, `invalid`, `inconclusive`, `unprovided`.
Unknown ids/values appear under `verdict_warnings`. Identical token bytes in
multiple carriers share one `receipt_id`, so one verdict reaches every copy.

## Provenance and nesting

Each record stores `origin_path`, nesting `depth`, token DER SHA-256/length
and, for receipts inside another signer unsigned attributes, a
`provenance_chain` naming the parent receipt, signer-info index, attribute
type (`signature_time_stamp_token` or `microsoft_time_stamp_token`) and
attribute value index.

## CLI

    python -m timestamp_audit audit \
        --receipt summary_a.tsr --receipt summary_b.tsr \
        --exhibit EX-01=exhibit1.pdf --exhibit EX-02=exhibit2.pdf \
        --verdicts verdicts.json --output report.json

A JSON manifest (`receipt_files`, `exhibits`, `signature_verdicts`) may be
passed with `--manifest`. Both bare CMS `ContentInfo` (DER or PEM) and full
`TimeStampResp` wrappers are accepted. Exit code is 1 when the run contains
parse errors, missing exhibit bytes, unmatched receipts or unexplained
algorithms, and 0 otherwise; the JSON report is always written.

## Library use

    from timestamp_audit import build_inventory
    report = build_inventory(
        receipt_files=["summary_a.tsr"],
        exhibits=[("EX-01", "exhibit1.pdf")],
        signature_verdicts={receipt_id: {"verdict": "valid"}},
    )

The report is a plain dict suitable for `json.dumps`. See
`tests/test_timestamp_audit.py` and the synthetic fixture builder
`tests/timestamp_audit_data.py` for the full worked scenario, including two
equally-timed summary pages where only one exhibit has its own receipt.
