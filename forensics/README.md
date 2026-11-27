# Sealed-notice forensic review

The OpenPGP signatures on a batch of sealed notices all verify. What is
disputed is whether the custodian signed inside the approved time
window. `forensics.review` adds the forensic re-review on top of PGPy:

1. read the claimed signing time from the PGPy signature record
   (`PGPSignature.created`),
2. list it separately next to the externally observed windows — the
   external receipt of the notice and its independent preservation,
3. cross-check the claim against the caller-supplied approval window,
4. archive one record per notice, so a claim contradicted by a receipt
   is never conflated with a claim that has no external support at all.

## Usage

```
python -m forensics.review case.json --key custodian_pub.asc --out archive_report.json
```

The case file carries the approval window and, per notice, the notice
file, its detached signature and whatever external evidence exists:

```json
{
  "approved_window": {
    "not_before": "2026-03-01T00:00:00+00:00",
    "not_after": "2026-03-31T23:59:59+00:00",
    "issued_by": "compliance-office"
  },
  "notices": [
    {
      "id": "notice-a",
      "notice": "notice-a.txt",
      "signature": "notice-a.txt.sig.asc",
      "external_receipt": {
        "window": {"start": "2026-02-20T08:15:00+00:00"},
        "source": "mail-gateway received-headers log"
      },
      "independent_preservation": {
        "window": {"start": "2026-04-02T11:00:00+00:00",
                   "end": "2026-04-02T11:30:00+00:00"},
        "source": "third-party timestamping service"
      }
    },
    {"id": "notice-b", "notice": "notice-b.txt",
     "signature": "notice-b.txt.sig.asc"}
  ]
}
```

## Assessments

- `proven_before_approval` — external evidence proves the notice
  already existed before the approval window opened; the claimed
  signing time is contradicted.
- `claim_contradicted` — external evidence predates the claimed
  signing time (but not the approval window).
- `corroborated` — external evidence is consistent with the claim.
- `self_declared_only` — no receipt and no independent preservation;
  the signing time rests solely on the signer's own declaration.
- `signature_invalid` — the OpenPGP signature does not verify.

## Worked example

`forensics/examples/` holds two notices whose *printed* claimed signing
times are identical (`2026-03-10T09:30:00+00:00`, inside the approved
window). `notice-a` is proven by a mail-gateway receipt to have existed
on 2026-02-20 — before permission — while `notice-b` carries only its
own declaration. `archive_report.json` keeps that distinction.
Regenerate with:

```
python -m forensics.examples.build_examples
```

## Tests

```
python -m pytest forensics/tests
```
