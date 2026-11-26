# Approval attachment retirement demo

Run from the repository root:

```bash
python examples/approval_retirement/demo.py
```

The demo writes two evidence bundles under `evidence/`:

- `success/` contains a completed retirement: the attachment is deleted, the
  signed manifest keeps its digest and approver-signed authorization, and
  `evidence/verification-report.json` has status `valid`.
- `shared-reference/` contains a refused retirement: two cases use the same
  attachment, so it is kept. `evidence/rejection.json` and
  `evidence/verification-report.json` record the reason and the still-matching
  digest.

`evidence/acceptance-summary.json` lists both outcomes and their evidence
directories. Each bundle also includes `public-keys.json`, which can be used to
re-verify the signed index and manifest independently.

To re-run verification from those public keys only:

```bash
python examples/approval_retirement/verify_evidence.py
```
