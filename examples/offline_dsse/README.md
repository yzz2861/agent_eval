# Offline DSSE verification evidence

These two tiny bundles show the exchange format for a DSSE verification
conclusion that must remain recomputable after the original verifier is gone.

Each bundle contains:

- `evidence.json`: the sealed verification evidence.
- `artifact.txt`: the artifact bytes identified by the verification input.
- `public_key.pem`: caller-supplied public key material.

`evidence.json` records the exact `DSSEv1` pre-authentication encoding (PAE)
bytes, the payload type and payload lengths, the artifact SHA-256, and a
snapshot of each signer's algorithm and public key material. It never contains
private key material. Re-verification uses the recorded `keytype` and `scheme`;
it does not fill in a scheme from the library's current defaults.
The public key material embedded in the evidence is an identity checkpoint, not
an implicit trust anchor: pass `keys=` or `certificates=` to verify.

## Sample 1: reformat the outer JSON

The envelope is verified from decoded payload bytes and payload type, not from
the whitespace or key order of the exchange JSON. Reformatting the outer JSON
does not change the result:

```bash
python examples/offline_dsse/verify_samples.py
```

`sample1` is accepted as `verified`.

## Sample 2: one artifact byte changed

`sample2` uses the same sealed conclusion but changes the last byte of
`artifact.txt` from `0` to `1`. Verification is recomputable and explicitly
`rejected` with `artifact-digest-mismatch`.

## Result classes

- `verified`: the recorded conclusion was recomputed and reached the threshold.
- `rejected`: recomputation was possible, but the artifact, signature input, or
  signature check failed.
- `unverifiable`: the conclusion could not be recomputed, for example because
  caller key material is missing, the recorded algorithm is unavailable, or a
  verifier backend has been retired. The sealed conclusion is preserved in the
  report.
