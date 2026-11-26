# Exchange gateway offline receipt

This example compares two ID-preserving STIX `identity` samples after exchange-gateway processing.

- `identity-before.json` and `identity-after.json` are the exchanged samples.
- `gateway-disclosure.json` binds gateway transform and marking rules to STIX granular-marking selectors.
- `gateway-markings.json` contains the referenced marking definitions.
- `verify.py` writes `offline-receipt.json` and asserts the scenario contract.

Run:

```sh
.venv/bin/python examples/exchange_receipt/verify.py
```

The receipt classifies `id` and unchanged properties as `identity_preserved`, `name` as
`explicitly_transformed`, and `contact_information` as `unverifiable`. `external_references` is
matched without regard to the two source-system entries' order. STIX `modified` is reported
separately as revision metadata. The only certified payload update is `description`.

An irreversible token cannot reverse the contact name. The receipt only verifies the marking
binding, declared token format, and, when a stable token is unchanged, pseudonym continuity. A
changed stable token without a continuity receipt remains visible as `transformed_drift_unproven`;
it is never silently excused as redaction.
