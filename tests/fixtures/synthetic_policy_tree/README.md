# Synthetic policy tree

This is a deliberately small certificate tree used by `tests/test_policy.py`.
It contains one leaf and two candidate validation paths:

```text
root
 |-- mid_good  (certificatePolicies P1)
 |    `-- issuer_good  (same subject/key as issuer_bad; policyMappings P1->P2)
 |         `-- leaf  (certificatePolicies P2)
 `-- mid_bad  (certificatePolicies P1; policyConstraints inhibitPolicyMapping=0)
      `-- issuer_bad  (same subject/key as issuer_good; policyMappings P1->P2)
           `-- leaf  (certificatePolicies P2)
```

`P1` is `1.3.6.1.4.1.99999.1.1` and `P2` is
`1.3.6.1.4.1.99999.1.2`.

The two issuer certificates intentionally share a subject and public key, so
the same leaf can be chained through either one. The good path applies the
P1->P2 mapping. The bad path hits `inhibitPolicyMapping=0` at `mid_bad`, so the
later mapping at `issuer_bad` is suppressed and no caller-approved policy
reaches the leaf. Both paths end at a leaf that declares P2, which is exactly
the case the policy evidence needs to keep distinct.

`leaf_pending.crt` is the same leaf with an extra unknown critical extension
(`1.3.6.1.4.1.99999.9.9`). It is used to verify that unreadable extensions are
reported as pending instead of being silently ignored.

All certificates are RSA/SHA-256 and valid for twenty years from their
generation date. No private keys are needed to use the fixtures.
