# securesystemslib

[![CI](https://github.com/secure-systems-lab/securesystemslib/workflows/Run%20Securesystemslib%20tests/badge.svg)](https://github.com/secure-systems-lab/securesystemslib/actions?query=workflow%3A%22Run+Securesystemslib+tests%22+branch%3Amain)
[![Documentation Status](https://readthedocs.org/projects/python-securesystemslib/badge/?version=latest)](https://python-securesystemslib.readthedocs.io/en/latest/?badge=latest)

Securesystemslib is a cryptography interface for signing and verifying digital
signatures. It is developed for the [TUF](https://theupdateframework.io) and
[in-toto](https://in-toto.io) projects: the key and signature containers are
compatible with metadata formats from those projects.

Under the hood, Securesystemslib can use various digital signing systems
(e.g. [cryptography](https://pypi.org/project/cryptography/), PIV hardware keys
and multiple cloud-based key management systems).

## Installation

The default installation supports [pure-Python `ed25519` signature
verification](https://github.com/pyca/ed25519) only. To enable other schemes and
signature creation, `securesystemslib` can be installed with *extras*. See
[pyproject.toml](pyproject.toml) for available *optional dependencies*.

```bash
# Install with ed25519, RSA, ECDSA, ML-DSA sign and verify support
pip install securesystemslib[crypto]
```

```bash
# ...or with HSM (e.g. Yubikey) support
pip install securesystemslib[hsm]
```

## Usage
[python-securesystemslib.readthedocs.io](https://python-securesystemslib.readthedocs.io)

## Contact
- Questions and discussions:
  [`#securesystemslib-python`](https://cloud-native.slack.com/archives/C05PF3GA7AL)
  on [CNCF Slack](https://communityinviter.com/apps/cloud-native/cncf)
- Security issues: see [Security policy](docs/SECURITY.md)
- Other issues and requests: [*Open a new
  issue*](https://github.com/secure-systems-lab/securesystemslib/issues/new)

## Offline signing-policy review

The policy-review subpackage is an offline, read-only companion to the
DSSE signing code. It takes the key combinations accepted by a DSSE policy and
a frozen roster mapping each key to its control domain, then reports the
minimum number of domains that can jointly satisfy the policy (concentration)
and the minimum number whose absence blocks every legal release
(availability). Candidate-only ownership produces a pending-confirmation range
rather than a single number, and every result includes witness sets and a
per-key domain table for manual verification. See
[POLICY_REVIEW.md](docs/POLICY_REVIEW.md) and the examples under
[docs/policy_review_examples](docs/policy_review_examples).

## Contribute
See [Instructions for contributors](docs/CONTRIBUTING.md).

## Legacy key migration

Use
[`migrate_keys`](https://github.com/secure-systems-lab/securesystemslib/blob/v0.31.0/docs/migrate_key.py)
script to convert key pairs generated with legacy `keys` or `interface` modules
to a consistent standard format, which is compatible with
[`CryptoSigner`](docs/CRYPTO_SIGNER.md). The script requires
`securesystemslib~=0.31.0`.
