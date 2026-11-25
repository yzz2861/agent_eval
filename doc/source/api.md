# API

The in-toto API provides various functions and {doc}`classes <model>` that you
can use to generate, consume, modify and verify in-toto metadata, as a more
feature-rich, programmable alternative to the {doc}`command line tools
<command-line-tools/index>`.

```{admonition} Cryptographic Signatures
:class: tip

in-toto metadata is signed with cryptographic keys via the *Signer API*
in [securesystemslib](https://github.com/secure-systems-lab/securesystemslib)
Please refer to its [documentation](https://python-securesystemslib.readthedocs.io/en/latest/signer.html)
for details about loading a `Signer` for "Evidence Generation".

Loading verification keys for "Supply Chain Verification" is
documented [in-toto#663](https://github.com/in-toto/in-toto/issues/663).
```

## Evidence Generation

```{eval-rst}
.. autofunction:: in_toto.runlib.in_toto_run
```

```{eval-rst}
.. autofunction:: in_toto.runlib.in_toto_record_start
```

```{eval-rst}
.. autofunction:: in_toto.runlib.in_toto_record_stop
```

```{eval-rst}
.. autofunction:: in_toto.runlib.in_toto_match_products

```

## Supply Chain Verification

```{eval-rst}
.. autofunction:: in_toto.verifylib.in_toto_verify
```

## Optional Artifact Usage Review

The review is an optional, non-fatal analysis of how copies of an approved
artifact are renamed and consumed across the actual steps of a layout. It is
path-aware: two downstream files with identical hashes are not interchangeable
when only one of them is connected to the approved origin by a MATCH rule.

```{eval-rst}
.. autofunction:: in_toto.reviewlib.review_material_usage
```

```{eval-rst}
.. autoclass:: in_toto.reviewlib.ReviewResult
```

```{eval-rst}
.. autoclass:: in_toto.reviewlib.Finding
```
