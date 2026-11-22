# CSR to Certificate Comparison

`asn1crypto.approval` provides a serializable comparison view for an approved
certificate signing request (CSR) and the certificate that was issued for it.
It is intended to sit inside an approval or audit backend.

The comparison is structural. It does not verify the CSR signature or the
certificate signature; those checks should be performed before the view is
built.

## Quick Start

```python
from asn1crypto import approval, csr, x509

approved = csr.CertificationRequest.load(csr_der)
issued = x509.Certificate.load(certificate_der)

view = approval.compare_csr_to_certificate(approved, issued)
print(view.verdict)
print(view.summary)
```

The same comparison is available from either object:

```python
view = approved.compare_to_certificate(issued)
view = issued.compare_to_csr(approved)
```

`approved_csr` and `issued_certificate` may also be DER or PEM byte strings.

## Result Shape

`view` is a `ComparisonView`. Important attributes are:

- `verdict`: `approved`, `review_required` or `rejected`
- `approved`: boolean shortcut for `verdict == "approved"`
- `summary`: counts of exact, narrowed, omitted, widened and issuer-added rows
- `extensions`: list of `ExtensionComparison` rows
- `findings`: flat list of errors and review warnings
- `subject` and `public_key`: comparison rows for the CSR identity and key
- `rows`: alias for `extensions`

`view.to_dict()` returns a JSON-ready structure. Individual rows are also
dict-like and expose `to_dict()`.

Every extension row carries:

- `extension` and `oid`
- `status`, `approved`, `legal_narrowing` and `reason`
- `request`, `requests` and `request_variants`
- `certificate`
- `change.added`, `change.removed` and `change.details`
- `provenance`
- `evidence`
- `trace`
- `issues`

## Extension Status

- `exact`: the issued value preserves the requested value
- `narrowed`: the issued value is a legal subset or less privilege
- `omitted`: the requested extension was not issued and omission is allowed
- `issuer_added`: the issuer added an extension with declared provenance
- `widened`: the certificate adds scope or removes a requested restriction
- `mismatch`: the value differs but is neither a subset nor a superset
- `unrequested`: the issuer added an extension with no declared provenance

Statuses are semantic, not byte-oriented. A certificate value that is
semantically equal but encoded differently is reported as `exact`, with
`evidence.match_basis == "semantic_exact"`.

## Default Narrowing Rules

The default policy allows these extensions to be narrowed:

- `key_usage`: bits may be removed
- `extended_key_usage`: purposes may be removed
- `subject_alt_name` and `issuer_alt_name`: names may be removed
- `certificate_policies`: policy identifiers may be removed
- `tls_feature`: features may be removed
- `subject_directory_attributes`: attributes may be removed
- `basic_constraints`: a CA may be reduced to an end entity, or a path length
  may be reduced
- `private_key_usage_period`: the period may be reduced

Other extensions default to exact semantic matching.

Custom rules can be supplied with `ApprovalPolicy`:

```python
policy = approval.ApprovalPolicy(
    narrowing={
        "1.2.3.4.5": "subset",
        "extended_key_usage": "subset"
    }
)
view = approval.compare_csr_to_certificate(approved, issued, policy=policy)
```

A rule may be a callable receiving
`(request_extension, certificate_extension)` and returning a boolean or a dict
with `approved`, `relation`, `added`, `removed` and `details`.

## Omission Semantics

Omission is not always narrowing. Absence of `extended_key_usage` or
`key_usage` means the certificate is not restricted to the requested usage, so
the default view classifies omission of those requests as `widened`. The
exception is a request for `any_extended_key_usage` or `any_policy`, where
absence and the requested value have the same scope.

The default omission table is:

- `widened`: `key_usage`, `extended_key_usage`, `private_key_usage_period`,
  `tls_feature`, `certificate_policies`, `name_constraints`,
  `policy_constraints`, `inhibit_any_policy`
- `narrowed`: `subject_alt_name`, `issuer_alt_name`,
  `subject_directory_attributes`
- `basic_constraints`: narrowed when a CA was requested, exact otherwise
- all other extensions: `missing`

`allow_omission` controls whether a `narrowed` omission is approved.
Custom or otherwise unclassified omissions require
`allow_missing_extensions=True`. Override the classification with
`omission_rules` when the deployment has different semantics.

## Issuer-Added Provenance

An extension that is absent from the CSR is approved only when the policy
declares a source. By default, sources are declared for issuer profile fields
such as `authority_key_identifier`, `crl_distribution_points`,
`authority_information_access`, `certificate_policies` and
`signed_certificate_timestamp_list`.

`key_identifier` is declared as derived from the subject public key. When it
matches the RFC 5280 method 1 SHA-1 digest, `provenance.verified` is true.

Deployments can add sources by name or dotted OID:

```python
policy = approval.ApprovalPolicy(
    issuer_extension_sources={
        "1.3.6.1.4.1.99999.1": {
            "kind": "tenant_profile",
            "source": "tenant-policy-42"
        }
    }
)
```

Unknown issuer-added extensions produce `UNREQUESTED_EXTENSION` and reject the
view unless `allow_unknown_issuer_extensions=True` is explicitly configured.

## Matching Evidence and Traceback

Requests are never collapsed just because they share an OID. Each request
remains in `requests`, with its exact field path:

```text
certification_request_info.attributes[2].values[0][1]
```

`trace.selected_request_path` identifies the request used as the matching
basis. `trace.request_paths` lists all candidates with the same OID. Use
`view.request_extension(path)` to retrieve the original ASN.1 extension object,
or `view.certificate_extension(path)` for the issued side.

When several requests are semantically equal but encoded differently:

- `request_variants` has one semantic variant with multiple paths
- `evidence.request_encoding_count` shows how many distinct encodings exist
- `evidence.request_encodings` records each path and DER hash
- each encoding receives its own `match_basis`, such as `der_exact` or
  `semantic_exact`

If requests for the same OID are semantically different, the row sets
`request_conflict=True` and the view requires review unless
`allow_conflicting_requests=True` is configured.

## Evidence Fields

`evidence.request_encodings[*]` and `evidence.certificate_encoding` contain:

- `value_der_hex` for the extension value
- `value_der_sha256`
- `extension_der_sha256`
- `oid_der_hex` for the extension OID

This preserves the exact bytes used for matching while also exposing the
canonical semantic value and its fingerprint.
