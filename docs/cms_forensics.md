# CMS signing-material inventory

Old archives often pass CMS/PKCS#7 files through tools that re-wrap BER as DER,
change indefinite lengths to definite lengths, or choose a different but
semantically equivalent representation for an attribute. A decoded
`ContentInfo` can therefore look identical while the bytes a signer signed are
no longer present.

`asn1crypto.cms_forensics` keeps three views separate:

 - the exact bytes that a signature covered
 - the decoded ASN.1 semantics
 - changes made by an outer archival wrapper or canonicalization

## Entry points

```python
from asn1crypto import cms

inventory = cms.signing_material(encoded_bytes)
inventory = cms.ContentInfo.load(encoded_bytes).signing_material()
inventory = cms.SignedData.load(signed_data_bytes).signing_material()
```

The equivalent module-level functions are available from
`asn1crypto.cms_forensics` and the compatibility module
`asn1crypto.cms_audit`.

Every loaded ASN.1 value also keeps an immutable snapshot:

```python
info = cms.ContentInfo.load(encoded_bytes)
info.dump(force=True)                 # working view may become DER
info.original_dump()                  # bytes actually loaded, unchanged
info.original_bytes                   # alias
```

The inventory always reads the immutable snapshot, so calling `dump()` or
`dump(force=True)` first does not replace the forensic view.

## Record shape

The returned `SigningMaterialInventory` is an `OrderedDict` with attribute
access. Important keys are:

 - `source`: original bytes, length, SHA-1/SHA-256, trailing-data length
 - `outer`: whether the input is byte-identical to canonical DER, the first
   difference, indefinite-length locations and archive change records
 - `layers`: one record per SignedData layer, including nested SignedData
 - `signers`: a flattened, independent record per SignerInfo
 - `semantics`: decoded values with archive-only bytes excluded
 - `semantic_fingerprint`: hash of the decoded view, useful for comparing two
   differently encoded copies
 - `content_fingerprint`: hash of the eContent and signed-attribute semantics,
   ignoring the actual signature bytes
 - `conclusions`, `lost_direct_evidence`, `preserved_direct_evidence`

Each signer record contains:

 - `signed_attributes`: decoded attributes, original source bytes and region,
   the retagged `SET OF` signature input, and the canonical DER input
 - `signed_region`: the actual signature input, its source bytes and regions
 - `signed_content`: eContent octets, digest and byte regions
 - `message_digest`: declared and computed digest plus `match`
 - `signature`: signature bytes and byte region
 - `verification`: independent result per signer, with each attempted input
   labelled `source` or `canonical`
 - `direct_evidence` / `lost_direct_evidence`: whether the historical signature
   can still be checked against a preserved representation

If the optional `cryptography` package is installed, signatures with a matching
embedded certificate are checked. A missing certificate or backend is reported
as `unavailable`, never as a valid signature. Set `verify=False` for a purely
structural inventory.

## Multi-layer signing

SignerInfos are analyzed independently. A signature over preserved eContent
octets can remain valid even if another signer signed attributes that were
re-encoded and no longer match the historical signature. Nested SignedData in
eContent, timestamp-token attributes and Microsoft nested signatures are
reported as additional layers when they can be parsed.

## Two-copy acceptance check

Two samples can decode to the same `semantic_fingerprint` while only one keeps
the historical signed bytes. Compare them as follows:

```python
first = cms.signing_material(original_bytes)
second = cms.signing_material(repacked_bytes)
assert first["semantic_fingerprint"] == second["semantic_fingerprint"]
assert first["outer"]["byte_identical"] is True
assert second["outer"]["byte_identical"] is False
```

In the acceptance fixtures one signer signs the eContent directly and remains
`direct_evidence=True` in both copies. The other signer signs attributes that
were changed from UTCTime to the semantically equal GeneralizedTime; its
signature verifies only in the original copy, and the repacked copy reports
`lost_direct_evidence=True` with
`signature_unverifiable_after_rewrapping`. The message digest can still match,
so the decoded content is preserved, but the historical issuance signature no
longer has direct byte evidence.
