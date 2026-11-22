# Dual-sink upload recording

An offline (no network service) example built only on the existing
`MultipartParser` streaming callbacks. One parsed upload fans out to two
independent trust domains.

## Outputs and trust levels

| Record | When produced | Business receipt | Support log |
| --- | --- | --- | --- |
| `ConfirmedMetadata` | part fully parsed and accepted | field name, content type, redacted filename, hashes, chunk count | never sent |
| `PublicReference` | every completed part | derived as a subset view | opaque `request_ref`/`part_ref`, status, byte count, salted fingerprint, reason code |
| `RejectionInfo` | refused part or request | reason, status, byte count, free-text detail | reason, status, byte count only (no detail) |

Raw part bytes only ever flow into streaming hash objects; they are never
buffered wholesale and never handed to a sink, so a half-parsed field cannot
be printed on error. Filenames are reduced to `file_redacted.<ext>` (or
`file_redacted`), so personal names and ID numbers cannot reach either log.

Fingerprints use an HMAC keyed with a per-request random salt, so identical
content from different requests is not linkable in the support log. The
business receipt additionally keeps an unsalted SHA-256 for reconciliation
against the original request.

## Edge cases covered

* field split across arbitrarily many transport chunks (streaming reassembly by hash);
* empty/missing part name -> `empty_name` rejection;
* missing or disallowed content type -> `unknown_content_type` rejection;
* audit callback returning `False` or raising -> `audit_callback_failed`, with the exception isolated so sibling parts still process;
* oversize part and malformed body, recorded with minimum info and no fingerprint.

Both sinks are optional and independent: pass `None` to switch either outlet
off while parsing and limits keep running.

## Running

```
python -m examples.dual_sink_upload.demo
pytest tests/test_dual_sink_upload.py --confcutdir=tests
```
