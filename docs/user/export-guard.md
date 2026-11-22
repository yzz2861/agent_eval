# Export guard

Applications that assemble a hand-over PDF from several password-protected
sources can let pypdf verify the already confirmed purpose and page selection.
The guard identifies each source by its decrypted page content, so a different
file with the same name cannot reuse an authorization.

```python
from pypdf import ExportAuthorization, ExportGuard, PdfReader, PdfWriter

auditor = PdfReader(auditor_stream, password=auditor_password)
viewer = PdfReader(viewer_stream, password=viewer_password)

auditor_auth = ExportAuthorization.issue(
    auditor,
    purpose="legal_transmittal",
    pages=[0, 2],
    document_name="contract.pdf",
    subject="auditor",
)
viewer_auth = ExportAuthorization.issue(
    viewer,
    purpose="legal_transmittal",
    pages=[1],
    document_name="exhibit.pdf",
    subject="viewer",
)
guard = ExportGuard([auditor_auth, viewer_auth])

writer = PdfWriter(export_guard=guard)
writer.append(auditor, pages=[0, 2], purpose="legal_transmittal")
writer.append(viewer, pages=[1], purpose="legal_transmittal")

# One record per output page: source fingerprint, source page, authorization.
for record in writer.export_provenance:
    print(record.as_dict())
```

If a caller passes an authorization for the wrong source, the raised
`ExportGuardError` names the first source page without a matching basis, for
example `source page 1 (index 0) has no matching authorization`. Expired or
revoked grants, and page selections outside the granted range, are also
rejected. Every allowed export, blocked export and partial selection is written
to `guard.audit_log`.
