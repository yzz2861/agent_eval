The Export Guard
===============

The export guard is optional. It lets an application hand the already verified
export purpose and page selection to :class:`~pypdf.PdfWriter` while the guard
checks that the selected source pages are covered by an authorization bound to
the actual document content.

.. autoclass:: pypdf.DocumentIdentity
    :members:

.. autoclass:: pypdf.ExportAuthorization
    :members:

.. autoclass:: pypdf.ExportGuard
    :members:

.. autoclass:: pypdf.ExportDecision
    :members:

.. autoclass:: pypdf.ExportGuardError
    :members:

.. autoclass:: pypdf.ExportAuditRecord
    :members:

.. autoclass:: pypdf.ExportedPageRecord
    :members:

.. autoclass:: pypdf.ExportAuditEvent
    :members:

.. autoclass:: pypdf.ExportBlockReason
    :members:
