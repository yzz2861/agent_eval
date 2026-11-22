"""Dual-sink upload recording built on python-multipart callbacks.

The same parsed upload feeds two independent record sinks:

* a business receipt that retains confirmed metadata so a downstream
  system can reconcile against the original request;
* a customer-service diagnostic log that only stores opaque references
  and the current processing status, never raw values, names or
  filenames.
"""

from .recorder import AuditCallback, RecorderConfig, UploadRecorder
from .records import (
    ConfirmedMetadata,
    PartStatus,
    PublicReference,
    RejectionInfo,
    RejectReason,
    RequestStatus,
    RequestSummary,
)
from .sinks import BusinessReceiptSink, CustomerServiceLogSink, JsonlSink

__all__ = [
    "AuditCallback",
    "BusinessReceiptSink",
    "ConfirmedMetadata",
    "CustomerServiceLogSink",
    "JsonlSink",
    "PartStatus",
    "PublicReference",
    "RecorderConfig",
    "RejectReason",
    "RejectionInfo",
    "RequestStatus",
    "RequestSummary",
    "UploadRecorder",
]
