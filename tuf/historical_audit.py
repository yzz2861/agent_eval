"""Public offline historical audit entry point."""

from __future__ import annotations

from tuf.api.history import (
    AuditReport,
    AuditRequest,
    CollectedMetadata,
    TargetSpec,
    TrustAnchor,
    audit,
    audit_dict,
    request_to_dict,
)
from tuf.api.history_codec import (
    request_from_dict,
    replay_bundle,
    replay_casebook,
)

audit_history = audit
audit_bundle = audit_dict
review_history = audit


class HistoricalAuditor:
    """Namespace-style facade for offline historical review."""

    audit = staticmethod(audit)
    audit_dict = staticmethod(audit_dict)
    audit_bundle = staticmethod(audit_dict)
    request_from_dict = staticmethod(request_from_dict)
    request_to_dict = staticmethod(request_to_dict)
    replay_bundle = staticmethod(replay_bundle)
    replay_casebook = staticmethod(replay_casebook)


__all__ = [
    "AuditReport",
    "AuditRequest",
    "CollectedMetadata",
    "HistoricalAuditor",
    "TargetSpec",
    "TrustAnchor",
    "audit",
    "audit_bundle",
    "audit_dict",
    "audit_history",
    "replay_bundle",
    "replay_casebook",
    "request_from_dict",
    "request_to_dict",
    "review_history",
]
