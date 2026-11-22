"""Offline maintenance admission gate built on the TUF trusted metadata model.

The package models pause update and resume update authorization slips as
signed TUF delegated targets metadata.  A device only ever acts on statements
that survive the TUF verification chain (root -> timestamp -> snapshot ->
targets/delegated targets), so the arrival order of slips on different
channels cannot change the final admission decision.
"""

from tuf.contrib.maintenance_gate.gate import MaintenanceGate
from tuf.contrib.maintenance_gate.model import (
    PAUSE,
    RESUME,
    AdmissionDecision,
    AdmissionVerdict,
    AuthorizationStatement,
    GateStatus,
    IngestResult,
)
from tuf.contrib.maintenance_gate.repo import (
    AuthorizationRepository,
    DelegationSpec,
    Statement,
    target_path,
)

__all__ = [
    "PAUSE",
    "RESUME",
    "AdmissionDecision",
    "AdmissionVerdict",
    "AuthorizationRepository",
    "AuthorizationStatement",
    "DelegationSpec",
    "GateStatus",
    "IngestResult",
    "MaintenanceGate",
    "Statement",
    "target_path",
]
