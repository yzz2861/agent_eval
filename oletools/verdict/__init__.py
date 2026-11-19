"""Composite verdict engine for oletools (gateway-embeddable).

Turns a container tree and per-node detector results into a single
order-independent security verdict that distinguishes detected risk,
checked-but-clean, not-covered and unparseable nodes, while retaining the
minimal evidence set needed to justify blocking.
"""

from .model import (
    Capability,
    ContainerEdge,
    ContainerNode,
    DetectorResult,
    Evidence,
    EvidenceReason,
    NodeKind,
    NodeStatus,
    Outcome,
    Policy,
    Severity,
    Verdict,
    content_key,
)
from .engine import VerdictEngine, VerdictReport, evaluate, worst_status
from . import adapters, fixtures

__all__ = [
    "Capability",
    "ContainerEdge",
    "ContainerNode",
    "DetectorResult",
    "Evidence",
    "EvidenceReason",
    "NodeKind",
    "NodeStatus",
    "Outcome",
    "Policy",
    "Severity",
    "Verdict",
    "VerdictEngine",
    "VerdictReport",
    "adapters",
    "content_key",
    "evaluate",
    "fixtures",
    "worst_status",
]
