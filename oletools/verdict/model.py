"""
model.py - composite verdict data model for oletools.

This module defines the container-tree primitives, detector-result records and
the vocabulary shared by the verdict engine.  It deliberately has no third
party dependency so that a gateway can import it in restricted environments.

Status vocabulary (the four dispositions a scanned object can end up with):

* :data:`NodeStatus.RISK`        - a confirmed risk was detected
* :data:`NodeStatus.CLEAN`       - every required capability ran and found none
* :data:`NodeStatus.UNCOVERED`   - a required capability could not be exercised
* :data:`NodeStatus.UNPARSEABLE` - the object itself could not be parsed

A whole-document :class:`Verdict` additionally distinguishes *why* a scan is
incomplete (unparseable vs. uncovered) so a gateway never mistakes "nothing
found" for "the file is safe".
"""

from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional, Set, Tuple, Union


class Capability(str, enum.Enum):
    """Scanning capabilities a detector may provide for an object."""

    MACRO = 'macro'
    DDE = 'dde'
    EMBEDDED_OBJECT = 'embedded_object'
    EXTERNAL_RELATIONSHIP = 'external_relationship'
    FLASH = 'flash'
    OLE_STRUCTURE = 'ole_structure'
    OOXML_STRUCTURE = 'ooxml_structure'
    ENCRYPTION = 'encryption'
    UNKNOWN_EMBED = 'unknown_embed'
    PARSER = 'parser'


class NodeKind(str, enum.Enum):
    """Kinds of container-tree nodes."""

    OLE = 'ole'
    OOXML = 'ooxml'
    RTF = 'rtf'
    OLE_STREAM = 'ole_stream'
    OOXML_PART = 'ooxml_part'
    EMBEDDED = 'embedded'
    UNKNOWN = 'unknown'


class NodeStatus(str, enum.Enum):
    """The four object-level dispositions required by the gateway contract."""

    RISK = 'risk'
    CLEAN = 'clean'
    UNCOVERED = 'uncovered'
    UNPARSEABLE = 'unparseable'


class Verdict(str, enum.Enum):
    """Document-level decision returned to the gateway."""

    ALLOW = 'allow'
    BLOCK_RISK = 'block_risk'
    BLOCK_UNPARSEABLE = 'block_unparseable'
    BLOCK_UNCOVERED = 'block_uncovered'


class Outcome(str, enum.Enum):
    """Outcome of a single detector run against one node/capability."""

    CLEAN = 'clean'
    RISK = 'risk'
    ERROR = 'error'


class Severity(int, enum.Enum):
    """Severity ordering used to rank risk evidence (higher wins)."""

    INFO = 10
    LOW = 20
    MEDIUM = 30
    HIGH = 40
    CRITICAL = 50


class EvidenceReason(str, enum.Enum):
    """Why a piece of blocking evidence was produced."""

    DETECTOR_FINDING = 'detector_finding'
    DETECTOR_ERROR = 'detector_error'
    DETECTOR_CLEAN = 'detector_clean'
    ENCRYPTED = 'encrypted'
    CORRUPT = 'corrupt'
    CYCLE = 'cycle'
    UNKNOWN_FORMAT = 'unknown_format'
    CAPABILITY_GAP = 'capability_gap'
    UNEXAMINED_EDGE = 'unexamined_edge'
    UNKNOWN_EDGE = 'unknown_edge'
    GAP = 'capability_gap'
    BRANCH_UNEXAMINED = 'unexamined_edge'


# Reasons that describe a structural parsing failure of the node itself.
UNPARSEABLE_REASONS = frozenset((
    EvidenceReason.ENCRYPTED,
    EvidenceReason.CORRUPT,
    EvidenceReason.CYCLE,
))


def content_key(payload: bytes) -> str:
    """Return a stable identity key for raw node content."""
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError('payload must be bytes, got {0}'.format(type(payload)))
    return hashlib.sha256(bytes(payload)).hexdigest()


@dataclass(frozen=True)
class DetectorResult:
    """The result of one detector examining one node for one capability.

    ``capability`` accepts either a :class:`Capability` or a plain string so
    gateway-defined capabilities do not require code changes here.
    """

    node_id: str
    capability: Union[Capability, str]
    outcome: Outcome
    detector: str
    severity: Severity = Severity.MEDIUM
    detail: str = ''
    signature: str = ''

    def __post_init__(self) -> None:
        if isinstance(self.outcome, str) and not isinstance(self.outcome, Outcome):
            object.__setattr__(self, 'outcome', Outcome(self.outcome))
        if isinstance(self.severity, int) and not isinstance(self.severity, Severity):
            object.__setattr__(self, 'severity', Severity(self.severity))

    @property
    def capability_key(self) -> str:
        cap = self.capability
        return cap.value if isinstance(cap, Capability) else str(cap)

    def dedupe_key(self) -> Tuple[str, str, str, str]:
        """Identity used for retry replacement / de-duplication."""
        return (self.node_id, self.capability_key, self.detector, self.signature)


@dataclass
class ContainerNode:
    """One object in the container tree.

    ``node_id`` must be unique within a tree.  When the same physical sub-object
    is reachable through several parents it should be modelled as one node with
    several incoming edges, never as duplicated nodes - that is what keeps
    shared content from being counted twice.
    """

    node_id: str
    kind: Union[NodeKind, str] = NodeKind.UNKNOWN
    name: str = ''
    encrypted: bool = False
    corrupt: bool = False
    payload: Optional[bytes] = None
    content_key: Optional[str] = None
    tags: Set[str] = field(default_factory=set)
    parse_error: Optional[str] = None
    format_hint: Optional[str] = None

    def __post_init__(self) -> None:
        if isinstance(self.kind, str) and not isinstance(self.kind, NodeKind):
            self.kind = NodeKind(self.kind)
        if self.content_key is None and self.payload is not None:
            self.content_key = content_key(self.payload)

    @property
    def kind_key(self) -> str:
        kind = self.kind
        return kind.value if isinstance(kind, NodeKind) else str(kind)


@dataclass(frozen=True)
class ContainerEdge:
    """A directed parent -> child reference inside the container tree."""

    parent_id: str
    child_id: str
    label: str = ''
    known_format: bool = True
    examined: bool = True

    def sort_key(self) -> Tuple[str, str, str]:
        return (self.parent_id, self.label, self.child_id)


@dataclass(frozen=True)
class Evidence:
    """A minimal, serialisable record justifying part of a verdict."""

    node_id: str
    capability: str
    reason: EvidenceReason
    severity: Severity
    detector: str = ''
    detail: str = ''
    signature: str = ''
    edge: Tuple[str, str] = ('', '')
    attempts: int = 1

    def __post_init__(self) -> None:
        if isinstance(self.reason, str) and not isinstance(self.reason, EvidenceReason):
            object.__setattr__(self, 'reason', EvidenceReason(self.reason))
        if isinstance(self.severity, int) and not isinstance(self.severity, Severity):
            object.__setattr__(self, 'severity', Severity(self.severity))

    def dedupe_key(self) -> Tuple[Any, ...]:
        return (
            self.node_id,
            self.capability,
            self.reason.value,
            self.detector,
            self.signature,
            self.edge,
        )

    def sort_key(self) -> Tuple[Any, ...]:
        return (
            -int(self.severity),
            self.node_id,
            self.capability,
            self.reason.value,
            self.detector,
            self.signature,
            self.edge,
        )

    def to_dict(self) -> dict:
        return {
            'node_id': self.node_id,
            'capability': self.capability,
            'reason': self.reason.value,
            'severity': int(self.severity),
            'severity_name': self.severity.name,
            'detector': self.detector,
            'detail': self.detail,
            'signature': self.signature,
            'edge': list(self.edge),
            'attempts': self.attempts,
        }


@dataclass(frozen=True)
class Policy:
    """Gateway policy describing which capabilities are mandatory.

    ``required_capabilities`` is the set of capabilities that must be exercised
    on every node for which they are applicable.  A node lacking one is
    *uncovered*, never clean.

    ``applicability`` optionally restricts a capability to specific node kinds.
    A capability absent from the mapping applies to every node kind.

    Removing a capability from the required set only stops *missing coverage*
    from blocking; a confirmed :data:`Outcome.RISK` result for that capability
    still blocks.  Ignoring a detector can therefore never erase known risk.
    """

    required_capabilities: frozenset
    applicability: dict = field(default_factory=dict)

    def __init__(
        self,
        required_capabilities: Iterable[Union[Capability, str]] = (),
        applicability: Optional[dict] = None,
    ) -> None:
        normalized = frozenset(
            cap.value if isinstance(cap, Capability) else str(cap)
            for cap in required_capabilities
        )
        object.__setattr__(self, 'required_capabilities', normalized)
        mapping = {}
        for cap, kinds in (applicability or {}).items():
            cap_key = cap.value if isinstance(cap, Capability) else str(cap)
            mapping[cap_key] = frozenset(
                kind.value if isinstance(kind, NodeKind) else str(kind)
                for kind in kinds
            )
        object.__setattr__(self, 'applicability', mapping)

    def is_required(self, capability: Union[Capability, str]) -> bool:
        cap = capability.value if isinstance(capability, Capability) else str(capability)
        return cap in self.required_capabilities

    def applies_to(self, capability: Union[Capability, str], kind: Union[NodeKind, str]) -> bool:
        cap = capability.value if isinstance(capability, Capability) else str(capability)
        kind_key = kind.value if isinstance(kind, NodeKind) else str(kind)
        allowed = self.applicability.get(cap)
        return allowed is None or kind_key in allowed

    def required_for(self, kind: Union[NodeKind, str]) -> Set[str]:
        kind_key = kind.value if isinstance(kind, NodeKind) else str(kind)
        return {
            cap
            for cap in self.required_capabilities
            if self.applies_to(cap, kind_key)
        }

    @classmethod
    def strict_default(cls):
        """Policy with every standard scanning capability required."""
        return cls(required_capabilities=(
            Capability.MACRO,
            Capability.DDE,
            Capability.EMBEDDED_OBJECT,
            Capability.EXTERNAL_RELATIONSHIP,
            Capability.FLASH,
            Capability.OLE_STRUCTURE,
            Capability.OOXML_STRUCTURE,
            Capability.ENCRYPTION,
            Capability.UNKNOWN_EMBED,
            Capability.PARSER,
        ))

    def to_dict(self) -> dict:
        return {
            'required_capabilities': sorted(self.required_capabilities),
            'applicability': {
                cap: sorted(kinds) for cap, kinds in sorted(self.applicability.items())
            },
        }
