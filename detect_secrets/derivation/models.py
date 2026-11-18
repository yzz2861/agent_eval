"""In-memory data model for derived-relationship analysis.

These types carry plaintext candidate values while a scan is running.
Persistence (:mod:`detect_secrets.derivation.report`) strips every
plaintext field and writes only domain-separated identities.
"""
from dataclasses import dataclass
from typing import Any
from typing import Dict
from typing import List
from typing import Optional


@dataclass
class Observation:
    """One candidate occurrence, at one original source location."""

    occurrence_identity: str
    tenant: str
    secret_type: str
    filename: str
    line_number: int
    raw_value: str


@dataclass(frozen=True)
class TransformStep:
    """A single verified decoding edge, with the location of its source."""

    transform: str
    source_location: Dict[str, Any]
    input_identity: str
    output_identity: str


@dataclass(frozen=True)
class GroupMember:
    """One occurrence as it participates in a verified derived group."""

    occurrence_identity: str
    filename: str
    line_number: int
    secret_type: str
    tenant: str
    chain: List[TransformStep]
    connects_via: str
    root_reachable: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "occurrence_identity": self.occurrence_identity,
            "location": {
                "filename": self.filename,
                "line_number": self.line_number,
            },
            "secret_type": self.secret_type,
            "tenant": self.tenant,
            "connects_via": self.connects_via,
            "root_reachable": self.root_reachable,
            "chain": [
                {
                    "transform": step.transform,
                    "source_location": step.source_location,
                    "input_identity": step.input_identity,
                    "output_identity": step.output_identity,
                }
                for step in self.chain
            ],
        }


@dataclass(frozen=True)
class DerivationGroup:
    """A set of occurrences merged through verified decode chains."""

    group_identity: str
    root_value_identity: str
    members: List[GroupMember]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "group_identity": self.group_identity,
            "root_value_identity": self.root_value_identity,
            "members": [member.to_dict() for member in self.members],
        }


@dataclass(frozen=True)
class UnverifiableRelationship:
    """A look-alike pair that failed every verifiable decode test."""

    relationship_identity: str
    left_occurrence_identity: str
    right_occurrence_identity: str
    reason: str
    masked_left: str
    masked_right: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "relationship_identity": self.relationship_identity,
            "left_occurrence_identity": self.left_occurrence_identity,
            "right_occurrence_identity": self.right_occurrence_identity,
            "reason": self.reason,
            "masked_left": self.masked_left,
            "masked_right": self.masked_right,
        }


@dataclass
class DerivationAnalysis:
    """In-memory analysis result. Holds plaintext; never serialize directly."""

    tenant: Optional[str]
    observations: List[Observation]
    groups: List[DerivationGroup]
    unverifiable_relationships: List[UnverifiableRelationship]
    max_chain_depth: int = 3

    def to_report(self) -> "DerivationReport":
        """Projects the analysis into a plaintext-free persistable report."""
        return DerivationReport(
            tenant=self.tenant,
            max_chain_depth=self.max_chain_depth,
            observation_identities=sorted(
                observation.occurrence_identity
                for observation in self.observations
            ),
            groups=list(self.groups),
            unverifiable_relationships=list(self.unverifiable_relationships),
        )


@dataclass(frozen=True)
class DerivationReport:
    """Plaintext-free, JSON-serializable derivation report."""

    tenant: Optional[str]
    max_chain_depth: int
    observation_identities: List[str]
    groups: List[DerivationGroup]
    unverifiable_relationships: List[UnverifiableRelationship]

    def to_dict(self) -> Dict[str, Any]:
        from .identity import SCHEMA_VERSION
        return {
            "schema_version": SCHEMA_VERSION,
            "tenant": self.tenant,
            "max_chain_depth": self.max_chain_depth,
            "observations": list(self.observation_identities),
            "groups": [group.to_dict() for group in self.groups],
            "unverifiable_relationships": [
                candidate.to_dict()
                for candidate in self.unverifiable_relationships
            ],
        }
