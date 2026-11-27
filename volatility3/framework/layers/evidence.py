"""Read provenance records shared by data and translation layers."""

from volatility3.framework.interfaces import layers

EvidenceInterval = layers.EvidenceInterval
LayerReadReport = layers.LayerReadReport
MappingInterval = layers.MappingInterval
MappingProvenance = layers.MappingProvenance
MappingSource = layers.MappingSource
ReadEvidence = layers.ReadEvidence
ReadGap = layers.ReadGap
ReadReport = layers.ReadReport
ReadResult = layers.ReadResult
coalesce_evidence = layers.coalesce_evidence
coalesce_mappings = layers.coalesce_mappings

__all__ = [
    "EvidenceInterval",
    "LayerReadReport",
    "MappingInterval",
    "MappingProvenance",
    "MappingSource",
    "ReadEvidence",
    "ReadGap",
    "ReadReport",
    "ReadResult",
    "coalesce_evidence",
    "coalesce_mappings",
]
