"""Structure-aware fuzzing backend for oletools RTF object extraction.
The package works on a syntax tree (groups, destinations, backslash-bin
entries and hexadecimal fragments), keeps separate valid and invalid sample
pools, reduces findings by syntax unit while preserving the original
difference signature, and records seeds, transformation chains and minimal
samples under a dual step/byte budget. No Office application is ever invoked;
all embedded objects are harmless synthetic markers generated in-memory.
"""

from .model import (
    BinNode, ControlSymbolNode, ControlWordNode, DocumentNode,
    GroupNode, TextNode, parse_rtf, render, walk,
    find_objdata_groups, find_bin_nodes, find_hex_fragments,
)
from .seeds import (
    build_ole1_object, build_seed_documents, default_seed_corpus,
    hex_encode, bin_encode,
)
from .mutators import (
    VALID_MUTATORS, INVALID_MUTATORS, valid_mutation, invalid_mutation,
)
from .oracle import (
    Budget, Difference, ExtractionResult, extract,
    compare_valid, compare_invalid,
)
from .reducer import reduce_finding, ReductionOutcome
from .campaign import Campaign, CampaignConfig, run_campaign

__all__ = [
    "BinNode", "ControlSymbolNode", "ControlWordNode", "DocumentNode",
    "GroupNode", "TextNode", "parse_rtf", "render", "walk",
    "find_objdata_groups", "find_bin_nodes", "find_hex_fragments",
    "build_ole1_object", "build_seed_documents", "default_seed_corpus",
    "hex_encode", "bin_encode",
    "VALID_MUTATORS", "INVALID_MUTATORS", "valid_mutation",
    "invalid_mutation",
    "Budget", "Difference", "ExtractionResult", "extract",
    "compare_valid", "compare_invalid",
    "reduce_finding", "ReductionOutcome",
    "Campaign", "CampaignConfig", "run_campaign",
]
