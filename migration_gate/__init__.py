"""Migration gate: compare protected YAML config paths across a rewrite.

Uses PyYAML's safe loading path only. Compares effective values, types and
object-sharing relationships reachable from the protected key paths, and
collects evidence about merge keys, duplicate references and cyclic graphs.
"""

from .gate import (
    DEFAULT_MAX_DEPTH,
    DEFAULT_MAX_NODES,
    Finding,
    GateReport,
    run_gate,
)

__all__ = [
    "DEFAULT_MAX_DEPTH",
    "DEFAULT_MAX_NODES",
    "Finding",
    "GateReport",
    "run_gate",
]
