"""Read-only static evidence view for PE delay-load transfer paths.

The package never invokes the operating system loader. Every conclusion is
derived from the bytes of a PE image (or an in-memory style dump of one) and
is tagged with the structural level at which the evidence exists.
"""

from .analyzer import analyze
from .loader import LoaderError, load_bytes, load_path
from .model import (
    AnalysisResult,
    Evidence,
    EvidenceKind,
    EvidenceLevel,
    LoadConfigSummary,
    ModuleEvidence,
    SymbolEvidence,
)
from .removal import remove_target
from .report import render_markdown, render_text

__all__ = [
    "analyze",
    "load_bytes",
    "load_path",
    "LoaderError",
    "remove_target",
    "render_markdown",
    "render_text",
    "AnalysisResult",
    "Evidence",
    "EvidenceKind",
    "EvidenceLevel",
    "LoadConfigSummary",
    "ModuleEvidence",
    "SymbolEvidence",
]
