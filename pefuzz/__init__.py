"""Structure-preserving fuzzing toolkit for the pefile parser.

The package generates fully synthetic, sub-4KB PE images and mutates them
while preserving parseable semantics.  Every transformation records the
fields it depends on and the invariants the result must still satisfy, so a
differential test can prove that only coordinates changed unless a
single-constraint breakage mode was deliberately selected.
"""

from .records import (
    MutationRecord,
    FieldRef,
    SemanticChange,
)
from .builder import build_mini_pe
from .model import PEModel, PEError
from . import mutators
from . import compare
from .coverage import DirectoryCoverage, CoverageReport, measure
from .reducer import reduce_failure, ReductionResult
from .harness import generate_cases, FuzzCase, DEFAULT_SEED

__all__ = [
    "MutationRecord",
    "FieldRef",
    "SemanticChange",
    "build_mini_pe",
    "PEModel",
    "PEError",
    "mutators",
    "compare",
    "DirectoryCoverage",
    "CoverageReport",
    "measure",
    "reduce_failure",
    "ReductionResult",
    "generate_cases",
    "FuzzCase",
    "DEFAULT_SEED",
]
