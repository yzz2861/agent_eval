"""Compatibility import for the review coverage ledger.

The implementation lives in :mod:`Evtx.Ledger`; this module gives the
feature the alternative ``Evtx.Coverage`` import path.
"""

from .Ledger import CoverageLedger, FieldRequirements, RecordEntry, Receipt, TraceHit, UnreviewedRecord

__all__ = [
    "CoverageLedger",
    "FieldRequirements",
    "RecordEntry",
    "Receipt",
    "TraceHit",
    "UnreviewedRecord",
]
