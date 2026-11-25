"""Synthetic CMS evidence time-line reconstruction (parse-only, no crypto trust).

Public entry points:

* :class:`evidence_timeline.analyzer.TimelineAnalyzer` - reconstruct which
  time-stamp receipt promised which byte range of which supplied record.
* :class:`evidence_timeline.model.TrustInputs` - caller-supplied trust
  verdicts. The package itself never verifies signatures.
* :mod:`evidence_timeline.samples` - builders for the three-stage synthetic
  CMS / receipt sample set.
"""

from .analyzer import TimelineAnalyzer
from .model import (
    ByteRange,
    Commitment,
    Gap,
    ParsedRecord,
    RecordEntry,
    Timeline,
    TimelineEntry,
    TrustInput,
    TrustInputs,
    TokenInfo,
)

__all__ = [
    'TimelineAnalyzer',
    'TrustInputs',
    'TrustInput',
    'Timeline',
    'TimelineEntry',
    'RecordEntry',
    'Commitment',
    'ByteRange',
    'Gap',
    'ParsedRecord',
    'TokenInfo',
]
