"""
HTTP/2 header encoding for Python.
"""
from __future__ import annotations

from .exceptions import (
    CompressionContextMismatchError,
    CompressionDomainMismatchError,
    ContextDomainMismatchError,
    DomainMismatchError,
    HPACKDecodingError,
    HPACKEncodingError,
    HPACKError,
    InvalidTableIndex,
    InvalidTableIndexError,
    InvalidTableSizeError,
    OversizedHeaderListError,
    SecurityDomainError,
    SecurityDomainMismatchError,
)
from .hpack import Decoder, Encoder
from .struct import HeaderTuple, NeverIndexedHeaderTuple

__all__ = [
    "CompressionContextMismatchError",
    "CompressionDomainMismatchError",
    "ContextDomainMismatchError",
    "Decoder",
    "DomainMismatchError",
    "Encoder",
    "HPACKDecodingError",
    "HPACKEncodingError",
    "HPACKError",
    "HeaderTuple",
    "InvalidTableIndex",
    "InvalidTableIndexError",
    "InvalidTableSizeError",
    "NeverIndexedHeaderTuple",
    "OversizedHeaderListError",
    "SecurityDomainError",
    "SecurityDomainMismatchError",
]

__version__ = "4.3.0+dev"
