"""Structured result types for the evidence timeline analysis."""

from __future__ import unicode_literals

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ByteRange(object):
    """A half-open ``[start, end)`` byte range inside a specific record blob."""

    record_id: str
    start: int
    end: int

    @property
    def length(self):
        return self.end - self.start

    def __str__(self):
        return '%s:[%d,%d)' % (self.record_id, self.start, self.end)


@dataclass
class Commitment(object):
    """What one time-stamp message imprint actually hashes to."""

    status: str
    kind: str
    description: str
    byte_ranges: List[ByteRange] = field(default_factory=list)
    matched_bytes: int = 0


@dataclass
class TokenInfo(object):
    """One parsed time-stamp token and where it was found."""

    token_id: str
    token_der: bytes
    generation_time: object
    serial_number: int
    tsa_key_id: Optional[str]
    hash_algorithm: str
    message_imprint: bytes
    located_in: List[str]
    attribute_oid: str
    signer_index: Optional[int]


@dataclass
class NestedRecord(object):
    """A ContentInfo discovered inside an outer wrapper."""

    path: List[str]
    bytes: bytes
    content_type: str


@dataclass
class ParsedRecord(object):
    """Parse result for one caller-supplied CMS record blob."""

    record_id: str
    content_type: str
    record_digest: bytes
    envelope_path: List[str]
    tokens: List[TokenInfo]
    nested_records: List[NestedRecord]
    signers: list


class TrustInput(object):
    """Caller-supplied trust verdicts. This package never signs or verifies."""

    TRUSTED = 'trusted'
    REJECTED = 'rejected'
    UNDETERMINED = 'undetermined'

    CHOICES = (TRUSTED, REJECTED, UNDETERMINED)


@dataclass
class TrustInputs(object):
    """Trust decisions injected by the caller, keyed by token / signer id."""

    token_verdicts: dict = field(default_factory=dict)
    signer_verdicts: dict = field(default_factory=dict)
    default_verdict: str = TrustInput.UNDETERMINED

    def __post_init__(self):
        for verdict in list(self.token_verdicts.values()) + list(
            self.signer_verdicts.values()
        ) + [self.default_verdict]:
            if verdict not in TrustInput.CHOICES:
                raise ValueError('unsupported trust verdict: %r' % (verdict,))

    def get(self, key, default=None):
        return self.token_verdicts.get(key, default)


@dataclass
class TimelineEntry(object):
    """One receipt on the reconstructed time line."""

    token_id: str
    record_id: str
    generation_time: object
    serial_number: int
    tsa_key_id: Optional[str]
    hash_algorithm: str
    message_imprint: bytes
    located_in: List[str]
    attribute_oid: str
    commitment: Commitment
    predecessor: Optional[str]
    trust: str
    repackaged: bool = False


@dataclass
class RecordEntry(object):
    """Summary of one supplied record and every receipt it carries."""

    record_id: str
    content_type: str
    record_digest: bytes
    blob_length: int
    envelope_path: List[str]
    tokens: List[TimelineEntry]


@dataclass
class Gap(object):
    """A broken link: which provable history segment is missing."""

    after_token_id: str
    missing_record_digest: Optional[str]
    reason: str
    still_provable_from: str


@dataclass
class Timeline(object):
    """Full reconstruction result."""

    records: List[RecordEntry]
    timeline: List[TimelineEntry]
    gaps: List[Gap]
    provable_window: List[str]
