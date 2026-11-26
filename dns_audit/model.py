"""Evidence models for offline DNS question/answer review."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


MATCH_UNIQUE = "unique"
MATCH_AMBIGUOUS = "ambiguous"
MATCH_ORPHAN = "orphan_response"
MATCH_UNANSWERED = "unanswered"

CLAIM_ADDRESS = "address"
CLAIM_ALIAS = "alias"
CLAIM_NEGATIVE = "negative"

COMPARE_EQUAL_OBSERVED = "equal_observed"
COMPARE_DIFFERENT_OBSERVED = "different_observed"
COMPARE_INSUFFICIENT = "insufficient_evidence"

QTYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    10: "NULL",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    41: "OPT",
    255: "ANY",
}

RCODE_NAMES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
    6: "YXDOMAIN",
    7: "YXRRSET",
    8: "NXRRSET",
    9: "NOTAUTH",
    10: "NOTZONE",
}


def normalize_name(name: Any) -> str:
    """Normalize DNS names for comparison without changing provenance."""
    if name is None:
        return ""
    if isinstance(name, bytes):
        name = name.decode("ascii", errors="replace")
    return str(name).rstrip(".").lower()


def qtype_name(qtype: Optional[int]) -> str:
    if qtype is None:
        return "UNKNOWN"
    return QTYPE_NAMES.get(int(qtype), "TYPE%d" % int(qtype))


def rcode_name(rcode: Optional[int]) -> str:
    if rcode is None:
        return "NONE"
    return RCODE_NAMES.get(int(rcode), "RCODE%d" % int(rcode))


@dataclass(frozen=True)
class PacketRef:
    """A packet location and its immutable collection attribution."""

    site: str
    source: str
    frame_index: int = 0
    timestamp: Optional[float] = None
    capture_domain: Optional[str] = None

    def __post_init__(self) -> None:
        if self.capture_domain is None:
            object.__setattr__(self, "capture_domain", self.site)

    @property
    def frame_number(self) -> int:
        """Wireshark-style one-based frame number."""
        return int(self.frame_index) + 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "site": self.site,
            "capture_domain": self.capture_domain or self.site,
            "source": self.source,
            "frame_index": self.frame_index,
            "frame_number": self.frame_number,
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True)
class Question:
    name: str
    qtype: int
    qclass: int = 1

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", normalize_name(self.name))

    def key(self) -> Tuple[str, int, int]:
        return self.name, int(self.qtype), int(self.qclass)

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "qtype": self.qtype,
                "qtype_name": qtype_name(self.qtype), "qclass": self.qclass}


@dataclass(frozen=True)
class ResourceRecord:
    name: str
    rtype: int
    rclass: int = 1
    ttl: int = 0
    value: Optional[str] = None
    raw_text: Optional[str] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", normalize_name(self.name))
        if self.rtype in (2, 5, 12) and self.value:
            object.__setattr__(self, "value", normalize_name(self.value))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "type": self.rtype,
            "type_name": qtype_name(self.rtype),
            "class": self.rclass,
            "ttl": self.ttl,
            "value": self.value,
            "raw_text": self.raw_text,
        }


# Shorter alias used throughout the auditor.
RR = ResourceRecord


@dataclass(frozen=True)
class DnsMessage:
    ref: PacketRef
    txid: int
    is_response: bool
    qr_names: Tuple[str, ...] = ()
    questions: Tuple[Question, ...] = ()
    answers: Tuple[ResourceRecord, ...] = ()
    authorities: Tuple[ResourceRecord, ...] = ()
    additionals: Tuple[ResourceRecord, ...] = ()
    rcode: Optional[int] = 0
    truncated: bool = False
    authoritative: bool = False
    recursion_available: bool = False
    transport: str = "udp"
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    parse_note: Optional[str] = None

    @property
    def site(self) -> str:
        return self.ref.site

    @property
    def qname(self) -> Optional[str]:
        return self.questions[0].name if self.questions else None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ref": self.ref.to_dict(),
            "site": self.ref.site,
            "capture_domain": self.ref.capture_domain or self.ref.site,
            "txid": self.txid,
            "is_response": self.is_response,
            "rcode": self.rcode,
            "rcode_name": rcode_name(self.rcode),
            "truncated": self.truncated,
            "authoritative": self.authoritative,
            "transport": self.transport,
            "five_tuple": {
                "src_ip": self.src_ip, "src_port": self.src_port,
                "dst_ip": self.dst_ip, "dst_port": self.dst_port,
                "transport": self.transport,
            },
            "questions": [q.to_dict() for q in self.questions],
            "answers": [rr.to_dict() for rr in self.answers],
            "authorities": [rr.to_dict() for rr in self.authorities],
            "additionals": [rr.to_dict() for rr in self.additionals],
            "parse_note": self.parse_note,
        }


# Compatibility name for callers thinking in terms of observations.
PacketObservation = DnsMessage


@dataclass(frozen=True)
class ReadError:
    ref: PacketRef
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return {"ref": self.ref.to_dict(), "reason": self.reason}


@dataclass
class CaptureResult:
    source: str
    site: str
    capture_domain: Optional[str] = None
    file_format: Optional[str] = None
    messages: List[DnsMessage] = field(default_factory=list)
    read_errors: List[ReadError] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.capture_domain is None:
            self.capture_domain = self.site

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "site": self.site,
            "capture_domain": self.capture_domain,
            "file_format": self.file_format,
            "message_count": len(self.messages),
            "read_errors": [e.to_dict() for e in self.read_errors],
        }


@dataclass(frozen=True)
class Scope:
    """Empirical observation window and TTL-based claim limit."""

    site: str
    observed_first: Optional[float]
    observed_last: Optional[float]
    response_time: Optional[float] = None
    ttl_seconds: Optional[int] = None
    valid_until: Optional[float] = None
    ttl_until: Optional[float] = None
    truncated: bool = False
    complete: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "site": self.site,
            "observed_first": self.observed_first,
            "observed_last": self.observed_last,
            "response_time": self.response_time,
            "ttl_seconds": self.ttl_seconds,
            "valid_until": self.valid_until,
            "ttl_until": self.ttl_until,
            "truncated": self.truncated,
            "complete": self.complete,
            "validity_statement": (
                "limited to packets saved in this capture domain and "
                "the observed time window; TTL expiry is an extrapolation"
            ),
        }


@dataclass(frozen=True)
class Claim:
    kind: str
    site: str
    name: str
    value: Optional[str]
    scope: Scope
    query_ref: PacketRef
    response_ref: PacketRef
    exchange_id: Optional[str] = None
    claim_id: Optional[str] = None
    query_name: Optional[str] = None
    qtype: Optional[int] = None
    rcode: Optional[int] = None
    rr_index: Optional[int] = None
    match_basis: Tuple[str, ...] = ()
    exchange_index: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "exchange_id": self.exchange_id,
            "exchange_index": self.exchange_index,
            "kind": self.kind,
            "site": self.site,
            "capture_domain": self.site,
            "name": self.name,
            "query_name": self.query_name,
            "qtype": self.qtype,
            "qtype_name": qtype_name(self.qtype),
            "value": self.value,
            "rcode": self.rcode,
            "rcode_name": rcode_name(self.rcode),
            "match_basis": list(self.match_basis),
            "scope": self.scope.to_dict(),
            "query_ref": self.query_ref.to_dict(),
            "response_ref": self.response_ref.to_dict(),
        }


@dataclass
class Exchange:
    site: str
    txid: int
    status: str
    match_basis: List[str] = field(default_factory=list)
    exchange_id: Optional[str] = None
    query: Optional[DnsMessage] = None
    response: Optional[DnsMessage] = None
    candidates: List[PacketRef] = field(default_factory=list)
    candidate_requests: List[str] = field(default_factory=list)
    candidate_responses: List[str] = field(default_factory=list)
    ambiguity: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        query_ref = self.query.ref.to_dict() if self.query else None
        response_ref = self.response.ref.to_dict() if self.response else None
        return {
            "exchange_id": self.exchange_id,
            "site": self.site,
            "capture_domain": self.site,
            "txid": self.txid,
            "status": self.status,
            "match_basis": list(self.match_basis),
            "ambiguity": self.ambiguity,
            "query": self.query.to_dict() if self.query else None,
            "response": self.response.to_dict() if self.response else None,
            "query_ref": query_ref,
            "response_ref": response_ref,
            "query_frame": self.query.ref.frame_index if self.query else None,
            "response_frame": self.response.ref.frame_index if self.response else None,
            "query_frame_number": self.query.ref.frame_number if self.query else None,
            "response_frame_number": self.response.ref.frame_number if self.response else None,
            "candidate_refs": [r.to_dict() for r in self.candidates],
            "candidate_frames": [r.frame_index for r in self.candidates],
            "candidate_frame_numbers": [r.frame_number for r in self.candidates],
            "candidate_requests": list(self.candidate_requests),
            "candidate_responses": list(self.candidate_responses),
        }
