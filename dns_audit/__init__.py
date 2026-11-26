"""Offline, provenance-preserving DNS alias auditing built on dpkt."""

from .audit import Audit
from .observer import DnsAudit, OfflineAliasObserver, audit_dns, observe_aliases
from .matching import MatchingResult, pair_exchanges
from .model import (
    Claim,
    DnsMessage,
    Exchange,
    PacketRef,
    Question,
    ReadError,
    ResourceRecord,
    Scope,
)

__version__ = "0.1.0"

__all__ = [
    "Audit",
    "DnsAudit",
    "OfflineAliasObserver",
    "audit_dns",
    "observe_aliases",
    "pair_exchanges",
    "MatchingResult",
    "Claim",
    "DnsMessage",
    "Exchange",
    "PacketRef",
    "Question",
    "ReadError",
    "ResourceRecord",
    "Scope",
]
