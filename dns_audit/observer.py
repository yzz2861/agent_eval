"""Stateful offline observer entry point."""
from __future__ import annotations

from typing import Iterable, Optional, Sequence, Tuple, Union

from .audit import Audit
from .model import DnsMessage
from .reader import read_capture

Source = Union[str, Tuple[str, str], dict]


class OfflineAliasObserver:
    """Collect captures or in-memory messages and then build an Audit."""

    def __init__(self, default_site: str = "memory") -> None:
        self.default_site = default_site
        self.captures = []
        self.messages = []

    def add_capture(self, source: str, site: Optional[str] = None):
        site = site or self.default_site
        capture = read_capture(source, site)
        self.captures.append(capture)
        self.messages.extend(capture.messages)
        return capture

    def add_source(self, source: Source):
        if isinstance(source, str):
            return self.add_capture(source)
        if isinstance(source, tuple) and len(source) == 2:
            path, site = source
            return self.add_capture(path, site)
        raise TypeError("unsupported source: %r" % (source,))

    def add_message(self, message: DnsMessage) -> None:
        self.messages.append(message)

    def add_messages(self, messages: Iterable[DnsMessage]) -> None:
        self.messages.extend(messages)

    def observe(self) -> Audit:
        return Audit.from_messages(self.messages, self.captures)

    run = observe
    build = observe


DnsAudit = Audit


def audit_dns(*sources: Source, messages: Optional[Sequence[DnsMessage]] = None) -> Audit:
    """Audit ``(path, site)`` sources and optional in-memory messages."""
    observer = OfflineAliasObserver()
    for source in sources:
        observer.add_source(source)
    if messages:
        observer.add_messages(messages)
    return observer.observe()


def observe_aliases(messages: Sequence[DnsMessage]) -> Audit:
    return Audit.from_messages(messages)
