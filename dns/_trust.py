# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

"""DNS response trust policy.

This internal module implements the explicit trust policy applied to
recursive (stub) resolver responses before anything is cached.

A response is split into two views:

* the *raw* response is preserved unchanged, for inspection and debugging;
* the *trusted* (cacheable) view only contains RRSets that are anchored to
  the query name, reachable through a well formed CNAME/DNAME chain, inside
  the applicable bailiwick, and in an appropriate section.

Audit information deliberately contains only coarse classifications (name
category, RR class/type category, and a rejection reason).  Full upstream
response contents are never copied into audit records.

The rules follow the bailiwick and CNAME/DNAME guidance in RFC 1034 and
RFC 2181, the DNAME specification RFC 6672, and the DNSSEC processing rules
of RFC 4035 (which require security metadata to be retained alongside the
records it protects).
"""

from __future__ import annotations

import dataclasses
import enum
from typing import TYPE_CHECKING

import dns.exception
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset

if TYPE_CHECKING:
    import dns.message

#: Maximum permitted CNAME/DNAME chain length.  Mirrors
#: ``dns.message.MAX_CHAIN`` so this module does not import dns.message at
#: runtime (the import graph would otherwise be circular).
MAX_CHAIN = 16


class TrustError(dns.exception.DNSException):
    """Base class for response trust policy violations."""


class CNAMELoop(TrustError):
    """A CNAME chain in the response contains a loop."""


class ChainTooLong(TrustError):
    """The CNAME/DNAME chain is longer than the permitted maximum."""


class NameCategory(enum.Enum):
    """Coarse classification of an owner or target name, for auditing."""

    QUERY_NAME = "query-name"
    CHAIN_NAME = "chain-name"
    AUTHORITY_NAME = "authority-name"
    UNRELATED_NAME = "unrelated-name"


class TrustRejectReason(enum.Enum):
    """Reasons an RRset may be refused entry into the cacheable view."""

    UNKNOWN_RDCLASS = "unknown-rdclass"
    UNKNOWN_RDTYPE = "unknown-rdtype"
    WRONG_RDCLASS = "wrong-rdclass"
    OUT_OF_BAILIWICK = "out-of-bailiwick"
    CROSS_ZONE_TARGET = "cross-zone-target"
    DUPLICATE_OWNER = "duplicate-owner"
    BAD_SECTION = "bad-section"
    CNAME_LOOP = "cname-loop"
    CHAIN_TOO_LONG = "chain-too-long"


@dataclasses.dataclass(frozen=True)
class TrustReject:
    """An audit entry for a single RRset refused by the trust policy.

    Only coarse, non-sensitive classifications are stored: the message
    section number, a name category, the numeric RR class/type categories,
    and the rejection reason.  Owner names, rdata, and the upstream message
    itself are never recorded here.
    """

    section: int
    name_category: NameCategory
    rdclass: int
    rdtype: int
    reason: TrustRejectReason


@dataclasses.dataclass
class TrustResult:
    """The outcome of applying a :class:`TrustPolicy` to a response.

    ``trusted_response`` is a new :class:`dns.message.QueryMessage` containing
    only cacheable RRSets.  ``raw_response`` is the original, unmodified
    response.  ``rejects`` holds one :class:`TrustReject` per refused RRset.
    """

    trusted_response: dns.message.QueryMessage
    raw_response: dns.message.QueryMessage
    rejects: list[TrustReject]


class TrustPolicy:
    """Resolver response trust policy.

    The policy walks the CNAME/DNAME chain rooted at the question name and
    admits into the cacheable view only the RRSets that belong to that chain
    (the chain links themselves and the final answer), plus in-bailiwick
    authority SOA/NS RRSets and DNSSEC security metadata.  Everything else
    stays in the raw response but never reaches the cache.

    A loop or a chain longer than :data:`dns.message.MAX_CHAIN` is a hard
    error; other violations are soft rejections recorded in ``rejects``.

    Instances carry only per-application state, so a fresh policy should be
    used for each response; they are cheap to construct and this keeps policy
    application safe under concurrent resolutions.
    """

    def __init__(self) -> None:
        self.rejects: list[TrustReject] = []
        self.qname = dns.name.empty
        self.rdclass = dns.rdataclass.IN
        self.rdtype = dns.rdatatype.A
        self.trusted_names: set[dns.name.Name] = set()
        # The CNAME/DNAME RRSets that actually make up the validated chain,
        # keyed by owner name.  Only chain links and terminal answers at
        # trusted names are admitted to the cacheable view; an in-bailiwick
        # CNAME that the chain did not follow is still untrusted.
        self.chain_link_rrset_ids: set[int] = set()
        self.seen_answer_owners: set[
            tuple[dns.name.Name, dns.rdataclass.RdataClass, dns.rdatatype.RdataType]
        ] = set()

    def _reject(
        self,
        rrset: dns.rrset.RRset,
        section: int,
        name_category: NameCategory,
        reason: TrustRejectReason,
    ) -> None:
        self.rejects.append(
            TrustReject(
                section,
                name_category,
                int(rrset.rdclass),
                int(rrset.rdtype),
                reason,
            )
        )

    def _name_category(self, name: dns.name.Name) -> NameCategory:
        if name == self.qname:
            return NameCategory.QUERY_NAME
        if name in self.trusted_names:
            return NameCategory.CHAIN_NAME
        return NameCategory.UNRELATED_NAME

    def _is_known_class(self, rrset: dns.rrset.RRset) -> bool:
        return rrset.has_known_rdclass()

    def _is_known_type(self, rrset: dns.rrset.RRset) -> bool:
        return rrset.has_known_rdtype()

    def _walk_chain(self, message: dns.message.QueryMessage) -> None:
        """Validate the CNAME/DNAME chain and collect trusted names.

        :raises dns._trust.CNAMELoop: if a chain name repeats.
        :raises dns._trust.ChainTooLong: if the chain exceeds
            :data:`dns._trust.MAX_CHAIN`.
        """

        question = message.question[0]
        current = question.name
        visited: set[dns.name.Name] = set()
        count = 0
        while count < MAX_CHAIN:
            if current in visited:
                raise CNAMELoop
            visited.add(current)
            self.trusted_names.add(current)
            try:
                answer_rrset = message.find_rrset(
                    message.answer,
                    current,
                    question.rdclass,
                    question.rdtype,
                )
            except KeyError:
                answer_rrset = None
            if answer_rrset is not None:
                # Terminal answer reached.
                return
            dname_rrset = self._find_applicable_dname(message, current)
            if dname_rrset is not None:
                self.chain_link_rrset_ids.add(id(dname_rrset))
            if question.rdtype != dns.rdatatype.CNAME:
                try:
                    cname_rrset = message.find_rrset(
                        message.answer,
                        current,
                        question.rdclass,
                        dns.rdatatype.CNAME,
                    )
                except KeyError:
                    cname_rrset = None
                if cname_rrset is not None:
                    target = cname_rrset[0].target
                    if target == current or target in visited:
                        raise CNAMELoop
                    self.chain_link_rrset_ids.add(id(cname_rrset))
                    current = target
                    count += 1
                    continue
            # No answer and no CNAME at this name: the chain ends here,
            # possibly at a DNAME substitution handled by the server.
            return
        raise ChainTooLong

    def _find_applicable_dname(
        self, message: dns.message.QueryMessage, current: dns.name.Name
    ) -> dns.rrset.RRset | None:
        """Find a DNAME RRset whose owner is a superdomain of *current*.

        A DNAME redirects the whole subtree below its owner; it is applicable
        when its owner name is a proper superdomain of (or equal to) the
        chain name currently being resolved.
        """

        question = message.question[0]
        for rrset in message.answer:
            if (
                rrset.rdtype == dns.rdatatype.DNAME
                and rrset.rdclass == question.rdclass
                and current.is_subdomain(rrset.name)
            ):
                self.trusted_names.add(rrset.name)
                return rrset
        return None

    def _in_bailiwick(self, name: dns.name.Name) -> bool:
        # A stub resolver cannot know zone cuts, so bailiwick is defined
        # relative to the set of names reached through the validated chain.
        # Every trusted name is itself in bailiwick; a name is also admitted
        # when it is a superdomain of a trusted name (delegation/zone apex
        # data such as NS/SOA).  Cross-zone CNAME targets are trusted because
        # they were reached through the chain and are members of trusted_names.
        if name in self.trusted_names:
            return True
        for trusted_name in self.trusted_names:
            if trusted_name.is_subdomain(name):
                return True
        return False

    def _filter_answer(
        self, message: dns.message.QueryMessage, trusted: dns.message.QueryMessage
    ) -> None:
        for rrset in message.answer:
            section = 1
            category = self._name_category(rrset.name)
            if not self._is_known_class(rrset):
                self._reject(
                    rrset, section, category, TrustRejectReason.UNKNOWN_RDCLASS
                )
                continue
            if rrset.rdclass != self.rdclass:
                self._reject(rrset, section, category, TrustRejectReason.WRONG_RDCLASS)
                continue
            if not self._is_known_type(rrset):
                self._reject(rrset, section, category, TrustRejectReason.UNKNOWN_RDTYPE)
                continue
            owner_key = (rrset.name, rrset.rdclass, rrset.rdtype)
            if owner_key in self.seen_answer_owners:
                # A second RRset with the same owner/class/type in one
                # section is ambiguous; keep the first, refuse the rest.
                self._reject(
                    rrset, section, category, TrustRejectReason.DUPLICATE_OWNER
                )
                continue
            if rrset.rdtype in (
                dns.rdatatype.CNAME,
                dns.rdatatype.DNAME,
            ):
                # Redirection RRSets are trustworthy only when they are the
                # actual links followed while validating the chain.  An
                # unrelated or un-followed CNAME/DNAME is a poisoning attempt
                # even if its owner happens to be in bailiwick.
                if id(rrset) not in self.chain_link_rrset_ids:
                    reason = TrustRejectReason.OUT_OF_BAILIWICK
                    if rrset.rdtype == dns.rdatatype.CNAME:
                        reason = TrustRejectReason.CROSS_ZONE_TARGET
                    self._reject(rrset, section, category, reason)
                    continue
            elif not self._in_bailiwick(rrset.name):
                self._reject(
                    rrset, section, category, TrustRejectReason.OUT_OF_BAILIWICK
                )
                continue
            self.seen_answer_owners.add(owner_key)
            trusted.answer.append(rrset)

    def _filter_authority(
        self, message: dns.message.QueryMessage, trusted: dns.message.QueryMessage
    ) -> None:
        section = 2
        for rrset in message.authority:
            category = NameCategory.AUTHORITY_NAME
            if not self._is_known_class(rrset):
                self._reject(
                    rrset, section, category, TrustRejectReason.UNKNOWN_RDCLASS
                )
                continue
            if rrset.rdclass != self.rdclass:
                self._reject(rrset, section, category, TrustRejectReason.WRONG_RDCLASS)
                continue
            if not self._is_known_type(rrset):
                self._reject(rrset, section, category, TrustRejectReason.UNKNOWN_RDTYPE)
                continue
            if rrset.is_dnssec():
                # Security metadata must survive filtering so signed data
                # remains verifiable; RRSIG owners always match signed data.
                trusted.authority.append(rrset)
                continue
            if rrset.rdtype in (
                dns.rdatatype.SOA,
                dns.rdatatype.NS,
            ) and self._in_bailiwick(rrset.name):
                # Zone apex / negative-answer data for a relevant zone.
                trusted.authority.append(rrset)
                continue
            self._reject(rrset, section, category, TrustRejectReason.BAD_SECTION)

    def _filter_additional(
        self, message: dns.message.QueryMessage, trusted: dns.message.QueryMessage
    ) -> None:
        section = 3
        for rrset in message.additional:
            if rrset.is_dnssec():
                trusted.additional.append(rrset)
                continue
            self._reject(
                rrset,
                section,
                self._name_category(rrset.name),
                TrustRejectReason.BAD_SECTION,
            )

    def _build_trusted_message(
        self, message: dns.message.QueryMessage
    ) -> dns.message.QueryMessage:
        import dns.message

        trusted = dns.message.QueryMessage(id=message.id)
        trusted.flags = message.flags
        trusted.question = list(message.question)
        trusted.opt = message.opt
        trusted.tsig = message.tsig
        trusted.keyring = message.keyring
        trusted.request_mac = message.request_mac
        trusted.tsig_ctx = message.tsig_ctx
        trusted.origin = message.origin
        trusted.time = message.time
        # RRSets are appended directly rather than through find_rrset(), so
        # the freshly initialized index would not know about them.  Switch to
        # linear scans, which correctly reflect the section contents.
        trusted.index = None
        return trusted

    def apply(self, message: dns.message.QueryMessage) -> TrustResult:
        """Apply the trust policy to *message*.

        The raw message is never modified; a new cacheable message is
        returned together with the audit trail.

        :raises dns._trust.CNAMELoop: if the answer chain contains a loop.
        :raises dns._trust.ChainTooLong: if the answer chain is too long.
        :rtype: dns._trust.TrustResult
        """

        import dns.message

        if not isinstance(message, dns.message.QueryMessage):
            raise TypeError("trust policy requires a dns.message.QueryMessage")
        if len(message.question) != 1:
            raise dns.exception.FormError
        question = message.question[0]
        self.qname = question.name
        self.rdclass = question.rdclass
        self.rdtype = question.rdtype
        self.rejects = []
        self.trusted_names = set()
        self.chain_link_rrset_ids = set()
        self.seen_answer_owners = set()
        # Direct section mutation does not maintain the message index, so
        # rely on linear section scans instead.  Wire-parsed messages simply
        # lose their index for the duration of policy evaluation; neither the
        # raw response nor its sections are modified.
        saved_index = message.index
        message.index = None

        try:
            self._walk_chain(message)

            trusted = self._build_trusted_message(message)
            self._filter_answer(message, trusted)
            self._filter_authority(message, trusted)
            self._filter_additional(message, trusted)
            return TrustResult(trusted, message, self.rejects)
        finally:
            message.index = saved_index
