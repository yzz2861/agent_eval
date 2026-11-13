# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

"""Resolver integration tests for the response trust policy and caching.

These tests use an in-process fake nameserver so they need no network access.
Acceptance is expressed in terms of which RRSets end up in the cache.
"""

import asyncio

import pytest

import dns._trust
import dns.asyncresolver
import dns.message
import dns.name
import dns.nameserver
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.rrset

QNAME = dns.name.from_text("app.corp.example.")


class FakeNameserver(dns.nameserver.Nameserver):
    """A nameserver that returns a fixed response without doing I/O."""

    def __init__(self, response):
        super().__init__()
        self.response = response

    def __str__(self):
        return "Do53:fake@53"

    def kind(self):
        return "Do53"

    def is_always_max_size(self):
        return False

    def answer_nameserver(self):
        return "fake"

    def answer_port(self):
        return 53

    def query(
        self,
        request,
        timeout,
        source,
        source_port,
        max_size,
        one_rr_per_rrset=False,
        ignore_trailing=False,
    ):
        return self.response

    async def async_query(
        self,
        request,
        timeout,
        source,
        source_port,
        max_size,
        backend,
        one_rr_per_rrset=False,
        ignore_trailing=False,
    ):
        return self.response


def make_resolver(response):
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [FakeNameserver(response)]
    resolver.cache = dns.resolver.Cache()
    return resolver


def make_response():
    query = dns.message.make_query(QNAME, "A")
    response = dns.message.make_response(query)
    response.set_rcode(dns.rcode.NOERROR)
    response.flags |= dns.flags.RA
    return response


def cached_answer(resolver):
    return resolver.cache.get((QNAME, dns.rdatatype.A, dns.rdataclass.IN))


def test_legitimate_cname_is_cached_and_resolves():
    response = make_response()
    response.answer.append(
        dns.rrset.from_text(QNAME, 300, "IN", "CNAME", "cdn.example.")
    )
    response.answer.append(
        dns.rrset.from_text("cdn.example.", 300, "IN", "A", "192.0.2.10")
    )
    resolver = make_resolver(response)

    answer = resolver.resolve(QNAME, "A")

    assert answer.canonical_name == dns.name.from_text("cdn.example.")
    assert [rdata.address for rdata in answer] == ["192.0.2.10"]
    cached = cached_answer(resolver)
    assert cached is not None
    cached_names = {rrset.name for rrset in cached.trusted_response.answer}
    assert cached_names == {
        QNAME,
        dns.name.from_text("cdn.example."),
    }


def test_out_of_bailiwick_a_never_enters_cache():
    response = make_response()
    response.answer.append(
        dns.rrset.from_text(QNAME, 300, "IN", "CNAME", "cdn.example.")
    )
    response.answer.append(
        dns.rrset.from_text("cdn.example.", 300, "IN", "A", "192.0.2.10")
    )
    response.answer.append(
        dns.rrset.from_text("evil.example.", 60, "IN", "A", "198.51.100.66")
    )
    resolver = make_resolver(response)

    answer = resolver.resolve(QNAME, "A")

    # Resolution still succeeds using the legitimate chain.
    assert [rdata.address for rdata in answer] == ["192.0.2.10"]
    cached = cached_answer(resolver)
    cached_names = {rrset.name for rrset in cached.trusted_response.answer}
    assert dns.name.from_text("evil.example.") not in cached_names
    # The raw response handed to callers still contains the full message.
    raw_names = {rrset.name for rrset in answer.response.answer}
    assert dns.name.from_text("evil.example.") in raw_names
    # And the audit trail explains the refusal.
    assert dns._trust.TrustRejectReason.OUT_OF_BAILIWICK in {
        reject.reason for reject in answer.trust_rejects
    }


def test_cname_loop_marks_nameserver_bad_and_raises_no_nameservers():
    response = make_response()
    response.answer.append(dns.rrset.from_text(QNAME, 300, "IN", "CNAME", "a.example."))
    response.answer.append(
        dns.rrset.from_text("a.example.", 300, "IN", "CNAME", "app.corp.example.")
    )
    resolver = make_resolver(response)

    with pytest.raises(dns.resolver.NoNameservers):
        resolver.resolve(QNAME, "A")

    # A poisoned loop response must never be cached.
    assert cached_answer(resolver) is None


def test_max_chain_length_is_enforced_and_not_cached():
    response = make_response()
    current = QNAME
    for i in range(dns.message.MAX_CHAIN + 1):
        target = f"hop{i}.example."
        response.answer.append(dns.rrset.from_text(current, 300, "IN", "CNAME", target))
        current = dns.name.from_text(target)
    resolver = make_resolver(response)

    with pytest.raises(dns.resolver.NoNameservers):
        resolver.resolve(QNAME, "A")
    assert cached_answer(resolver) is None


def test_duplicate_owner_first_rrset_is_cached():
    response = make_response()
    response.answer.append(dns.rrset.from_text(QNAME, 300, "IN", "A", "192.0.2.1"))
    response.answer.append(dns.rrset.from_text(QNAME, 30, "IN", "A", "198.51.100.2"))
    resolver = make_resolver(response)

    answer = resolver.resolve(QNAME, "A")

    assert [rdata.address for rdata in answer] == ["192.0.2.1"]
    cached = cached_answer(resolver)
    cached_owner_rrsets = [
        rrset for rrset in cached.trusted_response.answer if rrset.name == QNAME
    ]
    assert len(cached_owner_rrsets) == 1
    assert [rdata.address for rdata in cached_owner_rrsets[0]] == ["192.0.2.1"]


def test_authority_pollution_is_not_cached():
    response = make_response()
    response.answer.append(dns.rrset.from_text(QNAME, 300, "IN", "A", "192.0.2.10"))
    response.authority.append(
        dns.rrset.from_text(
            "corp.example.",
            300,
            "IN",
            "SOA",
            "ns.corp.example. hostmaster.corp.example. 1 2 3 4 5",
        )
    )
    response.authority.append(
        dns.rrset.from_text("evil.example.", 300, "IN", "A", "198.51.100.66")
    )
    resolver = make_resolver(response)

    answer = resolver.resolve(QNAME, "A")

    cached = cached_answer(resolver)
    authority_names = {rrset.name for rrset in cached.trusted_response.authority}
    assert dns.name.from_text("corp.example.") in authority_names
    assert dns.name.from_text("evil.example.") not in authority_names
    # The original message retains the polluting record for inspection.
    raw_authority = {rrset.name for rrset in answer.response.authority}
    assert dns.name.from_text("evil.example.") in raw_authority


def test_dnssec_records_survive_into_cache():
    response = make_response()
    response.answer.append(dns.rrset.from_text(QNAME, 300, "IN", "A", "192.0.2.10"))
    response.answer.append(
        dns.rrset.from_text(
            QNAME,
            300,
            "IN",
            "RRSIG",
            "A 13 4 300 20350101000000 20250101000000 12345 corp.example. YWJjZGVmZ2g=",
        )
    )
    resolver = make_resolver(response)

    resolver.resolve(QNAME, "A")

    cached = cached_answer(resolver)
    cached_types = {rrset.rdtype for rrset in cached.trusted_response.answer}
    assert dns.rdatatype.RRSIG in cached_types


def test_raw_response_is_available_on_answer_and_cache_hit():
    response = make_response()
    response.answer.append(dns.rrset.from_text(QNAME, 300, "IN", "A", "192.0.2.10"))
    response.answer.append(
        dns.rrset.from_text("evil.example.", 60, "IN", "A", "198.51.100.66")
    )
    resolver = make_resolver(response)

    first = resolver.resolve(QNAME, "A")
    second = resolver.resolve(QNAME, "A")

    # Second call is served from the cache.
    assert second is first
    assert len(second.response.answer) == 2
    assert len(second.trusted_response.answer) == 1


def test_disabling_trust_policy_keeps_everything():
    response = make_response()
    response.answer.append(
        dns.rrset.from_text("evil.example.", 60, "IN", "A", "198.51.100.66")
    )
    resolver = make_resolver(response)
    resolver.trust_policy = False

    answer = resolver.resolve(QNAME, "A", raise_on_no_answer=False)

    assert answer.trust_rejects == []
    assert answer.trusted_response is answer.response
    cached = cached_answer(resolver)
    assert dns.name.from_text("evil.example.") in {
        rrset.name for rrset in cached.trusted_response.answer
    }


def test_async_resolver_uses_same_trust_policy():
    # The async backend must not re-implement validation: it goes through the
    # same shared _Resolution trust path as the synchronous resolver.
    response = make_response()
    response.answer.append(
        dns.rrset.from_text(QNAME, 300, "IN", "CNAME", "cdn.example.")
    )
    response.answer.append(
        dns.rrset.from_text("cdn.example.", 300, "IN", "A", "192.0.2.10")
    )
    response.answer.append(
        dns.rrset.from_text("evil.example.", 60, "IN", "A", "198.51.100.66")
    )

    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = [FakeNameserver(response)]
    resolver.cache = dns.resolver.Cache()

    async def run():
        return await resolver.resolve(QNAME, "A")

    answer = asyncio.run(run())

    assert [rdata.address for rdata in answer] == ["192.0.2.10"]
    cached = resolver.cache.get((QNAME, dns.rdatatype.A, dns.rdataclass.IN))
    cached_names = {rrset.name for rrset in cached.trusted_response.answer}
    assert dns.name.from_text("evil.example.") not in cached_names
    assert dns._trust.TrustRejectReason.OUT_OF_BAILIWICK in {
        reject.reason for reject in answer.trust_rejects
    }
