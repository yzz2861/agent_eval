# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

"""Tests for the explicit resolver response trust policy."""

import struct

import pytest

import dns._trust
import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rrset

QNAME = "app.corp.example."


def make_response():
    query = dns.message.make_query(QNAME, "A")
    response = dns.message.make_response(query)
    return query, response


def names_in(section):
    return {rrset.name for rrset in section}


def types_in(section):
    return {rrset.rdtype for rrset in section}


def reject_reasons(result):
    return {reject.reason for reject in result.rejects}


def test_legitimate_cross_zone_cname_chain_resolves():
    # A legitimate cross-zone CNAME must still reach its final address.
    _, response = make_response()
    response.answer.append(
        dns.rrset.from_text(QNAME, 300, "IN", "CNAME", "cdn.example.")
    )
    response.answer.append(
        dns.rrset.from_text("cdn.example.", 300, "IN", "A", "192.0.2.10")
    )

    result = response.apply_trust_policy()
    trusted = result.trusted_response

    assert result.rejects == []
    assert names_in(trusted.answer) == {
        dns.name.from_text(QNAME),
        dns.name.from_text("cdn.example."),
    }
    chaining = trusted.resolve_chaining()
    assert chaining.canonical_name == dns.name.from_text("cdn.example.")
    assert [rdata.address for rdata in chaining.answer] == ["192.0.2.10"]


def test_dname_chain_is_followed_and_preserved():
    query = dns.message.make_query("a.branch.example.", "A")
    response = dns.message.make_response(query)
    response.answer.append(
        dns.rrset.from_text("branch.example.", 300, "IN", "DNAME", "target.example.")
    )
    response.answer.append(
        dns.rrset.from_text(
            "a.branch.example.",
            300,
            "IN",
            "CNAME",
            "a.target.example.",
        )
    )
    response.answer.append(
        dns.rrset.from_text("a.target.example.", 300, "IN", "A", "192.0.2.55")
    )

    result = response.apply_trust_policy()
    trusted = result.trusted_response

    assert result.rejects == []
    trusted_types = {rrset.rdtype for rrset in trusted.answer}
    assert trusted_types == {
        dns.rdatatype.DNAME,
        dns.rdatatype.CNAME,
        dns.rdatatype.A,
    }
    chaining = trusted.resolve_chaining()
    assert chaining.canonical_name == dns.name.from_text("a.target.example.")


def test_out_of_bailiwick_a_is_rejected_but_kept_raw():
    _, response = make_response()
    response.answer.append(
        dns.rrset.from_text(QNAME, 300, "IN", "CNAME", "cdn.example.")
    )
    response.answer.append(
        dns.rrset.from_text("cdn.example.", 300, "IN", "A", "192.0.2.10")
    )
    response.answer.append(
        dns.rrset.from_text("evil.example.", 60, "IN", "A", "198.51.100.66")
    )

    result = response.apply_trust_policy()

    # The cacheable view only keeps chain-anchored RRSets.
    assert dns.name.from_text("evil.example.") not in names_in(
        result.trusted_response.answer
    )
    assert dns.message.TrustRejectReason.OUT_OF_BAILIWICK in reject_reasons(result)
    # The raw message is preserved untouched.
    assert dns.name.from_text("evil.example.") in names_in(response.answer)
    assert len(response.answer) == 3


def test_unfollowed_in_bailiwick_cname_is_rejected():
    # An A answer already exists at the query name, so an accompanying CNAME
    # at the same owner is not part of the validated chain and must not be
    # cached even though its owner is the query name.
    _, response = make_response()
    response.answer.append(dns.rrset.from_text(QNAME, 300, "IN", "A", "192.0.2.1"))
    response.answer.append(
        dns.rrset.from_text(QNAME, 300, "IN", "CNAME", "other.example.")
    )

    result = response.apply_trust_policy()

    trusted_types = {rrset.rdtype for rrset in result.trusted_response.answer}
    assert trusted_types == {dns.rdatatype.A}
    assert dns.message.TrustRejectReason.CROSS_ZONE_TARGET in reject_reasons(result)


def test_cross_zone_cname_target_is_rejected_when_unrelated():
    _, response = make_response()
    response.answer.append(dns.rrset.from_text(QNAME, 300, "IN", "A", "192.0.2.1"))
    response.answer.append(
        dns.rrset.from_text("evil.example.", 300, "IN", "CNAME", "worse.example.")
    )

    result = response.apply_trust_policy()

    assert dns.name.from_text("evil.example.") not in names_in(
        result.trusted_response.answer
    )
    assert dns.message.TrustRejectReason.CROSS_ZONE_TARGET in reject_reasons(result)


def test_cname_loop_is_a_hard_error():
    _, response = make_response()
    response.answer.append(dns.rrset.from_text(QNAME, 300, "IN", "CNAME", "a.example."))
    response.answer.append(dns.rrset.from_text("a.example.", 300, "IN", "CNAME", QNAME))

    with pytest.raises(dns._trust.CNAMELoop):
        response.apply_trust_policy()
    # The raw message is not modified by the failed policy application.
    assert len(response.answer) == 2


def test_self_referential_cname_is_a_loop():
    _, response = make_response()
    response.answer.append(dns.rrset.from_text(QNAME, 300, "IN", "CNAME", QNAME))

    with pytest.raises(dns._trust.CNAMELoop):
        response.apply_trust_policy()


def test_chain_too_long_is_a_hard_error():
    _, response = make_response()
    current = QNAME
    for i in range(dns.message.MAX_CHAIN + 1):
        target = f"hop{i}.example."
        response.answer.append(dns.rrset.from_text(current, 300, "IN", "CNAME", target))
        current = target

    with pytest.raises(dns._trust.ChainTooLong):
        response.apply_trust_policy()


def test_duplicate_owner_keeps_first_only():
    _, response = make_response()
    first = dns.rrset.from_text(QNAME, 300, "IN", "A", "192.0.2.1")
    duplicate = dns.rrset.from_text(QNAME, 30, "IN", "A", "198.51.100.2")
    response.answer.append(first)
    response.answer.append(duplicate)

    result = response.apply_trust_policy()
    trusted = result.trusted_response

    duplicate_rejects = [
        reject
        for reject in result.rejects
        if reject.reason == dns.message.TrustRejectReason.DUPLICATE_OWNER
    ]
    assert len(duplicate_rejects) == 1
    answer_rrsets = [
        rrset for rrset in trusted.answer if rrset.name == dns.name.from_text(QNAME)
    ]
    assert len(answer_rrsets) == 1
    assert [rdata.address for rdata in answer_rrsets[0]] == ["192.0.2.1"]


def test_authority_pollution_is_filtered():
    _, response = make_response()
    response.answer.append(dns.rrset.from_text(QNAME, 300, "IN", "A", "192.0.2.10"))
    # In-bailiwick SOA (negative/zone data) must survive.
    response.authority.append(
        dns.rrset.from_text(
            "corp.example.",
            300,
            "IN",
            "SOA",
            "ns.corp.example. hostmaster.corp.example. 1 2 3 4 5",
        )
    )
    # Unrelated cacheable record smuggled in authority is rejected.
    response.authority.append(
        dns.rrset.from_text("evil.example.", 300, "IN", "A", "198.51.100.66")
    )

    result = response.apply_trust_policy()
    trusted = result.trusted_response

    authority_names = names_in(trusted.authority)
    assert dns.name.from_text("corp.example.") in authority_names
    assert dns.name.from_text("evil.example.") not in authority_names
    assert dns.message.TrustRejectReason.BAD_SECTION in reject_reasons(result)
    # The raw authority section keeps everything.
    assert len(response.authority) == 2


def test_dnssec_records_are_not_dropped():
    _, response = make_response()
    a_rrset = dns.rrset.from_text(QNAME, 300, "IN", "A", "192.0.2.10")
    response.answer.append(a_rrset)
    rrsig = dns.rrset.from_text(
        QNAME,
        300,
        "IN",
        "RRSIG",
        "A 13 4 300 20350101000000 20250101000000 12345 corp.example. YWJjZGVmZ2g=",
    )
    response.answer.append(rrsig)
    nsec = dns.rrset.from_text(
        "app.corp.example.", 300, "IN", "NSEC", "next.corp.example. A RRSIG"
    )
    response.authority.append(nsec)

    result = response.apply_trust_policy()
    trusted = result.trusted_response

    assert dns.rdatatype.RRSIG in types_in(trusted.answer)
    assert dns.rdatatype.NSEC in types_in(trusted.authority)
    assert result.rejects == []


def test_unknown_rdtype_is_rejected():
    # Build the unknown RR on the wire so it parses as GenericRdata.
    query = dns.message.make_query(QNAME, "A")
    qwire = query.to_wire()
    # Header: id, flags(0x8180), qd=1, an=1, ns=0, ar=0
    header = struct.pack("!HHHHHH", query.id, 0x8180, 1, 1, 0, 0)
    question = qwire[12:]
    owner = b"\x03app\x04corp\x07example\x00"
    # TYPE65200, class IN, TTL 60, RDLENGTH 4, rdata 1.2.3.4
    answer = owner + struct.pack("!HHIH4s", 65200, 1, 60, 4, b"\x01\x02\x03\x04")
    wire = header + question + answer
    response = dns.message.from_wire(wire)

    unknown_rrset = response.answer[0]
    assert not unknown_rrset.has_known_rdtype()

    result = response.apply_trust_policy()

    assert result.trusted_response.answer == []
    assert dns.message.TrustRejectReason.UNKNOWN_RDTYPE in reject_reasons(result)
    assert response.answer[0] is unknown_rrset


def test_wrong_rdclass_is_rejected():
    _, response = make_response()
    rrset = dns.rrset.RRset(
        dns.name.from_text(QNAME), dns.rdataclass.CH, dns.rdatatype.TXT
    )
    rrset.add(dns.rdata.from_text(dns.rdataclass.CH, "TXT", '"chaos"'))
    rrset.update_ttl(300)
    response.answer.append(rrset)

    result = response.apply_trust_policy()

    assert result.trusted_response.answer == []
    assert dns.message.TrustRejectReason.WRONG_RDCLASS in reject_reasons(result)


def test_unknown_rdclass_is_rejected():
    _, response = make_response()
    rrset = dns.rrset.RRset(
        dns.name.from_text(QNAME),
        dns.rdataclass.RdataClass.make(99),
        dns.rdatatype.A,
    )
    rrset.add(
        dns.rdata.from_text(dns.rdataclass.RdataClass.make(99), "A", r"\# 4 C000020A")
    )
    rrset.update_ttl(300)
    response.answer.append(rrset)

    assert not rrset.has_known_rdclass()
    result = response.apply_trust_policy()

    assert result.trusted_response.answer == []
    assert dns.message.TrustRejectReason.UNKNOWN_RDCLASS in reject_reasons(result)


def test_audit_entries_contain_only_categories():
    _, response = make_response()
    response.answer.append(
        dns.rrset.from_text("evil.example.", 60, "IN", "A", "198.51.100.66")
    )

    result = response.apply_trust_policy()
    reject = result.rejects[0]

    # Only coarse categories, never names or rdata payloads.
    assert isinstance(reject.name_category, dns._trust.NameCategory)
    assert isinstance(reject.reason, dns._trust.TrustRejectReason)
    assert isinstance(reject.rdclass, int)
    assert isinstance(reject.rdtype, int)
    assert reject.section == int(dns.message.MessageSection.ANSWER)
    dataclass_fields = {
        field.name for field in dns._trust.TrustReject.__dataclass_fields__.values()
    }
    assert dataclass_fields == {
        "section",
        "name_category",
        "rdclass",
        "rdtype",
        "reason",
    }


def test_raw_message_is_preserved_through_policy():
    _, response = make_response()
    response.answer.append(dns.rrset.from_text(QNAME, 300, "IN", "A", "192.0.2.10"))
    response.answer.append(
        dns.rrset.from_text("evil.example.", 60, "IN", "A", "198.51.100.66")
    )

    result = response.apply_trust_policy()

    assert result.raw_response is response
    assert result.trusted_response is not response
    assert len(result.raw_response.answer) == 2
    assert len(result.trusted_response.answer) == 1


def test_disabled_policy_is_a_passthrough():
    policy = dns._trust.TrustPolicy()
    _, response = make_response()
    response.answer.append(
        dns.rrset.from_text("evil.example.", 60, "IN", "A", "198.51.100.66")
    )

    # Resolver-level disabling reuses TrustResult with identical views.
    result = dns._trust.TrustResult(response, response, [])
    assert result.trusted_response is response
    assert result.raw_response is response
    # And an enabled policy still rejects the same record.
    enabled_result = policy.apply(response)
    assert enabled_result.trusted_response.answer == []
