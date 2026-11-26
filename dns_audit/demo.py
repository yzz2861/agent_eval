"""In-memory review scenario used by the CLI and smoke tests."""
from __future__ import annotations

from typing import List, Optional, Sequence

import dpkt.dns

from .audit import Audit
from .model import CaptureResult, DnsMessage, PacketRef, Question, ResourceRecord


A = dpkt.dns.DNS_A
AAAA = dpkt.dns.DNS_AAAA
CNAME = dpkt.dns.DNS_CNAME


def rr(name: str, value: str, *, rtype: Optional[int] = None, ttl: int = 120) -> ResourceRecord:
    if rtype is None:
        rtype = AAAA if ":" in value else A
    return ResourceRecord(name=name, rtype=rtype, rclass=dpkt.dns.DNS_IN, ttl=ttl, value=value)


def cname(name: str, target: str, ttl: int = 300) -> ResourceRecord:
    return ResourceRecord(name=name, rtype=CNAME, rclass=dpkt.dns.DNS_IN, ttl=ttl, value=target)


def _ref(site: str, frame_index: int, timestamp: float) -> PacketRef:
    return PacketRef(
        site=site,
        source="memory://%s/review-example" % site,
        frame_index=frame_index,
        timestamp=timestamp,
    )


def _message(
    site: str,
    frame_index: int,
    timestamp: float,
    txid: int,
    *,
    response: bool,
    qname: str,
    answers: Sequence[ResourceRecord] = (),
    client_port: int = 40000,
    client_ip: str = "10.0.0.10",
    resolver_ip: str = "198.51.100.53",
    truncated: bool = False,
) -> DnsMessage:
    question = Question(name=qname, qtype=A, qclass=dpkt.dns.DNS_IN)
    if response:
        src_ip, dst_ip = resolver_ip, client_ip
        src_port, dst_port = 53, client_port
    else:
        src_ip, dst_ip = client_ip, resolver_ip
        src_port, dst_port = client_port, 53
    return DnsMessage(
        ref=_ref(site, frame_index, timestamp),
        txid=txid,
        is_response=response,
        rcode=dpkt.dns.DNS_RCODE_NOERR if response else None,
        questions=(question,),
        qr_names=(qname,),
        answers=tuple(answers),
        truncated=truncated,
        transport="udp",
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
    )


def _qa(
    messages: List[DnsMessage],
    site: str,
    txid: int,
    qname: str,
    answers: Sequence[ResourceRecord],
    *,
    base: float,
    client_port: int,
) -> None:
    frame = len([m for m in messages if m.site == site])
    messages.append(_message(site, frame, base, txid, response=False, qname=qname,
                             client_port=client_port))
    messages.append(_message(site, frame + 1, base + 0.04, txid, response=True, qname=qname,
                             answers=answers, client_port=client_port))


def build_demo_audit() -> Audit:
    """Return the fixed two-collector example and assert its safety properties."""
    messages: List[DnsMessage] = []

    # Deliberate cross-domain txid reuse: 0x4242 is a normal Q/A in each domain,
    # but the edge-b query is not the source of edge-a's response.
    _qa(
        messages, "edge-a", 0x4242, "svc-a.example",
        [rr("svc-a.example", "192.0.2.10"), rr("svc-a.example", "192.0.2.11")],
        base=100.0, client_port=41001,
    )
    _qa(
        messages, "edge-b", 0x4242, "unrelated-b.example",
        [rr("unrelated-b.example", "203.0.113.7")],
        base=100.5, client_port=42002,
    )

    # A second name in edge-a independently yields the same address set.
    _qa(
        messages, "edge-a", 0x5555, "svc-b.example",
        [rr("svc-b.example", "192.0.2.11"), rr("svc-b.example", "192.0.2.10")],
        base=101.0, client_port=41003,
    )

    # Complete CNAME closure for both names.
    _qa(
        messages, "edge-a", 0x6666, "web-a.example",
        [cname("web-a.example", "shared.example"), rr("shared.example", "198.51.100.7")],
        base=102.0, client_port=41004,
    )
    _qa(
        messages, "edge-a", 0x6667, "web-b.example",
        [cname("web-b.example", "shared.example"), rr("shared.example", "198.51.100.7")],
        base=102.5, client_port=41005,
    )

    # Chain is saved through CNAME, but the terminal address record is absent.
    _qa(
        messages, "edge-b", 0x8888, "alias-missing.example",
        [cname("alias-missing.example", "cdn-missing.example")],
        base=103.0, client_port=42006,
    )

    # Same-domain duplicate candidates with indistinguishable five-tuples.
    duplicate_question = "dup.example"
    duplicate_txid = 0x9999
    frame_b = len([m for m in messages if m.site == "edge-a"])
    messages.append(_message("edge-a", frame_b, 104.0, duplicate_txid,
                             response=False, qname=duplicate_question, client_port=41007))
    messages.append(_message("edge-a", frame_b + 1, 104.1, duplicate_txid,
                             response=False, qname=duplicate_question, client_port=41007))
    messages.append(_message("edge-a", frame_b + 2, 104.2, duplicate_txid,
                             response=True, qname=duplicate_question,
                             answers=[rr("dup.example", "198.18.0.9")], client_port=41007))

    captures = []
    for site in sorted({message.site for message in messages}):
        captures.append(
            CaptureResult(
                source='memory-example',
                site=site,
                file_format='in-memory',
                messages=[message for message in messages if message.site == site],
            )
        )
    audit = Audit.from_messages(messages, captures)
    _assert_demo_invariants(audit)
    return audit


def _assert_demo_invariants(audit: Audit) -> None:
    reused = [
        item for item in audit.exchanges
        if item.txid == 0x4242 and item.status == "unique"
    ]
    assert {(item.site, item.query.qname) for item in reused} == {
        ("edge-a", "svc-a.example"),
        ("edge-b", "unrelated-b.example"),
    }
    collision = next(item for item in audit.matching.cross_site_txid_collisions
                     if item["txid"] == 0x4242)
    assert collision["sites"] == ["edge-a", "edge-b"]

    ambiguous = [item for item in audit.exchanges if item.txid == 0x9999]
    assert len(ambiguous) == 1
    assert ambiguous[0].status == "ambiguous"
    assert len(ambiguous[0].candidates) == 2

    trace = next(item for item in audit.alias_traces
                 if item.start_name == "alias-missing.example")
    assert trace.complete is False
    assert trace.incomplete_reasons

    comparisons = {
        tuple(sorted((item.name_a, item.name_b))): item
        for item in audit.comparisons
    }
    same_direct = comparisons[("svc-a.example", "svc-b.example")]
    assert same_direct.equal is True
    assert same_direct.status == "equal_observed"

    same_alias = comparisons[("web-a.example", "web-b.example")]
    assert same_alias.addresses_a == {"198.51.100.7"}
    assert same_alias.addresses_b == {"198.51.100.7"}
    assert same_alias.equal is True

    assert all(item.site in {"edge-a", "edge-b"} for item in audit.comparisons)


def main() -> int:
    audit = build_demo_audit()
    print(audit.to_dict())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
