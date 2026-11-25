"""主张提取、离线别名观察与同址核对测试。"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))

from pcap_builder import (  # noqa: E402
    a_rr,
    aaaa_rr,
    cname_rr,
    dns_question,
    dns_query,
    dns_response,
    exchange_packets,
    write_pcap,
)

from dns_audit.audit import Audit  # noqa: E402
from dns_audit.model import (  # noqa: E402
    CLAIM_ADDRESS,
    CLAIM_ALIAS,
    CLAIM_NEGATIVE,
    MATCH_ORPHAN,
)


def _audit(tmp_path, site_packets):
    sources = []
    for site, packets in site_packets.items():
        path = str(tmp_path / ('%s.pcap' % site))
        write_pcap(path, packets)
        sources.append((path, site))
    return Audit.from_sources(sources)


def test_address_and_alias_claims_with_scopes(tmp_path):
    packets = exchange_packets(
        0x0010,
        'www.example.',
        [
            cname_rr('www.example.', 'cdn.example.', ttl=600),
            a_rr('cdn.example.', '203.0.113.7', ttl=30),
        ],
        t0=1000.0,
    )
    audit = _audit(tmp_path, {'edge_a': packets})

    kinds = {(claim.kind, claim.name, claim.value) for claim in audit.claims}
    assert (CLAIM_ALIAS, 'www.example', 'cdn.example') in kinds
    assert (CLAIM_ADDRESS, 'cdn.example', '203.0.113.7') in kinds

    address_claim = next(
        claim for claim in audit.claims
        if claim.kind == CLAIM_ADDRESS and claim.name == 'cdn.example'
    )
    # 有效范围：观察窗来自问答时间，TTL 外推取回答内最小 TTL
    assert address_claim.scope.observed_first == pytest.approx(1000.0)
    assert address_claim.scope.observed_last == pytest.approx(1000.05)
    assert address_claim.scope.ttl_until == pytest.approx(1000.05 + 30)
    # 证据指针能回到具体帧
    assert address_claim.query_ref.frame_index == 0
    assert address_claim.response_ref.frame_index == 1
    assert address_claim.site == 'edge_a'


def test_alias_trace_complete_chain(tmp_path):
    packets = exchange_packets(
        0x0011,
        'shop.example.',
        [
            cname_rr('shop.example.', 'shop.cdn.example.'),
            cname_rr('shop.cdn.example.', 'edge.cdn.example.'),
            a_rr('edge.cdn.example.', '198.51.100.9'),
        ],
    )
    audit = _audit(tmp_path, {'edge_a': packets})
    assert len(audit.alias_traces) == 1
    trace = audit.alias_traces[0]
    assert trace.start_name == 'shop.example'
    assert [hop.target_name for hop in trace.hops] == [
        'shop.cdn.example',
        'edge.cdn.example',
    ]
    assert trace.complete is True
    assert trace.terminal_addresses == ['198.51.100.9']


def test_incomplete_alias_chain_is_reviewable(tmp_path):
    # 只看到 CNAME，终点地址不在该采集点的窗口内：链未看全但证据保留
    packets = exchange_packets(
        0x0012,
        'app.example.',
        [cname_rr('app.example.', 'elsewhere.example.')],
    )
    audit = _audit(tmp_path, {'edge_a': packets})
    trace = audit.alias_traces[0]
    assert trace.complete is False
    assert trace.terminal_name == 'elsewhere.example'
    assert trace.terminal_addresses == []
    assert trace.incomplete_reasons, '未看全的链必须给出可复查原因'
    # 别名主张本身仍然成立
    assert any(
        claim.kind == CLAIM_ALIAS and claim.name == 'app.example'
        for claim in audit.claims
    )


def test_same_address_set_only_within_site_and_window(tmp_path):
    site_a = (
        exchange_packets(
            0x0020, 'name1.example.', [a_rr('name1.example.', '5.5.5.5')],
            t0=10.0, client_port=40010,
        )
        + exchange_packets(
            0x0021, 'name2.example.',
            [a_rr('name2.example.', '5.5.5.5'), a_rr('name2.example.', '6.6.6.6')],
            t0=20.0, client_port=40011,
        )
    )
    site_b = exchange_packets(
        0x0022, 'name1.example.', [a_rr('name1.example.', '7.7.7.7')],
        t0=30.0, client_port=40012,
    )
    audit = _audit(tmp_path, {'edge_a': site_a, 'edge_b': site_b})

    # 同采集点内：集合不同 -> 不能声称两个名字一直同址
    comp_a = next(
        item for item in audit.comparisons
        if item.site == 'edge_a' and item.name_a == 'name1.example'
    )
    assert comp_a.equal is False
    assert comp_a.addresses_a == {'5.5.5.5'}
    assert comp_a.addresses_b == {'5.5.5.5', '6.6.6.6'}

    # 跨采集点绝不产生比较项；edge_b 的 7.7.7.7 不会污染 edge_a 的结论
    assert all(item.site != 'edge_b' or item.name_a != item.name_b
               for item in audit.comparisons)
    # 只有一对名称时，edge_b 内部没有两两比较
    assert {item.site for item in audit.comparisons} == {'edge_a'}


def test_equal_address_set_reported_with_window_limit(tmp_path):
    packets = (
        exchange_packets(
            0x0030, 'x.example.', [a_rr('x.example.', '9.9.9.9')],
            t0=10.0, client_port=40020,
        )
        + exchange_packets(
            0x0031, 'y.example.', [a_rr('y.example.', '9.9.9.9')],
            t0=11.0, client_port=40021,
        )
    )
    audit = _audit(tmp_path, {'edge_a': packets})
    comparison = audit.comparisons[0]
    assert comparison.equal is True
    assert '观察窗' in comparison.note


def test_negative_answer_becomes_negative_claim(tmp_path):
    question = dns_question('nope.example.')
    packets = [
        (100.0, dns_query(0x0040, [question]), True, 40030, 53),
        (100.05, dns_response(0x0040, [question], rcode=3), False, 53, 40030),
    ]
    audit = _audit(tmp_path, {'edge_a': packets})
    assert len(audit.claims) == 1
    claim = audit.claims[0]
    assert claim.kind == CLAIM_NEGATIVE
    assert claim.rcode == 3
    assert claim.name == 'nope.example'
    assert claim.value is None


def test_nodata_noerror_is_negative_claim(tmp_path):
    question = dns_question('empty.example.')
    packets = [
        (100.0, dns_query(0x0041, [question]), True, 40031, 53),
        (100.05, dns_response(0x0041, [question], answers=[]), False, 53, 40031),
    ]
    audit = _audit(tmp_path, {'edge_a': packets})
    assert len(audit.claims) == 1
    assert audit.claims[0].kind == CLAIM_NEGATIVE


def test_aaaa_address_claim(tmp_path):
    packets = exchange_packets(
        0x0050,
        'v6.example.',
        [aaaa_rr('v6.example.', '2001:db8::42')],
        qtype=28,
    )
    audit = _audit(tmp_path, {'edge_a': packets})
    claim = audit.claims[0]
    assert claim.kind == CLAIM_ADDRESS
    assert claim.value == '2001:db8::42'
    assert claim.qtype == 28


def test_orphan_response_generates_no_claims(tmp_path):
    question = dns_question('lonely.example.')
    packets = [
        (100.2, dns_response(
            0x0060, [question], [a_rr('lonely.example.', '4.4.4.4')]),
         False, 53, 40040),
    ]
    audit = _audit(tmp_path, {'edge_a': packets})
    assert audit.exchanges[0].status == MATCH_ORPHAN
    assert audit.claims == []


def test_to_dict_is_serializable_and_keeps_provenance(tmp_path):
    packets = exchange_packets(
        0x0070, 'z.example.', [a_rr('z.example.', '1.2.3.4')],
    )
    audit = _audit(tmp_path, {'edge_a': packets})
    import json

    payload = json.dumps(audit.to_dict(), ensure_ascii=False)
    decoded = json.loads(payload)
    assert decoded['captures'][0]['site'] == 'edge_a'
    claim = decoded['claims'][0]
    assert claim['query_ref']['site'] == 'edge_a'
    assert claim['response_ref']['frame_index'] == 1
    assert 'scope' in claim and 'ttl_until' in claim['scope']


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
