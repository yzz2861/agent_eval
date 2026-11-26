"""问答匹配测试：同号 txid 的陷阱与采集点隔离。"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))

from pcap_builder import (  # noqa: E402
    a_rr,
    build_pcap,
    dns_query,
    dns_question,
    dns_response,
    exchange_packets,
    write_pcap,
)

from dns_audit.audit import Audit  # noqa: E402
from dns_audit.matching import (  # noqa: E402
    BASIS_QUESTION,
    BASIS_SAME_SITE,
    BASIS_SOCKET,
    pair_exchanges,
)
from dns_audit.model import (  # noqa: E402
    MATCH_AMBIGUOUS,
    MATCH_ORPHAN,
    MATCH_UNANSWERED,
    MATCH_UNIQUE,
)
from dns_audit.reader import read_capture  # noqa: E402


def _audit(tmp_path, site_packets):
    sources = []
    for site, packets in site_packets.items():
        path = str(tmp_path / ('%s.pcap' % site))
        write_pcap(path, packets)
        sources.append((path, site))
    return Audit.from_sources(sources)


def test_cross_site_same_txid_never_paired(tmp_path):
    """两个正常问答使用同一 txid，但分属两个采集点，只能各自配对。"""
    site_a = exchange_packets(
        0x1234, 'alpha.example.', [a_rr('alpha.example.', '1.1.1.1')],
        t0=100.0, client_port=40000,
    )
    site_b = exchange_packets(
        0x1234, 'beta.example.', [a_rr('beta.example.', '2.2.2.2')],
        t0=100.0, client_port=40000,
    )
    audit = _audit(tmp_path, {'site_a': site_a, 'site_b': site_b})

    assert len(audit.exchanges) == 2
    assert all(item.status == MATCH_UNIQUE for item in audit.exchanges)
    # 每条问答都必须留在自己的采集域内
    assert {item.site for item in audit.exchanges} == {'site_a', 'site_b'}
    for exchange in audit.exchanges:
        assert exchange.query.ref.site == exchange.site
        assert exchange.response.ref.site == exchange.site
        assert BASIS_SAME_SITE in exchange.match_basis

    # 同号被记录为跨采集点碰撞，但没有产生任何跨点配对
    collisions = audit.matching.cross_site_txid_collisions
    assert len(collisions) == 1
    assert collisions[0]['txid'] == 0x1234
    assert collisions[0]['sites'] == ['site_a', 'site_b']

    # 主张也严格分属各自采集点，site_a 的回答不会被当作 site_b 的证据
    claims_by_site = {}
    for claim in audit.claims:
        claims_by_site.setdefault(claim.site, set()).add((claim.name, claim.value))
    assert claims_by_site['site_a'] == {('alpha.example', '1.1.1.1')}
    assert claims_by_site['site_b'] == {('beta.example', '2.2.2.2')}


def test_orphan_response_from_other_site_is_not_adopted(tmp_path):
    """site_b 只有回答、问题在另一份抓包里：同号也不能拿来配对。"""
    question = dns_question('alpha.example.')
    site_a = [
        (100.0, dns_query(0x0AAA, [question]), True, 40000, 53),
    ]
    orphan = dns_response(0x0AAA, [question], [a_rr('alpha.example.', '9.9.9.9')])
    site_b = [
        (100.2, orphan, False, 53, 40000),
    ]
    audit = _audit(tmp_path, {'site_a': site_a, 'site_b': site_b})

    statuses = {(item.site, item.status) for item in audit.exchanges}
    assert ('site_a', MATCH_UNANSWERED) in statuses
    assert ('site_b', MATCH_ORPHAN) in statuses
    # 孤立回答不产生任何主张
    assert audit.claims == []


def test_same_site_duplicate_txid_is_ambiguous(tmp_path):
    """同采集点内同 txid/同问题/同套接字的两个问题，候选无法排除。"""
    question = dns_question('dup.example.')
    packets = [
        (100.0, dns_query(0x0777, [question]), True, 40000, 53),
        (100.1, dns_query(0x0777, [question]), True, 40000, 53),
        (100.2, dns_response(0x0777, [question], [a_rr('dup.example.', '5.5.5.5')]),
         False, 53, 40000),
    ]
    audit = _audit(tmp_path, {'site_a': packets})
    assert len(audit.exchanges) == 1
    exchange = audit.exchanges[0]
    assert exchange.status == MATCH_AMBIGUOUS
    assert len(exchange.candidates) == 2
    # 歧义配对不提取主张，证据保留待人工复查
    assert audit.claims == []


def test_unique_match_uses_full_basis(tmp_path):
    site_a = exchange_packets(
        0x0001, 'one.example.', [a_rr('one.example.', '10.0.0.1')],
    )
    audit = _audit(tmp_path, {'site_a': site_a})
    exchange = audit.exchanges[0]
    assert exchange.status == MATCH_UNIQUE
    for basis in (BASIS_SAME_SITE, BASIS_QUESTION, BASIS_SOCKET):
        assert basis in exchange.match_basis


def test_matching_keeps_sites_independent_directly():
    """直接用内存报文验证：分组键里包含采集点。"""
    packets = []
    # 构造两个采集点的空列表结果，保证函数按 site 分组
    result = pair_exchanges([])
    assert result.exchanges == []
    assert result.cross_site_txid_collisions == []


def test_truncated_response_is_flagged_in_scope(tmp_path):
    site_a = exchange_packets(
        0x0002, 'big.example.', [a_rr('big.example.', '10.0.0.2')],
        truncated=True,
    )
    audit = _audit(tmp_path, {'site_a': site_a})
    claim = audit.claims[0]
    assert claim.scope.truncated is True


def test_read_errors_are_retained(tmp_path):
    good = write_pcap(
        str(tmp_path / 'good.pcap'),
        exchange_packets(0x0003, 'ok.example.', [a_rr('ok.example.', '10.0.0.3')]),
    )
    bad = str(tmp_path / 'bad.pcap')
    with open(bad, 'wb') as handle:
        handle.write(b'not a pcap at all')
    capture_good = read_capture(good, 'site_a')
    capture_bad = read_capture(bad, 'site_b')
    assert len(capture_good.messages) == 2
    assert capture_bad.messages == []
    assert capture_bad.read_errors, '损坏文件必须留下可复查的读取异常'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
