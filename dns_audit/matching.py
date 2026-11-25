"""按采集点隔离的离线问答匹配。

关键约束：问题与回答只在 *同一采集点* 内配对。两个采集点即使出现
相同事务 ID（txid）也绝不互相串证——txid 只是 16 位易复用编号，
不是跨采集点的关联键。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from .model import (
    DnsMessage,
    Exchange,
    MATCH_AMBIGUOUS,
    MATCH_ORPHAN,
    MATCH_UNANSWERED,
    MATCH_UNIQUE,
    PacketRef,
)

# 每一条匹配依据都显式留痕，便于事后复查
BASIS_SAME_SITE = 'same_site'
BASIS_TXID = 'txid_equal'
BASIS_QUESTION = 'question_section_equal'
BASIS_SOCKET = 'socket_reversed'
BASIS_ORDER = 'response_after_query'
BASIS_SINGLE = 'single_candidate'
BASIS_MULTI = 'multiple_candidates_unresolved'


def _question_key(message: DnsMessage) -> Tuple[Tuple[str, int, int], ...]:
    return tuple(q.key() for q in message.questions)


def _socket_reversed(query: DnsMessage, response: DnsMessage) -> bool:
    return (
        response.src_ip == query.dst_ip
        and response.dst_ip == query.src_ip
        and response.src_port == query.dst_port
        and response.dst_port == query.src_port
    )


def _is_candidate(query: DnsMessage, response: DnsMessage) -> bool:
    return (
        query.ref.site == response.ref.site
        and query.txid == response.txid
        and _question_key(query) == _question_key(response)
        and _socket_reversed(query, response)
        and response.ref.timestamp >= query.ref.timestamp
    )


@dataclass
class MatchingResult:
    """全采集点的配对结果。"""

    exchanges: List[Exchange] = field(default_factory=list)
    # 同一 txid 在多个采集点同时出现问题的碰撞清单（只读展示，不参与配对）
    cross_site_txid_collisions: List[dict] = field(default_factory=list)


def pair_exchanges(messages: List[DnsMessage]) -> MatchingResult:
    """把报文按采集点分组后再做问答配对。"""
    result = MatchingResult()
    by_site: Dict[str, List[DnsMessage]] = {}
    for message in messages:
        by_site.setdefault(message.ref.site, []).append(message)

    for site in sorted(by_site):
        result.exchanges.extend(_pair_one_site(site, by_site[site]))

    result.cross_site_txid_collisions = _txid_collisions(by_site)
    return result


def _pair_one_site(site: str, messages: List[DnsMessage]) -> List[Exchange]:
    queries = [m for m in messages if not m.is_response]
    responses = [m for m in messages if m.is_response]
    by_txid: Dict[int, List[DnsMessage]] = {}
    for query in queries:
        by_txid.setdefault(query.txid, []).append(query)

    tied_queries = set()  # 陷入多候选歧义的问题，不再算作未回答
    matched_queries = set()  # 已唯一配对的问题
    exchanges: List[Exchange] = []

    for response in responses:
        candidates = [
            query
            for query in by_txid.get(response.txid, [])
            if query not in tied_queries
            and query not in matched_queries
            and _is_candidate(query, response)
        ]
        if not candidates:
            exchanges.append(
                Exchange(
                    site=site,
                    txid=response.txid,
                    status=MATCH_ORPHAN,
                    match_basis=(BASIS_SAME_SITE, BASIS_TXID),
                    response=response,
                )
            )
            continue
        if len(candidates) == 1:
            query = candidates[0]
            matched_queries.add(query)
            exchanges.append(
                Exchange(
                    site=site,
                    txid=response.txid,
                    status=MATCH_UNIQUE,
                    match_basis=(
                        BASIS_SAME_SITE,
                        BASIS_TXID,
                        BASIS_QUESTION,
                        BASIS_SOCKET,
                        BASIS_ORDER,
                        BASIS_SINGLE,
                    ),
                    candidates=(query.ref,),
                    query=query,
                    response=response,
                )
            )
            continue
        refs: List[PacketRef] = []
        for query in candidates:
            tied_queries.add(query)
            refs.append(query.ref)
        exchanges.append(
            Exchange(
                site=site,
                txid=response.txid,
                status=MATCH_AMBIGUOUS,
                match_basis=(
                    BASIS_SAME_SITE,
                    BASIS_TXID,
                    BASIS_QUESTION,
                    BASIS_SOCKET,
                    BASIS_ORDER,
                    BASIS_MULTI,
                ),
                candidates=tuple(refs),
                response=response,
            )
        )

    for query in queries:
        if query in tied_queries or query in matched_queries:
            continue
        exchanges.append(
            Exchange(
                site=site,
                txid=query.txid,
                status=MATCH_UNANSWERED,
                match_basis=(BASIS_SAME_SITE, BASIS_TXID),
                query=query,
            )
        )

    exchanges.sort(key=lambda item: (item.site, item.txid))
    return exchanges


def _txid_collisions(by_site: Dict[str, List[DnsMessage]]) -> List[dict]:
    """列出在多个采集点都发起过的 txid，证明同号不等于同一事务。"""
    sites_by_txid: Dict[int, Dict[str, List[PacketRef]]] = {}
    for site, messages in by_site.items():
        for message in messages:
            if message.is_response:
                continue
            entry = sites_by_txid.setdefault(message.txid, {})
            entry.setdefault(site, []).append(message.ref)
    collisions = []
    for txid in sorted(sites_by_txid):
        per_site = sites_by_txid[txid]
        if len(per_site) > 1:
            collisions.append(
                {
                    'txid': txid,
                    'sites': sorted(per_site),
                    'query_refs': {
                        site: [ref.frame_index for ref in refs]
                        for site, refs in sorted(per_site.items())
                    },
                }
            )
    return collisions
