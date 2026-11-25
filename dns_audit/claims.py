"""从已配对问答中组合有限的名称/地址主张。

只接受 status=unique 的配对；多候选（ambiguous）与孤立回答
（orphan_response）不产生主张，只保留在交换记录里供人工复查。
每条主张都带上采集归属、证据指针与声称的有效范围。
"""
from __future__ import annotations

from typing import List, Optional

import dpkt

from .model import (
    CLAIM_ADDRESS,
    CLAIM_ALIAS,
    CLAIM_NEGATIVE,
    Claim,
    Exchange,
    MATCH_UNIQUE,
    Scope,
)

_ADDRESS_TYPES = (dpkt.dns.DNS_A, dpkt.dns.DNS_AAAA)


def _scope_of(exchange: Exchange) -> Scope:
    response = exchange.response
    query = exchange.query
    ttl_values = [rr.ttl for rr in response.answers if rr.ttl > 0]
    ttl_until: Optional[float] = None
    if ttl_values:
        ttl_until = response.ref.timestamp + min(ttl_values)
    return Scope(
        site=exchange.site,
        observed_first=query.ref.timestamp,
        observed_last=response.ref.timestamp,
        ttl_until=ttl_until,
        truncated=response.truncated,
    )


def _negative_claim(exchange: Exchange) -> Optional[Claim]:
    response = exchange.response
    if response.rcode == dpkt.dns.DNS_RCODE_NOERR and response.answers:
        return None
    query = exchange.query
    if not query.questions:
        return None
    question = query.questions[0]
    return Claim(
        kind=CLAIM_NEGATIVE,
        site=exchange.site,
        name=question.name.lower(),
        qtype=question.qtype,
        value=None,
        rcode=response.rcode,
        scope=_scope_of(exchange),
        exchange_index=0,  # 由 build_claims 回填
        response_ref=response.ref,
        query_ref=query.ref,
    )


def build_claims(exchanges: List[Exchange]) -> List[Claim]:
    """从唯一配对的回答中提取主张；其余状态一律不推断。"""
    claims: List[Claim] = []
    for exchange_index, exchange in enumerate(exchanges):
        if exchange.status != MATCH_UNIQUE:
            continue
        response = exchange.response
        query = exchange.query

        negative = _negative_claim(exchange)
        if negative is not None:
            claims.append(
                Claim(
                    kind=negative.kind,
                    site=negative.site,
                    name=negative.name,
                    qtype=negative.qtype,
                    value=negative.value,
                    rcode=negative.rcode,
                    scope=negative.scope,
                    exchange_index=exchange_index,
                    response_ref=negative.response_ref,
                    query_ref=negative.query_ref,
                )
            )
            continue

        scope = _scope_of(exchange)
        for rr in response.answers:
            if rr.rtype in _ADDRESS_TYPES and rr.value is not None:
                claims.append(
                    Claim(
                        kind=CLAIM_ADDRESS,
                        site=exchange.site,
                        name=rr.name.lower(),
                        qtype=rr.rtype,
                        value=rr.value,
                        rcode=None,
                        scope=scope,
                        exchange_index=exchange_index,
                        response_ref=response.ref,
                        query_ref=query.ref,
                    )
                )
            elif rr.rtype == dpkt.dns.DNS_CNAME and rr.value is not None:
                claims.append(
                    Claim(
                        kind=CLAIM_ALIAS,
                        site=exchange.site,
                        name=rr.name.lower(),
                        qtype=dpkt.dns.DNS_CNAME,
                        value=rr.value.lower(),
                        rcode=None,
                        scope=scope,
                        exchange_index=exchange_index,
                        response_ref=response.ref,
                        query_ref=query.ref,
                    )
                )
    return claims
