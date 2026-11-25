"""离线别名观察：只用抓包内保存的 CNAME/A/AAAA 记录构建别名图。

所有图都按采集点分别构建，绝不把两个采集点的记录连成同一条链。
没有看全的链（指向采集窗口外、或缺少后续地址记录）显式标注为不完整，
保留每一跳的证据，方便人工复查。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .model import CLAIM_ADDRESS, CLAIM_ALIAS, Claim


@dataclass(frozen=True)
class AliasHop:
    """别名链上的一跳。"""

    source_name: str
    target_name: str
    claim_index: int


@dataclass
class AliasTrace:
    """从某个查询名出发、在单个采集点内观察到的别名链。"""

    site: str
    start_name: str
    hops: List[AliasHop] = field(default_factory=list)
    terminal_name: Optional[str] = None
    terminal_addresses: List[str] = field(default_factory=list)
    complete: bool = True
    incomplete_reasons: List[str] = field(default_factory=list)


def _alias_edges(claims: List[Claim], site: str) -> Dict[str, List[Tuple[str, int]]]:
    edges: Dict[str, List[Tuple[str, int]]] = {}
    for index, claim in enumerate(claims):
        if claim.kind != CLAIM_ALIAS or claim.site != site:
            continue
        edges.setdefault(claim.name, []).append((claim.value, index))
    return edges


def _address_map(claims: List[Claim], site: str) -> Dict[str, Set[str]]:
    addresses: Dict[str, Set[str]] = {}
    for claim in claims:
        if claim.kind == CLAIM_ADDRESS and claim.site == site:
            addresses.setdefault(claim.name, set()).add(claim.value)
    return addresses


def build_alias_traces(claims: List[Claim]) -> List[AliasTrace]:
    """按采集点构建别名链；链上每一跳都可回溯到具体回答帧。"""
    sites = sorted({claim.site for claim in claims})
    traces: List[AliasTrace] = []
    for site in sites:
        edges = _alias_edges(claims, site)
        addresses = _address_map(claims, site)
        # 链的起点：作为 CNAME 源出现、但从未作为任何 CNAME 目标出现的名字
        all_targets = {target for pairs in edges.values() for target, _ in pairs}
        starts = sorted(name for name in edges if name not in all_targets)
        if not starts:
            continue
        for start in starts:
            traces.append(_trace_one(site, start, edges, addresses))
    return traces


def _trace_one(
    site: str,
    start: str,
    edges: Dict[str, List[Tuple[str, int]]],
    addresses: Dict[str, Set[str]],
) -> AliasTrace:
    trace = AliasTrace(site=site, start_name=start)
    visited: Set[str] = {start}
    current = start
    while True:
        pairs = edges.get(current, [])
        if len(pairs) > 1:
            trace.complete = False
            trace.incomplete_reasons.append(
                'name %s 在该采集点有多个 CNAME 目标，无法排除候选: %s'
                % (current, sorted({target for target, _ in pairs}))
            )
        if not pairs:
            trace.terminal_name = current
            break
        target, claim_index = pairs[0]
        trace.hops.append(
            AliasHop(source_name=current, target_name=target, claim_index=claim_index)
        )
        if target in visited:
            trace.complete = False
            trace.incomplete_reasons.append('CNAME 出现环路，终点 %s 已访问过' % target)
            trace.terminal_name = target
            return trace
        visited.add(target)
        current = target

    terminal_addresses = sorted(addresses.get(trace.terminal_name, set()))
    trace.terminal_addresses = terminal_addresses
    if not terminal_addresses:
        trace.complete = False
        trace.incomplete_reasons.append(
            '终点 %s 在该采集点没有观察到 A/AAAA 地址记录（链未看全）'
            % trace.terminal_name
        )
    return trace


def trace_to_claim_chain(trace: AliasTrace) -> List[int]:
    """别名链引用的全部主张下标，供报告做证据跳转。"""
    return [hop.claim_index for hop in trace.hops]
