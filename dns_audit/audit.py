"""端到端离线核对：读取抓包 -> 隔离配对 -> 提取主张 -> 同址核对。

对外的主入口是 :class:`Audit`。所有结论都限定在各自采集点的
观察窗内，报告里同时保留未看全的链、未配对的回答与多候选歧义。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

from .alias import AliasTrace, build_alias_traces
from .claims import build_claims
from .matching import MatchingResult, pair_exchanges
from .model import (
    CLAIM_ADDRESS,
    CaptureResult,
    Claim,
    DnsMessage,
    Exchange,
    ReadError,
)
from .reader import read_capture
from .resolution import resolve_names


@dataclass
class NameProfile:
    """单个采集点内，一个名称被观察到的地址集合与范围。"""

    site: str
    name: str
    addresses: Set[str] = field(default_factory=set)
    claim_indices: List[int] = field(default_factory=list)
    observed_first: Optional[float] = None
    observed_last: Optional[float] = None
    any_truncated: bool = False
    resolution_complete: bool = True
    ambiguous: bool = False
    chain: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    all_claim_indices: List[int] = field(default_factory=list)


@dataclass
class NameComparison:
    """两个名称在同一采集点内的同址核对结论。"""

    site: str
    name_a: str
    name_b: str
    equal: bool
    note: str
    addresses_a: Set[str] = field(default_factory=set)
    addresses_b: Set[str] = field(default_factory=set)
    status: str = 'unknown'
    complete: bool = True


@dataclass
class Audit:
    """一次完整离线核对的全部产物，均可序列化复查。"""

    captures: List[CaptureResult] = field(default_factory=list)
    matching: Optional[MatchingResult] = None
    exchanges: List[Exchange] = field(default_factory=list)
    claims: List[Claim] = field(default_factory=list)
    alias_traces: List[AliasTrace] = field(default_factory=list)
    profiles: List[NameProfile] = field(default_factory=list)
    comparisons: List[NameComparison] = field(default_factory=list)

    @classmethod
    def from_sources(cls, sources: Sequence[Tuple[str, str]]) -> "Audit":
        """sources 为 (pcap 路径, 采集点标识) 序列。"""
        audit = cls()
        for source, site in sources:
            audit.captures.append(read_capture(source, site))

        messages: List[DnsMessage] = []
        for capture in audit.captures:
            messages.extend(capture.messages)

        return cls.from_messages(messages, audit.captures)

    @classmethod
    def from_messages(
        cls,
        messages: Sequence[DnsMessage],
        captures: Optional[Sequence[CaptureResult]] = None,
    ) -> "Audit":
        """Build an audit from in-memory or already-parsed DNS messages."""
        audit = cls(captures=list(captures or []))
        audit.matching = pair_exchanges(list(messages))
        audit.exchanges = audit.matching.exchanges
        audit.claims = build_claims(audit.exchanges)
        audit.alias_traces = build_alias_traces(audit.claims)
        audit.profiles = _build_profiles(audit.claims)
        audit.comparisons = _compare_profiles(audit.profiles)
        return audit

    def read_errors(self) -> List[ReadError]:
        return [error for capture in self.captures for error in capture.read_errors]

    def addresses_for(self, site: str, name: str) -> Set[str]:
        """只在指定采集点内取某名称的地址，避免跨采集点混证。"""
        name = name.lower()
        result: Set[str] = set()
        for claim in self.claims:
            if (
                claim.kind == CLAIM_ADDRESS
                and claim.site == site
                and claim.name == name
            ):
                result.add(claim.value)
        return result

    def to_dict(self) -> dict:
        return {
            'captures': [
                {
                    'source': capture.source,
                    'site': capture.site,
                    'message_count': len(capture.messages),
                    'read_errors': [
                        {
                            'frame_index': error.ref.frame_index,
                            'timestamp': error.ref.timestamp,
                            'reason': error.reason,
                        }
                        for error in capture.read_errors
                    ],
                }
                for capture in self.captures
            ],
            'cross_site_txid_collisions': self.matching.cross_site_txid_collisions,
            'exchanges': [_exchange_to_dict(item) for item in self.exchanges],
            'claims': [_claim_to_dict(item) for item in self.claims],
            'alias_traces': [_trace_to_dict(item) for item in self.alias_traces],
            'comparisons': [
                {
                    'site': item.site,
                    'name_a': item.name_a,
                    'name_b': item.name_b,
                    'equal_in_observed_window': item.equal,
                    'note': item.note,
                    'status': item.status,
                    'complete': item.complete,
                    'addresses_a': sorted(item.addresses_a),
                    'addresses_b': sorted(item.addresses_b),
                }
                for item in self.comparisons
            ],
        }


def _build_profiles(claims: List[Claim]) -> List[NameProfile]:
    grouped: Dict[Tuple[str, str], NameProfile] = {}
    for index, claim in enumerate(claims):
        if claim.kind != CLAIM_ADDRESS:
            continue
        key = (claim.site, claim.name)
        profile = grouped.get(key)
        if profile is None:
            profile = NameProfile(site=claim.site, name=claim.name)
            grouped[key] = profile
        profile.addresses.add(claim.value)
        profile.claim_indices.append(index)
        first = claim.scope.observed_first
        last = claim.scope.observed_last
        profile.observed_first = (
            first if profile.observed_first is None else min(profile.observed_first, first)
        )
        profile.observed_last = (
            last if profile.observed_last is None else max(profile.observed_last, last)
        )
        profile.any_truncated = profile.any_truncated or claim.scope.truncated
    profiles = [grouped[key] for key in sorted(grouped)]
    _merge_alias_resolutions(profiles, claims)
    return profiles


def _merge_alias_resolutions(profiles: List[NameProfile], claims: List[Claim]) -> None:
    resolutions = resolve_names(claims)
    by_key = {(profile.site, profile.name): profile for profile in profiles}
    for (site, name), resolution in resolutions.items():
        profile = by_key.get((site, name))
        if profile is None:
            profile = NameProfile(site=site, name=name)
            profiles.append(profile)
            by_key[(site, name)] = profile
        profile.addresses.update(resolution.addresses)
        profile.resolution_complete = resolution.complete
        profile.ambiguous = resolution.ambiguous
        profile.truncated = resolution.truncated
        profile.chain = list(resolution.chain)
        profile.reasons = list(resolution.reasons)

        indices = set(resolution.claim_indices)
        if indices:
            profile.claim_indices = sorted(set(profile.claim_indices) | indices)
            first_times = []
            last_times = []
            for index in indices:
                if 0 <= index < len(claims):
                    scope = claims[index].scope
                    first_times.append(scope.observed_first)
                    last_times.append(scope.observed_last)
                    profile.any_truncated = profile.any_truncated or scope.truncated
            if first_times:
                valid_first = [value for value in first_times if value is not None]
                valid_last = [value for value in last_times if value is not None]
                if valid_first:
                    profile.observed_first = min(
                        value for value in [profile.observed_first, min(valid_first)]
                        if value is not None
                    ) if profile.observed_first is not None else min(valid_first)
                if valid_last:
                    profile.observed_last = max(
                        value for value in [profile.observed_last, max(valid_last)]
                        if value is not None
                    ) if profile.observed_last is not None else max(valid_last)


def _compare_profiles(profiles: List[NameProfile]) -> List[NameComparison]:
    """同一采集点内两两核对地址集合；跨采集点不作相等判断。"""
    by_site: Dict[str, List[NameProfile]] = {}
    for profile in profiles:
        by_site.setdefault(profile.site, []).append(profile)

    comparisons: List[NameComparison] = []
    for site in sorted(by_site):
        site_profiles = sorted(by_site[site], key=lambda item: item.name)
        for i in range(len(site_profiles)):
            for j in range(i + 1, len(site_profiles)):
                left = site_profiles[i]
                right = site_profiles[j]
                evidence_complete = (
                    left.resolution_complete
                    and right.resolution_complete
                    and not left.any_truncated
                    and not right.any_truncated
                )
                if not left.addresses or not right.addresses:
                    equal = False
                    status = 'insufficient_evidence'
                    note = (
                        '在 %s 内证据不足：至少一个名称没有可复查的地址集合或完整别名链' % site
                    )
                elif left.addresses == right.addresses:
                    equal = True
                    status = 'equal_observed'
                    note = (
                        '在 %s 已保存证据和观察窗内地址集合一致；不代表窗口外或其它采集点同样一致' % site
                    )
                    if not evidence_complete:
                        status = 'equal_saved_evidence_incomplete'
                        note += '；但别名链或 TC=1 表明显式集合可能不完整，不能作更强主张'
                else:
                    equal = False
                    status = 'different_observed'
                    note = '在 %s 已保存证据中的地址集合不同' % site
                    if not evidence_complete:
                        note += '；仍有链未看全，因此不排除缺失记录会带来额外重叠'
                comparisons.append(
                    NameComparison(
                        site=site,
                        name_a=left.name,
                        name_b=right.name,
                        equal=equal,
                        note=note,
                        addresses_a=set(left.addresses),
                        addresses_b=set(right.addresses),
                        status=status,
                        complete=evidence_complete,
                    )
                )
    return comparisons


def _exchange_to_dict(exchange: Exchange) -> dict:
    return {
        'site': exchange.site,
        'txid': exchange.txid,
        'status': exchange.status,
        'match_basis': list(exchange.match_basis),
        'candidate_frames': [ref.frame_index for ref in exchange.candidates],
        'query_frame': exchange.query.ref.frame_index if exchange.query else None,
        'response_frame': exchange.response.ref.frame_index if exchange.response else None,
        'query_ref': _ref_to_dict(exchange.query.ref) if exchange.query else None,
        'response_ref': _ref_to_dict(exchange.response.ref) if exchange.response else None,
    }


def _ref_to_dict(ref) -> dict:
    return {
        'source': ref.source,
        'site': ref.site,
        'frame_index': ref.frame_index,
        'timestamp': ref.timestamp,
    }


def _claim_to_dict(claim: Claim) -> dict:
    return {
        'kind': claim.kind,
        'site': claim.site,
        'name': claim.name,
        'qtype': claim.qtype,
        'value': claim.value,
        'rcode': claim.rcode,
        'scope': {
            'observed_first': claim.scope.observed_first,
            'observed_last': claim.scope.observed_last,
            'ttl_until': claim.scope.ttl_until,
            'truncated': claim.scope.truncated,
        },
        'exchange_index': claim.exchange_index,
        'query_ref': _ref_to_dict(claim.query_ref),
        'response_ref': _ref_to_dict(claim.response_ref),
    }


def _trace_to_dict(trace: AliasTrace) -> dict:
    return {
        'site': trace.site,
        'start_name': trace.start_name,
        'hops': [
            {
                'source_name': hop.source_name,
                'target_name': hop.target_name,
                'claim_index': hop.claim_index,
            }
            for hop in trace.hops
        ],
        'terminal_name': trace.terminal_name,
        'terminal_addresses': trace.terminal_addresses,
        'complete': trace.complete,
        'incomplete_reasons': trace.incomplete_reasons,
    }
