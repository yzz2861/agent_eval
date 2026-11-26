"""Alias closure and name-to-address resolution within one capture domain."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .model import CLAIM_ADDRESS, CLAIM_ALIAS, Claim


@dataclass
class NameResolution:
    site: str
    name: str
    addresses: Set[str] = field(default_factory=set)
    complete: bool = True
    truncated: bool = False
    ambiguous: bool = False
    chain: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    claim_indices: List[int] = field(default_factory=list)
    alias_claim_indices: List[int] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            'site': self.site,
            'name': self.name,
            'addresses': sorted(self.addresses),
            'complete': self.complete,
            'truncated': self.truncated,
            'ambiguous': self.ambiguous,
            'chain': list(self.chain),
            'reasons': list(self.reasons),
            'claim_indices': list(self.claim_indices),
            'alias_claim_indices': list(self.alias_claim_indices),
        }


def resolve_names(claims: List[Claim]) -> Dict[Tuple[str, str], NameResolution]:
    """Resolve every observed queried/owner name using only same-site claims."""
    result: Dict[Tuple[str, str], NameResolution] = {}
    sites = sorted({claim.site for claim in claims})
    for site in sites:
        site_claims = [(index, claim) for index, claim in enumerate(claims) if claim.site == site]
        edges = _edges(site_claims)
        addresses = _addresses(site_claims)
        starts = _start_names(site_claims, edges, addresses)
        for name in sorted(starts):
            result[(site, name)] = _resolve_one(site, name, edges, addresses)
    return result


def _edges(site_claims) -> Dict[str, Dict[str, List[int]]]:
    edges: Dict[str, Dict[str, List[int]]] = {}
    for index, claim in site_claims:
        if claim.kind != CLAIM_ALIAS or not claim.value:
            continue
        targets = edges.setdefault(claim.name, {})
        targets.setdefault(claim.value, []).append(index)
    return edges


def _addresses(site_claims) -> Dict[str, Dict[str, List[int]]]:
    addresses: Dict[str, Dict[str, List[int]]] = {}
    for index, claim in site_claims:
        if claim.kind != CLAIM_ADDRESS or not claim.value:
            continue
        values = addresses.setdefault(claim.name, {})
        values.setdefault(claim.value, []).append(index)
    return addresses


def _start_names(site_claims, edges, addresses) -> Set[str]:
    names: Set[str] = set(edges) | set(addresses)
    for _index, claim in site_claims:
        if claim.query_name:
            names.add(claim.query_name.lower())
    return names


def _resolve_one(site, start, edges, addresses) -> NameResolution:
    resolution = NameResolution(site=site, name=start, chain=[start])
    current = start
    visited = {start}

    direct = addresses.get(current, {})
    for address, indices in direct.items():
        resolution.addresses.add(address)
        resolution.claim_indices.extend(indices)

    while current in edges:
        targets = edges[current]
        if len(targets) > 1:
            resolution.complete = False
            resolution.ambiguous = True
            resolution.reasons.append(
                'CNAME name %s has multiple observed targets: %s'
                % (current, sorted(targets))
            )
            for indices in targets.values():
                resolution.alias_claim_indices.extend(indices)
            break

        target = next(iter(targets))
        indices = targets[target]
        resolution.alias_claim_indices.extend(indices)
        resolution.chain.append(target)
        current = target

        if target in visited:
            resolution.complete = False
            resolution.reasons.append('CNAME cycle detected at %s' % target)
            break
        visited.add(target)

        for address, address_indices in addresses.get(current, {}).items():
            resolution.addresses.add(address)
            resolution.claim_indices.extend(address_indices)

    if resolution.complete and current not in addresses and not resolution.addresses:
        resolution.complete = False
        resolution.reasons.append(
            'terminal name %s has no observed A/AAAA record in this capture domain'
            % current
        )

    for index in resolution.claim_indices + resolution.alias_claim_indices:
        claim_scope_site = site
        if 0 <= index < len([]):
            continue
    resolution.claim_indices = sorted(set(resolution.claim_indices))
    resolution.alias_claim_indices = sorted(set(resolution.alias_claim_indices))
    return resolution
