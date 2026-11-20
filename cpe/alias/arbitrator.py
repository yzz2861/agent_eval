"""Enterprise arbitration layer in front of the CPE name matching.

The original CPE equivalence judgement (CPESet2_3.name_match) is reused
unchanged.  Only when that judgement fails does the arbitrator consult the
enterprise alias graph, so alias evidence can never override or widen the
original CPE semantics.  No database or online bulletin feed is used.
"""

from collections import OrderedDict

from ..cpe import CPE
from ..cpe2_3_wfn import CPE2_3_WFN
from ..cpeset2_3 import CPESet2_3
from .asset import AssetBook
from .model import Disposition, EdgeReason, MatchEvidence
from .resolver import AliasResolver


def _to_wfn(cpe_str):
    cpe = CPE(cpe_str)
    if isinstance(cpe, CPE2_3_WFN):
        return cpe
    return CPE2_3_WFN(cpe.as_wfn())


def _wfn_key(cpe_str):
    return _to_wfn(cpe_str).as_wfn()


class MatchResult(object):
    """Explainable classification of one bulletin against the asset books."""

    def __init__(self, bulletin_id, bulletin_cpe, classification,
                 matches, blocked):
        self.bulletin_id = bulletin_id
        self.bulletin_cpe = bulletin_cpe
        self.classification = classification
        self.matches = tuple(matches)
        self.blocked = tuple(blocked)

    @property
    def matched(self):
        return bool(self.matches)

    def explain_lines(self):
        lines = ["bulletin={0} class={1}".format(
            self.bulletin_id, self.classification)]
        for evidence in self.matches:
            lines.append("  MATCH " + evidence.explain())
        for evidence in self.blocked:
            lines.append("  BLOCK " + evidence.explain())
        return lines


class MatchReport(object):
    """Per-bulletin results for a single audit run at a fixed date."""

    def __init__(self, query_date, results):
        self.query_date = query_date
        self.results = tuple(results)

    def __iter__(self):
        return iter(self.results)

    def __len__(self):
        return len(self.results)

    def by_classification(self, disposition):
        return tuple(r for r in self.results if r.classification == disposition)


class EnterpriseArbitrator(object):
    """Match bulletins against asset books using CPE plus alias evidence.

    :param AliasRegistry registry: explicit enterprise alias agreements.
    :param ProductCatalog catalog: product id to canonical CPE lookup.
    """

    def __init__(self, registry, catalog):
        self.registry = registry
        self.catalog = catalog

    @staticmethod
    def cpe_equivalent(bulletin_cpe, asset_cpe):
        """Original CPE judgement: bulletin X is an instance of asset K."""
        known = CPESet2_3()
        known.append(_to_wfn(asset_cpe))
        return known.name_match(_to_wfn(bulletin_cpe))

    def classify_pair(self, asset, bulletin, query_date):
        """Classify one (asset, bulletin) pair with full explainability."""
        if self.cpe_equivalent(bulletin.cpe, asset.cpe):
            return Disposition.DIRECT_MATCH, self._direct_evidence(asset, bulletin)

        resolver = AliasResolver(self.registry)
        resolution = resolver.resolve(
            product_from=asset.product_id,
            business_unit=asset.business_unit,
            query_date=query_date)

        target_product = self._product_matching_bulletin(resolution, bulletin)
        if target_product is not None:
            chain = resolution.chain_to(target_product)
            return Disposition.ALIAS_MATCH, self._alias_evidence(
                asset, bulletin, chain)

        disposition, reason_text = self._blocked(resolution)
        return disposition, self._blocked_evidence(
            asset, bulletin, resolution, disposition, reason_text)

    def _product_matching_bulletin(self, resolution, bulletin):
        """Return a reached product whose canonical CPE matches bulletin.

        Only explicit, already-authorized reached products are tested, so an
        alias can only point at a product the catalog actually defines; it
        cannot broaden a match beyond the recorded scope.
        """
        for product_id in resolution.reached_products:
            product_cpe = self.catalog.cpe_of(product_id)
            if product_cpe is None:
                continue
            if self.cpe_equivalent(bulletin.cpe, product_cpe):
                return product_id
        return None

    def _direct_evidence(self, asset, bulletin):
        return MatchEvidence(
            kind=Disposition.DIRECT_MATCH,
            asset_id=asset.asset_id,
            product_id=asset.product_id,
            bulletin_id=bulletin.bulletin_id,
            normalized_asset_cpe=_wfn_key(asset.cpe),
            normalized_bulletin_cpe=_wfn_key(bulletin.cpe),
            relation_ids=(),
            chain=(),
            reason="CPE name-equivalence judgement")

    def _alias_evidence(self, asset, bulletin, chain):
        edges = chain.edges
        relation_ids = tuple(edge.relation_id for edge in edges)
        reason = self._chain_reason(edges)
        return MatchEvidence(
            kind=Disposition.ALIAS_MATCH,
            asset_id=asset.asset_id,
            product_id=asset.product_id,
            bulletin_id=bulletin.bulletin_id,
            normalized_asset_cpe=_wfn_key(asset.cpe),
            normalized_bulletin_cpe=_wfn_key(bulletin.cpe),
            relation_ids=relation_ids,
            chain=relation_ids,
            reason=reason)

    def _blocked_evidence(self, asset, bulletin, resolution,
                          disposition, reason_text):
        relation_ids = tuple(
            attempt.edge.relation_id
            for attempt in resolution.attempts if not attempt.allowed)
        return MatchEvidence(
            kind=disposition,
            asset_id=asset.asset_id,
            product_id=asset.product_id,
            bulletin_id=bulletin.bulletin_id,
            normalized_asset_cpe=_wfn_key(asset.cpe),
            normalized_bulletin_cpe=_wfn_key(bulletin.cpe),
            relation_ids=relation_ids,
            chain=relation_ids,
            reason=reason_text)

    @staticmethod
    def _chain_reason(edges):
        parts = []
        for edge in edges:
            parts.append(
                "{0}->{1} via {2} (scope={3}, {4}..{5})".format(
                    edge.product_from, edge.product_to, edge.source,
                    "/".join(edge.business_scope), edge.valid_from,
                    edge.valid_to or "open"))
        return "authorized alias chain: " + " | ".join(parts)

    @staticmethod
    def _blocked(resolution):
        if not resolution.attempts:
            return (Disposition.NO_MATCH,
                    "no direct CPE match and no alias edge on record")
        reason = AliasResolver.worst_reason(resolution.attempts)
        mapping = {
            EdgeReason.REVOKED: (Disposition.BLOCKED_REVOKED,
                                 "a required alias edge was revoked"),
            EdgeReason.EXPIRED: (Disposition.BLOCKED_EXPIRED,
                                 "a required alias edge is past its validity"),
            EdgeReason.NOT_YET_VALID: (Disposition.BLOCKED_EXPIRED,
                                 "a required alias edge is not yet in force"),
            EdgeReason.UNAUTHORIZED_WILDCARD: (Disposition.BLOCKED_SCOPE,
                                 "wildcard scope does not authorize this unit"),
            EdgeReason.OUT_OF_SCOPE: (Disposition.BLOCKED_SCOPE,
                                 "querying unit is outside the edge scope"),
            EdgeReason.CONFLICT: (Disposition.BLOCKED_CONFLICT,
                                 "conflicting explicit relations on this path"),
        }
        return mapping[reason]

    def run_match(self, books, bulletins, query_date):
        """Match every bulletin against every asset across the books."""
        assets = []
        for book in books:
            assets.extend(book.assets)

        results = []
        for bulletin in bulletins:
            raw = [self.classify_pair(asset, bulletin, query_date)
                   for asset in assets]
            results.append(self._build_result(bulletin, raw))
        return MatchReport(query_date=query_date, results=results)

    @staticmethod
    def _build_result(bulletin, raw):
        """Merge evidence that normalizes to the same WFN key.

        Merging only combines supporting asset ids / relation ids behind an
        identical normalized CPE; it never adds a product or a scope that was
        not matched on its own merits.
        """
        buckets = OrderedDict()
        blocked = []
        for disposition, evidence in raw:
            if evidence.kind == Disposition.NO_MATCH:
                blocked.append(evidence)
                continue
            if evidence.kind in (Disposition.DIRECT_MATCH, Disposition.ALIAS_MATCH):
                key = (evidence.normalized_bulletin_cpe,
                       evidence.normalized_asset_cpe, evidence.kind)
                bucket = buckets.get(key)
                if bucket is None:
                    buckets[key] = {
                        "evidence": evidence,
                        "asset_ids": [evidence.asset_id],
                        "relation_ids": list(evidence.relation_ids)}
                else:
                    if evidence.asset_id not in bucket["asset_ids"]:
                        bucket["asset_ids"].append(evidence.asset_id)
                    for rid in evidence.relation_ids:
                        if rid not in bucket["relation_ids"]:
                            bucket["relation_ids"].append(rid)
            else:
                blocked.append(evidence)

        matches = []
        for bucket in buckets.values():
            base = bucket["evidence"]
            merged_asset = (tuple(bucket["asset_ids"])
                            if len(bucket["asset_ids"]) > 1
                            else bucket["asset_ids"][0])
            matches.append(MatchEvidence(
                kind=base.kind,
                asset_id=merged_asset,
                product_id=base.product_id,
                bulletin_id=base.bulletin_id,
                normalized_asset_cpe=base.normalized_asset_cpe,
                normalized_bulletin_cpe=base.normalized_bulletin_cpe,
                relation_ids=tuple(bucket["relation_ids"]),
                chain=base.chain,
                reason=base.reason))

        if any(m.kind == Disposition.ALIAS_MATCH for m in matches):
            classification = Disposition.ALIAS_MATCH
        elif matches:
            classification = Disposition.DIRECT_MATCH
        elif blocked:
            classification = sorted(m.kind for m in blocked)[0]
        else:
            classification = Disposition.NO_MATCH
        return MatchResult(
            bulletin_id=bulletin.bulletin_id,
            bulletin_cpe=bulletin.cpe,
            classification=classification,
            matches=matches,
            blocked=blocked)
