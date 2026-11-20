"""
Offline review engine.

The engine reuses the CPE parsing of :class:`cpe.CPE` and the WFN relation
logic of :class:`cpe.cpeset2_3.CPESet2_3` and adds an evidence-driven layer
on top:

1. Every advisory CPE is compared with every queryable inventory record.
2. A relation is only accepted when at least one :class:`Evidence` item
   backs it; a shared product-name layer is never enough on its own.
3. ``same`` relations are the only relations that may fold identifiers.
4. ``contained`` relations must walk explicit, provable parent links.
5. Supplier declarations without a queryable record stay in a separate
   ``supplied`` bucket and can never confirm an affected asset by themselves.
"""

from collections import OrderedDict

from cpe import CPE
from cpe.cpe2_3_wfn import CPE2_3_WFN
from cpe.cpeset2_3 import CPESet2_3

from .model import (
    REL_SAME,
    REL_CONTAINED,
    REL_SUPPLIED,
    DISPOSITION_ACTIONABLE,
    DISPOSITION_REVIEW,
    DISPOSITION_EXCLUDED,
    Evidence,
    Relation,
    DispositionItem,
)


# Logical relation values returned by ``CPESet2_3.compare_wfns``.
# ``cpe_superset(source, target)`` means *source* is more general than
# *target*, so when the advisory (source) ranges over an inventory record
# (target) both EQUAL and SUPERSET confirm the same identity.
_EQUAL = CPESet2_3.LOGICAL_VALUE_EQUAL
_SUPERSET = CPESet2_3.LOGICAL_VALUE_SUPERSET


def parse_wfn(cpe_str):
    """Parse any supported CPE string and normalize it to a WFN object."""
    return CPE2_3_WFN(CPE(cpe_str).as_wfn())


class _CPEIndex(object):
    """Cache of parsed WFN objects keyed by the original CPE string."""

    def __init__(self):
        self._cache = {}

    def get(self, cpe_str):
        if cpe_str not in self._cache:
            self._cache[cpe_str] = parse_wfn(cpe_str)
        return self._cache[cpe_str]


class ReviewResult(object):
    """
    Outcome of one offline review run.

    Relations are grouped by kind so callers can see exactly which evidence
    supports identity folding, containment walks and supplier declarations.
    """

    def __init__(self):
        self.relations = []
        self.dispositions = OrderedDict()

    def relations_of(self, kind):
        return [relation for relation in self.relations
                if relation.kind == kind]

    def to_dict(self):
        return OrderedDict((
            ("relations", [relation.to_dict()
                           for relation in self.relations]),
            ("dispositions", OrderedDict(
                (asset_id, item.to_dict())
                for asset_id, item in self.dispositions.items())),
        ))


class OfflineReview(object):
    """
    Evidence-driven offline review of advisory CPEs against an inventory.

    :param assets: iterable of :class:`~cpe.review.model.Asset` objects.
    :param advisories: iterable of
        :class:`~cpe.review.model.AdvisoryEntry` objects.
    """

    def __init__(self, assets, advisories):
        self.assets = list(assets)
        self.advisories = list(advisories)
        self._index = _CPEIndex()

    # ------------------------------------------------------------------
    # Attribute comparison helpers, built on the existing CPE matching
    # ------------------------------------------------------------------

    def _attribute_relations(self, source_str, target_str):
        """
        Pairwise WFN attribute relation between two CPE strings.

        Returns a dict keyed by CPE attribute name with the logical value
        produced by ``CPESet2_3.compare_wfns``.
        """
        source = self._index.get(source_str)
        target = self._index.get(target_str)
        return OrderedDict(
            CPESet2_3.compare_wfns(source, target))

    def _is_same_identity(self, advisory_str, known_str):
        """
        Same identity requires equality on every non-wildcard attribute.

        Wildcards on either side are allowed on advisory ranges as long as
        the fixed attributes agree; product name alone is not compared
        anywhere, the full WFN relation is always evaluated.
        """
        relations = self._attribute_relations(advisory_str, known_str)
        for attribute, value in relations.items():
            if value not in (_EQUAL, _SUPERSET):
                return False
        return True

    def _identity_key(self, cpe_str):
        """
        Canonical key used for identity folding.

        Only a ``same`` relation may produce this key; containment and
        supplier relations never call it.
        """
        wfn = self._index.get(cpe_str)
        parts = []
        for attribute in ("part", "vendor", "product", "version",
                          "update", "edition", "language", "sw_edition",
                          "target_sw", "target_hw", "other"):
            value = wfn.get_attribute_values(attribute)[0]
            parts.append(value)
        return tuple(parts)

    # ------------------------------------------------------------------
    # Evidence collection
    # ------------------------------------------------------------------

    def _same_evidence(self, advisory_str, known_str, record_source):
        relations = self._attribute_relations(advisory_str, known_str)
        return Evidence(
            source=record_source,
            detail=OrderedDict((
                ("type", REL_SAME),
                ("advisory_cpe", advisory_str),
                ("inventory_cpe", known_str),
                ("attribute_relations", list(relations.values())),
            )))

    def _collect_same(self, asset):
        """Collect same-identity evidence against queryable records."""
        found = []
        queryable = [asset.device_cpe]
        queryable.extend(asset.component_cpes)
        for advisory in self.advisories:
            for known_str in queryable:
                if self._is_same_identity(advisory.cpe_str, known_str):
                    evidence = self._same_evidence(
                        advisory.cpe_str, known_str,
                        record_source="inventory")
                    relation = Relation(
                        kind=REL_SAME,
                        subject_cpe=advisory.cpe_str,
                        object_cpe=known_str,
                        evidence=[evidence],
                        asset_id=asset.asset_id)
                    found.append((advisory, relation))

        # Explicit same-identity aliases declared by inventory documents.
        # These are the only pairs that may be folded without an advisory.
        for group in asset.identity_aliases:
            for left in group:
                for right in group:
                    if left == right:
                        continue
                    # Identity is asserted by the inventory document, not
                    # inferred from name similarity: every declared alias
                    # pair is accepted as same identity on that record.
                    evidence = Evidence(
                        source="inventory-alias",
                        detail=OrderedDict((
                            ("type", REL_SAME),
                            ("alias_cpe", left),
                            ("canonical_cpe", right),
                            ("declared_in", "identity_aliases"),
                        )))
                    relation = Relation(
                        kind=REL_SAME,
                        subject_cpe=left,
                        object_cpe=right,
                        evidence=[evidence],
                        asset_id=asset.asset_id)
                    found.append((None, relation))
        return found

    def _walk_containment(self, asset, start_cpe):
        """
        Walk the explicit parent links stored on the asset.

        Returns the ordered chain from a top-level parent down to
        ``start_cpe`` when every edge is backed by an inventory document,
        otherwise ``None``.  Product-name similarity is never used.
        """
        reverse_edges = {}
        for parent, children in asset.parent_links.items():
            for child in children:
                reverse_edges.setdefault(child, parent)

        if start_cpe not in reverse_edges and start_cpe not in asset.parent_links:
            return None

        chain = [start_cpe]
        current = start_cpe
        seen = set(chain)
        while current in reverse_edges:
            parent = reverse_edges[current]
            if parent in seen:
                return None
            chain.append(parent)
            seen.add(parent)
            current = parent
        chain.reverse()

        known = set(asset.all_known_cpes())
        if any(node not in known for node in chain):
            return None
        return chain

    def _collect_contained(self, asset, same_matches):
        """
        Collect containment evidence for components not matched directly.

        A component is provably affected when an advisory matches a parent
        of the component and every edge of the parent -> child chain is an
        explicit inventory link.
        """
        found = []
        seen_contained = set()
        matched_objects = set(relation.object_cpe
                              for _, relation in same_matches)
        for advisory in self.advisories:
            for component in asset.component_cpes:
                if component in matched_objects:
                    continue
                chain = self._walk_containment(asset, component)
                if not chain:
                    continue
                # Any ancestor that an advisory identifies directly is a
                # valid provable root; the walk below it must stay on
                # explicit inventory parent links (already validated).
                proven_ancestors = [
                    node for node in chain if node in matched_objects]
                root = next((
                    node for node in proven_ancestors
                    if self._is_same_identity(advisory.cpe_str, node)),
                    None)
                if root is None:
                    continue
                provable_chain = chain[chain.index(root):]
                evidence = Evidence(
                    source="hierarchy",
                    detail=OrderedDict((
                        ("type", REL_CONTAINED),
                        ("advisory_cpe", advisory.cpe_str),
                        ("root_cpe", root),
                        ("chain", list(provable_chain)),
                        ("edges", [
                            OrderedDict((
                                ("parent", provable_chain[i]),
                                ("child", provable_chain[i + 1])))
                            for i in range(len(provable_chain) - 1)]),
                    )))
                relation = Relation(
                    kind=REL_CONTAINED,
                    subject_cpe=advisory.cpe_str,
                    object_cpe=component,
                    evidence=[evidence],
                    chain=provable_chain,
                    asset_id=asset.asset_id)
                signature = (advisory.cpe_str, component,
                             tuple(provable_chain))
                if signature not in seen_contained:
                    seen_contained.add(signature)
                    found.append((advisory, relation))
        return found

    def _collect_supplied(self, asset, same_matches, contained_matches):
        """
        Collect supplier-declaration evidence.

        A claim is only considered when its CPE matches an advisory but no
        queryable component record confirms the identity.  The resulting
        relation never qualifies as actionable by itself.
        """
        proven_objects = set(relation.object_cpe
                             for _, relation in same_matches)
        proven_objects.update(relation.object_cpe
                              for _, relation in contained_matches)
        found = []
        for advisory in self.advisories:
            for claimed_cpe, supplier in sorted(asset.supplier_claims.items()):
                if claimed_cpe in proven_objects:
                    continue
                if not self._is_same_identity(advisory.cpe_str, claimed_cpe):
                    continue
                evidence = Evidence(
                    source="supplier-declaration",
                    detail=OrderedDict((
                        ("type", REL_SUPPLIED),
                        ("advisory_cpe", advisory.cpe_str),
                        ("claimed_cpe", claimed_cpe),
                        ("supplier", supplier),
                        ("queryable_record", False),
                    )))
                relation = Relation(
                    kind=REL_SUPPLIED,
                    subject_cpe=advisory.cpe_str,
                    object_cpe=claimed_cpe,
                    evidence=[evidence],
                    asset_id=asset.asset_id)
                found.append((advisory, relation))
        return found

    def _enclosure_rejection(self, asset):
        """
        Record why enclosure CPEs stay out of scope.

        The enclosure shares the supplier product-naming layer but is a
        hardware record with no identity equality and no containment edge
        to an affected component, so the only possible evidence rejects it.
        """
        rejections = []
        for enclosure in asset.enclosure_cpes:
            enclosure_wfn = self._index.get(enclosure)
            name_layer_hits = []
            for advisory in self.advisories:
                advisory_wfn = self._index.get(advisory.cpe_str)
                product_relations = OrderedDict(
                    CPESet2_3.compare_wfns(advisory_wfn, enclosure_wfn))
                if product_relations.get("vendor") in (_EQUAL, _SUPERSET):
                    name_layer_hits.append(advisory.cpe_str)
            chain = self._walk_containment(asset, enclosure)
            rejections.append(Evidence(
                source="inventory",
                supports=False,
                detail=OrderedDict((
                    ("type", "name_layer_only"),
                    ("enclosure_cpe", enclosure),
                    ("advisories_sharing_name_layer", name_layer_hits),
                    ("part_relation", "hw vs a: hardware enclosure is not software"),
                    ("provable_chain", chain is not None),
                ))))
        return rejections

    # ------------------------------------------------------------------
    # Identity folding
    # ------------------------------------------------------------------

    def fold_identities(self, result):
        """
        Fold same-identity relations onto canonical identity keys.

        Only ``same`` relations participate; contained and supplied
        relations are returned untouched and can never be folded.
        """
        # Union-find: every same relation is an equality edge.
        # contained/supplied relations are deliberately excluded so they
        # can never fold identifiers.
        parent = {}

        def find(node):
            parent.setdefault(node, node)
            while parent[node] != node:
                parent[node] = parent[parent[node]]
                node = parent[node]
            return node

        def union(left, right):
            root_left, root_right = find(left), find(right)
            if root_left != root_right:
                parent[root_right] = root_left

        for relation in result.relations:
            if relation.kind != REL_SAME:
                continue
            union(relation.subject_cpe, relation.object_cpe)

        groups = OrderedDict()
        for node in sorted(parent):
            groups.setdefault(find(node), []).append(node)
        return OrderedDict(
            (self._identity_key(names[0]), sorted(names))
            for names in groups.values() if len(names) > 1)

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def run(self):
        """Run the offline review and build the remediation disposition."""
        result = ReviewResult()
        for asset in self.assets:
            same_matches = self._collect_same(asset)
            contained_matches = self._collect_contained(
                asset, same_matches)
            supplied_matches = self._collect_supplied(
                asset, same_matches, contained_matches)
            enclosure_rejections = self._enclosure_rejection(asset)

            all_matches = same_matches + contained_matches + supplied_matches
            for _, relation in all_matches:
                result.relations.append(relation)

            disposition = self._build_disposition(
                asset, same_matches, contained_matches,
                supplied_matches, enclosure_rejections)
            result.dispositions[asset.asset_id] = disposition
        return result

    def _build_disposition(self, asset, same_matches, contained_matches,
                           supplied_matches, enclosure_rejections):
        relations = [relation for _, relation in
                     same_matches + contained_matches + supplied_matches]
        if same_matches or contained_matches:
            proven = sorted(set(
                relation.object_cpe
                for _, relation in same_matches + contained_matches))
            reason = (
                "provable identity or containment evidence for: "
                + ", ".join(proven))
            disposition = DISPOSITION_ACTIONABLE
            matched = proven
        elif supplied_matches:
            claimed = sorted(set(
                relation.object_cpe for _, relation in supplied_matches))
            reason = (
                "only supplier declarations exist for: "
                + ", ".join(claimed)
                + "; no queryable component record, manual review required")
            disposition = DISPOSITION_REVIEW
            matched = claimed
        else:
            reason = "no same, containment or supplier evidence; " \
                     "name-layer-only records (e.g. enclosure) excluded"
            disposition = DISPOSITION_EXCLUDED
            matched = []

        return DispositionItem(
            asset_id=asset.asset_id,
            disposition=disposition,
            matched_cpe=matched,
            relations=relations,
            reason=reason,
            rejections=enclosure_rejections)
