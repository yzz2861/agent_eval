"""In-memory registry of explicit enterprise alias relations.

No database and no network source is involved.  Relations are supplied by
the enterprise with their full provenance (source, business scope and
validity window) and are retained together with their lifecycle, including
revocation, so that historical queries can be replayed.
"""

from .model import (
    AliasRelation,
    EdgeStatus,
    RelationConflict,
    ScopeViolation,
    scope_has_bare_wildcard,
)


class AliasRegistry(object):
    """Holds alias edges and detects conflicting explicit statements."""

    def __init__(self):
        self._relations = []
        self._conflicts = {}

    def register(self, relation):
        """Validate and store an alias relation.

        :param AliasRelation relation: explicit, fully-evidenced edge.
        :raises ScopeViolation: a bare wildcard or empty scope is recorded.
        :raises RelationConflict: a contradictory relation already exists.
        """
        if not isinstance(relation, AliasRelation):
            raise TypeError("expected an AliasRelation instance")
        if scope_has_bare_wildcard(relation.business_scope):
            raise ScopeViolation(
                "relation {0} uses a bare wildcard scope".format(
                    relation.relation_id))

        pair = (relation.product_from, relation.product_to)
        for existing in self._relations:
            if (existing.product_from, existing.product_to) == pair:
                # Two active explicit relations for the same ordered pair
                # with disagreeing sources are an explainable conflict.
                if (existing.status == EdgeStatus.ACTIVE and
                        relation.status == EdgeStatus.ACTIVE and
                        existing.source != relation.source):
                    key = pair
                    self._conflicts.setdefault(key, set()).update(
                        (existing.relation_id, relation.relation_id))
                    raise RelationConflict(
                        "conflicting alias relations {0} and {1} on {2}".format(
                            existing.relation_id, relation.relation_id, pair))
        self._relations.append(relation)
        return relation

    @property
    def relations(self):
        return list(self._relations)

    def get(self, relation_id):
        for relation in self._relations:
            if relation.relation_id == relation_id:
                return relation
        return None

    def edges_leaving(self, product_id, query_date):
        """All recorded edges whose origin is ``product_id``.

        Revoked or out-of-window edges are *not* filtered out: the resolver
        must still examine them so that their blocking reason (revoked,
        expired, out of scope, ...) stays explainable.  Every edge carries
        its own validity window, so an audit at an earlier query date simply
        sees the edge as authorized again.
        """
        return [r for r in self._relations if r.product_from == product_id]

    def active_edges_leaving(self, product_id, query_date):
        """Subset of edges still active (in force, unrevoked) at the date."""
        return [r for r in self.edges_leaving(product_id, query_date)
                if r.is_active_on(query_date)]

    def revoke(self, relation_id, revoked_at):
        """Revoke a relation while preserving the original record.

        :returns: the revoked copy that replaced the original.
        """
        for index, relation in enumerate(self._relations):
            if relation.relation_id == relation_id:
                revoked = relation.revoke(revoked_at)
                self._relations[index] = revoked
                return revoked
        raise KeyError("unknown relation id: {0}".format(relation_id))

    def conflict_ids_for(self, product_from, product_to):
        return tuple(sorted(self._conflicts.get(
            (product_from, product_to), set())))

    def has_conflict(self, product_from, product_to):
        return bool(self.conflict_ids_for(product_from, product_to))
