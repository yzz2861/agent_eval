"""Enterprise alias graph resolution with per-edge authorization.

The resolver never invents equivalences.  It only follows explicit
AliasRelation edges, re-validating every crossed edge against the
requesting business unit and the query date.  A chain crossing several
sources is therefore only usable when each edge independently grants
permission to the querying unit.
"""

from collections import namedtuple

from .model import EdgeReason


# An edge examined while walking the graph, together with its verdict.
EdgeAttempt = namedtuple(
    "EdgeAttempt", ["edge", "allowed", "reason"])

# A complete path whose every edge was authorized.
AuthorizedChain = namedtuple("AuthorizedChain", ["edges", "target_product"])


class Resolution(namedtuple("Resolution", [
        "start_product", "reached", "chains", "attempts"])):
    """Outcome of an alias graph walk for one starting product."""

    @property
    def reached_products(self):
        return tuple(self.reached)

    def chain_to(self, target_product):
        for chain in self.chains:
            if chain.target_product == target_product:
                return chain
        return None


class AliasResolver(object):
    """Walks the alias graph, authorizing every crossed edge."""

    def __init__(self, registry):
        self.registry = registry

    def resolve(self, product_from, business_unit, query_date):
        """Return every product reachable from ``product_from`` via edges
        that each independently authorize ``business_unit`` at the date."""
        reached = []
        chains = []
        attempts = []
        visited_pairs = set()
        self._walk(product_from, business_unit, query_date, [],
                    reached, chains, attempts, visited_pairs)
        return Resolution(
            start_product=product_from,
            reached=tuple(reached),
            chains=tuple(chains),
            attempts=tuple(attempts))

    def _walk(self, current_product, business_unit, query_date, edges_so_far,
              reached, chains, attempts, visited_pairs):
        for edge in self.registry.edges_leaving(current_product, query_date):
            pair = (edge.relation_id, edge.product_to)
            if pair in visited_pairs:
                continue
            visited_pairs.add(pair)

            allowed, reason = edge.edge_verdict(business_unit, query_date)
            attempts.append(EdgeAttempt(edge=edge, allowed=allowed, reason=reason))
            if not allowed:
                continue

            chain_edges = edges_so_far + [edge]
            target = edge.product_to
            if target not in reached:
                reached.append(target)
            chains.append(AuthorizedChain(
                edges=tuple(chain_edges), target_product=target))
            self._walk(target, business_unit, query_date, chain_edges,
                        reached, chains, attempts, visited_pairs)

    @staticmethod
    def worst_reason(attempts):
        """Pick the most security-relevant blocked reason for reporting."""
        priority = (
            EdgeReason.CONFLICT,
            EdgeReason.REVOKED,
            EdgeReason.EXPIRED,
            EdgeReason.NOT_YET_VALID,
            EdgeReason.UNAUTHORIZED_WILDCARD,
            EdgeReason.OUT_OF_SCOPE,
        )
        reasons = [attempt.reason for attempt in attempts if not attempt.allowed]
        for candidate in priority:
            if candidate in reasons:
                return candidate
        return EdgeReason.OUT_OF_SCOPE
