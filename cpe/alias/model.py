"""
Enterprise-side alias arbitration data model.

This module is deliberately self-contained: it only depends on the standard
library and the :mod:`cpe` package.  It never opens a database and never
reaches out to an online bulletin source.

An :class:`AliasRelation` is an *explicit* statement recorded by the
enterprise.  Every relation carries the three pieces of evidence required by
the arbitration policy:

* ``source``      - who recorded / signed the alias agreement;
* ``business_scope`` - the business units for which the alias is licensed;
* ``valid_from`` / ``valid_to`` - the closed validity interval.

A relation is a directed edge ``product_from -> product_to``.  Alias chains
are reconstructed by walking these edges.  Every edge keeps its own
authorization, so a chain that crosses sources is only usable when *each*
edge on the chain is independently authorized for the querying unit.
"""

from collections import namedtuple
from datetime import date


#: Wildcard token used inside a business scope.  It is *not* an implicit
#: grant: an edge whose scope contains a wildcard only authorizes units that
#: additionally match the (explicit) prefix of that wildcard entry.
SCOPE_WILDCARD = "*"


class EdgeStatus(object):
    """Lifecycle states of an alias edge, recorded for audit purposes."""

    #: The edge is part of the active alias agreement.
    ACTIVE = "active"

    #: The edge was explicitly revoked.  Historical queries before
    #: ``revoked_at`` still see it as active.
    REVOKED = "revoked"


class Disposition(object):
    """Explainable classification emitted for every bulletin / asset pair.

The prefix groups make the audit log easy to filter:

* ``DIRECT_*`` - the original CPE equivalence judgement, untouched;
* ``ALIAS_*``  - matches that only exist because of an authorized alias;
* ``BLOCKED_*`` - alias attempts that were refused and why.
"""

    #: Matched through the original CPE name-equivalence judgement.
    DIRECT_MATCH = "direct_match"

    #: No direct CPE match and no usable alias path.
    NO_MATCH = "no_match"

    #: Matched through one or more fully authorized alias edges.
    ALIAS_MATCH = "alias_match"

    #: An edge on the only available path is outside the querying unit's
    #: business scope (includes unauthorized wildcard scopes).
    BLOCKED_SCOPE = "blocked_scope"

    #: An edge on the only available path is not valid on the query date.
    BLOCKED_EXPIRED = "blocked_expired"

    #: An edge on the only available path was revoked before the query date.
    BLOCKED_REVOKED = "blocked_revoked"

    #: Two relations disagree about the same ordered product pair.
    BLOCKED_CONFLICT = "blocked_conflict"


# Reason codes attached to a single traversed edge.
class EdgeReason(object):
    """Per-edge classification used while walking an alias chain."""

    AUTHORIZED = "authorized"
    OUT_OF_SCOPE = "out_of_scope"
    UNAUTHORIZED_WILDCARD = "unauthorized_wildcard"
    EXPIRED = "expired"
    NOT_YET_VALID = "not_yet_valid"
    REVOKED = "revoked"
    CONFLICT = "conflict"


class ScopeViolation(ValueError):
    """Raised when a relation is registered with an illegal wildcard scope."""


class RelationConflict(ValueError):
    """Raised when two contradictory explicit relations are registered."""


def _as_date(value):
    """Accept ``datetime.date`` or ISO ``YYYY-MM-DD`` strings."""
    if value is None:
        return None
    if isinstance(value, date):
        return value
    return date.fromisoformat(value)


def scope_allows(scope, business_unit):
    """Return whether ``business_unit`` is authorized by ``scope``.

    A scope is a list of explicit unit names and optional wildcard entries.
    A wildcard entry has the form ``"prefix*"`` and only authorizes units
    starting with ``prefix``.  A bare ``"*"`` would grant every unit and is
    therefore rejected at registration time, so it can never silently widen
    the applicability of an alias.
    """
    for entry in scope:
        if entry == business_unit:
            return True
        if entry.endswith(SCOPE_WILDCARD):
            prefix = entry[:-1]
            if prefix and business_unit.startswith(prefix):
                return True
    return False


def scope_has_bare_wildcard(scope):
    """A bare ``*`` means "every unit" and is not a defensible grant."""
    return SCOPE_WILDCARD in scope


class AliasRelation(namedtuple(
        "AliasRelation",
        ["relation_id", "product_from", "product_to", "source",
         "business_scope", "valid_from", "valid_to",
         "revoked_at", "status", "recorded_at"])):
    """An immutable, fully-evidenced directed alias edge.

    Construct instances through :meth:`create` so that wildcard scope and
    date arguments are validated consistently.
    """

    __slots__ = ()

    @classmethod
    def create(cls, relation_id, product_from, product_to, source,
               business_scope, valid_from, valid_to,
               revoked_at=None, status=EdgeStatus.ACTIVE, recorded_at=None):
        scope = tuple(business_scope)
        if scope_has_bare_wildcard(scope):
            raise ScopeViolation(
                "relation {0} uses a bare '*' scope, which would grant every "
                "business unit; record explicit units or prefix wildcards "
                "instead".format(relation_id))
        if not scope:
            raise ScopeViolation(
                "relation {0} has an empty business scope".format(relation_id))

        start = _as_date(valid_from)
        end = _as_date(valid_to)
        if start is None:
            raise ValueError("relation {0} needs a valid_from date".format(
                relation_id))
        if end is not None and end < start:
            raise ValueError(
                "relation {0} valid_to precedes valid_from".format(
                    relation_id))

        return cls(
            relation_id=relation_id,
            product_from=product_from,
            product_to=product_to,
            source=source,
            business_scope=scope,
            valid_from=start,
            valid_to=end,
            revoked_at=_as_date(revoked_at),
            status=status,
            recorded_at=_as_date(recorded_at) or start)

    def revoke(self, revoked_at):
        """Return a revoked copy.  The original record is never mutated."""
        return self._replace(
            status=EdgeStatus.REVOKED, revoked_at=_as_date(revoked_at))

    def is_active_on(self, query_date):
        """Lifecycle check ignoring business scope."""
        query_date = _as_date(query_date)
        if query_date < self.valid_from:
            return False
        if self.valid_to is not None and query_date > self.valid_to:
            return False
        if (self.status == EdgeStatus.REVOKED and
                self.revoked_at is not None and
                query_date >= self.revoked_at):
            return False
        return True

    def edge_verdict(self, business_unit, query_date):
        """Classify this single edge for ``business_unit`` at ``query_date``.

        Returns a tuple ``(allowed, reason)``.  ``allowed`` is only True when
        the edge is simultaneously in its validity window, unrevoked and
        inside the unit's authorized scope.
        """
        query_date = _as_date(query_date)

        if (self.status == EdgeStatus.REVOKED and
                self.revoked_at is not None and
                query_date >= self.revoked_at):
            return False, EdgeReason.REVOKED
        if query_date < self.valid_from:
            return False, EdgeReason.NOT_YET_VALID
        if self.valid_to is not None and query_date > self.valid_to:
            return False, EdgeReason.EXPIRED

        # Scope last: distinguish an explicit-but-foreign unit from an
        # unauthorized wildcard so the bulletin log stays explainable.
        if business_unit in self.business_scope:
            return True, EdgeReason.AUTHORIZED
        for entry in self.business_scope:
            if entry.endswith(SCOPE_WILDCARD):
                prefix = entry[:-1]
                if prefix and business_unit.startswith(prefix):
                    return True, EdgeReason.AUTHORIZED
        if any(entry.endswith(SCOPE_WILDCARD)
               for entry in self.business_scope):
            return False, EdgeReason.UNAUTHORIZED_WILDCARD
        return False, EdgeReason.OUT_OF_SCOPE


class Evidence(namedtuple(
        "Evidence", ["asset_id", "book_id", "cpe_name", "product_name"])):
    """A single piece of supporting evidence for a normalized CPE."""

    __slots__ = ()


class MatchResult(namedtuple(
        "MatchResult",
        ["bulletin_id", "asset_id", "book_id", "normalized_cpe",
         "disposition", "reasons", "chain", "evidence"])):
    """Explainable outcome of matching one bulletin against one asset.

    ``chain`` holds the ordered relation ids that produced an alias match
    (empty for direct matches).  ``reasons`` carries per-edge reason codes so
    a blocked result can be traced back to the exact edge that refused it.
    ``evidence`` lists the assets merged behind a shared normalized CPE.
    """

    __slots__ = ()

    @property
    def matched(self):
        return self.disposition in (
            Disposition.DIRECT_MATCH, Disposition.ALIAS_MATCH)

    def explain(self):
        """Return a compact, human-readable audit line."""
        parts = [
            "bulletin={0}".format(self.bulletin_id),
            "asset={0}".format(self.asset_id),
            "cpe={0}".format(self.normalized_cpe),
            "class={0}".format(self.disposition),
        ]
        if self.chain:
            parts.append("chain={0}".format("->".join(self.chain)))
        if self.reasons:
            parts.append("reasons={0}".format(",".join(self.reasons)))
        if len(self.evidence) > 1:
            parts.append("merged_evidence={0}".format(
                ",".join(sorted(item.asset_id for item in self.evidence))))
        return " ".join(parts)


class MatchEvidence(namedtuple(
        "MatchEvidence",
        ["kind", "asset_id", "product_id", "bulletin_id",
         "normalized_asset_cpe", "normalized_bulletin_cpe",
         "relation_ids", "chain", "reason"])):
    """Explainable evidence attached to a bulletin classification.

    ``kind`` is one of the :class:`Disposition` values.  ``relation_ids``
    and ``chain`` stay empty for a direct CPE match and carry the exact
    alias edges for an alias match or a blocked alias attempt.
    """

    __slots__ = ()

    def explain(self):
        parts = [
            "bulletin={0}".format(self.bulletin_id),
            "asset={0}".format(self.asset_id),
            "class={0}".format(self.kind),
            "reason={0}".format(self.reason),
        ]
        if self.chain:
            parts.append("chain={0}".format("->".join(self.chain)))
        return " ".join(parts)
