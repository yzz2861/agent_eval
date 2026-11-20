Enterprise alias arbitration
===========================

An in-memory enterprise ruling layer that runs *before* the CPE name
matching algorithm (``cpe.cpeset2_3.CPESet2_3``). It never opens a
database and never contacts an online bulletin source.

Concepts
--------

* ``AliasRelation`` - an explicit, directed product alias edge. Every edge
  records its ``source``, ``business_scope`` and a closed validity window
  (``valid_from`` / ``valid_to``), plus an optional ``revoked_at`` date.
* ``AliasRegistry`` - stores relations, rejects bare ``*`` scopes and empty
  scopes up front, and raises ``RelationConflict`` when two active relations
  disagree on the same ordered product pair.
* ``AliasResolver`` - walks the alias graph. Each crossed edge is
  re-validated independently for the querying unit and date, so a
  cross-source chain only succeeds when *every* edge authorizes it.
* ``EnterpriseArbitrator`` - first applies the original CPE equivalence
  judgement unchanged; only when that fails does it consult the alias graph.

Classifications (``Disposition``)
---------------------------------

``direct_match``, ``alias_match``, ``no_match`` and the explainable blocked
classes ``blocked_scope`` (including unauthorized wildcard scopes),
``blocked_expired``, ``blocked_revoked`` and ``blocked_conflict``. Every
result carries the contributing relation ids and the exact chain, so an
auditor can trace why a bulletin did or did not match.

Evidence merging
----------------

Assets that normalize to the same WFN key merge their supporting asset ids
and relation ids behind one evidence entry. The merge never adds a product
or scope that was not matched on its own merits.

Audit replay
------------

Relations are retained (never deleted) on revocation. Passing an earlier
``query_date`` to ``run_match`` re-evaluates every edge as of that date, so
a chain that is currently revoked can still be reconstructed for the period
when it was in force.

Demo
----

Run ``python examples/alias_arbitration_demo.py`` for a worked example with
two small asset books, scope narrowing on renewal, cross-source chains,
revocation and historical replay. Unit tests live in
``tests/unit/test_alias_arbitration.py``.
