OFFLINE EVIDENCE REVIEW
=======================

The CPE parser and name matching only decide whether two CPE names are
compatible.  They cannot decide whether an asset is actually affected by
an advisory: an asset table may describe firmware, distribution packages,
package components and even physical enclosures with CPE names at the same
product-name layer.  Matching on that layer alone pulls unrelated records
(for example an enclosure) into the remediation scope.

The ``cpe.review`` package adds a fully offline review entry point on top of
the existing parser and ``CPESet2_3`` relation logic.  Every accepted
relation must be backed by an evidence record; a shared product name is
never sufficient.

Relation kinds
-------------

Three relation kinds are collected, each with its own evidence rules:

- ``same``: two CPE names denote the same component identity.  This is the
  only relation allowed to fold identifiers.  Inventory documents may also
  declare explicit identity aliases (``Asset.identity_aliases``), which are
  accepted on the strength of that record rather than name similarity.
- ``contained``: a parent component provably contains a child component.
  The relation is only accepted while every edge of the parent -> child
  chain exists as an explicit inventory parent link, and the walk starts
  from a component directly identified by an advisory.
- ``supplied``: a supplier declaration names a component but no queryable
  component record exists.  It can never confirm an affected asset by
  itself; the asset stays in a manual-review disposition.

Remediation disposition
-----------------------

Each asset receives one of three disposition levels:

- ``actionable``: at least one ``same`` or ``contained`` proof exists.
- ``manual_review``: only ``supplied`` declarations exist.
- ``excluded``: no proof exists.  Name-layer-only records such as
  enclosures are attached as rejecting evidence instead of matches.

Inventory updates and lost proofs
---------------------------------

``InventoryStore`` persists snapshots as JSON without any network access.
When a refreshed snapshot replaces the previous one, ``update_and_diff``
re-runs both reviews and reports every proof that was added or removed.
Removed proofs keep their original evidence and carry an explanation, for
example a containment chain that is no longer fully backed by parent links
or a queryable record that disappeared.

Self-test
---------

Three fictional devices are bundled in ``cpe.review.fixtures.devices``:

- ``gw-alpha-01`` and ``gw-bravo-02`` have queryable firmware, distribution
  and component records plus explicit parent links; alpha also carries a
  same-identity alias.
- ``gw-charlie-03`` has no queryable component record, only a supplier
  declaration, so it is routed to manual review.

Run the self-test offline with::

    python -m cpe.review.cli --snapshot-dir ./review-state
    python -m cpe.review.cli --snapshot-dir ./review-state --update

The unit tests live in ``tests/unit/test_review.py`` and cover all three
relation kinds, identity folding, enclosure rejection and the proof
disappearance diff.
