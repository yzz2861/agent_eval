Entity Merge Reconciliation
===========================

Before building an offline archive, identifiers that may denote the same
entity can be reconciled without silently collapsing uncertain pairs.

Merge evidence is treated as an equivalence relation.  Explicit separations,
such as legal holds, are hard constraints.  If a chain of merge evidence
contradicts a separation, the smallest conflicting assertion set is reported
and every maximal compatible grouping is returned.

.. code-block:: python

    from stix2.equivalence.merge import reconcile_entity_merges

    report = reconcile_entity_merges(
        positive=[("A", "B"), ("B", "C")],
        negative=[("A", "C")],
    )

    print(report["status"])                 # ambiguous
    print(report["minimal_conflicts"][0]["pairs"])
    # [[A, B], [B, C], [A, C]]
    print(report["partitions"])
    # [[[A], [B, C]], [[A, B], [C]]]
    print(report["still_valid_merges"])
    # [[A, B], [B, C]]

The two direct merges remain individually possible, but they cannot both hold
at once.  No single grouping is selected.  Pairs with no evidence are listed in
``undetermined_pairs`` rather than being declared distinct.

Purposes
--------

Assertions may be scoped to a purpose.  Unscoped assertions apply to every
purpose.  A per-purpose report and a combined report are both returned.

.. code-block:: python

    report = reconcile_entity_merges(
        [
            {"left": "A", "right": "B", "purpose": "analysis"},
            {"left": "B", "right": "C", "purpose": "analysis"},
            {"left": "A", "right": "C", "relation": "separate", "purpose": "legal"},
        ],
    )

    print(report["by_purpose"]["analysis"]["groups"])  # [[A, B, C]]
    print(report["combined_consistent"])               # False

STIX input
----------

Relationships with ``same-as`` or ``equivalent-to`` contribute merge evidence;
``different-from`` or ``distinct-from`` contribute separations.  Bundles,
lists, and data stores can be supplied through ``objects``.
