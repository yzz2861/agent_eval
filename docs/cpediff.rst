Offline exclusion diff
======================

``cpe.cpediff2_3`` compares two CPE 2.3 applicability expressions without
scanning a network or contacting a live instance.  It is intended for the
review question: when a negated branch changes, does the excluded set grow
or shrink, and exactly which device changes ownership?

Semantics
---------

* ``TRUE`` means the device is covered by the announcement.
* ``FALSE`` means the device is excluded from the announcement.
* ``UNKNOWN`` means a value is unknown or an attribute pair is incomparable;
  the device is retained for review instead of being guessed.

A *new exclusion* is ``old covered -> new excluded``.  A *removed exclusion*
is ``old excluded -> new covered``.  The reported ``exclusion_scope`` is
``expanded`` when only new exclusions are found, ``shrunk`` when only removed
exclusions are found, ``mixed`` when both occur, and ``undetermined`` when no
device is decisive but at least one is pending.

Review input
------------

Run the command with an old expression, a new expression, and a JSON review
file::

    python -m cpe.cpediff2_3 --old old.xml --new new.xml --review review.json

A review file contains a finite attribute domain plus devices.  Domain values
bound unconfirmed attributes; devices can either list concrete CPE names::

    {
      "domain": {"version": ["1.0", "1.1", "1.2", "2.0"]},
      "devices": [
        {"id": "edge-1.2",
         "cpes": ["cpe:2.3:o:acme:edge_os:1.2:*:*:*:*:*:*:*"]}
      ]
    }

or state that a field is not yet confirmed::

    {
      "domain": {"version": ["1.0", "1.2", "2.0"]},
      "devices": [
        {"id": "edge-version-unknown",
         "components": [
           {"part": "o", "vendor": "acme", "product": "edge_os",
            "version": null}
         ]}
      ]
    }

For a component object:

* an explicit value is confirmed by default;
* ``null`` or ``"?"`` means the value is unknown and is expanded over the
  finite domain;
* ``unknown`` is a list of attributes to treat as unknown;
* ``confirmed`` is an optional list (strict allowlist) or object (trusted
  value overlay).  A list restricts which supplied fields are trusted; an
  object adds or overrides confirmed values.  With an explicit allowlist, a
  field that appears in the finite domain but is not confirmed is treated as
  unknown and expanded, even when it is omitted from the component.

An unconfirmed attribute with no finite domain, a value that expands to too
many candidates, or an expression result that is still unknown after
expansion is reported under ``pending_reasons``.  A device is also pending
when different completions of its unknown fields produce different
transitions; the report includes one witness per distinct outcome under
``variants``.

Matching details
----------------

The evaluator walks the same ``cpe:logical-test`` / ``cpe:fact-ref`` tree as
``CPELanguage2_3``.  Attribute relations come from
``CPESet2_3.compare_wfns`` (``equal``, ``superset``, ``subset``, ``disjoint``,
``undefined``).  A fact-ref is true when at least one device component is a
non-proper superset.  Logical tests use three-valued AND, OR, and NOT: a
disjoint attribute is a definite false, while ``subset`` or ``undefined``
leaves the branch unknown.  This keeps ``UNKNOWN`` from being silently
converted into a non-match.

Output
------

The default text output contains a one-line conclusion, the expression delta,
and per-device witnesses.  For each changed device it prints the exact old and
new evaluation expression, so the ownership change can be recomputed by hand.
JSON output is available with ``--format json`` and contains the same
information plus full paths, WFN components, relation buckets, and traces.

Demo
----

``examples/cpe_diff`` contains two expressions that differ in exactly one
negated branch (an extra ``1.2`` fact-ref).  The review contains four concrete
devices and one device with an unconfirmed version::

    python -m cpe.cpediff2_3 --old examples/cpe_diff/old.xml \
      --new examples/cpe_diff/new.xml \
      --review examples/cpe_diff/review.json

Expected result: ``edge-1.2`` is the only new exclusion; ``edge-1.0`` and
``edge-1.1`` stay excluded; ``edge-2.0`` stays covered; and
``edge-version-unconfirmed`` stays pending because its version can produce
more than one outcome inside the supplied domain.
