Collection-plan coverage pre-check
==================================

The :mod:`cpe.coverage` module answers a question that ordinary CPE name
matching does not: *given an advisory CPE range and a set of collection
channels, which part of the advisory can the plan actually assert, and what
observation is missing elsewhere?*

The pre-check is deliberately conservative.  A channel can assert an
advisory range only when both conditions hold:

* the channel applies to the relevant assets (the advisory range and the
  channel scope overlap), and
* the channel can prove every CPE attribute constrained by the advisory.

``part`` is treated as structural (the asset class), not as an observation
field.  A collector that proves only ``vendor`` and ``product`` can
therefore assert::

    cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*

but cannot assert::

    cpe:2.3:a:acme:widget:4.2:*:*:*:*:*:*:*

because the latter requires a ``version`` observation.  Adding more
collectors of the first kind does not change that verdict.

Inputs
------

An advisory range is any CPE 2.3 name (WFN, URI or formatted string).  A
channel has a name, the fields it can prove, and the CPE range of assets to
which it applies.  Exclusions are CPE ranges that are explicitly out of
scope.

.. code-block:: python

    from cpe.coverage import CollectionChannel, precheck_coverage

    report = precheck_coverage(
        advisories=[
            "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
            "cpe:2.3:a:acme:widget:4.2:*:*:*:*:*:*:*",
        ],
        channels=[
            CollectionChannel(
                "endpoint-inventory",
                fields=["vendor", "product"],
                assets="cpe:2.3:a:*:*:*:*:*:*:*:*:*:*",
            ),
        ],
        exclusions=[
            "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*",
        ],
    )

    report.asserted_ranges
    # ("cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",)

    report.unclear[0].missing_observations
    # ("version",)

Overlap and exclusions
----------------------

Channel coverage is unioned, so overlapping channels do not double-count or
create duplicate asserted ranges.  Explicit exclusions are unioned first and
then deducted from that merged coverage ("merge, then deduct").  A range
that is fully excluded is reported with status ``"excluded"`` and is not a
coverage gap.

When an advisory range is not fully asserted, the diagnostics distinguish:

* a missing observation field such as ``version`` or ``update``, and
* a missing asset-scope observation, reported as ``asset_scope``.

Evidence is not joined across different collectors.  If one collector sees
``vendor``/``product`` and another sees only ``version``, the plan cannot
assume the two observations describe the same CPE name; a single channel
must prove the complete required field set.

Result objects
--------------

``precheck_coverage`` returns a :class:`~cpe.coverage.CoverageReport`.  Each
advisory has an :class:`~cpe.coverage.AdvisoryCoverage` verdict with:

* ``status``: ``"asserted"``, ``"unclear"`` or ``"excluded"``;
* ``missing_observations``: field names, or ``"asset_scope"``;
* ``asserted_ranges`` and ``unclear_ranges``;
* ``channels`` that overlap the advisory; and
* ``reason`` and ``partial`` details.

``CoverageReport.complete`` is true when every advisory is either asserted
or explicitly excluded.

The existing CPE 2.3 string comparison behavior (``CPE.__eq__``,
``CPESet2_3.cpe_*`` and ``CPESet2_3.name_match``) is unchanged.  The
coverage layer normalises ranges to WFN internally and uses its own
range-algebra for union, intersection and subtraction.
