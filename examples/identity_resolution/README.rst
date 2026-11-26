Import-time identity resolution
===============================

This example replays a case-file merge in which ticket numbers were reused.
Both ``case_alpha`` and ``case_beta`` carry an object whose STIX identifier is
``identity--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa``.  The review batch adds a
revoked duplicate, and the legacy event bundle still refers to the duplicated
identifier on both sides of a Relationship.

The import service keeps:

* candidate occupancy for every identifier;
* an auditable anchor for each analyst-confirmed decision;
* the batch provenance, review flag, and version of every candidate.

Resolution applies anchors first, then the sole-candidate, review, version,
and batch rules.  It reports ``ambiguous`` rather than choosing arbitrarily.
Incoming objects may be ingested in any order, and snapshots restore the same
attachment decisions.

Run the replay::

    python examples/identity_resolution/replay.py
