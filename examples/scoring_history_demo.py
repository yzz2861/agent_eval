# Copyright (c) 2026 Red Hat, Inc.
# License: LGPLv3+

"""
Scoring-history walk-through for a delayed advisory correction.

The incident below contains:

* one original advisory whose threat indicator (Exploit Code Maturity) later changed;
* two late errata, each updating the single updateable metric ``E``;
* one revocation of the second erratum, which restores the previous value;
* one illegal cross-version reference used to demonstrate provenance of bad data.

Querying one and the same business point in time yields two complete scoring bases:
the basis the on-call team could actually have known then, and the hindsight basis
recomputed with the late events.
"""

from __future__ import print_function

from datetime import datetime

from cvss import CVSSHistoryReferenceError, ScoringHistory

ADVISORY_ID = "CVE-2025-9001"

# Business point in time under review.
BUSINESS_TIME = datetime(2025, 3, 9, 12, 0)


def build_history():
    history = ScoringHistory()

    # Original advisory: no exploit code known yet.
    history.add_advisory(
        ADVISORY_ID,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C",
        known_at=datetime(2025, 3, 1, 9, 0),
        effective_at=datetime(2025, 3, 1, 12, 0),
    )

    # First late correction: PoC appeared, filed four days later but effective
    # retroactively, so it is invisible in the original as-of basis yet affects hindsight.
    history.add_erratum(
        ADVISORY_ID,
        "E",
        "P",
        known_at=datetime(2025, 3, 5, 10, 0),
        effective_at=datetime(2025, 3, 4, 12, 0),
    )

    # Second late correction: functional exploit reported.
    history.add_erratum(
        ADVISORY_ID,
        "E",
        "F",
        known_at=datetime(2025, 3, 12, 10, 0),
        effective_at=datetime(2025, 3, 8, 12, 0),
    )

    # Revocation: the functional-exploit report was unsubstantiated. Its effective time
    # matches the revoked erratum so the metric falls back to E:P for every reconstruction.
    second_erratum_id = history.events[-1].event_id
    history.add_revocation(
        ADVISORY_ID,
        second_erratum_id,
        known_at=datetime(2025, 3, 15, 9, 0),
        effective_at=datetime(2025, 3, 8, 12, 0),
    )

    return history


def print_basis(title, basis):
    print(title)
    print("  vector:      {0}".format(basis.vector))
    print("  scores:      {0}".format(basis.scores))
    print("  severities:  {0}".format(basis.severities))
    print("  applied:     {0}".format(", ".join(basis.applied_event_ids)))
    print("  revoked:     {0}".format(", ".join(basis.revoked_event_ids) or "-"))
    print("  provenance:  {0}".format(basis.metric_provenance))
    print()


def main():
    history = build_history()

    print("Incident events for {0}".format(ADVISORY_ID))
    for event in history.events:
        print(
            "  {0:10s} {1:28s} known={2}  effective={3}  payload={4}".format(
                event.event_type,
                event.event_id,
                event.known_at.isoformat(),
                event.effective_at.isoformat(),
                event.vector or "{0}:{1}".format(event.metric, event.value),
            )
        )
    print()

    # Basis 1: what the on-call team could have known on 2025-03-03.
    as_of_basis = history.as_of(
        ADVISORY_ID, known_at=datetime(2025, 3, 3, 12, 0), effective_at=BUSINESS_TIME
    )

    # Basis 2: the same business time recomputed with every event filed afterwards.
    hindsight_basis = history.hindsight(ADVISORY_ID, BUSINESS_TIME)

    print_basis("Basis 1 - as_of (knowledge available on 2025-03-03)", as_of_basis)
    print_basis("Basis 2 - hindsight (all late events, second erratum revoked)", hindsight_basis)

    assert as_of_basis.scores[1] == 8.5
    assert hindsight_basis.scores[1] == 8.8
    assert as_of_basis.vector != hindsight_basis.vector

    # Illegal cross-version reference: a 3.0 correction against a 3.1 advisory.
    try:
        history.add_erratum(
            ADVISORY_ID,
            "E",
            "H",
            known_at=datetime(2025, 3, 16, 9, 0),
            effective_at=datetime(2025, 3, 16, 9, 0),
            reference_prefix="CVSS:3.0",
        )
    except CVSSHistoryReferenceError as exc:
        print(
            "Traced illegal cross-version reference: event={0} advisory={1} referenced={2}".format(
                exc.event_id, exc.advisory_id, exc.referenced_prefix
            )
        )


if __name__ == "__main__":
    main()
