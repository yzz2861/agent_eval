import pytest

import stix2
from stix2.imports import (
    AmbiguousCandidateError, AnchorError, ImportService, ResolutionStatus,
)


IDENTITY_ID = "identity--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
INDICATOR_ID = "indicator--bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
RELATIONSHIP_ID = "relationship--cccccccc-cccc-4ccc-8ccc-cccccccccccc"


def record(
    stix_id,
    name,
    modified,
    external_id=None,
    revoked=False,
    stix_type="identity",
):
    obj = {
        "type": stix_type,
        "spec_version": "2.1",
        "id": stix_id,
        "created": modified,
        "modified": modified,
        "name": name,
    }
    if stix_type == "relationship":
        obj.update({
            "relationship_type": "targets",
            "source_ref": INDICATOR_ID,
            "target_ref": IDENTITY_ID,
        })
    if revoked:
        obj["revoked"] = True
    if external_id is not None:
        obj["external_references"] = [{
            "source_name": "legacy",
            "external_id": external_id,
        }]
    return obj


def relationship(modified):
    return record(
        RELATIONSHIP_ID,
        "legacy event",
        modified,
        external_id="EVT-1",
        stix_type="relationship",
    )


def build(*items):
    service = ImportService()
    for batch, obj in items:
        service.ingest(obj, batch=batch)
    return service


def duplicate_identities():
    return (
        ("case-alpha", record(IDENTITY_ID, "Acme old", "2024-02-10T00:00:00Z", "TKT-42")),
        ("case-beta", record(IDENTITY_ID, "Acme new", "2024-05-20T00:00:00Z", "TKT-42")),
    )


def test_ingest_is_idempotent_and_occupancy_tracks_claims():
    old = record(IDENTITY_ID, "Acme old", "2024-02-10T00:00:00Z", "TKT-42")
    service = build(("case-alpha", old), ("case-alpha", old))

    assert len(service) == 1
    slot = service.occupancy(IDENTITY_ID)[0]
    assert len(slot.candidates) == 1
    assert not slot.conflicted

    service.ingest(record(IDENTITY_ID, "Acme other", "2024-05-20T00:00:00Z", "TKT-42"), batch="case-beta")
    slot = service.occupancy(IDENTITY_ID)[0]
    assert len(slot.candidates) == 2
    assert not slot.conflicted  # different versions are legitimate


def test_stix_objects_can_be_ingested_directly():
    obj = stix2.v21.Identity(
        id=IDENTITY_ID,
        created="2024-02-10T00:00:00Z",
        modified="2024-02-10T00:00:00Z",
        name="Acme",
        identity_class="organization",
        external_references=[{"source_name": "legacy", "external_id": "TKT-42"}],
    )
    service = ImportService()
    service.ingest(obj, batch="case-alpha")

    resolution = service.resolve("TKT-42")
    assert resolution.candidate.stix_id == IDENTITY_ID


def test_same_version_different_content_is_an_occupancy_conflict():
    service = build(
        ("case-alpha", record(IDENTITY_ID, "Acme", "2024-02-10T00:00:00Z")),
        ("case-beta", record(IDENTITY_ID, "Acme alias", "2024-02-10T00:00:00Z")),
    )

    slot = service.occupancy(IDENTITY_ID)[0]
    assert slot.conflicted
    assert len(slot.occupants) == 2
    assert slot.occupants == tuple(sorted(slot.occupants))
    assert len(service.collisions()) == 1

    resolution = service.resolve(IDENTITY_ID)
    assert resolution.status is ResolutionStatus.AMBIGUOUS
    assert len(resolution.candidates) == 2


def test_alias_lookup_and_unique_candidate():
    service = build(
        ("case-alpha", record(IDENTITY_ID, "Acme", "2024-02-10T00:00:00Z", "TKT-42")),
    )

    assert [candidate.stix_id for candidate in service.candidates("TKT-42")] == [IDENTITY_ID]
    assert "legacy:TKT-42" in service.references()
    assert service.resolve("TKT-42").candidate.batch == "case-alpha"


def test_anchor_alias_wins_then_revoke_reassigns_via_version_window():
    service = build(*duplicate_identities())
    referrer = relationship("2024-03-05T00:00:00Z")

    before = service.attach(referrer, references=[IDENTITY_ID])
    assert before.references[IDENTITY_ID].candidate.batch == "case-alpha"
    assert before.references[IDENTITY_ID].reason == "version-window"

    beta = next(c for c in service.candidates("TKT-42") if c.batch == "case-beta")
    service.confirm_anchor(
        "TKT-42", candidate=beta, confirmed_by="analyst",
        confirmed_at="2024-07-01T00:00:00Z",
    )
    anchored = service.resolve(IDENTITY_ID, referrer=referrer)
    assert anchored.candidate.batch == "case-beta"
    assert anchored.reason == "anchor"

    service.revoke_anchor("TKT-42", revoked_by="reviewer", revoked_at="2024-07-02T00:00:00Z")
    after = service.resolve(IDENTITY_ID, referrer=referrer)
    assert after.candidate.batch == "case-alpha"
    assert after.reason == "version-window"


def test_review_flag_removes_revoked_duplicate():
    service = build(
        ("case-alpha", record(IDENTITY_ID, "Acme", "2024-02-10T00:00:00Z", "TKT-42")),
        (
            "case-review",
            record(IDENTITY_ID, "Acme rejected", "2024-04-10T00:00:00Z", "TKT-42", revoked=True),
        ),
    )

    resolution = service.resolve("TKT-42", version="2024-04-15T00:00:00Z")
    assert resolution.status is ResolutionStatus.UNIQUE
    assert resolution.candidate.batch == "case-alpha"
    assert resolution.reason == "review-flag"


def test_all_revoked_is_reported_not_silently_attached():
    service = build(
        ("case-a", record(IDENTITY_ID, "Acme a", "2024-01-01T00:00:00Z", revoked=True)),
        ("case-b", record(IDENTITY_ID, "Acme b", "2024-02-01T00:00:00Z", revoked=True)),
    )

    resolution = service.resolve(IDENTITY_ID)
    assert resolution.status is ResolutionStatus.REVOKED
    assert resolution.candidate is None


def test_version_visibility_selects_the_representative_version():
    service = build(
        ("case-alpha", record(IDENTITY_ID, "Acme v1", "2024-01-01T00:00:00Z")),
        ("case-alpha", record(IDENTITY_ID, "Acme v2", "2024-04-01T00:00:00Z")),
    )

    early = service.resolve(IDENTITY_ID, version="2024-02-01T00:00:00Z")
    late = service.resolve(IDENTITY_ID, version="2024-06-01T00:00:00Z")
    assert early.candidate.version.isoformat() == "2024-01-01T00:00:00+00:00"
    assert late.candidate.version.isoformat() == "2024-04-01T00:00:00+00:00"


def test_batch_provenance_decides_an_otherwise_tied_attachment():
    service = build(*duplicate_identities())

    resolution = service.resolve(
        IDENTITY_ID, version="2024-06-01T00:00:00Z", batch="case-beta",
    )
    assert resolution.status is ResolutionStatus.UNIQUE
    assert resolution.candidate.batch == "case-beta"
    assert resolution.reason == "batch"


def test_attach_resolves_both_sides_on_compatible_versions():
    service = build(
        ("case-alpha", record(IDENTITY_ID, "Acme old", "2024-02-10T00:00:00Z", "TKT-42")),
        ("case-beta", record(IDENTITY_ID, "Acme new", "2024-05-20T00:00:00Z", "TKT-42")),
        ("case-alpha", record(INDICATOR_ID, "Lure old", "2024-02-11T00:00:00Z", "TKT-43", stix_type="indicator")),
        ("case-beta", record(INDICATOR_ID, "Lure new", "2024-05-21T00:00:00Z", "TKT-43", stix_type="indicator")),
    )

    early = service.attach(relationship("2024-03-05T00:00:00Z"))
    assert early.unique
    assert {target.batch for target in early.targets.values()} == {"case-alpha"}

    late = service.attach(
        relationship("2024-06-05T00:00:00Z"), batch="case-beta",
    )
    assert late.unique
    assert {target.batch for target in late.targets.values()} == {"case-beta"}


def test_ambiguous_is_reported_without_guessing():
    service = build(*duplicate_identities())

    resolution = service.resolve(IDENTITY_ID, version="2024-06-01T00:00:00Z")
    assert resolution.status is ResolutionStatus.AMBIGUOUS
    assert resolution.candidate is None
    assert [candidate.batch for candidate in resolution.candidates] == ["case-alpha", "case-beta"]


def test_conflicting_anchors_are_ambiguous():
    service = build(*duplicate_identities())
    alpha, beta = service.candidates("TKT-42")
    service.confirm_anchor("TKT-42", candidate=alpha, confirmed_by="analyst-a")
    service.confirm_anchor("TKT-42", candidate=beta, confirmed_by="analyst-b")

    resolution = service.resolve("TKT-42")
    assert resolution.status is ResolutionStatus.AMBIGUOUS
    assert resolution.reason == "conflicting-anchors"


def test_anchor_can_assign_a_reference_that_no_candidate_lists():
    service = build(*duplicate_identities())
    beta = next(c for c in service.candidates("TKT-42") if c.batch == "case-beta")
    service.confirm_anchor("TKT-999", candidate=beta, confirmed_by="analyst")

    resolution = service.resolve("TKT-999")
    assert resolution.status is ResolutionStatus.UNIQUE
    assert resolution.candidate.batch == "case-beta"
    assert resolution.reason == "anchor"


def test_anchor_to_an_archived_branch_is_not_silently_moved():
    service = build(*duplicate_identities())
    beta = next(c for c in service.candidates("TKT-42") if c.batch == "case-beta")
    service.confirm_anchor("TKT-42", candidate=beta, confirmed_by="analyst")
    service.archive("case-beta")

    resolution = service.resolve("TKT-42")
    assert resolution.status is ResolutionStatus.UNRESOLVED
    assert resolution.reason == "archived-anchor"


def test_anchor_requires_an_explicit_analyst_and_candidate():
    service = build(*duplicate_identities())

    with pytest.raises(ValueError):
        service.confirm_anchor("TKT-42", candidate=service.candidates("TKT-42")[0], confirmed_by="")

    with pytest.raises(AmbiguousCandidateError):
        service.confirm_anchor("TKT-42", confirmed_by="analyst")

    with pytest.raises(AnchorError):
        service.revoke_anchor("TKT-42")


def test_archive_branch_changes_candidates_and_survives_snapshot():
    service = build(*duplicate_identities())
    referrer = relationship("2024-03-05T00:00:00Z")

    service.archive("case-alpha")
    archived = service.attach(referrer, references=[IDENTITY_ID])
    assert archived.references[IDENTITY_ID].candidate.batch == "case-beta"
    assert service.archived_batches == ("case-alpha",)

    restored = ImportService.restore(service.snapshot())
    assert restored.archived_batches == ("case-alpha",)
    assert restored.attach(referrer, references=[IDENTITY_ID]).to_dict() == archived.to_dict()

    service.unarchive("case-alpha")
    assert service.resolve(IDENTITY_ID, referrer=referrer).candidate.batch == "case-alpha"


def test_reordered_ingest_and_snapshot_restore_are_deterministic():
    items = (
        *duplicate_identities(),
        ("case-alpha", record(INDICATOR_ID, "Lure old", "2024-02-11T00:00:00Z", "TKT-43", stix_type="indicator")),
        ("case-beta", record(INDICATOR_ID, "Lure new", "2024-05-21T00:00:00Z", "TKT-43", stix_type="indicator")),
    )
    forward = build(*items)
    reverse = build(*reversed(items))
    referrer = relationship("2024-03-05T00:00:00Z")

    assert forward.snapshot() == reverse.snapshot()
    assert forward.attach(referrer).to_dict() == reverse.attach(referrer).to_dict()

    restored = ImportService.restore(forward.snapshot())
    assert restored.attach(referrer).to_dict() == forward.attach(referrer).to_dict()


def test_replay_confirms_then_revokes_and_reassigns():
    service = build(*duplicate_identities())
    beta = next(c for c in service.candidates("TKT-42") if c.batch == "case-beta")
    referrer = relationship("2024-03-05T00:00:00Z")

    steps = service.replay(
        [
            {
                "action": "confirm",
                "reference": "TKT-42",
                "candidate": beta.key,
                "by": "analyst",
                "at": "2024-07-01T00:00:00Z",
            },
            {
                "action": "revoke",
                "reference": "TKT-42",
                "by": "reviewer",
                "at": "2024-07-02T00:00:00Z",
            },
        ],
        referrer=referrer,
    )

    assert [step.action for step in steps] == ["confirm", "revoke"]
    assert steps[0].resolution.candidate.batch == "case-beta"
    assert steps[0].resolution.reason == "anchor"
    assert steps[1].resolution.candidate.batch == "case-alpha"
    assert steps[1].resolution.reason == "version-window"
