import pytest

from bleach.review import (
    ContentFragment,
    OfflinePublicationReview,
    SANITIZED,
    UNRESOLVED_REFERENCE,
    WITHDRAWN_APPROVAL,
)


def test_three_source_document_tracks_shared_reference_withdrawal():
    review = OfflinePublicationReview()
    review.grant_approval(
        reviewer="legal",
        sources={"alpha", "beta"},
        reader_domains={"internal"},
        approval_id="legal-core",
    )
    review.grant_approval(
        reviewer="legal",
        sources={"gamma"},
        reader_domains={"internal"},
        approval_id="legal-gamma",
    )
    review.grant_approval(
        reviewer="external_editor",
        sources={"alpha", "beta", "gamma"},
        reader_domains={"internal", "public"},
        approval_id="editor-core",
    )

    fragments = [
        ContentFragment(
            fragment_id="f1",
            source="alpha",
            reader_domain="internal",
            html="<p>Alpha introduction</p>",
            references=("f2", "f3"),
        ),
        ContentFragment(
            fragment_id="f2",
            source="beta",
            reader_domain="internal",
            html="<strong>Beta</strong><script>alert(1)</script>",
            references=("f3",),
        ),
        ContentFragment(
            fragment_id="f3",
            source="gamma",
            reader_domain="internal",
            html="<em>Gamma shared citation</em>",
        ),
    ]

    initial = review.review(fragments)

    assert [item.fragment_id for item in initial.publishable] == [
        "f1",
        "f2",
        "f3",
    ]
    assert initial.withdrawn == ()
    assert initial.published_map["f1"].reviewers == (
        "legal",
        "external_editor",
    )
    assert initial.published_map["f2"].changes == (SANITIZED,)
    assert "<script>" not in initial.published_map["f2"].sanitized_html
    assert "<strong>Beta</strong>" in initial.published_map["f2"].sanitized_html

    review.revoke_approval("legal-gamma")
    updated = review.review(fragments)

    assert [item.fragment_id for item in updated.publishable] == []
    assert [item.fragment_id for item in updated.withdrawn] == [
        "f1",
        "f2",
        "f3",
    ]

    f1 = updated.withdrawn_map["f1"]
    f2 = updated.withdrawn_map["f2"]
    f3 = updated.withdrawn_map["f3"]

    assert f1.reason == UNRESOLVED_REFERENCE
    assert f1.unresolved_references == ("f2", "f3")
    assert f1.missing_reviewers == ()
    assert f2.reason == UNRESOLVED_REFERENCE
    assert f2.unresolved_references == ("f3",)
    assert f2.missing_reviewers == ()
    assert f3.reason == WITHDRAWN_APPROVAL
    assert f3.missing_reviewers == ("legal",)
    assert f3.approval_ids == ("editor-core",)
    assert f3.reviewers == ("external_editor",)

    revoke_event = updated.approval_history[-1]
    assert revoke_event.action == "revoke"
    assert revoke_event.approval_id == "legal-gamma"
    assert revoke_event.reviewer == "legal"
    assert revoke_event.active is False
    assert [event.sequence for event in updated.approval_history] == [1, 2, 3, 4]


def test_reader_domain_uses_approval_intersection():
    review = OfflinePublicationReview()
    review.grant_approval(
        "legal",
        sources={"alpha"},
        reader_domains={"internal"},
        approval_id="legal-internal",
    )
    review.grant_approval(
        "external_editor",
        sources={"alpha"},
        reader_domains={"internal", "public"},
        approval_id="editor-all-domains",
    )
    fragment = ContentFragment(
        fragment_id="public-fragment",
        source="alpha",
        reader_domain="public",
        html="public text",
    )

    result = review.review([fragment])

    assert result.publishable == ()
    assert result.withdrawn[0].reason == WITHDRAWN_APPROVAL
    assert result.withdrawn[0].missing_reviewers == ("legal",)
    assert result.withdrawn[0].reviewers == ("external_editor",)


def test_overlapping_approvals_can_be_revoked_independently():
    review = OfflinePublicationReview()
    review.grant_approval(
        "legal",
        sources={"alpha", "beta"},
        reader_domains={"internal"},
        approval_id="legal-broad",
    )
    review.grant_approval(
        "legal",
        sources={"alpha"},
        reader_domains={"internal"},
        approval_id="legal-alpha-only",
    )
    review.grant_approval(
        "external_editor",
        sources={"alpha", "beta"},
        reader_domains={"internal"},
        approval_id="editor",
    )
    fragment = ContentFragment(
        fragment_id="alpha-fragment",
        source="alpha",
        reader_domain="internal",
        html="alpha text",
    )

    initial = review.review([fragment])
    assert initial.published_map["alpha-fragment"].approval_ids == (
        "legal-broad",
        "legal-alpha-only",
        "editor",
    )

    review.revoke_approval("legal-alpha-only", reviewer="legal")
    updated = review.review([fragment])

    assert updated.published_map["alpha-fragment"].approval_ids == (
        "legal-broad",
        "editor",
    )
    assert updated.approval_history[-1].approval_id == "legal-alpha-only"


def test_revoking_unknown_approval_keeps_history_intact():
    review = OfflinePublicationReview()

    with pytest.raises(ValueError):
        review.revoke_approval("missing")

    assert review.review([]).approval_history == ()
