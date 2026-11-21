import json

from bleach.comments import CommentReviewer, sanitize_comment


def _reviewer():
    return CommentReviewer()


def test_sanitize_before_review_drops_unsafe_href():
    reviewer = _reviewer()
    revision = reviewer.submit(
        '<p>ok <a href="https://example.com">safe</a> '
        '<a href="javascript:alert(1)">bad</a></p>'
    )

    assert revision.sanitized == (
        '<p>ok <a href="https://example.com">safe</a> <a>bad</a></p>'
    )
    assert [link.href for link in revision.links] == ["https://example.com"]
    assert reviewer.check().ok is False


def test_edit_to_other_block_keeps_approval():
    reviewer = _reviewer()
    text = '<p>one <a href="https://example.com">link</a></p><p>two</p>'
    revision = reviewer.submit(text)
    approval = reviewer.approve(revision.blocks[0].links[0], moderator="mod")

    check = reviewer.check(
        '<p>one <a href="https://example.com">link</a></p><p>two changed</p>'
    )

    assert check.ok is True
    assert approval.status == "valid"
    assert approval.bound_block_id == "b1"


def test_one_character_change_invalidates_old_approval():
    reviewer = _reviewer()
    text = '<p>one <a href="https://example.com">link</a></p><p>two</p>'
    revision = reviewer.submit(text)
    approval = reviewer.approve(revision.blocks[0].links[0])

    check = reviewer.check(
        '<p>one! <a href="https://example.com">link</a></p><p>two</p>'
    )

    assert check.ok is False
    assert approval.status == "stale"
    assert approval.reason == "block-changed"
    assert check.pending_links[0].block_id == "b1"

    # Reverting the characters does not resurrect the old confirmation: the
    # source went through a new revision and needs a fresh review.
    reverted = reviewer.check(text)
    assert reverted.ok is False
    assert approval.status == "stale"


def test_split_keeps_approval_on_piece_that_retains_the_source():
    reviewer = _reviewer()
    text = '<p>Intro <a href="https://example.com">link</a> outro</p>'
    revision = reviewer.submit(text)
    approval = reviewer.approve(revision.blocks[0].links[0])

    split = reviewer.check(
        '<p>Intro <a href="https://example.com">link</a></p><p>outro</p>'
    )

    assert split.ok is True
    assert approval.status == "carried"
    assert approval.bound_block_id == "b1"
    assert split.revision.block_count == 2

    changed = reviewer.check(
        '<p>Intro! <a href="https://example.com">link</a></p><p>outro</p>'
    )
    assert changed.ok is False
    assert approval.status == "stale"
    assert approval.reason == "block-changed"


def test_inserting_another_block_preserves_approval():
    reviewer = _reviewer()
    text = '<p>one <a href="https://example.com">link</a></p><p>two</p>'
    revision = reviewer.submit(text)
    reviewer.approve(revision.blocks[0].links[0])

    check = reviewer.check(
        '<p>zero</p><p>one <a href="https://example.com">link</a></p><p>two</p>'
    )

    assert check.ok is True
    assert check.approvals[0].bound_block_id == "b2"


def test_moving_identical_link_to_another_block_needs_review():
    reviewer = _reviewer()
    text = '<p>one <a href="https://example.com">link</a></p><p>two</p>'
    revision = reviewer.submit(text)
    approval = reviewer.approve(revision.blocks[0].links[0])

    check = reviewer.check(
        '<p>one</p><p>two <a href="https://example.com">link</a></p>'
    )

    assert check.ok is False
    assert approval.status == "stale"
    assert approval.reason == "moved"
    assert approval.moved_to == "b2"
    assert [(link.block_id, link.href) for link in check.pending_links] == [
        ("b2", "https://example.com")
    ]


def test_duplicate_blocks_are_reviewed_separately():
    reviewer = _reviewer()
    text = (
        '<p>A <a href="https://example.com">link</a></p>'
        '<p>A <a href="https://example.com">link</a></p>'
    )
    revision = reviewer.submit(text)
    first = reviewer.approve(revision.blocks[0].links[0])

    check = reviewer.check(text)

    assert check.ok is False
    assert first.status == "valid"
    assert [link.block_id for link in check.approved_links] == ["b1"]
    assert [link.block_id for link in check.pending_links] == ["b2"]

    second = reviewer.approve(revision.blocks[1].links[0])
    both = reviewer.check(text)
    assert both.ok is True

    edited = reviewer.check(
        '<p>B <a href="https://example.com">link</a></p>'
        '<p>A <a href="https://example.com">link</a></p>'
    )
    assert edited.ok is False
    assert first.status == "stale"
    assert second.status == "valid"
    assert second.bound_block_id == "b2"


def test_duplicate_links_inside_one_block_are_separate_occurrences():
    reviewer = _reviewer()
    text = (
        '<p><a href="https://example.com">link</a> '
        '<a href="https://example.com">link</a></p>'
    )
    revision = reviewer.submit(text)
    assert [link.occurrence for link in revision.links] == [0, 1]

    reviewer.approve(revision.blocks[0].links[0])
    check = reviewer.check(text)

    assert check.ok is False
    assert len(check.approved_links) == 1
    assert len(check.pending_links) == 1


def test_duplicate_links_survive_a_split_onto_the_same_offsets():
    reviewer = _reviewer()
    text = (
        '<p><a href="https://example.com">link</a> '
        '<a href="https://example.com">link</a></p>'
    )
    revision = reviewer.submit(text)
    reviewer.approve(revision.blocks[0].links[0])
    reviewer.approve(revision.blocks[0].links[1])

    check = reviewer.check(
        '<p><a href="https://example.com">link</a></p>'
        '<p><a href="https://example.com">link</a></p>'
    )

    assert check.ok is True
    assert all(approval.status == "carried" for approval in check.approvals)
    assert [link.block_id for link in check.approved_links] == ["b1", "b2"]


def test_approval_records_round_trip_as_json():
    reviewer = _reviewer()
    text = '<p>one <a href="https://example.com">link</a></p>'
    revision = reviewer.submit(text)
    reviewer.approve(revision.blocks[0].links[0], moderator="mod", note="checked")

    records = json.loads(reviewer.dumps_approvals())
    assert records[0]["href"] == "https://example.com"
    assert records[0]["moderator"] == "mod"

    restarted = _reviewer()
    restarted.submit(text)
    restarted.load_approvals(records)
    assert restarted.check().ok is True
    assert restarted.check(text.replace("one", "ONE")).ok is False


def test_linkify_option_reviews_generated_links():
    reviewer = CommentReviewer(linkify=True)
    revision = reviewer.submit("see https://example.com now")

    assert '<a href="https://example.com"' in revision.sanitized
    assert len(revision.links) == 1
    reviewer.approve(revision.blocks[0].links[0])
    assert reviewer.check().ok is True


def test_sanitize_comment_helper_removes_scripts():
    sanitized = sanitize_comment("<script>alert(1)</script><p>hello</p>")
    assert "<script>" not in sanitized
    assert "<p>hello</p>" in sanitized
