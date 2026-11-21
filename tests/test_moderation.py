import pytest

from bleach.moderation import (
    ModerationSession,
    NoApprovedStateError,
    NothingToApproveError,
    SessionPausedError,
)
from bleach.sanitizer import Cleaner


class FakeClock:
    def __init__(self, start=1000.0):
        self.now = start

    def __call__(self):
        return self.now

    def tick(self, seconds=1.0):
        self.now += seconds


NORMAL_FRAGMENT = '<em>hello <a href="https://example.com/">example</a></em>'
YUCKY_FRAGMENT = (
    '<em>hi <a href="javascript:alert(1)">click</a>'
    '<script src="https://evil.example/x.js"></script></em>'
)


def make_session(text=NORMAL_FRAGMENT, clock=None):
    # strip=True so machine-removed markup is gone from the publish
    # entry entirely rather than lingering as escaped text
    return ModerationSession(text, cleaner=Cleaner(strip=True), clock=clock)


class TestMachineBaseline:
    def test_machine_actions_recorded_separately_from_moderator(self):
        session = make_session()
        session.moderator_edit("edited")
        session.approve()

        machine_entries = [e for e in session.audit_log if e.actor == "machine"]
        moderator_entries = [e for e in session.audit_log if e.actor == "moderator"]

        assert [e.kind for e in machine_entries] == ["sanitize", "approve"]
        assert [e.kind for e in moderator_entries] == ["edit", "approve"]
        # machine trail always comes first
        assert session.audit_log[0].actor == "machine"

    def test_raw_payload_never_enters_publish_or_audit_trail(self):
        session = make_session(YUCKY_FRAGMENT)

        assert "javascript:" not in session.publish_content
        assert "evil.example" not in session.publish_content
        assert "alert" not in session.publish_content

        log_text = repr(session.audit_log)
        assert "javascript:" not in log_text
        assert "evil.example" not in log_text
        assert "alert" not in log_text

    def test_machine_removal_summary_is_redacted(self):
        session = make_session(YUCKY_FRAGMENT)
        sanitize_entry = session.audit_log[0]

        assert sanitize_entry.kind == "sanitize"
        removed = sanitize_entry.detail["removed"]
        assert removed["changed"] is True
        assert "script" in removed["removed_tags"]
        assert removed["removed_link_count"] == 1


class TestApprovalFlow:
    def test_moderator_edit_is_not_publishable_until_approved(self):
        session = make_session()
        session.moderator_edit("<strong>moderator rewrite</strong>")

        assert session.has_pending_edit is True
        assert session.pending_preview == "<strong>moderator rewrite</strong>"
        # publish entry still shows the approved baseline
        assert session.publish_content == NORMAL_FRAGMENT

        session.approve()
        assert session.has_pending_edit is False
        assert session.publish_content == "<strong>moderator rewrite</strong>"

    def test_approve_without_pending_edit_raises(self):
        session = make_session()
        with pytest.raises(NothingToApproveError):
            session.approve()

    def test_moderator_edit_is_cleaned_under_current_policy(self):
        session = make_session()
        session.moderator_edit('x <a href="javascript:alert(1)">y</a>')

        assert session.pending_preview is not None
        assert "javascript:" not in session.pending_preview

        session.approve()
        assert "javascript:" not in session.publish_content


class TestUndo:
    def test_undo_discards_unapproved_pending_edit(self):
        session = make_session()
        session.moderator_edit("unapproved")

        result = session.undo()

        assert result == NORMAL_FRAGMENT
        assert session.has_pending_edit is False
        assert session.publish_content == NORMAL_FRAGMENT

    def test_undo_walks_back_only_approved_states(self):
        session = make_session()
        session.moderator_edit("revision one")
        session.approve()
        session.moderator_edit("revision two")
        session.approve()

        assert session.undo() == "revision one"
        assert session.publish_content == "revision one"

        assert session.undo() == NORMAL_FRAGMENT
        assert session.publish_content == NORMAL_FRAGMENT

        with pytest.raises(NoApprovedStateError):
            session.undo()

    def test_undo_never_resurrects_removed_links_or_raw_fields(self):
        session = make_session(YUCKY_FRAGMENT)
        baseline = session.publish_content

        # moderator removes the remaining link text and approves
        session.moderator_edit("hi click")
        session.approve()
        # a further approved revision on top
        session.moderator_edit("hi click, revised")
        session.approve()

        seen = []
        seen.append(session.undo())
        seen.append(session.undo())
        seen.append(session.publish_content)

        for content in seen:
            assert "javascript:" not in content
            assert "evil.example" not in content
            assert "alert" not in content
        # the final undo target is the machine-approved baseline
        assert seen[-1] == baseline

    def test_undo_cannot_reach_unapproved_intermediate_states(self):
        session = make_session()
        session.moderator_edit("approved one")
        session.approve()
        # this preview is never approved
        session.moderator_edit("sneaky unapproved")
        session.undo()  # discards the pending preview

        assert session.undo() == NORMAL_FRAGMENT
        with pytest.raises(NoApprovedStateError):
            session.undo()


class TestPause:
    def test_pause_blocks_edit_approve_and_undo(self):
        session = make_session()
        session.pause()

        assert session.paused is True
        with pytest.raises(SessionPausedError):
            session.moderator_edit("nope")
        with pytest.raises(SessionPausedError):
            session.approve()
        with pytest.raises(SessionPausedError):
            session.undo()

    def test_pause_and_resume_are_audited_as_moderator_actions(self):
        session = make_session()
        session.pause()
        session.resume()

        kinds = [(e.actor, e.kind) for e in session.audit_log]
        assert ("moderator", "pause") in kinds
        assert ("moderator", "resume") in kinds

    def test_pause_is_idempotent(self):
        session = make_session()
        session.pause()
        session.pause()
        pause_entries = [e for e in session.audit_log if e.kind == "pause"]
        assert len(pause_entries) == 1


class TestPauseUndoReapprove:
    """End-to-end pause / undo / re-approve flows on normal fragments"""

    def test_pause_undo_then_reapprove(self):
        clock = FakeClock()
        session = make_session(clock=clock)

        clock.tick()
        session.moderator_edit("first revision")
        session.approve()

        clock.tick()
        session.pause()
        with pytest.raises(SessionPausedError):
            session.undo()
        session.resume()

        clock.tick()
        assert session.undo() == NORMAL_FRAGMENT

        clock.tick()
        session.moderator_edit("re-approved revision")
        session.approve()

        assert session.publish_content == "re-approved revision"
        # the re-approved state is the only path forward; the discarded
        # "first revision" checkpoint is gone from the publish history
        digests = [s.digest for s in session.approved_history]
        assert len(digests) == len(set(digests)) == 2

    def test_reapprove_after_undo_of_pending_edit(self):
        session = make_session()
        session.moderator_edit("draft one")
        session.undo()  # discard the draft

        session.moderator_edit("draft two")
        session.approve()

        assert session.publish_content == "draft two"
        edit_entries = [e for e in session.audit_log if e.kind == "edit"]
        approve_entries = [e for e in session.audit_log if e.kind == "approve"]
        # two moderator edits recorded, one moderator approval plus the
        # machine baseline approval
        assert len(edit_entries) == 2
        assert len(approve_entries) == 2


class TestArchivedSummaries:
    def test_view_at_returns_approved_summary_for_old_edit_time(self):
        clock = FakeClock()
        session = make_session(YUCKY_FRAGMENT, clock=clock)
        baseline_time = clock.now

        clock.tick(10)
        session.moderator_edit("hi click")
        edit_time = clock.now
        session.approve()

        old = session.view_at(baseline_time + 1)
        assert old is not None
        assert old.actor == "machine"
        assert old.content == session.approved_history[0].content
        assert "script" in old.removed["removed_tags"]

        newer = session.view_at(edit_time + 1)
        assert newer.actor == "moderator"
        assert newer.content == "hi click"

    def test_view_at_summary_never_contains_removed_content(self):
        clock = FakeClock()
        session = make_session(YUCKY_FRAGMENT, clock=clock)

        for when in (clock.now, clock.now + 100):
            summary = session.view_at(when)
            assert summary is not None
            summary_text = repr(summary) + repr(summary.removed) + summary.content
            assert "javascript:" not in summary_text
            assert "evil.example" not in summary_text
            assert "alert" not in summary_text

    def test_view_at_before_any_approved_state_returns_none(self):
        clock = FakeClock()
        session = make_session(clock=clock)
        assert session.view_at(clock.now - 1) is None

    def test_pending_edit_is_not_visible_in_history(self):
        clock = FakeClock()
        session = make_session(clock=clock)
        clock.tick()
        session.moderator_edit("unapproved draft")

        summary = session.view_at(clock.now + 1)
        assert summary.content == NORMAL_FRAGMENT
        assert len(session.approved_history) == 1
