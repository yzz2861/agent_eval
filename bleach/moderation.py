"""Reviewable content-safety moderation sessions built on bleach cleaning.

A :py:class:`ModerationSession` turns content safety review into an
auditable editing session:

* Machine sanitization and moderator-confirmed edits are recorded as
  separate audit-trail actors (``"machine"`` vs ``"moderator"``).
* Raw user input is cleaned before it becomes the baseline publish
  state; the original text never enters the publish entry.
* Moderator edits are cleaned under the current policy and stay in a
  pending (non-publishable) preview until explicitly approved.
* Undo can only ever return to a state that was approved under the
  current policy--never to raw user fields or unapproved previews.
* Material removed by sanitization or by the moderator is kept only as
  a redacted summary (tag names and counts), so removed content cannot
  be resurrected from the audit trail into the publish entry.
* Past edit times can be inspected through approved archived summaries
  via :py:meth:`ModerationSession.view_at`.
"""

import hashlib
import time
from html.parser import HTMLParser

from bleach.sanitizer import Cleaner


__all__ = [
    "ArchivedSummary",
    "AuditEntry",
    "ModerationSession",
    "NoApprovedStateError",
    "NothingToApproveError",
    "SessionPausedError",
]


MACHINE = "machine"
MODERATOR = "moderator"


class SessionPausedError(Exception):
    """Raised when mutating a paused moderation session."""


class NothingToApproveError(Exception):
    """Raised when approving without a pending moderator edit."""


class NoApprovedStateError(Exception):
    """Raised when undoing past the earliest approved publish state."""


class _FragmentInventory(HTMLParser):
    """Collects tag names and link targets from an HTML fragment."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags = []
        self.links = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        for name, value in attrs:
            if name == "href" and value:
                self.links.append(value)


def _inventory(text):
    parser = _FragmentInventory()
    parser.feed(text)
    parser.close()
    return parser


def _summarize_removed(before_text, after_text):
    """Builds a redacted summary of what was removed between two fragments

    Only tag names and counts are recorded--never attribute values,
    link targets, or text content--so removed material cannot be
    resurrected from the audit trail into the publish entry.

    """
    before = _inventory(before_text)
    after = _inventory(after_text)

    remaining = list(after.tags)
    removed_tags = []
    for tag in before.tags:
        if tag in remaining:
            remaining.remove(tag)
        else:
            removed_tags.append(tag)

    return {
        "changed": before_text != after_text,
        "removed_tags": sorted(removed_tags),
        "removed_link_count": max(0, len(before.links) - len(after.links)),
    }


def _digest(content):
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


class AuditEntry:
    """A single recorded action in a moderation session

    ``actor`` is ``"machine"`` for automated sanitization steps and
    ``"moderator"`` for human-confirmed steps, so the two trails can be
    reviewed separately.

    """

    def __init__(self, seq, timestamp, actor, kind, detail):
        self.seq = seq
        self.timestamp = timestamp
        self.actor = actor
        self.kind = kind
        self.detail = detail

    def __repr__(self):
        return "AuditEntry(seq={!r}, actor={!r}, kind={!r})".format(
            self.seq, self.actor, self.kind
        )


class _EditState:
    """A sanitized content state; only approved ones are publishable"""

    def __init__(self, content, actor, created, removed):
        self.content = content
        self.actor = actor
        self.created = created
        self.removed = removed
        self.digest = _digest(content)


class ArchivedSummary:
    """Approved, redacted view of a past publish state

    Exposes only material that was approved under policy. Fragments
    removed by sanitization or by the moderator appear solely as a
    redacted summary--the removed content itself is not available here.

    """

    def __init__(self, state):
        self.created = state.created
        self.actor = state.actor
        self.content = state.content
        self.digest = state.digest
        self.removed = dict(state.removed)

    def __repr__(self):
        return "ArchivedSummary(created={!r}, actor={!r}, digest={!r})".format(
            self.created, self.actor, self.digest
        )


class ModerationSession:
    """A reviewable editing session for content safety review

    The session starts by cleaning the raw user submission; that
    machine-sanitized result is the first approved publish state.
    Moderator edits are cleaned under the same current policy and must
    be approved before they become publishable. Undo only ever moves
    back between approved states.

    Example::

        session = ModerationSession(user_submitted_html)
        session.moderator_edit(edited_html)
        session.approve()
        publish(session.publish_content)

    :arg str raw_text: the raw, untrusted user submission

    :arg cleaner: a :py:class:`bleach.sanitizer.Cleaner` defining the
        current policy; defaults to a cleaner with default settings

    :arg clock: callable returning the current time as a float;
        defaults to ``time.time`` (injectable for tests)

    """

    def __init__(self, raw_text, cleaner=None, clock=None):
        self._cleaner = cleaner if cleaner is not None else Cleaner()
        self._clock = clock if clock is not None else time.time
        self._log = []
        self._checkpoints = []
        self._pending = None
        self._paused = False

        now = self._now()
        cleaned = self._cleaner.clean(raw_text)
        removed = _summarize_removed(raw_text, cleaned)
        self._record(MACHINE, "sanitize", {"removed": removed}, timestamp=now)
        baseline = _EditState(cleaned, MACHINE, now, removed)
        self._checkpoints.append(baseline)
        self._record(MACHINE, "approve", {"digest": baseline.digest}, timestamp=now)

    def _now(self):
        return self._clock()

    def _record(self, actor, kind, detail, timestamp=None):
        self._log.append(
            AuditEntry(
                seq=len(self._log),
                timestamp=self._now() if timestamp is None else timestamp,
                actor=actor,
                kind=kind,
                detail=dict(detail),
            )
        )

    def _require_active(self):
        if self._paused:
            raise SessionPausedError(
                "moderation session is paused; resume() before editing"
            )

    @property
    def paused(self):
        """Whether the session is currently paused"""
        return self._paused

    def pause(self):
        """Pauses the session; edits, approvals and undos are blocked"""
        if not self._paused:
            self._paused = True
            self._record(MODERATOR, "pause", {})

    def resume(self):
        """Resumes a paused session"""
        if self._paused:
            self._paused = False
            self._record(MODERATOR, "resume", {})

    @property
    def audit_log(self):
        """The full audit trail as a tuple of :py:class:`AuditEntry`"""
        return tuple(self._log)

    @property
    def publish_content(self):
        """Content currently cleared for publishing

        This is always an approved, policy-sanitized checkpoint; raw
        user input and unapproved previews are never reachable here.

        """
        return self._checkpoints[-1].content

    @property
    def pending_preview(self):
        """Sanitized preview of the unapproved moderator edit, or None"""
        return self._pending.content if self._pending is not None else None

    @property
    def has_pending_edit(self):
        """Whether a moderator edit is waiting for approval"""
        return self._pending is not None

    @property
    def approved_history(self):
        """Archived summaries of every approved publish state, in order"""
        return tuple(ArchivedSummary(state) for state in self._checkpoints)

    def moderator_edit(self, text):
        """Records a moderator edit as a pending, non-publishable preview

        The edit is cleaned under the current policy before previewing.
        What the moderator removed relative to the current publish
        state is recorded as a redacted summary.

        :arg str text: the moderator-edited fragment

        """
        self._require_active()
        cleaned = self._cleaner.clean(text)
        policy_removed = _summarize_removed(text, cleaned)
        moderator_removed = _summarize_removed(self.publish_content, cleaned)
        self._record(
            MODERATOR,
            "edit",
            {
                "policy_removed": policy_removed,
                "moderator_removed": moderator_removed,
            },
        )
        self._pending = _EditState(cleaned, MODERATOR, self._now(), moderator_removed)

    def approve(self):
        """Approves the pending moderator edit, making it publishable

        :raises NothingToApproveError: if there is no pending edit

        """
        self._require_active()
        if self._pending is None:
            raise NothingToApproveError("no moderator edit is waiting for approval")
        state = self._pending
        self._pending = None
        self._checkpoints.append(state)
        self._record(MODERATOR, "approve", {"digest": state.digest})

    def undo(self):
        """Reverts to the most recent earlier approved publish state

        A pending (unapproved) edit is discarded first. Otherwise the
        newest approved checkpoint is dropped and the session returns
        to the previous approved checkpoint, re-validated against the
        current policy. Raw user input and unapproved previews are
        never checkpoints, so undo can never reach them.

        :returns: the content of the approved state reverted to

        :raises NoApprovedStateError: if there is no earlier approved
            state to return to

        """
        self._require_active()
        if self._pending is not None:
            discarded = self._pending
            self._pending = None
            self._record(
                MODERATOR, "undo", {"discarded_pending_digest": discarded.digest}
            )
            return self.publish_content

        if len(self._checkpoints) < 2:
            raise NoApprovedStateError("no earlier approved state to undo to")

        discarded = self._checkpoints.pop()
        # Undo targets must be recognized by the *current* policy; skip
        # any checkpoint whose content no longer survives cleaning.
        while len(self._checkpoints) > 1 and not self._is_current_policy_approved(
            self._checkpoints[-1]
        ):
            self._checkpoints.pop()
        target = self._checkpoints[-1]
        self._record(
            MODERATOR,
            "undo",
            {"discarded_digest": discarded.digest, "restored_digest": target.digest},
        )
        return target.content

    def _is_current_policy_approved(self, state):
        return self._cleaner.clean(state.content) == state.content

    def view_at(self, timestamp):
        """Returns the approved archived summary in effect at ``timestamp``

        Only approved checkpoints are visible; removed fragments appear
        only as redacted summaries. Returns None if no approved state
        existed yet at that time.

        :arg float timestamp: the point in time to inspect

        """
        state = None
        for checkpoint in self._checkpoints:
            if checkpoint.created <= timestamp:
                state = checkpoint
            else:
                break
        if state is None:
            return None
        return ArchivedSummary(state)
