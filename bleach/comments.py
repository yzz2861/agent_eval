"""Moderator approval for links in Bleach-sanitized comments.

The important idea in this module is that a link approval is not a statement
about a URL in isolation.  It is a statement about a link in a particular
piece of reviewed source text.  The approval is therefore bound to:

* a stable block lineage,
* a digest of the sanitized block that the moderator reviewed, and
* the occurrence of the link inside that block.

That distinction matters when a comment is edited.  Changing an unrelated
block leaves the approved block's lineage and digest intact, so the approval
can be reused.  Changing even one character in the approved block, or moving
the same-looking link into a different block, produces a different binding and
requires another review.  Duplicate blocks and duplicate links are kept apart
by their occurrence numbers.

The typical flow is::

    reviewer = CommentReviewer()
    revision = reviewer.submit(user_html)
    reviewer.approve(revision.blocks[0].links[0], moderator="alice")

    check = reviewer.resend_check(edited_html)
    if check.ok:
        publish(revision.sanitized)
    else:
        show_to_moderator(check.review_view())

Sanitization always happens before a block or link is exposed for approval.
Only sanitized ``<a href=...>`` elements become approvable links, so a URL
removed by the sanitizer cannot be approved accidentally.
"""

from __future__ import annotations

import datetime as _datetime
import hashlib
import html as _html
import json
import re
import unicodedata
from collections import OrderedDict
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any, Mapping

from bleach import html5lib_shim
from bleach.linkifier import DEFAULT_CALLBACKS, Linker
from bleach.sanitizer import (
    ALLOWED_ATTRIBUTES,
    ALLOWED_PROTOCOLS,
    ALLOWED_TAGS,
    Cleaner,
)


#: Schema marker used by serialized approval records.
APPROVAL_SCHEMA = "bleach.comment-approval/1"

#: A comfortable safe default for comments.  It extends Bleach's normal
#: defaults with block-level elements so paragraph boundaries can be retained
#: and reviewed separately.
COMMENT_TAGS = frozenset(
    set(ALLOWED_TAGS)
    | {
        "br",
        "p",
        "div",
        "blockquote",
        "pre",
        "ul",
        "ol",
        "li",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "hr",
        "span",
        "del",
        "ins",
        "sup",
        "sub",
        "mark",
        "q",
        "cite",
        "s",
        "u",
        "small",
    }
)

#: Attributes allowed by the comment-oriented default sanitizer.
COMMENT_ATTRIBUTES = {tag: list(values) for tag, values in ALLOWED_ATTRIBUTES.items()}
COMMENT_ATTRIBUTES["a"] = ["href", "title", "rel"]

#: Block boundaries understood by the review model.
BLOCK_TAGS = frozenset(html5lib_shim.HTML_TAGS_BLOCK_LEVEL | {"main"})

_NEWLINES_RE = re.compile(r"\r\n|\r|\n")
_WHITESPACE_RE = re.compile(r"\s+")


def _utcnow():
    return _datetime.datetime.now(_datetime.timezone.utc).isoformat()


def _sha256(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _normalize_text(value):
    """Return the text identity used by approvals.

    Whitespace-only changes in presentation should not force a new review, but
    any visible character change should.  Unicode normalization also keeps a
    composed and decomposed spelling from looking like two different blocks.
    """

    value = unicodedata.normalize("NFC", value or "")
    value = _NEWLINES_RE.sub("\n", value)
    value = _WHITESPACE_RE.sub(" ", value)
    return value.strip()


def _normalized_offset(value, raw_offset):
    """Map an offset in the source text to the normalized text.

    Collapsing a whitespace run to a single space means the length of the
    normalized prefix is not always the link's position in the normalized
    block.  This helper keeps the position exact, including the single space
    that survives immediately before a link.
    """

    value = unicodedata.normalize("NFC", value or "")
    raw_offset = max(0, min(raw_offset, len(value)))
    count = 0
    started = False
    pending_space = False
    for index, char in enumerate(value):
        if index >= raw_offset:
            return count + (1 if pending_space and started else 0)
        if char.isspace():
            if started:
                pending_space = True
            continue
        if pending_space:
            count += 1
            pending_space = False
        count += 1
        started = True
    return count


def _escape_text(value):
    return _html.escape(value, quote=False)


def _block_digest(normalized_text, links):
    payload = [
        normalized_text,
        [
            [
                link.href,
                _normalize_text(link.text),
                link.occurrence,
            ]
            for link in links
        ],
    ]
    return _sha256(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))


def _link_digest(href, text, occurrence):
    payload = json.dumps(
        [href, _normalize_text(text), occurrence],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return _sha256(payload)


def _attribute(attrs, name):
    for key, value in attrs:
        if key.lower() == name:
            return value
    return None


@dataclass(frozen=True)
class CommentLink:
    """A sanitized link occurrence inside a comment block."""

    block_index: int
    block_id: str
    index: int
    link_id: str
    href: str
    text: str
    start: int
    end: int
    link_offset: int
    occurrence: int
    link_key: str
    context_before: str = ""
    context_after: str = ""

    @property
    def display_text(self):
        return self.text or self.href

    @property
    def excerpt(self):
        before = self.context_before
        after = self.context_after
        middle = self.display_text
        if self.text and self.text != self.href:
            middle = "%s <%s>" % (self.display_text, self.href)
        return "%s%s%s" % (before, middle, after)

    def to_dict(self):
        return {
            "block_index": self.block_index,
            "block_id": self.block_id,
            "index": self.index,
            "link_id": self.link_id,
            "href": self.href,
            "text": self.text,
            "start": self.start,
            "end": self.end,
            "link_offset": self.link_offset,
            "occurrence": self.occurrence,
            "link_key": self.link_key,
            "context_before": self.context_before,
            "context_after": self.context_after,
            "excerpt": self.excerpt,
        }


@dataclass
class CommentBlock:
    """One independently reviewable paragraph/block in a comment."""

    index: int
    block_id: str
    digest: str
    occurrence: int
    text: str
    normalized_text: str
    html: str
    links: tuple[CommentLink, ...] = ()
    stable_id: str | None = None
    previous_stable_id: str | None = None
    change: str = "new"

    @property
    def link_count(self):
        return len(self.links)

    def link(self, selector):
        if isinstance(selector, CommentLink):
            return selector
        if isinstance(selector, int):
            return self.links[selector]
        if isinstance(selector, str):
            for link in self.links:
                if selector in (link.link_id, link.link_key):
                    return link
            matches = [link for link in self.links if link.href == selector]
            if len(matches) == 1:
                return matches[0]
        raise LookupError("no unique link %r in %s" % (selector, self.block_id))

    def to_dict(self):
        return {
            "index": self.index,
            "block_id": self.block_id,
            "stable_id": self.stable_id,
            "previous_stable_id": self.previous_stable_id,
            "change": self.change,
            "digest": self.digest,
            "occurrence": self.occurrence,
            "text": self.text,
            "html": self.html,
            "links": [link.to_dict() for link in self.links],
        }


@dataclass
class CommentRevision:
    """The sanitized result of submitting a comment for review."""

    number: int
    source: str
    sanitized: str
    blocks: tuple[CommentBlock, ...]
    created_at: str = field(default_factory=_utcnow)
    previous_number: int | None = None

    @property
    def links(self):
        return tuple(link for block in self.blocks for link in block.links)

    @property
    def block_count(self):
        return len(self.blocks)

    @property
    def link_count(self):
        return len(self.links)

    def block(self, selector):
        if isinstance(selector, CommentBlock):
            return selector
        if isinstance(selector, int):
            return self.blocks[selector]
        if isinstance(selector, str):
            for block in self.blocks:
                if selector in (block.block_id, block.stable_id):
                    return block
            matches = [
                block for block in self.blocks if block.digest.startswith(selector)
            ]
            if len(matches) == 1:
                return matches[0]
        raise LookupError("no unique block %r in revision %s" % (selector, self.number))

    def link(self, selector):
        if isinstance(selector, CommentLink):
            return selector
        if isinstance(selector, int):
            return self.links[selector]
        if isinstance(selector, str):
            for link in self.links:
                if selector in (link.link_id, link.link_key):
                    return link
            matches = [link for link in self.links if link.href == selector]
            if len(matches) == 1:
                return matches[0]
        raise LookupError("no unique link %r in revision %s" % (selector, self.number))

    def to_dict(self):
        return {
            "number": self.number,
            "previous_number": self.previous_number,
            "created_at": self.created_at,
            "source": self.source,
            "sanitized": self.sanitized,
            "blocks": [block.to_dict() for block in self.blocks],
        }


@dataclass
class LinkApproval:
    """A moderator's approval of one link occurrence in one source block."""

    approval_id: str
    href: str
    link_text: str
    block_id: str
    block_digest: str
    block_occurrence: int
    link_id: str
    link_key: str
    source_fragment: str
    link_offset: int = 0
    prefix: str = ""
    suffix: str = ""
    moderator: str | None = None
    note: str | None = None
    created_at: str = field(default_factory=_utcnow)
    revision: int = 0
    stable_block_id: str | None = None
    bound_block_id: str | None = None
    bound_block_stable_id: str | None = None
    bound_link_key: str | None = None
    status: str = "valid"
    reason: str | None = None
    invalidated_by: str | None = None
    moved_to: str | None = None
    last_checked_revision: int | None = None
    origin_approval_id: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)
    schema: str = APPROVAL_SCHEMA

    @property
    def valid(self):
        return self.status in ("valid", "carried")

    @property
    def stale(self):
        return self.status == "stale"

    @property
    def approved(self):
        return self.valid

    @property
    def text(self):
        return self.link_text

    @property
    def bound_to(self):
        """The current block binding, or the last source block if stale."""

        return self.bound_block_id or self.block_id

    @property
    def location(self):
        return self.bound_to

    @property
    def binding(self):
        return {
            "approval_id": self.approval_id,
            "block_id": self.bound_to,
            "link_id": self.link_id,
            "href": self.href,
            "status": self.status,
            "reason": self.reason,
        }

    def to_dict(self):
        return {
            "schema": self.schema,
            "approval_id": self.approval_id,
            "href": self.href,
            "link_text": self.link_text,
            "block_id": self.block_id,
            "block_digest": self.block_digest,
            "block_occurrence": self.block_occurrence,
            "link_id": self.link_id,
            "link_key": self.link_key,
            "link_offset": self.link_offset,
            "source_fragment": self.source_fragment,
            "prefix": self.prefix,
            "suffix": self.suffix,
            "moderator": self.moderator,
            "note": self.note,
            "created_at": self.created_at,
            "revision": self.revision,
            "stable_block_id": self.stable_block_id,
            "status": self.status,
            "reason": self.reason,
            "invalidated_by": self.invalidated_by,
            "moved_to": self.moved_to,
            "last_checked_revision": self.last_checked_revision,
            "origin_approval_id": self.origin_approval_id,
            "metadata": dict(sorted(self.metadata.items())),
        }

    @classmethod
    def from_dict(cls, data):
        if not isinstance(data, Mapping):
            raise TypeError("approval record must be a mapping")
        known = {
            "schema",
            "approval_id",
            "href",
            "link_text",
            "block_id",
            "block_digest",
            "block_occurrence",
            "link_id",
            "link_key",
            "link_offset",
            "source_fragment",
            "prefix",
            "suffix",
            "moderator",
            "note",
            "created_at",
            "revision",
            "stable_block_id",
            "status",
            "reason",
            "invalidated_by",
            "moved_to",
            "last_checked_revision",
            "origin_approval_id",
            "metadata",
        }
        values = {key: data[key] for key in known if key in data}
        metadata = values.get("metadata") or {}
        values["metadata"] = {
            str(key): str(value) for key, value in dict(metadata).items()
        }
        return cls(**values)

    def diagnostic(self):
        return {
            "approval_id": self.approval_id,
            "status": self.status,
            "reason": self.reason,
            "invalidated_by": self.invalidated_by,
            "href": self.href,
            "text": self.link_text,
            "link_offset": self.link_offset,
            "block_id": self.block_id,
            "bound_block_id": self.bound_block_id,
            "moved_to": self.moved_to,
            "revision": self.revision,
            "last_checked_revision": self.last_checked_revision,
            "origin_approval_id": self.origin_approval_id,
        }


#: Friendly aliases kept intentionally: the record is an approval for a link.
ApprovalRecord = LinkApproval
ApprovedLink = LinkApproval


class _CommentHTMLParser(HTMLParser):
    """Turn sanitized comment HTML into independently reviewable blocks."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.raw_blocks = []
        self._parts = []
        self._text_parts = []
        self._text_len = 0
        self._links = []
        self._anchors = []
        self._started = False

    def _ensure_block(self):
        self._started = True

    def _append_text(self, value):
        if not value:
            return
        self._ensure_block()
        self._parts.append(_escape_text(value))
        self._text_parts.append(value)
        self._text_len += len(value)

    def _start_anchor(self, href):
        self._anchors.append(
            {
                "href": href,
                "start": self._text_len,
                "text": [],
            }
        )

    def _finish_anchor(self):
        if not self._anchors:
            return
        anchor = self._anchors.pop()
        if anchor["href"] is None:
            return
        self._links.append(
            {
                "href": anchor["href"],
                "text": "".join(anchor["text"]),
                "start": anchor["start"],
                "end": self._text_len,
            }
        )

    def _has_content(self):
        return bool(
            "".join(self._text_parts).strip()
            or self._links
            or (self._parts and "".join(self._parts).strip())
        )

    def _flush(self):
        text = "".join(self._text_parts)
        if not text.strip() and not self._links:
            self._parts = []
            self._text_parts = []
            self._text_len = 0
            self._links = []
            self._anchors = []
            self._started = False
            return

        leading = len(text) - len(text.lstrip())
        trimmed = text.strip()
        links = []
        for link in self._links:
            start = max(0, link["start"] - leading)
            end = max(start, link["end"] - leading)
            links.append(
                {
                    "href": link["href"],
                    "text": link["text"],
                    "start": min(start, len(trimmed)),
                    "end": min(end, len(trimmed)),
                }
            )

        raw_html = "".join(self._parts).strip()
        if not raw_html:
            raw_html = _escape_text(trimmed)

        self.raw_blocks.append(
            {
                "text": trimmed,
                "html": raw_html,
                "links": links,
            }
        )
        self._parts = []
        self._text_parts = []
        self._text_len = 0
        self._links = []
        self._anchors = []
        self._started = False

    def handle_starttag(self, tag, attrs):
        lower = tag.lower()
        raw = self.get_starttag_text() or "<%s>" % tag
        if lower in ("br", "hr"):
            self._flush()
            return

        if lower in BLOCK_TAGS:
            self._flush()
            self._ensure_block()
            self._parts.append(raw)
            return

        self._ensure_block()
        self._parts.append(raw)
        if lower == "a":
            self._start_anchor(_attribute(attrs, "href"))

    def handle_startendtag(self, tag, attrs):
        lower = tag.lower()
        if lower in ("br", "hr"):
            self._flush()
            return
        self._ensure_block()
        self._parts.append(self.get_starttag_text() or "<%s/>" % tag)

    def handle_endtag(self, tag):
        lower = tag.lower()
        if lower in ("br", "hr"):
            self._flush()
            return

        if lower == "a":
            self._finish_anchor()

        if lower in BLOCK_TAGS:
            if self._has_content():
                self._parts.append("</%s>" % tag)
            self._flush()
            return

        if self._started:
            self._parts.append("</%s>" % tag)

    def handle_data(self, data):
        if not data:
            return

        if self._anchors:
            # A link should remain one occurrence even if the source wrapped
            # its anchor text over a line.
            value = _NEWLINES_RE.sub(" ", data)
            self._append_text(value)
            for anchor in self._anchors:
                anchor["text"].append(value)
            return

        pieces = _NEWLINES_RE.split(data)
        for index, piece in enumerate(pieces):
            self._append_text(piece)
            if index != len(pieces) - 1:
                self._flush()

    def handle_entityref(self, name):
        value = "&%s;" % name
        self._append_text(value)
        for anchor in self._anchors:
            anchor["text"].append(value)

    def handle_charref(self, name):
        value = "&#%s;" % name
        self._append_text(value)
        for anchor in self._anchors:
            anchor["text"].append(value)

    def handle_comment(self, data):
        # Comments are removed by Bleach by default.  If a caller deliberately
        # keeps them, they are presentation only and not reviewable text.
        return


def _finalize_blocks(raw_blocks):
    blocks = []
    digest_occurrences = {}
    for block_index, raw in enumerate(raw_blocks):
        normalized_text = _normalize_text(raw["text"])
        links = []
        link_occurrences = {}
        for link_index, raw_link in enumerate(raw["links"]):
            occurrence_key = (
                raw_link["href"],
                _normalize_text(raw_link["text"]),
            )
            occurrence = link_occurrences.get(occurrence_key, 0)
            link_occurrences[occurrence_key] = occurrence + 1
            start = raw_link["start"]
            end = raw_link["end"]
            text = raw_link["text"]
            links.append(
                CommentLink(
                    block_index=block_index,
                    block_id="b%s" % (block_index + 1),
                    index=link_index,
                    link_id="l%s" % (link_index + 1),
                    href=raw_link["href"],
                    text=text,
                    start=start,
                    end=end,
                    link_offset=_normalized_offset(raw["text"], start),
                    occurrence=occurrence,
                    link_key=_link_digest(raw_link["href"], text, occurrence),
                    context_before=raw["text"][max(0, start - 40) : start],
                    context_after=raw["text"][end : end + 40],
                )
            )

        digest = _block_digest(normalized_text, links)
        occurrence = digest_occurrences.get(digest, 0)
        digest_occurrences[digest] = occurrence + 1
        blocks.append(
            CommentBlock(
                index=block_index,
                block_id="b%s" % (block_index + 1),
                digest=digest,
                occurrence=occurrence,
                text=raw["text"],
                normalized_text=normalized_text,
                html=raw["html"],
                links=tuple(links),
            )
        )
    return blocks


def parse_comment_blocks(sanitized_html):
    """Split already-sanitized HTML into reviewable blocks.

    This helper does not sanitize.  Callers that have untrusted input should
    use :class:`CommentReviewer` or :func:`sanitize_comment` first.
    """

    parser = _CommentHTMLParser()
    parser.feed(sanitized_html)
    parser.close()
    parser._flush()
    return tuple(_finalize_blocks(parser.raw_blocks))


def sanitize_comment(
    text,
    tags=None,
    attributes=None,
    protocols=None,
    strip=False,
    strip_comments=True,
    linkify=False,
):
    """Sanitize a comment using Bleach and return the safe HTML string."""

    cleaner = Cleaner(
        tags=COMMENT_TAGS if tags is None else tags,
        attributes=COMMENT_ATTRIBUTES if attributes is None else attributes,
        protocols=ALLOWED_PROTOCOLS if protocols is None else protocols,
        strip=strip,
        strip_comments=strip_comments,
    )
    cleaned = cleaner.clean(text)
    if linkify:
        cleaned = Linker(callbacks=DEFAULT_CALLBACKS).linkify(cleaned)
    return cleaned


@dataclass
class ApprovalCheck:
    """Result of checking whether the current comment may be sent."""

    revision: CommentRevision
    approved_links: tuple[CommentLink, ...]
    pending_links: tuple[CommentLink, ...]
    approvals: tuple[LinkApproval, ...]
    stale_approvals: tuple[LinkApproval, ...]
    diagnostics: tuple[dict[str, Any], ...]
    link_statuses: tuple[dict[str, Any], ...]

    @property
    def ok(self):
        return not self.pending_links

    @property
    def valid(self):
        return self.ok

    @property
    def passed(self):
        return self.ok

    @property
    def can_send(self):
        return self.ok

    @property
    def blocked(self):
        return not self.ok

    @property
    def requires_review(self):
        return self.pending_links

    @property
    def stale(self):
        return self.stale_approvals

    @property
    def issues(self):
        return tuple(item for item in self.diagnostics if item["status"] == "stale")

    @property
    def summary(self):
        return {
            "ok": self.ok,
            "approved": len(self.approved_links),
            "pending": len(self.pending_links),
            "stale_approvals": len(self.stale_approvals),
            "blocks": self.revision.block_count,
            "links": self.revision.link_count,
        }

    def __bool__(self):
        return self.ok

    @property
    def approved(self):
        return self.approved_links

    @property
    def pending(self):
        return self.pending_links

    @property
    def unapproved(self):
        return self.pending_links

    @property
    def needs_review(self):
        return self.pending_links

    @property
    def invalid_approvals(self):
        return self.stale_approvals

    @property
    def valid_approvals(self):
        return tuple(approval for approval in self.approvals if approval.valid)

    def to_dict(self):
        return {
            "ok": self.ok,
            "can_send": self.can_send,
            "blocked": self.blocked,
            "revision": self.revision.to_dict(),
            "summary": self.summary,
            "approved_links": [link.to_dict() for link in self.approved_links],
            "pending_links": [link.to_dict() for link in self.pending_links],
            "approvals": [approval.to_dict() for approval in self.approvals],
            "stale_approvals": [
                approval.to_dict() for approval in self.stale_approvals
            ],
            "diagnostics": list(self.diagnostics),
            "link_statuses": list(self.link_statuses),
        }

    def review_view(self):
        return _review_view(self)


#: Friendly result aliases.
CheckResult = ApprovalCheck
ResendCheck = ApprovalCheck
ReviewResult = ApprovalCheck


def _review_view(check):
    status_by_key = {}
    approval_by_key = {}
    for status in check.link_statuses:
        status_by_key[(status["block_stable_id"], status["link_key"])] = status
    for approval in check.approvals:
        if approval.valid:
            approval_by_key[
                (approval.bound_block_stable_id, approval.bound_link_key)
            ] = approval

    blocks = []
    for block in check.revision.blocks:
        links = []
        for link in block.links:
            key = (block.stable_id, link.link_key)
            status = status_by_key.get(key, {})
            approval = approval_by_key.get(key)
            item = link.to_dict()
            item["status"] = "approved" if approval else "pending"
            item["approval_id"] = approval.approval_id if approval else None
            links.append(item)
        block_item = block.to_dict()
        block_item["links"] = links
        blocks.append(block_item)

    return {
        "revision": check.revision.number,
        "sanitized": check.revision.sanitized,
        "ok": check.ok,
        "can_send": check.can_send,
        "blocked": check.blocked,
        "summary": check.summary,
        "blocks": blocks,
        "pending": [link.to_dict() for link in check.pending_links],
        "approved": [link.to_dict() for link in check.approved_links],
        "stale": list(check.issues),
    }


class CommentReviewer:
    """Sanitize comments and manage moderator link approvals.

    A reviewer instance represents one comment thread.  Calling :meth:`submit`
    or :meth:`check` with new text advances the revision and re-binds every
    approval to the new revision's matching block lineage.
    """

    def __init__(
        self,
        tags=None,
        attributes=None,
        protocols=None,
        strip=False,
        strip_comments=True,
        cleaner=None,
        sanitizer=None,
        linkify=False,
        callbacks=None,
    ):
        self.tags = COMMENT_TAGS if tags is None else tags
        self.attributes = COMMENT_ATTRIBUTES if attributes is None else attributes
        self.protocols = ALLOWED_PROTOCOLS if protocols is None else protocols
        self.strip = strip
        self.strip_comments = strip_comments
        self.cleaner = (
            cleaner
            or sanitizer
            or Cleaner(
                tags=self.tags,
                attributes=self.attributes,
                protocols=self.protocols,
                strip=self.strip,
                strip_comments=self.strip_comments,
            )
        )
        self.linkify = linkify
        self.callbacks = list(DEFAULT_CALLBACKS if callbacks is None else callbacks)
        self._linker = Linker(callbacks=self.callbacks) if linkify else None

        self._approvals = OrderedDict()
        self._revision = None
        self._revision_count = 0
        self._next_stable = 0

    # -- sanitization and submission -------------------------------------

    def sanitize(self, text):
        """Sanitize text with this reviewer's Bleach configuration."""

        if not isinstance(text, str):
            raise TypeError("comment must be text")
        cleaned = self.cleaner.clean(text)
        if self._linker is not None:
            cleaned = self._linker.linkify(cleaned)
        return cleaned

    clean = sanitize

    def submit(self, text):
        """Sanitize and submit a new comment revision."""

        if not isinstance(text, str):
            raise TypeError("comment must be text")

        sanitized = self.sanitize(text)
        blocks = list(parse_comment_blocks(sanitized))
        self._revision_count += 1
        previous = self._revision
        revision = CommentRevision(
            number=self._revision_count,
            source=text,
            sanitized=sanitized,
            blocks=tuple(blocks),
            previous_number=previous.number if previous else None,
        )

        if previous is None:
            for block in revision.blocks:
                self._new_stable_id(block)
                block.change = "new"
            self._revision = revision
            self._evaluate(revision, previous=None, mapping={}, groups=[])
        else:
            mapping, groups = self._link_blocks(previous.blocks, revision.blocks)
            self._apply_lineage(previous.blocks, revision.blocks, mapping)
            self._revision = revision
            self._evaluate(
                revision,
                previous=previous,
                mapping=mapping,
                groups=groups,
            )
        return revision

    def _new_stable_id(self, block):
        self._next_stable += 1
        block.stable_id = "s%s" % self._next_stable
        return block.stable_id

    def _link_blocks(self, previous_blocks, blocks):
        """Match old blocks to new blocks and return mapping and gap groups."""

        mapping = self._align_blocks(previous_blocks, blocks)
        anchors = sorted(mapping.items())
        groups = []
        old_start = 0
        new_start = 0
        for old_anchor, new_anchor in anchors:
            old_group = tuple(previous_blocks[old_start:old_anchor])
            new_group = tuple(blocks[new_start:new_anchor])
            if old_group or new_group:
                groups.append(
                    (
                        old_group,
                        new_group,
                        self._is_structural_repartition(old_group, new_group),
                    )
                )
            old_start = old_anchor + 1
            new_start = new_anchor + 1

        old_group = tuple(previous_blocks[old_start:])
        new_group = tuple(blocks[new_start:])
        if old_group or new_group:
            groups.append(
                (
                    old_group,
                    new_group,
                    self._is_structural_repartition(old_group, new_group),
                )
            )
        return mapping, groups

    def _align_blocks(self, previous_blocks, blocks):
        """Align equal blocks, preferring nearby duplicate occurrences.

        A plain longest-common-subsequence match is not enough here: given
        two identical paragraphs, a change in the first one can make the
        matcher pair the *second* old paragraph with the first new one.  The
        dynamic program below assigns a small cost to skipping a block and a
        cost proportional to the distance between matched duplicate
        occurrences, so edits keep their positional identity while a newly
        inserted paragraph still lines up the copies before it.
        """

        old_count = len(previous_blocks)
        new_count = len(blocks)
        gap_cost = 1.5
        infinity = float("inf")

        # Cost table and choice table for backtracking.
        costs = [[infinity] * (new_count + 1) for _ in range(old_count + 1)]
        choices = [[None] * (new_count + 1) for _ in range(old_count + 1)]
        costs[0][0] = 0.0

        for old_index in range(old_count + 1):
            for new_index in range(new_count + 1):
                current = costs[old_index][new_index]
                if current == infinity:
                    continue

                if (
                    old_index < old_count
                    and new_index < new_count
                    and previous_blocks[old_index].digest == blocks[new_index].digest
                ):
                    distance = abs(old_index - new_index)
                    candidate = current + distance
                    if candidate < costs[old_index + 1][new_index + 1]:
                        costs[old_index + 1][new_index + 1] = candidate
                        choices[old_index + 1][new_index + 1] = (
                            "match",
                            old_index,
                            new_index,
                        )

                if old_index < old_count:
                    candidate = current + gap_cost
                    if candidate < costs[old_index + 1][new_index]:
                        costs[old_index + 1][new_index] = candidate
                        choices[old_index + 1][new_index] = (
                            "skip-old",
                            old_index,
                            new_index,
                        )

                if new_index < new_count:
                    candidate = current + gap_cost
                    if candidate < costs[old_index][new_index + 1]:
                        costs[old_index][new_index + 1] = candidate
                        choices[old_index][new_index + 1] = (
                            "skip-new",
                            old_index,
                            new_index,
                        )

        mapping = {}
        old_index, new_index = old_count, new_count
        while old_index or new_index:
            choice = choices[old_index][new_index]
            if choice is None:
                break
            action, previous_old, previous_new = choice
            if action == "match":
                mapping[previous_old] = previous_new
            old_index, new_index = previous_old, previous_new
        return mapping

    def _is_structural_repartition(self, old_group, new_group):
        if not old_group or not new_group:
            return False
        if len(old_group) == len(new_group) == 1:
            # A single changed block is not a split/merge.  If the digest
            # changed, the reviewed source changed.
            return False
        if len(old_group) == len(new_group):
            # Equal-sized replacement groups are ambiguous.  Be conservative
            # and require review rather than carrying an approval across them.
            return False
        return _group_text(old_group) == _group_text(new_group) and _group_links(
            old_group
        ) == _group_links(new_group)

    def _apply_lineage(self, previous_blocks, blocks, mapping):
        for old_index, new_index in mapping.items():
            old_block = previous_blocks[old_index]
            new_block = blocks[new_index]
            new_block.stable_id = old_block.stable_id
            new_block.previous_stable_id = old_block.stable_id
            new_block.change = "unchanged"

        mapped_new = set(mapping.values())
        for block in blocks:
            if block.index in mapped_new:
                continue
            self._new_stable_id(block)
            block.change = "new"

        # Give unmapped blocks a positional predecessor for useful diagnostics
        # even though that predecessor's approval is never transferred.
        for old_index, old_block in enumerate(previous_blocks):
            if old_index in mapping:
                continue
            if old_index < len(blocks):
                block = blocks[old_index]
                if block.previous_stable_id is None:
                    block.previous_stable_id = old_block.stable_id
                    if block.change == "new":
                        block.change = "changed"

    # -- approvals -------------------------------------------------------

    def approve(
        self,
        block=None,
        link=None,
        *,
        href=None,
        block_index=None,
        link_index=None,
        block_id=None,
        link_id=None,
        moderator=None,
        note=None,
        approve_all=False,
        metadata=None,
        **kwargs,
    ):
        """Approve one link occurrence.

        ``block`` can be a :class:`CommentBlock`, a block id such as ``"b2"``,
        a stable id, or a zero-based block index.  ``link`` can be a
        :class:`CommentLink`, a link id such as ``"l1"``, a zero-based link
        index, or an href unique in the block.  For convenience the link object
        itself may be passed as the first argument.
        """

        revision = self._require_revision()
        if isinstance(block, CommentLink) and link is None:
            link = block
            block = None
        if block_index is not None:
            block = block_index
        if block_id is not None:
            block = block_id
        if link_index is not None:
            link = link_index
        if link_id is not None:
            link = link_id
        if kwargs.get("url") is not None:
            href = kwargs["url"]
        if kwargs.get("all"):
            approve_all = True

        if approve_all:
            if block is None and link is None and href is None:
                links = list(revision.links)
            else:
                block_obj = self._resolve_block(revision, block)
                links = list(block_obj.links)
            return tuple(
                self.approve(
                    candidate,
                    moderator=moderator,
                    note=note,
                    metadata=metadata,
                )
                for candidate in links
            )

        if isinstance(link, CommentLink):
            return self._approve_link(
                revision,
                revision.blocks[link.block_index],
                link,
                moderator=moderator,
                note=note,
                metadata=metadata,
            )

        if block is None and isinstance(link, (int, str)) and href is None:
            # Let approve("l1") / approve(0) work when the selector is
            # unambiguous across the revision.
            try:
                link_obj = revision.link(link)
            except LookupError:
                link_obj = None
            if link_obj is not None:
                return self._approve_link(
                    revision,
                    revision.blocks[link_obj.block_index],
                    link_obj,
                    moderator=moderator,
                    note=note,
                    metadata=metadata,
                )

        if block is None and href is not None:
            matches = [
                candidate for candidate in revision.links if candidate.href == href
            ]
            if len(matches) != 1:
                raise LookupError("href must identify exactly one link")
            link_obj = matches[0]
            return self._approve_link(
                revision,
                revision.blocks[link_obj.block_index],
                link_obj,
                moderator=moderator,
                note=note,
                metadata=metadata,
            )

        block_obj = self._resolve_block(revision, block)
        link_obj = self._resolve_link(revision, block_obj, link, href=href)
        return self._approve_link(
            revision,
            block_obj,
            link_obj,
            moderator=moderator,
            note=note,
            metadata=metadata,
        )

    approve_link = approve
    confirm = approve

    def _resolve_block(self, revision, selector):
        if selector is None:
            raise ValueError("a block selector is required")
        return revision.block(selector)

    def _resolve_link(self, revision, block, selector, href=None):
        if href is not None:
            matches = [link for link in block.links if link.href == href]
            if len(matches) != 1:
                raise LookupError(
                    "href must identify exactly one link in %s" % block.block_id
                )
            return matches[0]
        if selector is None:
            if len(block.links) == 1:
                return block.links[0]
            if not block.links:
                raise LookupError("block %s has no links" % block.block_id)
            raise ValueError(
                "block %s has %s links; specify a link"
                % (block.block_id, len(block.links))
            )
        return block.link(selector)

    def _approve_link(
        self, revision, block, link, moderator=None, note=None, metadata=None
    ):
        existing = None
        for approval in self._approvals.values():
            if (
                approval.stable_block_id == block.stable_id
                and approval.link_key == link.link_key
                and approval.valid
            ):
                existing = approval
                break

        if existing is not None:
            if moderator is not None:
                existing.moderator = moderator
            if note is not None:
                existing.note = note
            if metadata:
                existing.metadata.update(
                    {str(key): str(value) for key, value in metadata.items()}
                )
            return existing

        approval_id = (
            "apr_%s"
            % _sha256("%s:%s:%s" % (block.digest, block.occurrence, link.link_key))[:24]
        )
        prefix = _normalize_text(block.text[: link.start])
        suffix = _normalize_text(block.text[link.end :])
        approval = LinkApproval(
            approval_id=approval_id,
            href=link.href,
            link_text=link.text,
            block_id=block.block_id,
            block_digest=block.digest,
            block_occurrence=block.occurrence,
            link_id=link.link_id,
            link_key=link.link_key,
            link_offset=link.link_offset,
            source_fragment=block.normalized_text,
            prefix=prefix,
            suffix=suffix,
            moderator=moderator,
            note=note,
            revision=revision.number,
            stable_block_id=block.stable_id,
            bound_block_id=block.block_id,
            bound_block_stable_id=block.stable_id,
            bound_link_key=link.link_key,
            last_checked_revision=revision.number,
            metadata={str(key): str(value) for key, value in (metadata or {}).items()},
        )
        self._approvals[approval.approval_id] = approval
        return approval

    def revoke(self, approval=None, *, block=None, link=None, href=None):
        """Remove an approval.  Returns ``True`` if something was removed."""

        if approval is None and (
            block is not None or link is not None or href is not None
        ):
            revision = self._require_revision()
            if href is not None and block is None:
                matches = [
                    candidate for candidate in revision.links if candidate.href == href
                ]
                if len(matches) != 1:
                    raise LookupError("href must identify exactly one link")
                link = matches[0]
            if isinstance(link, CommentLink):
                approval = self._find_approval(link)
            else:
                block_obj = self._resolve_block(revision, block)
                link_obj = self._resolve_link(revision, block_obj, link, href=href)
                approval = self._find_approval(link_obj)

        if isinstance(approval, LinkApproval):
            approval = approval.approval_id
        if approval is None:
            return False
        return self._approvals.pop(approval, None) is not None

    unapprove = revoke

    def _find_approval(self, link):
        for approval in self._approvals.values():
            if approval.valid and approval.bound_link_key == link.link_key:
                return approval
        return None

    # -- checking --------------------------------------------------------

    def check(self, text=None, revision=None):
        """Return a :class:`ApprovalCheck` for a new or current revision."""

        if revision is not None:
            checked = revision
        elif text is not None:
            checked = self.submit(text)
        else:
            checked = self._require_revision()
            # Re-evaluate imported approvals or approvals changed outside the
            # normal submit path against the current revision.
            self._evaluate(
                checked,
                previous=checked,
                mapping={block.index: block.index for block in checked.blocks},
                groups=[],
            )

        return self._build_check(checked)

    resend_check = check
    validate_comment = check
    inspect = check

    def validate(self, text=None, revision=None):
        """Return whether the current/check revision is safe to send."""

        return self.check(text=text, revision=revision).ok

    is_valid = validate
    can_send = validate

    def pending_links(self, text=None, revision=None):
        return self.check(text=text, revision=revision).pending_links

    def approved_links(self, text=None, revision=None):
        return self.check(text=text, revision=revision).approved_links

    def approve_all(self, block=None, **kwargs):
        """Approve every selected link occurrence in one call."""

        return self.approve(block=block, approve_all=True, **kwargs)

    def clear_approvals(self):
        """Forget every approval while keeping the current revision."""

        self._approvals.clear()

    def review(self, text=None, revision=None):
        """Return a JSON-friendly moderator review view."""

        return self.check(text=text, revision=revision).review_view()

    def review_view(self, text=None, revision=None):
        return self.review(text=text, revision=revision)

    preview = review_view

    def _build_check(self, revision):
        covered = {}
        for approval in self._approvals.values():
            if (
                approval.valid
                and approval.bound_block_stable_id
                and approval.bound_link_key
            ):
                covered[(approval.bound_block_stable_id, approval.bound_link_key)] = (
                    approval
                )

        approved_links = []
        pending_links = []
        link_statuses = []
        for block in revision.blocks:
            for link in block.links:
                key = (block.stable_id, link.link_key)
                approval = covered.get(key)
                status = {
                    "block_id": block.block_id,
                    "block_stable_id": block.stable_id,
                    "link_id": link.link_id,
                    "link_key": link.link_key,
                    "href": link.href,
                    "text": link.text,
                    "status": "approved" if approval else "pending",
                    "approval_id": approval.approval_id if approval else None,
                }
                link_statuses.append(status)
                if approval:
                    approved_links.append(link)
                else:
                    pending_links.append(link)

        approvals = tuple(self._approvals.values())
        return ApprovalCheck(
            revision=revision,
            approved_links=tuple(approved_links),
            pending_links=tuple(pending_links),
            approvals=approvals,
            stale_approvals=tuple(
                approval for approval in approvals if approval.status == "stale"
            ),
            diagnostics=tuple(approval.diagnostic() for approval in approvals),
            link_statuses=tuple(link_statuses),
        )

    # -- lineage evaluation ---------------------------------------------

    def _evaluate(self, revision, previous, mapping, groups):
        previous_blocks = previous.blocks if previous is not None else ()
        previous_by_stable = {
            block.stable_id: block for block in previous_blocks if block.stable_id
        }
        mapped_new = set(mapping.values())

        for approval in self._approvals.values():
            approval.last_checked_revision = revision.number
            approval.reason = None
            approval.invalidated_by = None
            approval.moved_to = None
            approval.bound_block_id = None
            approval.bound_block_stable_id = None
            approval.bound_link_key = None

            old_block = None
            if approval.stable_block_id:
                old_block = previous_by_stable.get(approval.stable_block_id)

            if old_block is None:
                # Imported approvals have no session-local lineage.  Bind them
                # by content and block occurrence instead.
                old_block = _find_block_by_digest(
                    previous_blocks,
                    approval.block_digest,
                    approval.block_occurrence,
                )

            target = None
            carried = False
            target_link = None

            if old_block is not None:
                new_index = mapping.get(old_block.index)
                if new_index is not None:
                    candidate = revision.blocks[new_index]
                    if candidate.digest == approval.block_digest:
                        candidate_link = _link_for_approval(candidate, approval)
                        if candidate_link is not None:
                            target = candidate
                            target_link = candidate_link

                if target is None:
                    candidates = []
                    for old_group, new_group, structural in groups:
                        if not structural or old_block not in old_group:
                            continue
                        old_offset = _group_offset(old_group, old_block)
                        for candidate in new_group:
                            new_offset = _group_offset(new_group, candidate)
                            candidate_link = _carry_candidate(
                                approval,
                                old_block,
                                candidate,
                                old_offset=old_offset,
                                new_offset=new_offset,
                            )
                            if candidate_link is not None:
                                candidates.append((candidate, candidate_link))
                    if len(candidates) == 1:
                        target, target_link = candidates[0]
                        carried = True
                    elif len(candidates) > 1:
                        approval.status = "stale"
                        approval.reason = "ambiguous"
                        approval.invalidated_by = "multiple-candidates"
                        continue

            if (
                target is None
                and old_block is None
                and approval.stable_block_id is None
            ):
                # Last-resort content binding, still respecting the duplicate
                # block occurrence so two identical blocks are not collapsed.
                candidate = _find_block_by_digest(
                    revision.blocks,
                    approval.block_digest,
                    approval.block_occurrence,
                )
                if candidate is not None:
                    candidate_link = _link_for_approval(candidate, approval)
                    if candidate_link is not None:
                        target = candidate
                        target_link = candidate_link

            if target is not None and target_link is not None:
                approval.status = "carried" if carried else "valid"
                approval.stable_block_id = target.stable_id
                approval.block_id = target.block_id
                approval.block_digest = target.digest
                approval.block_occurrence = target.occurrence
                approval.link_id = target_link.link_id
                approval.link_key = target_link.link_key
                approval.link_offset = target_link.link_offset
                approval.source_fragment = target.normalized_text
                approval.prefix = _normalize_text(target.text[: target_link.start])
                approval.suffix = _normalize_text(target.text[target_link.end :])
                approval.bound_block_id = target.block_id
                approval.bound_block_stable_id = target.stable_id
                approval.bound_link_key = target_link.link_key
                if carried:
                    approval.origin_approval_id = (
                        approval.origin_approval_id or approval.approval_id
                    )
                continue

            approval.status = "stale"
            reason, moved_to = self._stale_reason(
                approval,
                old_block,
                revision,
                previous_blocks,
                mapped_new,
            )
            approval.reason = reason
            approval.moved_to = moved_to
            approval.invalidated_by = reason

    def _stale_reason(
        self,
        approval,
        old_block,
        revision,
        previous_blocks,
        mapped_new,
    ):
        same_link = []
        for block in revision.blocks:
            for link in block.links:
                if link.href == approval.href and _normalize_text(
                    link.text
                ) == _normalize_text(approval.link_text):
                    same_link.append(block)

        if same_link:
            if old_block is None:
                return "moved", same_link[0].block_id
            for candidate in same_link:
                if (
                    candidate.previous_stable_id == old_block.stable_id
                    or candidate.stable_id == old_block.stable_id
                ):
                    return "block-changed", candidate.block_id
            return "moved", same_link[0].block_id

        if old_block is not None:
            new_position = None
            for old_index, new_index in self._last_mapping(
                previous_blocks, revision
            ).items():
                if previous_blocks[old_index].stable_id == old_block.stable_id:
                    new_position = new_index
                    break
            if new_position is not None and new_position in mapped_new:
                return "block-changed", revision.blocks[new_position].block_id
            if old_block.index < len(revision.blocks):
                return "block-changed", revision.blocks[old_block.index].block_id
            return "removed", None

        return "content-changed", None

    def _last_mapping(self, previous_blocks, revision):
        mapping = {}
        for index in range(min(len(previous_blocks), len(revision.blocks))):
            if previous_blocks[index].digest == revision.blocks[index].digest:
                mapping[index] = index
        return mapping

    # -- serialization ---------------------------------------------------

    @property
    def approvals(self):
        return tuple(self._approvals.values())

    @property
    def revision(self):
        return self._revision

    @property
    def links(self):
        if self._revision is None:
            return ()
        return self._revision.links

    def _require_revision(self):
        if self._revision is None:
            raise RuntimeError("submit or check a comment before approving links")
        return self._revision

    def export_approvals(self):
        """Return serializable approval records."""

        return [approval.to_dict() for approval in self._approvals.values()]

    def dumps_approvals(self, indent=2):
        return json.dumps(self.export_approvals(), ensure_ascii=False, indent=indent)

    def load_approvals(self, records, replace=False):
        """Load approval records produced by :meth:`export_approvals`."""

        if isinstance(records, str):
            records = json.loads(records)
        if isinstance(records, LinkApproval):
            records = [records]
        elif isinstance(records, Mapping):
            if "approvals" in records:
                records = records["approvals"]
            elif "approval_id" in records:
                records = [records]
            else:
                records = []
        if records is None:
            records = []
        if replace:
            self._approvals.clear()

        loaded = []
        for record in records:
            approval = LinkApproval.from_dict(record)
            # A restored approval is content-addressed.  It will be rebound to
            # the matching current block on the next check.
            approval.stable_block_id = None
            approval.bound_block_id = None
            approval.bound_block_stable_id = None
            approval.bound_link_key = None
            approval.status = "valid"
            self._approvals[approval.approval_id] = approval
            loaded.append(approval)

        if self._revision is not None:
            self._evaluate(
                self._revision,
                previous=self._revision,
                mapping={block.index: block.index for block in self._revision.blocks},
                groups=[],
            )
        return tuple(loaded)

    import_approvals = load_approvals
    from_records = load_approvals

    def to_dict(self):
        """Return the current revision and approvals as plain data."""

        return {
            "revision": self._revision.to_dict() if self._revision else None,
            "approvals": self.export_approvals(),
        }

    def to_json(self, indent=None):
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    @classmethod
    def from_dict(cls, data, **kwargs):
        """Restore a reviewer state produced by :meth:`to_dict`."""

        reviewer = cls(**kwargs)
        revision = data.get("revision") if isinstance(data, Mapping) else None
        if revision:
            source = revision.get("source", revision.get("sanitized", ""))
            reviewer.submit(source)
        approvals = data.get("approvals", []) if isinstance(data, Mapping) else []
        reviewer.load_approvals(approvals, replace=True)
        return reviewer

    @classmethod
    def from_json(cls, value, **kwargs):
        return cls.from_dict(json.loads(value), **kwargs)

    def __len__(self):
        return len(self._approvals)

    def __iter__(self):
        return iter(self._approvals.values())


def _find_block_by_digest(blocks, digest, occurrence):
    for block in blocks:
        if block.digest == digest and block.occurrence == occurrence:
            return block
    return None


def _link_for_approval(block, approval):
    for link in block.links:
        if link.link_key == approval.link_key:
            return link
    # Keep a conservative fallback for records imported from older
    # serializations where the link key format may differ.
    matches = [
        link
        for link in block.links
        if link.href == approval.href
        and _normalize_text(link.text) == _normalize_text(approval.link_text)
    ]
    if len(matches) == 1:
        return matches[0]
    return None


def _carry_candidate(approval, old_block, candidate, old_offset=0, new_offset=0):
    """Return the candidate link if a pure split/merge preserved the source."""

    for link in candidate.links:
        if link.href != approval.href:
            continue
        if _normalize_text(link.text) != _normalize_text(approval.link_text):
            continue

        old_position = old_offset + approval.link_offset
        new_position = new_offset + link.link_offset

        # The old and new groups are a structural repartition, so the same
        # reviewed link has to sit at the same offset in the joined group.
        # Comparing offsets (not just block-local text) keeps two identical
        # links in two split pieces from being confused with each other.
        if old_position == new_position:
            return link

    return None


def _group_offset(blocks, target):
    """Return the normalized offset of ``target`` in a joined block group."""

    parts = []
    for block in blocks:
        if block is target:
            break
        parts.append(block.normalized_text)
    if not parts:
        return 0
    return len(" ".join(parts)) + 1


def _approx_link_start(block, approval):
    """Find the approved link's position without trusting a moved occurrence."""

    prefix_len = len(approval.prefix)
    for link in block.links:
        if link.href != approval.href:
            continue
        if _normalize_text(link.text) != _normalize_text(approval.link_text):
            continue
        if len(_normalize_text(block.text[: link.start])) == prefix_len:
            return link.start
    # Fall back to the first same-looking link.  The exact key match above is
    # preferred; this only helps imported records from older formats.
    for link in block.links:
        if link.href == approval.href:
            return link.start
    return 0


def _group_text(blocks):
    return _normalize_text(" ".join(block.normalized_text for block in blocks))


def _group_links(blocks):
    return tuple(
        (link.href, _normalize_text(link.text))
        for block in blocks
        for link in block.links
    )


def review_comment(text, approvals=None, **kwargs):
    """Convenience helper: submit text, load approvals, and check it."""

    reviewer = CommentReviewer(**kwargs)
    reviewer.submit(text)
    if approvals:
        reviewer.load_approvals(approvals)
    return reviewer.check()


def check_comment(text, approvals=None, **kwargs):
    return review_comment(text, approvals=approvals, **kwargs)


def clean_comment(text, **kwargs):
    return CommentReviewer(**kwargs).sanitize(text)


def linkify_comment(text, **kwargs):
    """Sanitize text and turn bare URLs into reviewable links."""

    kwargs["linkify"] = True
    return CommentReviewer(**kwargs).sanitize(text)


clean_and_linkify = linkify_comment


#: A few descriptive aliases for hosts that prefer different terminology.
ModeratedComment = CommentReviewer
CommentApprovals = CommentReviewer
CommentModeration = CommentReviewer
CommentReview = CommentReviewer
ReviewSession = CommentReviewer
Moderator = CommentReviewer
ModerationSession = CommentReviewer
CommentApprovalSystem = CommentReviewer
LinkApprover = CommentReviewer
CommentModerator = CommentReviewer
CommentApproval = LinkApproval
ModeratorApproval = LinkApproval
LinkApprovalRecord = LinkApproval

# Method aliases for common host vocabulary.
CommentReviewer.submit_for_review = CommentReviewer.submit
CommentReviewer.resubmit = CommentReviewer.submit
CommentReviewer.submit_comment = CommentReviewer.submit
CommentReviewer.prepare = CommentReviewer.submit
CommentReviewer.process = CommentReviewer.submit
CommentReviewer.check_resend = CommentReviewer.check
CommentReviewer.check_for_resend = CommentReviewer.check
CommentReviewer.resend = CommentReviewer.check
CommentReviewer.verify = CommentReviewer.validate
CommentReviewer.can_publish = CommentReviewer.validate
CommentReviewer.pending = CommentReviewer.pending_links
CommentReviewer.sanitize_comment = CommentReviewer.sanitize
CommentReviewer.clean_comment = CommentReviewer.sanitize
sanitize_and_review = review_comment

LinkApproval.as_dict = LinkApproval.to_dict
ApprovalCheck.as_dict = ApprovalCheck.to_dict


__all__ = [
    "APPROVAL_SCHEMA",
    "BLOCK_TAGS",
    "COMMENT_ATTRIBUTES",
    "COMMENT_TAGS",
    "ApprovalCheck",
    "ApprovalRecord",
    "ApprovedLink",
    "CheckResult",
    "CommentApproval",
    "CommentApprovalSystem",
    "CommentApprovals",
    "CommentBlock",
    "CommentLink",
    "CommentModeration",
    "CommentModerator",
    "CommentReview",
    "CommentReviewer",
    "CommentRevision",
    "LinkApprovalRecord",
    "LinkApproval",
    "LinkApprover",
    "ModeratedComment",
    "ModerationSession",
    "Moderator",
    "ModeratorApproval",
    "ResendCheck",
    "ReviewResult",
    "ReviewSession",
    "check_comment",
    "clean_comment",
    "clean_and_linkify",
    "linkify_comment",
    "parse_comment_blocks",
    "review_comment",
    "sanitize_and_review",
    "sanitize_comment",
]
