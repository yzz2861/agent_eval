"""Optional, caller-trusted status re-check on top of the sanitizer.

The sanitizer turns rich-text forms into shareable summaries. A user may
type the literal words "已批准" (approved) into a form, but that text is
not a trusted approval: the trust decision always belongs to the caller.

This module is an *optional* entry point. The default :class:`Sanitizer`
behavior is unchanged. A caller that wants a status re-check constructs a
:class:`StatusReviewer`, hands it the trusted markers separately, and lets
the reviewer stamp the matching DOM explanation elements. The stamped
attributes travel through the cleaning pipeline, so the final, reader
visible status is always backed by an explanation element that actually
survived cleaning.

Three fragile transitions are covered explicitly:

* Tag migration -- e.g. ``<b>`` becomes ``<strong>`` or a bold ``<span>``
  becomes ``<strong>``. Stamping happens before migration, the marker
  attributes are allowed on every destination tag, and the original and
  final tag are both recorded.
* Duplicate text -- repeated "已批准" claims are counted but only a
  caller-supplied marker can make a claim trusted. Duplicates outside the
  trusted anchor never upgrade the status.
* Cleaning removes the marker -- when the explanation element (or its
  marker attributes) is dropped during cleaning the evidence is reported as
  removed, and the archive view must not issue an approval conclusion.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

import lxml.html

from .sanitizer import DEFAULT_SETTINGS, Sanitizer

__all__ = (
    "MARKER_ATTRIBUTE",
    "STATUS_ATTRIBUTE",
    "TrustedStatus",
    "StatusMarker",
    "StatusEvidence",
    "ReviewResult",
    "ArchiveConclusion",
    "StatusReviewSanitizer",
    "StatusReviewer",
    "RETAINED",
    "MARKER_REMOVED",
    "ANCHOR_NOT_FOUND",
)


#: Attribute linking a surviving DOM element to a caller-supplied marker id.
MARKER_ATTRIBUTE = "data-trusted-marker"
#: Attribute carrying the caller-trusted status onto the reader-visible HTML.
STATUS_ATTRIBUTE = "data-trusted-status"

#: The explanation element survived cleaning and still carries the marker.
RETAINED = "retained"
#: The explanation element survived but cleaning stripped the marker.
MARKER_REMOVED = "marker-removed"
#: No DOM element matched the marker's anchor before cleaning.
ANCHOR_NOT_FOUND = "anchor-not-found"


class TrustedStatus(str, Enum):
    """Statuses that a caller is allowed to attest for a marker."""

    APPROVED = "approved"
    REJECTED = "rejected"
    PENDING = "pending"


@dataclass(frozen=True)
class StatusMarker:
    """A trusted fact supplied by the caller, never inferred from the HTML.

    ``marker_id`` is the stable identity used to link the marker across
    cleaning. ``anchor_id`` identifies the DOM element that explains the
    status (the element carrying ``id="<anchor_id>"`` in the submitted
    form). ``claim`` is the literal wording a reader sees inside that
    explanation, e.g. ``"已批准"``.
    """

    marker_id: str
    status: TrustedStatus
    anchor_id: str
    claim: str

    def __post_init__(self):
        if not self.marker_id:
            raise ValueError("StatusMarker.marker_id must not be empty")
        if not self.anchor_id:
            raise ValueError("StatusMarker.anchor_id must not be empty")
        if not isinstance(self.status, TrustedStatus):
            raise TypeError(
                "StatusMarker.status must be a TrustedStatus value; trust"
                " decisions cannot be parsed from document text"
            )


@dataclass(frozen=True)
class StatusEvidence:
    """The cleaning trace for a single marker."""

    marker: StatusMarker
    disposition: str
    original_tag: str | None
    final_tag: str | None

    @property
    def retained(self):
        """True when the explanation and its marker survived cleaning."""
        return self.disposition == RETAINED


@dataclass(frozen=True)
class ReviewResult:
    """Cleaned HTML together with the status re-check outcome."""

    cleaned_html: str
    evidence: tuple[StatusEvidence, ...]
    claim_occurrences: int
    untrusted_claim_occurrences: int

    def retained_evidence(self):
        return tuple(item for item in self.evidence if item.retained)

    def reader_visible_statuses(self):
        """Map marker id -> trusted status for markers a reader can verify.

        Only retained evidence is exposed. The status matches the
        :data:`STATUS_ATTRIBUTE` present on the surviving explanation
        element in :attr:`cleaned_html`, so the visible explanation and the
        readable status are explicitly linked.
        """
        return {
            item.marker.marker_id: item.marker.status.value
            for item in self.retained_evidence()
        }

    def status_line(self):
        """One-line, reader-facing summary of every retained status."""
        visible = self.reader_visible_statuses()
        if not visible:
            return "无可信状态依据"
        return "；".join(
            f"{marker_id}: {status}" for marker_id, status in visible.items()
        )

    def archive_conclusion(self):
        return archive_conclusion(self)


@dataclass(frozen=True)
class ArchiveConclusion:
    """What an archive view is allowed to state about the document."""

    approved: bool
    approved_marker_ids: frozenset[str]
    missing_marker_ids: frozenset[str]
    untrusted_claim_occurrences: int
    reason: str


def archive_conclusion(result):
    """Decide the archive statement from retained trusted evidence only.

    An approval conclusion is issued solely when at least one caller-trusted
    marker with :data:`TrustedStatus.APPROVED` survives cleaning. User-typed
    "已批准" text (counted in ``untrusted_claim_occurrences``) and removed
    markers can never produce an approval.
    """

    approved = frozenset(
        item.marker.marker_id
        for item in result.retained_evidence()
        if item.marker.status is TrustedStatus.APPROVED
    )
    missing = frozenset(
        item.marker.marker_id
        for item in result.evidence
        if not item.retained
    )
    if approved:
        reason = (
            "批准结论基于保留下来的可信标记："
            + ", ".join(sorted(approved))
        )
    elif missing:
        reason = (
            "可信依据在清洗中丢失（"
            + ", ".join(sorted(missing))
            + "），不得仅凭正文文字出具批准结论"
        )
    else:
        reason = "未提供可信批准标记，不得仅凭正文文字出具批准结论"
    return ArchiveConclusion(
        approved=bool(approved),
        approved_marker_ids=approved,
        missing_marker_ids=missing,
        untrusted_claim_occurrences=result.untrusted_claim_occurrences,
        reason=reason,
    )


class StatusReviewSanitizer(Sanitizer):
    """Sanitizer that never merges two distinctly marked explanations.

    Merging adjacent same-tag elements would otherwise silently drop the
    second element's marker attributes. Elements carrying different marker
    ids are kept distinct; everything else follows the default merge rules.
    """

    @staticmethod
    def is_mergeable(e1, e2):
        marker1 = e1.get(MARKER_ATTRIBUTE)
        marker2 = e2.get(MARKER_ATTRIBUTE)
        if marker1 is not None or marker2 is not None:
            return marker1 == marker2
        return True


class StatusReviewer:
    """Optional re-check entry point; trust is supplied by the caller.

    Construct with the trusted :class:`StatusMarker` objects (which are
    independent of the submitted HTML) and optionally extra sanitizer
    settings. Then call :meth:`review` per document.
    """

    def __init__(self, markers, *, settings=None, claim_word="已批准"):
        self.markers = tuple(markers)
        self.claim_word = claim_word
        self._by_anchor = {}
        for marker in self.markers:
            existing = self._by_anchor.get(marker.anchor_id)
            if existing is not None and existing.marker_id != marker.marker_id:
                raise ValueError(
                    f"Anchor id {marker.anchor_id!r} is claimed by markers"
                    f" {existing.marker_id!r} and {marker.marker_id!r}"
                )
            self._by_anchor[marker.anchor_id] = marker

        self.sanitizer = StatusReviewSanitizer(self._build_settings(settings))
        # Transient per-document bookkeeping, reset on every review() call.
        self._seen_anchors = {}
        self._tag_trace = {}

    def _build_settings(self, overrides):
        settings = dict(DEFAULT_SETTINGS)
        settings.update(overrides or {})

        tags = set(settings["tags"])
        tracking_attributes = (MARKER_ATTRIBUTE, STATUS_ATTRIBUTE)
        attributes = {
            tag: tuple(attrs) + tracking_attributes
            for tag, attrs in settings["attributes"].items()
        }
        for tag in tags:
            attributes.setdefault(tag, tracking_attributes)
        settings["attributes"] = attributes

        preprocessors = [
            self._stamp_marker,
            *settings["element_preprocessors"],
        ]
        settings["element_preprocessors"] = preprocessors
        settings["element_postprocessors"] = [
            *settings["element_postprocessors"],
            self._record_final_tag,
        ]
        return settings

    def _stamp_marker(self, element):
        anchor_id = element.get("id")
        if anchor_id is None:
            return element
        marker = self._by_anchor.get(anchor_id)
        if marker is None:
            # An id without a caller marker is ordinary content; the
            # attribute will be removed again because it is not allowed.
            return element

        count = self._seen_anchors.get(anchor_id, 0)
        self._seen_anchors[anchor_id] = count + 1
        if count == 0:
            self._tag_trace[marker.marker_id] = {
                "original_tag": element.tag,
                "final_tag": element.tag,
            }
        element.set(MARKER_ATTRIBUTE, marker.marker_id)
        element.set(STATUS_ATTRIBUTE, marker.status.value)
        return element

    def _record_final_tag(self, element):
        marker_id = element.get(MARKER_ATTRIBUTE)
        if marker_id is not None and marker_id in self._tag_trace:
            self._tag_trace[marker_id]["final_tag"] = element.tag
        return element

    def review(self, html):
        """Clean ``html`` and re-check every trusted marker against it."""
        self._seen_anchors = {}
        self._tag_trace = {}

        cleaned = self.sanitizer.sanitize(html)
        surviving = self._parse_surviving_markers(cleaned)

        evidence = tuple(
            self._build_evidence(marker, surviving) for marker in self.markers
        )
        claim_occurrences, untrusted = self._count_claims(html, evidence)
        return ReviewResult(
            cleaned_html=cleaned,
            evidence=evidence,
            claim_occurrences=claim_occurrences,
            untrusted_claim_occurrences=untrusted,
        )

    def _parse_surviving_markers(self, cleaned):
        surviving = {}
        if MARKER_ATTRIBUTE not in cleaned:
            return surviving
        root = lxml.html.fromstring(f"<div>{cleaned}</div>")
        for node in root.iter():
            marker_id = node.get(MARKER_ATTRIBUTE)
            if marker_id is None:
                continue
            surviving[marker_id] = {
                "final_tag": node.tag,
                "status": node.get(STATUS_ATTRIBUTE),
            }
        return surviving

    def _build_evidence(self, marker, surviving):
        if self._seen_anchors.get(marker.anchor_id, 0) == 0:
            disposition = ANCHOR_NOT_FOUND
        elif marker.marker_id in surviving:
            disposition = RETAINED
        else:
            disposition = MARKER_REMOVED

        trace = self._tag_trace.get(marker.marker_id, {})
        final_tag = surviving.get(marker.marker_id, {}).get(
            "final_tag", trace.get("final_tag")
        )
        return StatusEvidence(
            marker=marker,
            disposition=disposition,
            original_tag=trace.get("original_tag"),
            final_tag=final_tag if disposition == RETAINED else None,
        )

    def _count_claims(self, raw_html, evidence):
        document = lxml.html.fromstring("<div>%s</div>" % raw_html)
        total = document.text_content().count(self.claim_word)

        trusted_claims = 0
        for item in evidence:
            if not item.retained:
                continue
            trusted_claims += item.marker.claim.count(self.claim_word)
        return total, max(0, total - trusted_claims)

    def reader_line(self, evidence):
        """Human-readable line tying one explanation element to its status.

        The line names the reader-visible tag and the ``data-trusted-marker``
        id that the cleaned HTML actually carries, so the DOM explanation and
        the status a reader sees can be correlated without trusting document
        text.
        """

        if not evidence.retained:
            return (
                f"标记 {evidence.marker.marker_id} 在清洗后无可信依据"
                f"（{evidence.disposition}）"
            )
        return (
            f"<{evidence.final_tag} {MARKER_ATTRIBUTE}="
            f'"{evidence.marker.marker_id}"> 的说明对应读者可见状态：'
            f"{evidence.marker.status.value}"
        )
