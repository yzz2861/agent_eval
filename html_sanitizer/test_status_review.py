from unittest import TestCase

from .sanitizer import Sanitizer
from .status_review import (
    ANCHOR_NOT_FOUND,
    MARKER_ATTRIBUTE,
    MARKER_REMOVED,
    RETAINED,
    STATUS_ATTRIBUTE,
    StatusMarker,
    StatusReviewer,
    TrustedStatus,
)

Q = chr(34)


def attr(name, value):
    return f"{name}={Q}{value}{Q}"


APPROVAL_MARKER = StatusMarker(
    marker_id="m1",
    anchor_id="status-note",
    status=TrustedStatus.APPROVED,
    claim="已批准",
)

SAME_FRAGMENT = (
    "<h2>报销报告</h2>"
    "<p>费用合计 <strong>1280 元</strong>，附件齐全。</p>"
    f"<p id={Q}status-note{Q} class={Q}badge{Q}>状态：已批准</p>"
)


class StatusReviewerTestCase(TestCase):
    def test_lookalike_fragments_have_identical_plain_sanitization(self):
        with_marker = StatusReviewer([APPROVAL_MARKER]).review(SAME_FRAGMENT)
        without_marker = StatusReviewer([]).review(SAME_FRAGMENT)
        baseline = Sanitizer().sanitize(SAME_FRAGMENT)
        stripped = with_marker.cleaned_html
        for attribute in (
            attr(MARKER_ATTRIBUTE, "m1"),
            attr(STATUS_ATTRIBUTE, "approved"),
        ):
            stripped = stripped.replace(" " + attribute, "")
        self.assertEqual(stripped, without_marker.cleaned_html)
        self.assertEqual(without_marker.cleaned_html, baseline)

    def test_trusted_marker_links_dom_explanation_to_reader_status(self):
        result = StatusReviewer([APPROVAL_MARKER]).review(SAME_FRAGMENT)
        evidence = result.evidence[0]
        self.assertEqual(evidence.disposition, RETAINED)
        self.assertEqual(evidence.original_tag, "p")
        self.assertEqual(evidence.final_tag, "p")
        self.assertEqual(result.reader_visible_statuses(), {"m1": "approved"})
        self.assertIn(attr(MARKER_ATTRIBUTE, "m1"), result.cleaned_html)
        self.assertIn(attr(STATUS_ATTRIBUTE, "approved"), result.cleaned_html)
        conclusion = result.archive_conclusion()
        self.assertTrue(conclusion.approved)
        self.assertEqual(conclusion.approved_marker_ids, frozenset({"m1"}))

    def test_lookalike_without_marker_never_approves(self):
        result = StatusReviewer([]).review(SAME_FRAGMENT)
        self.assertEqual(result.evidence, ())
        self.assertEqual(result.claim_occurrences, 1)
        self.assertEqual(result.untrusted_claim_occurrences, 1)
        self.assertEqual(result.reader_visible_statuses(), {})
        self.assertNotIn(MARKER_ATTRIBUTE, result.cleaned_html)
        self.assertFalse(result.archive_conclusion().approved)

    def test_tag_migration_b_to_strong_keeps_marker(self):
        reviewer = StatusReviewer([
            StatusMarker("m2", TrustedStatus.APPROVED, "note", "已批准")
        ])
        result = reviewer.review(f"<b id={Q}note{Q}>已批准</b>")
        evidence = result.evidence[0]
        self.assertEqual(evidence.original_tag, "b")
        self.assertEqual(evidence.final_tag, "strong")
        self.assertEqual(evidence.disposition, RETAINED)
        self.assertIn("<strong", result.cleaned_html)
        self.assertIn(attr(MARKER_ATTRIBUTE, "m2"), result.cleaned_html)
        self.assertTrue(result.archive_conclusion().approved)

    def test_tag_migration_bold_span_keeps_marker(self):
        reviewer = StatusReviewer([
            StatusMarker("m3", TrustedStatus.PENDING, "note", "待审")
        ])
        html = f"<span id={Q}note{Q} style={Q}font-weight: bold{Q}>待审</span>"
        result = reviewer.review(html)
        evidence = result.evidence[0]
        self.assertEqual(evidence.original_tag, "span")
        self.assertEqual(evidence.final_tag, "strong")
        self.assertEqual(evidence.disposition, RETAINED)
        self.assertEqual(result.reader_visible_statuses(), {"m3": "pending"})

    def test_duplicate_claims_are_counted_but_not_trusted(self):
        html = (
            "<p>已批准</p><p>已批准</p>"
            f"<p id={Q}status-note{Q}>状态：已批准</p>"
        )
        result = StatusReviewer([APPROVAL_MARKER]).review(html)
        self.assertEqual(result.claim_occurrences, 3)
        self.assertEqual(result.untrusted_claim_occurrences, 2)
        self.assertEqual(result.reader_visible_statuses(), {"m1": "approved"})
        self.assertTrue(result.archive_conclusion().approved)

    def test_duplicate_claims_without_marker_never_approve(self):
        html = "<p>已批准</p><p>已批准</p><p>已批准</p>"
        result = StatusReviewer([]).review(html)
        self.assertEqual(result.claim_occurrences, 3)
        self.assertEqual(result.untrusted_claim_occurrences, 3)
        self.assertFalse(result.archive_conclusion().approved)

    def test_cleaning_removing_marker_blocks_approval(self):
        html = f"<b id={Q}status-note{Q}></b><p>正文已批准</p>"
        result = StatusReviewer([APPROVAL_MARKER]).review(html)
        evidence = result.evidence[0]
        self.assertEqual(evidence.disposition, MARKER_REMOVED)
        self.assertIsNone(evidence.final_tag)
        self.assertNotIn(MARKER_ATTRIBUTE, result.cleaned_html)
        self.assertEqual(result.reader_visible_statuses(), {})
        conclusion = result.archive_conclusion()
        self.assertFalse(conclusion.approved)
        self.assertEqual(conclusion.missing_marker_ids, frozenset({"m1"}))
        self.assertEqual(result.untrusted_claim_occurrences, 1)

    def test_anchor_not_found_is_reported(self):
        result = StatusReviewer([APPROVAL_MARKER]).review("<p>已批准</p>")
        evidence = result.evidence[0]
        self.assertEqual(evidence.disposition, ANCHOR_NOT_FOUND)
        self.assertIsNone(evidence.original_tag)
        self.assertFalse(result.archive_conclusion().approved)

    def test_distinctly_marked_adjacent_elements_are_not_merged(self):
        markers = [
            StatusMarker("a", TrustedStatus.APPROVED, "n1", "已批准"),
            StatusMarker("b", TrustedStatus.REJECTED, "n2", "已驳回"),
        ]
        html = (
            f"<strong id={Q}n1{Q}>已批准</strong>"
            f"<strong id={Q}n2{Q}>已驳回</strong>"
        )
        result = StatusReviewer(markers).review(html)
        self.assertEqual(len(result.retained_evidence()), 2)
        self.assertIn(attr(MARKER_ATTRIBUTE, "a"), result.cleaned_html)
        self.assertIn(attr(MARKER_ATTRIBUTE, "b"), result.cleaned_html)

    def test_trust_cannot_be_parsed_from_document_text(self):
        with self.assertRaises(TypeError):
            StatusMarker("x", "approved", "n", "已批准")

    def test_reader_line_and_status_line(self):
        reviewer = StatusReviewer([APPROVAL_MARKER])
        result = reviewer.review(SAME_FRAGMENT)
        line = reviewer.reader_line(result.evidence[0])
        self.assertIn(MARKER_ATTRIBUTE, line)
        self.assertIn("approved", line)
        self.assertEqual(result.status_line(), "m1: approved")
        empty = StatusReviewer([]).review("<p>已批准</p>")
        self.assertEqual(empty.status_line(), "无可信状态依据")

    def test_duplicate_anchor_claim_rejected(self):
        markers = [
            StatusMarker("a", TrustedStatus.APPROVED, "same", "已批准"),
            StatusMarker("b", TrustedStatus.REJECTED, "same", "已驳回"),
        ]
        with self.assertRaises(ValueError):
            StatusReviewer(markers)
