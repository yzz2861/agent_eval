"""Demo: optional caller-trusted status re-check during sanitization."
Run with: python -m html_sanitizer.demo_status_review
Two fragments look identical; only the caller-trusted one can be approved.
"""
from .status_review import StatusMarker, StatusReviewer, TrustedStatus
Q = chr(34)
LOOKALIKE_FRAGMENT = (
    "<h2>报销报告</h2>"
    "<p>费用合计 <strong>1280 元</strong>，附件齐全。</p>"
    f"<p id={Q}status-note{Q}>状态：已批准</p>"
)


def heading(title):
    print()
    print("=" * 72)
    print(title)
    print("=" * 72)


def show(label, reviewer, fragment):
    result = reviewer.review(fragment)
    print(label)
    print("  cleaned :", result.cleaned_html.strip())
    print("  claims  : total=%d untrusted=%d" % (
        result.claim_occurrences,
        result.untrusted_claim_occurrences,
    ))
    for evidence in result.evidence:
        print(
            "  evidence:",
            evidence.marker.marker_id,
            evidence.original_tag,
            "->",
            evidence.final_tag,
            evidence.disposition,
        )
        print("  link    :", reviewer.reader_line(evidence))
    print("  visible :", result.status_line())
    conclusion = result.archive_conclusion()
    print("  archive : approved=%s" % conclusion.approved)
    print("            ", conclusion.reason)


def main():
    trusted_marker = StatusMarker(
        marker_id="m1",
        anchor_id="status-note",
        status=TrustedStatus.APPROVED,
        claim="已批准",
    )

    heading("1. Two identical-looking ordinary fragments")
    show(
        "A) caller supplies a trusted marker:",
        StatusReviewer([trusted_marker]),
        LOOKALIKE_FRAGMENT,
    )
    show(
        "B) user only typed the words, no trusted marker:",
        StatusReviewer([]),
        LOOKALIKE_FRAGMENT,
    )

    heading("2. Tag migration keeps the trusted link")
    migration = StatusReviewer([
        StatusMarker("m2", TrustedStatus.APPROVED, "note", "已批准")
    ])
    show("b -> strong:", migration, f"<b id={Q}note{Q}>已批准</b>")

    heading("3. Duplicate wording is counted, never auto-trusted")
    duplicate = ("<p>已批准</p><p>已批准</p>"
                 f"<p id={Q}status-note{Q}>状态：已批准</p>")
    show("duplicates + one trusted anchor:",
         StatusReviewer([trusted_marker]), duplicate)
    show("duplicates, no trusted marker:",
         StatusReviewer([]), "<p>已批准</p><p>已批准</p>")

    heading("4. Cleaning removes the marker: no approval possible")
    removed = StatusReviewer([trusted_marker])
    show(
        "empty anchor is dropped during cleaning:",
        removed,
        f"<b id={Q}status-note{Q}></b><p>正文已批准</p>",
    )


if __name__ == "__main__":
    main()
