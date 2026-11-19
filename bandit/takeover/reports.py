# SPDX-License-Identifier: Apache-2.0
"""Report renderers for the takeover layer.

Two independent renderers are provided:

* :func:`render_legacy_report` reproduces the plain Bandit JSON report shape
  (``results`` + ``errors`` + ``metrics``) so downstream tools built for the
  old format keep working; it can be generated standalone without rendering
  the new approval detail.
* :func:`render_approval_detail` renders the human-oriented approval document
  showing, per owner, which findings were accepted as legacy debt, which must
  be fixed now and which directories still carry unknown risk.
"""
from __future__ import annotations

import json
from collections import OrderedDict
from typing import Any, Dict, List

from bandit.takeover.engine import AdjudicationReport, Disposition

_DISPOSITION_TITLES = {
    Disposition.LEGACY_DEBT: "Accepted legacy debt (non-blocking)",
    Disposition.ESCALATED: "Escalated legacy finding - fix now",
    Disposition.CROSS_BOUNDARY_UNACCEPTED: (
        "Cross-boundary move without handoff record - fix now"
    ),
    Disposition.NEW_FINDING: "New finding - fix now",
}


def render_legacy_report(current_scan: Dict[str, Any]) -> str:
    """Render a report in the legacy Bandit JSON format.

    Only fields produced by ``bandit -f json`` are emitted.  The adjudication
    layer is not required to produce this output, so the old report pipeline
    can continue to run independently.
    """
    legacy_shape = {
        "errors": list(current_scan.get("errors", [])),
        "results": list(current_scan.get("results", [])),
        "metrics": current_scan.get("metrics", {}),
        "generated_at": current_scan.get("generated_at", ""),
    }
    return json.dumps(legacy_shape, indent=2, sort_keys=False)


def _finding_line(adjudication) -> List[str]:
    finding = adjudication.finding
    location = finding.filename
    if finding.line_number is not None:
        location += ":" + str(finding.line_number)
    lines = [
        "  - ["
        + finding.severity
        + "/"
        + finding.confidence
        + "] "
        + finding.test_id
        + " "
        + finding.test_name
        + " @ "
        + location
    ]
    lines.append("    fingerprint: " + finding.fingerprint)
    lines.append("    issue: " + " ".join(finding.issue_text.split()))
    for reason in adjudication.reasons:
        lines.append("    reason: " + reason)
    if adjudication.handoff is not None:
        lines.append(
            "    handoff: "
            + adjudication.handoff.record_id
            + " ("
            + adjudication.handoff.from_team
            + " -> "
            + adjudication.handoff.to_team
            + ", "
            + adjudication.handoff.date
            + ")"
        )
    return lines


def render_approval_detail(report: AdjudicationReport) -> str:
    """Render the approval-detail document for a gate review."""
    lines: List[str] = []
    lines.append("BANDIT TAKEOVER ADJUDICATION - APPROVAL DETAIL")
    if report.generated_at:
        lines.append("Generated at: " + report.generated_at)
    gate = "FAIL" if report.gate_failed else "PASS"
    lines.append("Gate decision: " + gate)
    lines.append("")
    lines.append("Summary:")
    for key, value in sorted(report.summary().items()):
        lines.append("  - " + key + ": " + str(value))
    lines.append("")

    grouped: "OrderedDict[str, List[Any]]" = OrderedDict()
    for adjudication in sorted(
        report.adjudications,
        key=lambda item: (
            item.owner, item.finding.filename
        ),
    ):
        grouped.setdefault(adjudication.owner, []).append(adjudication)

    lines.append("Findings by responsible owner:")
    if not grouped:
        lines.append("  (no findings in this scan)")
    for owner, items in grouped.items():
        lines.append("")
        lines.append("Owner: " + owner)
        blocking = [item for item in items if item.blocks]
        carried = [item for item in items if not item.blocks]
        lines.append(
            "  accepted from backlog: "
            + str(len(carried))
            + ", must fix now: "
            + str(len(blocking))
        )
        for disposition in (
            Disposition.LEGACY_DEBT,
            Disposition.ESCALATED,
            Disposition.CROSS_BOUNDARY_UNACCEPTED,
            Disposition.NEW_FINDING,
        ):
            bucket = [
                item
                for item in items
                if item.disposition == disposition
            ]
            if not bucket:
                continue
            lines.append("  " + _DISPOSITION_TITLES[disposition] + ":")
            for adjudication in bucket:
                lines.extend(_finding_line(adjudication))

    lines.append("")
    lines.append("Directories with unknown risk (rescanning required):")
    unknown = report.unknown_risk_directories()
    if not unknown:
        lines.append("  (all manifest directories fully scanned)")
    for coverage in unknown:
        lines.append(
            "  - "
            + coverage.directory
            + " ["
            + coverage.status.value
            + "]"
        )
        for reason in coverage.reasons:
            lines.append("      " + reason)

    if report.resolved_legacy:
        lines.append("")
        lines.append(
            "Legacy findings absent from this scan "
            "(verify before close):"
        )
        for item in report.resolved_legacy:
            lines.append(
                "  - "
                + str(item.get("test_id", ""))
                + " @ "
                + str(item.get("filename", ""))
                + " (owner: "
                + str(item.get("owner", ""))
                + ")"
            )
    lines.append("")
    return "\n".join(lines)


def render_approval_json(report: AdjudicationReport) -> str:
    """Render the full adjudication result as machine-readable JSON."""
    return json.dumps(report.to_dict(), indent=2, sort_keys=False)
