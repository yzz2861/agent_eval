"""Serialization of review results into machine JSON and human Markdown.

Both formats embed the witness material needed to verify every number by
hand: the exact domains in the minimum set, the rule combinations they cover,
and the key-to-domain mapping behind each claim.
"""

from __future__ import annotations

from typing import Any

from securesystemslib.policy_review.review import PENDING_DOMAIN, ReviewReport


def report_to_dict(report: ReviewReport) -> dict[str, Any]:
    """Serialize a report to JSON-compatible data."""
    data: dict[str, Any] = {
        "policy_id": report.policy_id,
        "roster_id": report.roster_id,
        "frozen_at": report.frozen_at,
        "combination_count": report.combination_count,
        "distinct_key_count": report.distinct_key_count,
        "domain_count": report.domain_count,
        "warnings": list(report.warnings),
        "findings": list(report.findings),
        "unassigned_keyids": list(report.unassigned_keyids),
        "confirmed_view": {
            "minimum_satisfying_domains": _metric_dict(report.confirmed_satisfying),
            "minimum_blocking_domains": _metric_dict(report.confirmed_blocking),
        },
    }
    if report.candidate_range is not None:
        rng = report.candidate_range
        data["candidate_range"] = {
            "unresolved_keyids": list(rng.unresolved_keyids),
            "exhaustive": rng.exhaustive,
            "enumerated_assignments": rng.enumerated,
            "total_assignments": rng.total_assignments,
            "minimum_satisfying_domains": [rng.satisfying_min, rng.satisfying_max],
            "minimum_blocking_domains": [rng.blocking_min, rng.blocking_max],
            "most_concentrated_assignment": _resolution_dict(rng.best_resolution),
            "most_dispersed_assignment": _resolution_dict(rng.worst_resolution),
        }
    return data


def _metric_dict(metric: Any) -> dict[str, Any] | None:
    if metric is None:
        return None
    result: dict[str, Any] = {
        "value": metric.value,
        "exhaustive": metric.exhaustive,
        "note": metric.note,
    }
    if metric.witness is not None:
        witness = metric.witness
        result["witness"] = {
            "domains": sorted(witness.domains),
            "key_to_domains": {k: list(v) for k,
                v in sorted(witness.key_to_domains.items())},
            "rules": {
                rule_id: {keyid: list(domains) for keyid,
                    domains in sorted(per_key.items())}
                for rule_id, per_key in sorted(witness.covers.items())
            },
        }
    return result


def _resolution_dict(result: Any) -> dict[str, Any]:
    return {
        "assignment": dict(result.assignment),
        "minimum_satisfying_domains": result.satisfying,
        "minimum_blocking_domains": result.blocking,
    }


def report_to_markdown(report: ReviewReport) -> str:
    """Render a human-readable, hand-checkable Markdown report."""
    lines: list[str] = []
    lines.append(f"# Offline signing-policy review: {report.policy_id}")
    lines.append("")
    frozen = f" (frozen at {report.frozen_at})" if report.frozen_at else ""
    lines.append(f"- Roster: {report.roster_id}{frozen}")
    lines.append(f"- Distinct legal combinations: {report.combination_count}")
    lines.append(f"- Distinct key ids: {report.distinct_key_count}")
    lines.append(f"- Control domains in roster: {report.domain_count}")
    lines.append("")

    lines.append("## Metrics on confirmed ownership")
    lines.append("")
    _render_metric(lines, "Minimum domains that can satisfy a legal release",
        report.confirmed_satisfying)
    _render_metric(lines, "Minimum domains whose absence blocks every release",
        report.confirmed_blocking)
    lines.append("")

    if report.candidate_range is not None:
        rng = report.candidate_range
        lines.append("## Pending-confirmation range (candidate owners)")
        lines.append("")
        scope = "exhaustive" if rng.exhaustive else "NON-exhaustive (cap reached)"
        unresolved = ", ".join(rng.unresolved_keyids)
        lines.append(f"- Unresolved key ids: {unresolved}")
        lines.append(
            f"- Assignments evaluated: {rng.enumerated} of "
            f"{rng.total_assignments} ({scope})"
        )
        lines.append(
            f"- Minimum satisfying domains: "
            f"{rng.satisfying_min} to {rng.satisfying_max}"
        )
        lines.append(
            f"- Minimum blocking domains: "
            f"{rng.blocking_min} to {rng.blocking_max}"
        )
        lines.append("")
        lines.append("### Most concentrated candidate assignment (to confirm)")
        lines.append("")
        _render_resolution(lines, rng.best_resolution)
        lines.append("### Most dispersed candidate assignment (to confirm)")
        lines.append("")
        _render_resolution(lines, rng.worst_resolution)
        lines.append("")

    if report.warnings:
        lines.append("## Warnings")
        lines.append("")
        lines.extend(f"- {warning}" for warning in report.warnings)
        lines.append("")
    lines.append("## Findings")
    lines.append("")
    if report.findings:
        lines.extend(f"- {finding}" for finding in report.findings)
    else:
        lines.append("- No automatic concentration or availability findings.")
    lines.append("")
    return chr(10).join(lines)


def _render_metric(lines: list[str], title: str, metric: Any) -> None:
    lines.append(f"### {title}")
    lines.append("")
    if metric is None:
        lines.append("- Not evaluated.")
        lines.append("")
        return
    if metric.value is None:
        lines.append(f"- Result: not attainable ({metric.note})")
        lines.append("")
        return
    exhaustive = "exhaustive minimum" if metric.exhaustive else "NON-exhaustive bound"
    lines.append(f"- Value: {metric.value} domain(s) ({exhaustive})")
    if metric.witness is None:
        lines.append("")
        return
    witness = metric.witness
    witness_domains = ", ".join(sorted(witness.domains))
    lines.append(f"- Witness domains: {witness_domains}")
    if PENDING_DOMAIN in witness.domains:
        lines.append(
            "  - Witness includes the unassigned-key placeholder; see warnings."
        )
    lines.append("")
    lines.append("| Rule | Key id | Supplied by witness domain(s) |")
    lines.append("| --- | --- | --- |")
    for rule_id, per_key in sorted(witness.covers.items()):
        for keyid, domains in sorted(per_key.items()):
            joined = ", ".join(domains) if domains else "(none)"
            lines.append(f"| {rule_id} | {keyid} | {joined} |")
    lines.append("")


def _render_resolution(lines: list[str], result: Any) -> None:
    lines.append("| Unresolved key id | Assumed owner domain |")
    lines.append("| --- | --- |")
    for keyid, domain in sorted(result.assignment.items()):
        lines.append(f"| {keyid} | {domain} |")
    lines.append("")
    lines.append(
        f"- Minimum satisfying domains under this assignment: "
        f"{result.satisfying}"
    )
    lines.append(f"- Minimum blocking domains under this assignment: {result.blocking}")
    lines.append("")
