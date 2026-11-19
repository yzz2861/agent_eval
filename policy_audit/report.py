"""Human-readable rendering of audit and comparison results."""

from __future__ import annotations

from .analyze import Context


def format_context(context: Context) -> str:
    tags = ", ".join("%s=%r" % (k, v) for k, v in context.tags)
    return "environment=%r, tags={%s}" % (context.environment, tags)


def render_report(policy, verdicts, issues, domain) -> str:
    lines = []
    lines.append(
        "Policy audit: %d file(s), %d effective rule(s), %d domain point(s), "
        "%d issue(s)"
        % (len(policy.files), len(verdicts), len(domain), len(issues))
    )
    for path in policy.files:
        lines.append("  input: %s" % path)

    if issues:
        lines.append("")
        lines.append("ISSUES")
        for issue in issues:
            where = " (%s)" % issue.provenance if issue.provenance else ""
            lines.append("  [%s]%s %s" % (issue.kind, where, issue.message))

    if verdicts:
        lines.append("")
        lines.append("RULES")
        for verdict in verdicts:
            entry = verdict.entry
            data = entry.data
            lines.append(
                "  %s (%s) action=%s priority=%r"
                % (verdict.rule_id, entry.provenance, data.get("action"),
                   data.get("priority"))
            )
            lines.append(
                "    verdict: %s (wins %d of %d matched point(s))"
                % (verdict.verdict, verdict.winning_points,
                   verdict.matched_points)
            )
            if verdict.shadowed_by:
                lines.append(
                    "    shadowed by: %s" % ", ".join(verdict.shadowed_by)
                )
            if verdict.winning_example is not None:
                lines.append(
                    "    effective example: %s"
                    % format_context(verdict.winning_example)
                )
            if verdict.shadowed_example is not None:
                lines.append(
                    "    shadowed example: %s"
                    % format_context(verdict.shadowed_example)
                )
    return "\n".join(lines)


def render_comparison(changes, old_paths, new_paths) -> str:
    lines = []
    lines.append("Policy comparison")
    lines.append("  old: %s" % ", ".join(old_paths))
    lines.append("  new: %s" % ", ".join(new_paths))
    if not changes:
        lines.append("")
        lines.append("No deployment scope changes hands.")
        return "\n".join(lines)
    lines.append("")
    lines.append("SCOPE CHANGES (old winner -> new winner)")
    for change in changes:
        lines.append(
            "  environment=%r: %s -> %s (%d domain point(s))"
            % (
                change.environment,
                change.old_winner or "<no match>",
                change.new_winner or "<no match>",
                change.points,
            )
        )
        lines.append("    example: %s" % format_context(change.example))
    return "\n".join(lines)
