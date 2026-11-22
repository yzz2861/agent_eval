"""Render acceptance results as machine-readable JSON and a short text report."""

import json

from .validator import MIN_INDEPENDENT_OBSERVATIONS


def build_report(verdicts):
    released = [v for v in verdicts if v.releasable]
    blocked = [v for v in verdicts if not v.releasable]
    return {
        "summary": {
            "total_conclusions": len(verdicts),
            "releasable": len(released),
            "blocked": len(blocked),
            "required_independent_observations": MIN_INDEPENDENT_OBSERVATIONS,
        },
        "verdicts": [verdict.as_dict() for verdict in verdicts],
    }


def write_json_report(verdicts, path):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(build_report(verdicts), handle, ensure_ascii=False, indent=2)


def render_text_report(verdicts):
    lines = []
    released = [v for v in verdicts if v.releasable]
    blocked = [v for v in verdicts if not v.releasable]
    lines.append("Offline release-gate report")
    lines.append("=" * 27)
    lines.append("conclusions checked: %d | releasable: %d | blocked: %d"
                 % (len(verdicts), len(released), len(blocked)))
    lines.append("")
    for verdict in verdicts:
        status = "RELEASE" if verdict.releasable else "HOLD"
        lines.append("[%s] %s (%s, scope=%s)"
                     % (status, verdict.name, verdict.conclusion_id, verdict.scope))
        lines.append("  cited references: %d | distinct sources: %d | distinct raw material: %d"
                     % (len(verdict.evidence_refs),
                        len(verdict.independent_sources),
                        len(verdict.independent_material)))
        reused = {m: c for m, c in verdict.material_reference_counts.items() if c > 1}
        if reused:
            lines.append("  reused material (references preserved, counted once): %s"
                         % ", ".join("%s x%d" % (m, c) for m, c in sorted(reused.items())))
        if verdict.reasons:
            for reason in verdict.reasons:
                lines.append("  - cannot release: " + reason)
        else:
            lines.append("  - usable authorization and >= %d independent observations confirmed"
                         % MIN_INDEPENDENT_OBSERVATIONS)
        lines.append("")
    return "\n".join(lines)
