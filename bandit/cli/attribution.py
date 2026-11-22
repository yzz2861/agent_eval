#
# SPDX-License-Identifier: Apache-2.0
"""Attribute an existing Bandit JSON report to release owners.

This command is intentionally separate from ``bandit`` itself.  It consumes a
finished report and a release manifest, which keeps scans and ownership policy
independently reproducible.
"""
import argparse
import json
import sys

from bandit.core import attribution


def _build_parser():
    parser = argparse.ArgumentParser(
        prog="bandit-attribution",
        description=(
            "Attribute Bandit findings to release artifacts and source "
            "component owners using a release manifest."
        ),
    )
    parser.add_argument(
        "-m",
        "--manifest",
        required=True,
        help="release manifest JSON file",
    )
    parser.add_argument(
        "-r",
        "--report",
        default="-",
        help="Bandit JSON report (default: stdin)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="-",
        help="output file (default: stdout)",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=("json", "text"),
        default="json",
        help="output format (default: json)",
    )
    parser.add_argument(
        "--view",
        choices=("both", "current", "legacy"),
        default="both",
        help=(
            "report current ownership, legacy ownership, or both "
            "(default: both)"
        ),
    )
    parser.add_argument(
        "--fail-on-unattributed",
        action="store_true",
        help="exit 1 when any finding has no current owner",
    )
    return parser


def _read_report(path):
    if path == "-":
        try:
            return json.load(sys.stdin)
        except ValueError as exc:
            raise attribution.ReportError(
                "invalid Bandit report JSON on stdin: %s" % exc
            )
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except OSError as exc:
        raise attribution.ReportError("cannot read Bandit report: %s" % exc)
    except ValueError as exc:
        raise attribution.ReportError(
            "invalid Bandit report JSON: %s" % exc
        )


def _read_manifest(path):
    return attribution.load_manifest(path)


def _render_text(result):
    summary = result.get("summary", {})
    lines = [
        "Attribution: %d findings, %d attributed, %d legacy-only, "
        "%d need investigation"
        % (
            summary.get("findings", 0),
            summary.get("attributed", 0),
            summary.get("legacy_only", 0),
            summary.get("needs_investigation", 0),
        ),
        (
            "Risk points: %d" % summary["risk_points"]
            if "risk_points" in summary
            else "Legacy risk points: %d"
            % summary.get("legacy_risk_points", 0)
        ),
    ]
    if summary.get("double_count_detected"):
        lines.append(
            "Double counting avoided: %(double_count_detected)d finding(s), "
            "%(double_count_avoided_points)d point(s)"
            % summary
        )

    risk_by_owner = result.get("risk_by_owner") or {}
    if risk_by_owner:
        lines.append("")
        lines.append("Current risk by owner:")
        for owner, bucket in sorted(risk_by_owner.items()):
            lines.append(
                "  %s: %d finding(s), %d point(s)"
                % (owner, bucket["finding_count"], bucket["risk_points"])
            )

    legacy_by_owner = result.get("legacy_risk_by_owner") or {}
    if legacy_by_owner:
        lines.append("")
        lines.append("Legacy risk by owner (report only):")
        for owner, bucket in sorted(legacy_by_owner.items()):
            lines.append(
                "  %s: %d finding(s), %d point(s)"
                % (owner, bucket["finding_count"], bucket["risk_points"])
            )

    events = (result.get("double_count") or {}).get("events") or []
    if events:
        lines.append("")
        lines.append("Double-count reasons:")
        for event in events:
            lines.append(
                "  %s: %s" % (event["component_id"], event["detail"])
            )

    investigation = result.get("investigation_queue") or []
    if investigation:
        lines.append("")
        lines.append("Needs investigation (not attributed):")
        for lead in investigation:
            lines.append(
                "  %s -> %s (%.3f, %s)"
                % (
                    lead.get("filename", "<unknown>"),
                    lead.get("candidate_component_id", "<none>"),
                    lead.get("score", 0.0),
                    lead["kind"],
                )
            )
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        manifest = _read_manifest(args.manifest)
        report = _read_report(args.report)
        result = attribution.attribute_report(
            report, manifest, view=args.view
        )
    except (
        attribution.ManifestError,
        attribution.ReportError,
        OSError,
    ) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2

    if args.format == "text":
        rendered = _render_text(result)
    else:
        rendered = attribution.dumps(result)

    if args.output == "-":
        sys.stdout.write(rendered)
        if not rendered.endswith("\n"):
            sys.stdout.write("\n")
    else:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(rendered)
            if not rendered.endswith("\n"):
                handle.write("\n")

    if args.fail_on_unattributed:
        summary = result.get("summary", {})
        if summary.get("unattributed", 0) or summary.get(
            "needs_investigation", 0
        ):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
