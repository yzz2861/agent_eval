# Copyright (c) 2016 Rackspace, Inc.
#
# SPDX-License-Identifier: Apache-2.0
"""Utility functions for formatting plugins for Bandit."""
import io


def wrap_file_object(fileobj):
    """If the fileobj passed in cannot handle text, use TextIOWrapper
    to handle the conversion.
    """
    if isinstance(fileobj, io.TextIOBase):
        return fileobj
    return io.TextIOWrapper(fileobj)


def get_multi_target_details(manager):
    """Render the multi-target coverage block for text-style reports."""
    report = getattr(manager, "multi_target_report", None)
    if not report:
        return None

    bits = [
        "Multi-target syntax coverage (host %s):"
        % report.get("host_python_version", "unknown"),
        "\tTargets: %s" % ", ".join(report.get("targets", [])),
    ]
    for file_report in report.get("files", []):
        bits.append(
            "\t%s: %s"
            % (
                file_report.get("file", "<unknown>"),
                file_report.get("explanation", ""),
            )
        )
        for finding in file_report.get("findings", []):
            state = "suppressed" if finding.get("suppressed") else "visible"
            bits.append(
                "\t\t%s at line %s applies to %s (%s)"
                % (
                    finding.get("test_id", "?"),
                    finding.get("line_number", "?"),
                    ", ".join(finding.get("python_versions", [])),
                    state,
                )
            )

    summary = report.get("summary", {})
    bits.append(
        "\tChecked: %s, rejected: %s, uncovered: %s, inconclusive: %s"
        % (
            summary.get("checked_targets", 0),
            summary.get("rejected_targets", 0),
            summary.get("uncovered_targets", 0),
            summary.get("inconclusive_targets", 0),
        )
    )
    return "\n".join(bits)
