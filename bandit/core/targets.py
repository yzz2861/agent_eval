# SPDX-License-Identifier: Apache-2.0
"""Scan one source tree against several Python grammar targets.

Bandit normally parses source with the AST implementation of the interpreter
that is running it.  That is convenient, but it also means a file written for
an older or newer grammar can be skipped without the summary making the gap
obvious.  ``ast.parse`` accepts ``feature_version`` and can therefore emulate
older grammars with the host interpreter.  This module drives that facility
for every requested target and records an explicit state per file and target.

No additional Python installation is used.  A target the host cannot emulate
is reported as ``UNCOVERED``; an empty finding list for such a target is not a
clean result.
"""
import ast
import io
import logging
import re
import sys
import tokenize

from bandit.core import extension_loader
from bandit.core import meta_ast as b_meta_ast
from bandit.core import metrics as b_metrics
from bandit.core import node_visitor as b_node_visitor

LOG = logging.getLogger(__name__)

#: A target was parsed and every applicable plugin completed.
CHECKED = "CHECKED"
#: The source is not valid syntax for the requested target.
REJECTED = "REJECTED"
#: The host interpreter does not implement this grammar target.
UNCOVERED = "UNCOVERED"
#: The source was readable, but at least one rule could not complete.
INCONCLUSIVE = "INCONCLUSIVE"

#: Compatibility aliases for callers that use a different vocabulary.
NOT_COVERED = UNCOVERED
UNKNOWN = INCONCLUSIVE

CONCLUSIVE_STATUSES = (CHECKED,)

#: ``feature_version`` emulation is dependable for these CPython grammars.
MIN_SUPPORTED_FEATURE_VERSION = (3, 4)

NOSEC_COMMENT = re.compile(r"#\s*nosec:?\s*(?P<tests>[^#]+)?#?")
NOSEC_COMMENT_TESTS = re.compile(r"(?:(B\d+|[a-z\d_]+),?)+", re.IGNORECASE)

STATUS_LEGEND = {
    CHECKED: (
        "the file parsed for this grammar and every applicable rule "
        "completed; finding_count is authoritative"
    ),
    REJECTED: (
        "the file is not valid syntax for this grammar; no rule result "
        "exists for this target"
    ),
    UNCOVERED: (
        "the host interpreter cannot parse this grammar; the target was "
        "not scanned and an empty result is not a clean bill of health"
    ),
    INCONCLUSIVE: (
        "the file parsed, but at least one rule could not complete; the "
        "reported findings are partial rather than a full conclusion"
    ),
}


class TargetVersionError(ValueError):
    """Raised when a requested grammar target cannot be interpreted."""


def parse_target_versions(values):
    """Parse target version specifications.

    Accepts ``"3.10,3.12"``, ``["3.10", (3, 12)]`` or a single version tuple
    such as ``(3, 10)``.  Order is retained and duplicates are removed.

    :param values: ``None``, a string, a version tuple, or an iterable
    :return: list of ``(major, minor)`` tuples
    :raises TargetVersionError: if a spec is not a ``major.minor`` pair
    """
    if values is None:
        return []

    if isinstance(values, str):
        specs = [part.strip() for part in values.split(",") if part.strip()]
    elif (
        isinstance(values, (tuple, list))
        and len(values) == 2
        and all(isinstance(part, int) for part in values)
    ):
        # A bare (3, 10) is one target, not two malformed targets.
        specs = [values]
    else:
        specs = []
        for value in values:
            if isinstance(value, str) and "," in value:
                specs.extend(
                    part.strip()
                    for part in value.split(",")
                    if part.strip()
                )
            else:
                specs.append(value)

    targets = []
    for spec in specs:
        if isinstance(spec, (tuple, list)):
            parts = list(spec)
        else:
            parts = str(spec).strip().split(".")
        if len(parts) != 2:
            raise TargetVersionError(
                f"Invalid Python target version {spec!r}; "
                "expected 'major.minor', for example 3.10"
            )
        try:
            version = (int(parts[0]), int(parts[1]))
        except (TypeError, ValueError) as exc:
            raise TargetVersionError(
                f"Invalid Python target version {spec!r}; "
                "major and minor must be integers"
            ) from exc
        if version[0] < 0 or version[1] < 0:
            raise TargetVersionError(
                f"Invalid Python target version {spec!r}; "
                "version parts must be non-negative"
            )
        if version not in targets:
            targets.append(version)
    return targets


def format_target(version):
    """Render a ``(major, minor)`` tuple as a report label."""
    if isinstance(version, str):
        version = parse_target_versions(version)[0]
    return f"{version[0]}.{version[1]}"


def host_supports_target(version):
    """Return whether the running interpreter can emulate this grammar.

    Newer ``feature_version`` values are silently clamped by some CPython
    releases, so the comparison is deliberately explicit.  Python 2 and
    grammars older than the host's supported emulation range cannot be
    concluded either, even though their version tuple is numerically lower.
    """
    version = tuple(version[:2])
    host = sys.version_info[:2]
    return (
        version >= MIN_SUPPORTED_FEATURE_VERSION
        and version <= host
    )


def _find_test_id_from_nosec_string(extman, match):
    if extman.check_id(match):
        return match
    test_id = extman.get_test_id(match)
    if not test_id:
        LOG.warning(
            "Test in comment: %s is not a test name or id, ignoring", match
        )
    return test_id


def _parse_nosec_comment(comment):
    found = NOSEC_COMMENT.search(comment)
    if not found:
        return None
    nosec_tests = found.groupdict().get("tests", set())
    test_ids = set()
    if nosec_tests:
        extman = extension_loader.MANAGER
        for test in NOSEC_COMMENT_TESTS.finditer(nosec_tests):
            test_id = _find_test_id_from_nosec_string(
                extman, test.group(1)
            )
            if test_id:
                test_ids.add(test_id)
    return test_ids


def _collect_nosec(data, ignore_nosec):
    nosec_lines = {}
    if ignore_nosec:
        return nosec_lines
    try:
        readline = io.BytesIO(data).readline
        for toktype, tokval, (lineno, _), _, _ in tokenize.tokenize(
            readline
        ):
            if toktype == tokenize.COMMENT:
                nosec_lines[lineno] = _parse_nosec_comment(tokval)
    except (tokenize.TokenError, SyntaxError, UnicodeDecodeError):
        # Mirror BanditManager: tokenizer trouble means there are no usable
        # nosec annotations, not that the file itself is unreadable.
        pass
    return nosec_lines


def _syntax_reason(exc):
    reason = exc.msg or "syntax error while parsing AST from file"
    if exc.lineno is not None:
        reason = f"{reason} (line {exc.lineno})"
    return reason


def _unsupported_feature(tree, version):
    """Detect syntax the host parser accepted but the target lacks.

    ``ast.parse(feature_version=...)`` enforces several grammar changes, but
    not every one (notably f-strings and variable annotations on some
    hosts).  This guard keeps an old target from being reported as CHECKED
    for syntax it could not actually compile.
    """
    for node in ast.walk(tree):
        if version < (3, 6):
            if isinstance(node, ast.JoinedStr):
                return (
                    "f-strings are only supported in Python 3.6 and "
                    "greater"
                )
            if isinstance(node, ast.AnnAssign):
                return (
                    "variable annotations are only supported in Python "
                    "3.6 and greater"
                )
            if isinstance(node, ast.comprehension) and node.is_async:
                return (
                    "asynchronous comprehensions are only supported in "
                    "Python 3.6 and greater"
                )
        if version < (3, 5):
            if isinstance(
                node, (ast.AsyncFunctionDef, ast.AsyncFor, ast.AsyncWith)
            ):
                return (
                    "async syntax is only supported in Python 3.5 and "
                    "greater"
                )
            if isinstance(node, ast.Await):
                return (
                    "await is only supported in Python 3.5 and greater"
                )
            if isinstance(node, ast.BinOp) and isinstance(
                node.op, ast.MatMult
            ):
                return (
                    "the matrix multiplication operator is only supported "
                    "in Python 3.5 and greater"
                )
            if isinstance(node, ast.Dict) and any(
                key is None for key in node.keys
            ):
                return (
                    "dictionary unpacking is only supported in Python "
                    "3.5 and greater"
                )
        if version < (3, 8):
            if isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef)
            ) and getattr(node.args, "posonlyargs", None):
                return (
                    "positional-only parameters are only supported in "
                    "Python 3.8 and greater"
                )
    return None


def _scan_one(data, fname, version, testset, metrics, ignore_nosec):
    """Parse and scan ``data`` against one grammar target.

    :return: ``(status, reason, issues)``
    """
    if not host_supports_target(version):
        return (
            UNCOVERED,
            "target grammar is newer or older than the host interpreter "
            f"({format_target(sys.version_info[:2])}) can emulate; no "
            "extra interpreter is installed or attempted",
            [],
        )

    # Some feature_version values are silently accepted by the host even
    # though the target grammar is older.  Validate the resulting tree as
    # well so an old target is not called CHECKED for newer syntax.
    try:
        parsed = ast.parse(data, feature_version=version)
    except SyntaxError as exc:
        return REJECTED, _syntax_reason(exc), []
    except ValueError as exc:
        return (
            UNCOVERED,
            f"host parser rejects feature_version {format_target(version)}: "
            f"{exc}",
            [],
        )
    unsupported = _unsupported_feature(parsed, version)
    if unsupported is not None:
        return REJECTED, unsupported, []

    # Suppression is annotated after the scan.  Running the visitor without
    # nosec keeps suppressed rule hits visible with their original IDs.
    visitor = b_node_visitor.BanditNodeVisitor(
        fname,
        io.BytesIO(data),
        b_meta_ast.BanditMetaAst(),
        testset,
        False,
        {},
        metrics,
    )
    try:
        visitor.process(data, feature_version=version)
    except SyntaxError as exc:
        return REJECTED, _syntax_reason(exc), []
    except ValueError as exc:
        return (
            UNCOVERED,
            f"host parser rejects feature_version {format_target(version)}: "
            f"{exc}",
            [],
        )
    except Exception as exc:  # noqa: BLE001 - report, never hide a gap
        return (
            INCONCLUSIVE,
            f"scan could not complete: {type(exc).__name__}: {exc}",
            list(getattr(visitor.tester, "results", [])),
        )

    issues = list(visitor.tester.results)
    errors = list(getattr(visitor.tester, "errors", []))
    if errors:
        names = ", ".join(error["test"] for error in errors[:3])
        if len(errors) > 3:
            names += ", ..."
        return (
            INCONCLUSIVE,
            f"{len(errors)} rule(s) could not complete ({names}); "
            "findings are partial",
            issues,
        )
    return CHECKED, None, issues


def _nosec_for_issue(issue, nosec_lines):
    """Return suppression information for one finding.

    :return: ``(suppressed, test_ids, blanket, mode)``
    """
    if not nosec_lines:
        return False, set(), False, "none"

    found = False
    test_ids = set()
    blanket = False
    for lineno in list(issue.linerange) or [issue.lineno]:
        entry = nosec_lines.get(lineno)
        if entry is None:
            continue
        found = True
        if not entry:
            blanket = True
        else:
            test_ids.update(entry)

    if not found:
        return False, set(), False, "none"
    if blanket:
        return True, set(), True, "blanket"
    if issue.test_id in test_ids:
        return True, {issue.test_id}, False, "explicit"
    return False, set(), False, "none"


def _finding_key(issue):
    """Merge key for a rule hit at one concrete source location."""
    return (
        issue.fname,
        issue.test_id,
        issue.lineno,
        issue.col_offset,
    )


def _target_report(
    version, status, reason, issues, suppressed_count, unsuppressed_count
):
    label = format_target(version)
    conclusive = status in CONCLUSIVE_STATUSES
    report = {
        "python_version": label,
        "target": label,
        "status": status,
        "state": status.lower(),
        "covered": status != UNCOVERED,
        "conclusive": conclusive,
        "reason": reason,
        "finding_count": len(issues) if conclusive else None,
        "suppressed_count": suppressed_count if conclusive else None,
        "unsuppressed_count": unsuppressed_count if conclusive else None,
    }
    if status == INCONCLUSIVE:
        report["partial_finding_count"] = len(issues)
        report["partial_suppressed_count"] = suppressed_count
        report["status_reason"] = reason
    if status in (REJECTED, UNCOVERED):
        report["status_reason"] = reason
    return report


def _explain_targets(target_reports):
    parts = []
    for target in target_reports:
        text = (
            f"{target['python_version']}: "
            f"{target['status'].lower()}"
        )
        if target.get("reason"):
            text += f" ({target['reason']})"
        elif target["status"] == CHECKED:
            text += (
                f" ({target['finding_count']} finding(s), "
                f"{target['suppressed_count']} suppressed)"
            )
        parts.append(text)

    explanation = "; ".join(parts)
    statuses = {target["status"] for target in target_reports}
    if CHECKED in statuses and statuses - {CHECKED}:
        explanation += (
            ". Rules only appear for targets that were actually checked; "
            "rejected or uncovered targets cannot contribute a conclusion."
        )
    if CHECKED not in statuses:
        explanation += (
            ". No target produced a complete scan, so absent findings are "
            "not evidence of safety."
        )
    return explanation


def _file_report(fname, target_reports, findings):
    by_status = {
        CHECKED: [],
        REJECTED: [],
        UNCOVERED: [],
        INCONCLUSIVE: [],
    }
    for target in target_reports:
        by_status[target["status"]].append(target["python_version"])

    checked = by_status[CHECKED]
    conclusive = bool(checked)
    total = len(target_reports)
    if checked and len(checked) == total:
        file_status = CHECKED
    elif not checked and len(by_status[REJECTED]) == total:
        file_status = REJECTED
    elif not checked and len(by_status[UNCOVERED]) == total:
        file_status = UNCOVERED
    elif not checked:
        file_status = INCONCLUSIVE
    else:
        file_status = "PARTIAL"

    return {
        "file": fname,
        "filename": fname,
        "status": file_status,
        "state": file_status.lower(),
        "targets": target_reports,
        "findings": findings,
        "coverage": {
            "checked": checked,
            "rejected": by_status[REJECTED],
            "uncovered": by_status[UNCOVERED],
            "inconclusive": by_status[INCONCLUSIVE],
        },
        "conclusive": conclusive,
        "fully_checked": len(checked) == len(target_reports),
        "explanation": _explain_targets(target_reports),
    }


def _serialize_finding(entry):
    issue = entry["issue"]
    serialized = issue.as_dict()
    versions = list(entry["versions"])
    suppressed_versions = list(entry["suppressed_versions"])
    partial_versions = list(entry["partial_versions"])
    suppressed = bool(suppressed_versions)
    fully_suppressed = bool(versions) and len(
        suppressed_versions
    ) == len(versions)

    if not suppressed:
        suppression = "none"
    elif fully_suppressed and entry["blanket_nosec"]:
        suppression = "blanket"
    elif fully_suppressed:
        suppression = "explicit"
    else:
        suppression = "partial"

    serialized.update(
        {
            "python_versions": versions,
            "applicable_versions": versions,
            "partial_versions": partial_versions,
            "suppressed_versions": suppressed_versions,
            "suppressed": suppressed,
            "fully_suppressed": fully_suppressed,
            "suppressed_test_ids": sorted(
                entry["suppressed_test_ids"]
            ),
            "blanket_nosec": entry["blanket_nosec"],
            "suppression": suppression,
            "rule_id": issue.test_id,
            "original_test_id": issue.test_id,
            "target_status": dict(entry["target_status"]),
        }
    )
    return serialized


def scan_file(
    fname,
    data,
    targets,
    testset,
    metrics=None,
    ignore_nosec=False,
):
    """Scan one source file against every grammar target.

    Nosec comments never delete a finding.  Every rule hit is retained and
    annotated with the versions it applies to and whether, on each of those
    versions, it is suppressed.

    :param fname: logical filename stored on each issue
    :param data: raw source bytes or text
    :param targets: iterable of ``(major, minor)`` tuples
    :param testset: BanditTestSet containing the configured plugins
    :param metrics: optional metrics sink
    :param ignore_nosec: whether ``# nosec`` should be ignored
    :return: JSON-serialisable per-file report dictionary
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    if metrics is None:
        metrics = b_metrics.Metrics()
    targets = parse_target_versions(targets)

    labels = [format_target(target) for target in targets]
    nosec_lines = _collect_nosec(data, ignore_nosec)

    target_reports = []
    merged = {}

    for version in targets:
        label = format_target(version)
        status, reason, issues = _scan_one(
            data, fname, version, testset, metrics, ignore_nosec
        )
        suppressed_count = 0
        unsuppressed_count = 0

        if status in (CHECKED, INCONCLUSIVE):
            for current_issue in issues:
                (
                    suppressed,
                    suppressed_ids,
                    blanket,
                    _mode,
                ) = _nosec_for_issue(current_issue, nosec_lines)
                if suppressed:
                    suppressed_count += 1
                else:
                    unsuppressed_count += 1

                key = _finding_key(current_issue)
                if key not in merged:
                    merged[key] = {
                        "issue": current_issue,
                        "versions": [],
                        "partial_versions": [],
                        "suppressed_versions": [],
                        "suppressed_test_ids": set(),
                        "blanket_nosec": False,
                        "target_status": {},
                    }
                entry = merged[key]
                entry["target_status"][label] = status
                version_list = (
                    entry["versions"]
                    if status == CHECKED
                    else entry["partial_versions"]
                )
                if label not in version_list:
                    version_list.append(label)
                if status == CHECKED and suppressed:
                    if label not in entry["suppressed_versions"]:
                        entry["suppressed_versions"].append(label)
                    entry["blanket_nosec"] = (
                        entry["blanket_nosec"] or blanket
                    )
                    entry["suppressed_test_ids"].update(suppressed_ids)

        target_reports.append(
            _target_report(
                version,
                status,
                reason,
                issues,
                suppressed_count,
                unsuppressed_count,
            )
        )

    findings = []
    for entry in merged.values():
        finding = _serialize_finding(entry)
        finding["target_status"].update(
            {
                label: target["status"]
                for label, target in zip(labels, target_reports)
            }
        )
        findings.append(finding)

    findings.sort(
        key=lambda item: (
            item.get("line_number") or 0,
            item.get("col_offset") or 0,
            item.get("test_id") or "",
        )
    )
    return _file_report(fname, target_reports, findings)


def file_error_report(fname, targets, reason):
    """Build a per-file report for a file that could not be read."""
    targets = parse_target_versions(targets)
    target_reports = []
    for version in targets:
        target_reports.append(
            {
                "python_version": format_target(version),
                "target": format_target(version),
                "status": INCONCLUSIVE,
                "state": INCONCLUSIVE.lower(),
                "covered": host_supports_target(version),
                "conclusive": False,
                "reason": reason,
                "status_reason": reason,
                "finding_count": None,
                "suppressed_count": None,
                "unsuppressed_count": None,
                "partial_finding_count": 0,
                "partial_suppressed_count": 0,
            }
        )
    return _file_report(fname, target_reports, [])


def build_report(files, targets, host_version=None):
    """Assemble a top-level multi-target report from per-file reports."""
    targets = parse_target_versions(targets)
    host = host_version or sys.version_info[:2]
    labels = [format_target(target) for target in targets]
    summary = {
        "files": len(files),
        "findings": 0,
        "unsuppressed_findings": 0,
        "suppressed_findings": 0,
        "checked_targets": 0,
        "rejected_targets": 0,
        "uncovered_targets": 0,
        "inconclusive_targets": 0,
        "files_with_conclusive_results": 0,
        "files_without_conclusion": 0,
    }

    for file_report in files:
        if file_report["conclusive"]:
            summary["files_with_conclusive_results"] += 1
        else:
            summary["files_without_conclusion"] += 1
        for target in file_report["targets"]:
            key = target["status"].lower() + "_targets"
            if key in summary:
                summary[key] += 1
        for finding in file_report["findings"]:
            summary["findings"] += 1
            if finding["suppressed"]:
                summary["suppressed_findings"] += 1
            else:
                summary["unsuppressed_findings"] += 1

    return {
        "host_python_version": format_target(host),
        "targets": labels,
        "status_legend": dict(STATUS_LEGEND),
        "summary": summary,
        "files": files,
    }


def scan_files(
    files,
    targets,
    testset,
    metrics=None,
    ignore_nosec=False,
):
    """Backend entry point for scanning several files.

    ``files`` may contain paths or ``(filename, data)`` pairs.  Read
    failures produce an inconclusive file report rather than disappearing
    from the result.
    """
    targets = parse_target_versions(targets)
    if not targets:
        raise TargetVersionError(
            "at least one Python target version is required"
        )
    if metrics is None:
        metrics = b_metrics.Metrics()

    file_reports = []
    for item in files:
        if isinstance(item, (tuple, list)) and len(item) == 2:
            fname, data = item
            file_reports.append(
                scan_file(
                    fname,
                    data,
                    targets,
                    testset,
                    metrics,
                    ignore_nosec,
                )
            )
            continue

        fname = item
        try:
            with open(fname, "rb") as handle:
                data = handle.read()
        except OSError as exc:
            reason = exc.strerror or str(exc)
            file_reports.append(
                file_error_report(fname, targets, reason)
            )
            continue
        file_reports.append(
            scan_file(
                fname,
                data,
                targets,
                testset,
                metrics,
                ignore_nosec,
            )
        )

    return build_report(file_reports, targets)


def scan_target_versions(
    files,
    targets,
    testset,
    metrics=None,
    ignore_nosec=False,
):
    """Backward-friendly name for :func:`scan_files`."""
    return scan_files(
        files,
        targets,
        testset,
        metrics=metrics,
        ignore_nosec=ignore_nosec,
    )
